//! Mask styles: how a detected span is rendered in redacted output.
//!
//! [`MaskStyle`] is the one knob behind [`Detector::redact`] and the
//! [`Guard`] masking paths. Secret findings are not affected by it: a
//! leaked credential always renders as `[SECRET:VENDOR]`.
//!
//! A line on which the detection engine hit a runtime error (see
//! [`ScanReport::error_spans`]) was not fully scanned; the scan-aware
//! [`MaskStyle::redact_scan`] replaces such a line as a whole with
//! [`SCAN_INCOMPLETE_MASK`] instead of letting unchecked text through.
//!
//! Pseudonyms ([`MaskStyle::Pseudonym`]) are keyed HMAC-SHA256 digests
//! (RFC 2104, <https://www.rfc-editor.org/rfc/rfc2104>, retrieved
//! 2026-10-29). RFC 2104 section 3 ("Keys"): "less than L bytes is
//! strongly discouraged as it would decrease the security strength of the
//! function", where section 2 defines L as "the byte-length of hash
//! outputs"; SHA-256 outputs 256 bits (FIPS 180-4), so L = 32 and
//! [`PseudonymKey::new`] refuses shorter keys.
//!
//! [`Detector::redact`]: crate::Detector::redact
//! [`Guard`]: crate::Guard

use std::fmt;

use super::detector::ScanReport;
use crate::guard::audit::hmac_sha256;
use crate::guard::normalize::normalize_for_scan;
use crate::pii::{replace_spans, Entity, EntityType, ReplaceSpan};

/// The `{type}` template equivalent to [`MaskStyle::Label`].
const LABEL_TEMPLATE: &str = "[{type}]";

/// What [`MaskStyle::redact_scan`] writes in place of a line that the
/// detection engine could not scan completely (a regex runtime error such
/// as an exhausted backtrack budget happened on it).
///
/// # Examples
/// ```
/// assert_eq!(redactify::policy::mask::SCAN_INCOMPLETE_MASK, "[SCAN_INCOMPLETE]");
/// ```
pub const SCAN_INCOMPLETE_MASK: &str = "[SCAN_INCOMPLETE]";

/// How a detected span is rendered in redacted output.
///
/// Overlapping spans are masked as ONE region covering their union (no
/// tail of a longer span leaks); the region takes the type of its longest
/// span, ties broken by the more specific type. Invalid spans (empty, out
/// of bounds, not on a character boundary) are skipped, never a panic.
///
/// # Examples
/// ```
/// use redactify::{Detector, MaskStyle};
///
/// let text = "TCKN 12345678950";
/// let ents = Detector::new().detect(text);
/// assert_eq!(MaskStyle::Label.redact(text, &ents), "TCKN [TCKN]");
/// assert_eq!(
///     MaskStyle::Template("<{type}>".into()).redact(text, &ents),
///     "TCKN <TCKN>"
/// );
/// assert_eq!(MaskStyle::default(), MaskStyle::Label);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum MaskStyle {
    /// The type label in brackets, e.g. `[TCKN]` (the default).
    #[default]
    Label,
    /// A custom template: every `{type}` placeholder receives the type
    /// label (e.g. `"<<{type}>>"` renders `<<TCKN>>`).
    Template(String),
    /// Every character of the region replaced by this character (the
    /// character count is kept: `12345678950` -> `***********`).
    ///
    /// # Examples
    /// ```
    /// use redactify::{Detector, MaskStyle};
    ///
    /// let d = Detector::new().with_mask_style(MaskStyle::Char('*'));
    /// assert_eq!(d.redact("TCKN 12345678950"), "TCKN ***********");
    /// ```
    Char(char),
    /// Keeps the last `keep_last` alphanumeric characters visible and
    /// replaces every other alphanumeric character with `ch`; separators
    /// (spaces, dashes, dots, `@`, ...) stay in place. A partial mask
    /// never reveals a whole value: when the region has `keep_last` or
    /// fewer alphanumeric characters, all of them are masked.
    ///
    /// # Examples
    /// ```
    /// use redactify::{Detector, MaskStyle};
    ///
    /// let d = Detector::new().with_mask_style(MaskStyle::Partial { keep_last: 4, ch: '*' });
    /// assert_eq!(d.redact("kart 4111 1111 1111 1111"), "kart **** **** **** 1111");
    /// // 4 or fewer alphanumerics: nothing is revealed
    /// assert_eq!(d.redact("mail a@b.co"), "mail *@*.**");
    /// ```
    Partial {
        /// How many trailing alphanumeric characters stay visible.
        keep_last: usize,
        /// The replacement character for the masked ones.
        ch: char,
    },
    /// A stable keyed pseudonym `[TYPE#<16 hex digits>]`: the first 8
    /// bytes of HMAC-SHA256(key, `TYPE` || 0x00 || normalized value), in
    /// lowercase hex. The value is normalized like the detector's
    /// normalized view (NFKC, invisible characters stripped), so a
    /// fullwidth or zero-width-scattered spelling of a value gets the same
    /// pseudonym as its plain spelling. Equal values of the same type
    /// always map to the same pseudonym under one key; without the key the
    /// pseudonym cannot be recomputed from a guessed value.
    ///
    /// # Examples
    /// ```
    /// use redactify::{Detector, MaskStyle, PseudonymKey};
    ///
    /// let key = PseudonymKey::new([7u8; 32]).unwrap();
    /// let d = Detector::new().with_mask_style(MaskStyle::Pseudonym(key));
    /// let a = d.redact("TCKN 12345678950");
    /// assert!(a.starts_with("TCKN [TCKN#") && a.ends_with(']'));
    /// assert_eq!(a.len(), "TCKN [TCKN#]".len() + 16);
    /// // the same value always gets the same pseudonym
    /// let b = d.redact("kimlik: 12345678950");
    /// assert_eq!(b.split_once('[').unwrap().1, a.split_once('[').unwrap().1);
    /// ```
    Pseudonym(PseudonymKey),
    /// Replaces the first `count` alphanumeric characters with `ch` and
    /// leaves the rest visible; separators stay in place. A `count` of 0,
    /// or one that reaches the whole region, masks every alphanumeric
    /// character: a style never reveals a whole value.
    ///
    /// # Examples
    /// ```
    /// use redactify::{Detector, MaskStyle};
    ///
    /// let d = Detector::new().with_mask_style(MaskStyle::MaskFirst { count: 3, ch: '*' });
    /// assert_eq!(d.redact("TCKN 12345678950"), "TCKN ***45678950");
    /// ```
    MaskFirst {
        /// How many leading alphanumeric characters are masked.
        count: usize,
        /// The replacement character.
        ch: char,
    },
    /// Replaces the last `count` alphanumeric characters with `ch` and
    /// leaves the beginning visible; separators stay in place. A `count`
    /// of 0, or one that reaches the whole region, masks every
    /// alphanumeric character.
    ///
    /// # Examples
    /// ```
    /// use redactify::{Detector, MaskStyle};
    ///
    /// let d = Detector::new().with_mask_style(MaskStyle::MaskLast { count: 4, ch: '*' });
    /// assert_eq!(d.redact("kart 4111 1111 1111 1111"), "kart 4111 1111 1111 ****");
    /// ```
    MaskLast {
        /// How many trailing alphanumeric characters are masked.
        count: usize,
        /// The replacement character.
        ch: char,
    },
    /// A different style per entity type: a region of a type listed in
    /// `overrides` uses that style, every other region uses `default`.
    /// Build it with [`MaskStyle::by_type`]. An overlap of several types
    /// is one region that takes the type of its longest span, so the style
    /// of that type applies.
    ///
    /// # Examples
    /// ```
    /// use redactify::{Detector, EntityType, MaskStyle};
    ///
    /// let style = MaskStyle::by_type(
    ///     MaskStyle::Label,
    ///     vec![(EntityType::Email, MaskStyle::Char('*'))],
    /// );
    /// let d = Detector::new().with_mask_style(style);
    /// assert_eq!(d.redact("TCKN 12345678950 mail a@b.co"), "TCKN [TCKN] mail ******");
    /// ```
    ByType {
        /// The style of every type without an override.
        default: Box<MaskStyle>,
        /// The per-type styles (the first entry of a type wins).
        overrides: Vec<(EntityType, MaskStyle)>,
    },
}

/// The secret key of [`MaskStyle::Pseudonym`]: at least
/// [`PseudonymKey::MIN_LEN`] bytes (see the module docs for the RFC 2104
/// basis).
///
/// `Debug` never prints the key bytes, only their count:
/// `PseudonymKey(<redacted, 32 bytes>)`. There is deliberately no serde
/// support (a key must not end up in a serialized policy or log).
///
/// # Examples
/// ```
/// use redactify::{MaskStyleError, PseudonymKey};
///
/// let key = PseudonymKey::new(vec![1u8; 32]).unwrap();
/// assert_eq!(format!("{key:?}"), "PseudonymKey(<redacted, 32 bytes>)");
/// assert_eq!(
///     PseudonymKey::new(b"too short".to_vec()),
///     Err(MaskStyleError::KeyTooShort { len: 9, min: 32 })
/// );
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct PseudonymKey(Vec<u8>);

impl PseudonymKey {
    /// Minimum key length in bytes: L = 32, the SHA-256 output length
    /// (RFC 2104 section 3).
    pub const MIN_LEN: usize = 32;

    /// Wraps `key` as a pseudonym key.
    ///
    /// # Errors
    /// [`MaskStyleError::KeyTooShort`] when `key` has fewer than
    /// [`PseudonymKey::MIN_LEN`] bytes.
    ///
    /// # Examples
    /// ```
    /// use redactify::PseudonymKey;
    ///
    /// assert!(PseudonymKey::new("a key of at least thirty-two bytes!").is_ok());
    /// assert!(PseudonymKey::new("short").is_err());
    /// ```
    pub fn new(key: impl Into<Vec<u8>>) -> Result<Self, MaskStyleError> {
        let key = key.into();
        if key.len() < Self::MIN_LEN {
            return Err(MaskStyleError::KeyTooShort {
                len: key.len(),
                min: Self::MIN_LEN,
            });
        }
        Ok(Self(key))
    }

    /// The key length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always `false`: a key holds at least [`PseudonymKey::MIN_LEN`]
    /// bytes (present for API symmetry with [`PseudonymKey::len`]).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `[TYPE#<16 hex>]` for one value (see [`MaskStyle::Pseudonym`]).
    fn pseudonym(&self, kind: EntityType, value: &str) -> String {
        let label = kind.as_str();
        let norm = normalize_for_scan(value);
        let mut message = Vec::with_capacity(label.len() + 1 + norm.len());
        message.extend_from_slice(label.as_bytes());
        message.push(0x00);
        message.extend_from_slice(norm.as_bytes());
        let digest = hmac_sha256(&self.0, &message);
        let mut out = String::with_capacity(label.len() + 19);
        out.push('[');
        out.push_str(label);
        out.push('#');
        for b in &digest[..8] {
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0x0f)]));
        }
        out.push(']');
        out
    }
}

/// Lowercase hex digits.
const HEX: &[u8; 16] = b"0123456789abcdef";

impl fmt::Debug for PseudonymKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PseudonymKey(<redacted, {} bytes>)", self.0.len())
    }
}

/// Error of the mask-style constructors ([`PseudonymKey::new`]).
///
/// # Examples
/// ```
/// use redactify::{MaskStyleError, PseudonymKey};
///
/// let err = PseudonymKey::new([0u8; 8]).unwrap_err();
/// assert_eq!(err, MaskStyleError::KeyTooShort { len: 8, min: 32 });
/// assert_eq!(err.to_string(), "pseudonym key too short: 8 bytes, at least 32 required");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MaskStyleError {
    /// The pseudonym key is shorter than [`PseudonymKey::MIN_LEN`].
    #[error("pseudonym key too short: {len} bytes, at least {min} required")]
    KeyTooShort {
        /// The given key length in bytes.
        len: usize,
        /// The minimum length in bytes.
        min: usize,
    },
}

impl MaskStyle {
    /// A style that applies `overrides` per entity type and `default` to
    /// every other type (see [`MaskStyle::ByType`]).
    #[must_use]
    pub fn by_type(default: MaskStyle, overrides: Vec<(EntityType, MaskStyle)>) -> Self {
        Self::ByType {
            default: Box::new(default),
            overrides,
        }
    }

    /// Masks `entities` in `text` with this style. The entities are
    /// typically a detection result for the same text (see
    /// [`Detector::detect`](crate::Detector::detect)); they may be unsorted
    /// or overlapping.
    ///
    /// This renders entities only; use [`MaskStyle::redact_scan`] with a
    /// [`ScanReport`] so that lines the engine could not scan completely
    /// are masked too.
    ///
    /// # Examples
    /// ```
    /// use redactify::{Detector, MaskStyle, MockNameRecognizer, NerRecognizer};
    ///
    /// let ner = MockNameRecognizer::new();
    /// let rec = [&ner as &dyn NerRecognizer];
    /// let text = "we met Ahmet Yilmaz, TCKN 12345678950 on file";
    /// let ents = Detector::new().with_ner(&rec).detect(text);
    /// let masked = MaskStyle::Label.redact(text, &ents);
    /// assert!(masked.contains("[NAME]"));
    /// assert!(masked.contains("[TCKN]"));
    /// ```
    #[must_use]
    pub fn redact(&self, text: &str, entities: &[Entity]) -> String {
        replace_spans(text, entities, |kind, region| self.render(kind, region))
    }

    /// Scan-aware masking: masks `report.entities` like
    /// [`MaskStyle::redact`] AND replaces every line listed in
    /// `report.error_spans` (a line the engine could not scan completely)
    /// with [`SCAN_INCOMPLETE_MASK`], whatever the style.
    ///
    /// The error line wins over entities inside it: an entity that lies in
    /// such a line disappears into the line mask, and an entity that
    /// crosses into it (a whole-text NER span) keeps its own mask for the
    /// part outside the line. A report without error spans renders exactly
    /// like [`MaskStyle::redact`].
    ///
    /// # Examples
    /// ```
    /// use redactify::{CustomRule, Detector, EntityType, MaskStyle};
    ///
    /// // a pathological custom pattern exhausts the backtrack budget on
    /// // the second line: that line was not fully checked
    /// let rule = CustomRule::new(EntityType::Itin, r"(?i)(a|b|ab)*(?>c)").unwrap();
    /// let rules = [&rule];
    /// let text = format!("kimlik 12345678950\n{} c\nend", "ab".repeat(40));
    /// let report = Detector::new().with_custom_rules(&rules).scan(&text);
    /// assert!(!report.is_complete());
    /// assert_eq!(
    ///     MaskStyle::Label.redact_scan(&text, &report),
    ///     "kimlik [TCKN]\n[SCAN_INCOMPLETE]\nend"
    /// );
    /// ```
    #[must_use]
    pub fn redact_scan(&self, text: &str, report: &ScanReport) -> String {
        let errors = valid_error_spans(text, &report.error_spans);
        if errors.is_empty() {
            return self.redact(text, &report.entities);
        }
        let mut spans: Vec<MaskSpan> = Vec::with_capacity(report.entities.len() + errors.len());
        for e in &report.entities {
            push_outside(&mut spans, e, &errors);
        }
        spans.extend(errors.iter().map(|&(start, end)| MaskSpan {
            start,
            end,
            label: MaskLabel::Incomplete,
        }));
        replace_spans(text, &spans, |label, region| match label {
            MaskLabel::Entity(kind) => self.render(kind, region),
            MaskLabel::Incomplete => SCAN_INCOMPLETE_MASK.to_owned(),
        })
    }

    /// The replacement of one merged region of type `kind` whose original
    /// text is `region`.
    fn render(&self, kind: EntityType, region: &str) -> String {
        match self {
            Self::Label => LABEL_TEMPLATE.replace("{type}", kind.as_str()),
            Self::Template(template) => template.replace("{type}", kind.as_str()),
            Self::Char(ch) => region.chars().map(|_| *ch).collect(),
            Self::Partial { keep_last, ch } => partial(region, *keep_last, *ch),
            Self::Pseudonym(key) => key.pseudonym(kind, region),
            Self::MaskFirst { count, ch } => edge_mask(region, *count, *ch, true),
            Self::MaskLast { count, ch } => edge_mask(region, *count, *ch, false),
            Self::ByType { default, overrides } => overrides
                .iter()
                .find(|(t, _)| *t == kind)
                .map_or(&**default, |(_, style)| style)
                .render(kind, region),
        }
    }
}

/// [`MaskStyle::MaskFirst`] and [`MaskStyle::MaskLast`]: masks `count`
/// alphanumeric characters from the start (or the end) of `region`. A
/// `count` of 0, or one covering every alphanumeric character, masks them
/// all (a region without any alphanumeric character is masked entirely).
fn edge_mask(region: &str, count: usize, ch: char, from_start: bool) -> String {
    let alnum = region.chars().filter(|c| c.is_alphanumeric()).count();
    if alnum == 0 {
        return region.chars().map(|_| ch).collect();
    }
    let masked = if count == 0 || count >= alnum {
        alnum
    } else {
        count
    };
    let mut seen = 0usize;
    region
        .chars()
        .map(|c| {
            if !c.is_alphanumeric() {
                return c;
            }
            seen += 1;
            let hide = if from_start {
                seen <= masked
            } else {
                seen > alnum - masked
            };
            if hide {
                ch
            } else {
                c
            }
        })
        .collect()
}

/// [`MaskStyle::Partial`]: masks every alphanumeric character except the
/// last `keep_last` ones; reveals nothing when that would be all of them
/// (a region without any alphanumeric character is masked entirely).
fn partial(region: &str, keep_last: usize, ch: char) -> String {
    let alnum = region.chars().filter(|c| c.is_alphanumeric()).count();
    if alnum == 0 {
        return region.chars().map(|_| ch).collect();
    }
    let reveal = if keep_last >= alnum { 0 } else { keep_last };
    let masked = alnum - reveal;
    let mut seen = 0usize;
    region
        .chars()
        .map(|c| {
            if !c.is_alphanumeric() {
                return c;
            }
            seen += 1;
            if seen <= masked {
                ch
            } else {
                c
            }
        })
        .collect()
}

/// The label of one span in a scan-aware masking pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MaskLabel {
    /// A detected entity of this type.
    Entity(EntityType),
    /// A line the engine could not scan completely.
    Incomplete,
}

/// One span of a scan-aware masking pass (an entity piece or an error
/// line).
struct MaskSpan {
    start: usize,
    end: usize,
    label: MaskLabel,
}

impl ReplaceSpan for MaskSpan {
    type Label = MaskLabel;

    fn byte_range(&self) -> (usize, usize) {
        (self.start, self.end)
    }

    fn label(&self) -> MaskLabel {
        self.label
    }

    fn rank(&self) -> u8 {
        match self.label {
            MaskLabel::Entity(kind) => kind.priority(),
            // an error line outranks every entity type
            MaskLabel::Incomplete => 0,
        }
    }
}

/// The well-formed error spans of `spans` (non-empty, in bounds, on char
/// boundaries), sorted by start.
fn valid_error_spans(text: &str, spans: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = spans
        .iter()
        .copied()
        .filter(|&(s, e)| {
            s < e && e <= text.len() && text.is_char_boundary(s) && text.is_char_boundary(e)
        })
        .collect();
    out.sort_unstable();
    out
}

/// Pushes the parts of entity `e` that lie OUTSIDE every error span
/// (`errors` sorted by start): the error line wins over the entity.
fn push_outside(spans: &mut Vec<MaskSpan>, e: &Entity, errors: &[(usize, usize)]) {
    let label = MaskLabel::Entity(e.kind);
    let mut cursor = e.start;
    for &(s, en) in errors {
        if en <= cursor {
            continue;
        }
        if s >= e.end {
            break;
        }
        if s > cursor {
            spans.push(MaskSpan {
                start: cursor,
                end: s,
                label,
            });
        }
        cursor = cursor.max(en);
        if cursor >= e.end {
            return;
        }
    }
    if cursor < e.end {
        spans.push(MaskSpan {
            start: cursor,
            end: e.end,
            label,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{MaskStyle, ScanReport};
    use crate::pii::{Entity, EntityType};

    fn ents() -> Vec<Entity> {
        vec![
            Entity {
                kind: EntityType::Address,
                start: 3,
                end: 8,
                text: "defgh".into(),
                score: 0.9,
            },
            Entity {
                kind: EntityType::Name,
                start: 0,
                end: 5,
                text: "abcde".into(),
                score: 0.9,
            },
        ]
    }

    fn report(entities: Vec<Entity>, error_spans: Vec<(usize, usize)>) -> ScanReport {
        ScanReport {
            engine_errors: error_spans.len(),
            entities,
            error_spans,
        }
    }

    #[test]
    fn template_fills_every_placeholder_of_the_merged_region() {
        // the two spans overlap: ONE region [0, 8) with the first span's
        // label (equal lengths, equal rank)
        let text = "abcdefgh tail";
        for (template, expected) in [
            ("[{type}]", "[NAME] tail"),
            ("<<{type}>>", "<<NAME>> tail"),
            ("{type}-{type}", "NAME-NAME tail"),
            ("no placeholder", "no placeholder tail"),
        ] {
            assert_eq!(
                MaskStyle::Template(template.to_owned()).redact(text, &ents()),
                expected,
                "{template}"
            );
        }
    }

    #[test]
    fn label_equals_the_bracket_template() {
        let text = "abcdefgh tail";
        assert_eq!(
            MaskStyle::Label.redact(text, &ents()),
            MaskStyle::Template("[{type}]".into()).redact(text, &ents())
        );
        assert_eq!(MaskStyle::Label.redact(text, &ents()), "[NAME] tail");
    }

    #[test]
    fn redact_scan_without_errors_equals_redact() {
        let text = "abcdefgh tail";
        let r = report(ents(), Vec::new());
        assert_eq!(
            MaskStyle::Label.redact_scan(text, &r),
            MaskStyle::Label.redact(text, &ents())
        );
    }

    #[test]
    fn redact_scan_masks_the_error_line_over_entities_inside_it() {
        // line 2 ("bad 1234 line") errored; an entity inside it vanishes
        // into the line mask, entities on other lines keep their label
        let text = "ok 5678\nbad 1234 line\nend";
        let line2 = (8, 8 + "bad 1234 line".len());
        let inside = Entity {
            kind: EntityType::Tckn,
            start: 12,
            end: 16,
            text: "1234".into(),
            score: 1.0,
        };
        let outside = Entity {
            kind: EntityType::Phone,
            start: 3,
            end: 7,
            text: "5678".into(),
            score: 0.8,
        };
        let r = report(vec![inside, outside], vec![line2]);
        assert_eq!(
            MaskStyle::Label.redact_scan(text, &r),
            "ok [PHONE]\n[SCAN_INCOMPLETE]\nend"
        );
        // the style never changes the line marker
        assert_eq!(
            MaskStyle::Template("#".into()).redact_scan(text, &r),
            "ok #\n[SCAN_INCOMPLETE]\nend"
        );
    }

    #[test]
    fn redact_scan_keeps_the_outside_part_of_a_crossing_entity() {
        // a whole-text span crossing into the error line: its part before
        // the line keeps the entity mask, the line itself is the marker
        let text = "Ahmet\nYilmaz zz\nrest";
        let name = Entity {
            kind: EntityType::Name,
            start: 0,
            end: 12,
            text: "Ahmet\nYilmaz".into(),
            score: 0.9,
        };
        let r = report(vec![name], vec![(6, 15)]);
        assert_eq!(
            MaskStyle::Label.redact_scan(text, &r),
            "[NAME][SCAN_INCOMPLETE]\nrest"
        );
    }

    #[test]
    fn redact_scan_skips_malformed_error_spans() {
        let text = "a\u{fc}b";
        // 2 sits inside the 2-byte u-umlaut; 9 is out of bounds
        let r = report(Vec::new(), vec![(2, 3), (1, 9), (3, 3)]);
        assert_eq!(MaskStyle::Label.redact_scan(text, &r), text);
    }
}
