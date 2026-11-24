//! JSON redaction: masks PII and secrets inside the string leaves of a
//! JSON document while keeping its structure, and reports WHERE something
//! was masked (RFC 6901 JSON Pointers) without ever reporting a value.
//!
//! Per string leaf the redactor builds one synthetic line
//! `"{key}: {value}"` from the leaf's object key (array items use the key
//! of the enclosing member), so the key acts as a context cue exactly like
//! a label in free text (`{"vergi_no": "1234567890"}` is a VKN). Only the
//! last 64 characters of a longer key enter that line (every built-in
//! rule's reach into it fits; see `CUE_TAIL_CHARS`), so a long key is not
//! rescanned in full for every value under it. Secrets are masked first
//! (`[SECRET:VENDOR]`, raw and normalized view), then the detector runs on
//! the secret-masked line; every span is shifted back into the value.
//! Object KEYS are scanned too, once per distinct key: PII in a key is
//! reported (with that pointer segment masked) but the key itself is not
//! rewritten, since renaming a member would change the document's schema.
//!
//! The walk is iterative (an explicit stack, no recursion), so nesting
//! depth is bounded by memory, not by the call stack.
//!
//! JSON Pointer syntax: RFC 6901 (<https://www.rfc-editor.org/rfc/rfc6901>,
//! retrieved 2026-10-29), section 3: `json-pointer = *( "/"
//! reference-token )`, where `'~'` is encoded as `~0` and `'/'` as `~1`;
//! section 4: array elements are addressed by their base-10 index.

use std::borrow::Cow;
use std::collections::BTreeMap;

use serde_json::Value;

use super::detector::{Detector, ScanReport};
use super::mask::SCAN_INCOMPLETE_MASK;
use crate::guard::secrets::{find_secret_mask_spans, mask_findings, SecretFinding};
use crate::pii::{Entity, EntityType};

/// How many trailing characters of a member name the synthetic cue line
/// `"{cue}: {value}"` keeps (see [`cue_tail`]).
///
/// Derivation: the line exists so that patterns see the member name as
/// left context of the value. A built-in rule reaches into that context
/// in two ways: (1) the PII cue window (`pii::detect::CUE_WINDOW`, 18
/// characters): a leading cue counts when it ENDS within 18 characters
/// of the match; for a match at the value's start the `": "` separator
/// takes 2 of them, so the name must keep 16 characters plus the longest
/// built-in cue (44 today: the GSTIN label `goods and services tax
/// identification number`; pinned by the `cue_tail_covers_every_built_in_cue`
/// test); from a match that starts inside the name (the MRN rule's
/// `medical record number` cue, 21 characters) the worst case is
/// 21 + 18 + 21 = 60 characters; (2) secret patterns whose
/// match starts in the name, the longest
/// being the AWS secret-key rule `aws[^\n]{0,30}?(?:secret|sk)[^\n]{0,20}?[=:\s]`:
/// 3 + 30 + 6 + 19 = 58 characters of the name before the separator.
/// 64 covers every bounded reach, so for the built-in rules a cue line
/// built from the tail sees exactly what the full name gave; only an
/// unbounded whitespace run inside a longer name (`\s*` / `[\s:#]*`
/// gaps) can differ. Custom rules and NER recognizers see the tail as
/// their left context too. Characters are counted in the raw name
/// (invisible characters, which the normalized pass strips, count too).
const CUE_TAIL_CHARS: usize = 64;

/// The last [`CUE_TAIL_CHARS`] characters of `key` (all of it when
/// shorter), cut on a char boundary. Every value under a member is scanned
/// with this tail, so a long member name costs its length once (its own
/// scan), not once per value under it.
fn cue_tail(key: &str) -> &str {
    match key.char_indices().rev().nth(CUE_TAIL_CHARS - 1) {
        Some((i, _)) => &key[i..],
        None => key,
    }
}

/// Masks PII and secrets inside a JSON document (see the module docs).
///
/// # Examples
/// ```
/// use redactify::{JsonFindingKind, JsonRedactor, EntityType};
/// use serde_json::json;
///
/// let mut doc = json!({
///     "customer": {"vergi_no": "1234567890", "note": "mail a@b.com"},
///     "tags": ["ok", "TCKN 12345678950"]
/// });
/// let report = JsonRedactor::new().redact(&mut doc);
/// assert_eq!(doc, json!({
///     "customer": {"vergi_no": "[VKN]", "note": "mail [EMAIL]"},
///     "tags": ["ok", "TCKN [TCKN]"]
/// }));
/// let found: Vec<(&str, JsonFindingKind)> =
///     report.findings.iter().map(|f| (f.pointer.as_str(), f.kind)).collect();
/// assert_eq!(found, vec![
///     ("/customer/note", JsonFindingKind::Pii(EntityType::Email)),
///     ("/customer/vergi_no", JsonFindingKind::Pii(EntityType::Vkn)),
///     ("/tags/1", JsonFindingKind::Pii(EntityType::Tckn)),
/// ]);
/// assert!(report.is_complete());
/// ```
#[derive(Debug, Clone)]
#[must_use = "a JsonRedactor does nothing until `redact` runs"]
pub struct JsonRedactor<'a> {
    detector: Detector<'a>,
    numeric_leaves: bool,
}

impl<'a> JsonRedactor<'a> {
    /// A redactor with the default detector plus the normalization pass
    /// (`Detector::new().with_normalization(true)`), string leaves only.
    pub fn new() -> Self {
        Self {
            detector: Detector::new().with_normalization(true),
            numeric_leaves: false,
        }
    }

    /// Uses `detector` for the PII pass (locales, threshold, NER, custom
    /// rules, allowlist, normalization and the mask style all apply).
    ///
    /// # Examples
    /// ```
    /// use redactify::{Detector, JsonRedactor, MaskStyle};
    /// use serde_json::json;
    ///
    /// let d = Detector::new().with_locales(&["uk"]).with_mask_style(MaskStyle::Char('#'));
    /// let mut doc = json!({"nhs": "9434765870"});
    /// let _ = JsonRedactor::new().with_detector(d).redact(&mut doc);
    /// assert_eq!(doc, json!({"nhs": "##########"}));
    /// ```
    pub fn with_detector(mut self, detector: Detector<'a>) -> Self {
        self.detector = detector;
        self
    }

    /// Also scans number leaves (off by default). A number is scanned in
    /// its JSON text form; when it contains PII it is REPLACED by a string
    /// holding the masked form (`12345678950` -> `"[TCKN]"`), since a
    /// masked value is no longer a number.
    ///
    /// # Examples
    /// ```
    /// use redactify::JsonRedactor;
    /// use serde_json::json;
    ///
    /// let mut doc = json!({"tckn": 12345678950_u64, "count": 3});
    /// let _ = JsonRedactor::new().redact(&mut doc);
    /// assert_eq!(doc["tckn"], json!(12345678950_u64)); // numbers off by default
    /// let _ = JsonRedactor::new().with_numeric_leaves(true).redact(&mut doc);
    /// assert_eq!(doc, json!({"tckn": "[TCKN]", "count": 3}));
    /// ```
    pub fn with_numeric_leaves(mut self, on: bool) -> Self {
        self.numeric_leaves = on;
        self
    }

    /// Masks `value` in place and reports every finding by pointer and
    /// kind. The report never contains a value from the document.
    #[must_use = "the report says what was masked and whether the scan was complete"]
    pub fn redact(&self, value: &mut Value) -> JsonRedactionReport {
        let mut report = JsonRedactionReport::default();
        // node 0 is the document root (pointer ""); every other node is a
        // (parent, segment) pair, so pointers are built only on demand
        let mut nodes: Vec<(usize, Segment<'_>)> = vec![(0, Segment::Index(0))];
        let mut key_scans: BTreeMap<&str, LeafScan> = BTreeMap::new();
        // (value, node, cue, is an object member): a member's key findings
        // are recorded when the member is visited, right before its value
        let mut stack: Vec<(&mut Value, usize, Option<&str>, bool)> = vec![(value, 0, None, false)];
        while let Some((v, node, cue, member)) = stack.pop() {
            if member {
                if let Some(scan) = cue.and_then(|k| key_scans.get(k)) {
                    report.record(&nodes, node, scan, true);
                }
            }
            if let Value::Number(n) = &*v {
                if self.numeric_leaves {
                    let scan = self.scan_leaf(cue, &n.to_string());
                    report.record(&nodes, node, &scan, false);
                    if let Some(masked) = scan.masked {
                        *v = Value::String(masked);
                    }
                }
                continue;
            }
            match v {
                Value::String(s) => {
                    let scan = self.scan_leaf(cue, s);
                    report.record(&nodes, node, &scan, false);
                    if let Some(masked) = scan.masked {
                        *s = masked;
                    }
                }
                Value::Array(items) => {
                    let mut children = Vec::with_capacity(items.len());
                    for (i, child) in items.iter_mut().enumerate() {
                        nodes.push((node, Segment::Index(i)));
                        children.push((child, nodes.len() - 1, cue, false));
                    }
                    // reversed: children pop in document order
                    stack.extend(children.into_iter().rev());
                }
                Value::Object(map) => {
                    let mut children = Vec::with_capacity(map.len());
                    for (key, child) in map.iter_mut() {
                        let scan = key_scans
                            .entry(key.as_str())
                            .or_insert_with(|| self.scan_leaf(None, key));
                        let segment = match &scan.masked {
                            Some(masked) => Segment::Key(Cow::Owned(masked.clone())),
                            None => Segment::Key(Cow::Borrowed(key.as_str())),
                        };
                        nodes.push((node, segment));
                        children.push((child, nodes.len() - 1, Some(key.as_str()), true));
                    }
                    stack.extend(children.into_iter().rev());
                }
                Value::Null | Value::Bool(_) | Value::Number(_) => {}
            }
        }
        report
    }

    /// Scans one leaf (secrets first, then PII), with the tail of `cue`
    /// ([`cue_tail`]) as the synthetic `"{cue}: "` prefix.
    fn scan_leaf(&self, cue: Option<&str>, value: &str) -> LeafScan {
        self.scan_line(cue.map(cue_tail), value)
    }

    /// [`Self::scan_leaf`] with `cue` used as given.
    fn scan_line(&self, cue: Option<&str>, value: &str) -> LeafScan {
        let mut scan = LeafScan::default();
        let prefix = cue.map_or(0, |k| k.len() + 2);
        let mut line = String::with_capacity(prefix + value.len());
        if let Some(k) = cue {
            line.push_str(k);
            line.push_str(": ");
        }
        line.push_str(value);

        // 1) secrets, on the synthetic line (the key is a cue for them
        // too), raw and normalized view (the shared masking spans)
        let mut secrets: Vec<SecretFinding> = Vec::new();
        for f in find_secret_mask_spans(&line) {
            if f.start >= f.end {
                // the zero-length health marker of a secrets-engine error:
                // the leaf was not fully checked for secrets
                scan.errors += 1;
                continue;
            }
            if f.end <= prefix {
                continue; // entirely inside the key cue
            }
            secrets.push(SecretFinding {
                start: f.start.max(prefix) - prefix,
                end: f.end - prefix,
                ..f
            });
        }
        if scan.errors > 0 {
            scan.kinds.push(JsonFindingKind::ScanIncomplete);
            scan.masked = Some(SCAN_INCOMPLETE_MASK.to_owned());
            return scan;
        }
        scan.kinds
            .extend(secrets.iter().map(|s| JsonFindingKind::Secret(s.vendor)));
        let masked_secrets = if secrets.is_empty() {
            Cow::Borrowed(value)
        } else {
            Cow::Owned(mask_findings(value, &secrets, None))
        };

        // 2) PII on the secret-masked line, shifted back into the value
        line.truncate(prefix);
        line.push_str(&masked_secrets);
        let found = self.detector.scan(&line);
        scan.errors += found.engine_errors;
        let mut shifted = ScanReport {
            entities: Vec::with_capacity(found.entities.len()),
            engine_errors: found.engine_errors,
            error_spans: Vec::new(),
        };
        for e in found.entities {
            if e.end <= prefix {
                continue; // a finding inside the key cue itself
            }
            let (start, end) = (e.start.max(prefix) - prefix, e.end - prefix);
            scan.kinds.push(JsonFindingKind::Pii(e.kind));
            shifted.entities.push(Entity {
                start,
                end,
                text: masked_secrets[start..end].to_owned(),
                ..e
            });
        }
        for (s, e) in found.error_spans {
            if e > prefix {
                shifted
                    .error_spans
                    .push((s.max(prefix) - prefix, e - prefix));
            }
        }
        if !shifted.error_spans.is_empty() {
            scan.kinds.push(JsonFindingKind::ScanIncomplete);
        }
        if !secrets.is_empty() || !shifted.entities.is_empty() || !shifted.error_spans.is_empty() {
            scan.masked = Some(
                self.detector
                    .mask_style()
                    .redact_scan(&masked_secrets, &shifted),
            );
        }
        scan
    }
}

impl Default for JsonRedactor<'_> {
    /// Same as [`JsonRedactor::new`].
    fn default() -> Self {
        Self::new()
    }
}

/// The result of one leaf scan.
#[derive(Debug, Default)]
struct LeafScan {
    /// The masked leaf, when anything was masked.
    masked: Option<String>,
    /// One kind per finding, in leaf order (secrets, then PII).
    kinds: Vec<JsonFindingKind>,
    /// Engine errors hit while scanning the leaf.
    errors: usize,
}

/// One segment of a pointer: an object member name or an array index.
#[derive(Debug)]
enum Segment<'k> {
    /// An object member; a member name that contains PII is stored masked.
    Key(Cow<'k, str>),
    /// An array element.
    Index(usize),
}

/// The RFC 6901 pointer of `node` (`""` for the root).
fn pointer(nodes: &[(usize, Segment<'_>)], mut node: usize) -> String {
    let mut path: Vec<&Segment<'_>> = Vec::new();
    while node != 0 {
        let (parent, segment) = &nodes[node];
        path.push(segment);
        node = *parent;
    }
    let mut out = String::new();
    for segment in path.iter().rev() {
        out.push('/');
        match segment {
            Segment::Index(i) => out.push_str(&i.to_string()),
            Segment::Key(key) => {
                for c in key.chars() {
                    match c {
                        '~' => out.push_str("~0"),
                        '/' => out.push_str("~1"),
                        c => out.push(c),
                    }
                }
            }
        }
    }
    out
}

/// What [`JsonRedactor::redact`] found: where (RFC 6901 pointers) and what
/// kind, never a value.
///
/// serde (feature `serde`): `Serialize` only (secret vendor labels are
/// `&'static str`; a report is output, never read back).
///
/// # Examples
/// ```
/// use redactify::{JsonFindingKind, JsonRedactor};
/// use serde_json::json;
///
/// let mut doc = json!({"aws": "AKIAIOSFODNN7EXAMPLE"});
/// let report = JsonRedactor::new().redact(&mut doc);
/// assert_eq!(doc, json!({"aws": "[SECRET:AWS_ACCESS_KEY]"}));
/// assert_eq!(report.findings[0].pointer, "/aws");
/// assert_eq!(report.findings[0].kind, JsonFindingKind::Secret("AWS_ACCESS_KEY"));
/// assert!(!report.findings[0].in_key);
/// ```
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct JsonRedactionReport {
    /// Every finding, in walk order: depth first, object members in the
    /// map's iteration order (`serde_json::Map`: sorted by member name
    /// unless serde_json's `preserve_order` feature keeps document order),
    /// each member's key findings directly before the findings inside its
    /// value, array items by index, and within one leaf the secrets before
    /// the PII.
    pub findings: Vec<JsonFinding>,
    /// Engine errors hit during the scan (regex budget exhaustion in the
    /// PII or secrets engines). Non-zero means some leaf was not fully
    /// checked; such a leaf (or the affected line of it) is replaced by
    /// `[SCAN_INCOMPLETE]`.
    pub engine_errors: usize,
}

impl JsonRedactionReport {
    /// `true` when every leaf was scanned without an engine error.
    ///
    /// # Examples
    /// ```
    /// use redactify::JsonRedactor;
    ///
    /// let mut doc = serde_json::json!(["nothing here"]);
    /// assert!(JsonRedactor::new().redact(&mut doc).is_complete());
    /// ```
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.engine_errors == 0
    }

    /// Records the findings of one leaf (or member name) at `node`.
    fn record(
        &mut self,
        nodes: &[(usize, Segment<'_>)],
        node: usize,
        scan: &LeafScan,
        in_key: bool,
    ) {
        self.engine_errors += scan.errors;
        if scan.kinds.is_empty() {
            return;
        }
        let at = pointer(nodes, node);
        self.findings
            .extend(scan.kinds.iter().map(|&kind| JsonFinding {
                pointer: at.clone(),
                kind,
                in_key,
            }));
    }
}

/// One finding of a [`JsonRedactionReport`].
///
/// # Examples
/// ```
/// use redactify::{EntityType, JsonFindingKind, JsonRedactor};
/// use serde_json::json;
///
/// // PII in a member NAME: reported (the pointer segment is masked) but
/// // the key is not rewritten
/// let mut doc = json!({"12345678950": true});
/// let report = JsonRedactor::new().redact(&mut doc);
/// let f = &report.findings[0];
/// assert_eq!(f.pointer, "/[TCKN]");
/// assert_eq!(f.kind, JsonFindingKind::Pii(EntityType::Tckn));
/// assert!(f.in_key);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct JsonFinding {
    /// RFC 6901 pointer of the leaf (or of the member, for a key finding).
    /// Every member name in it that contains PII or a secret is given in
    /// its MASKED form, so a pointer never carries a detected value.
    pub pointer: String,
    /// What was found.
    pub kind: JsonFindingKind,
    /// `true` when the finding is in the member NAME (reported only, the
    /// name is not rewritten), `false` for a value.
    pub in_key: bool,
}

/// The kind of a [`JsonFinding`].
///
/// serde (feature `serde`): `{"PII": "TCKN"}`, `{"SECRET": "AWS_ACCESS_KEY"}`,
/// `"SCAN_INCOMPLETE"`.
///
/// # Examples
/// ```
/// use redactify::{EntityType, JsonFindingKind};
///
/// assert_ne!(JsonFindingKind::Pii(EntityType::Tckn), JsonFindingKind::ScanIncomplete);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "SCREAMING_SNAKE_CASE"))]
#[non_exhaustive]
pub enum JsonFindingKind {
    /// A PII entity of this type.
    Pii(EntityType),
    /// A secret of this vendor/transport label (`AWS_ACCESS_KEY`, ...).
    Secret(&'static str),
    /// The leaf (or one line of it) was not fully scanned (engine error)
    /// and was replaced by `[SCAN_INCOMPLETE]`.
    ScanIncomplete,
}

#[cfg(test)]
mod tests {
    use super::{pointer, JsonFindingKind, JsonRedactor, Segment};
    use crate::{CustomRule, Detector, EntityType};
    use serde_json::{json, Value};
    use std::borrow::Cow;

    #[test]
    fn cue_tail_covers_every_built_in_cue() {
        // a leading cue counts when it ends within CUE_WINDOW characters of
        // the match; `": "` takes 2 of them, so the kept tail must hold the
        // rest of the window plus the whole longest cue of any built-in rule
        use crate::pii::locales::{rules_for_locales, ContextPolicy};
        let longest = rules_for_locales(crate::SUPPORTED_LOCALES)
            .iter()
            .filter_map(|r| match r.context {
                ContextPolicy::RequiredCue(c) | ContextPolicy::Boost(c, _) => Some(c),
                ContextPolicy::None => None,
            })
            .flatten()
            .map(|c| c.chars().count())
            .max()
            .unwrap_or(0);
        assert!(
            super::CUE_TAIL_CHARS >= crate::pii::CUE_WINDOW - 2 + longest,
            "CUE_TAIL_CHARS {} < window {} - 2 + longest cue {longest}",
            super::CUE_TAIL_CHARS,
            crate::pii::CUE_WINDOW
        );
    }

    #[test]
    fn pointer_escapes_tilde_and_slash() {
        let nodes = vec![
            (0, Segment::Index(0)),
            (0, Segment::Key(Cow::Borrowed("a/b~c"))),
            (1, Segment::Index(3)),
            (2, Segment::Key(Cow::Borrowed(""))),
        ];
        assert_eq!(pointer(&nodes, 0), "");
        assert_eq!(pointer(&nodes, 1), "/a~1b~0c");
        assert_eq!(pointer(&nodes, 3), "/a~1b~0c/3/");
    }

    #[test]
    fn engine_error_in_a_leaf_masks_that_line() {
        let rule = CustomRule::new(EntityType::Itin, r"(?i)(a|b|ab)*(?>c)").unwrap();
        let rules = [&rule];
        let bad = format!("{} c", "ab".repeat(40));
        // (no other `c` anywhere: the custom pattern matches nothing else)
        let mut doc = json!({"x": format!("kimlik 12345678950\n{bad}"), "y": "fine"});
        let report = JsonRedactor::new()
            .with_detector(Detector::new().with_custom_rules(&rules))
            .redact(&mut doc);
        assert!(!report.is_complete());
        assert_eq!(doc["x"], json!("kimlik [TCKN]\n[SCAN_INCOMPLETE]"));
        assert_eq!(doc["y"], json!("fine"));
        let kinds: Vec<JsonFindingKind> = report.findings.iter().map(|f| f.kind).collect();
        assert_eq!(
            kinds,
            vec![
                JsonFindingKind::Pii(EntityType::Tckn),
                JsonFindingKind::ScanIncomplete
            ]
        );
    }

    #[test]
    fn root_scalar_leaf_has_the_empty_pointer() {
        let mut doc = Value::String("mail a@b.com".into());
        let report = JsonRedactor::new().redact(&mut doc);
        assert_eq!(doc, json!("mail [EMAIL]"));
        assert_eq!(report.findings[0].pointer, "");
    }

    #[test]
    fn cue_tail_keeps_the_last_64_chars_on_a_char_boundary() {
        use super::{cue_tail, CUE_TAIL_CHARS};
        assert_eq!(CUE_TAIL_CHARS, 64);
        assert_eq!(cue_tail(""), "");
        assert_eq!(cue_tail("vergi_no"), "vergi_no");
        let exact = "x".repeat(64);
        assert_eq!(cue_tail(&exact), exact);
        // multibyte chars count as one each and are never split
        let long = format!("{}{}", "\u{e7}".repeat(10), "y".repeat(63));
        assert_eq!(cue_tail(&long), format!("\u{e7}{}", "y".repeat(63)));
        assert_eq!(cue_tail(&long).chars().count(), 64);
    }

    #[test]
    fn the_cue_tail_line_scans_like_the_full_key_line() {
        // equivalence: for member names far longer than the tail,
        // with the cue at every distance the built-in rules can reach,
        // the tail line gives the full-key line's result
        let aws_cue = format!("aws{}secret{}", "a".repeat(30), "b".repeat(19));
        let cues = [
            "vergi_no",
            "tckn",
            "TC Kimlik No",
            "aws_secret_access_key",
            aws_cue.as_str(),
            "patient mrn",
            "medical record number",
            "password",
            "api key",
            "client_secret",
            "Authorization",
            "the access token for prod",
            "telefon",
            "iban",
            "x",
            "",
        ];
        let values = [
            "1234567890",
            "12345678950",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "Bearer AbCdEf123456789012345678",
            "12345678",
            "hunter2secure42!",
            "3q2+7wJalrXUtnFEMIK7MDENGbPxRfiCY",
            "0532 123 45 67",
            "TR33 0006 1005 1978 6457 8413 26",
            "a@b.com",
            "plain words",
            "",
        ];
        let pads = ["", "z", "word word ", "\u{e7}\u{11f}\u{131}", "k"];
        let r = JsonRedactor::new();
        let mut compared = 0;
        for pad in pads {
            for reps in [1usize, 80, 1_000] {
                let head = pad.repeat(reps);
                for cue in cues {
                    let key = format!("{head}{cue}");
                    for value in values {
                        let full = r.scan_line(Some(&key), value);
                        let tail = r.scan_leaf(Some(&key), value);
                        assert_eq!(
                            (&full.masked, &full.kinds, full.errors),
                            (&tail.masked, &tail.kinds, tail.errors),
                            "key {key:?} value {value:?}"
                        );
                        compared += 1;
                    }
                }
            }
        }
        assert!(compared > 2_000);
    }

    #[test]
    fn secret_placeholders_render_like_the_replace_spans_reference() {
        // JSON leaves render secret placeholders through
        // secrets::mask_findings; it must agree with replace_spans and
        // `format!("[SECRET:{vendor}]")` (label = vendor, rank 0) on
        // overlapping, nested, adjacent, unsorted, empty and invalid spans.
        use crate::guard::secrets::{mask_findings, SecretFinding};
        use crate::pii::replace_spans;
        let f = |start, end, vendor| SecretFinding {
            start,
            end,
            vendor,
            score: 0.9,
        };
        let value = "ab\u{e7}def AKIA x\u{11f}y tail";
        let cases: Vec<Vec<SecretFinding>> = vec![
            vec![],
            vec![f(0, 2, "A")],
            vec![f(0, 4, "A"), f(4, 7, "B")],
            vec![f(0, 6, "A"), f(4, 12, "B")],
            vec![f(8, 12, "B"), f(0, 3, "A")],
            vec![f(0, 20, "OUTER"), f(5, 9, "INNER")],
            vec![f(5, 9, "SAME"), f(5, 9, "TIE")],
            vec![f(0, 0, "SCAN_ERROR"), f(8, 12, "B")],
            vec![f(3, 3, "EMPTY"), f(2, 3, "OFF_BOUNDARY"), f(9, 400, "OUT")],
        ];
        for spans in cases {
            let expected_out =
                replace_spans(value, &spans, |vendor, _| format!("[SECRET:{vendor}]"));
            assert_eq!(
                mask_findings(value, &spans, None),
                expected_out,
                "{spans:?}"
            );
        }
    }
}
