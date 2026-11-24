//! The detection builder: ONE configurable entry point for detection,
//! redaction, scan reports and reversible pseudonymization.
//!
//! [`Detector`] collects every detection option (locales, threshold, NER
//! recognizers, custom rules, an allowlist, encoding-evasion
//! normalization, the mask style) in one builder and runs them through
//! the single detection engine.

use std::borrow::Cow;
use std::fmt;

use super::mask::MaskStyle;
use crate::guard::normalize::{
    align_for_scan_with, align_line, normalize_for_scan, LineAlignment, ScanAlignment,
};
use crate::pii::{
    run, CustomRule, DetectionView, EngineOpts, EngineOutput, Entity, EntityType, Explanation,
    NerRecognizer, Vault,
};

/// Configurable PII detector (builder).
///
/// Every setter consumes and returns the builder; a terminal method
/// ([`detect`](Self::detect), [`redact`](Self::redact),
/// [`scan`](Self::scan), [`pseudonymize`](Self::pseudonymize)) runs the engine.
/// A `Detector` borrows its inputs and is cheap to clone, so one value can
/// serve many texts.
///
/// Lifetime note: the slices passed to the setters must outlive the
/// detector. Bind a recognizer list to a local before handing it over
/// (`let rec = [&ner as &dyn NerRecognizer];` then `.with_ner(&rec)`); a
/// temporary array only lives until the end of its statement.
///
/// `Debug` never prints allowlisted values or context texts (they may be
/// PII): it shows the locales, threshold, recognizer names, the
/// custom-rule, allowlist and context COUNTS, the normalization flag and
/// the mask style.
///
/// # Examples
/// ```
/// use redactify::{Detector, EntityType, MockNameRecognizer, NerRecognizer};
///
/// let ner = MockNameRecognizer::new();
/// let rec = [&ner as &dyn NerRecognizer];
/// let detector = Detector::new().with_locales(&["tr"]).with_ner(&rec);
///
/// let text = "we met Ahmet Yilmaz today, TCKN 12345678950";
/// let kinds: Vec<EntityType> = detector.detect(text).iter().map(|e| e.kind).collect();
/// assert_eq!(kinds, vec![EntityType::Name, EntityType::Tckn]);
/// assert_eq!(detector.redact(text), "we met [NAME] today, TCKN [TCKN]");
/// ```
#[derive(Clone)]
#[must_use = "a Detector does nothing until a terminal method runs"]
pub struct Detector<'a> {
    /// Locale codes (empty = the default tr+en set).
    locales: Cow<'a, [&'a str]>,
    /// Minimum score, applied inside overlap resolution.
    threshold: f32,
    /// NER recognizers (see the whole text).
    ner: &'a [&'a dyn NerRecognizer],
    /// User-defined custom rules (owned when a guard adds its policy's
    /// rules to the caller's).
    custom: Cow<'a, [&'a CustomRule]>,
    /// Allowlisted values (pre-filter on the exact candidate text, before
    /// overlap resolution).
    ignored: &'a [&'a str],
    /// Entity types that are never reported (dropped before overlap
    /// resolution).
    ignored_types: &'a [EntityType],
    /// Caller-supplied context texts whose cues unlock cue-gated rules.
    context: &'a [&'a str],
    /// Also scan the normalized (NFKC, invisible-stripped) view (default
    /// on).
    normalize: bool,
    /// How [`Detector::redact`] renders spans.
    mask: MaskStyle,
}

impl<'a> Detector<'a> {
    /// A detector with the defaults: the tr+en locale set, no threshold,
    /// no recognizers, no custom rules, no allowlist, the normalization
    /// pass ON (see [`with_normalization`](Self::with_normalization)),
    /// [`MaskStyle::Label`].
    ///
    /// # Examples
    /// ```
    /// use redactify::Detector;
    ///
    /// assert_eq!(Detector::new().redact("mail a@b.com"), "mail [EMAIL]");
    /// ```
    pub const fn new() -> Self {
        Self {
            locales: Cow::Borrowed(&[]),
            threshold: 0.0,
            ner: &[],
            custom: Cow::Borrowed(&[]),
            ignored: &[],
            ignored_types: &[],
            context: &[],
            normalize: true,
            mask: MaskStyle::Label,
        }
    }

    /// Runs the rules of these locale packs. The locale-independent rules
    /// (IBAN, VIN, credit card, e-mail, IP address, URL, SWIFT/BIC,
    /// international `+CC` phone numbers, IMEI, Bitcoin and Ethereum
    /// addresses) are always included; an EMPTY
    /// slice selects the default tr+en set.
    ///
    /// Codes are matched exactly against [`crate::SUPPORTED_LOCALES`]: an
    /// unknown, miscased or padded code (`"TR"`, `"tr "`) selects no pack,
    /// and a non-empty list of only such codes turns the tr+en default
    /// off. Validate codes that come from users against that list (the
    /// REST, MCP, CLI and TOML-policy surfaces reject them).
    ///
    /// # Examples
    /// ```
    /// use redactify::Detector;
    ///
    /// assert_eq!(
    ///     Detector::new().with_locales(&["uk"]).redact("nhs 9434765870"),
    ///     "nhs [UK_NHS]"
    /// );
    /// // the uk pack is opt-in: the default set leaves the value alone
    /// assert_eq!(Detector::new().redact("nhs 9434765870"), "nhs 9434765870");
    /// ```
    pub fn with_locales(mut self, locales: &'a [&'a str]) -> Self {
        self.locales = Cow::Borrowed(locales);
        self
    }

    /// Drops detections scoring below `threshold`. The cutoff applies
    /// INSIDE overlap resolution: a below-threshold candidate cannot
    /// swallow an overlapping above-threshold one. A NaN score (from a
    /// recognizer or a custom rule) or a NaN threshold never drops a
    /// detection: the comparison fails safe, toward masking.
    ///
    /// # Examples
    /// ```
    /// use redactify::Detector;
    ///
    /// // a "plaka" cue nearby scores 0.95; a bare plate 0.85
    /// let strict = Detector::new().with_threshold(0.9);
    /// assert_eq!(strict.detect("Plaka 34 ABC 123 kayitli").len(), 1);
    /// assert!(strict.detect("yolda 34 ABC 123 var").is_empty());
    /// ```
    pub fn with_threshold(mut self, threshold: f32) -> Self {
        self.threshold = threshold;
        self
    }

    /// Adds NER recognizers. They see the whole text; their spans compete
    /// with the rule findings in the same overlap resolution (a
    /// checksum-validated identifier always beats a model span).
    ///
    /// # Examples
    /// ```
    /// use redactify::{Detector, MockNameRecognizer, NerRecognizer};
    ///
    /// let ner = MockNameRecognizer::new();
    /// let rec = [&ner as &dyn NerRecognizer];
    /// // a name outside the Turkish name lexicon (`tr::person`)
    /// let text = "we met Jean Dupont yesterday.";
    /// assert!(Detector::new().detect(text).is_empty());
    /// assert_eq!(
    ///     Detector::new().with_ner(&rec).redact(text),
    ///     "we met [NAME] yesterday."
    /// );
    /// ```
    pub fn with_ner(mut self, ner: &'a [&'a dyn NerRecognizer]) -> Self {
        self.ner = ner;
        self
    }

    /// Adds user-defined custom rules; their matches join the built-in
    /// candidates in one overlap resolution.
    ///
    /// # Examples
    /// ```
    /// use redactify::{CustomRule, Detector, EntityType};
    ///
    /// let rule = CustomRule::new(EntityType::Itin, r"ORC-\d{4,6}").unwrap();
    /// let rules = [&rule];
    /// let ents = Detector::new().with_custom_rules(&rules).detect("bkz ORC-12345 detay");
    /// assert!(ents.iter().any(|e| e.text == "ORC-12345"));
    /// ```
    pub fn with_custom_rules(mut self, rules: &'a [&'a CustomRule]) -> Self {
        self.custom = Cow::Borrowed(rules);
        self
    }

    /// [`with_custom_rules`](Self::with_custom_rules) over an owned list
    /// (a guard's own rules followed by its policy's).
    pub(crate) fn with_custom_rule_refs(mut self, rules: Vec<&'a CustomRule>) -> Self {
        self.custom = Cow::Owned(rules);
        self
    }

    /// Allowlist: a candidate whose exact text equals one of these values
    /// is dropped (and therefore stays unmasked), together with every
    /// candidate lying entirely inside it - the allowlisted value as a
    /// whole is not PII, so neither is any part of it.
    ///
    /// The allowlist is applied BEFORE overlap resolution, like the
    /// threshold: an allowlisted value that would have won an overlap no
    /// longer hides the overlapping candidate it would have beaten. With
    /// normalization on, the normalized-view pass compares the normalized
    /// form of each value, so a fullwidth or zero-width-scattered spelling
    /// of an allowlisted value is allowlisted too.
    ///
    /// # Examples
    /// ```
    /// use redactify::Detector;
    ///
    /// let out = Detector::new()
    ///     .with_ignored(&["0532 123 45 67"])
    ///     .redact("Destek: 0532 123 45 67, TCKN 12345678950");
    /// assert_eq!(out, "Destek: 0532 123 45 67, TCKN [TCKN]");
    /// ```
    pub fn with_ignored(mut self, values: &'a [&'a str]) -> Self {
        self.ignored = values;
        self
    }

    /// Entity types this detector never reports (a policy's `Ignore`
    /// entity action, see [`EntityAction`](crate::policy::EntityAction)):
    /// their candidates are dropped before overlap resolution, so, unlike an
    /// allowlisted value, an ignored type hides nothing - an overlapping
    /// candidate of another type is reported as if the ignored one had
    /// never matched.
    ///
    /// # Examples
    /// ```
    /// use redactify::{Detector, EntityType};
    ///
    /// let out = Detector::new()
    ///     .with_ignored_types(&[EntityType::Email])
    ///     .redact("mail a@b.com, TCKN 12345678950");
    /// assert_eq!(out, "mail a@b.com, TCKN [TCKN]");
    /// ```
    pub fn with_ignored_types(mut self, kinds: &'a [EntityType]) -> Self {
        self.ignored_types = kinds;
        self
    }

    /// Context texts the scanned text answers, for example the previous
    /// turn of a chat or call transcript (`"What is your tax number?"`).
    /// A rule that needs a cue (or whose score a cue raises) also accepts
    /// a cue found ANYWHERE in these texts when the value's own line has
    /// none, under the same matching rules (Turkish case folding, the
    /// word-start rule for short cues). Validators still apply: a context
    /// cue never makes a failing checksum pass. There is no distance
    /// limit, so pass only the text the input actually answers: every
    /// cue-gated pattern match in the scanned text can use it. Context
    /// texts are read as given (they are not normalized) and are never
    /// echoed in results.
    ///
    /// # Examples
    /// ```
    /// use redactify::Detector;
    ///
    /// // the cue sits in the question, the answer is the bare number
    /// assert_eq!(Detector::new().redact("1234567890"), "1234567890");
    /// let turn = ["Vergi numaranizi yazar misiniz?"];
    /// assert_eq!(Detector::new().with_context(&turn).redact("1234567890"), "[VKN]");
    /// ```
    pub fn with_context(mut self, texts: &'a [&'a str]) -> Self {
        self.context = texts;
        self
    }

    /// Whether to also scan the normalized view (NFKC folding +
    /// invisible-character stripping) and map its findings back to
    /// raw-text spans, so encoding evasions (fullwidth digits, zero-width
    /// scatter) are found and masked too. ON by default. Findings of both
    /// views compete in one overlap resolution: a longer or
    /// higher-priority normalized finding replaces an overlapping raw
    /// fragment, and a value found identically on both views is reported
    /// once (as the raw finding). A line whose normalized view cannot be
    /// aligned with the raw text is reported as not fully scanned
    /// ([`ScanReport::error_spans`]). Text that is its own normalized form
    /// (every ASCII text) costs one pass, as without normalization.
    /// `with_normalization(false)` scans the raw text only.
    ///
    /// # Examples
    /// ```
    /// use redactify::Detector;
    ///
    /// // TCKN digits scattered with zero-width spaces
    /// let text = "TCKN 1\u{200B}2345678950";
    /// assert_eq!(Detector::new().redact(text), "TCKN [TCKN]");
    /// // the raw text alone does not show a TCKN
    /// assert_eq!(Detector::new().with_normalization(false).redact(text), text);
    /// ```
    pub fn with_normalization(mut self, on: bool) -> Self {
        self.normalize = on;
        self
    }

    /// Selects how [`redact`](Self::redact) renders detected spans.
    ///
    /// # Examples
    /// ```
    /// use redactify::{Detector, MaskStyle};
    ///
    /// let d = Detector::new().with_mask_style(MaskStyle::Template("<<{type}>>".into()));
    /// assert_eq!(d.redact("TCKN 12345678950"), "TCKN <<TCKN>>");
    /// ```
    pub fn with_mask_style(mut self, style: MaskStyle) -> Self {
        self.mask = style;
        self
    }

    /// Returns the validated, non-overlapping entities, sorted by start
    /// offset (byte offsets into `text`).
    ///
    /// # Examples
    /// ```
    /// use redactify::{Detector, EntityType};
    ///
    /// let ents = Detector::new().detect("Beni 0532 123 45 67'den ara.");
    /// assert_eq!(ents[0].kind, EntityType::Phone);
    /// assert_eq!(&ents[0].text, "0532 123 45 67");
    /// ```
    #[must_use]
    pub fn detect(&self, text: &str) -> Vec<Entity> {
        self.scan(text).entities
    }

    /// Detects and masks with the configured [`MaskStyle`]. A line on
    /// which the engine hit a runtime error (it was not fully scanned) is
    /// replaced as a whole with `[SCAN_INCOMPLETE]` (see
    /// [`MaskStyle::redact_scan`]): unchecked text never passes through.
    ///
    /// # Examples
    /// ```
    /// use redactify::Detector;
    ///
    /// assert_eq!(
    ///     Detector::new().redact("TCKN'm 12345678950, mail a@b.com"),
    ///     "TCKN'm [TCKN], mail [EMAIL]"
    /// );
    /// ```
    #[must_use]
    pub fn redact(&self, text: &str) -> String {
        self.mask.redact_scan(text, &self.scan(text))
    }

    /// Detects and reports engine health alongside the entities: a regex
    /// runtime error (e.g. an exhausted backtrack budget) on some line
    /// means that line was not fully scanned, and
    /// [`ScanReport::is_complete`] returns `false`.
    ///
    /// # Examples
    /// ```
    /// use redactify::Detector;
    ///
    /// let report = Detector::new().scan("TCKN 12345678950");
    /// assert!(report.is_complete());
    /// assert_eq!(report.entities.len(), 1);
    /// ```
    #[must_use]
    pub fn scan(&self, text: &str) -> ScanReport {
        let out = self.run_views(text, false);
        ScanReport {
            entities: out.entities,
            engine_errors: out.engine_errors,
            error_spans: out.error_spans,
        }
    }

    /// Detects like [`detect`](Self::detect) and explains every entity:
    /// which rule, custom rule or recognizer produced it, whether a
    /// validator accepted it, which configured cue was found, its base and
    /// final score, and which view (raw or normalized) it was found on.
    /// The entities are exactly the [`detect`](Self::detect) result, in
    /// the same order; explanations are only built on this path.
    ///
    /// # Examples
    /// ```
    /// use redactify::{DetectionSource, Detector};
    ///
    /// let explained = Detector::new().explain("Plaka 34 ABC 123, mail a@b.com");
    /// let (plate, why) = &explained[0];
    /// assert_eq!(plate.text, "34 ABC 123");
    /// assert_eq!(why.source, DetectionSource::Rule { id: "tr::plaka" });
    /// // a nearby "plaka" cue boosts the structural base score
    /// assert_eq!(why.cue.as_deref(), Some("plaka"));
    /// assert!(why.score > why.base_score);
    /// assert_eq!(explained[1].1.source, DetectionSource::Rule { id: "generic::email" });
    /// ```
    #[must_use]
    pub fn explain(&self, text: &str) -> Vec<(Entity, Explanation)> {
        let out = self.run_views(text, true);
        out.entities.into_iter().zip(out.explanations).collect()
    }

    /// Reversible pseudonymization: every detected entity is replaced by a
    /// numbered placeholder (`[TCKN_1]`, `[EMAIL_1]`, ...; the same value
    /// always gets the same placeholder) and the returned [`Vault`]
    /// restores the originals. The mask style does not apply here.
    ///
    /// # Examples
    /// ```
    /// use redactify::Detector;
    ///
    /// let text = "IdNr 86095742719 in der Akte";
    /// let (anon, vault) = Detector::new().with_locales(&["de"]).pseudonymize(text);
    /// assert_eq!(anon, "IdNr [DE_TAX_ID_1] in der Akte");
    /// assert_eq!(vault.restore(&anon), text);
    /// ```
    #[must_use]
    pub fn pseudonymize(&self, text: &str) -> (String, Vault) {
        Vault::pseudonymize_entities(text, &self.detect(text))
    }

    /// The configured mask style (for maskers that build their own scan
    /// report, e.g. the JSON redactor).
    pub(crate) const fn mask_style(&self) -> &MaskStyle {
        &self.mask
    }

    /// The engine options of this builder.
    fn engine_opts(&self) -> EngineOpts<'_> {
        EngineOpts {
            locales: &self.locales,
            threshold: self.threshold,
            ner: self.ner,
            custom: &self.custom,
            ignored: self.ignored,
            ignored_types: self.ignored_types,
            context: self.context,
            ..EngineOpts::default()
        }
    }

    /// The raw engine pass plus, with normalization on, the normalized-view
    /// pass; entities (and explanations, when requested) sorted by start.
    fn run_views(&self, text: &str, explain: bool) -> EngineOutput {
        let opts = EngineOpts {
            explain,
            ..self.engine_opts()
        };
        let mut out = run(text, &opts);
        if self.normalize {
            add_normalized_pass(text, &opts, &mut out);
        }
        out
    }
}

impl Default for Detector<'_> {
    /// Same as [`Detector::new`].
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Detector<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ner: Vec<&str> = self.ner.iter().map(|r| r.name()).collect();
        f.debug_struct("Detector")
            .field("locales", &self.locales)
            .field("threshold", &self.threshold)
            .field("ner", &ner)
            .field("custom_rules", &self.custom.len())
            .field("ignored", &self.ignored.len())
            .field("ignored_types", &self.ignored_types)
            .field("context", &self.context.len())
            .field("normalize", &self.normalize)
            .field("mask", &self.mask)
            .finish()
    }
}

/// The second pass of a normalization-aware scan: detection on the
/// normalized view, with every finding translated back into raw-text
/// coordinates (a span START inside a multi-char normalization cluster
/// maps to the cluster's raw start, a span END to its raw end, so neither
/// side under-masks). The translated findings join the raw findings in
/// the engine's overlap resolution ([`EngineOutput::merge_view`]): a
/// longer or higher-priority normalized finding replaces an overlapping
/// raw fragment (e.g. a zero-width-split IBAN beats the card-shaped digits
/// after the split), and an exact tie keeps the raw finding. Engine
/// errors of this pass are added to the output, their line spans mapped
/// back as well.
///
/// Fail closed: a line whose normalized view cannot be aligned with the
/// raw text (defensive; see
/// [`normalize_for_scan_with_map`](crate::normalize::normalize_for_scan_with_map)) is not
/// silently skipped - it counts as one engine error and its raw span is
/// reported as not fully scanned, so every masking path replaces it with
/// `[SCAN_INCOMPLETE]`. Alignment is line-local, so a streaming scan of
/// the same line reaches the same verdict.
///
/// Fast path: a text that is its own normalized form (every ASCII text
/// is: NFKC, invisible stripping and confusable folding only change
/// non-ASCII characters) costs no second pass and no offset map.
fn add_normalized_pass(text: &str, opts: &EngineOpts<'_>, out: &mut EngineOutput) {
    add_normalized_pass_with(text, opts, out, align_line);
}

/// [`add_normalized_pass`] with the per-line aligner as a parameter (the
/// fail-closed tests inject a failing one).
fn add_normalized_pass_with(
    text: &str,
    opts: &EngineOpts<'_>,
    out: &mut EngineOutput,
    align: impl Fn(&str) -> Option<LineAlignment>,
) {
    if text.is_ascii() || normalize_for_scan(text) == text {
        return;
    }
    let view = align_for_scan_with(text, align);
    // the allowlist compares values in the view being scanned: normalize
    // the configured values the same way as the text
    let ignored_norm: Vec<String> = opts.ignored.iter().map(|v| normalize_for_scan(v)).collect();
    let ignored: Vec<&str> = ignored_norm.iter().map(String::as_str).collect();
    let pass = run(
        &view.normalized,
        &EngineOpts {
            ignored: &ignored,
            ..*opts
        },
    );
    let (entities, explanations) = translate(text, &view, pass.entities, pass.explanations);
    out.merge_view(entities, opts.explain.then_some(explanations));
    out.engine_errors += pass.engine_errors;
    for (s, e) in pass.error_spans {
        let start = view.start.get(s).copied().unwrap_or(0);
        let end = view.end.get(e).copied().unwrap_or(text.len());
        out.error_spans.push((start, end));
    }
    for &span in &view.unaligned {
        out.engine_errors += 1;
        out.error_spans.push(span);
    }
    out.error_spans.sort_unstable();
    out.error_spans.dedup();
}

/// Translates the normalized pass's entities (sorted by start, each with
/// its explanation when requested) into raw-text coordinates.
///
/// Two findings that were disjoint in the normalized view stay disjoint:
/// when they share one multi-char cluster (one ends and the next starts
/// inside it), the later one starts at the earlier one's raw end instead
/// of the cluster start, and a finding left with an empty raw span (it
/// lay entirely inside a cluster the earlier finding already covers) is
/// dropped. Explanations are re-tagged with the normalized view.
fn translate(
    text: &str,
    view: &ScanAlignment,
    entities: Vec<Entity>,
    explanations: Vec<Explanation>,
) -> (Vec<Entity>, Vec<Explanation>) {
    let raw_end = |e: &Entity| view.end.get(e.end).copied();
    // (normalized end, raw end) of every finding, by normalized end: the
    // findings that END before a given normalized start form a prefix
    let mut ends: Vec<(usize, usize)> = entities
        .iter()
        .filter_map(|e| raw_end(e).map(|r| (e.end, r)))
        .collect();
    ends.sort_unstable();
    let mut done = 0usize; // ends[..done] end at or before the current start
    let mut covered = 0usize; // largest raw end among them
    let mut whys = explanations.into_iter();
    let mut out_entities = Vec::with_capacity(entities.len());
    let mut out_whys = Vec::new();
    for e in entities {
        // aligned with the entities whenever explanations were requested
        let why = whys.next();
        while let Some(&(norm_end, raw)) = ends.get(done) {
            if norm_end > e.start {
                break;
            }
            covered = covered.max(raw);
            done += 1;
        }
        let (Some(&s), Some(end)) = (view.start.get(e.start), raw_end(&e)) else {
            continue;
        };
        let s = s.max(covered.min(end));
        let (s, end) = crate::guard::normalize::trim_directional_edges(text, s, end);
        if s >= end || end > text.len() || !text.is_char_boundary(s) || !text.is_char_boundary(end)
        {
            continue;
        }
        out_entities.push(Entity {
            start: s,
            end,
            text: text[s..end].to_owned(),
            ..e
        });
        if let Some(mut why) = why {
            why.view = DetectionView::Normalized;
            out_whys.push(why);
        }
    }
    (out_entities, out_whys)
}

/// The result of [`Detector::scan`]: the entities plus the engine's
/// health for this text.
///
/// serde (feature `serde`): `Serialize` only - a report is engine output,
/// never read back.
///
/// # Examples
/// ```
/// use redactify::Detector;
///
/// let report = Detector::new().scan("mail a@b.com");
/// assert!(report.is_complete());
/// assert_eq!(report.engine_errors, 0);
/// assert!(report.error_spans.is_empty());
/// assert_eq!(report.entities[0].text, "a@b.com");
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct ScanReport {
    /// The detected entities (same as [`Detector::detect`]).
    pub entities: Vec<Entity>,
    /// Number of regex runtime errors (e.g. an exhausted backtrack budget)
    /// hit during the scan, plus one per line whose normalized view could
    /// not be aligned with the raw text (defensive, see
    /// [`Detector::with_normalization`]). Non-zero means some part of the
    /// text was not fully checked.
    pub engine_errors: usize,
    /// Byte span `[start, end)` of every line that was not fully scanned
    /// (sorted, one entry per affected line).
    pub error_spans: Vec<(usize, usize)>,
}

impl ScanReport {
    /// `true` when the whole text was scanned without an engine error.
    ///
    /// # Examples
    /// ```
    /// use redactify::Detector;
    ///
    /// assert!(Detector::new().scan("nothing here").is_complete());
    /// ```
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.engine_errors == 0
    }
}

/// Returns the validated, non-overlapping PII entities in `text`, sorted
/// by start (byte offsets into `text`): the default [`Detector`] - tr+en
/// locale set, the normalization pass on, no threshold, no recognizers.
/// Same as `Detector::new().detect(text)`.
///
/// Flow: every rule of the locale set collects candidates per line ->
/// validator (checksum/structure) -> context policy (required cue or
/// confidence boost) -> overlap resolution (the more specific type first,
/// then the longer span). The normalized view (NFKC folding, invisible
/// characters stripped) is scanned too and its findings are mapped back
/// onto the raw text, so fullwidth digits or zero-width scatter do not
/// hide an identifier.
///
/// # Examples
/// ```
/// use redactify::{detect, EntityType};
///
/// let ents = detect("TCKN 12345678950, mail a@b.com");
/// let kinds: Vec<_> = ents.iter().map(|e| e.kind).collect();
/// assert_eq!(kinds, vec![EntityType::Tckn, EntityType::Email]);
/// assert!(detect("").is_empty());
///
/// // typed spans, byte offsets into the input
/// let ents = detect("Beni 0532 123 45 67'den ara.");
/// assert_eq!(ents[0].kind, EntityType::Phone);
/// assert_eq!(&ents[0].text, "0532 123 45 67");
///
/// // a zero-width space inside the digits does not hide the TCKN; the
/// // span covers the raw characters
/// let ents = detect("TCKN 1\u{200B}2345678950");
/// assert_eq!(ents[0].text, "1\u{200B}2345678950");
/// ```
#[must_use]
pub fn detect(text: &str) -> Vec<Entity> {
    Detector::new().detect(text)
}

/// Replaces detected PII with `[TYPE]` labels: the default [`Detector`]
/// (see [`detect`]), same as `Detector::new().redact(text)`. A line the
/// engine could not scan completely is replaced by `[SCAN_INCOMPLETE]`.
///
/// For options - other locale packs, NER recognizers, an allowlist, a
/// different [`MaskStyle`] - use [`Detector::redact`]; to mask entities
/// you already detected, use [`MaskStyle::redact`].
///
/// # Examples
/// ```
/// use redactify::redact;
///
/// assert_eq!(
///     redact("TCKN'm 12345678950, mail a@b.com"),
///     "TCKN'm [TCKN], mail [EMAIL]"
/// );
/// // an order number without a valid checksum stays UNCHANGED:
/// let order = "Sipari\u{15f} numaran\u{131}z 12000345671 olarak kaydedildi.";
/// assert_eq!(redact(order), order);
/// // fullwidth digits are masked too
/// assert_eq!(redact("TCKN １２３４５６７８９５０"), "TCKN [TCKN]");
/// ```
#[must_use]
pub fn redact(text: &str) -> String {
    Detector::new().redact(text)
}

#[cfg(test)]
mod tests {
    use super::{Detector, MaskStyle};
    use crate::pii::{
        run, CustomRule, EngineOpts, Entity, EntityType, MockNameRecognizer, NerRecognizer, Vault,
    };

    /// Representative inputs: every locale family, multi-line, CRLF,
    /// overlaps, encoding evasions, free prose, Turkish multibyte text
    /// (escaped: U+0131 dotless i, U+015F s-cedilla, U+00FC u-umlaut,
    /// U+00F6 o-umlaut, U+00E7 c-cedilla), empty.
    const TEXTS: &[&str] = &[
        "",
        "TCKN'm 12345678950, IBAN TR33 0006 1005 1978 6457 8413 26, mail a@b.com",
        "Sipari\u{15f} numaran\u{131}z 12000345671 olarak kaydedildi.",
        "Beni 0532 123 45 67'den ara. vergi no 1234567890",
        "Plakas\u{131} 34 ABC 123 olan ara\u{e7}, yolda 34 ABC 123 g\u{f6}rd\u{fc}m",
        "SSN 536-90-6292 ve TCKN 12345678950\nnhs 9434765870\r\npesel 80010123450",
        "IdNr 86095742719 in der Akte",
        "Bug\u{fc}n toplant\u{131}da Ahmet Y\u{131}lmaz konu\u{15f}tu, Ad Soyad: Ali Veli",
        "Destek: 0532 123 45 67, TCKN 12345678950",
        "kimlik ＴＣＫＮ １２３４５６７８９５０",
        "TCKN 1\u{200B}2345678950 ve 0532 123 45 67",
        "bkz ORC-12345 detay",
    ];

    const LOCALE_SETS: &[&[&str]] = &[&[], &["tr"], &["en"], &["uk", "pl", "de"]];

    /// The raw-text-only detector: the configuration a single engine
    /// pass reproduces.
    fn raw<'a>() -> Detector<'a> {
        Detector::new().with_normalization(false)
    }

    /// One direct engine pass: the reference every builder terminal must
    /// reproduce for the same options.
    fn engine(text: &str, opts: EngineOpts<'_>) -> Vec<Entity> {
        run(text, &opts).entities
    }

    #[test]
    fn builder_options_reach_the_engine_unchanged() {
        let ner = MockNameRecognizer::new();
        let rec = [&ner as &dyn NerRecognizer];
        let rule = CustomRule::new(EntityType::Itin, r"ORC-\d{4,6}").unwrap();
        let rules = [&rule];
        let ignored = ["0532 123 45 67"];
        for text in TEXTS {
            assert_eq!(Detector::new().detect(text), crate::detect(text));
            assert_eq!(raw().detect(text), engine(text, EngineOpts::default()));
            for t in [0.0, 0.85, 0.9, 0.99] {
                assert_eq!(
                    raw().with_threshold(t).detect(text),
                    engine(
                        text,
                        EngineOpts {
                            threshold: t,
                            ..EngineOpts::default()
                        }
                    )
                );
                assert_eq!(
                    raw().with_threshold(t).with_ner(&rec).detect(text),
                    engine(
                        text,
                        EngineOpts {
                            threshold: t,
                            ner: &rec,
                            ..EngineOpts::default()
                        }
                    )
                );
            }
            for locales in LOCALE_SETS {
                assert_eq!(
                    raw().with_locales(locales).detect(text),
                    engine(
                        text,
                        EngineOpts {
                            locales,
                            ..EngineOpts::default()
                        }
                    )
                );
                assert_eq!(
                    raw()
                        .with_locales(locales)
                        .with_ignored(&ignored)
                        .detect(text),
                    engine(
                        text,
                        EngineOpts {
                            locales,
                            ignored: &ignored,
                            ..EngineOpts::default()
                        }
                    )
                );
                assert_eq!(
                    raw()
                        .with_locales(locales)
                        .with_ner(&rec)
                        .with_threshold(0.9)
                        .detect(text),
                    engine(
                        text,
                        EngineOpts {
                            locales,
                            threshold: 0.9,
                            ner: &rec,
                            ..EngineOpts::default()
                        }
                    )
                );
                assert_eq!(
                    raw()
                        .with_locales(locales)
                        .with_ner(&rec)
                        .with_custom_rules(&rules)
                        .detect(text),
                    engine(
                        text,
                        EngineOpts {
                            locales,
                            ner: &rec,
                            custom: &rules,
                            ..EngineOpts::default()
                        }
                    )
                );
            }
        }
    }

    #[test]
    fn redact_and_pseudonymize_render_the_engine_result() {
        let ner = MockNameRecognizer::new();
        let rec = [&ner as &dyn NerRecognizer];
        let ignored = ["0532 123 45 67"];
        for text in TEXTS {
            let plain = engine(text, EngineOpts::default());
            assert_eq!(Detector::new().redact(text), crate::redact(text));
            assert_eq!(raw().redact(text), MaskStyle::Label.redact(text, &plain));
            let template = MaskStyle::Template("<<{type}>>".into());
            assert_eq!(
                raw().with_mask_style(template.clone()).redact(text),
                template.redact(text, &plain)
            );
            assert_eq!(raw().pseudonymize(text), Vault::pseudonymize(text));
            for locales in LOCALE_SETS {
                let opts = EngineOpts {
                    locales,
                    ..EngineOpts::default()
                };
                assert_eq!(
                    raw().with_locales(locales).redact(text),
                    MaskStyle::Label.redact(text, &engine(text, opts))
                );
                assert_eq!(
                    raw()
                        .with_locales(locales)
                        .with_ignored(&ignored)
                        .redact(text),
                    MaskStyle::Label.redact(
                        text,
                        &engine(
                            text,
                            EngineOpts {
                                ignored: &ignored,
                                ..opts
                            }
                        )
                    )
                );
                assert_eq!(
                    raw().with_locales(locales).with_ner(&rec).redact(text),
                    MaskStyle::Label.redact(text, &engine(text, EngineOpts { ner: &rec, ..opts }))
                );
                assert_eq!(
                    raw().with_locales(locales).pseudonymize(text),
                    Vault::pseudonymize_entities(text, &engine(text, opts))
                );
            }
        }
    }

    #[test]
    fn normalization_finds_evasions_and_keeps_raw_spans() {
        let text = "x ＴＣＫ\u{200B}Ｎ １２３４５６７８９５０ y";
        assert!(raw().detect(text).is_empty());
        let ents = Detector::new().detect(text);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::Tckn);
        assert_eq!(&text[ents[0].start..ents[0].end], ents[0].text);
        assert_eq!(ents[0].text, "１２３４５６７８９５０");
    }

    #[test]
    fn regex_runtime_errors_are_counted_with_their_line_span() {
        // nested alternation + atomic group: the backtracking VM explores
        // exponentially many splits of the run before giving up, which
        // exhausts the default backtrack budget
        let rule = CustomRule::new(EntityType::Itin, r"(?i)(a|b|ab)*(?>c)").unwrap();
        let rules = [&rule];
        // (the other lines carry no `c`, so the rule cannot match there)
        let line2 = format!("{} c", "ab".repeat(40));
        let text = format!("kimlik 12345678950\n{line2}\ntel 0532 123 45 67");
        let report = Detector::new().with_custom_rules(&rules).scan(&text);
        assert!(!report.is_complete(), "{report:?}");
        assert!(report.engine_errors >= 1);
        let start = "kimlik 12345678950\n".len();
        assert_eq!(report.error_spans, vec![(start, start + line2.len())]);
        // the other lines are unaffected
        let kinds: Vec<EntityType> = report.entities.iter().map(|e| e.kind).collect();
        assert_eq!(kinds, vec![EntityType::Tckn, EntityType::Phone]);
        // the plain detect result is the same entity list
        assert_eq!(
            Detector::new().with_custom_rules(&rules).detect(&text),
            report.entities
        );
        // redaction masks the unscanned line as a whole: nothing of
        // it passes through, the other lines are masked as usual
        assert_eq!(
            Detector::new().with_custom_rules(&rules).redact(&text),
            "kimlik [TCKN]\n[SCAN_INCOMPLETE]\ntel [PHONE]"
        );
    }

    #[test]
    fn normalization_aware_output_is_sorted_by_start() {
        // findings of the normalized pass are merged by start, not appended
        // after the raw ones; the fullwidth TCKN precedes the raw e-mail here
        let text = "\u{FF11}\u{FF12}\u{FF13}\u{FF14}\u{FF15}\u{FF16}\u{FF17}\u{FF18}\u{FF19}\u{FF15}\u{FF10} ve mail a@b.com";
        let d = Detector::new().with_normalization(true);
        let kinds: Vec<EntityType> = d.detect(text).iter().map(|e| e.kind).collect();
        assert_eq!(kinds, vec![EntityType::Tckn, EntityType::Email]);
        let explained = d.explain(text);
        let views: Vec<_> = explained.iter().map(|(_, w)| w.view).collect();
        assert_eq!(
            views,
            vec![crate::DetectionView::Normalized, crate::DetectionView::Raw]
        );
        // explain returns exactly the detect result, in the same order
        let ents: Vec<Entity> = explained.into_iter().map(|(e, _)| e).collect();
        assert_eq!(ents, d.detect(text));
        // ASCII and already-normalized text take the fast path: identical
        // to the plain engine pass
        for t in TEXTS {
            if t.is_ascii() {
                assert_eq!(d.detect(t), Detector::new().detect(t), "{t}");
            }
        }
    }

    #[test]
    fn allowlist_applies_the_same_way_on_the_normalized_view() {
        // a fullwidth spelling of an allowlisted value is allowlisted too,
        // and an allowlist does not switch normalization off
        let fullwidth =
            "Destek: \u{FF10}\u{FF15}\u{FF13}\u{FF12} 123 45 67, TCKN 1\u{200B}2345678950";
        let d = Detector::new()
            .with_normalization(true)
            .with_ignored(&["0532 123 45 67"]);
        let kinds: Vec<EntityType> = d.detect(fullwidth).iter().map(|e| e.kind).collect();
        assert_eq!(kinds, vec![EntityType::Tckn]);
        assert_eq!(
            d.redact(fullwidth),
            "Destek: \u{FF10}\u{FF15}\u{FF13}\u{FF12} 123 45 67, TCKN [TCKN]"
        );
        // the same request without the allowlist masks both
        let all = Detector::new().with_normalization(true).detect(fullwidth);
        assert_eq!(all.len(), 2, "{all:?}");
    }

    #[test]
    fn debug_shows_counts_never_allowlisted_values() {
        let ner = MockNameRecognizer::new();
        let rec = [&ner as &dyn NerRecognizer];
        let d = Detector::new()
            .with_locales(&["tr"])
            .with_ner(&rec)
            .with_ignored(&["0532 123 45 67"]);
        let dbg = format!("{d:?}");
        assert!(!dbg.contains("0532"), "{dbg}");
        assert!(dbg.contains("ignored: 1"), "{dbg}");
        assert!(dbg.contains("mock-ner"), "{dbg}");
        assert!(dbg.contains("\"tr\""), "{dbg}");
    }

    /// One normalization-aware scan whose per-line aligner fails on every
    /// line starting with `BAD` (the defensive path, unreachable with the
    /// real aligner).
    fn scan_with_failing_line(text: &str) -> super::ScanReport {
        use crate::guard::normalize::align_line;
        let opts = EngineOpts::default();
        let mut out = run(text, &opts);
        super::add_normalized_pass_with(text, &opts, &mut out, |line| {
            if line.starts_with("BAD") {
                None
            } else {
                align_line(line)
            }
        });
        super::ScanReport {
            entities: out.entities,
            engine_errors: out.engine_errors,
            error_spans: out.error_spans,
        }
    }

    #[test]
    fn an_unaligned_line_fails_closed_as_scan_incomplete() {
        let bad = "BAD kimlik \u{FF11}\u{FF12}\u{FF13}\u{FF14}\u{FF15}\u{FF16}\u{FF17}\u{FF18}\u{FF19}\u{FF15}\u{FF10}";
        let text = format!("TCKN 1\u{200B}2345678950\n{bad}\ntel 0532 123 45 67");
        let report = scan_with_failing_line(&text);
        assert!(!report.is_complete());
        assert_eq!(report.engine_errors, 1);
        let start = "TCKN 1\u{200B}2345678950\n".len();
        assert_eq!(report.error_spans, vec![(start, start + bad.len())]);
        // the aligned lines keep their normalized findings
        let kinds: Vec<EntityType> = report.entities.iter().map(|e| e.kind).collect();
        assert_eq!(kinds, vec![EntityType::Tckn, EntityType::Phone]);
        assert_eq!(
            MaskStyle::Label.redact_scan(&text, &report),
            "TCKN [TCKN]\n[SCAN_INCOMPLETE]\ntel [PHONE]"
        );
        // the real aligner handles the same text completely
        let real = Detector::new().scan(&text);
        assert!(real.is_complete(), "{real:?}");
        assert_eq!(real.entities.len(), 3);
    }

    #[test]
    fn findings_sharing_one_expansion_cluster_stay_disjoint() {
        // U+FB01 (fi ligature) normalizes to `f`, `i`: one finding ends
        // after the `f`, the next starts at the `i`
        let a = CustomRule::new(EntityType::Itin, r"ABf").unwrap();
        let b = CustomRule::new(EntityType::Vkn, r"iCD").unwrap();
        let rules = [&a, &b];
        let d = Detector::new().with_custom_rules(&rules);
        let text = "x AB\u{FB01}CD y";
        let ents = d.detect(text);
        let spans: Vec<&str> = ents.iter().map(|e| e.text.as_str()).collect();
        assert_eq!(spans, vec!["AB\u{FB01}", "CD"], "{ents:?}");
        assert_eq!(d.redact(text), "x [ITIN][VKN] y");
        // a finding entirely inside the shared cluster is already covered
        let inner = CustomRule::new(EntityType::Vkn, r"i").unwrap();
        let rules = [&a, &inner];
        let ents = Detector::new().with_custom_rules(&rules).detect(text);
        let spans: Vec<&str> = ents.iter().map(|e| e.text.as_str()).collect();
        assert_eq!(spans, vec!["AB\u{FB01}"], "{ents:?}");
    }
}
