//! Detection engine: candidate collection, context policies, scoring and
//! overlap resolution. Locale-agnostic: every rule comes from `locales`.

use crate::pii::context;
use crate::pii::custom::{CustomContext, CustomRule};
use crate::pii::entity::{Entity, EntityType};
use crate::pii::locales::{self, ContextPolicy, Rule};
use crate::pii::ner::{sanitize_spans, NerRecognizer};
use std::fmt;

/// Context window (characters) applied to every cue policy.
pub(crate) const CUE_WINDOW: usize = 18;

/// The validated, non-overlapping PII entities of the RAW text (no
/// normalization pass), left to right: one engine pass with the default
/// options (tr+en locale set, no threshold, no recognizers).
///
/// Crate-internal raw-view helper (layers that cannot reach the
/// normalization-aware [`Detector`](crate::Detector), and callers that
/// scan an already-normalized view). The public conveniences
/// `redactify::detect` / `redactify::redact` are the normalization-aware
/// default `Detector`.
///
/// Flow: for each rule (from `locales::rules_for_locales`) collect candidates per line
/// -> run the rule's validator -> apply the rule's context policy (required cue
/// or confidence boost), plus the spans of the locale line scanners
/// (`locales::line_scanners_for_locales`) -> resolve overlaps (higher priority = lower
/// `EntityType::priority` first, then longer spans) -> sort by start.
///
/// Scanning is **line-scoped**: each regex sees a single line. Since no
/// supported entity can span lines, results are identical to whole-text
/// scanning, yet one pathological line cannot stall the whole scan
/// (a simple but effective ReDoS mitigation). The regex engine has no
/// wall-clock timeout, but it does enforce a backtracking step budget per
/// match attempt (set explicitly, see `pii::rule::BACKTRACK_LIMIT`); a line
/// that exhausts it is reported as an incomplete scan by [`run`].
#[must_use]
pub(crate) fn detect(text: &str) -> Vec<Entity> {
    run(text, &EngineOpts::default()).entities
}

/// The locale set used when a caller passes an empty slice: the documented
/// empty-means-default contract of every locale-taking entry point (every
/// caller may pass its locale list unconditionally; no `is_empty`
/// dispatch).
const DEFAULT_LOCALES: &[&str] = &["tr", "en"];

/// Everything that parameterizes one engine pass.
///
/// Construct it ONLY with struct-update syntax over the default
/// (`EngineOpts { threshold, ..EngineOpts::default() }`): the option set
/// grows and call sites must keep compiling when it does.
#[derive(Clone, Copy, Default)]
pub(crate) struct EngineOpts<'a> {
    /// Locale codes; an EMPTY slice selects the default tr+en set.
    pub(crate) locales: &'a [&'a str],
    /// Minimum score: candidates below it are dropped BEFORE overlap
    /// resolution, so a below-threshold candidate cannot swallow an
    /// overlapping above-threshold one.
    pub(crate) threshold: f32,
    /// NER recognizers; they see the WHOLE text (rules stay line-scoped).
    pub(crate) ner: &'a [&'a dyn NerRecognizer],
    /// User-defined custom rules, pooled with the built-in candidates.
    pub(crate) custom: &'a [&'a CustomRule],
    /// Allowlisted values, applied BEFORE overlap resolution: a candidate
    /// whose exact `text` equals one of them is dropped together with every
    /// candidate lying entirely inside it (the allowlisted value as a whole
    /// is not PII, so neither is any part of it). An allowlisted winner
    /// therefore does not hide the overlapping candidates it would have
    /// beaten.
    pub(crate) ignored: &'a [&'a str],
    /// Entity types dropped BEFORE overlap resolution (a policy's `Ignore`
    /// entity action): unlike an allowlisted value, an ignored type hides
    /// nothing - the candidates of other types it overlaps compete as if it
    /// had never matched.
    pub(crate) ignored_types: &'a [EntityType],
    /// Record one [`Explanation`] per returned entity in
    /// [`EngineOutput::explanations`]; off by default (the non-explain
    /// path builds no explanation at all).
    pub(crate) explain: bool,
    /// Caller-supplied context texts: a cue found in them satisfies a
    /// rule's cue policy (required or boost) when the value's own line has
    /// none (see [`context::ExternalContext`]). Empty by default.
    pub(crate) context: &'a [&'a str],
}

/// Why an entity was reported: which rule or recognizer produced it, what
/// gated it and how it was scored. Produced by
/// [`Detector::explain`](crate::Detector::explain), one per entity.
///
/// The record never carries input text: `cue` is the configured cue
/// literal that matched (e.g. `"vergi"`), not the characters found around
/// the value.
///
/// serde (feature `serde`): `Serialize` only - the rule id and recognizer
/// name are `&'static str`, and an explanation is engine output, never
/// read back.
///
/// # Examples
/// ```
/// use redactify::{DetectionSource, DetectionView, Detector};
///
/// let explained = Detector::new().explain("vergi no 1234567890");
/// let (entity, why) = &explained[0];
/// assert_eq!(entity.text, "1234567890");
/// assert_eq!(why.source, DetectionSource::Rule { id: "tr::vkn" });
/// assert!(why.validator_passed);
/// assert_eq!(why.cue.as_deref(), Some("vergi"));
/// assert_eq!(why.view, DetectionView::Raw);
/// assert_eq!(why.score, entity.score);
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct Explanation {
    /// What produced the entity.
    pub source: DetectionSource,
    /// `true` when a checksum/structure validator ran and accepted the
    /// value; `false` only when the source has no validator (cue-gated
    /// rules without a checksum, custom rules without one, NER spans).
    pub validator_passed: bool,
    /// The configured cue literal found near the value, when the rule has
    /// a cue policy and a cue was present (`None` otherwise).
    pub cue: Option<String>,
    /// The source's base score, before any cue boost.
    pub base_score: f32,
    /// The final score (equals the entity's `score`).
    pub score: f32,
    /// Which text view the entity was found on.
    pub view: DetectionView,
}

/// What produced a detected entity (see [`Explanation`]).
///
/// serde (feature `serde`): `Serialize` only, internally tagged:
/// `{"kind": "RULE", "id": "tr::tckn"}`.
///
/// # Examples
/// ```
/// use redactify::{DetectionSource, Detector};
///
/// let explained = Detector::new().explain("TCKN 12345678950");
/// assert_eq!(explained[0].1.source, DetectionSource::Rule { id: "tr::tckn" });
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")
)]
#[non_exhaustive]
pub enum DetectionSource {
    /// A built-in rule. The id is the rule's module below the locale
    /// registry (`"tr::tckn"`, `"en::ssn"`, `"iban"`); the always-on
    /// generic rules are named individually (`"generic::email"`,
    /// `"generic::card"`, `"generic::ip"`, `"generic::url"`,
    /// `"generic::intl_phone"`, and `"generic::ipv6_collapsed"` for
    /// whitespace-separated IPv6 groups); `"tr::person"` is the
    /// label-free Turkish person-name lexicon scanner.
    Rule {
        /// Stable rule id.
        id: &'static str,
    },
    /// A user-defined [`CustomRule`]: its index in the slice passed to
    /// [`Detector::with_custom_rules`](crate::Detector::with_custom_rules).
    Custom {
        /// Index of the rule in the configured custom-rule slice.
        index: usize,
    },
    /// An NER recognizer ([`NerRecognizer::name`]).
    Ner {
        /// The recognizer's name.
        name: &'static str,
    },
}

/// The text view an entity was found on (see [`Explanation`]).
///
/// # Examples
/// ```
/// use redactify::{DetectionView, Detector};
///
/// // fullwidth digits: only the normalized view sees a TCKN
/// let explained = Detector::new()
///     .with_normalization(true)
///     .explain("TCKN \u{FF11}\u{FF12}\u{FF13}\u{FF14}\u{FF15}\u{FF16}\u{FF17}\u{FF18}\u{FF19}\u{FF15}\u{FF10}");
/// assert_eq!(explained[0].1.view, DetectionView::Normalized);
/// assert_eq!(DetectionView::Normalized.as_str(), "NORMALIZED");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "SCREAMING_SNAKE_CASE"))]
#[non_exhaustive]
pub enum DetectionView {
    /// The raw input text.
    Raw,
    /// The normalized view (NFKC folding, invisible characters stripped);
    /// the entity's span was mapped back onto the raw text.
    Normalized,
}

impl DetectionView {
    /// Canonical label (`"RAW"`, `"NORMALIZED"`; the serde spelling).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "RAW",
            Self::Normalized => "NORMALIZED",
        }
    }
}

impl fmt::Display for DetectionView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The result of one engine pass.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EngineOutput {
    /// Validated, non-overlapping entities, sorted by start offset.
    pub(crate) entities: Vec<Entity>,
    /// One explanation per entity (same index) when
    /// [`EngineOpts::explain`] is set; empty otherwise.
    pub(crate) explanations: Vec<Explanation>,
    /// Number of regex runtime errors (e.g. a backtrack limit) hit during
    /// the scan. Every such error means some candidates on that line may
    /// be missing: the scan of that line is INCOMPLETE.
    pub(crate) engine_errors: usize,
    /// Byte span `[start, end)` of every line on which at least one
    /// runtime error happened (one entry per line, in text order; the
    /// span excludes the line's `\n`).
    pub(crate) error_spans: Vec<(usize, usize)>,
}

/// The candidate pool of one engine pass: every candidate entity plus,
/// only when explanations are requested, a parallel explanation list.
struct Pool {
    cands: Vec<Entity>,
    /// `Some` (same length as `cands`) iff explanations are requested.
    whys: Option<Vec<Explanation>>,
}

impl Pool {
    /// Adds a candidate; `why` runs only when explanations are requested.
    fn push(&mut self, entity: Entity, why: impl FnOnce() -> Explanation) {
        if let Some(whys) = &mut self.whys {
            whys.push(why());
        }
        self.cands.push(entity);
    }
}

/// The ONE detection engine every detect/redact/guard entry point funnels
/// through: built-in locale rules + custom rules (line-scoped) + NER
/// recognizers (whole text) in one candidate pool, the threshold and
/// allowlist pre-filter, then one overlap resolution.
///
/// Regex runtime errors never vanish silently: each one is counted in
/// [`EngineOutput::engine_errors`] and the affected line is recorded in
/// [`EngineOutput::error_spans`]. The entity result is unchanged by the
/// accounting (an erroring rule still contributes nothing on that line).
pub(crate) fn run(text: &str, opts: &EngineOpts<'_>) -> EngineOutput {
    let mut out = EngineOutput {
        entities: Vec::new(),
        explanations: Vec::new(),
        engine_errors: 0,
        error_spans: Vec::new(),
    };
    if text.is_empty() {
        return out;
    }
    // empty locale slice = the default tr+en set (see DEFAULT_LOCALES)
    let locales: &[&str] = if opts.locales.is_empty() {
        DEFAULT_LOCALES
    } else {
        opts.locales
    };
    // build the rule set ONCE per call: rules_for_locales allocates a fresh
    // Vec and collect_line_with_rules runs per line, so rebuilding it inside
    // the line loop made long documents pay one Vec rebuild per line
    let rules = locales::rules_for_locales(locales);
    let mut scanners = LineScanners {
        scanners: locales::line_scanners_for_locales(locales),
        spans: Vec::new(),
    };
    let mut pool = Pool {
        cands: Vec::new(),
        whys: opts.explain.then(Vec::new),
    };
    let external = context::ExternalContext::new(opts.context);
    let mut offset = 0;
    for line in text.split('\n') {
        let at = LineAt {
            line,
            offset,
            external: &external,
            normalized: std::cell::OnceCell::new(),
        };
        let errors = collect_line_with_rules(&at, &mut pool, &rules)
            + collect_line_custom(&at, &mut pool, opts.custom);
        scanners.collect(&at, &mut pool);
        if errors > 0 {
            out.engine_errors += errors;
            out.error_spans.push((offset, offset + line.len()));
        }
        offset += line.len() + 1; // +1: the '\n' itself
    }
    // Recognizers see the WHOLE text (models need context beyond one line);
    // their spans share the same global byte-offset coordinate system.
    for r in opts.ner {
        for e in sanitize_spans(text, r.recognize(text)) {
            let score = e.score;
            pool.push(e, || Explanation {
                source: DetectionSource::Ner { name: r.name() },
                validator_passed: false,
                cue: None,
                base_score: score,
                score,
                view: DetectionView::Raw,
            });
        }
    }
    let mut keep = prefilter(&pool.cands, opts.threshold, opts.ignored);
    if !opts.ignored_types.is_empty() {
        for (k, c) in keep.iter_mut().zip(&pool.cands) {
            *k = *k && !opts.ignored_types.contains(&c.kind);
        }
    }
    // after the ignore filter: an ignored phone must not drop an SGK value
    sgk_yields_to_phone(&pool.cands, &mut keep);
    let chosen = resolve_overlaps(&pool.cands, &keep);
    out.entities = take_in_order(pool.cands, &chosen);
    if let Some(whys) = pool.whys {
        out.explanations = take_in_order(whys, &chosen);
    }
    out
}

/// Drops every kept SGK candidate that lies strictly inside a kept phone
/// candidate (`SGK birimi +90 5321234567`: the cued 8-12 digit SGK token
/// `5321234567` is the subscriber part of the phone).
///
/// SGK is top tier (`EntityType::priority`, to outrank the card rule on a
/// cued 13-digit value), so in overlap resolution it would beat the phone
/// and leave `+90` in clear under a wrong label. A phone span that strictly
/// contains the SGK token is the more complete reading of those digits; an
/// equal span keeps the SGK label (the cue decided it). The alternative,
/// an SGK pattern that swallows a preceding `+90 212 ` and then fails its
/// validator, gives the same output on a 3213-item Turkish evaluation set
/// but leaves `+90 212 12345678` (no phone rule claims an
/// 8-digit subscriber number) entirely in clear, where this keeps the
/// eight digits masked.
///
/// Cost: one pass over the candidates when there is no SGK candidate;
/// otherwise the phone spans sorted once and two binary searches per SGK
/// candidate (a prefix maximum of the phone ends, as in [`prefilter`]).
fn sgk_yields_to_phone(cands: &[Entity], keep: &mut [bool]) {
    let kept = |kind: EntityType| {
        cands
            .iter()
            .zip(keep.iter())
            .filter(move |(c, k)| **k && c.kind == kind)
    };
    if kept(EntityType::Sgk).next().is_none() {
        return;
    }
    let mut phones: Vec<(usize, usize)> = kept(EntityType::Phone)
        .map(|(c, _)| (c.start, c.end))
        .collect();
    if phones.is_empty() {
        return;
    }
    phones.sort_unstable();
    let mut reach = 0;
    for span in &mut phones {
        reach = reach.max(span.1);
        span.1 = reach;
    }
    let furthest = |n: usize| n.checked_sub(1).map_or(0, |last| phones[last].1);
    for (c, k) in cands.iter().zip(keep.iter_mut()) {
        if *k && c.kind == EntityType::Sgk {
            let le = furthest(phones.partition_point(|&(s, _)| s <= c.start));
            let lt = furthest(phones.partition_point(|&(s, _)| s < c.start));
            if le > c.end || lt >= c.end {
                *k = false;
            }
        }
    }
}

impl EngineOutput {
    /// Merges the findings of another view of the same text (`entities`,
    /// already translated into this output's coordinates and pre-filtered
    /// by their own pass) through the engine's overlap resolution: the
    /// union competes like one candidate pool, so a longer or
    /// higher-priority finding of the other view replaces an overlapping
    /// fragment found here. The existing entities enter the pool first,
    /// so an exact tie keeps the existing finding and its explanation.
    ///
    /// `explanations` is `Some` (one per entity, same order) exactly when
    /// this output carries explanations.
    pub(crate) fn merge_view(
        &mut self,
        entities: Vec<Entity>,
        explanations: Option<Vec<Explanation>>,
    ) {
        if entities.is_empty() {
            return;
        }
        let mut cands = std::mem::take(&mut self.entities);
        cands.extend(entities);
        let whys = explanations.map(|extra| {
            let mut whys = std::mem::take(&mut self.explanations);
            whys.extend(extra);
            whys
        });
        let chosen = resolve_overlaps(&cands, &vec![true; cands.len()]);
        self.entities = take_in_order(cands, &chosen);
        if let Some(whys) = whys {
            self.explanations = take_in_order(whys, &chosen);
        }
    }
}

/// The candidates that may enter overlap resolution: score at or above
/// `threshold`, and neither an allowlisted value nor lying entirely inside
/// an allowlisted candidate (see [`EngineOpts::ignored`]).
///
/// A NaN score (or a NaN threshold) never drops a candidate: an
/// unordered comparison keeps it, so a recognizer or custom rule that
/// reports NaN fails safe (masked) instead of open.
fn prefilter(cands: &[Entity], threshold: f32, ignored: &[&str]) -> Vec<bool> {
    let mut ignored_spans: Vec<(usize, usize)> = if ignored.is_empty() {
        Vec::new()
    } else {
        cands
            .iter()
            .filter(|c| ignored.contains(&c.text.as_str()))
            .map(|c| (c.start, c.end))
            .collect()
    };
    // by start, each end raised to the furthest end so far: a candidate
    // lies inside an allowlisted span iff the furthest end among the spans
    // starting at or before it reaches its end (checking every span per
    // candidate was quadratic when the allowlisted value recurs)
    ignored_spans.sort_unstable();
    let mut reach = 0;
    for span in &mut ignored_spans {
        reach = reach.max(span.1);
        span.1 = reach;
    }
    cands
        .iter()
        .map(|c| {
            let before = ignored_spans.partition_point(|&(s, _)| s <= c.start);
            c.score.partial_cmp(&threshold) != Some(std::cmp::Ordering::Less)
                && !before
                    .checked_sub(1)
                    .is_some_and(|last| ignored_spans[last].1 >= c.end)
        })
        .collect()
}

/// Moves the items at `order` (distinct indices into `items`) out, in that
/// order.
fn take_in_order<T>(items: Vec<T>, order: &[usize]) -> Vec<T> {
    let mut slots: Vec<Option<T>> = items.into_iter().map(Some).collect();
    order
        .iter()
        .filter_map(|&i| slots.get_mut(i).and_then(Option::take))
        .collect()
}

/// The cue policy of one line rule, borrowed from a built-in rule's
/// [`ContextPolicy`] (static cue lists) or a custom rule's
/// [`CustomContext`] (owned, pre-normalized cue lists).
enum CuePolicy<'c, S> {
    /// No context handling.
    None,
    /// The match is claimed only with a cue nearby.
    Required(&'c [S]),
    /// A nearby cue raises the score to the boosted value.
    Boost(&'c [S], f32),
}

/// One line being scanned: its text, its byte offset in the document and
/// the caller-supplied context shared by every line.
struct LineAt<'l> {
    line: &'l str,
    offset: usize,
    external: &'l context::ExternalContext<'l>,
    /// [`context::normalize_tr`] of `line`, built on first use by
    /// [`may_hold_cue`] and shared by every cue-gated rule of the line.
    normalized: std::cell::OnceCell<String>,
}

/// Whether a cue of `cues` can unlock anything on `at.line`: some cue occurs
/// in the normalized line or in the caller's context. [`context::find_cue`]
/// only searches the line itself (and the caller's context), so when no cue
/// occurs anywhere a `RequiredCue` rule cannot claim a match on this line,
/// and its regex need not run at all - the same candidates, without the
/// per-line scan. A capital sigma is the one character whose lower case
/// depends on its neighbours (final `ς` vs `σ`), so the normalized whole
/// line and the normalized slices `find_cue` compares could differ: such a
/// line is always scanned.
fn may_hold_cue<S: AsRef<str>>(at: &LineAt<'_>, cues: &[S]) -> bool {
    if at.line.contains('\u{3a3}') {
        return true;
    }
    let normalized = at.normalized.get_or_init(|| context::normalize_tr(at.line));
    cues.iter().any(|c| normalized.contains(c.as_ref())) || at.external.find_cue(cues).is_some()
}

/// The cue that unlocks match `m` of a `kind` rule on `at.line`: a cue
/// near it on the line, else a cue anywhere in the caller's context;
/// `None` without either.
///
/// On the line, a short cue may also start at a camelCase boundary
/// (`customerSsn: 536906292`, the `"{key}: {value}"` line the JSON
/// redactor builds) for identifier kinds, whose value shape is itself
/// evidence. Names and addresses (priority 8, a free capitalized sequence)
/// keep the strict word start: `fileName: Annual Report` must not unlock
/// a NAME through `name:`.
fn cue_for<'c, S: AsRef<str>>(
    at: &LineAt<'_>,
    m: &fancy_regex::Match<'_>,
    cues: &'c [S],
    kind: EntityType,
) -> Option<&'c str> {
    let camel_case = kind.priority() < 8;
    context::find_cue(at.line, m.start(), m.end(), cues, CUE_WINDOW, camel_case)
        .or_else(|| at.external.find_cue(cues))
}

/// One regex rule as the line scanner runs it: built-in and custom rules
/// share this ONE path (match -> validator -> cue policy -> candidate +
/// explanation).
struct LineRule<'r, S> {
    kind: EntityType,
    regex: &'r fancy_regex::Regex,
    validator: Option<fn(&str) -> bool>,
    score: f32,
    cues: CuePolicy<'r, S>,
    source: DetectionSource,
}

impl<S: AsRef<str>> LineRule<'_, S> {
    /// Scans one line, pushing every validated, cue-gated match into the
    /// pool. A cue is searched on the line first, then in the caller's
    /// context. Returns the number of regex runtime errors hit on this
    /// line.
    fn collect(&self, at: &LineAt<'_>, pool: &mut Pool) -> usize {
        if let CuePolicy::Required(cues) = &self.cues {
            if !may_hold_cue(at, cues) {
                return 0;
            }
        }
        let (line, offset) = (at.line, at.offset);
        let mut errors = 0;
        for m in self.regex.find_iter(line) {
            let Ok(m) = m else {
                errors += 1;
                continue;
            };
            // a zero-width match (a custom `\d*` between two letters) holds
            // no text to mask: it would be a `start == end` entity
            if m.start() == m.end() {
                continue;
            }
            let val = m.as_str();
            if let Some(validate) = self.validator {
                if !validate(val) {
                    continue;
                }
            }
            let (score, cue) = match self.cues {
                CuePolicy::Required(cues) => match cue_for(at, &m, cues, self.kind) {
                    Some(cue) => (self.score, Some(cue)),
                    // checksum-less identifier: not claimable without a cue
                    None => continue,
                },
                CuePolicy::Boost(cues, boosted) => match cue_for(at, &m, cues, self.kind) {
                    Some(cue) => (boosted, Some(cue)),
                    None => (self.score, None),
                },
                CuePolicy::None => (self.score, None),
            };
            pool.push(
                Entity {
                    kind: self.kind,
                    start: offset + m.start(),
                    end: offset + m.end(),
                    text: val.to_owned(),
                    score,
                },
                || Explanation {
                    source: self.source,
                    validator_passed: self.validator.is_some(),
                    cue: cue.map(str::to_owned),
                    base_score: self.score,
                    score,
                    view: DetectionView::Raw,
                },
            );
        }
        errors
    }
}

/// Scans one line with user-defined custom rules (the same [`LineRule`]
/// path as the built-in rules, with the rule's owned, pre-normalized cue
/// list). Returns the number of regex runtime errors hit on this line.
fn collect_line_custom(at: &LineAt<'_>, pool: &mut Pool, custom: &[&CustomRule]) -> usize {
    if at.line.is_empty() || custom.is_empty() {
        return 0;
    }
    let mut errors = 0;
    for (index, rule) in custom.iter().enumerate() {
        let cues = match &rule.context {
            CustomContext::None => CuePolicy::None,
            CustomContext::RequiredCue(cues) => CuePolicy::Required(cues.as_slice()),
            CustomContext::Boost(cues, boosted) => CuePolicy::Boost(cues.as_slice(), *boosted),
        };
        errors += LineRule {
            kind: rule.kind,
            regex: &rule.regex,
            validator: rule.validator,
            score: rule.score,
            cues,
            source: DetectionSource::Custom { index },
        }
        .collect(at, pool);
    }
    errors
}

/// The line scanners of one engine pass (`locales::LineScanner`) and a
/// span buffer reused across lines (no allocation per line).
struct LineScanners {
    scanners: Vec<locales::LineScanner>,
    spans: Vec<(usize, usize, f32)>,
}

impl LineScanners {
    /// Runs every scanner over one line and pushes its spans into the
    /// pool. A scanner has no validator and no cue policy: its own word
    /// evidence decides (see `locales::tr::person`).
    fn collect(&mut self, at: &LineAt<'_>, pool: &mut Pool) {
        if at.line.is_empty() {
            return;
        }
        for scanner in &self.scanners {
            self.spans.clear();
            (scanner.scan)(at.line, &mut self.spans);
            for &(start, end, score) in &self.spans {
                pool.push(
                    Entity {
                        kind: scanner.kind,
                        start: at.offset + start,
                        end: at.offset + end,
                        text: at.line[start..end].to_owned(),
                        score,
                    },
                    || Explanation {
                        source: DetectionSource::Rule { id: scanner.id },
                        validator_passed: false,
                        cue: None,
                        base_score: score,
                        score,
                        view: DetectionView::Raw,
                    },
                );
            }
        }
    }
}

/// Rule id reported for whitespace-separated IPv6 groups (the
/// collapsed-copy helper, not a `rule!` rule).
const IPV6_COLLAPSED_ID: &str = "generic::ipv6_collapsed";

/// Score of a collapsed-IPv6 finding (same as the contiguous IP rule).
const IPV6_COLLAPSED_SCORE: f32 = 0.85;

/// Scans one line with the built-in locale rules (plus the spaced-IPv6
/// helper). Returns the number of regex runtime errors hit on this line.
fn collect_line_with_rules(at: &LineAt<'_>, pool: &mut Pool, rules: &[Rule]) -> usize {
    let (line, offset) = (at.line, at.offset);
    if line.is_empty() {
        return 0;
    }
    let mut errors = 0;
    for rule in rules {
        let cues = match rule.context {
            ContextPolicy::None => CuePolicy::None,
            ContextPolicy::RequiredCue(cues) => CuePolicy::Required(cues),
            ContextPolicy::Boost(cues, boosted) => CuePolicy::Boost(cues, boosted),
        };
        errors += LineRule {
            kind: rule.kind,
            regex: rule.regex,
            validator: rule.validator,
            score: rule.score,
            cues,
            source: DetectionSource::Rule { id: rule.id },
        }
        .collect(at, pool);
    }
    // spaced IPv6 fragments are invisible to the contiguous rules; scan a
    // whitespace-collapsed copy and map matches back (same score/kind as the
    // IP rule; overlap resolution dedups against contiguous claims)
    for (s, e) in locales::generic::collapsed_ipv6_spans(line, &mut errors) {
        pool.push(
            Entity {
                kind: EntityType::IpAddress,
                start: offset + s,
                end: offset + e,
                text: line[s..e].to_owned(),
                score: IPV6_COLLAPSED_SCORE,
            },
            || Explanation {
                source: DetectionSource::Rule {
                    id: IPV6_COLLAPSED_ID,
                },
                // the helper keeps only public-address validated matches
                validator_passed: true,
                cue: None,
                base_score: IPV6_COLLAPSED_SCORE,
                score: IPV6_COLLAPSED_SCORE,
                view: DetectionView::Raw,
            },
        );
    }
    errors
}

/// Resolves overlapping candidates: walk the kept candidates (`keep[i]`)
/// in (priority asc, length desc) order and greedily accept the
/// non-overlapping ones. Returns the accepted indices sorted by start
/// (stable: equal starts keep acceptance order).
///
/// Exception (PII-Bench v4: 90.0% with it, 85.1% without):
/// two **priority-8 spans of different kinds** (a Name and an Address) may
/// overlap and both survive - e.g. XLM-R's LOC "Johannes R. Becher Institute"
/// containing PIIRanha's GIVENNAME "Johannes R. Becher". Deleting either
/// loses a real, differently-typed detection; masking handles the union
/// region once. Same-kind priority-8 overlaps still keep only the longer
/// span, and any higher-priority (checksum/structural) span still wins
/// absolutely over priority 8.
///
/// Cost O(n log n): the accepted spans are kept in sets that are each
/// pairwise disjoint (the spans below tier 8, and the tier-8 spans of one
/// kind), so one predecessor lookup per set answers the overlap question.
/// Checking every candidate against every accepted span would make a large
/// document quadratic (1 / 2 / 4 MiB of four-PII lines: 1.26 / 3.35 /
/// 9.39 s).
fn resolve_overlaps(cands: &[Entity], keep: &[bool]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..cands.len())
        .filter(|&i| keep.get(i).copied().unwrap_or(false))
        .collect();
    // stable sort: equal (priority, length) keeps insertion (= rule) order
    order.sort_by(|&a, &b| {
        let (a, b) = (&cands[a], &cands[b]);
        a.kind
            .priority()
            .cmp(&b.kind.priority())
            .then(b.len().cmp(&a.len()))
    });
    // accepted spans below tier 8: disjoint from every accepted span
    let mut solid = DisjointSpans::default();
    // accepted tier-8 spans by kind: disjoint within a kind and from `solid`
    let mut coexisting: Vec<(EntityType, DisjointSpans)> = Vec::new();
    let mut chosen: Vec<usize> = Vec::new();
    for i in order {
        let e = &cands[i];
        let (start, end) = (e.start, e.end);
        let blocked = solid.overlaps(start, end)
            || if e.kind.priority() == 8 {
                // a tier-8 span coexists with tier-8 spans of other kinds
                coexisting
                    .iter()
                    .any(|(k, spans)| *k == e.kind && spans.overlaps(start, end))
            } else {
                coexisting
                    .iter()
                    .any(|(_, spans)| spans.overlaps(start, end))
            };
        if blocked {
            continue;
        }
        if e.kind.priority() == 8 {
            match coexisting.iter_mut().find(|(k, _)| *k == e.kind) {
                Some((_, spans)) => spans.insert(start, end),
                None => {
                    let mut spans = DisjointSpans::default();
                    spans.insert(start, end);
                    coexisting.push((e.kind, spans));
                }
            }
        } else {
            solid.insert(start, end);
        }
        chosen.push(i);
    }
    chosen.sort_by_key(|&i| cands[i].start);
    chosen
}

/// Pairwise disjoint byte spans (`[start, end)`), ordered by start. In
/// such a set the ends ascend with the starts, so among the spans that
/// start before a given end, the last one reaches furthest.
#[derive(Default)]
struct DisjointSpans(std::collections::BTreeSet<(usize, usize)>);

impl DisjointSpans {
    /// Whether some span overlaps `[start, end)` (the engine's overlap:
    /// each starts before the other ends).
    fn overlaps(&self, start: usize, end: usize) -> bool {
        self.0
            .range(..(end, 0))
            .next_back()
            .is_some_and(|&(_, e)| e > start)
    }

    /// Adds a span that overlaps none of the set.
    fn insert(&mut self, start: usize, end: usize) {
        self.0.insert((start, end));
    }
}

/// Test shorthand for the pii layer, which cannot use the policy-layer
/// `Detector` builder: one engine pass over the given locale set (an
/// EMPTY slice selects the default tr+en set).
#[cfg(test)]
pub(crate) fn engine_detect(text: &str, locales: &[&str]) -> Vec<Entity> {
    run(
        text,
        &EngineOpts {
            locales,
            ..EngineOpts::default()
        },
    )
    .entities
}

#[cfg(test)]
mod tests {
    use super::{detect, run, EngineOpts};
    use crate::pii::entity::{Entity, EntityType};

    /// The pairwise allowlist check `prefilter` replaced, kept as the
    /// reference it must equal.
    fn prefilter_pairwise(cands: &[Entity], threshold: f32, ignored: &[&str]) -> Vec<bool> {
        let ignored_spans: Vec<(usize, usize)> = cands
            .iter()
            .filter(|c| ignored.contains(&c.text.as_str()))
            .map(|c| (c.start, c.end))
            .collect();
        cands
            .iter()
            .map(|c| {
                c.score.partial_cmp(&threshold) != Some(std::cmp::Ordering::Less)
                    && !ignored_spans
                        .iter()
                        .any(|&(s, e)| s <= c.start && c.end <= e)
            })
            .collect()
    }

    #[test]
    fn prefilter_equals_the_pairwise_reference() {
        use super::prefilter;
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = |bound: usize| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            usize::try_from(state >> 33).unwrap_or(0) % bound
        };
        for round in 0..3_000 {
            let n = next(20);
            let cands: Vec<Entity> = (0..n)
                .map(|_| {
                    let start = next(40);
                    Entity {
                        kind: EntityType::Email,
                        start,
                        end: start + 1 + next(10),
                        text: ["a", "b", "c"][next(3)].to_owned(),
                        score: [0.2, 0.5, 0.9, f32::NAN][next(4)],
                    }
                })
                .collect();
            for ignored in [&[][..], &["a"][..], &["a", "c"][..]] {
                assert_eq!(
                    prefilter(&cands, 0.5, ignored),
                    prefilter_pairwise(&cands, 0.5, ignored),
                    "round {round}: {cands:?} ignored {ignored:?}"
                );
            }
        }
    }

    #[test]
    fn sgk_yields_to_phone_equals_the_pairwise_reference() {
        use super::sgk_yields_to_phone;
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = |bound: usize| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            usize::try_from(state >> 33).unwrap_or(0) % bound
        };
        let kinds = [EntityType::Sgk, EntityType::Phone, EntityType::Email];
        for round in 0..3_000 {
            let n = next(12);
            let cands: Vec<Entity> = (0..n)
                .map(|_| {
                    let start = next(30);
                    Entity {
                        kind: kinds[next(3)],
                        start,
                        end: start + 1 + next(12),
                        text: String::new(),
                        score: 1.0,
                    }
                })
                .collect();
            let keep: Vec<bool> = (0..n).map(|_| next(4) != 0).collect();
            let want: Vec<bool> = cands
                .iter()
                .zip(&keep)
                .map(|(c, &k)| {
                    k && !(c.kind == EntityType::Sgk
                        && cands.iter().zip(&keep).any(|(p, &pk)| {
                            pk && p.kind == EntityType::Phone
                                && p.start <= c.start
                                && c.end <= p.end
                                && (p.start, p.end) != (c.start, c.end)
                        }))
                })
                .collect();
            let mut got = keep.clone();
            sgk_yields_to_phone(&cands, &mut got);
            assert_eq!(got, want, "round {round}: {cands:?} keep {keep:?}");
        }
    }

    /// A pairwise check (every candidate against every allowlisted span)
    /// adds 0.08 / 0.43 / 1.36 s over 1 / 2 / 4 MiB when an allowlisted
    /// e-mail recurs on every line (release build).
    #[test]
    fn prefilter_is_not_quadratic() {
        use super::prefilter;
        let cands: Vec<Entity> = (0..120_000)
            .map(|i| Entity {
                kind: EntityType::Email,
                start: i * 10,
                end: i * 10 + 8,
                text: if i % 2 == 0 { "a" } else { "b" }.to_owned(),
                score: 1.0,
            })
            .collect();
        let started = std::time::Instant::now();
        let keep = prefilter(&cands, 0.0, &["a"]);
        let elapsed = started.elapsed();
        assert_eq!(keep.iter().filter(|&&k| k).count(), 60_000);
        assert!(elapsed.as_secs_f64() < 2.0, "took {elapsed:?}");
    }

    /// The pairwise resolution `resolve_overlaps` replaced (every candidate
    /// against every accepted span), kept as the reference it must equal.
    fn resolve_overlaps_pairwise(cands: &[Entity], keep: &[bool]) -> Vec<usize> {
        let mut order: Vec<usize> = (0..cands.len())
            .filter(|&i| keep.get(i).copied().unwrap_or(false))
            .collect();
        order.sort_by(|&a, &b| {
            let (a, b) = (&cands[a], &cands[b]);
            a.kind
                .priority()
                .cmp(&b.kind.priority())
                .then(b.len().cmp(&a.len()))
        });
        let mut occupied: Vec<(usize, usize, EntityType)> = Vec::new();
        let mut chosen: Vec<usize> = Vec::new();
        for i in order {
            let e = &cands[i];
            let coexists = e.kind.priority() == 8;
            let blocked = occupied.iter().any(|&(s, en, k)| {
                let overlaps = !(e.end <= s || e.start >= en);
                overlaps && !(coexists && k.priority() == 8 && k != e.kind)
            });
            if !blocked {
                occupied.push((e.start, e.end, e.kind));
                chosen.push(i);
            }
        }
        chosen.sort_by_key(|&i| cands[i].start);
        chosen
    }

    #[test]
    fn overlap_resolution_equals_the_pairwise_reference() {
        use super::resolve_overlaps;
        // kinds across the tiers, two of them in the coexisting tier 8
        const KINDS: [EntityType; 7] = [
            EntityType::Iban,
            EntityType::Tckn,
            EntityType::Email,
            EntityType::Phone,
            EntityType::Vkn,
            EntityType::Name,
            EntityType::Address,
        ];
        // deterministic LCG (Knuth MMIX constants)
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = |bound: usize| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            usize::try_from(state >> 33).unwrap_or(0) % bound
        };
        for round in 0..3_000 {
            let n = 1 + next(24);
            let span = 4 + next(60);
            let cands: Vec<Entity> = (0..n)
                .map(|_| {
                    let start = next(span);
                    let end = start + 1 + next(12);
                    Entity {
                        kind: KINDS[next(KINDS.len())],
                        start,
                        end,
                        text: String::new(),
                        score: 1.0,
                    }
                })
                .collect();
            let keep: Vec<bool> = (0..n).map(|_| next(5) != 0).collect();
            assert_eq!(
                resolve_overlaps(&cands, &keep),
                resolve_overlaps_pairwise(&cands, &keep),
                "round {round}: {cands:?} keep {keep:?}"
            );
        }
    }

    /// A pairwise overlap check grows with candidates x accepted spans:
    /// detect over 1 / 2 / 4 MiB of four-PII lines takes 1.26 / 3.35 /
    /// 9.39 s with it (release build).
    #[test]
    fn overlap_resolution_is_not_quadratic() {
        use super::resolve_overlaps;
        let cands: Vec<Entity> = (0..120_000)
            .map(|i| Entity {
                kind: if i % 3 == 0 {
                    EntityType::Name
                } else {
                    EntityType::Tckn
                },
                start: i * 10,
                end: i * 10 + 12,
                text: String::new(),
                score: 1.0,
            })
            .collect();
        let keep = vec![true; cands.len()];
        let started = std::time::Instant::now();
        let chosen = resolve_overlaps(&cands, &keep);
        let elapsed = started.elapsed();
        assert!(!chosen.is_empty());
        assert!(elapsed.as_secs_f64() < 2.0, "took {elapsed:?}");
    }

    fn kinds(text: &str) -> Vec<(EntityType, String)> {
        detect(text).into_iter().map(|e| (e.kind, e.text)).collect()
    }

    /// One engine pass with a score threshold (default locales).
    fn threshold_detect(text: &str, threshold: f32) -> Vec<Entity> {
        run(
            text,
            &EngineOpts {
                threshold,
                ..EngineOpts::default()
            },
        )
        .entities
    }

    /// One engine pass with NER recognizers (default locales).
    fn ner_detect(text: &str, ner: &[&dyn NerRecognizer]) -> Vec<Entity> {
        run(
            text,
            &EngineOpts {
                ner,
                ..EngineOpts::default()
            },
        )
        .entities
    }

    /// One engine pass with NER recognizers and a score threshold.
    fn ner_threshold_detect(text: &str, threshold: f32, ner: &[&dyn NerRecognizer]) -> Vec<Entity> {
        run(
            text,
            &EngineOpts {
                threshold,
                ner,
                ..EngineOpts::default()
            },
        )
        .entities
    }

    #[test]
    fn iban_wins_over_embedded_vkn_spans() {
        let t = "IBAN TR33 0006 1005 1978 6457 8413 26";
        let found = kinds(t);
        assert_eq!(found.len(), 1, "expected only the IBAN: {found:?}");
        assert_eq!(found[0].0, EntityType::Iban);
        assert_eq!(found[0].1, "TR33 0006 1005 1978 6457 8413 26");
    }

    #[test]
    fn adjacent_tckns_both_found() {
        let found = kinds("12345678950 ve 10000000146");
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|(k, _)| *k == EntityType::Tckn));
    }

    #[test]
    fn tckn_inside_longer_digit_run_is_rejected() {
        assert!(kinds("ref 123456789501 X").is_empty());
    }

    #[test]
    fn empty_input() {
        assert!(detect("").is_empty());
    }

    // ------------------------------------------------ plate alignment

    #[test]
    fn hyphenated_plate_is_detected() {
        let found = kinds("plaka 34-ABC-123 geçti");
        assert_eq!(found, vec![(EntityType::Plaka, "34-ABC-123".into())]);
    }

    #[test]
    fn qwx_letters_rejected() {
        assert!(!kinds("plaka 34 QWX 123")
            .iter()
            .any(|(k, _)| *k == EntityType::Plaka));
    }

    #[test]
    fn five_digit_serial_rejected() {
        assert!(!kinds("plaka 34 ABC 12345")
            .iter()
            .any(|(k, _)| *k == EntityType::Plaka));
    }

    // ------------------------------------------------ score + threshold

    #[test]
    fn scores_follow_structural_certainty() {
        let ents = detect("TCKN 12345678950");
        assert_eq!(ents[0].score, 1.0); // checksum verified -> certainty

        let ents = detect("Plaka 34 ABC 123"); // "plaka" cue nearby
        assert_eq!(
            ents.iter()
                .find(|e| e.kind == EntityType::Plaka)
                .map(|e| e.score),
            Some(0.95)
        );

        let ents = detect("Yolda 34 ABC 123 gördüm"); // no cue
        assert_eq!(
            ents.iter()
                .find(|e| e.kind == EntityType::Plaka)
                .map(|e| e.score),
            Some(0.85)
        );

        let ents = detect("mail a@b.com");
        assert_eq!(ents[0].score, 0.85);

        let ents = detect("Cep: 532 123 45 67");
        assert_eq!(ents[0].score, 0.8);
    }

    #[test]
    fn threshold_filters_weak_detections() {
        // a cue-less plate (0.85) is dropped at threshold 0.9; a cued one (0.95) stays
        assert_eq!(threshold_detect("Yolda 34 ABC 123 gördüm", 0.9).len(), 0);
        assert_eq!(
            threshold_detect("Plakası 34 ABC 123 olan araç", 0.9).len(),
            1
        );
        // checksum-backed types survive any reasonable threshold
        assert_eq!(threshold_detect("TCKN 12345678950", 0.99).len(), 1);
    }

    // ------------------------------------------------ line-scoped scanning

    #[test]
    fn multiline_offsets_are_global() {
        let text = "birinci satır\nTCKN 12345678950\nson satır";
        let ents = detect(text);
        assert_eq!(ents.len(), 1);
        assert_eq!(&text[ents[0].start..ents[0].end], "12345678950");
        // the TCKN is on line 2: the first line is 15 bytes ('ı' is 2 bytes)
        // plus the 5 bytes of "TCKN "
        assert_eq!(ents[0].start, 15 + 5);
    }

    #[test]
    fn crlf_line_endings_keep_offsets_correct() {
        let text = "satir1\r\nplaka 34 ABC 123\r\n";
        let ents = detect(text);
        assert_eq!(ents.len(), 1);
        assert_eq!(&text[ents[0].start..ents[0].end], "34 ABC 123");
    }

    // ------------------------------------------------ passport + landline

    #[test]
    fn passport_requires_cue() {
        let found = kinds("Pasaport numaram U12345678.");
        assert_eq!(found, vec![(EntityType::Passport, "U12345678".into())]);
        // lowercase u with a cue is also accepted
        let found = kinds("pasaport: u12345678");
        assert_eq!(found, vec![(EntityType::Passport, "u12345678".into())]);
        // no cue -> a checksum-less candidate cannot be claimed
        assert!(!kinds("kayit u12345678 tamam")
            .iter()
            .any(|(k, _)| *k == EntityType::Passport));
    }

    #[test]
    fn passport_score_is_structural() {
        let ents = detect("Pasaport: U12345678");
        assert_eq!(ents[0].kind, EntityType::Passport);
        assert_eq!(ents[0].score, 0.9); // format + mandatory cue; no checksum -> not 1.0
    }

    #[test]
    fn landline_detected_with_separator_after_area_code() {
        assert_eq!(
            kinds("ofis 0 212 555 44 33."),
            vec![(EntityType::Phone, "0 212 555 44 33".into())]
        );
        assert_eq!(
            kinds("ofis 0212 555 44 33."),
            vec![(EntityType::Phone, "0212 555 44 33".into())]
        );
    }

    #[test]
    fn bare_ten_digit_vkn_is_not_confused_with_landline() {
        // a REAL (checksum-valid) VKN starting with 212, without separators:
        let found = kinds("vergi no 2120000004");
        assert!(found
            .iter()
            .any(|(k, t)| *k == EntityType::Vkn && t == "2120000004"));
        assert!(!found.iter().any(|(k, _)| *k == EntityType::Phone));
        // with no cue, nothing is claimed
        assert!(kinds("kod 2120000004 x").is_empty());
    }

    // ------------------------------------------------ NER merge

    use crate::pii::ner::NerRecognizer;

    /// Test recognizer claiming the ENTIRE text as a NAME span (worst-case
    /// greedy model): overlap resolution must protect structural finds.
    struct WideRecognizer;

    impl NerRecognizer for WideRecognizer {
        fn recognize(&self, text: &str) -> Vec<Entity> {
            vec![Entity {
                kind: EntityType::Name,
                start: 0,
                end: text.len(),
                text: text.to_owned(),
                score: 0.99,
            }]
        }
        fn name(&self) -> &'static str {
            "wide"
        }
    }

    /// Test recognizer returning an offset that sits mid-character: the
    /// engine must drop it instead of panicking downstream slicing.
    struct BrokenRecognizer;

    impl NerRecognizer for BrokenRecognizer {
        fn recognize(&self, _text: &str) -> Vec<Entity> {
            // 'ü' is 2 bytes: offset 1 inside it is not a char boundary
            vec![Entity {
                kind: EntityType::Name,
                start: 1,
                end: 2,
                text: String::new(),
                score: 0.99,
            }]
        }
        fn name(&self) -> &'static str {
            "broken"
        }
    }

    #[test]
    fn ner_free_prose_name_found() {
        let ner = crate::MockNameRecognizer::new();
        // a name outside the Turkish lexicon: the recognizer's span (score
        // 0.9) is the only one (for "Ahmet Yılmaz" the lexicon scanner
        // reports the same span first and keeps the tie)
        let ents = ner_detect("Bugün toplantıda Jean Dupont konuştu.", &[&ner]);
        assert_eq!(ents.len(), 1);
        assert_eq!(ents[0].kind, EntityType::Name);
        assert_eq!(&ents[0].text, "Jean Dupont");
        assert_eq!(ents[0].score, 0.9);
    }

    #[test]
    fn checksum_always_beats_model_span() {
        // The recognizer claims the whole line (including the TCKN); the
        // TCKN (priority 3) must win and the greedy NAME span must drop.
        let text = "TCKN 12345678950 burada";
        let ents = ner_detect(text, &[&WideRecognizer]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::Tckn);
        assert_eq!(&ents[0].text, "12345678950");
    }

    #[test]
    fn ner_and_rules_coexist_without_overlap() {
        let ner = crate::MockNameRecognizer::new();
        let ents = ner_detect("Ahmet Yılmaz'ın TCKN 12345678950", &[&ner]);
        let k: Vec<_> = ents.iter().map(|e| e.kind).collect();
        assert!(k.contains(&EntityType::Name), "{ents:?}");
        assert!(k.contains(&EntityType::Tckn), "{ents:?}");
    }

    #[test]
    fn invalid_model_spans_are_dropped() {
        let ents = ner_detect("ğüps", &[&BrokenRecognizer]);
        assert!(ents.is_empty(), "{ents:?}");
    }

    /// Priority-8 cross-kind overlap (PII-Bench v4 evidence: XLM-R LOC ⊃
    /// PIIRanha GIVENNAME): both must survive.
    struct NameInsideAddress;

    impl NerRecognizer for NameInsideAddress {
        fn recognize(&self, text: &str) -> Vec<Entity> {
            let name_end = text.find(" Institute").unwrap_or(text.len());
            vec![
                Entity {
                    kind: EntityType::Address,
                    start: 0,
                    end: name_end + " Institute".len(),
                    text: text.to_owned(),
                    score: 0.9,
                },
                Entity {
                    kind: EntityType::Name,
                    start: 0,
                    end: name_end,
                    text: text[..name_end].to_owned(),
                    score: 0.9,
                },
            ]
        }
        fn name(&self) -> &'static str {
            "name-in-address"
        }
    }

    /// Same-kind priority-8 overlaps: only the longer span survives.
    struct TwoSameKind;

    impl NerRecognizer for TwoSameKind {
        fn recognize(&self, text: &str) -> Vec<Entity> {
            vec![
                Entity {
                    kind: EntityType::Name,
                    start: 0,
                    end: 6,
                    text: text[..6].to_owned(),
                    score: 0.9,
                },
                Entity {
                    kind: EntityType::Name,
                    start: 3,
                    end: text.len(),
                    text: text.to_owned(),
                    score: 0.9,
                },
            ]
        }
        fn name(&self) -> &'static str {
            "two-same-kind"
        }
    }

    #[test]
    fn priority8_cross_kind_overlap_coexists() {
        let ents = ner_detect("Johannes R. Becher Institute", &[&NameInsideAddress]);
        let kinds: Vec<_> = ents.iter().map(|e| e.kind).collect();
        assert!(kinds.contains(&EntityType::Name), "{ents:?}");
        assert!(kinds.contains(&EntityType::Address), "{ents:?}");
    }

    #[test]
    fn priority8_same_kind_overlap_keeps_longer_only() {
        let ents = ner_detect("Ahmet Yılmaz", &[&TwoSameKind]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].end, "Ahmet Yılmaz".len());
    }

    #[test]
    fn checksum_still_beats_priority8_pair() {
        // a structural find overlapping the coexisting pair still wins both
        let text = "TCKN 12345678950 burada";
        let ents = ner_detect(text, &[&WideRecognizer]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::Tckn);
    }

    #[test]
    fn ner_threshold_applies_to_merged_result() {
        let ner = crate::MockNameRecognizer::new();
        let text = "Bugün toplantıda Ahmet Yılmaz konuştu.";
        // mock score 0.9: kept at 0.85, dropped at 0.95
        assert_eq!(ner_threshold_detect(text, 0.85, &[&ner]).len(), 1);
        assert_eq!(ner_threshold_detect(text, 0.95, &[&ner]).len(), 0);
    }

    // ------------------------------------------------ allowlist pre-filter

    use crate::pii::custom::CustomRule;

    /// One engine pass with custom rules, an allowlist and a threshold.
    fn ignore_detect(
        text: &str,
        custom: &[&CustomRule],
        ignored: &[&str],
        threshold: f32,
    ) -> Vec<(EntityType, String)> {
        run(
            text,
            &EngineOpts {
                custom,
                ignored,
                threshold,
                ..EngineOpts::default()
            },
        )
        .entities
        .into_iter()
        .map(|e| (e.kind, e.text))
        .collect()
    }

    #[test]
    fn ignored_winner_no_longer_hides_the_overlapping_loser() {
        // "AB-1234" (TCKN tier 3) beats the partially overlapping
        // "1234-CD" (VKN tier 7). The allowlist is a pre-filter, so the
        // loser competes on its own once the winner is allowlisted; removing
        // the winner after resolution would leave nothing reported.
        let winner = CustomRule::new(EntityType::Tckn, r"AB-\d{4}").unwrap();
        let loser = CustomRule::new(EntityType::Vkn, r"\d{4}-CD").unwrap();
        let rules = [&winner, &loser];
        let text = "ref AB-1234-CD x";
        assert_eq!(
            ignore_detect(text, &rules, &[], 0.0),
            vec![(EntityType::Tckn, "AB-1234".to_owned())]
        );
        assert_eq!(
            ignore_detect(text, &rules, &["AB-1234"], 0.0),
            vec![(EntityType::Vkn, "1234-CD".to_owned())]
        );
    }

    #[test]
    fn candidates_inside_an_ignored_value_are_dropped_too() {
        // the allowlisted value as a whole is not PII, so a candidate lying
        // entirely inside it must not resurface once the outer one is gone
        let outer = CustomRule::new(EntityType::Tckn, r"AB-\d{4}").unwrap();
        let inner = CustomRule::new(EntityType::Vkn, r"\d{4}").unwrap();
        let rules = [&outer, &inner];
        assert_eq!(
            ignore_detect("ref AB-1234 x", &rules, &["AB-1234"], 0.0),
            Vec::new()
        );
        // the same inner value elsewhere is still reported
        assert_eq!(
            ignore_detect("ref AB-1234 and 5678", &rules, &["AB-1234"], 0.0),
            vec![(EntityType::Vkn, "5678".to_owned())]
        );
    }

    #[test]
    fn allowlist_and_threshold_are_consistent_with_and_without_each_other() {
        // allowlist and threshold are both engine pre-filters, so an empty
        // or non-matching allowlist never changes the result at any
        // threshold
        let texts = [
            "TCKN'm 12345678950, IBAN TR33 0006 1005 1978 6457 8413 26, mail a@b.com",
            "Plakası 34 ABC 123 olan araç, yolda 34 ABC 123 gördüm",
            "Destek: 0532 123 45 67, vergi no 1234567890",
            "kart 4111111111111111",
        ];
        for text in texts {
            for t in [0.0, 0.85, 0.9, 0.99] {
                let plain = ignore_detect(text, &[], &[], t);
                assert_eq!(
                    ignore_detect(text, &[], &["absent"], t),
                    plain,
                    "{text} @ {t}"
                );
                // allowlisting one reported value removes exactly that
                // value here (no other candidate overlaps it)
                if let Some((_, first)) = plain.first() {
                    let without: Vec<_> =
                        plain.iter().filter(|(_, v)| v != first).cloned().collect();
                    assert_eq!(
                        ignore_detect(text, &[], &[first.as_str()], t),
                        without,
                        "{text} @ {t}"
                    );
                }
            }
        }
    }

    // ------------------------------------------------ explanations

    use super::{DetectionSource, DetectionView};

    #[test]
    fn explanations_align_with_entities_and_leave_them_unchanged() {
        let ner = crate::MockNameRecognizer::new();
        let rule = CustomRule::new(EntityType::Itin, r"ORC-\d{4}")
            .unwrap()
            .with_cue(&["Ticket"]);
        // a name outside the Turkish lexicon: only the mock recognizer
        // claims it (the lexicon scanner would win "Ahmet Yılmaz")
        let text = "Jean Dupont ticket ORC-1234, vergi no 1234567890\n\
                    ip 0 a 12 : d3 3 e : a 9 b 2 : db 4 a : b2 e 7 : 76 cd : 9 ea c : 29 af ok";
        let base = EngineOpts {
            ner: &[&ner as &dyn NerRecognizer],
            custom: &[&rule],
            ..EngineOpts::default()
        };
        let plain = run(text, &base);
        assert!(plain.explanations.is_empty(), "no work without the flag");
        let explained = run(
            text,
            &EngineOpts {
                explain: true,
                ..base
            },
        );
        assert_eq!(explained.entities, plain.entities);
        assert_eq!(explained.explanations.len(), explained.entities.len());
        let by_text = |needle: &str| {
            let i = explained
                .entities
                .iter()
                .position(|e| e.text.contains(needle))
                .unwrap_or_else(|| panic!("{needle} not found: {:?}", explained.entities));
            explained.explanations[i].clone()
        };
        let name = by_text("Jean");
        assert_eq!(name.source, DetectionSource::Ner { name: "mock-ner" });
        assert!(!name.validator_passed);
        assert_eq!(name.cue, None);
        let custom = by_text("ORC-1234");
        assert_eq!(custom.source, DetectionSource::Custom { index: 0 });
        assert_eq!(custom.cue.as_deref(), Some("ticket"));
        assert!(!custom.validator_passed);
        let vkn = by_text("1234567890");
        assert_eq!(vkn.source, DetectionSource::Rule { id: "tr::vkn" });
        assert!(vkn.validator_passed);
        assert_eq!(vkn.cue.as_deref(), Some("vergi"));
        let ip = by_text("d3 3 e");
        assert_eq!(
            ip.source,
            DetectionSource::Rule {
                id: "generic::ipv6_collapsed"
            }
        );
        assert!(explained
            .explanations
            .iter()
            .all(|w| w.view == DetectionView::Raw));
        for (e, w) in explained.entities.iter().zip(&explained.explanations) {
            assert_eq!(e.score, w.score, "{e:?}");
            assert!(w.score >= w.base_score, "{w:?}");
        }
    }
}
