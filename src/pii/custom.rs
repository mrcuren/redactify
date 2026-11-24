//! User-defined detection rules (caller extension point).
//!
//! The built-in locale rules are crate-private by design (checksum-locked,
//! canary-gated). Domain-specific identifiers (internal ticket numbers,
//! employee IDs, product serials, ...) are caller-specific: [`CustomRule`]
//! lets a user register a pattern (+ optional validator) that joins the
//! SAME pipeline as the built-ins - one candidate pool, one overlap
//! resolution, one threshold semantics.

use std::sync::Arc;

use crate::pii::context::normalize_tr;
use crate::pii::entity::{CustomLabelError, EntityType};
use crate::pii::rule::BACKTRACK_LIMIT;

/// Error of [`CustomRule::new`].
///
/// # Examples
/// ```
/// use redactify::{CustomRule, CustomRuleError, EntityType};
///
/// let err = CustomRule::new(EntityType::Itin, r"ORC-(\d+").unwrap_err();
/// assert!(matches!(err, CustomRuleError::InvalidPattern(_)));
/// // the underlying regex error stays reachable through `source()`
/// assert!(std::error::Error::source(&err).is_some());
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CustomRuleError {
    /// The pattern does not compile (syntax error, unsupported construct,
    /// or a compiled program over the engine's size limit).
    #[error("invalid custom rule pattern: {0}")]
    InvalidPattern(#[source] Box<fancy_regex::Error>),
    /// The label of a [`CustomRuleSpec`] is neither a built-in label nor a
    /// valid custom label (see [`EntityType::custom`]).
    #[error("invalid custom rule label: {0}")]
    Label(#[from] CustomLabelError),
    /// A [`CustomRuleSpec`] must set exactly one of `pattern` and `words`.
    #[error("a custom rule needs exactly one of `pattern` and `words`")]
    PatternOrWords,
    /// A [`CustomRuleSpec`] score outside `0.0..=1.0` (or NaN).
    #[error("custom rule score {0} is outside 0.0..=1.0")]
    ScoreOutOfRange(f32),
    /// [`CustomRule::new_linear`] refused the pattern. The text names the
    /// limit or the construct and a byte offset, never the pattern.
    #[error("custom rule pattern rejected: {0}")]
    Rejected(String),
}

/// The context-cue policy of a custom rule: like the built-in rules'
/// policy, but with OWNED cue lists, normalized when the rule is built.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum CustomContext {
    /// No context handling.
    None,
    /// The match is claimed only with a cue nearby.
    RequiredCue(Vec<String>),
    /// A nearby cue raises the score to the boosted value.
    Boost(Vec<String>, f32),
}

/// Normalizes cue words the way the engine normalizes the context it
/// searches ([`normalize_tr`]: lowercase, dotless i folded, combining dot
/// above stripped) and drops cues that are empty after normalization (an
/// empty cue would match every context).
fn normalize_cues(cues: &[&str]) -> Vec<String> {
    cues.iter()
        .map(|c| normalize_tr(c))
        .filter(|c| !c.is_empty())
        .collect()
}

/// Compiles a detection pattern with the explicit backtrack budget shared
/// by every detection regex.
fn compile(pattern: &str) -> Result<fancy_regex::Regex, fancy_regex::Error> {
    fancy_regex::RegexBuilder::new(pattern)
        .backtrack_limit(BACKTRACK_LIMIT)
        .build()
}

/// Longest pattern [`CustomRule::new_linear`] accepts, in bytes.
pub const LINEAR_MAX_PATTERN_BYTES: usize = 256;

/// Fewest characters a [`CustomRule::new_linear`] pattern must match: a
/// shorter shortest-match (`\d`, `.`, `a?`) would claim a span at nearly
/// every position of a long text.
pub const LINEAR_MIN_MATCH_LEN: usize = 3;

/// Deepest group nesting [`CustomRule::new_linear`] accepts.
const LINEAR_NEST_LIMIT: u32 = 20;

/// Compiled-program size limit of [`CustomRule::new_linear`], in bytes.
const LINEAR_SIZE_LIMIT: usize = 256 * 1024;

/// The message of a pattern parse error: the kind and the byte offset,
/// without the pattern text the library error would quote.
fn syntax_message(e: &regex_syntax::Error) -> String {
    match e {
        regex_syntax::Error::Parse(p) => {
            format!("{} (byte {})", p.kind(), p.span().start.offset)
        }
        regex_syntax::Error::Translate(t) => {
            format!("{} (byte {})", t.kind(), t.span().start.offset)
        }
        _ => "unsupported syntax".to_owned(),
    }
}

/// A user-supplied detection rule: regex + optional validator + entity
/// kind + score + optional context cue. Built-in rules keep absolute
/// priority over checksum-backed kinds; the rule's `kind` decides overlap
/// priority ([`EntityType::priority`]) exactly like a built-in match.
///
/// # Examples
/// ```
/// use redactify::{CustomRule, Detector, EntityType};
///
/// // internal ticket references like ORC-12345
/// let rule = CustomRule::new(EntityType::Itin, r"ORC-\d{4,6}").expect("compiles");
/// let rules = [&rule];
/// let ents = Detector::new()
///     .with_locales(&["en"])
///     .with_custom_rules(&rules)
///     .detect("bkz ORC-12345 detay");
/// assert!(ents.iter().any(|e| e.text == "ORC-12345"), "{ents:?}");
///
/// // deny-list: exact words that should always be redacted
/// let deny = CustomRule::deny_list(EntityType::Name, &["AcmeCorp", "SecretProject"]);
/// let rules = [&deny];
/// let ents = Detector::new()
///     .with_locales(&["en"])
///     .with_custom_rules(&rules)
///     .detect("client AcmeCorp called");
/// assert!(ents.iter().any(|e| e.text == "AcmeCorp"), "{ents:?}");
/// ```
#[derive(Debug, Clone)]
pub struct CustomRule {
    pub(crate) kind: EntityType,
    pub(crate) regex: fancy_regex::Regex,
    pub(crate) validator: Option<fn(&str) -> bool>,
    pub(crate) score: f32,
    pub(crate) context: CustomContext,
}

impl CustomRule {
    /// Compiles `pattern` (full `fancy-regex` syntax, lookarounds included)
    /// into a rule that emits entities of `kind`, which drives the mask
    /// label and the overlap priority: a built-in kind, or a type with its
    /// own label from [`EntityType::custom`] (`[EMPLOYEE_ID]`, overlap tier
    /// 7).
    ///
    /// The pattern runs with the same backtracking budget as the built-in
    /// rules (1,000,000 steps per match attempt). A line on which a match
    /// attempt exhausts it is reported as not fully scanned
    /// ([`ScanReport::error_spans`](crate::ScanReport::error_spans)) and
    /// masked as a whole by [`Detector::redact`](crate::Detector::redact).
    /// A zero-width match (`\d*` between two letters, a bare lookahead) is
    /// never a finding: it holds no text to mask.
    ///
    /// # Errors
    /// [`CustomRuleError::InvalidPattern`] when the pattern does not
    /// compile.
    pub fn new(kind: EntityType, pattern: &str) -> Result<Self, CustomRuleError> {
        let regex = compile(pattern).map_err(|e| CustomRuleError::InvalidPattern(Box::new(e)))?;
        Ok(Self {
            kind,
            regex,
            validator: None,
            score: 0.8,
            context: CustomContext::None,
        })
    }

    /// Compiles `pattern` restricted to the linear-time regex syntax, the
    /// constructor for a pattern that comes from an untrusted caller.
    ///
    /// The pattern must parse with the plain regular-expression grammar:
    /// look-around, back-references and atomic groups are refused, so the
    /// engine never backtracks and a match attempt costs time linear in the
    /// text, whatever the pattern (`(a+)+b` included). Further limits: at
    /// most [`LINEAR_MAX_PATTERN_BYTES`] bytes, group nesting at most 20, a
    /// shortest match of at least [`LINEAR_MIN_MATCH_LEN`] characters and a
    /// compiled program under 256 KiB. Inline flags such as `(?i)` are
    /// fine. Errors name the construct or limit and a byte offset, never
    /// the pattern.
    ///
    /// # Errors
    /// [`CustomRuleError::Rejected`].
    ///
    /// # Examples
    /// ```
    /// use redactify::{CustomRule, Detector, EntityType};
    ///
    /// let rule = CustomRule::new_linear(EntityType::Itin, r"(?i)acme-[a-z]{4}").unwrap();
    /// let rules = [&rule];
    /// assert_eq!(Detector::new().with_custom_rules(&rules).redact("see ACME-wxyz"), "see [ITIN]");
    /// assert!(CustomRule::new_linear(EntityType::Itin, r"foo(?=bar)").is_err()); // look-ahead
    /// assert!(CustomRule::new_linear(EntityType::Itin, r"\d").is_err()); // matches one character
    /// ```
    pub fn new_linear(kind: EntityType, pattern: &str) -> Result<Self, CustomRuleError> {
        let reject = |m: String| CustomRuleError::Rejected(m);
        if pattern.len() > LINEAR_MAX_PATTERN_BYTES {
            return Err(reject(format!(
                "longer than {LINEAR_MAX_PATTERN_BYTES} bytes"
            )));
        }
        let hir = regex_syntax::ParserBuilder::new()
            .nest_limit(LINEAR_NEST_LIMIT)
            .build()
            .parse(pattern)
            .map_err(|e| reject(syntax_message(&e)))?;
        if hir.properties().minimum_len().unwrap_or(0) < LINEAR_MIN_MATCH_LEN {
            return Err(reject(format!(
                "it can match fewer than {LINEAR_MIN_MATCH_LEN} characters"
            )));
        }
        let regex = fancy_regex::RegexBuilder::new(pattern)
            .backtrack_limit(BACKTRACK_LIMIT)
            .delegate_size_limit(LINEAR_SIZE_LIMIT)
            .delegate_dfa_size_limit(LINEAR_SIZE_LIMIT)
            .build()
            .map_err(|_| reject("compiled pattern is over the size limit".to_owned()))?;
        Ok(Self {
            kind,
            regex,
            validator: None,
            score: 0.8,
            context: CustomContext::None,
        })
    }

    /// Creates a deny-list rule: matches any of `words` as a whole word
    /// (case-sensitive, word-boundary delimited). Use this to redact
    /// specific known-sensitive terms (project codenames, client names).
    ///
    /// Empty words are silently dropped; an all-empty list produces a
    /// never-matching rule (not an error).
    #[must_use]
    pub fn deny_list(kind: EntityType, words: &[&str]) -> Self {
        Self::deny_list_with_case(kind, words, false)
    }

    /// Like [`deny_list`](Self::deny_list), but the words match regardless
    /// of letter case (Unicode case folding of the regex engine).
    ///
    /// # Examples
    /// ```
    /// use redactify::{CustomRule, Detector, EntityType};
    ///
    /// let rule = CustomRule::deny_list_ignore_case(EntityType::Itin, &["Phoenix"]);
    /// let rules = [&rule];
    /// let d = Detector::new().with_custom_rules(&rules);
    /// assert_eq!(d.redact("ask PHOENIX now"), "ask [ITIN] now");
    /// ```
    #[must_use]
    pub fn deny_list_ignore_case(kind: EntityType, words: &[&str]) -> Self {
        Self::deny_list_with_case(kind, words, true)
    }

    fn deny_list_with_case(kind: EntityType, words: &[&str], ignore_case: bool) -> Self {
        let escaped: Vec<String> = words
            .iter()
            .filter(|w| !w.is_empty())
            .map(|w| fancy_regex::escape(w).into_owned())
            .collect();
        // an all-empty list must be a NEVER-matching rule (doc contract):
        // the naive `\b(?:)\b` alternative matches at every word boundary
        // (zero-width alternation), flagging plain text
        let pattern = if escaped.is_empty() {
            r"(?!)".to_owned()
        } else {
            let flag = if ignore_case { "(?i)" } else { "" };
            format!(r"{flag}\b(?:{})\b", escaped.join("|"))
        };
        // deny_list is infallible: every non-empty word is escaped
        let regex = compile(&pattern).expect("escaped words compile");
        Self {
            kind,
            regex,
            validator: None,
            score: 0.95,
            context: CustomContext::None,
        }
    }

    /// Adds a precision gate: a match is claimed only when the validator
    /// accepts the matched text (e.g. a modulus check for an internal ID).
    #[must_use]
    pub const fn with_validator(mut self, validator: fn(&str) -> bool) -> Self {
        self.validator = Some(validator);
        self
    }

    /// Overrides the confidence score (default 0.8; also feeds
    /// score cutoffs such as `Detector::with_threshold`).
    #[must_use]
    pub const fn with_score(mut self, score: f32) -> Self {
        self.score = score;
        self
    }

    /// Adds a context-cue requirement: a match is claimed only when one
    /// of the cue words is near it (same machinery as the built-in locale
    /// rules): a cue before the match counts when it ENDS within 18
    /// characters of the match, a cue after it must lie entirely within
    /// the 18 characters that follow. A cue of at most 5 characters that
    /// starts with an ASCII letter counts only at the start of a word (so
    /// `"tax"` matches `TAX:` but not `syntax`); longer cues match anywhere.
    ///
    /// Cue matching is case-insensitive and Turkish-aware: the cues are
    /// normalized here (lowercased, dotless `ı` folded to `i`, the
    /// combining dot above dropped) exactly like the text around a match,
    /// so `"Müşteri No"` matches `MÜŞTERİ NO` and `müşteri no` alike. Cues
    /// that are empty after normalization are dropped; a rule left with no
    /// cue never matches.
    ///
    /// # Examples
    /// ```
    /// use redactify::{CustomRule, Detector, EntityType};
    ///
    /// let rule = CustomRule::new(EntityType::Itin, r"\b\d{6}\b")
    ///     .unwrap()
    ///     .with_cue(&["Müşteri No"]);
    /// let rules = [&rule];
    /// let d = Detector::new().with_custom_rules(&rules);
    /// assert_eq!(d.redact("MÜŞTERİ NO: 482913"), "MÜŞTERİ NO: [ITIN]");
    /// assert_eq!(d.redact("siparis 482913"), "siparis 482913");
    /// ```
    #[must_use]
    pub fn with_cue(mut self, cues: &[&str]) -> Self {
        self.context = CustomContext::RequiredCue(normalize_cues(cues));
        self
    }

    /// Adds a context-cue score boost: when a cue word is nearby, the
    /// score is boosted to `boosted` (e.g. 0.8 -> 0.95). Cues are
    /// normalized like in [`CustomRule::with_cue`].
    ///
    /// # Examples
    /// ```
    /// use redactify::{CustomRule, Detector, EntityType};
    ///
    /// let rule = CustomRule::new(EntityType::Itin, r"X\d{5}")
    ///     .unwrap()
    ///     .with_score(0.5)
    ///     .with_cue_boost(&["Ticket"], 0.95);
    /// let rules = [&rule];
    /// let d = Detector::new().with_custom_rules(&rules);
    /// assert_eq!(d.detect("TICKET X12345")[0].score, 0.95);
    /// assert_eq!(d.detect("X12345")[0].score, 0.5);
    /// ```
    #[must_use]
    pub fn with_cue_boost(mut self, cues: &[&str], boosted: f32) -> Self {
        self.context = CustomContext::Boost(normalize_cues(cues), boosted);
        self
    }
}

/// A custom rule as configuration data (the TOML policy's
/// `[[custom_rules]]` table): a `label` (a built-in label such as `ITIN`
/// or a custom one, registered on compilation, see
/// [`EntityType::custom`]), either a `pattern` or deny-list `words`,
/// optional required context `cues` and an optional `score` in
/// `0.0..=1.0` (default 0.8 for a pattern and 0.95 for words, as
/// [`CustomRule::new`] and [`CustomRule::deny_list`] set them).
///
/// # Examples
/// ```
/// use redactify::{CustomRuleSpec, Detector};
///
/// let rule = CustomRuleSpec::pattern("TICKET_ID", r"\bT-\d{4}\b")
///     .with_cues(&["ticket"])
///     .compile()
///     .unwrap();
/// let rules = [&rule];
/// let d = Detector::new().with_custom_rules(&rules);
/// assert_eq!(d.redact("ticket T-1234"), "ticket [TICKET_ID]");
/// assert_eq!(d.redact("T-1234"), "T-1234"); // the cue is required
/// ```
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
#[non_exhaustive]
pub struct CustomRuleSpec {
    /// Entity label: a built-in label or a custom label.
    pub label: String,
    /// The detection pattern (`fancy-regex` syntax); exclusive with
    /// `words`.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub pattern: Option<String>,
    /// Deny-list words matched as whole words; exclusive with `pattern`.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub words: Vec<String>,
    /// Required context cues (see [`CustomRule::with_cue`]); empty = none.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub cues: Vec<String>,
    /// Score override in `0.0..=1.0`.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub score: Option<f32>,
}

impl CustomRuleSpec {
    /// A pattern rule for `label`.
    #[must_use]
    pub fn pattern(label: &str, pattern: &str) -> Self {
        Self {
            label: label.to_owned(),
            pattern: Some(pattern.to_owned()),
            ..Self::default()
        }
    }

    /// A deny-list rule for `label`.
    #[must_use]
    pub fn words(label: &str, words: &[&str]) -> Self {
        Self {
            label: label.to_owned(),
            words: words.iter().map(|w| (*w).to_owned()).collect(),
            ..Self::default()
        }
    }

    /// Requires one of `cues` near a match.
    #[must_use]
    pub fn with_cues(mut self, cues: &[&str]) -> Self {
        self.cues = cues.iter().map(|c| (*c).to_owned()).collect();
        self
    }

    /// Overrides the score.
    #[must_use]
    pub const fn with_score(mut self, score: f32) -> Self {
        self.score = Some(score);
        self
    }

    /// Compiles the spec into a [`CustomRule`] (a new custom label is
    /// registered here).
    ///
    /// # Errors
    /// [`CustomRuleError::Label`], [`CustomRuleError::PatternOrWords`],
    /// [`CustomRuleError::ScoreOutOfRange`] or
    /// [`CustomRuleError::InvalidPattern`].
    pub fn compile(&self) -> Result<CustomRule, CustomRuleError> {
        if let Some(score) = self.score {
            if !(0.0..=1.0).contains(&score) {
                return Err(CustomRuleError::ScoreOutOfRange(score));
            }
        }
        let kind = match self.label.parse::<EntityType>() {
            Ok(kind) => kind,
            Err(_) => EntityType::custom(&self.label)?,
        };
        let mut rule = match (&self.pattern, self.words.is_empty()) {
            (Some(pattern), true) => CustomRule::new(kind, pattern)?,
            (None, false) => {
                let words: Vec<&str> = self.words.iter().map(String::as_str).collect();
                CustomRule::deny_list(kind, &words)
            }
            _ => return Err(CustomRuleError::PatternOrWords),
        };
        if !self.cues.is_empty() {
            let cues: Vec<&str> = self.cues.iter().map(String::as_str).collect();
            rule = rule.with_cue(&cues);
        }
        if let Some(score) = self.score {
            rule = rule.with_score(score);
        }
        Ok(rule)
    }
}

/// A list of [`CustomRuleSpec`]s together with their compiled rules: built
/// only through [`CustomRules::new`], which compiles every spec, so a
/// value never holds a rule that does not compile. Equality, `Debug` and
/// serde (a list of specs) look at the specs; clones share the compiled
/// rules.
///
/// # Examples
/// ```
/// use redactify::{CustomRuleSpec, CustomRules};
///
/// let rules = CustomRules::new(vec![CustomRuleSpec::words("CODENAME", &["Falcon"])]).unwrap();
/// assert_eq!(rules.len(), 1);
/// let err = CustomRules::new(vec![CustomRuleSpec::pattern("BAD", "(")]).unwrap_err();
/// assert_eq!(err.index, 0);
/// ```
#[derive(Clone)]
pub struct CustomRules {
    specs: Vec<CustomRuleSpec>,
    compiled: Arc<[CustomRule]>,
}

/// Which spec of [`CustomRules::new`] failed to compile, and why.
#[derive(Debug, thiserror::Error)]
#[error("custom rule {index}: {source}")]
#[non_exhaustive]
pub struct CustomRulesError {
    /// Position of the failing spec (0-based).
    pub index: usize,
    /// The compilation error.
    #[source]
    pub source: CustomRuleError,
}

impl CustomRules {
    /// Compiles every spec.
    ///
    /// # Errors
    /// [`CustomRulesError`] naming the first spec that does not compile.
    pub fn new(specs: Vec<CustomRuleSpec>) -> Result<Self, CustomRulesError> {
        let compiled = specs
            .iter()
            .enumerate()
            .map(|(index, spec)| {
                spec.compile()
                    .map_err(|source| CustomRulesError { index, source })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            specs,
            compiled: Arc::from(compiled),
        })
    }

    /// The specs, in order.
    #[must_use]
    pub fn specs(&self) -> &[CustomRuleSpec] {
        &self.specs
    }

    /// The compiled rules, in spec order.
    #[must_use]
    pub fn rules(&self) -> &[CustomRule] {
        &self.compiled
    }

    /// Number of rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.specs.len()
    }

    /// Whether there is no rule.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.specs.is_empty()
    }
}

impl Default for CustomRules {
    fn default() -> Self {
        Self {
            specs: Vec::new(),
            compiled: Arc::from(Vec::new()),
        }
    }
}

impl PartialEq for CustomRules {
    fn eq(&self, other: &Self) -> bool {
        self.specs == other.specs
    }
}

impl std::fmt::Debug for CustomRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CustomRules").field(&self.specs).finish()
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for CustomRules {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.specs.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for CustomRules {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let specs = Vec::<CustomRuleSpec>::deserialize(deserializer)?;
        Self::new(specs).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::{CustomContext, CustomRule, CustomRuleError};
    use crate::pii::{run, EngineOpts, Entity, NerRecognizer};
    use crate::EntityType;

    /// One engine pass: the built-in rules of `locales` plus `custom`.
    fn custom_detect(text: &str, locales: &[&str], custom: &[&CustomRule]) -> Vec<Entity> {
        run(
            text,
            &EngineOpts {
                locales,
                custom,
                ..EngineOpts::default()
            },
        )
        .entities
    }

    #[test]
    fn invalid_pattern_is_a_typed_error_with_its_source() {
        let err = CustomRule::new(EntityType::Itin, r"ORC-(\d+").unwrap_err();
        assert!(matches!(err, CustomRuleError::InvalidPattern(_)));
        assert!(err.to_string().starts_with("invalid custom rule pattern: "));
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn deny_list_all_empty_is_never_matching() {
        // a naive `(?:)` would zero-width-match at every word boundary and
        // flag plain text
        let deny = super::CustomRule::deny_list(EntityType::Name, &["", ""]);
        let ents = custom_detect("hello world", &["en"], &[&deny]);
        assert!(
            ents.is_empty(),
            "all-empty deny list must never match: {ents:?}"
        );
        // mixed lists still drop only the empty entries
        let deny = super::CustomRule::deny_list(EntityType::Name, &["", "AcmeCorp"]);
        let ents = custom_detect("client AcmeCorp called", &["en"], &[&deny]);
        assert_eq!(ents.len(), 1);
        assert_eq!(ents[0].text, "AcmeCorp");
    }

    #[test]
    fn custom_rule_detects_and_validates() {
        let rule = CustomRule::new(EntityType::Itin, r"ORC-\d{4,6}").unwrap();
        let ents = custom_detect("bkz ORC-12345 detay", &["en"], &[&rule]);
        assert_eq!(
            ents.iter().filter(|e| e.kind == EntityType::Itin).count(),
            1
        );

        // validator rejects
        let strict = rule.clone().with_validator(|s| !s.ends_with("9999"));
        assert!(custom_detect("ref ORC-9999", &["en"], &[&strict])
            .iter()
            .all(|e| e.kind != EntityType::Itin));
    }

    #[test]
    fn checksum_rule_beats_custom_on_overlap() {
        // custom claims a span containing a TCKN: the checksum entity wins
        let greedy = CustomRule::new(EntityType::Vkn, r"ID \d{11}").unwrap();
        let ents = custom_detect("ID 12345678950 burada", &["tr", "en"], &[&greedy]);
        let tckn = ents.iter().find(|e| e.kind == EntityType::Tckn);
        assert!(tckn.is_some(), "{ents:?}");
        assert!(ents.iter().all(|e| e.kind != EntityType::Vkn), "{ents:?}");
    }

    #[test]
    fn custom_rules_compose_with_ner() {
        use crate::MockNameRecognizer;
        let rule = CustomRule::new(EntityType::Itin, r"ORC-\d{4}").unwrap();
        let ner = MockNameRecognizer::new();
        let ents = run(
            "Ahmet Yılmaz ORC-1234",
            &EngineOpts {
                locales: &["tr", "en"],
                ner: &[&ner as &dyn NerRecognizer],
                custom: &[&rule],
                ..EngineOpts::default()
            },
        )
        .entities;
        assert!(ents.iter().any(|e| e.kind == EntityType::Name), "{ents:?}");
        assert!(ents.iter().any(|e| e.kind == EntityType::Itin), "{ents:?}");
    }

    #[test]
    fn deny_list_detects_words() {
        let deny = CustomRule::deny_list(EntityType::Name, &["AcmeCorp", "SecretProject"]);
        let ents = custom_detect("client AcmeCorp called", &["en"], &[&deny]);
        assert!(ents.iter().any(|e| e.text == "AcmeCorp"), "{ents:?}");
        // word-boundary: AcmeCorporation does NOT match AcmeCorp
        let ents = custom_detect("AcmeCorporation is big", &["en"], &[&deny]);
        assert!(!ents.iter().any(|e| e.text == "AcmeCorp"), "{ents:?}");
        // both words
        let ents = custom_detect("SecretProject and AcmeCorp", &["en"], &[&deny]);
        assert_eq!(
            ents.iter().filter(|e| e.kind == EntityType::Name).count(),
            2
        );
    }

    #[test]
    fn custom_rule_with_cue_required() {
        // without cue: not claimed
        let rule = CustomRule::new(EntityType::Itin, r"X\d{5}")
            .unwrap()
            .with_cue(&["internal", "ticket", "ref"]);
        let ents = custom_detect("X12345 here", &["en"], &[&rule]);
        assert!(!ents.iter().any(|e| e.kind == EntityType::Itin), "{ents:?}");
        // with cue: claimed
        let ents = custom_detect("internal X12345 here", &["en"], &[&rule]);
        assert!(ents.iter().any(|e| e.kind == EntityType::Itin), "{ents:?}");
    }

    #[test]
    fn custom_rule_with_cue_boost() {
        let rule = CustomRule::new(EntityType::Itin, r"X\d{5}")
            .unwrap()
            .with_score(0.5)
            .with_cue_boost(&["internal", "ticket"], 0.95);
        // no cue: base score 0.5
        let ents = custom_detect("X12345", &["en"], &[&rule]);
        let e = ents.iter().find(|e| e.kind == EntityType::Itin).unwrap();
        assert!((e.score - 0.5).abs() < 1e-6);
        // with cue: boosted to 0.95
        let ents = custom_detect("ticket X12345", &["en"], &[&rule]);
        let e = ents.iter().find(|e| e.kind == EntityType::Itin).unwrap();
        assert!((e.score - 0.95).abs() < 1e-6);
    }

    #[test]
    fn mixed_case_turkish_cues_match_after_normalization() {
        // cues are normalized like the context; stored raw, a capitalized
        // or dotted-I cue would never match
        let rule = CustomRule::new(EntityType::Itin, r"\b\d{6}\b")
            .unwrap()
            .with_cue(&["Müşteri No"]);
        assert_eq!(
            rule.context,
            CustomContext::RequiredCue(vec!["müşteri no".to_owned()])
        );
        for text in [
            "Müşteri No: 482913",
            "MÜŞTERİ NO 482913",
            "müşteri no 482913",
        ] {
            let ents = custom_detect(text, &["tr"], &[&rule]);
            assert!(
                ents.iter().any(|e| e.kind == EntityType::Itin),
                "{text}: {ents:?}"
            );
        }
        assert!(custom_detect("kod 482913", &["tr"], &[&rule]).is_empty());
        // a dotless-i spelling in the cue folds the same way as the text
        let rule = CustomRule::new(EntityType::Itin, r"\b\d{6}\b")
            .unwrap()
            .with_cue_boost(&["KIMLIK", "Sıra"], 0.95);
        let ents = custom_detect("kimlik 482913", &["tr"], &[&rule]);
        assert!((ents[0].score - 0.95).abs() < 1e-6, "{ents:?}");
        let ents = custom_detect("SIRA 482913", &["tr"], &[&rule]);
        assert!((ents[0].score - 0.95).abs() < 1e-6, "{ents:?}");
    }

    #[test]
    fn cues_are_owned_and_empty_cues_are_dropped() {
        // the cue list may be built at runtime (no 'static requirement)
        let configured: Vec<String> = vec!["Ref".into(), String::new(), "\u{307}".into()];
        let cues: Vec<&str> = configured.iter().map(String::as_str).collect();
        let rule = CustomRule::new(EntityType::Itin, r"X\d{5}")
            .unwrap()
            .with_cue(&cues);
        drop(configured);
        assert_eq!(rule.context, CustomContext::RequiredCue(vec!["ref".into()]));
        // an all-empty cue list leaves a rule that never matches
        let never = CustomRule::new(EntityType::Itin, r"X\d{5}")
            .unwrap()
            .with_cue(&[""]);
        assert!(custom_detect("ref X12345", &["en"], &[&never]).is_empty());
    }

    #[test]
    fn zero_width_matches_are_never_findings() {
        // `\d*` also matches the empty string between any two characters;
        // an empty span holds no text to mask (fuzz: start == end entity)
        for pattern in [r"\d*", r"(?=\d)", r"", r"x?"] {
            let rule = CustomRule::new(EntityType::Itin, pattern).unwrap();
            let ents = custom_detect("ab 12 cd", &["en"], &[&rule]);
            assert!(ents.iter().all(|e| e.start < e.end), "{pattern}: {ents:?}");
        }
        let rule = CustomRule::new(EntityType::Itin, r"\d*").unwrap();
        let rules = [&rule];
        let detector = crate::Detector::new().with_custom_rules(&rules);
        assert_eq!(detector.redact("ab 12 cd"), "ab [ITIN] cd");
    }
}
