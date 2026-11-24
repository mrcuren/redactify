//! Pluggable guard-classifier interface.
//!
//! [`MlClassifier`](crate::guard::ml::MlClassifier) is the contract the
//! pipeline consumes: synchronous, no error channel, no deadline, no role.
//! [`GuardClassifier`] is the contract a model ADAPTER implements instead:
//!
//! - it returns `Result<`[`Verdict`]`, `[`ClassifierError`]`>`, so a
//!   timeout, an unavailable backend, an unparseable answer and a rejected
//!   input stay distinguishable;
//! - it receives a [`ClassifyRequest`]: the (PII-masked) text, its
//!   [`Role`] (prompt, response or tool output), an optional prompt context
//!   for response classification, and an absolute deadline;
//! - it declares its [`Capabilities`]: the categories it is responsible for
//!   (the fail-closed set), the roles it handles, and its own per-call
//!   character budget (instead of the global
//!   [`CHUNK_CHAR_BUDGET`]);
//! - its [`Verdict`] carries per-category scores BEFORE any threshold, the
//!   model's raw label for each score (audit), and whether the scores are
//!   probabilities or label-only.
//!
//! Policy stays out of the adapter: [`Guarded`](crate::guard::guarded::Guarded)
//! wraps any `GuardClassifier` and owns the threshold, the fail mode, the
//! deadline, chunking and health (optionally a hard timeout and circuit
//! breaker), and implements `MlClassifier`, so a plugged model works with
//! [`Guard::with_ml`](crate::Guard::with_ml), the streaming guard and the
//! REST state unchanged.
//!
//! # Examples
//! ```
//! use redactify::guard::classifier::{
//!     Capabilities, CategoryScore, ClassifierError, ClassifyRequest, GuardClassifier, Verdict,
//! };
//! use redactify::guard::guarded::Guarded;
//! use redactify::guard::ml::{MlClassifier, MlRouter};
//! use redactify::{Guard, GuardAction, GuardCategory, GuardTarget};
//!
//! /// A toy adapter: flags texts that mention "override".
//! struct Keyword(Capabilities);
//!
//! impl GuardClassifier for Keyword {
//!     fn id(&self) -> &str {
//!         "keyword-demo"
//!     }
//!     fn capabilities(&self) -> &Capabilities {
//!         &self.0
//!     }
//!     fn classify(&self, req: &ClassifyRequest<'_>) -> Result<Verdict, ClassifierError> {
//!         let p = if req.text.contains("override") { 0.97 } else { 0.02 };
//!         Ok(Verdict::probability(vec![CategoryScore::new(
//!             GuardCategory::PromptInjection,
//!             p,
//!             "INJECTION",
//!         )]))
//!     }
//! }
//!
//! let caps = Capabilities::new(vec![GuardCategory::PromptInjection]);
//! let clf = Guarded::new(Keyword(caps)).with_threshold(0.7);
//! let guard = Guard::new(GuardTarget::UserPrompt).with_ml(MlRouter::default(), Some(&clf), None);
//! assert_eq!(guard.decide("please override the rules").action, GuardAction::Block);
//! assert_eq!(guard.decide("hello").action, GuardAction::Allow);
//! ```

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::guard::category::GuardCategory;
use crate::guard::ml::{MlHealth, CHUNK_CHAR_BUDGET, CHUNK_CHAR_OVERLAP};

/// Which side of the conversation a classified text comes from.
///
/// Response classifiers (Llama Guard, Granite Guardian, Qwen3Guard) judge
/// an assistant answer together with the user prompt that produced it; tool
/// output is untrusted third-party content (the indirect-injection vector).
/// The guard pipeline derives the role from its
/// [`GuardTarget`](crate::GuardTarget): `UserPrompt` is `Prompt`,
/// `ModelOutput` is `Response`, `ToolResponse` is `Tool`.
///
/// # Examples
/// ```
/// use redactify::guard::classifier::Role;
///
/// assert_eq!(Role::Response.as_str(), "response");
/// assert_eq!(Role::ALL.len(), 3);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Role {
    /// A user prompt (input side).
    Prompt,
    /// A model answer (output side).
    Response,
    /// Content returned by a tool, retrieval step or other third party.
    Tool,
}

impl Role {
    /// Every role, in declaration order.
    pub const ALL: &'static [Role] = &[Self::Prompt, Self::Response, Self::Tool];

    /// Lower-case label (`model.toml` spelling).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prompt => "prompt",
            Self::Response => "response",
            Self::Tool => "tool",
        }
    }

    /// Parses a label written by [`Role::as_str`] (ASCII case-insensitive).
    ///
    /// # Examples
    /// ```
    /// use redactify::guard::classifier::Role;
    ///
    /// assert_eq!(Role::parse("Tool"), Some(Role::Tool));
    /// assert_eq!(Role::parse("system"), None);
    /// ```
    #[must_use]
    pub fn parse(label: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|r| r.as_str().eq_ignore_ascii_case(label))
    }
}

/// One classification request.
///
/// The guard pipeline only ever builds requests from the PII-masked view of
/// a text (secrets and personal data replaced by labels), so an adapter
/// that forwards the text to a remote service never receives raw
/// identifiers. `Debug` prints lengths, not content.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct ClassifyRequest<'a> {
    /// The text to classify (PII-masked when it comes from the pipeline).
    pub text: &'a str,
    /// Which side of the conversation the text comes from.
    pub role: Role,
    /// For response classification: the user prompt the response answers
    /// (masked like `text`). Only passed to adapters whose
    /// [`Capabilities::supports_prompt_context`] is set.
    pub prompt_context: Option<&'a str>,
    /// Absolute deadline. An adapter should not run past it (a blocking
    /// client turns it into its read timeout); an answer that arrives after
    /// it is discarded as a [`ClassifierError::Timeout`] by
    /// [`Guarded`](crate::guard::guarded::Guarded).
    pub deadline: Instant,
}

impl<'a> ClassifyRequest<'a> {
    /// A request without prompt context.
    #[must_use]
    pub const fn new(text: &'a str, role: Role, deadline: Instant) -> Self {
        Self {
            text,
            role,
            prompt_context: None,
            deadline,
        }
    }

    /// Adds the prompt the classified response answers.
    #[must_use]
    pub const fn with_prompt_context(mut self, prompt: &'a str) -> Self {
        self.prompt_context = Some(prompt);
        self
    }

    /// Time left until the deadline (zero once it has passed).
    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

impl fmt::Debug for ClassifyRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // lengths only: the text may carry user content
        f.debug_struct("ClassifyRequest")
            .field("text_len", &self.text.len())
            .field("role", &self.role)
            .field("prompt_context_len", &self.prompt_context.map(str::len))
            .field("deadline", &self.deadline)
            .finish()
    }
}

/// What a score means: decisive for thresholds and for the router's safety
/// gate, which compares a RAW security score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ScoreKind {
    /// A model probability (softmax/sigmoid output, or the probability of
    /// a judge's decision token).
    #[default]
    Probability,
    /// The model returned a label only; scores are 1.0 (flagged) or 0.0.
    /// A threshold is meaningless, and the router does not gate the safety
    /// classifier on a label-only security verdict (the safety classifier
    /// runs).
    LabelOnly,
}

/// One category score of a [`Verdict`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct CategoryScore {
    /// The redactify category the model label maps to.
    pub category: GuardCategory,
    /// Score in `[0, 1]`, BEFORE any threshold.
    pub score: f32,
    /// The model's own label for this score (`"S9"`, `"jailbreak"`,
    /// `"INJECTION"`), kept for the audit trail: the decision rationale
    /// names it when it differs from the category label.
    pub raw_label: Cow<'static, str>,
}

impl CategoryScore {
    /// A score with its model label.
    #[must_use]
    pub fn new(
        category: GuardCategory,
        score: f32,
        raw_label: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            category,
            score,
            raw_label: raw_label.into(),
        }
    }

    /// A score whose model label is the category label itself (classifiers
    /// that speak redactify's taxonomy natively).
    #[must_use]
    pub const fn native(category: GuardCategory, score: f32) -> Self {
        Self {
            category,
            score,
            raw_label: Cow::Borrowed(category.as_str()),
        }
    }
}

/// A classifier's answer for one text.
///
/// # Examples
/// ```
/// use redactify::guard::classifier::{CategoryScore, ScoreKind, Verdict};
/// use redactify::GuardCategory;
///
/// let v = Verdict::probability(vec![
///     CategoryScore::new(GuardCategory::Hate, 0.2, "S10"),
///     CategoryScore::new(GuardCategory::Violence, 0.7, "S1"),
/// ]);
/// assert_eq!(v.kind, ScoreKind::Probability);
/// assert_eq!(v.max_score(), Some(0.7));
/// ```
#[derive(Debug, Clone, PartialEq, Default)]
#[non_exhaustive]
pub struct Verdict {
    /// Per-category scores, NOT thresholded (an empty list means the model
    /// flagged nothing).
    pub scores: Vec<CategoryScore>,
    /// What the scores mean.
    pub kind: ScoreKind,
}

impl Verdict {
    /// A verdict with explicit score semantics.
    #[must_use]
    pub const fn new(scores: Vec<CategoryScore>, kind: ScoreKind) -> Self {
        Self { scores, kind }
    }

    /// A verdict of model probabilities.
    #[must_use]
    pub const fn probability(scores: Vec<CategoryScore>) -> Self {
        Self::new(scores, ScoreKind::Probability)
    }

    /// A label-only verdict (scores 1.0 for flagged categories).
    #[must_use]
    pub const fn label_only(scores: Vec<CategoryScore>) -> Self {
        Self::new(scores, ScoreKind::LabelOnly)
    }

    /// The highest score over every category (`None` for an empty verdict).
    #[must_use]
    pub fn max_score(&self) -> Option<f32> {
        self.scores
            .iter()
            .map(|s| s.score)
            .fold(None, |m: Option<f32>, s| Some(m.map_or(s, |m| m.max(s))))
    }
}

/// Why a classification produced no verdict.
///
/// Every message is human-readable and never contains the classified text
/// or the model's raw output (the audit rule of this crate).
///
/// # Examples
/// ```
/// use redactify::guard::classifier::ClassifierError;
///
/// let e = ClassifierError::Timeout("no answer within 2s".to_owned());
/// assert_eq!(e.kind(), "timeout");
/// assert_eq!(e.to_string(), "deadline exceeded: no answer within 2s");
/// assert_eq!(ClassifierError::Parse.kind(), "parse");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClassifierError {
    /// The deadline passed before an answer arrived.
    #[error("deadline exceeded: {0}")]
    Timeout(String),
    /// The backend cannot be reached or is failing fast (a degraded lane,
    /// an open circuit breaker, a dead worker, a refused connection).
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    /// The backend answered this input with an error.
    #[error("inference failed: {0}")]
    Inference(String),
    /// The model output could not be interpreted (unknown label, a score
    /// outside `[0, 1]` or not a number). Never carries the output itself.
    #[error("unparseable model output")]
    Parse,
    /// The input was rejected before inference (for example by the
    /// tokenizer).
    #[error("input rejected: {0}")]
    Input(String),
}

impl ClassifierError {
    /// Short machine-readable kind: `timeout`, `unavailable`, `inference`,
    /// `parse` or `input`.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Timeout(_) => "timeout",
            Self::Unavailable(_) => "unavailable",
            Self::Inference(_) => "inference",
            Self::Parse => "parse",
            Self::Input(_) => "input",
        }
    }
}

/// Static capabilities of a classifier: what the wrapper and router read
/// instead of assuming.
///
/// # Examples
/// ```
/// use redactify::guard::classifier::{Capabilities, Role};
/// use redactify::GuardCategory;
///
/// let caps = Capabilities::new(vec![GuardCategory::Jailbreak])
///     .with_roles(vec![Role::Prompt])
///     .with_chunking(8_000, 400);
/// assert_eq!(caps.max_chars, 8_000);
/// assert!(!caps.supports_role(Role::Response));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Capabilities {
    /// The categories this classifier is responsible for: also the set a
    /// fail-closed failure reports at maximum severity.
    pub categories: Vec<GuardCategory>,
    /// The roles the classifier handles; a text of another role is not sent
    /// to it (no verdict, no failure).
    pub roles: Vec<Role>,
    /// Characters one call handles safely; longer texts are classified in
    /// overlapping windows of this size (per category, the maximum score
    /// wins). Default [`CHUNK_CHAR_BUDGET`]; `usize::MAX` never splits.
    pub max_chars: usize,
    /// Overlap between consecutive windows, in characters (always below
    /// `max_chars`). Default [`CHUNK_CHAR_OVERLAP`].
    pub chunk_overlap_chars: usize,
    /// Whether the classifier reads [`ClassifyRequest::prompt_context`].
    pub supports_prompt_context: bool,
}

impl Capabilities {
    /// Capabilities for `categories`: every role, the default 1,800-char
    /// windows with 200-char overlap, no prompt context.
    #[must_use]
    pub fn new(categories: Vec<GuardCategory>) -> Self {
        Self {
            categories,
            roles: Role::ALL.to_vec(),
            max_chars: CHUNK_CHAR_BUDGET,
            chunk_overlap_chars: CHUNK_CHAR_OVERLAP,
            supports_prompt_context: false,
        }
    }

    /// Restricts the handled roles.
    #[must_use]
    pub fn with_roles(mut self, roles: Vec<Role>) -> Self {
        self.roles = roles;
        self
    }

    /// Sets the per-call character budget and window overlap. `max_chars`
    /// is at least 1, and the overlap is clamped below it (a window must
    /// always advance).
    #[must_use]
    pub fn with_chunking(mut self, max_chars: usize, overlap: usize) -> Self {
        self.max_chars = max_chars.max(1);
        self.chunk_overlap_chars = overlap.min(self.max_chars - 1);
        self
    }

    /// Declares that the classifier reads the prompt context.
    #[must_use]
    pub const fn with_prompt_context(mut self, yes: bool) -> Self {
        self.supports_prompt_context = yes;
        self
    }

    /// Whether `role` is handled.
    #[must_use]
    pub fn supports_role(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }
}

/// The contract a model adapter implements (see the module docs).
///
/// Implementations must be `Send + Sync` (one instance serves concurrent
/// requests) and should be deterministic for the same request; a remote
/// generative judge is best-effort (temperature 0), which its adapter
/// documents.
pub trait GuardClassifier: Send + Sync {
    /// Stable identifier (logged as `ml:<id>` evidence and in rationales).
    fn id(&self) -> &str;

    /// Static capabilities (read on every call: return a stored value).
    fn capabilities(&self) -> &Capabilities;

    /// Classifies one request (at most [`Capabilities::max_chars`]
    /// characters; the wrapper splits longer texts).
    ///
    /// # Errors
    /// Any [`ClassifierError`]: the wrapper applies its fail mode and
    /// reports the failure as an `ML_DEGRADED` signal.
    fn classify(&self, req: &ClassifyRequest<'_>) -> Result<Verdict, ClassifierError>;

    /// Health after recent calls (the default is [`MlHealth::Ok`]).
    fn health(&self) -> MlHealth {
        MlHealth::Ok
    }
}

/// Parses a category label (the [`GuardCategory::as_str`] spelling, ASCII
/// case-insensitive) that a model may map a label to. The three health
/// categories (`NER_DEGRADED`, `SCAN_INCOMPLETE`, `ML_DEGRADED`) are
/// refused: they report pipeline health, never content.
///
/// # Examples
/// ```
/// use redactify::guard::classifier::parse_model_category;
/// use redactify::GuardCategory;
///
/// assert_eq!(parse_model_category("jailbreak"), Some(GuardCategory::Jailbreak));
/// assert_eq!(parse_model_category("ML_DEGRADED"), None);
/// assert_eq!(parse_model_category("nonsense"), None);
/// ```
#[must_use]
pub fn parse_model_category(label: &str) -> Option<GuardCategory> {
    GuardCategory::ALL
        .iter()
        .copied()
        .filter(|c| {
            !matches!(
                c,
                GuardCategory::NerDegraded
                    | GuardCategory::ScanIncomplete
                    | GuardCategory::MlDegraded
            )
        })
        .find(|c| c.as_str().eq_ignore_ascii_case(label))
}

/// The MLCommons hazard taxonomy (Llama Guard 3 and 4 codes `S1`-`S14`)
/// mapped onto redactify's categories.
///
/// The mapping is lossy and documented, not learned: redactify's ML label
/// space has eight categories, MLCommons has fourteen. The model's own
/// code survives as [`CategoryScore::raw_label`], so audit records keep it.
///
/// | Code | Hazard | Category |
/// |---|---|---|
/// | S1 | Violent Crimes | `VIOLENCE` |
/// | S2 | Non-Violent Crimes | `MISCONDUCT` |
/// | S3 | Sex-Related Crimes | `SEXUAL` |
/// | S4 | Child Sexual Exploitation | `SEXUAL` |
/// | S5 | Defamation | `MISCONDUCT` |
/// | S6 | Specialized Advice | `MISCONDUCT` |
/// | S7 | Privacy | `MISCONDUCT` |
/// | S8 | Intellectual Property | `MISCONDUCT` |
/// | S9 | Indiscriminate Weapons | `VIOLENCE` |
/// | S10 | Hate | `HATE` |
/// | S11 | Suicide & Self-Harm | `SELF_HARM` |
/// | S12 | Sexual Content | `SEXUAL` |
/// | S13 | Elections | `MISCONDUCT` |
/// | S14 | Code Interpreter Abuse | `TOOL_INJECTION` |
///
/// # Examples
/// ```
/// use redactify::guard::classifier::mlcommons_category;
/// use redactify::GuardCategory;
///
/// assert_eq!(mlcommons_category("S10"), Some(GuardCategory::Hate));
/// assert_eq!(mlcommons_category("s14"), Some(GuardCategory::ToolInjection));
/// assert_eq!(mlcommons_category("S15"), None);
/// ```
#[must_use]
pub fn mlcommons_category(code: &str) -> Option<GuardCategory> {
    let n: u8 = code
        .strip_prefix('S')
        .or_else(|| code.strip_prefix('s'))?
        .parse()
        .ok()?;
    Some(match n {
        1 | 9 => GuardCategory::Violence,
        3 | 4 | 12 => GuardCategory::Sexual,
        2 | 5 | 6 | 7 | 8 | 13 => GuardCategory::Misconduct,
        10 => GuardCategory::Hate,
        11 => GuardCategory::SelfHarm,
        14 => GuardCategory::ToolInjection,
        _ => return None,
    })
}

/// Interns `s` as a `&'static str`: each distinct string is leaked once and
/// reused (a classifier id or model label configured at runtime, for the
/// `&'static str` that [`MlClassifier::name`] and
/// [`CategoryScore::raw_label`] need without a per-call allocation).
/// Bounded by the number of distinct ids and labels a process configures.
///
/// [`MlClassifier::name`]: crate::guard::ml::MlClassifier::name
pub(crate) fn intern(s: &str) -> &'static str {
    static TABLE: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let mut table = crate::guard::executor::lock(TABLE.get_or_init(Mutex::default));
    if let Some(found) = table.get(s) {
        return found;
    }
    let leaked: &'static str = Box::leak(s.to_owned().into_boxed_str());
    table.insert(leaked);
    leaked
}

#[cfg(test)]
mod tests {
    use super::{intern, mlcommons_category, parse_model_category, Capabilities, Role};
    use crate::guard::category::GuardCategory;

    #[test]
    fn mlcommons_covers_s1_to_s14_and_nothing_else() {
        for n in 1..=14 {
            assert!(mlcommons_category(&format!("S{n}")).is_some(), "S{n}");
        }
        for bad in ["S0", "S15", "S", "9", "X1", ""] {
            assert_eq!(mlcommons_category(bad), None, "{bad}");
        }
    }

    #[test]
    fn model_categories_exclude_health_signals() {
        for c in GuardCategory::ALL {
            let parsed = parse_model_category(c.as_str());
            let health = matches!(
                c,
                GuardCategory::NerDegraded
                    | GuardCategory::ScanIncomplete
                    | GuardCategory::MlDegraded
            );
            assert_eq!(parsed.is_none(), health, "{c:?}");
        }
    }

    #[test]
    fn chunking_overlap_is_clamped_below_the_budget() {
        let caps = Capabilities::new(vec![]).with_chunking(10, 50);
        assert_eq!((caps.max_chars, caps.chunk_overlap_chars), (10, 9));
        let caps = Capabilities::new(vec![]).with_chunking(0, 0);
        assert_eq!((caps.max_chars, caps.chunk_overlap_chars), (1, 0));
    }

    #[test]
    fn interning_returns_one_allocation_per_distinct_string() {
        let a = intern("classifier-intern-test");
        let b = intern(&String::from("classifier-intern-test"));
        assert!(std::ptr::eq(a, b));
        assert_eq!(a, "classifier-intern-test");
    }

    #[test]
    fn roles_round_trip_through_their_labels() {
        for r in Role::ALL {
            assert_eq!(Role::parse(r.as_str()), Some(*r));
        }
    }
}
