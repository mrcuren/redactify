//! The ONNX encoder adapter: any sequence-classification encoder export,
//! described by a per-model `model.toml`, behind the
//! [`GuardClassifier`] interface.
//!
//! `model.toml` (paths relative to the file's directory):
//!
//! ```toml
//! id = "prompt-guard-oss-small"      # evidence `ml:<id>` and rationale name
//! model = "model.onnx"
//! tokenizer = "../security_tokenizer" # a directory or a tokenizer.json file
//! max_tokens = 512                    # tokenizer truncation per window
//! max_chars = 1800                    # characters per call (window size)
//! chunk_overlap_chars = 200
//! threshold = 0.706                   # emission threshold (Guarded)
//! fail_mode = "closed"                # or "open"
//! timeout_ms = 2000                   # per-inference bound
//! roles = ["prompt", "response", "tool"]
//! license = "MIT"                     # informational
//!
//! [thresholds]                        # optional per-category thresholds
//! JAILBREAK = 0.706
//!
//! [head]
//! kind = "binary"                     # or "categorical"
//! labels = ["benign", "jailbreak"]    # logits order (config.json id2label)
//! positive = "jailbreak"
//! category = "JAILBREAK"
//! ```
//!
//! A categorical head lists every class and maps the ones that matter:
//!
//! ```toml
//! [head]
//! kind = "categorical"
//! activation = "softmax"              # or "sigmoid" (multi-label)
//! labels = ["safe", "hate", "violence"]
//! [head.categories]
//! hate = "HATE"
//! violence = "VIOLENCE"               # unmapped labels ("safe") never emit
//! ```
//!
//! Loading validates the description against the model: the label count
//! must equal the model's logits width (warmup inference), and when a
//! `config.json` sits next to the model its `id2label` must list exactly
//! the `labels`, in order. The second check is the structural guard against
//! an inverted score (a positive class read from the wrong index flags
//! every benign text and none of the attacks).

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use super::{
    logits_to_positive_prob, sigmoid_all, softmax_all, MlError, OnnxCore, OnnxOptions,
    DEFAULT_INFER_TIMEOUT, DEFAULT_MAX_LEN,
};
use crate::guard::category::GuardCategory;
use crate::guard::classifier::{
    intern, parse_model_category, Capabilities, CategoryScore, ClassifierError, ClassifyRequest,
    GuardClassifier, Role, Verdict,
};
use crate::guard::guarded::{Guarded, DEFAULT_THRESHOLD};
use crate::guard::ml::{FailMode, MlHealth, CHUNK_CHAR_BUDGET, CHUNK_CHAR_OVERLAP};

/// `model.toml` as written (validated into [`ModelSpec`]).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSpec {
    id: String,
    model: String,
    tokenizer: String,
    max_tokens: Option<usize>,
    max_chars: Option<usize>,
    chunk_overlap_chars: Option<usize>,
    threshold: Option<f32>,
    #[serde(default)]
    thresholds: BTreeMap<String, f32>,
    fail_mode: Option<String>,
    timeout_ms: Option<u64>,
    roles: Option<Vec<String>>,
    license: Option<String>,
    head: RawHead,
}

/// The `[head]` table as written.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHead {
    kind: String,
    labels: Vec<String>,
    positive: Option<String>,
    category: Option<String>,
    activation: Option<String>,
    #[serde(default)]
    categories: BTreeMap<String, String>,
}

/// The classification head of an encoder export.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncoderHead {
    /// Two-class (or single-logit) model: one positive label mapped to one
    /// category. Two or more logits are softmax-normalized, one logit is a
    /// sigmoid.
    Binary {
        /// Model labels in logits order.
        labels: Vec<String>,
        /// Logits index of the positive label.
        positive_index: usize,
        /// Category the positive label maps to.
        category: GuardCategory,
    },
    /// N-class model: each label maps to a category or to nothing.
    Categorical {
        /// Model labels in logits order.
        labels: Vec<String>,
        /// Per label, the mapped category (`None`: never emitted).
        map: Vec<Option<GuardCategory>>,
        /// Per-class sigmoid (independent labels) instead of softmax.
        multi_label: bool,
    },
}

impl EncoderHead {
    /// The model labels in logits order.
    #[must_use]
    pub fn labels(&self) -> &[String] {
        match self {
            Self::Binary { labels, .. } | Self::Categorical { labels, .. } => labels,
        }
    }

    /// The categories this head can emit (the fail-closed set), in label
    /// order, without duplicates.
    #[must_use]
    pub fn categories(&self) -> Vec<GuardCategory> {
        match self {
            Self::Binary { category, .. } => vec![*category],
            Self::Categorical { map, .. } => {
                let mut out: Vec<GuardCategory> = Vec::new();
                for c in map.iter().flatten() {
                    if !out.contains(c) {
                        out.push(*c);
                    }
                }
                out
            }
        }
    }
}

/// A validated `model.toml` (see the module docs for the format).
///
/// # Examples
/// ```
/// # #[cfg(feature = "ml-onnx")]
/// # {
/// use std::path::Path;
/// use redactify::guard::onnx::{EncoderHead, ModelSpec};
/// use redactify::GuardCategory;
///
/// let spec = ModelSpec::from_toml_str(
///     r#"
///     id = "demo"
///     model = "model.onnx"
///     tokenizer = "tokenizer"
///     threshold = 0.7
///     [head]
///     kind = "binary"
///     labels = ["benign", "malicious"]
///     positive = "malicious"
///     category = "PROMPT_INJECTION"
///     "#,
///     Path::new("/models/demo"),
/// )
/// .unwrap();
/// assert_eq!(spec.model_path, Path::new("/models/demo/model.onnx"));
/// assert!(matches!(
///     spec.head,
///     EncoderHead::Binary { positive_index: 1, category: GuardCategory::PromptInjection, .. }
/// ));
/// # }
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ModelSpec {
    /// Classifier id (evidence `ml:<id>`).
    pub id: String,
    /// The ONNX file.
    pub model_path: PathBuf,
    /// The tokenizer (`tokenizer.json` or a directory holding one).
    pub tokenizer_path: PathBuf,
    /// Tokenizer truncation bound per window (default 512).
    pub max_tokens: usize,
    /// Characters per call (default 1,800).
    pub max_chars: usize,
    /// Window overlap in characters (default 200; below `max_chars`).
    pub chunk_overlap_chars: usize,
    /// Emission threshold (default 0.5).
    pub threshold: f32,
    /// Per-category emission thresholds.
    pub category_thresholds: Vec<(GuardCategory, f32)>,
    /// Error policy (default [`FailMode::Closed`]).
    pub fail_mode: FailMode,
    /// Per-inference bound (default 2 s).
    pub timeout: Duration,
    /// Roles the model handles (default: every role).
    pub roles: Vec<Role>,
    /// License note, informational.
    pub license: Option<String>,
    /// The classification head.
    pub head: EncoderHead,
}

/// A configuration error in a `model.toml`.
fn spec_error(msg: impl fmt::Display) -> MlError {
    MlError::new(format!("model.toml: {msg}"))
}

/// A threshold must be a number in `[0, 1]`.
fn check_threshold(what: &str, t: f32) -> Result<f32, MlError> {
    if t.is_finite() && (0.0..=1.0).contains(&t) {
        Ok(t)
    } else {
        Err(spec_error(format!("{what} must be in [0, 1], got {t}")))
    }
}

/// A category label a model may map to (health categories refused).
fn model_category(label: &str) -> Result<GuardCategory, MlError> {
    parse_model_category(label).ok_or_else(|| {
        spec_error(format!(
            "`{label}` is not a content category (use a GuardCategory label such as JAILBREAK)"
        ))
    })
}

impl ModelSpec {
    /// Reads and validates a `model.toml`; relative paths resolve against
    /// the file's directory.
    ///
    /// # Errors
    /// The file cannot be read, is not valid TOML, has unknown keys, or
    /// fails a validation rule (see [`ModelSpec::from_toml_str`]).
    pub fn load(path: impl AsRef<Path>) -> Result<Self, MlError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        Self::from_toml_str(&text, base)
    }

    /// Parses and validates a `model.toml` text; relative paths resolve
    /// against `base_dir`.
    ///
    /// # Errors
    /// Invalid TOML or an unknown key; an empty `id` or label list;
    /// duplicate labels; a binary head without a known `positive` label or
    /// `category`; a categorical head with an unknown `activation`, a
    /// mapping for an unknown label, or no mapped label; a category label
    /// that is not a content category; a threshold outside `[0, 1]`; an
    /// unknown `fail_mode` or role; `max_tokens` or `max_chars` of zero; an
    /// overlap not below `max_chars`.
    pub fn from_toml_str(text: &str, base_dir: &Path) -> Result<Self, MlError> {
        let raw: RawSpec = toml::from_str(text).map_err(|e| {
            // the message names the key and position; it carries no input
            spec_error(e)
        })?;
        if raw.id.trim().is_empty() {
            return Err(spec_error("`id` cannot be empty"));
        }
        let head = Self::head(raw.head)?;
        let max_tokens = raw.max_tokens.unwrap_or(DEFAULT_MAX_LEN);
        let max_chars = raw.max_chars.unwrap_or(CHUNK_CHAR_BUDGET);
        let chunk_overlap_chars = raw
            .chunk_overlap_chars
            .unwrap_or(CHUNK_CHAR_OVERLAP.min(max_chars.saturating_sub(1)));
        if max_tokens == 0 || max_chars == 0 {
            return Err(spec_error("`max_tokens` and `max_chars` must be positive"));
        }
        if chunk_overlap_chars >= max_chars {
            return Err(spec_error(
                "`chunk_overlap_chars` must be below `max_chars`",
            ));
        }
        let threshold = check_threshold("threshold", raw.threshold.unwrap_or(DEFAULT_THRESHOLD))?;
        let category_thresholds = raw
            .thresholds
            .iter()
            .map(|(label, t)| Ok((model_category(label)?, check_threshold(label, *t)?)))
            .collect::<Result<Vec<_>, MlError>>()?;
        let fail_mode = match raw.fail_mode.as_deref() {
            None | Some("closed") => FailMode::Closed,
            Some("open") => FailMode::Open,
            Some(other) => {
                return Err(spec_error(format!(
                    "`fail_mode` must be \"open\" or \"closed\", got \"{other}\""
                )))
            }
        };
        let roles = match raw.roles {
            None => Role::ALL.to_vec(),
            Some(list) => list
                .iter()
                .map(|r| Role::parse(r).ok_or_else(|| spec_error(format!("unknown role \"{r}\""))))
                .collect::<Result<Vec<_>, MlError>>()?,
        };
        Ok(Self {
            id: raw.id,
            model_path: base_dir.join(raw.model),
            tokenizer_path: base_dir.join(raw.tokenizer),
            max_tokens,
            max_chars,
            chunk_overlap_chars,
            threshold,
            category_thresholds,
            fail_mode,
            timeout: raw
                .timeout_ms
                .map_or(DEFAULT_INFER_TIMEOUT, Duration::from_millis),
            roles,
            license: raw.license,
            head,
        })
    }

    /// Validates the `[head]` table.
    fn head(raw: RawHead) -> Result<EncoderHead, MlError> {
        if raw.labels.is_empty() {
            return Err(spec_error("`head.labels` cannot be empty"));
        }
        for (i, l) in raw.labels.iter().enumerate() {
            if raw.labels[..i].contains(l) {
                return Err(spec_error(format!("duplicate label \"{l}\"")));
            }
        }
        let index_of = |label: &str| raw.labels.iter().position(|l| l == label);
        match raw.kind.as_str() {
            "binary" => {
                if raw.activation.is_some() || !raw.categories.is_empty() {
                    return Err(spec_error(
                        "a binary head takes `positive` and `category`, not `activation` or `categories`",
                    ));
                }
                let positive = raw
                    .positive
                    .as_deref()
                    .ok_or_else(|| spec_error("a binary head needs `positive`"))?;
                let positive_index = index_of(positive).ok_or_else(|| {
                    spec_error(format!("`positive` \"{positive}\" is not in `labels`"))
                })?;
                let category = model_category(
                    raw.category
                        .as_deref()
                        .ok_or_else(|| spec_error("a binary head needs `category`"))?,
                )?;
                if raw.labels.len() > 2 {
                    return Err(spec_error(
                        "a binary head has one or two labels (use kind = \"categorical\")",
                    ));
                }
                Ok(EncoderHead::Binary {
                    labels: raw.labels,
                    positive_index,
                    category,
                })
            }
            "categorical" => {
                if raw.positive.is_some() || raw.category.is_some() {
                    return Err(spec_error(
                        "a categorical head takes `categories`, not `positive` or `category`",
                    ));
                }
                let multi_label = match raw.activation.as_deref() {
                    None | Some("softmax") => false,
                    Some("sigmoid") => true,
                    Some(other) => {
                        return Err(spec_error(format!(
                            "`activation` must be \"softmax\" or \"sigmoid\", got \"{other}\""
                        )))
                    }
                };
                let mut map = vec![None; raw.labels.len()];
                for (label, cat) in &raw.categories {
                    let i = index_of(label).ok_or_else(|| {
                        spec_error(format!("`head.categories` maps unknown label \"{label}\""))
                    })?;
                    map[i] = Some(model_category(cat)?);
                }
                if map.iter().all(Option::is_none) {
                    return Err(spec_error("`head.categories` maps no label"));
                }
                Ok(EncoderHead::Categorical {
                    labels: raw.labels,
                    map,
                    multi_label,
                })
            }
            other => Err(spec_error(format!(
                "`head.kind` must be \"binary\" or \"categorical\", got \"{other}\""
            ))),
        }
    }

    /// Applies this spec's policy (threshold, per-category thresholds, fail
    /// mode, timeout) to a [`Guarded`] wrapper.
    #[must_use]
    pub fn configure<C: GuardClassifier>(&self, guarded: Guarded<C>) -> Guarded<C> {
        let mut g = guarded
            .with_threshold(self.threshold)
            .with_fail_mode(self.fail_mode)
            .with_timeout(self.timeout);
        for (c, t) in &self.category_thresholds {
            g = g.with_category_threshold(*c, *t);
        }
        g
    }
}

/// Reads `id2label` from a Hugging Face `config.json` as a label list in
/// index order; `Ok(None)` when the file has no such table.
fn config_labels(path: &Path) -> Result<Option<Vec<String>>, MlError> {
    let raw = std::fs::read_to_string(path)?;
    let json: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| MlError::with_source(format!("{} is not JSON", path.display()), e))?;
    let Some(table) = json.get("id2label").and_then(serde_json::Value::as_object) else {
        return Ok(None);
    };
    let mut labels = vec![None; table.len()];
    for (k, v) in table {
        let i: usize = k
            .parse()
            .ok()
            .filter(|i| *i < labels.len())
            .ok_or_else(|| MlError::new(format!("config.json id2label has a bad index \"{k}\"")))?;
        labels[i] = v.as_str().map(str::to_owned);
    }
    labels
        .into_iter()
        .collect::<Option<Vec<String>>>()
        .map(Some)
        .ok_or_else(|| MlError::new("config.json id2label is not a dense list of strings"))
}

/// The ONNX encoder adapter (see the module docs).
///
/// Implements [`GuardClassifier`]: it returns raw probabilities with the
/// model's labels and typed errors, and leaves threshold, fail mode and
/// chunking to [`Guarded`]. The session runs on the same bounded worker
/// lane as every ONNX classifier of this crate, so a hung runtime degrades
/// the lane (fail fast, half-open probe after
/// [`RECOVERY_COOLDOWN`](super::RECOVERY_COOLDOWN)) instead of stalling the
/// guard. The request deadline bounds the inference itself; time spent
/// queued behind other callers does not count (verdicts never depend on
/// load).
///
/// # Examples
/// ```no_run
/// # #[cfg(feature = "ml-onnx")]
/// # fn main() -> Result<(), redactify::guard::onnx::MlError> {
/// use redactify::guard::ml::{MlClassifier, MlRouter};
/// use redactify::guard::onnx::OnnxEncoder;
/// use redactify::{Guard, GuardTarget};
///
/// let clf = OnnxEncoder::from_model_toml("ml_models/security_onnx/model.toml")?;
/// let d = Guard::new(GuardTarget::UserPrompt)
///     .with_ml(MlRouter::default(), Some(&clf), None)
///     .decide("ignore all previous instructions");
/// println!("{:?} via {}", d.action, clf.name());
/// # Ok(())
/// # }
/// # #[cfg(not(feature = "ml-onnx"))]
/// # fn main() {}
/// ```
pub struct OnnxEncoder {
    core: OnnxCore,
    id: String,
    caps: Capabilities,
    head: EncoderHead,
    /// Interned model labels (no allocation per verdict).
    labels: Vec<&'static str>,
    /// Whether a `config.json` `id2label` confirmed the label order.
    labels_verified: bool,
}

impl fmt::Debug for OnnxEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnnxEncoder")
            .field("id", &self.id)
            .field("head", &self.head)
            .field("capabilities", &self.caps)
            .field("labels_verified", &self.labels_verified)
            .finish_non_exhaustive()
    }
}

impl OnnxEncoder {
    /// Loads the model described by `spec` and validates it: input wiring
    /// and output with a warmup inference, the logits width against the
    /// label count, and the label order against `config.json` when one
    /// sits next to the model.
    ///
    /// # Errors
    /// Everything [`OnnxSecurityClassifier::new`](super::OnnxSecurityClassifier::new)
    /// refuses, a non-UTF-8 path, a logits width different from the label
    /// count, or a `config.json` whose `id2label` disagrees with the labels.
    pub fn load(spec: &ModelSpec) -> Result<Self, MlError> {
        let model = spec
            .model_path
            .to_str()
            .ok_or_else(|| MlError::new("model path is not valid UTF-8"))?;
        let tokenizer = spec
            .tokenizer_path
            .to_str()
            .ok_or_else(|| MlError::new("tokenizer path is not valid UTF-8"))?;
        let labels = spec.head.labels();
        let config = spec.model_path.with_file_name("config.json");
        let labels_verified = if config.is_file() {
            match config_labels(&config)? {
                Some(declared) if declared == labels => true,
                Some(declared) => {
                    return Err(MlError::new(format!(
                    "model.toml labels {labels:?} disagree with config.json id2label {declared:?}"
                )))
                }
                None => false,
            }
        } else {
            false
        };
        let mut options = OnnxOptions::defaults(spec.threshold);
        options.fail_mode = spec.fail_mode;
        // the construction warmup is a load check, not a request: it gets
        // at least the default bound (calls use the request deadline)
        options.timeout = spec.timeout.max(DEFAULT_INFER_TIMEOUT);
        options.max_len = spec.max_tokens;
        let (core, warmup) = OnnxCore::new(model, tokenizer, options)?;
        if warmup.len() != labels.len() {
            return Err(MlError::new(format!(
                "model has {} logits but model.toml lists {} labels",
                warmup.len(),
                labels.len()
            )));
        }
        let caps = Capabilities::new(spec.head.categories())
            .with_roles(spec.roles.clone())
            .with_chunking(spec.max_chars, spec.chunk_overlap_chars);
        Ok(Self {
            core,
            id: spec.id.clone(),
            caps,
            labels: labels.iter().map(|l| intern(l)).collect(),
            head: spec.head.clone(),
            labels_verified,
        })
    }

    /// Loads a `model.toml` and returns the adapter wrapped in [`Guarded`]
    /// with the spec's threshold, fail mode and timeout applied.
    ///
    /// # Errors
    /// See [`ModelSpec::load`] and [`OnnxEncoder::load`].
    pub fn from_model_toml(path: impl AsRef<Path>) -> Result<Guarded<Self>, MlError> {
        let spec = ModelSpec::load(path)?;
        let encoder = Self::load(&spec)?;
        Ok(spec.configure(Guarded::new(encoder)))
    }

    /// The classification head.
    #[must_use]
    pub const fn head(&self) -> &EncoderHead {
        &self.head
    }

    /// Whether a `config.json` next to the model confirmed the label order
    /// (`false` when there was none to compare with).
    #[must_use]
    pub const fn labels_verified(&self) -> bool {
        self.labels_verified
    }

    /// The model's scores for `logits` (one window).
    fn verdict(&self, logits: &[f32]) -> Result<Verdict, ClassifierError> {
        if logits.len() != self.labels.len() {
            return Err(ClassifierError::Parse);
        }
        let scores = match &self.head {
            EncoderHead::Binary {
                positive_index,
                category,
                ..
            } => {
                // the exact computation of OnnxSecurityClassifier::score
                let p = if *positive_index + 1 == logits.len() {
                    logits_to_positive_prob(logits)
                } else {
                    softmax_all(logits)[*positive_index]
                };
                vec![CategoryScore::new(
                    *category,
                    p,
                    self.labels[*positive_index],
                )]
            }
            EncoderHead::Categorical {
                map, multi_label, ..
            } => {
                let probs = if *multi_label {
                    sigmoid_all(logits)
                } else {
                    softmax_all(logits)
                };
                let mut scores: Vec<CategoryScore> = Vec::new();
                for ((p, cat), label) in probs.into_iter().zip(map).zip(&self.labels) {
                    let Some(cat) = cat else { continue };
                    match scores.iter_mut().find(|s| s.category == *cat) {
                        Some(s) if p > s.score => *s = CategoryScore::new(*cat, p, *label),
                        Some(_) => {}
                        None => scores.push(CategoryScore::new(*cat, p, *label)),
                    }
                }
                scores
            }
        };
        Ok(Verdict::probability(scores))
    }
}

impl GuardClassifier for OnnxEncoder {
    fn id(&self) -> &str {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }

    fn classify(&self, req: &ClassifyRequest<'_>) -> Result<Verdict, ClassifierError> {
        let remaining = req.remaining();
        if remaining.is_zero() {
            // no inference was started: the lane is not degraded
            return Err(ClassifierError::Timeout(
                "the deadline passed before the inference started".to_owned(),
            ));
        }
        let logits = self
            .core
            .raw_logits_within(req.text, remaining)
            .map_err(|e| e.to_classifier_error())?;
        if logits.is_empty() {
            // an empty token stream (empty text): nothing to flag
            return Ok(Verdict::default());
        }
        self.verdict(&logits)
    }

    /// The inference core's health (a degraded lane, or an inference
    /// failure within the last 30 s).
    fn health(&self) -> MlHealth {
        self.core.ml_health()
    }
}
