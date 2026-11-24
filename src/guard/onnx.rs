//! ONNX-backed classifiers (optional, behind `ml-onnx` feature).
//!
//! Real ONNX inference through the `ort` crate (ONNX Runtime bindings) and
//! the HuggingFace `tokenizers` runtime - the same tokenizer implementation
//! the Python export uses, so token streams match the reference pipeline
//! exactly.
//!
//! Five public model wrappers share one inference core:
//!
//! - [`OnnxSecurityClassifier`] - **binary** shape (NeuralTrust/
//!   prompt-guard-oss-small export: inputs `input_ids` + `attention_mask`
//!   [`token_type_ids` if the model asks], output `logits` `[batch, 2]`);
//!   score = `p(positive class)`.
//! - [`OnnxCategoricalClassifier`] (aliased [`OnnxSafetyClassifier`]) -
//!   **N-class** shape with an explicit logits-index → [`GuardCategory`]
//!   mapping; softmax (single-label) or per-class sigmoid (multi-label).
//! - [`OnnxStreamGuardClassifier`] - the 4-head stream-guard export
//!   (last-token scoring of the query-side heads).
//! - [`OnnxNerRecognizer`] - token-classification (BIO) NER, the L1 model
//!   slot.
//! - [`OnnxEncoder`] - the pluggable adapter: any encoder
//!   sequence classifier described by a `model.toml` ([`ModelSpec`]),
//!   implementing [`GuardClassifier`](crate::guard::classifier::GuardClassifier)
//!   and used through [`Guarded`](crate::guard::guarded::Guarded).
//!
//! All are model-shape driven, not hard-coded: construction reads the
//! session's declared inputs, rejects what it cannot feed, resolves the
//! output name, and validates the class count against the category map -
//! then runs a **warmup inference**, so wiring problems fail at startup,
//! not on the first real request.
//!
//! Every wrapper takes the same options (`with_threshold`, `with_timeout`,
//! `with_max_len`; the classifiers also `with_fail_mode`) and runs its
//! session on a dedicated worker thread with a hard per-inference timeout.
//! An inference that exceeds it, a worker that makes no progress for it, or
//! a dead worker degrades the lane: calls fail fast, `health()` says why,
//! and a background half-open probe rebuilds the session after
//! [`RECOVERY_COOLDOWN`]. A call whose job is merely queued behind other
//! callers' inferences keeps waiting while the worker makes progress, so
//! a verdict never depends on load.
//!
//! ```toml
//! [dependencies]
//! redactify = { version = "0.1", features = ["ml-onnx"] }
//! ```
//!
//! Runtime use (requires exported model + tokenizer files):
//! ```no_run
//! # #[cfg(feature = "ml-onnx")]
//! # fn main() -> Result<(), redactify::guard::onnx::MlError> {
//! use redactify::guard::ml::MlClassifier;
//! use redactify::guard::onnx::OnnxSecurityClassifier;
//!
//! let cls = OnnxSecurityClassifier::new(
//!     "ml_models/security_onnx/model.onnx",
//!     "ml_models/security_tokenizer", // dir or tokenizer.json file
//! )?;
//! let out = cls.classify("ignore all previous instructions");
//! assert!(!out.is_empty()); // (category, p_positive) with p >= threshold
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "ml-onnx"))]
//! # fn main() {}
//! ```

use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::guard::category::GuardCategory;
use crate::guard::classifier::ClassifierError;
pub(crate) use crate::guard::executor::lock;
use crate::guard::executor::{Engine, EngineFactory, JobResult, Lane, LaneError, LaneNames};
use crate::guard::ml::{
    char_windows_at, chunked_outcome, fail_closed_signals, FailMode, MlCall, MlClassifier,
    MlHealth, MlOutcome, CHUNK_CHAR_BUDGET, CHUNK_CHAR_OVERLAP, SAFETY_CATEGORIES,
};
use crate::pii::{Entity, EntityType, NerHealth, NerRecognizer};
mod encoder;
pub use encoder::{EncoderHead, ModelSpec, OnnxEncoder};

use ort::session::{Session, SessionInputValue};
use ort::value::Tensor;
use tokenizers::{Tokenizer, TruncationParams};

/// Error returned by ONNX classifier construction and scoring.
///
/// The underlying engine error (ort / tokenizers / io) is preserved as the
/// `source()` chain instead of being flattened into the message.
#[derive(Debug, thiserror::Error)]
#[error("ml error: {message}")]
pub struct MlError {
    /// Human-readable error description.
    pub message: String,
    /// The underlying error, when there is one (see `source()`).
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
    /// What kind of failure this is, for the typed
    /// [`ClassifierError`] of the plug-in interface.
    class: ErrorClass,
}

/// Failure class of an [`MlError`] (crate-internal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorClass {
    /// Construction, tokenization, or output-shape problem.
    Other,
    /// The inference exceeded its timeout (the lane is degraded).
    Timeout,
    /// The lane is degraded and failing fast, or its worker died.
    Unavailable,
    /// The runtime answered this input with an error.
    Inference,
    /// The input was rejected before inference (tokenization).
    Input,
}

impl MlError {
    /// Creates an error from any message (no underlying source).
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
            class: ErrorClass::Other,
        }
    }

    /// Creates an error that preserves `source` in the error chain.
    fn with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(source)),
            class: ErrorClass::Other,
        }
    }

    /// A lane failure, keeping its class.
    fn from_lane(e: LaneError) -> Self {
        let (class, message) = match e {
            LaneError::TimedOut(m) => (ErrorClass::Timeout, m),
            LaneError::Unavailable(m) => (ErrorClass::Unavailable, m),
            LaneError::Call(m) => (ErrorClass::Inference, m),
        };
        Self {
            message,
            source: None,
            class,
        }
    }

    /// The typed plug-in error for this failure (the message never carries
    /// input text).
    pub(crate) fn to_classifier_error(&self) -> ClassifierError {
        match self.class {
            ErrorClass::Timeout => ClassifierError::Timeout(self.message.clone()),
            ErrorClass::Unavailable => ClassifierError::Unavailable(self.message.clone()),
            ErrorClass::Input => ClassifierError::Input(self.message.clone()),
            ErrorClass::Inference | ErrorClass::Other => {
                ClassifierError::Inference(self.message.clone())
            }
        }
    }

    /// Marks the error as an input rejection (tokenization).
    const fn into_input(mut self) -> Self {
        self.class = ErrorClass::Input;
        self
    }
}

impl From<ort::Error> for MlError {
    fn from(e: ort::Error) -> Self {
        Self::with_source(format!("onnxruntime: {e}"), e)
    }
}

impl From<tokenizers::Error> for MlError {
    fn from(e: tokenizers::Error) -> Self {
        // tokenizers::Error is itself a Box<dyn Error + Send + Sync>
        Self {
            message: format!("tokenizer: {e}"),
            source: Some(e),
            class: ErrorClass::Other,
        }
    }
}

impl From<std::io::Error> for MlError {
    fn from(e: std::io::Error) -> Self {
        Self::with_source(format!("io: {e}"), e)
    }
}

/// Converts raw binary-classification logits to the positive-class
/// probability.
///
/// Shape driven, documented semantics:
/// - empty slice -> `0.0` (no signal)
/// - one logit -> sigmoid (single-sigmoid export)
/// - two or more -> softmax, positive class is the LAST index
///   (class 0 is "benign" in binary text-classification exports)
///
/// # Examples
/// ```
/// # #[cfg(feature = "ml-onnx")]
/// use redactify::guard::onnx::logits_to_positive_prob;
/// # #[cfg(feature = "ml-onnx")]
/// # {
/// // decisive positive: [benign=0, jailbreak=5]
/// assert!(logits_to_positive_prob(&[0.0, 5.0]) > 0.99);
/// // symmetric logits -> 0.5
/// assert!((logits_to_positive_prob(&[3.0, 3.0]) - 0.5).abs() < 1e-6);
/// // single-logit export: sigmoid(0) == 0.5
/// assert!((logits_to_positive_prob(&[0.0]) - 0.5).abs() < 1e-6);
/// // empty -> 0.0
/// assert_eq!(logits_to_positive_prob(&[]), 0.0);
/// # }
/// ```
#[must_use]
pub fn logits_to_positive_prob(logits: &[f32]) -> f32 {
    match logits.len() {
        0 => 0.0,
        1 => 1.0 / (1.0 + (-logits[0]).exp()),
        _ => {
            // numerically stable softmax over all classes; positive = last
            let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
            let sum: f32 = logits.iter().map(|l| (l - max).exp()).sum();
            (logits[logits.len() - 1] - max).exp() / sum
        }
    }
}

/// Numerically stable softmax over a whole logits slice (single-label N-class
/// exports). Empty input yields an empty vector.
#[must_use]
pub fn softmax_all(logits: &[f32]) -> Vec<f32> {
    if logits.is_empty() {
        return Vec::new();
    }
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = logits.iter().map(|l| (l - max).exp()).collect();
    let sum: f32 = exps.iter().sum();
    exps.iter().map(|e| e / sum).collect()
}

/// Per-class sigmoid (multi-label N-class exports: each class is an
/// independent yes/no). Empty input yields an empty vector.
#[must_use]
pub fn sigmoid_all(logits: &[f32]) -> Vec<f32> {
    logits.iter().map(|l| 1.0 / (1.0 + (-l).exp())).collect()
}

/// Accepts either a `tokenizer.json` file path or a directory containing one.
#[must_use]
pub fn resolve_tokenizer_path(path: &str) -> PathBuf {
    let pb = PathBuf::from(path);
    if pb.is_dir() {
        pb.join("tokenizer.json")
    } else {
        pb
    }
}

// ------------------------------------------------------------ inference lane

/// Default wall-clock bound for one ONNX inference (a hung runtime must
/// never silently stall the guard).
const DEFAULT_INFER_TIMEOUT: Duration = Duration::from_secs(2);

/// Default tokenizer truncation bound (tokens per window).
const DEFAULT_MAX_LEN: usize = 512;

/// Cooldown before a degraded inference lane is rebuilt, and the window in
/// which an input-level inference failure keeps `health()` degraded.
///
/// Every ONNX model wrapper in this module runs its session on a dedicated
/// worker thread. Concurrent calls queue behind one another on the worker;
/// a call waits for its job to START as long as the worker keeps making
/// progress (an inference started or finished within the timeout, default
/// 2 s), then at most its timeout for its own inference. A queued call
/// therefore never fails because of load: failing it would turn the
/// wrapper's [`FailMode`] into a verdict that depends on how busy the lane
/// is (a fail-closed block of a benign text, or a fail-open skipped scan).
/// A burst of legitimate requests never degrades the lane either. When an
/// inference itself exceeds the timeout, when the worker made no progress
/// within the timeout while a job was queued, or when the worker thread
/// dies, the lane is DEGRADED: from then on every call
/// fails fast (and follows the wrapper's [`FailMode`]; the NER recognizer
/// returns no spans) instead of queueing behind a stuck worker, and
/// `health()` reports the degradation.
///
/// Once this cooldown has elapsed since the lane degraded, the next call
/// starts ONE background half-open probe: a fresh session and worker are
/// built from the same model file and must answer a warmup inference within
/// the timeout. Success swaps the new worker in and clears the degradation;
/// failure restarts the cooldown. The call that starts the probe still fails
/// fast, so no request ever waits for a model load. The replaced worker is
/// abandoned, not killed (a native inference call cannot be interrupted): it
/// skips any queued job whose caller already gave up and exits as soon as
/// its current inference returns. At most one abandoned worker may be alive
/// per lane; while one is, a further rebuild is deferred, so a model that
/// hangs repeatedly never accumulates sessions in memory.
///
/// The lane machinery itself is the crate's shared bounded-inference
/// executor (the same one [`Guarded::isolated`] uses for plug-in
/// classifiers).
///
/// [`Guarded::isolated`]: crate::guard::guarded::Guarded::isolated
///
/// # Examples
/// ```
/// # #[cfg(feature = "ml-onnx")]
/// # {
/// use redactify::guard::onnx::RECOVERY_COOLDOWN;
///
/// assert_eq!(RECOVERY_COOLDOWN.as_secs(), 30);
/// # }
/// ```
pub const RECOVERY_COOLDOWN: Duration = crate::guard::executor::DEFAULT_COOLDOWN;

/// Every named model output as (name, shape, flat row-major data).
type WorkerOutputs = Vec<(String, Vec<i64>, Vec<f32>)>;

/// One encoded input: token ids and attention mask.
type OrtInput = (Vec<i64>, Vec<i64>);

/// Thread names of the ONNX lanes.
const ONNX_LANE_NAMES: LaneNames = LaneNames {
    worker: "redactify-onnx-infer",
    probe: "redactify-onnx-recover",
};

/// Production engine: one ONNX Runtime session.
struct OrtEngine {
    session: Session,
    wants_token_type_ids: bool,
}

impl OrtEngine {
    /// Loads `model_path` and validates its declared inputs: only what the
    /// wrappers can feed is accepted, anything else is rejected eagerly.
    fn load(model_path: &str) -> Result<Self, MlError> {
        let session = Session::builder()?.commit_from_file(model_path)?;
        let mut wants_token_type_ids = false;
        for input in session.inputs() {
            match input.name() {
                "input_ids" | "attention_mask" => {}
                "token_type_ids" => wants_token_type_ids = true,
                other => {
                    return Err(MlError::new(format!(
                        "model input `{other}` is not supported (expected input_ids/attention_mask/token_type_ids)"
                    )));
                }
            }
        }
        Ok(Self {
            session,
            wants_token_type_ids,
        })
    }
}

impl Engine<OrtInput, WorkerOutputs> for OrtEngine {
    fn run(&mut self, (ids, mask): OrtInput) -> JobResult<WorkerOutputs> {
        let len = ids.len();
        let shape = vec![1_usize, len];
        let mut inputs: Vec<(&'static str, SessionInputValue<'static>)> = Vec::with_capacity(3);
        // the token vectors are moved into the tensors (no copy)
        inputs.push((
            "input_ids",
            Tensor::from_array((shape.clone(), ids))
                .map_err(|e| format!("tensor: {e}"))?
                .into(),
        ));
        inputs.push((
            "attention_mask",
            Tensor::from_array((shape.clone(), mask))
                .map_err(|e| format!("tensor: {e}"))?
                .into(),
        ));
        if self.wants_token_type_ids {
            inputs.push((
                "token_type_ids",
                Tensor::from_array((shape, vec![0_i64; len]))
                    .map_err(|e| format!("tensor: {e}"))?
                    .into(),
            ));
        }
        let outputs = self
            .session
            .run(inputs)
            .map_err(|e| format!("onnxruntime: {e}"))?;
        let mut out = Vec::with_capacity(outputs.len());
        for (name, val) in outputs.iter() {
            let (shape, data) = val
                .try_extract_tensor::<f32>()
                .map_err(|e| format!("extract `{name}`: {e}"))?;
            out.push((name.to_owned(), shape.to_vec(), data.to_vec()));
        }
        Ok(out)
    }
}

// ------------------------------------------------------------ shared core

/// Runtime options shared by every model wrapper in this module: one copy
/// inside the core instead of four duplicated builder sets.
#[derive(Debug, Clone, Copy, PartialEq)]
struct OnnxOptions {
    /// Minimum score (classifiers) or mean span probability (NER).
    threshold: f32,
    /// Error policy of the classifiers (the NER recognizer is always
    /// fail-open and reports failures through `health()`).
    fail_mode: FailMode,
    /// Hard wall-clock bound for one inference.
    timeout: Duration,
    /// Tokenizer truncation bound (tokens per window).
    max_len: usize,
}

impl OnnxOptions {
    /// Defaults: the given threshold, fail-closed, 2 s, 512 tokens.
    const fn defaults(threshold: f32) -> Self {
        Self {
            threshold,
            fail_mode: FailMode::Closed,
            timeout: DEFAULT_INFER_TIMEOUT,
            max_len: DEFAULT_MAX_LEN,
        }
    }
}

/// Health of the shared core.
enum CoreHealth {
    Ok,
    /// The inference lane is degraded (timeout or dead worker).
    Lane(String),
    /// An input-level inference failure happened within the last
    /// [`RECOVERY_COOLDOWN`].
    Call(String),
}

/// Tokenized input with per-token byte offsets: `(ids, attention_mask, offsets)`.
type Tokenized = (Vec<i64>, Vec<i64>, Vec<(usize, usize)>);
/// Token-classification inference output: `(shape, flat logits, offsets)`.
type TokenLogits = (Vec<i64>, Vec<f32>, Vec<(usize, usize)>);

/// Shared inference core: tokenizer + inference lane + options + output
/// wiring. The session lives on the lane's worker thread, so the core (and
/// every wrapper) stays `Send + Sync` without a session mutex.
struct OnnxCore {
    lane: Arc<Lane<OrtInput, WorkerOutputs>>,
    tokenizer: Tokenizer,
    options: OnnxOptions,
    /// Model output this core extracts logits from.
    output_name: String,
    /// Last input-level inference failure (one that did not degrade the
    /// lane) and when it happened; reported by `health()` for
    /// [`RECOVERY_COOLDOWN`].
    last_call_error: Mutex<Option<(Instant, String)>>,
}

impl OnnxCore {
    /// Loads and validates the model/tokenizer pair; returns the warmup
    /// logits so callers can check the class count at construction time.
    fn new(
        model_path: &str,
        tokenizer_path: &str,
        options: OnnxOptions,
    ) -> Result<(Self, Vec<f32>), MlError> {
        if model_path.is_empty() {
            return Err(MlError::new("model path cannot be empty"));
        }
        let engine = OrtEngine::load(model_path)?;

        let tokenizer_file = resolve_tokenizer_path(tokenizer_path);
        if !tokenizer_file.is_file() {
            return Err(MlError::new(format!(
                "tokenizer file not found: {}",
                tokenizer_file.display()
            )));
        }
        let mut tokenizer = Tokenizer::from_file(&tokenizer_file)?;
        tokenizer.with_truncation(Some(TruncationParams {
            max_length: options.max_len,
            ..TruncationParams::default()
        }))?;
        let (ids, mask) = tokenize_ids(&tokenizer, "warmup")?;
        if ids.is_empty() {
            return Err(MlError::new(
                "tokenizer produced no ids for the warmup text",
            ));
        }

        let rebuild_path = model_path.to_owned();
        let factory: Box<EngineFactory<OrtInput, WorkerOutputs>> = Box::new(move || {
            OrtEngine::load(&rebuild_path)
                .map(|e| Box::new(e) as Box<dyn Engine<OrtInput, WorkerOutputs>>)
                .map_err(|e| e.message)
        });
        let lane = Lane::new(
            Box::new(engine),
            factory,
            (ids.clone(), mask.clone()),
            RECOVERY_COOLDOWN,
            ONNX_LANE_NAMES,
        )
        .map_err(|e| MlError::with_source("cannot spawn the inference worker thread", e))?;
        let mut core = Self {
            lane,
            tokenizer,
            options,
            output_name: String::new(),
            last_call_error: Mutex::new(None),
        };

        // Warmup: validate the full tokenize -> run -> extract path and
        // resolve the output ("logits", else the first output). Name and
        // data come from the SAME element, so the runtime reads exactly the
        // tensor the warmup validated.
        let outputs = core.infer_encoded(ids, mask)?;
        let (name, _, logits) = outputs
            .iter()
            .find(|(n, _, _)| n == "logits")
            .or_else(|| outputs.first())
            .ok_or_else(|| MlError::new("model produced no outputs"))?;
        if logits.is_empty() {
            return Err(MlError::new("model produced empty logits"));
        }
        core.output_name = name.clone();
        let logits = logits.clone();
        Ok((core, logits))
    }

    fn set_max_len(&mut self, max_len: usize) -> Result<(), MlError> {
        self.tokenizer.with_truncation(Some(TruncationParams {
            max_length: max_len,
            ..TruncationParams::default()
        }))?;
        self.options.max_len = max_len;
        Ok(())
    }

    /// Records an input-level failure for `health()` and passes it on.
    fn call_failed(&self, e: MlError) -> MlError {
        *lock(&self.last_call_error) = Some((Instant::now(), e.message.clone()));
        e
    }

    /// Sends one job through the lane and waits within the timeout.
    fn infer_encoded(&self, ids: Vec<i64>, mask: Vec<i64>) -> Result<WorkerOutputs, MlError> {
        self.infer_encoded_within(ids, mask, self.options.timeout)
    }

    /// [`Self::infer_encoded`] with an explicit per-inference bound.
    fn infer_encoded_within(
        &self,
        ids: Vec<i64>,
        mask: Vec<i64>,
        timeout: Duration,
    ) -> Result<WorkerOutputs, MlError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        self.lane.call((ids, mask), timeout).map_err(|e| match e {
            LaneError::Call(_) => self.call_failed(MlError::from_lane(e)),
            lane => MlError::from_lane(lane),
        })
    }

    /// Runs one inference and returns the raw logits row for `output_name`.
    fn raw_logits(&self, text: &str) -> Result<Vec<f32>, MlError> {
        self.raw_logits_within(text, self.options.timeout)
    }

    /// [`Self::raw_logits`] with an explicit per-inference bound.
    fn raw_logits_within(&self, text: &str, timeout: Duration) -> Result<Vec<f32>, MlError> {
        let (ids, mask) =
            tokenize_ids(&self.tokenizer, text).map_err(|e| self.call_failed(e.into_input()))?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let outs = self.infer_encoded_within(ids, mask, timeout)?;
        Ok(outs
            .iter()
            .find(|(n, _, _)| *n == self.output_name)
            .or_else(|| outs.first())
            .map(|(_, _, d)| d.clone())
            .unwrap_or_default())
    }

    /// Runs one inference and extracts several NAMED outputs as flat f32
    /// vectors (row-major, batch=1). Used by multi-head models whose outputs
    /// are not called `logits`.
    fn run_outputs(&self, text: &str, names: &[&str]) -> Result<Vec<Vec<f32>>, MlError> {
        let (ids, mask) = tokenize_ids(&self.tokenizer, text).map_err(|e| self.call_failed(e))?;
        if ids.is_empty() {
            return Ok(names.iter().map(|_| Vec::new()).collect());
        }
        let outs = self.infer_encoded(ids, mask)?;
        let mut out = Vec::with_capacity(names.len());
        for n in names {
            let val = outs
                .iter()
                .find(|(name, _, _)| name == n)
                .ok_or_else(|| self.call_failed(MlError::new(format!("output `{n}` missing"))))?;
            out.push(val.2.clone());
        }
        Ok(out)
    }

    /// Tokenizes and also returns per-token **byte offsets** into `text`
    /// (special tokens such as `[CLS]`/`[SEP]` carry zero-length offsets,
    /// which callers use to exclude them).
    fn tokenize_with_offsets(&self, text: &str) -> Result<Tokenized, MlError> {
        let encoding = self.tokenizer.encode(text, true)?;
        let ids: Vec<i64> = encoding.get_ids().iter().map(|&v| i64::from(v)).collect();
        let mask: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .map(|&v| i64::from(v))
            .collect();
        Ok((ids, mask, encoding.get_offsets().to_vec()))
    }

    /// Runs one token-classification inference and returns the output shape,
    /// the flat row-major logits (`[1, seq, num_labels]` for the standard
    /// export) and the token offsets.
    fn raw_token_logits(&self, text: &str) -> Result<TokenLogits, MlError> {
        let (ids, mask, offsets) = self
            .tokenize_with_offsets(text)
            .map_err(|e| self.call_failed(e))?;
        if ids.is_empty() {
            return Ok((Vec::new(), Vec::new(), offsets));
        }
        let outs = self.infer_encoded(ids, mask)?;
        let entry = outs
            .iter()
            .find(|(n, _, _)| *n == self.output_name)
            .or_else(|| outs.first())
            .ok_or_else(|| self.call_failed(MlError::new("model produced no outputs")))?;
        Ok((entry.1.clone(), entry.2.clone(), offsets))
    }

    /// Lane degradation first, then a recent input-level failure.
    fn health(&self) -> CoreHealth {
        if let Some(reason) = self.lane.degraded_reason() {
            return CoreHealth::Lane(reason);
        }
        match lock(&self.last_call_error).as_ref() {
            Some((at, msg)) if at.elapsed() < RECOVERY_COOLDOWN => CoreHealth::Call(msg.clone()),
            _ => CoreHealth::Ok,
        }
    }

    /// [`MlClassifier::health`] for the classifier wrappers.
    fn ml_health(&self) -> MlHealth {
        match self.health() {
            CoreHealth::Ok => MlHealth::Ok,
            CoreHealth::Lane(reason) => {
                MlHealth::Degraded(format!("inference lane degraded: {reason}"))
            }
            CoreHealth::Call(reason) => MlHealth::Degraded(format!(
                "an inference failed within the last {}s: {reason}",
                RECOVERY_COOLDOWN.as_secs()
            )),
        }
    }
}

/// Tokenizes `text` into `(ids, attention_mask)`.
fn tokenize_ids(tokenizer: &Tokenizer, text: &str) -> Result<(Vec<i64>, Vec<i64>), MlError> {
    let encoding = tokenizer.encode(text, true)?;
    let ids: Vec<i64> = encoding.get_ids().iter().map(|&v| i64::from(v)).collect();
    let mask: Vec<i64> = encoding
        .get_attention_mask()
        .iter()
        .map(|&v| i64::from(v))
        .collect();
    Ok((ids, mask))
}

/// Generates the option builders and getters every model wrapper shares
/// (the values live in the core's options: one implementation, four types).
macro_rules! shared_option_methods {
    ($ty:ident, $threshold_doc:literal) => {
        impl $ty {
            #[doc = $threshold_doc]
            #[must_use]
            pub const fn with_threshold(mut self, threshold: f32) -> Self {
                self.core.options.threshold = threshold;
                self
            }

            /// Sets the hard wall-clock bound for one inference (default
            /// 2 s).
            ///
            /// A call queued behind concurrent calls waits for its
            /// inference to start as long as the worker starts or finishes
            /// an inference within this bound, then at most this long for
            /// the inference itself. An inference that exceeds it (or a worker that made no progress within
            /// it) fails the call and degrades the inference lane: later
            /// calls fail fast until a background half-open probe, started
            /// after [`RECOVERY_COOLDOWN`], has rebuilt the session.
            ///
            /// The inference's duration is measured on the worker thread,
            /// so the bound holds even when the calling thread reads the
            /// answer late (a loaded host). `Duration::ZERO` fails every
            /// call.
            #[must_use]
            pub const fn with_timeout(mut self, timeout: Duration) -> Self {
                self.core.options.timeout = timeout;
                self
            }

            /// Sets the maximum token length (tokenizer truncation bound per
            /// window; default 512). Texts over the chunk budget are scanned
            /// in overlapping windows, so the bound applies per window.
            ///
            /// # Errors
            /// Propagates tokenizer configuration errors.
            pub fn with_max_len(mut self, max_len: usize) -> Result<Self, MlError> {
                self.core.set_max_len(max_len)?;
                Ok(self)
            }

            /// The emission threshold (see [`Self::with_threshold`]).
            #[must_use]
            pub const fn threshold(&self) -> f32 {
                self.core.options.threshold
            }

            /// The per-inference wall-clock bound (see [`Self::with_timeout`]).
            #[must_use]
            pub const fn timeout(&self) -> Duration {
                self.core.options.timeout
            }

            /// The tokenizer truncation bound (see [`Self::with_max_len`]).
            #[must_use]
            pub const fn max_len(&self) -> usize {
                self.core.options.max_len
            }
        }
    };
}

/// Generates the error-policy builder and getter of the classifiers.
macro_rules! fail_mode_methods {
    ($ty:ident) => {
        impl $ty {
            /// Sets the error policy ([`FailMode::Closed`] by default): what
            /// a failed, timed-out or fail-fast (degraded lane) inference
            /// emits.
            #[must_use]
            pub const fn with_fail_mode(mut self, mode: FailMode) -> Self {
                self.core.options.fail_mode = mode;
                self
            }

            /// The error policy (see [`Self::with_fail_mode`]).
            #[must_use]
            pub const fn fail_mode(&self) -> FailMode {
                self.core.options.fail_mode
            }
        }
    };
}

/// ONNX-backed binary security classifier (prompt-guard-oss-small shape).
///
/// Scores are `p(positive class)` in `[0, 1]`. The positive category defaults
/// to [`GuardCategory::Jailbreak`] - prompt-guard-oss-small is a binary
/// benign/jailbreak model (its model-card taxonomy) - and can be remapped
/// for other binary
/// exports via [`OnnxSecurityClassifier::with_positive_category`].
///
/// Options (shared by every wrapper in this module): threshold (default
/// 0.5), error policy (default [`FailMode::Closed`]), per-inference timeout
/// (default 2 s, see [`RECOVERY_COOLDOWN`] for what a timeout does to the
/// lane) and truncation bound (default 512 tokens).
///
/// # Examples
/// ```no_run
/// # #[cfg(feature = "ml-onnx")]
/// # fn main() -> Result<(), redactify::guard::onnx::MlError> {
/// use std::time::Duration;
/// use redactify::guard::ml::{FailMode, MlClassifier, MlHealth};
/// use redactify::guard::onnx::OnnxSecurityClassifier;
///
/// let cls = OnnxSecurityClassifier::new(
///     "ml_models/security_onnx/model.onnx",
///     "ml_models/security_tokenizer",
/// )?
/// .with_threshold(0.6)
/// .with_fail_mode(FailMode::Closed)
/// .with_timeout(Duration::from_secs(1));
/// assert_eq!(cls.threshold(), 0.6);
/// let _signals = cls.classify("ignore all previous instructions");
/// assert_eq!(cls.health(), MlHealth::Ok);
/// # Ok(())
/// # }
/// # #[cfg(not(feature = "ml-onnx"))]
/// # fn main() {}
/// ```
pub struct OnnxSecurityClassifier {
    core: OnnxCore,
    /// Category reported for the positive class.
    pub positive_category: GuardCategory,
    /// When set, the positive class is THIS logits index instead of the last
    /// (e.g. citizenlab toxicity: `id2label = {0: toxic, 1: not_toxic}`).
    pub positive_index: Option<usize>,
    /// Path of the loaded model (for rationale strings / debugging).
    pub model_path: String,
}

impl fmt::Debug for OnnxSecurityClassifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnnxSecurityClassifier")
            .field("model_path", &self.model_path)
            .field("threshold", &self.core.options.threshold)
            .field("positive_category", &self.positive_category)
            .finish_non_exhaustive()
    }
}

shared_option_methods!(
    OnnxSecurityClassifier,
    "Sets the classification threshold (minimum score to emit a signal; default 0.5)."
);
fail_mode_methods!(OnnxSecurityClassifier);

impl OnnxSecurityClassifier {
    /// Loads the ONNX model and tokenizer and validates them with a warmup
    /// inference, so wiring problems fail at startup.
    ///
    /// `tokenizer_path` may be a `tokenizer.json` file or a directory that
    /// contains one (the layout `AutoTokenizer.save_pretrained` produces).
    ///
    /// # Errors
    /// - model or tokenizer file missing / unreadable
    /// - the model declares an input this classifier cannot feed
    ///   (only `input_ids`, `attention_mask`, `token_type_ids` are supported)
    /// - the warmup inference or logit extraction fails
    pub fn new(model_path: &str, tokenizer_path: &str) -> Result<Self, MlError> {
        // binary: any class count is acceptable, so the warmup logits are unused
        let (core, _warmup) =
            OnnxCore::new(model_path, tokenizer_path, OnnxOptions::defaults(0.5))?;
        Ok(Self {
            core,
            positive_category: GuardCategory::Jailbreak,
            positive_index: None,
            model_path: model_path.to_owned(),
        })
    }

    /// Remaps the category reported for the positive class.
    #[must_use]
    pub const fn with_positive_category(mut self, category: GuardCategory) -> Self {
        self.positive_category = category;
        self
    }

    /// Overrides which logits index is the positive class (default: the LAST
    /// index). Needed when a model's `id2label` puts the attack class first
    /// (e.g. citizenlab DistilBERT toxicity: 0=toxic).
    #[must_use]
    pub const fn with_positive_index(mut self, index: usize) -> Self {
        self.positive_index = Some(index);
        self
    }

    /// Scores one text: `p(positive class)` via a real ONNX inference.
    ///
    /// # Errors
    /// Tokenization or inference failure, a timeout, or a degraded lane
    /// failing fast (extraction goes through `ort`'s checked API; never
    /// panics on model output shape).
    pub fn score(&self, text: &str) -> Result<f32, MlError> {
        let logits = self.core.raw_logits(text)?;
        match self.positive_index {
            Some(i) => Ok(softmax_all(&logits).get(i).copied().unwrap_or(0.0)),
            None => Ok(logits_to_positive_prob(&logits)),
        }
    }

    /// One window: the thresholded pair, the raw score, and the error that
    /// the [`FailMode`] turned into the pair (if any).
    fn evaluate(&self, text: &str) -> Evaluated {
        match self.score(text) {
            Ok(s) if s >= self.core.options.threshold => {
                (vec![(self.positive_category, s)], Some(s), None)
            }
            Ok(s) => (Vec::new(), Some(s), None),
            Err(e) => (
                match self.core.options.fail_mode {
                    FailMode::Closed => vec![(self.positive_category, 1.0)],
                    FailMode::Open => Vec::new(),
                },
                None,
                Some(e),
            ),
        }
    }
}

/// One window's result inside an ONNX classifier: thresholded pairs (or
/// the fail-mode pairs), the raw score, and the error, if the inference
/// failed.
type Evaluated = (Vec<(GuardCategory, f32)>, Option<f32>, Option<MlError>);

/// [`MlClassifier::classify_call`] of the ONNX classifiers: the global
/// [`CHUNK_CHAR_BUDGET`] windows merged exactly like the default (every
/// window scanned, per category the maximum), with the first window error
/// reported as the call's failure.
fn legacy_outcome(text: &str, mut evaluate: impl FnMut(&str) -> Evaluated) -> MlOutcome {
    chunked_outcome(text, CHUNK_CHAR_BUDGET, CHUNK_CHAR_OVERLAP, false, |w| {
        let (pairs, raw, err) = evaluate(w);
        let mut out = MlOutcome::from_pairs(pairs, raw);
        out.failure = err.map(|e| e.to_classifier_error());
        out
    })
}

impl MlClassifier for OnnxSecurityClassifier {
    /// Emits `(positive_category, p_positive)` when the score reaches the
    /// threshold.
    ///
    /// On any inference error (including a timeout and a degraded lane
    /// failing fast) the [`FailMode`] applies: [`FailMode::Closed`] (the
    /// default) emits `(positive_category, 1.0)`, i.e. a Block;
    /// [`FailMode::Open`] emits nothing and the deterministic L0/L1 layers
    /// decide alone. [`OnnxSecurityClassifier::score`] returns the error
    /// itself.
    fn classify(&self, text: &str) -> Vec<(GuardCategory, f32)> {
        self.classify_with_raw(text).0
    }

    /// One inference: the thresholded pair and the raw positive score
    /// (`None` on an error, where the [`FailMode`] decides the pairs).
    fn classify_with_raw(&self, text: &str) -> (Vec<(GuardCategory, f32)>, Option<f32>) {
        let (pairs, raw, _) = self.evaluate(text);
        (pairs, raw)
    }

    fn name(&self) -> &'static str {
        "onnx-security"
    }

    /// The global-budget windows, plus the exact per-call failure
    /// (an inference error, a timeout or a degraded lane failing fast).
    fn classify_call(&self, call: &MlCall<'_>) -> MlOutcome {
        legacy_outcome(call.text, |w| self.evaluate(w))
    }

    /// `Degraded` while the inference lane is degraded (a timeout or a dead
    /// worker, until a half-open probe succeeds; see [`RECOVERY_COOLDOWN`])
    /// or when an input-level inference failure happened within the last
    /// [`RECOVERY_COOLDOWN`]; `Ok` otherwise.
    fn health(&self) -> MlHealth {
        self.core.ml_health()
    }
}

/// ONNX-backed N-class classifier with an explicit category mapping.
///
/// Logits index `i` maps to `category_map[i]` (validated at construction:
/// the model's class count must equal the map length). Two output modes:
///
/// - **single-label** (default): softmax over all classes - the classes are
///   mutually exclusive alternatives
/// - **multi-label** ([`OnnxCategoricalClassifier::multi_label`]): per-class
///   sigmoid - several categories may fire independently
///
/// The safety alias ([`OnnxSafetyClassifier`]) presets the six
/// safety categories. Note: Qwen3Guard-Stream-0.6B is a generative model and
/// does not export to this classification shape directly; this classifier
/// serves safety models **with a classification head** - which candidate
/// qualifies is decided by measurement (ML_SETUP.md), not assumption.
///
/// Options: the same shared set as [`OnnxSecurityClassifier`] (threshold
/// default 0.5, [`FailMode::Closed`], 2 s timeout, 512 tokens).
pub struct OnnxCategoricalClassifier {
    core: OnnxCore,
    /// logits index -> category (length == model class count).
    pub category_map: Vec<GuardCategory>,
    /// sigmoid-per-class (true) vs softmax (false).
    pub multi_label: bool,
    /// Path of the loaded model (for rationale strings / debugging).
    pub model_path: String,
}

/// Safety-shape alias: six L3 categories, single-label by
/// default; switch to [`OnnxCategoricalClassifier::multi_label`] for models
/// trained with independent labels.
pub type OnnxSafetyClassifier = OnnxCategoricalClassifier;

impl fmt::Debug for OnnxCategoricalClassifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnnxCategoricalClassifier")
            .field("model_path", &self.model_path)
            .field("threshold", &self.core.options.threshold)
            .field("classes", &self.category_map.len())
            .field("multi_label", &self.multi_label)
            .finish_non_exhaustive()
    }
}

shared_option_methods!(
    OnnxCategoricalClassifier,
    "Sets the classification threshold (minimum probability to emit a pair; default 0.5)."
);
fail_mode_methods!(OnnxCategoricalClassifier);

impl OnnxCategoricalClassifier {
    /// Loads an N-class model with an explicit category mapping and
    /// validates everything (input wiring, output name, class count) with a
    /// warmup inference at startup.
    ///
    /// # Errors
    /// Same as [`OnnxSecurityClassifier::new`], plus: the model's class
    /// count differs from `category_map.len()`.
    pub fn new(
        model_path: &str,
        tokenizer_path: &str,
        category_map: Vec<GuardCategory>,
    ) -> Result<Self, MlError> {
        if category_map.is_empty() {
            return Err(MlError::new("category map cannot be empty"));
        }
        let (core, warmup) = OnnxCore::new(model_path, tokenizer_path, OnnxOptions::defaults(0.5))?;
        if warmup.len() != category_map.len() {
            return Err(MlError::new(format!(
                "model has {} classes but the category map has {} entries",
                warmup.len(),
                category_map.len()
            )));
        }
        Ok(Self {
            core,
            category_map,
            multi_label: false,
            model_path: model_path.to_owned(),
        })
    }

    /// Safety preset: the six L3 categories.
    ///
    /// # Errors
    /// Same as [`OnnxCategoricalClassifier::new`].
    pub fn safety(model_path: &str, tokenizer_path: &str) -> Result<Self, MlError> {
        Self::new(model_path, tokenizer_path, SAFETY_CATEGORIES.to_vec())
    }

    /// Switches to per-class sigmoid (independent labels).
    #[must_use]
    pub const fn multi_label(mut self, yes: bool) -> Self {
        self.multi_label = yes;
        self
    }

    /// Scores one text: `(category, probability)` for every class, in the
    /// model's class order (softmax- or sigmoid-normalized per the mode).
    ///
    /// # Errors
    /// Tokenization or inference failure, a timeout, or a degraded lane
    /// failing fast.
    pub fn probs(&self, text: &str) -> Result<Vec<(GuardCategory, f32)>, MlError> {
        let logits = self.core.raw_logits(text)?;
        let probs = if self.multi_label {
            sigmoid_all(&logits)
        } else {
            softmax_all(&logits)
        };
        Ok(self.category_map.iter().copied().zip(probs).collect())
    }

    /// One window: the thresholded pairs (highest first), the highest raw
    /// probability, and the error the [`FailMode`] decided on (if any).
    fn evaluate(&self, text: &str) -> Evaluated {
        let (mut out, raw, err) = match self.probs(text) {
            Ok(v) => {
                let raw = v
                    .iter()
                    .map(|p| p.1)
                    .fold(None, |m: Option<f32>, p| Some(m.map_or(p, |m| m.max(p))));
                let kept = v
                    .into_iter()
                    .filter(|(_, p)| *p >= self.core.options.threshold)
                    .collect();
                (kept, raw, None)
            }
            Err(e) => (
                match self.core.options.fail_mode {
                    FailMode::Closed => fail_closed_signals(&self.category_map),
                    FailMode::Open => Vec::new(),
                },
                None,
                Some(e),
            ),
        };
        out.sort_by(|a, b| b.1.total_cmp(&a.1));
        (out, raw, err)
    }
}

impl MlClassifier for OnnxCategoricalClassifier {
    /// Emits `(category, probability)` pairs at or above the threshold,
    /// sorted descending by probability (highest risk first).
    ///
    /// Fail-closed by DEFAULT: an inference error, a timeout
    /// or a degraded lane failing fast emits every category at 1.0 (block).
    /// Opt into fail-open with [`OnnxCategoricalClassifier::with_fail_mode`]
    /// and [`FailMode::Open`].
    fn classify(&self, text: &str) -> Vec<(GuardCategory, f32)> {
        self.classify_with_raw(text).0
    }

    /// One inference: the thresholded pairs (highest first) and the highest
    /// raw probability (`None` on an error).
    fn classify_with_raw(&self, text: &str) -> (Vec<(GuardCategory, f32)>, Option<f32>) {
        let (pairs, raw, _) = self.evaluate(text);
        (pairs, raw)
    }

    fn name(&self) -> &'static str {
        "onnx-categorical"
    }

    /// The global-budget windows, plus the exact per-call failure.
    fn classify_call(&self, call: &MlCall<'_>) -> MlOutcome {
        legacy_outcome(call.text, |w| self.evaluate(w))
    }

    /// Same semantics as the security classifier's `health`: `Degraded`
    /// while the lane is degraded or after an input-level failure within
    /// the last [`RECOVERY_COOLDOWN`].
    fn health(&self) -> MlHealth {
        self.core.ml_health()
    }
}

// ---------------------------------------------------------------- NER (L1)

/// A BIO-decoded candidate span before entity-type mapping.
struct BioSpan {
    /// Entity tag without the `B-`/`I-` prefix ("PER", "LOC", ...).
    label: String,
    /// Byte start (inclusive) into the input text.
    start: usize,
    /// Byte end (exclusive) into the input text.
    end: usize,
    /// Mean per-token probability of the winning labels.
    score: f32,
}

/// Pure BIO decoding over per-token `(label, probability, start, end)`
/// tuples. The caller filters zero-length (special/padding) offsets first.
///
/// Handles `B-X`/`I-X` schemes, plain `X` labels (IO scheme: consecutive
/// same-type tokens merge into one span) and the degenerate `I-X` without a
/// matching open span (treated as the start of a new span).
/// Merges duplicate entities produced by overlapping NER windows: same
/// kind + same text + overlapping span is the SAME real-world entity seen
/// by two windows; the best score survives. Partial-vs-full detections of
/// one entity (a window edge split it) have different texts and are both
/// kept - the engine's overlap resolver arbitrates them like any other
/// candidate collision.
fn merge_window_duplicates(mut ents: Vec<Entity>) -> Vec<Entity> {
    ents.sort_by_key(|e| (e.start, e.end));
    let mut kept: Vec<Entity> = Vec::with_capacity(ents.len());
    for e in ents {
        match kept
            .iter_mut()
            .find(|k| k.kind == e.kind && k.text == e.text && e.start < k.end && k.start < e.end)
        {
            Some(k) => k.score = k.score.max(e.score),
            None => kept.push(e),
        }
    }
    kept
}

fn decode_bio(tokens: &[(String, f32, usize, usize)]) -> Vec<BioSpan> {
    let mut spans: Vec<BioSpan> = Vec::new();
    // open span: (tag, start, end, per-token probabilities)
    let mut open: Option<(String, usize, usize, Vec<f32>)> = None;

    macro_rules! flush {
        () => {
            if let Some((label, s, e, probs)) = open.take() {
                spans.push(BioSpan {
                    label,
                    start: s,
                    end: e,
                    score: probs.iter().sum::<f32>() / probs.len() as f32,
                });
            }
        };
    }

    for (label, prob, start, end) in tokens {
        let (kind, tag) = if label.is_empty() || label == "O" {
            flush!();
            continue;
        } else if let Some(t) = label.strip_prefix("B-") {
            ('B', t.to_owned())
        } else if let Some(t) = label.strip_prefix("I-") {
            ('I', t.to_owned())
        } else {
            // plain (non-BIO) scheme: consecutive same-type tokens are one
            // entity, so a plain label continues an open span of its type
            ('P', label.clone())
        };

        let continues = kind != 'B' && matches!(&open, Some((t, _, _, _)) if *t == tag);
        if continues {
            let o = open.as_mut().expect("continues implies an open span");
            o.2 = *end;
            o.3.push(*prob);
        } else {
            flush!();
            open = Some((tag, *start, *end, vec![*prob]));
        }
    }
    flush!();
    spans
}

/// ONNX-backed NER recognizer for token-classification exports (the L1 model
/// slot, see [`NerRecognizer`]).
///
/// Shape: inputs `input_ids`/`attention_mask`/`token_type_ids`, output
/// `logits` `[1, seq, num_labels]` - the standard token-classification
/// export (`ML_SETUP.md` describes the expected files).
/// `label_map` follows the model's `id2label` order (e.g.
/// `["O","B-PER","I-PER","B-LOC",...]` for savasy/bert-base-turkish-ner).
///
/// Only tags mapped through the entity map are emitted (default:
/// `PER` -> [`EntityType::Name`] and `LOC` -> [`EntityType::Address`]);
/// `ORG`/`MISC`/... are decoded but dropped unless mapped with
/// [`OnnxNerRecognizer::with_entity_map`] or
/// [`OnnxNerRecognizer::with_entity_type`].
///
/// Options: the shared set of this module (threshold default 0.7, 2 s
/// timeout, 512 tokens). The recognizer has no error policy: it is an
/// enricher, so a failed inference yields no spans and is reported through
/// [`NerRecognizer::health`] instead.
pub struct OnnxNerRecognizer {
    core: OnnxCore,
    /// logits index -> BIO label string (length == model class count).
    pub label_map: Vec<String>,
    /// BIO tag -> entity type (default: PER -> Name, LOC -> Address).
    pub entity_map: Vec<(String, EntityType)>,
    /// Path of the loaded model (for rationale strings / debugging).
    pub model_path: String,
}

impl fmt::Debug for OnnxNerRecognizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnnxNerRecognizer")
            .field("model_path", &self.model_path)
            .field("labels", &self.label_map)
            .field("threshold", &self.core.options.threshold)
            .finish_non_exhaustive()
    }
}

shared_option_methods!(
    OnnxNerRecognizer,
    "Sets the minimum mean span probability (default 0.7; calibrate with the eval harness, `guard::metrics::best_f1_threshold`)."
);

impl OnnxNerRecognizer {
    /// Loads the model and tokenizer and validates the class count against
    /// `label_map` with a real token-classification warmup pass.
    ///
    /// # Errors
    /// - model/tokenizer missing or unreadable, unsupported model input
    /// - the warmup pass is not shaped `[seq, label_map.len()]`
    pub fn new(
        model_path: &str,
        tokenizer_path: &str,
        label_map: Vec<String>,
    ) -> Result<Self, MlError> {
        if label_map.is_empty() {
            return Err(MlError::new("label map cannot be empty"));
        }
        let (core, _) = OnnxCore::new(model_path, tokenizer_path, OnnxOptions::defaults(0.7))?;
        let r = Self {
            core,
            entity_map: vec![
                ("PER".to_owned(), EntityType::Name),
                ("LOC".to_owned(), EntityType::Address),
            ],
            label_map,
            model_path: model_path.to_owned(),
        };
        // warmup validation for the [seq, num_labels] shape
        let (_, data, offsets) = r.core.raw_token_logits("warmup")?;
        let seq = offsets.len();
        if seq == 0 || data.is_empty() {
            return Err(MlError::new(
                "NER warmup produced no logits (empty token stream?)",
            ));
        }
        let classes = data.len() / seq;
        if data.len() != classes * seq || classes != r.label_map.len() {
            return Err(MlError::new(format!(
                "model has {classes} classes but the label map has {} entries",
                r.label_map.len()
            )));
        }
        Ok(r)
    }

    /// Replaces the BIO-tag → [`EntityType`] mapping (default: PER→Name,
    /// LOC→Address). Tags not in the map are decoded but dropped - use this
    /// to attach models with richer taxonomies (e.g. PIIRanha's
    /// GIVENNAME/SURNAME/STREET/CITY labels).
    #[must_use]
    pub fn with_entity_map(mut self, map: Vec<(String, EntityType)>) -> Self {
        self.entity_map = map;
        self
    }

    /// Maps one more BIO tag to an entity type (e.g. a model-specific tag
    /// such as `("GIVENNAME", EntityType::Name)`).
    #[must_use]
    pub fn with_entity_type(mut self, tag: &str, kind: EntityType) -> Self {
        self.entity_map.push((tag.to_owned(), kind));
        self
    }

    /// Recognizes entities with a real ONNX inference: tokenize with
    /// offsets -> per-token softmax + argmax -> BIO decode -> entity mapping.
    ///
    /// Long documents (over the 1800-char chunk budget) are scanned in
    /// overlapping windows with span offsets remapped into document
    /// coordinates, so the 512-token truncation never hides a name past
    /// the document head. An entity found whole in
    /// one window and (partially) in the next keeps its best whole form;
    /// duplicates from the overlap band are merged by (kind + text).
    ///
    /// # Errors
    /// Tokenization or inference failure, a timeout, or a degraded lane
    /// failing fast. A malformed output shape yields an empty result
    /// instead of an error (the recognizer is an enricher: fail-open).
    pub fn recognize_raw(&self, text: &str) -> Result<Vec<Entity>, MlError> {
        // CHAR budget (chars().count(), matching the const contract;
        // ASCII fast path avoids the scan)
        let within = text.len() <= crate::guard::ml::CHUNK_CHAR_BUDGET && text.is_ascii()
            || text.chars().count() <= crate::guard::ml::CHUNK_CHAR_BUDGET;
        if within {
            return self.recognize_window(text);
        }
        let mut all: Vec<Entity> = Vec::new();
        for (base, window) in char_windows_at(
            text,
            crate::guard::ml::CHUNK_CHAR_BUDGET,
            crate::guard::ml::CHUNK_CHAR_OVERLAP,
        ) {
            for mut e in self.recognize_window(window)? {
                e.start += base;
                e.end += base;
                all.push(e);
            }
        }
        Ok(merge_window_duplicates(all))
    }

    /// Recognition over one window (at most one tokenizer truncation span).
    fn recognize_window(&self, text: &str) -> Result<Vec<Entity>, MlError> {
        let (_shape, data, offsets) = self.core.raw_token_logits(text)?;
        let seq = offsets.len();
        let labels = self.label_map.len();
        if seq == 0 || data.len() != seq * labels {
            return Ok(Vec::new()); // pathological shape: emit nothing
        }

        // per-token winning label + probability (skip specials: zero-length)
        let mut tokens: Vec<(String, f32, usize, usize)> = Vec::with_capacity(seq);
        for (i, &(s, e)) in offsets.iter().enumerate() {
            if s >= e {
                continue; // [CLS]/[SEP]/padding
            }
            let row = &data[i * labels..(i + 1) * labels];
            let probs = softmax_all(row);
            let (bi, bp) = probs
                .iter()
                .enumerate()
                .fold(
                    (0_usize, 0_f32),
                    |(bi, bp), (i, &p)| {
                        if p > bp {
                            (i, p)
                        } else {
                            (bi, bp)
                        }
                    },
                );
            let label = &self.label_map[bi];
            if label == "O" || label.is_empty() {
                continue;
            }
            tokens.push((label.clone(), bp, s, e));
        }

        let mut out = Vec::new();
        for span in decode_bio(&tokens) {
            let Some(kind) = self
                .entity_map
                .iter()
                .find(|(t, _)| *t == span.label)
                .map(|(_, k)| *k)
            else {
                continue; // decoded but not in entity_map (e.g. ORG/MISC): dropped
            };
            if span.score < self.core.options.threshold {
                continue;
            }
            if span.end > text.len()
                || !text.is_char_boundary(span.start)
                || !text.is_char_boundary(span.end)
            {
                continue; // defensive: tokenizer offsets must be boundaries
            }
            out.push(Entity {
                kind,
                start: span.start,
                end: span.end,
                text: text[span.start..span.end].to_owned(),
                score: span.score,
            });
        }
        Ok(out)
    }
}

impl NerRecognizer for OnnxNerRecognizer {
    /// Fail-open on inference errors (returns empty): construction already
    /// validated the model with a warmup, and the deterministic L1 rules
    /// keep running either way. The failure is RECORDED by the inference
    /// core, so [`NerRecognizer::health`] reports `Degraded` and the guard
    /// pipeline surfaces `NER_DEGRADED` instead of presenting the absence as
    /// clean text.
    fn recognize(&self, text: &str) -> Vec<Entity> {
        self.recognize_raw(text).unwrap_or_default()
    }

    /// `Degraded` while the inference lane is degraded (a timeout or a dead
    /// worker: every call returns no spans until a half-open probe has
    /// rebuilt the session, see [`RECOVERY_COOLDOWN`]) or when an
    /// input-level inference failure happened within the last
    /// [`RECOVERY_COOLDOWN`]; `Ok` otherwise. The state is shared by every
    /// caller of this recognizer, so a request reading it right after its
    /// own failed `recognize` always sees `Degraded`.
    fn health(&self) -> NerHealth {
        match self.core.health() {
            CoreHealth::Ok => NerHealth::Ok,
            CoreHealth::Lane(_) => NerHealth::Degraded(
                "onnx ner inference lane degraded (timeout or worker failure): spans absent until recovery",
            ),
            CoreHealth::Call(_) => NerHealth::Degraded("onnx ner inference failed: spans absent"),
        }
    }

    fn name(&self) -> &'static str {
        "onnx-ner"
    }
}

/// Loads `labels.json` (a JSON array of label strings in `id2label` order,
/// written next to the ONNX file at export time; see `ML_SETUP.md`).
///
/// # Errors
/// File missing/unreadable, or the content is not a JSON array of strings.
pub fn load_labels_json(path: &str) -> Result<Vec<String>, MlError> {
    let raw = std::fs::read_to_string(path)?;
    serde_json::from_str(&raw)
        .map_err(|e| MlError::with_source("labels.json is not a JSON array of strings", e))
}

/// Qwen3Guard-Stream query-side category slots (config.json
/// `query_category_map`; evidence: the 4-head export described in
/// `ML_SETUP.md` + the model README's usage rule "read the LAST token's
/// scores").
pub const QWEN_QUERY_CATEGORY_NAMES: [&str; 9] = [
    "Violent",
    "Sexual Content",
    "Self-Harm",
    "Political",
    "PII",
    "Copyright",
    "Illegal Acts",
    "Unethical",
    "Jailbreak",
];

/// Label harmonization: model slots → our taxonomy.
/// Political/Copyright/PII/Illegal/Unethical map to [`GuardCategory::Misconduct`]
/// (MISCONDUCT covers "non-violent illegal + unethical acts"); PII's
/// PRIMARY defense stays L1 masking - the ML signal is secondary evidence.
/// Remappable per deployment via [`OnnxStreamGuardClassifier::with_category_map`].
pub const QWEN_QUERY_CATEGORY_MAP: [GuardCategory; 9] = [
    GuardCategory::Violence,
    GuardCategory::Sexual,
    GuardCategory::SelfHarm,
    GuardCategory::Misconduct,
    GuardCategory::Misconduct,
    GuardCategory::Misconduct,
    GuardCategory::Misconduct,
    GuardCategory::Misconduct,
    GuardCategory::Jailbreak,
];

const STREAM_OUTPUTS: [&str; 4] = ["query_risk", "query_category", "resp_risk", "resp_category"];
const RISK_CLASSES: usize = 3; // safe / controversial / unsafe
const QUERY_CATS: usize = 9;
const RESP_CATS: usize = 8;

/// Returns the last row of a row-major `[1, seq, width]` flat tensor.
///
/// Returns `None` when `flat` is shorter than `width` or not row-aligned,
/// so a malformed model output never panics, in release builds too.
#[must_use]
pub fn last_row(flat: &[f32], width: usize) -> Option<&[f32]> {
    if width == 0 || flat.len() < width || flat.len() % width != 0 {
        return None;
    }
    flat.get(flat.len() - width..)
}

/// Three-tier risk band (model-card semantics: Safe / Controversial / Unsafe).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RiskBand {
    /// Model says safe.
    Safe,
    /// Model says controversial.
    Controversial,
    /// Model says unsafe.
    Unsafe,
}

/// A full scoring result from the stream-guard model.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct StreamGuardScore {
    /// p(safe) - last-token softmax over the 3-tier risk head.
    pub p_safe: f32,
    /// p(controversial).
    pub p_controversial: f32,
    /// p(unsafe).
    pub p_unsafe: f32,
    /// Argmax band of the risk head.
    pub risk: RiskBand,
    /// Index of the argmax category slot (see [`QWEN_QUERY_CATEGORY_NAMES`]).
    pub category_slot: usize,
    /// Raw model-side name of that slot.
    pub category_name: &'static str,
    /// Harmonized [`GuardCategory`] for the slot.
    pub category: GuardCategory,
    /// Risk signal used by [`MlClassifier::classify`]: the NOT-safe mass
    /// (`1 - p_safe`), i.e. controversial + unsafe combined. Rationale: the
    /// model is three-tier by design (model card); a binary classifier
    /// consumer needs one number, and "not safe" is the band union.
    pub score: f32,
}

/// Qwen3Guard-Stream (0.6B) classifier through the custom 4-head ONNX export.
///
/// Shape (evidence-driven, see the 4-head export in `ML_SETUP.md`): outputs
/// `query_risk [1,seq,3]`, `query_category [1,seq,9]`, `resp_risk [1,seq,3]`,
/// `resp_category [1,seq,8]`. Per the model card's usage rule, scoring reads
/// the **last token's** row of the query-side heads (this is a user-prompt
/// guard; response moderation is out of its scope).
///
/// Construction validates all four heads and cross-checks their sequence
/// lengths with a warmup inference.
///
/// Threshold calibration (measured):
/// the score distribution shifts by task family, so no single default fits
/// both - safety-guard use: **0.815** (best-F1 on the 330-item safety-v1
/// set; F1 0.785 / FPR 0.070), injection-guard use: ~**0.65** (best-F1
/// 0.721 on the 540-item v1 set, though at high FPR 0.436). The 0.5 default
/// sits in between on purpose; measure YOUR distribution before production.
///
/// Runtime note: the fp32 export is 2.3 GB; measure memory and latency before deploying it. int8 for this
/// model is untested.
///
/// Options: the shared set of this module (threshold default 0.5,
/// [`FailMode::Closed`] like every ONNX classifier, 2 s timeout, 512
/// tokens).
pub struct OnnxStreamGuardClassifier {
    core: OnnxCore,
    /// Slot → category harmonization (see [`QWEN_QUERY_CATEGORY_MAP`]).
    pub category_map: [GuardCategory; QUERY_CATS],
    /// Path of the loaded model (for rationale strings / debugging).
    pub model_path: String,
}

impl fmt::Debug for OnnxStreamGuardClassifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnnxStreamGuardClassifier")
            .field("model_path", &self.model_path)
            .field("threshold", &self.core.options.threshold)
            .finish_non_exhaustive()
    }
}

shared_option_methods!(
    OnnxStreamGuardClassifier,
    "Sets the minimum not-safe score to emit a signal (default 0.5; see the type docs for the measured operating points)."
);
fail_mode_methods!(OnnxStreamGuardClassifier);

impl OnnxStreamGuardClassifier {
    /// Loads the 4-head export and validates all heads with a warmup.
    ///
    /// # Errors
    /// - model/tokenizer problems (same as [`OnnxSecurityClassifier::new`])
    /// - a named output is missing, has a wrong class width, or the heads'
    ///   sequence lengths disagree
    pub fn new(model_path: &str, tokenizer_path: &str) -> Result<Self, MlError> {
        let (core, _single_warmup) =
            OnnxCore::new(model_path, tokenizer_path, OnnxOptions::defaults(0.5))?;
        let cls = Self {
            core,
            category_map: QWEN_QUERY_CATEGORY_MAP,
            model_path: model_path.to_owned(),
        };
        cls.validate_heads()?;
        Ok(cls)
    }

    /// Overrides the slot → category harmonization.
    #[must_use]
    pub const fn with_category_map(mut self, map: [GuardCategory; QUERY_CATS]) -> Self {
        self.category_map = map;
        self
    }

    fn validate_heads(&self) -> Result<(), MlError> {
        let outs = self.core.run_outputs("warmup", &STREAM_OUTPUTS)?;
        let [qr, qc, rr, rc] = [&outs[0], &outs[1], &outs[2], &outs[3]];
        if qr.is_empty() || qc.is_empty() || rr.is_empty() || rc.is_empty() {
            return Err(MlError::new("stream model produced an empty head"));
        }
        let seq = |flat: &[f32], width: usize| -> Result<usize, MlError> {
            if flat.len() % width != 0 {
                return Err(MlError::new(format!(
                    "head length {} not a multiple of class width {width}",
                    flat.len()
                )));
            }
            Ok(flat.len() / width)
        };
        let s = seq(qr, RISK_CLASSES)?;
        let lengths = [
            s,
            seq(qc, QUERY_CATS)?,
            seq(rr, RISK_CLASSES)?,
            seq(rc, RESP_CATS)?,
        ];
        if lengths.contains(&0) || lengths.iter().any(|&x| x != s) {
            return Err(MlError::new(format!(
                "head sequence lengths disagree: {lengths:?}"
            )));
        }
        Ok(())
    }

    /// Scores one text: last-token softmax over the query-side heads.
    ///
    /// # Errors
    /// Tokenization or inference failure, a timeout, or a degraded lane
    /// failing fast.
    pub fn score(&self, text: &str) -> Result<StreamGuardScore, MlError> {
        let outs = self
            .core
            .run_outputs(text, &["query_risk", "query_category"])?;
        let risk = softmax_all(
            last_row(outs.first().map_or(&[], |v| v.as_slice()), RISK_CLASSES)
                .ok_or_else(|| MlError::new("query_risk head shorter than class width"))?,
        );
        let cats = softmax_all(
            last_row(outs.get(1).map_or(&[], |v| v.as_slice()), QUERY_CATS)
                .ok_or_else(|| MlError::new("query_category head shorter than class width"))?,
        );
        let (slot, _) = cats
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.total_cmp(b.1))
            .unwrap_or((0, &0.0));
        let (band_idx, _) = risk
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.total_cmp(b.1))
            .unwrap_or((0, &0.0));
        let p_safe = risk.first().copied().unwrap_or(0.0);
        Ok(StreamGuardScore {
            p_safe,
            p_controversial: risk.get(1).copied().unwrap_or(0.0),
            p_unsafe: risk.get(2).copied().unwrap_or(0.0),
            risk: match band_idx {
                0 => RiskBand::Safe,
                1 => RiskBand::Controversial,
                _ => RiskBand::Unsafe,
            },
            category_slot: slot,
            category_name: QWEN_QUERY_CATEGORY_NAMES[slot],
            category: self.category_map[slot],
            score: 1.0 - p_safe,
        })
    }

    /// One window: the thresholded pair (no raw score is reported, as
    /// before) and the error the [`FailMode`] decided on (if any).
    fn evaluate(&self, text: &str) -> Evaluated {
        match self.score(text) {
            Ok(s) if s.score >= self.core.options.threshold => {
                (vec![(s.category, s.score)], None, None)
            }
            Ok(_) => (Vec::new(), None, None),
            Err(e) => (
                match self.core.options.fail_mode {
                    FailMode::Closed => fail_closed_signals(&self.category_map),
                    FailMode::Open => Vec::new(),
                },
                None,
                Some(e),
            ),
        }
    }
}

impl MlClassifier for OnnxStreamGuardClassifier {
    /// Emits `(harmonized category, 1 - p_safe)` when the not-safe mass
    /// reaches the threshold. On inference errors (including a timeout and
    /// a degraded lane failing fast) the [`FailMode`] policy applies:
    /// CLOSED (the default, same as every other ONNX classifier) emits
    /// maximum-severity signals so a failed runtime blocks; OPEN emits
    /// nothing and the deterministic layers decide.
    fn classify(&self, text: &str) -> Vec<(GuardCategory, f32)> {
        self.evaluate(text).0
    }

    fn name(&self) -> &'static str {
        "qwen3guard-stream"
    }

    /// The global-budget windows (no raw score is reported), plus
    /// the exact per-call failure.
    fn classify_call(&self, call: &MlCall<'_>) -> MlOutcome {
        legacy_outcome(call.text, |w| self.evaluate(w))
    }

    /// Same semantics as the security classifier's `health`: `Degraded`
    /// while the lane is degraded or after an input-level failure within
    /// the last [`RECOVERY_COOLDOWN`].
    fn health(&self) -> MlHealth {
        self.core.ml_health()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        logits_to_positive_prob, resolve_tokenizer_path, sigmoid_all, softmax_all,
        OnnxCategoricalClassifier, OnnxSecurityClassifier,
    };
    use crate::guard::category::GuardCategory;

    // ---------------------------------------------------- BIO decoding (NER)

    mod bio {
        use super::super::decode_bio;

        fn tok(label: &str, prob: f32, s: usize, e: usize) -> (String, f32, usize, usize) {
            (label.to_owned(), prob, s, e)
        }

        #[test]
        fn two_token_person_span() {
            let spans = decode_bio(&[
                tok("O", 0.99, 0, 5),
                tok("B-PER", 0.9, 6, 11),
                tok("I-PER", 0.8, 12, 18),
            ]);
            assert_eq!(spans.len(), 1);
            assert_eq!(spans[0].label, "PER");
            assert_eq!(spans[0].start, 6);
            assert_eq!(spans[0].end, 18);
            assert!((spans[0].score - 0.85).abs() < 1e-6);
        }

        #[test]
        fn i_without_b_starts_a_new_span() {
            let spans = decode_bio(&[tok("I-PER", 0.9, 0, 5), tok("I-PER", 0.7, 6, 10)]);
            assert_eq!(spans.len(), 1);
            assert_eq!(spans[0].start, 0);
            assert_eq!(spans[0].end, 10);
        }

        #[test]
        fn adjacent_different_types_split() {
            let spans = decode_bio(&[
                tok("B-PER", 0.9, 0, 5),
                tok("B-LOC", 0.8, 6, 14),
                tok("I-LOC", 0.7, 15, 20),
            ]);
            assert_eq!(spans.len(), 2);
            assert_eq!(spans[0].label, "PER");
            assert_eq!(spans[1].label, "LOC");
            assert_eq!(spans[1].end, 20);
        }

        #[test]
        fn same_type_second_b_starts_new_span() {
            let spans = decode_bio(&[tok("B-PER", 0.9, 0, 5), tok("B-PER", 0.9, 6, 11)]);
            assert_eq!(spans.len(), 2);
        }

        #[test]
        fn plain_labels_treated_as_b() {
            let spans = decode_bio(&[tok("PER", 0.9, 0, 5), tok("PER", 0.7, 6, 11)]);
            assert_eq!(spans.len(), 1);
            assert_eq!(spans[0].end, 11);
        }

        #[test]
        fn outside_closes_the_open_span() {
            let spans = decode_bio(&[
                tok("B-PER", 0.9, 0, 5),
                tok("O", 0.99, 6, 7),
                tok("B-PER", 0.9, 8, 13),
            ]);
            assert_eq!(spans.len(), 2);
            assert_eq!(spans[0].end, 5);
            assert_eq!(spans[1].start, 8);
        }

        #[test]
        fn trailing_open_span_is_flushed() {
            let spans = decode_bio(&[tok("B-PER", 0.9, 0, 5), tok("I-PER", 0.8, 6, 11)]);
            assert_eq!(spans.len(), 1);
            assert_eq!(spans[0].end, 11);
            assert!((spans[0].score - 0.85).abs() < 1e-6);
        }
    }

    #[test]
    fn logits_empty_is_zero() {
        assert_eq!(logits_to_positive_prob(&[]), 0.0);
    }

    #[test]
    fn fail_closed_signals_cover_every_category_at_block_level() {
        let cats = crate::policy::GuardCategory::Hate; // single-category map
        let sigs = super::fail_closed_signals(&[cats]);
        assert_eq!(sigs, vec![(cats, 1.0)]);
        // every severity band's block line is <= 1.0 by construction
        assert!(crate::policy::Threshold::High.block_score() <= sigs[0].1);
    }

    #[test]
    fn logits_single_is_sigmoid() {
        assert!((logits_to_positive_prob(&[0.0]) - 0.5).abs() < 1e-6);
        assert!(logits_to_positive_prob(&[4.0]) > 0.98);
        assert!(logits_to_positive_prob(&[-4.0]) < 0.02);
    }

    #[test]
    fn logits_binary_is_softmax_positive_last() {
        assert!(logits_to_positive_prob(&[0.0, 5.0]) > 0.99);
        assert!(logits_to_positive_prob(&[5.0, 0.0]) < 0.01);
        assert!((logits_to_positive_prob(&[3.0, 3.0]) - 0.5).abs() < 1e-6);
    }

    #[test]
    fn logits_multi_class_takes_last() {
        // three-class export: positive mass concentrated on the last index
        assert!(logits_to_positive_prob(&[0.0, 0.0, 8.0]) > 0.99);
    }

    #[test]
    fn logits_softmax_is_stable_for_large_values() {
        // naive exp(1000) overflows to inf; the stable path must not
        assert!((logits_to_positive_prob(&[1000.0, 1000.0]) - 0.5).abs() < 1e-6);
        let p = logits_to_positive_prob(&[1000.0, 1001.0]);
        assert!((p - 0.731).abs() < 0.01);
    }

    #[test]
    fn softmax_all_normalizes() {
        let p = softmax_all(&[0.0, 0.0, 0.0]);
        assert_eq!(p.len(), 3);
        assert!((p.iter().sum::<f32>() - 1.0).abs() < 1e-6);
        assert!(p.iter().all(|&v| (v - 1.0 / 3.0).abs() < 1e-6));
        let p = softmax_all(&[1000.0, 1000.0]);
        assert!((p[0] - 0.5).abs() < 1e-6, "stable at extreme logits");
        assert!(softmax_all(&[]).is_empty());
    }

    #[test]
    fn sigmoid_all_is_independent() {
        let p = sigmoid_all(&[0.0, 4.0, -4.0]);
        assert!((p[0] - 0.5).abs() < 1e-6);
        assert!(p[1] > 0.98);
        assert!(p[2] < 0.02);
        // multi-label: probabilities do NOT sum to 1
        assert!(p.iter().sum::<f32>() > 1.0);
        assert!(sigmoid_all(&[]).is_empty());
    }

    #[test]
    fn tokenizer_path_accepts_dir_or_file() {
        let file = resolve_tokenizer_path("a/b/tokenizer.json");
        assert!(file.to_string_lossy().ends_with("tokenizer.json"));
        // a directory gets tokenizer.json appended (uses the real temp dir so
        // is_dir() is honest on every platform)
        let dir = std::env::temp_dir();
        let joined = resolve_tokenizer_path(dir.to_str().unwrap());
        assert_eq!(joined, dir.join("tokenizer.json"));
    }

    #[test]
    fn new_rejects_empty_model_path() {
        let err = OnnxSecurityClassifier::new("", "nowhere").unwrap_err();
        assert!(err.message.contains("model path"));
    }

    #[test]
    fn new_rejects_missing_files() {
        let err = OnnxSecurityClassifier::new(
            "definitely/missing/model.onnx",
            "definitely/missing/tokenizer",
        )
        .unwrap_err();
        assert!(!err.message.is_empty());
    }

    #[test]
    fn categorical_rejects_empty_map() {
        let err = OnnxCategoricalClassifier::new(
            "definitely/missing/model.onnx",
            "definitely/missing/tokenizer",
            Vec::new(),
        )
        .unwrap_err();
        assert!(err.message.contains("category map"));
    }

    #[test]
    fn categorical_map_order_is_preserved() {
        // construction fails before the map is consulted; this checks the
        // intended mapping is expressible (all six safety categories distinct)
        let map = crate::guard::ml::SAFETY_CATEGORIES.to_vec();
        let mut seen = std::collections::HashSet::new();
        for c in &map {
            assert!(seen.insert(c.as_str()), "duplicate category in map");
        }
        let _ = GuardCategory::SelfHarm; // map targets are real variants
    }

    #[test]
    fn last_row_takes_final_width_slice() {
        use super::last_row;
        // [1, seq=2, width=3]: rows [1,2,3] and [4,5,6]
        assert_eq!(
            last_row(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0], 3),
            Some(&[4.0, 5.0, 6.0][..])
        );
        assert_eq!(last_row(&[7.0, 8.0, 9.0], 3), Some(&[7.0, 8.0, 9.0][..]));
        // short/misaligned output must be None, never a release-build
        // slice panic
        assert_eq!(last_row(&[1.0, 2.0], 3), None);
        assert_eq!(last_row(&[1.0, 2.0, 3.0, 4.0], 3), None);
        assert_eq!(last_row(&[], 3), None);
    }

    #[test]
    fn qwen_harmonization_matches_slot_names() {
        use super::{QWEN_QUERY_CATEGORY_MAP, QWEN_QUERY_CATEGORY_NAMES};
        assert_eq!(
            QWEN_QUERY_CATEGORY_NAMES.len(),
            QWEN_QUERY_CATEGORY_MAP.len()
        );
        // evidence-locked anchors: config.json query_category_map order
        assert_eq!(QWEN_QUERY_CATEGORY_NAMES[8], "Jailbreak");
        assert_eq!(QWEN_QUERY_CATEGORY_MAP[8], GuardCategory::Jailbreak);
        assert_eq!(QWEN_QUERY_CATEGORY_NAMES[0], "Violent");
        assert_eq!(QWEN_QUERY_CATEGORY_MAP[0], GuardCategory::Violence);
        assert_eq!(QWEN_QUERY_CATEGORY_MAP[2], GuardCategory::SelfHarm);
        // PII slot harmonizes to Misconduct; L1 masking stays the primary
        // PII defense (documented design decision)
        assert_eq!(QWEN_QUERY_CATEGORY_MAP[4], GuardCategory::Misconduct);
    }

    #[test]
    fn stream_guard_rejects_missing_files() {
        let err = super::OnnxStreamGuardClassifier::new(
            "definitely/missing/stream.onnx",
            "definitely/missing/tokenizer",
        )
        .unwrap_err();
        assert!(!err.message.is_empty());
    }
}
