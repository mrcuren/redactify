//! Deterministic guard rules, input normalization, output guards, the ML
//! classifier interfaces (the pipeline contract and the pluggable adapter
//! contract), and the evaluation harness (the L0/L2/L3/L4 layers).

pub mod action;
pub mod audit;
pub mod category;
pub mod classifier;
pub mod egress;
// generated Unicode confusable table (UTS #39 data, see its module doc)
mod confusables;
// generated Unicode decimal digit blocks (UCD data, see its module doc)
mod digits;
pub mod eval;
// shared bounded-inference executor (worker thread, hard timeout, circuit
// breaker with half-open probe): ONNX lanes and `Guarded::isolated`
pub(crate) mod executor;
pub mod guarded;
pub(crate) mod leak;
pub mod metrics;
pub mod ml;
#[cfg(feature = "ml-onnx")]
pub mod ner_router;
pub mod normalize;
#[cfg(feature = "ml-onnx")]
#[cfg_attr(docsrs, doc(cfg(feature = "ml-onnx")))]
pub mod onnx;
pub mod output;
pub mod rules;
pub mod secrets;
pub mod tools;

pub use action::GuardAction;
pub use audit::AuditRecord;
pub use category::GuardCategory;
pub use classifier::{
    Capabilities, CategoryScore, ClassifierError, ClassifyRequest, GuardClassifier, Role,
    ScoreKind, Verdict,
};
pub use egress::{EgressAllowlist, EgressAllowlistError, EgressFiltered, EgressLineFilter};
pub use eval::{
    evaluate, load_eval_set, render_markdown, score_with, EvalItem, EvalReport, SliceMetrics,
};
pub use guarded::Guarded;
pub use leak::{prompt_leak_risk, SHINGLE_WORDS};
pub use metrics::{
    auprc, best_f1_threshold, confusion, confusion_at_threshold, mcc, mcc_at_threshold, roc_auc,
    BinaryMetrics, ConfusionCounts, ThresholdPoint,
};
pub use ml::{
    fail_closed_signals, ml_degraded_signal, ml_signal, run_ml, run_ml_call, FailMode, MlCall,
    MlClassifier, MlHealth, MlOutcome, MlRouter, MockSafetyClassifier, MockSecurityClassifier,
    RouteAction, ML_DEGRADED_SCORE, SAFETY_CATEGORIES, SECURITY_CATEGORIES,
};
#[cfg(feature = "ml-onnx")]
pub use ner_router::{default_slots, NerRouter, NerSlot};
#[cfg(feature = "ml-onnx")]
pub use onnx::{
    last_row, ModelSpec, OnnxEncoder, OnnxNerRecognizer, OnnxStreamGuardClassifier, RiskBand,
    StreamGuardScore, QWEN_QUERY_CATEGORY_MAP, QWEN_QUERY_CATEGORY_NAMES,
};
pub use output::{encode_html, validate_json_schema, JsonSchema};
pub use rules::{
    authority_impersonation_risk, char_collapse, command_injection_risk, crlf_injection_risk,
    deep_pii, nosql_injection_risk, obfuscation_risk, path_traversal_risk, script_scheme_risk,
    sql_risk, template_injection_risk, tool_injection_risk, url_guard, xpath_injection_risk,
    xss_risk, xxe_risk, GuardSignal, SignalKind,
};
pub use secrets::{
    find_secret_mask_spans, find_secret_spans, mask_secrets, mask_secrets_with, secrets_risk,
    SecretFinding,
};
