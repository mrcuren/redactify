//! Deterministic guard rules, input normalization, output guards and the ML
//! classifier interface (the L0/L2/L3/L4 layers).

pub mod ml;
pub mod normalize;
#[cfg(feature = "ml-onnx")]
pub mod onnx;
pub mod output;
pub mod rules;

pub use ml::{
    ml_signal, run_ml, MlClassifier, MlRouter, MockSafetyClassifier, MockSecurityClassifier,
    RouteAction, SAFETY_CATEGORIES, SECURITY_CATEGORIES,
};
pub use output::{encode_html, validate_json_schema, JsonSchema};
pub use rules::{
    authority_impersonation_risk, char_collapse, command_injection_risk, crlf_injection_risk,
    deep_pii, nosql_injection_risk, obfuscation_risk, path_traversal_risk, sql_risk,
    template_injection_risk, url_guard, xpath_injection_risk, xss_risk, xxe_risk, GuardSignal,
    SignalKind,
};
