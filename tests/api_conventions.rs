//! Compile-time checks of the Rust API Guidelines the public surface
//! promises: the main types are `Send + Sync` (C-SEND-SYNC) and `Debug`
//! (C-DEBUG), and every error type is `std::error::Error + Send + Sync +
//! 'static` (C-GOOD-ERR), so it travels through `?` into
//! `Box<dyn Error + Send + Sync>` and across threads. A type that loses one
//! of these properties stops this file from compiling, which a runtime test
//! could not catch.

use std::error::Error;
use std::fmt::Debug;

use redactify::guard::audit::{
    AuditSinkError, ChainError, ChainedAuditSink, FileAuditSink, ToolAuditFields,
};
use redactify::guard::egress::{
    EgressAllowlist, EgressAllowlistError, EgressFiltered, EgressLineFilter,
};
use redactify::guard::eval::{EvalError, EvalItem, EvalReport, SliceMetrics};
use redactify::guard::metrics::{BinaryMetrics, ConfusionCounts, ThresholdPoint};
use redactify::guard::ml::{MlRouter, MockSafetyClassifier, MockSecurityClassifier, RouteInputs};
use redactify::guard::output::{JsonSchema, SchemaError};
use redactify::guard::rules::{GuardSignal, SignalKind};
use redactify::guard::secrets::SecretFinding;
use redactify::guard::tools::{
    CallCounts, SessionDecision, SessionLimits, ToolCall, ToolCheckError, ToolCheckOutcome,
    ToolContract, ToolContractError, ToolSessions, ToolVerdict,
};
use redactify::guard::AuditRecord;
use redactify::{
    CustomLabel, CustomLabelError, CustomRule, CustomRuleError, CustomRuleSpec, CustomRules,
    CustomRulesError, Decision, Detector, DowngradedSpan, Entity, EntityType, EntityTypeParseError,
    Explanation, Guard, GuardAction, GuardCategory, GuardEvent, GuardTarget, GuardVerdict,
    JsonFinding, JsonRedactionReport, JsonRedactor, MaskStyle, MaskStyleError, MlStreamBudget,
    MockNameRecognizer, NerHealth, Policy, PseudonymKey, RelevancePolicy, RelevanceRule,
    RestoreOptions, SanitizeResult, ScanReport, Severity, StreamRestorer, StreamingGuard,
    Threshold, Vault, VaultError,
};

const fn thread_safe<T: Send + Sync + Debug>() {}
const fn good_error<T: Error + Send + Sync + 'static>() {}

#[test]
fn public_types_are_send_sync_and_debug() {
    // builders and engines
    thread_safe::<Detector<'static>>();
    thread_safe::<Guard<'static>>();
    thread_safe::<StreamingGuard>();
    thread_safe::<JsonRedactor<'static>>();
    thread_safe::<Vault>();
    thread_safe::<StreamRestorer<'static>>();
    thread_safe::<RestoreOptions>();
    thread_safe::<CustomRule>();
    thread_safe::<CustomRules>();
    thread_safe::<CustomRuleSpec>();
    thread_safe::<CustomLabel>();
    thread_safe::<MlRouter>();
    #[cfg(feature = "ml-onnx")]
    thread_safe::<redactify::guard::ner_router::NerRouter>();
    #[cfg(feature = "ml-onnx")]
    thread_safe::<redactify::guard::ner_router::NerSlot>();
    thread_safe::<MockSecurityClassifier>();
    thread_safe::<MockSafetyClassifier>();
    thread_safe::<MockNameRecognizer>();
    thread_safe::<ChainedAuditSink<Vec<u8>>>();
    thread_safe::<FileAuditSink>();
    thread_safe::<ToolContract>();
    thread_safe::<ToolSessions>();
    thread_safe::<EgressAllowlist>();
    thread_safe::<EgressLineFilter<'static>>();
    thread_safe::<JsonSchema>();
    // configuration
    thread_safe::<Policy>();
    thread_safe::<RelevancePolicy>();
    thread_safe::<RelevanceRule>();
    thread_safe::<MaskStyle>();
    thread_safe::<PseudonymKey>();
    thread_safe::<MlStreamBudget>();
    thread_safe::<GuardTarget>();
    thread_safe::<Threshold>();
    thread_safe::<SessionLimits>();
    thread_safe::<RouteInputs>();
    // results
    thread_safe::<Entity>();
    thread_safe::<EntityType>();
    thread_safe::<Explanation>();
    thread_safe::<ScanReport>();
    thread_safe::<Decision>();
    thread_safe::<SanitizeResult>();
    thread_safe::<GuardVerdict>();
    thread_safe::<GuardAction>();
    thread_safe::<GuardCategory>();
    thread_safe::<GuardEvent>();
    thread_safe::<Severity>();
    thread_safe::<DowngradedSpan>();
    thread_safe::<GuardSignal>();
    thread_safe::<SignalKind>();
    thread_safe::<SecretFinding>();
    thread_safe::<AuditRecord>();
    thread_safe::<ToolCall>();
    thread_safe::<ToolVerdict>();
    thread_safe::<ToolCheckOutcome>();
    thread_safe::<ToolAuditFields>();
    thread_safe::<SessionDecision>();
    thread_safe::<CallCounts>();
    thread_safe::<EgressFiltered>();
    thread_safe::<JsonFinding>();
    thread_safe::<JsonRedactionReport>();
    thread_safe::<NerHealth>();
    thread_safe::<EvalItem>();
    thread_safe::<EvalReport>();
    thread_safe::<SliceMetrics>();
    thread_safe::<ConfusionCounts>();
    thread_safe::<BinaryMetrics>();
    thread_safe::<ThresholdPoint>();
}

#[test]
fn error_types_are_well_behaved() {
    good_error::<CustomRuleError>();
    good_error::<CustomRulesError>();
    good_error::<CustomLabelError>();
    good_error::<EntityTypeParseError>();
    good_error::<VaultError>();
    good_error::<MaskStyleError>();
    good_error::<ChainError>();
    good_error::<AuditSinkError>();
    good_error::<EvalError>();
    good_error::<SchemaError>();
    good_error::<ToolContractError>();
    good_error::<ToolCheckError>();
    good_error::<EgressAllowlistError>();
    #[cfg(feature = "api")]
    good_error::<redactify::api::BearerTokenError>();
    #[cfg(feature = "ml-onnx")]
    good_error::<redactify::guard::onnx::MlError>();
}
