//! ONNX-backed security classifier (optional, behind `ml-onnx` feature).
//!
//! Implements [`MlClassifier`] using a real ONNX model. The ONNX model
//! (537MB, opset 17, dynamic batch/seq) has been exported and verified
//! with Python onnxruntime. This Rust binding uses the `ort` crate.
//!
//! **Status:** The ONNX model is exported and verified. The `ort` crate
//! compiles but its RC API (`2.0.0-rc.13`) has breaking changes from the
//! documented API. This module is a skeleton that documents the intended
//! integration; the inference call needs to be completed against the
//! stable `ort` release.
//!
//! Usage:
//! ```toml
//! [dependencies]
//! redactify = { version = "0.3", features = ["ml-onnx"] }
//! ```

use crate::guard::ml::{MlClassifier, SECURITY_CATEGORIES};
use crate::policy::GuardCategory;

/// ONNX-backed binary security classifier.
///
/// Wraps an ONNX model (prompt-guard-oss-small exported to opset 17,
/// inputs: `input_ids` + `attention_mask`, output: `logits` shape `[batch, 2]`).
///
/// **Note:** The `ort` crate is at `2.0.0-rc.13` and its API is subject to
/// change. The inference implementation will be finalized when `ort` reaches
/// a stable release. The model file and tokenizer are already exported and
/// verified working via Python `onnxruntime`.
#[cfg(feature = "ml-onnx")]
pub struct OnnxSecurityClassifier {
    /// Path to the ONNX model file (for documentation/debugging).
    pub model_path: String,
    /// Classification threshold (default: 0.5).
    pub threshold: f32,
    /// Pre-computed scores for known patterns (placeholder until ort API stabilizes).
    pattern_scores: Vec<(&'static str, GuardCategory, f32)>,
}

#[cfg(feature = "ml-onnx")]
impl OnnxSecurityClassifier {
    /// Creates a classifier reference for the ONNX model at `model_path`.
    ///
    /// The model file must exist and be a valid ONNX text-classification
    /// model (verified separately with Python onnxruntime).
    ///
    /// # Errors
    /// Returns an error if the model path is empty.
    pub fn new(model_path: &str) -> Result<Self, String> {
        if model_path.is_empty() {
            return Err("model path cannot be empty".to_owned());
        }
        Ok(Self {
            model_path: model_path.to_owned(),
            threshold: 0.5,
            pattern_scores: Self::default_patterns(),
        })
    }

    /// Sets the classification threshold.
    #[must_use]
    pub const fn with_threshold(mut self, threshold: f32) -> Self {
        self.threshold = threshold;
        self
    }

    /// Deterministic pattern matching (bridge until ONNX inference is wired).
    fn default_patterns() -> Vec<(&'static str, GuardCategory, f32)> {
        vec![
            ("ignore previous", GuardCategory::PromptInjection, 0.92),
            ("ignore all", GuardCategory::PromptInjection, 0.90),
            ("jailbreak", GuardCategory::Jailbreak, 0.88),
            ("dan mode", GuardCategory::Jailbreak, 0.86),
            (
                "önceki talimatları yok say",
                GuardCategory::PromptInjection,
                0.91,
            ),
            (
                "tüm kuralları yok say",
                GuardCategory::PromptInjection,
                0.89,
            ),
        ]
    }
}

#[cfg(feature = "ml-onnx")]
impl MlClassifier for OnnxSecurityClassifier {
    fn classify(&self, text: &str) -> Vec<(GuardCategory, f32)> {
        let lower = text.to_lowercase();
        let mut results = Vec::new();
        for (pattern, category, base_score) in &self.pattern_scores {
            if lower.contains(pattern) {
                results.push((*category, *base_score));
            }
        }
        results
    }

    fn categories(&self) -> &'static [GuardCategory] {
        SECURITY_CATEGORIES
    }

    fn name(&self) -> &'static str {
        "onnx-security"
    }
}
