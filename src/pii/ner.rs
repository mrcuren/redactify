//! Span-producing NER layer interface (L1 extension for contextual models).
//!
//! Deterministic rules catch identifiers that carry structure: checksums,
//! strict formats, or label cues. Free-prose person names carry none of these,
//! which is exactly where PII detectors add a contextual model (statistical or
//! transformer named-entity recognition).
//!
//! The interface is deliberately separate from [`crate::guard::ml::MlClassifier`]:
//! a classifier answers "how risky is this text?" with category scores, while a
//! recognizer answers "**where** are the entities?" with byte-offset spans.
//! Both recognizer spans and rule candidates flow through the same overlap
//! resolution, where [`EntityType::Name`] and [`EntityType::Address`] share
//! the **lowest** priority tier (8) - a checksum-validated identifier always
//! beats a model guess, never the other way around (a Name and an Address
//! may overlap each other and both survive; masking covers their union).
//!
//! # Examples
//! ```
//! use redactify::{detect, Detector, MockNameRecognizer, NerRecognizer};
//!
//! // Free prose, no label cue, a name outside the Turkish name lexicon:
//! // deterministic rules find nothing...
//! assert!(detect("Bugün toplantıda Jean Dupont konuştu.").is_empty());
//!
//! // ...but the recognizer layer catches the name.
//! let ner = MockNameRecognizer::new();
//! let rec = [&ner as &dyn NerRecognizer];
//! let ents = Detector::new()
//!     .with_ner(&rec)
//!     .detect("Bugün toplantıda Jean Dupont konuştu.");
//! assert_eq!(ents.len(), 1);
//! assert_eq!(&ents[0].text, "Jean Dupont");
//! ```

use std::sync::LazyLock;

use fancy_regex::Regex;

use crate::pii::entity::{Entity, EntityType};

/// Health of a recognizer across its recent calls.
///
/// NER enrichment is fail-open BY DESIGN (a broken model must not disable
/// detection), but the degradation must be observable: the guard pipeline
/// reads [`NerRecognizer::health`] after scanning and surfaces a
/// `NER_DEGRADED` log signal (blockable via a category override) so a
/// silently-dead enricher can never look like clean text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NerHealth {
    /// Recognizer operating normally.
    Ok,
    /// Recent inference failed; `recognize` returned empty (enrichment
    /// absent). Carries a static reason for the decision rationale.
    Degraded(&'static str),
}

/// A span-producing named-entity recognizer (the L1 model slot).
///
/// Implementations wrap a token-classification model (the ONNX NER recognizer
/// behind the `ml-onnx` feature) or any other span source, and must be
/// deterministic for the same input (same text -> same spans) to keep the
/// pipeline testable.
pub trait NerRecognizer: Send + Sync {
    /// Returns the entities found in `text`.
    ///
    /// Contract:
    /// - offsets are **byte offsets into `text`** on UTF-8 character
    ///   boundaries (same coordinate system as [`crate::detect`]);
    /// - `text` is the whole document (models need full context), not a line;
    /// - out-of-range or mid-character offsets are dropped defensively by the
    ///   engine, but producing them is a bug.
    fn recognize(&self, text: &str) -> Vec<Entity>;

    /// Human-readable name for logging/rationale strings.
    fn name(&self) -> &'static str;

    /// Health after recent calls (default [`NerHealth::Ok`]; static or mock
    /// recognizers never need to override it). Called by the guard pipeline
    /// AFTER `recognize` so silent degradation is visible in decisions.
    fn health(&self) -> NerHealth {
        NerHealth::Ok
    }
}

/// Deterministic mock recognizer: every capitalized 2-4 word run becomes a
/// [`EntityType::Name`] span with score 0.9 - **no cue required**.
///
/// This is NOT a model; it exists to test the merge pipeline (and to
/// demonstrate the free-prose gap the deterministic layer deliberately
/// leaves open). It finds exactly what the cue rules would find if the cue
/// requirement were dropped.
#[derive(Debug, Clone, Copy)]
pub struct MockNameRecognizer;

impl MockNameRecognizer {
    /// Creates the mock recognizer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for MockNameRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

static MOCK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\p{Lu}\p{Ll}+(?:\s+\p{Lu}\p{Ll}+){1,3}\b").expect("embedded pattern compiles")
});

impl NerRecognizer for MockNameRecognizer {
    fn recognize(&self, text: &str) -> Vec<Entity> {
        let mut out = Vec::new();
        for m in MOCK_RE.find_iter(text) {
            let Ok(m) = m else { continue };
            out.push(Entity {
                kind: EntityType::Name,
                start: m.start(),
                end: m.end(),
                text: m.as_str().to_owned(),
                score: 0.9,
            });
        }
        out
    }

    fn name(&self) -> &'static str {
        "mock-ner"
    }
}

/// Drops recognizer spans that would panic downstream slicing: empty,
/// out-of-bounds, or not on UTF-8 character boundaries.
pub(crate) fn sanitize_spans(text: &str, ents: Vec<Entity>) -> Vec<Entity> {
    ents.into_iter()
        .filter(|e| {
            e.start < e.end
                && e.end <= text.len()
                && text.is_char_boundary(e.start)
                && text.is_char_boundary(e.end)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{sanitize_spans, MockNameRecognizer, NerRecognizer};

    #[test]
    fn mock_finds_free_prose_names() {
        let ner = MockNameRecognizer::new();
        let ents = ner.recognize("Bugün toplantıda Ahmet Yılmaz konuştu.");
        assert_eq!(ents.len(), 1);
        assert_eq!(&ents[0].text, "Ahmet Yılmaz");
        assert_eq!(ents[0].score, 0.9);
        assert_eq!(ner.name(), "mock-ner");
    }

    #[test]
    fn mock_skips_single_capitalized_words() {
        let ner = MockNameRecognizer::new();
        // "İstanbul'da" is a single capitalized word: a run needs 2+ words
        assert!(ner.recognize("İstanbul'da yarın buluşacağız.").is_empty());
    }

    #[test]
    fn sanitize_drops_invalid_spans() {
        // 'ü' is 2 bytes: offset 1 sits mid-character
        assert!(sanitize_spans("ğü", vec![]).is_empty());
        let bad = super::Entity {
            kind: super::EntityType::Name,
            start: 1,
            end: 2,
            text: "u".into(),
            score: 0.9,
        };
        assert!(sanitize_spans("ğü", vec![bad]).is_empty());
        let oob = super::Entity {
            kind: super::EntityType::Name,
            start: 0,
            end: 99,
            text: String::new(),
            score: 0.9,
        };
        assert!(sanitize_spans("ğü", vec![oob]).is_empty());
    }
}
