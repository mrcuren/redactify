//! NER model router: lazy-load + LRU + locale/script routing.
//!
//! Routes text to the appropriate NER model based on:
//! - the Unicode script gate (`lang_gate::script_candidates`): the first
//!   candidate language that has a slot wins
//! - fallback: the last slot (the multilingual model)
//!
//! Models are loaded lazily (first use of a slot) and evicted LRU when the
//! resident-set cap is reached. Each model runs on its own dedicated
//! inference worker thread (see `guard::onnx`).
//!
//! Model selection (measured):
//! - savasy (TR): TR F1 0.987, EN 0.909, DE/FR/ES 6/6 → best for TR
//! - XLM-R (multilingual): TR 0.848, EN 0.864, DE/FR/ES 6/6 → covers ar/it/nl/pt/zh too

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// `lock` recovers a poisoned mutex (the router's critical sections leave
// their data consistent)
use crate::guard::onnx::{load_labels_json, lock, MlError, OnnxNerRecognizer};
use crate::pii::NerHealth;
use crate::Entity;
use crate::EntityType;
use crate::NerRecognizer;

/// Configuration for one NER model slot.
#[derive(Debug, Clone)]
pub struct NerSlot {
    /// ISO 639-1 language codes this slot serves (e.g., ["tr"]).
    pub languages: Vec<String>,
    /// Path to the ONNX model file.
    pub model_path: PathBuf,
    /// Path to the tokenizer directory (or tokenizer.json file).
    pub tokenizer_path: PathBuf,
    /// Path to labels.json (id2label order).
    pub labels_path: PathBuf,
    /// Confidence threshold, calibrated per slot ([`default_slots`] uses
    /// 0.43 for Turkish and 0.5 for the multilingual slot).
    pub threshold: f32,
}

/// The default slot configuration for the two-model architecture.
/// savasy for TR (measured F1 0.987), XLM-R for everything else.
#[must_use]
pub fn default_slots() -> Vec<NerSlot> {
    vec![
        NerSlot {
            languages: vec!["tr".to_owned()],
            model_path: PathBuf::from("ml_models/ner_onnx/model.onnx"),
            tokenizer_path: PathBuf::from("ml_models/ner_tokenizer"),
            labels_path: PathBuf::from("ml_models/ner_onnx/labels.json"),
            threshold: 0.43, // measured best-F1
        },
        NerSlot {
            languages: ["en", "de", "fr", "es", "it", "nl", "pt", "ar", "zh"]
                .iter()
                .map(|&s| s.to_owned())
                .collect(),
            model_path: PathBuf::from("ml_models/ner_xlmr/ner_onnx/model.onnx"),
            tokenizer_path: PathBuf::from("ml_models/ner_xlmr/ner_tokenizer"),
            labels_path: PathBuf::from("ml_models/ner_xlmr/ner_onnx/labels.json"),
            // PII-Bench 200-item EN set: item-level capture plateaus at
            // tau<=0.5 (144/261) and decays above (0.7 -> 140, 0.87 -> 134),
            // with NO new canary false positives between 0.5 and 0.87, so
            // 0.5 buys ~10 recall hits for free.
            threshold: 0.5,
        },
    ]
}

/// PIIRanha (ai4privacy taxonomy) label → [`EntityType`].
///
/// On the PII-Bench 200-item set this map scores 90.0%
/// for det+XLM-R+PIIRanha vs 89.7% for a name/address-only map, and adds
/// zero canary false positives beyond the lone high-confidence "LUTFEN"
/// span XLM-R already emits. CREDITCARDNUMBER is deliberately unmapped
/// (the Luhn-checksum rule owns cards); DATEOFBIRTH/PASSWORD/USERNAME and
/// the remaining ID labels have no matching `EntityType`.
fn piiranha_entity_map() -> Vec<(String, EntityType)> {
    [
        ("GIVENNAME", EntityType::Name),
        ("SURNAME", EntityType::Name),
        ("STREET", EntityType::Address),
        ("CITY", EntityType::Address),
        ("BUILDINGNUM", EntityType::Address),
        ("ZIPCODE", EntityType::Address),
        ("EMAIL", EntityType::Email),
        ("TELEPHONENUM", EntityType::Phone),
        ("SOCIALNUM", EntityType::Ssn),
    ]
    .into_iter()
    .map(|(t, k)| (t.to_owned(), k))
    .collect()
}

/// Routes text to the appropriate NER model, lazy-loading on first use
/// and evicting LRU when the cap is reached.
///
/// Cache and failure semantics:
/// - the cache is keyed by SLOT, so one model serving several languages is
///   loaded once (one session, one inference thread);
/// - a model loads outside the cache lock (a per-slot load lock lets only
///   one thread load a given slot; cache hits and other slots never wait
///   for it), and the LRU entry is evicted only AFTER the new load
///   succeeded, so a failed load never costs a working model;
/// - a slot that failed to load is marked dead (negative cache: it is not
///   retried per request) and texts routed to it get no model spans;
/// - [`NerRecognizer::health`] reports `Degraded` when any slot (or the
///   opted-in ensemble member) failed to load, or when any loaded
///   recognizer reports `Degraded` (e.g. an inference timeout).
pub struct NerRouter {
    slots: Vec<NerSlot>,
    /// Loaded recognizers as `(slot index, recognizer)`, least-recently
    /// used first.
    loaded: Mutex<Vec<(usize, Arc<OnnxNerRecognizer>)>>,
    /// Per-slot load serialization (index-aligned with `slots`).
    load_locks: Vec<Mutex<()>>,
    /// Per-slot negative cache: set when the slot failed to load.
    dead: Vec<AtomicBool>,
    /// Model load attempts so far (primary slots and secondary).
    load_attempts: AtomicUsize,
    /// Maximum simultaneously loaded slot models (memory cap).
    max_loaded: usize,
    /// Optional ensemble secondary (e.g. PIIRanha): loaded once, run on
    /// every recognition, unioned into the routed model's spans.
    secondary: Mutex<Option<Arc<OnnxNerRecognizer>>>,
    /// Serializes the one secondary load attempt.
    secondary_load: Mutex<()>,
    secondary_spec: Option<NerSlot>,
    /// Set when the secondary failed to load (don't retry per request).
    secondary_dead: AtomicBool,
}

/// Configuration and counters only; takes no lock, so it never waits on a
/// model load in progress.
impl std::fmt::Debug for NerRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NerRouter")
            .field("slots", &self.slots.len())
            .field("max_loaded", &self.max_loaded)
            .field("load_attempts", &self.load_attempts.load(Ordering::Relaxed))
            .field("secondary", &self.secondary_spec.is_some())
            .finish_non_exhaustive()
    }
}

impl NerRouter {
    /// Creates a router with the given slots and a memory cap.
    #[must_use]
    pub fn new(slots: Vec<NerSlot>, max_loaded: usize) -> Self {
        Self {
            load_locks: slots.iter().map(|_| Mutex::new(())).collect(),
            dead: slots.iter().map(|_| AtomicBool::new(false)).collect(),
            slots,
            loaded: Mutex::new(Vec::new()),
            load_attempts: AtomicUsize::new(0),
            max_loaded: max_loaded.max(1),
            secondary: Mutex::new(None),
            secondary_load: Mutex::new(()),
            secondary_spec: None,
            secondary_dead: AtomicBool::new(false),
        }
    }

    /// Creates a router with the default two-model setup (savasy + XLM-R).
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(default_slots(), 2)
    }

    /// Opts into the PIIRanha ensemble (PII-Bench 200-item set: det+XLM-R
    /// alone 82.4% → +PIIRanha 90.0%, no new canary false positives).
    ///
    /// Requires `ml_models/piiranha_onnx/` (onnx-community ONNX export +
    /// labels.json). If the export is missing the router stays single-model
    /// (NER is an enricher, never a hard dependency) and
    /// [`NerRecognizer::health`] reports the missing member as `Degraded`.
    #[must_use]
    pub fn with_piiranha(mut self) -> Self {
        self.secondary_spec = Some(NerSlot {
            languages: vec!["en".to_owned()], // not routed by language; slot reuse
            model_path: PathBuf::from("ml_models/piiranha_onnx/onnx/model.onnx"),
            tokenizer_path: PathBuf::from("ml_models/piiranha_onnx"),
            labels_path: PathBuf::from("ml_models/piiranha_onnx/labels.json"),
            threshold: 0.5, // measured plateau (0.3-0.5 equal; 0.7 loses 11 items)
        });
        self
    }

    /// Loads one slot's recognizer (slow: model load + warmup inference).
    fn load(&self, spec: &NerSlot) -> Result<OnnxNerRecognizer, MlError> {
        self.load_attempts.fetch_add(1, Ordering::Relaxed);
        let path = |p: &PathBuf| {
            p.to_str()
                .map(str::to_owned)
                .ok_or_else(|| MlError::new(format!("path is not valid UTF-8: {}", p.display())))
        };
        let labels = load_labels_json(&path(&spec.labels_path)?)?;
        Ok(OnnxNerRecognizer::new(
            &path(&spec.model_path)?,
            &path(&spec.tokenizer_path)?,
            labels,
        )?
        .with_threshold(spec.threshold))
    }

    fn secondary_recognizer(&self) -> Option<Arc<OnnxNerRecognizer>> {
        let spec = self.secondary_spec.as_ref()?;
        if let Some(r) = lock(&self.secondary).as_ref() {
            return Some(Arc::clone(r));
        }
        if self.secondary_dead.load(Ordering::Acquire) {
            return None;
        }
        // one load attempt (outside the value lock); on failure mark dead so
        // requests stop paying for it
        let _loading = lock(&self.secondary_load);
        if let Some(r) = lock(&self.secondary).as_ref() {
            return Some(Arc::clone(r));
        }
        if self.secondary_dead.load(Ordering::Acquire) {
            return None;
        }
        match self.load(spec) {
            Ok(r) => {
                let arc = Arc::new(r.with_entity_map(piiranha_entity_map()));
                *lock(&self.secondary) = Some(Arc::clone(&arc));
                Some(arc)
            }
            Err(_) => {
                self.secondary_dead.store(true, Ordering::Release);
                None
            }
        }
    }

    /// Routes text to a slot by script and returns entities from that
    /// slot's model (plus the opted-in ensemble member's).
    fn route_and_recognize(&self, text: &str) -> Vec<Entity> {
        // an empty slot list would underflow `self.slots.len() - 1` below
        // (debug panic / release out-of-bounds index): nothing to route
        if self.slots.is_empty() {
            return Vec::new();
        }
        // script gate -> first candidate language that has a slot; no
        // candidate -> the last slot (multilingual fallback)
        let slot_idx = crate::pii::lang_gate::script_candidates(text)
            .iter()
            .find_map(|c| {
                self.slots
                    .iter()
                    .position(|s| s.languages.iter().any(|l| l == c))
            })
            .unwrap_or(self.slots.len() - 1);

        let mut out = match self.get_or_load(slot_idx) {
            Some(r) => r.recognize(text),
            None => Vec::new(), // model unavailable -> empty (fail-open, NER is an enricher)
        };
        // ensemble secondary (opt-in, e.g. PIIRanha): union its spans in;
        // the detection engine's overlap resolution dedups on the caller side
        if let Some(sec) = self.secondary_recognizer() {
            if out.is_empty() {
                out = sec.recognize(text);
            } else {
                out.extend(sec.recognize(text));
            }
        }
        out
    }

    /// Cache hit: refreshes the slot's LRU position.
    fn cached(&self, slot_idx: usize) -> Option<Arc<OnnxNerRecognizer>> {
        let mut loaded = lock(&self.loaded);
        let pos = loaded.iter().position(|(i, _)| *i == slot_idx)?;
        let entry = loaded.remove(pos);
        let r = Arc::clone(&entry.1);
        loaded.push(entry);
        Some(r)
    }

    fn get_or_load(&self, slot_idx: usize) -> Option<Arc<OnnxNerRecognizer>> {
        if let Some(r) = self.cached(slot_idx) {
            return Some(r);
        }
        if self.dead[slot_idx].load(Ordering::Acquire) {
            return None;
        }
        // one loader per slot; re-check after waiting (another thread may
        // have loaded the slot, or failed to, in the meantime)
        let _loading = lock(&self.load_locks[slot_idx]);
        if let Some(r) = self.cached(slot_idx) {
            return Some(r);
        }
        if self.dead[slot_idx].load(Ordering::Acquire) {
            return None;
        }
        match self.load(&self.slots[slot_idx]) {
            Ok(r) => {
                let arc = Arc::new(r);
                let mut loaded = lock(&self.loaded);
                loaded.push((slot_idx, Arc::clone(&arc)));
                // evict only now that the new model is in; never the new one
                while loaded.len() > self.max_loaded {
                    loaded.remove(0);
                }
                Some(arc)
            }
            Err(_) => {
                self.dead[slot_idx].store(true, Ordering::Release);
                None
            }
        }
    }

    /// Number of currently loaded models.
    #[must_use]
    pub fn loaded_count(&self) -> usize {
        lock(&self.loaded).len()
    }
}

impl NerRecognizer for NerRouter {
    fn recognize(&self, text: &str) -> Vec<Entity> {
        self.route_and_recognize(text)
    }

    fn name(&self) -> &'static str {
        "ner-router"
    }

    /// `Degraded` when a routed slot failed to load (texts routed to it get
    /// no model spans), when the opted-in ensemble member failed to load
    /// (single-model fallback), or when a loaded recognizer is degraded
    /// (its inference lane timed out, see
    /// `guard::onnx::RECOVERY_COOLDOWN`, feature `ml-onnx`);
    /// `Ok` otherwise.
    fn health(&self) -> NerHealth {
        if self.dead.iter().any(|d| d.load(Ordering::Acquire)) {
            return NerHealth::Degraded(
                "ner model slot failed to load: texts routed to it get no model spans",
            );
        }
        // an opted-in ensemble member that failed to load leaves the router
        // silently running single-model: that degradation must be visible
        if self.secondary_dead.load(Ordering::Acquire) {
            return NerHealth::Degraded(
                "piiranha ensemble member unavailable: single-model fallback",
            );
        }
        // snapshot the Arcs so no recognizer runs health() under our locks
        let mut live: Vec<Arc<OnnxNerRecognizer>> = lock(&self.loaded)
            .iter()
            .map(|(_, r)| Arc::clone(r))
            .collect();
        if let Some(sec) = lock(&self.secondary).as_ref() {
            live.push(Arc::clone(sec));
        }
        live.iter()
            .map(|r| r.health())
            .find(|h| *h != NerHealth::Ok)
            .unwrap_or(NerHealth::Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::{NerRouter, NerSlot};
    use crate::{NerHealth, NerRecognizer};
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;

    /// A slot whose files do not exist: every load attempt fails.
    fn missing_slot(languages: &[&str]) -> NerSlot {
        NerSlot {
            languages: languages.iter().map(|&l| l.to_owned()).collect(),
            model_path: PathBuf::from("definitely/missing/model.onnx"),
            tokenizer_path: PathBuf::from("definitely/missing/tokenizer"),
            labels_path: PathBuf::from("definitely/missing/labels.json"),
            threshold: 0.5,
        }
    }

    /// Whether every file of `slot` exists (real-model tests skip otherwise).
    fn slot_available(slot: &NerSlot) -> bool {
        slot.model_path.is_file()
            && slot.labels_path.is_file()
            && (slot.tokenizer_path.join("tokenizer.json").is_file()
                || slot.tokenizer_path.is_file())
    }

    #[test]
    fn failed_slot_load_is_negative_cached_and_reported() {
        let r = NerRouter::new(vec![missing_slot(&["tr"]), missing_slot(&["en"])], 2);
        assert_eq!(r.health(), NerHealth::Ok, "nothing attempted yet");
        // plain Latin text routes to the "en" slot (index 1)
        assert!(r.recognize("Jane Doe called yesterday").is_empty());
        assert_eq!(r.load_attempts.load(Ordering::Relaxed), 1);
        assert!(r.dead[1].load(Ordering::Acquire));
        assert!(
            !r.dead[0].load(Ordering::Acquire),
            "slot 0 was never routed to"
        );
        // negative cache: the dead slot is NOT retried per request
        assert!(r.recognize("John Smith called today").is_empty());
        assert_eq!(r.load_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(r.loaded_count(), 0);
        // the primary failure is visible, not silent
        assert!(
            matches!(r.health(), NerHealth::Degraded(m) if m.contains("slot failed to load")),
            "{:?}",
            r.health()
        );
    }

    #[test]
    fn languages_of_one_slot_share_one_loaded_model() {
        let multilingual = super::default_slots().remove(1);
        if !slot_available(&multilingual) {
            eprintln!("SKIP: multilingual NER export not present");
            return;
        }
        let r = NerRouter::new(vec![missing_slot(&["tr"]), multilingual], 2);
        // "en" and "zh" both route to slot 1: the cache is keyed by slot, so
        // the model is loaded ONCE, not once per language
        let _ = r.recognize("Jane Doe lives in Springfield.");
        let _ = r.recognize("张伟住在北京。");
        assert_eq!(r.loaded_count(), 1);
        assert_eq!(r.load_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(r.health(), NerHealth::Ok);
    }

    #[test]
    fn failed_load_never_evicts_a_working_model() {
        let turkish = super::default_slots().remove(0);
        if !slot_available(&turkish) {
            eprintln!("SKIP: Turkish NER export not present");
            return;
        }
        // cap 1: the working model must not be evicted BEFORE the failing
        // load is attempted
        let r = NerRouter::new(vec![turkish, missing_slot(&["en"])], 1);
        // Turkish test sentence (escaped; the letters route it to the "tr" slot)
        let tr = "Bug\u{fc}n toplant\u{131}da Ahmet Y\u{131}lmaz konu\u{15f}tu.";
        assert!(
            !r.recognize(tr).is_empty(),
            "Turkish slot must find the name"
        );
        assert_eq!(r.loaded_count(), 1);
        assert!(r.recognize("Jane Doe called yesterday").is_empty());
        assert_eq!(
            r.loaded_count(),
            1,
            "the failed load evicted the working model"
        );
        assert!(!r.recognize(tr).is_empty());
        assert_eq!(
            r.load_attempts.load(Ordering::Relaxed),
            2,
            "no reload of slot 0"
        );
        assert!(matches!(r.health(), NerHealth::Degraded(_)));
    }

    #[test]
    fn empty_slot_list_never_panics() {
        // routing with zero slots must not underflow `slots.len() - 1`;
        // an empty router simply produces no entities
        let r = NerRouter::new(Vec::new(), 2);
        assert!(r.recognize("Ahmet Yilmaz called").is_empty());
        assert_eq!(r.health(), NerHealth::Ok);
    }

    #[test]
    fn router_creates_with_defaults() {
        let r = NerRouter::with_defaults();
        assert_eq!(r.loaded_count(), 0); // lazy: nothing loaded yet
                                         // no secondary by default: the ensemble is opt-in
        assert!(r.secondary_recognizer().is_none());
        assert!(r.secondary_recognizer().is_none()); // stays none without dead-flag flapping
    }

    #[test]
    fn default_slots_have_two_models() {
        let slots = super::default_slots();
        assert_eq!(slots.len(), 2);
        assert!(slots[0].languages.contains(&"tr".to_owned()));
        assert!(slots[1].languages.contains(&"en".to_owned()));
        assert!(slots[1].languages.contains(&"zh".to_owned()));
        assert_eq!(slots[1].threshold, 0.5); // measured plateau (PII-Bench)
    }

    #[test]
    fn piiranha_builder_is_opt_in_and_missing_export_degrades() {
        let r = NerRouter::with_defaults().with_piiranha();
        // spec set; load attempted lazily. In a checkout without the export
        // this must simply return none (fail-open) and stay dead after.
        let first = r.secondary_recognizer();
        let second = r.secondary_recognizer();
        assert_eq!(first.is_some(), second.is_some());
        if first.is_none() {
            assert!(r.secondary_dead.load(std::sync::atomic::Ordering::Relaxed));
        }
    }

    /// Real-model integration: only runs where the PIIRanha export exists.
    #[test]
    fn piiranha_ensemble_recognizes_names() {
        const MODEL: &str = "ml_models/piiranha_onnx/onnx/model.onnx";
        if !std::path::Path::new(MODEL).is_file() {
            eprintln!("SKIP: {MODEL} not present (ensemble runs where the export exists)");
            return;
        }
        let router = NerRouter::with_defaults().with_piiranha();
        let ents = crate::pii::run(
            "Jane Doe lives at 42 Oak Street in Springfield.",
            &crate::pii::EngineOpts {
                ner: &[&router as &dyn crate::pii::NerRecognizer],
                ..crate::pii::EngineOpts::default()
            },
        )
        .entities;
        assert!(
            ents.iter().any(|e| e.kind == crate::EntityType::Name),
            "{ents:?}"
        );
    }
}
