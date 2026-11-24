//! `Detector::explain`: every entity comes with the rule / custom rule /
//! recognizer that produced it, its validator and cue gates, its base and
//! final score and the view it was found on - and explaining never changes
//! WHAT is detected.

use redactify::{
    CustomRule, DetectionSource, DetectionView, Detector, EntityType, MockNameRecognizer,
    NerRecognizer,
};

/// Representative inputs over the default and opt-in locale packs,
/// multi-line text and encoding evasions (escaped: U+0131 dotless i,
/// U+015F s-cedilla, fullwidth digits U+FF10-U+FF19, U+200B zero-width
/// space).
const TEXTS: &[&str] = &[
    "",
    "TCKN'm 12345678950, IBAN TR33 0006 1005 1978 6457 8413 26, mail a@b.com",
    "Plakas\u{131} 34 ABC 123 olan arac, yolda 34 ABC 123 gordum",
    "Beni 0532 123 45 67'den ara. vergi no 1234567890",
    "SSN 536-90-6292 ve TCKN 12345678950\nnhs 9434765870\r\npesel 80010123450",
    "kart 4111 1111 1111 1111, server 59.140.33.161, https://example.org/x",
    "IdNr 86095742719 in der Akte",
    "kimlik \u{FF11}\u{FF12}\u{FF13}\u{FF14}\u{FF15}\u{FF16}\u{FF17}\u{FF18}\u{FF19}\u{FF15}\u{FF10}",
    "TCKN 1\u{200B}2345678950 ve 0532 123 45 67",
];

const LOCALE_SETS: &[&[&str]] = &[&[], &["tr"], &["en"], &["uk", "pl", "de"]];

#[test]
fn explain_returns_exactly_the_detect_result() {
    let ner = MockNameRecognizer::new();
    let rec = [&ner as &dyn NerRecognizer];
    for locales in LOCALE_SETS {
        for normalize in [false, true] {
            for with_ner in [false, true] {
                let mut d = Detector::new()
                    .with_locales(locales)
                    .with_normalization(normalize);
                if with_ner {
                    d = d.with_ner(&rec);
                }
                for text in TEXTS {
                    let explained = d.explain(text);
                    let entities: Vec<_> = explained.iter().map(|(e, _)| e.clone()).collect();
                    assert_eq!(entities, d.detect(text), "{text:?} {locales:?}");
                    for (e, why) in &explained {
                        assert_eq!(e.score, why.score, "{e:?} {why:?}");
                        assert!(why.score >= why.base_score, "{why:?}");
                        if !normalize {
                            assert_eq!(why.view, DetectionView::Raw, "{why:?}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn rule_ids_are_module_paths_below_the_registry() {
    let d = Detector::new().with_locales(&["tr", "en", "uk", "pl", "de"]);
    let mut ids = Vec::new();
    for text in TEXTS {
        for (_, why) in d.explain(text) {
            if let DetectionSource::Rule { id } = why.source {
                ids.push(id);
            }
        }
    }
    for expected in [
        "tr::tckn",
        "iban",
        "generic::email",
        "tr::plaka",
        "tr::phone",
        "tr::vkn",
        "en::ssn",
        "uk::nhs",
        "pl::pesel",
        "generic::card",
        "generic::ip",
        "generic::url",
        "de::tax_id",
    ] {
        assert!(ids.contains(&expected), "{expected} missing from {ids:?}");
    }
    for id in &ids {
        assert!(!id.contains("redactify"), "{id}");
        assert!(!id.contains("pii::locales"), "{id}");
    }
}

#[test]
fn validator_and_cue_gates_are_reported() {
    let d = Detector::new();
    // checksum-validated, cue-less
    let (_, why) = &d.explain("TCKN 12345678950")[0];
    assert!(why.validator_passed);
    assert_eq!(why.cue, None);
    assert_eq!(why.base_score, 1.0);
    // structural plate: a cue raises the score, its absence keeps the base
    let cued = d.explain("Plaka 34 ABC 123");
    assert_eq!(cued[0].1.cue.as_deref(), Some("plaka"));
    assert!(cued[0].1.score > cued[0].1.base_score);
    let bare = d.explain("yolda 34 ABC 123 var");
    assert_eq!(bare[0].1.cue, None);
    assert_eq!(bare[0].1.score, bare[0].1.base_score);
    // the cue is the CONFIGURED literal, never the input spelling
    let upper = d.explain("VERG\u{130} NO 1234567890");
    assert_eq!(upper[0].0.kind, EntityType::Vkn);
    assert_eq!(upper[0].1.cue.as_deref(), Some("vergi"));
}

#[test]
fn custom_rules_and_recognizers_are_named() {
    let ner = MockNameRecognizer::new();
    let rec = [&ner as &dyn NerRecognizer];
    let first = CustomRule::new(EntityType::Itin, r"ORC-\d{4}").unwrap();
    let second = CustomRule::new(EntityType::Itin, r"ZX-\d{4}")
        .unwrap()
        .with_validator(|v| v.ends_with('7'));
    let rules = [&first, &second];
    let d = Detector::new().with_ner(&rec).with_custom_rules(&rules);
    // a name outside the Turkish lexicon, so the recognizer reports it
    let explained = d.explain("Jean Dupont ORC-1234 ZX-1237");
    let sources: Vec<DetectionSource> = explained.iter().map(|(_, w)| w.source).collect();
    assert_eq!(
        sources,
        vec![
            DetectionSource::Ner { name: "mock-ner" },
            DetectionSource::Custom { index: 0 },
            DetectionSource::Custom { index: 1 },
        ]
    );
    let validated: Vec<bool> = explained.iter().map(|(_, w)| w.validator_passed).collect();
    assert_eq!(validated, vec![false, false, true]);
}

#[test]
fn normalized_view_findings_are_marked() {
    let d = Detector::new().with_normalization(true);
    let text = "TCKN 1\u{200B}2345678950 ve 0532 123 45 67";
    let explained = d.explain(text);
    let views: Vec<(EntityType, DetectionView)> =
        explained.iter().map(|(e, w)| (e.kind, w.view)).collect();
    assert_eq!(
        views,
        vec![
            (EntityType::Tckn, DetectionView::Normalized),
            (EntityType::Phone, DetectionView::Raw),
        ]
    );
    // the span is the RAW one (zero-width space included)
    assert_eq!(explained[0].0.text, "1\u{200B}2345678950");
    assert_eq!(DetectionView::Raw.to_string(), "RAW");
}

#[cfg(feature = "serde")]
#[test]
fn explanation_serializes_with_tagged_source_and_no_input_text() {
    let explained = Detector::new().explain("vergi no 1234567890");
    let json = serde_json::to_value(&explained[0].1).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "source": {"kind": "RULE", "id": "tr::vkn"},
            "validator_passed": true,
            "cue": "vergi",
            "base_score": 1.0,
            "score": 1.0,
            "view": "RAW"
        })
    );
    assert!(!json.to_string().contains("1234567890"));
}
