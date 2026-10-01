//! English (US) rule integration tests: detection behavior, cue policies and
//! false-positive guards against TR traffic.

use redactify::{detect, redact, EntityType};

fn kinds(text: &str) -> Vec<(EntityType, String)> {
    detect(text).into_iter().map(|e| (e.kind, e.text)).collect()
}

#[test]
fn ssn_detected_with_separator_forms() {
    for s in ["SSN 536-90-6292", "my SSN: 536.90.6292", "ssn 536 90 6292"] {
        let found = kinds(s);
        assert!(
            found
                .iter()
                .any(|(k, t)| *k == EntityType::Ssn && t.contains("6292")),
            "missed in {s}: {found:?}"
        );
    }
}

#[test]
fn ssn_score_boosts_with_cue() {
    let ents = detect("social security number 536-90-6292");
    let s = ents.iter().find(|e| e.kind == EntityType::Ssn).unwrap();
    assert_eq!(s.score, 0.95);

    let ents = detect("ref 536-90-6292 end");
    let s = ents.iter().find(|e| e.kind == EntityType::Ssn).unwrap();
    assert_eq!(s.score, 0.75);
}

#[test]
fn ssn_structural_rules_reject_invalids() {
    for bad in [
        "000-45-6789",
        "666-45-6789",
        "123-00-6789",
        "123-45-0000",
        "111-11-1111",
        "123456789",
    ] {
        assert!(
            !kinds(&format!("SSN {bad}"))
                .iter()
                .any(|(k, _)| *k == EntityType::Ssn),
            "false positive: {bad}"
        );
    }
}

#[test]
fn itin_wins_over_ssn_when_shape_fits_both() {
    // 912-70-1234 fits both the SSN shape and the stricter ITIN shape;
    // the narrower rule (ITIN) must win in the single-decision model.
    let found = kinds("tax id 912-70-1234");
    assert!(
        found.iter().any(|(k, _)| *k == EntityType::Itin),
        "{found:?}"
    );
    assert!(!found.iter().any(|(k, _)| *k == EntityType::Ssn));
}

#[test]
fn us_passport_requires_cue() {
    assert!(detect("US passport: A12345678")
        .iter()
        .any(|e| e.kind == EntityType::UsPassport && e.score == 0.9));
    assert!(!detect("code A12345678 x")
        .iter()
        .any(|e| e.kind == EntityType::UsPassport));
}

#[test]
fn en_rules_do_not_fire_on_tr_traffic() {
    // Turkish corpus-style lines must not trigger EN rules.
    for t in [
        "TCKN 12345678950",
        "vergi no 2120000004",
        "IBAN TR33 0006 1005 1978 6457 8413 26",
        "Pasaport U12345678",
        "Plaka 34 ABC 123",
        "Cep 0532 123 45 67",
    ] {
        let found = kinds(t);
        assert!(
            found.iter().all(|(k, _)| {
                !matches!(
                    k,
                    EntityType::Ssn | EntityType::Itin | EntityType::UsPassport
                )
            }),
            "EN false positive on TR text {t}: {found:?}"
        );
    }
}

#[test]
fn mixed_locale_line() {
    let out = redact("SSN 536-90-6292 ve TCKN 12345678950");
    assert!(out.contains("[SSN]"));
    assert!(out.contains("[TCKN]"));
}
