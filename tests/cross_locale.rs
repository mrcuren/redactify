//! Cross-locale false-positive tests: TR rules must not fire on EN-only traffic
//! and vice versa. The reverse direction (EN rules on TR traffic) is covered
//! in `en_rules.rs`; this file covers TR rules on EN traffic.

use redactify::{detect, EntityType};

/// TR-only entity types that must not appear on pure EN text.
const TR_ONLY: &[EntityType] = &[
    EntityType::Tckn,
    EntityType::Vkn,
    EntityType::Plaka,
    EntityType::Passport,
];

/// EN-only entity types that must not appear on pure TR text.
const EN_ONLY: &[EntityType] = &[EntityType::Ssn, EntityType::Itin, EntityType::UsPassport];

#[test]
fn tr_rules_do_not_fire_on_en_traffic() {
    // Structurally valid EN identifiers and typical EN text patterns
    let en_texts = [
        "SSN 536-90-6292",
        "my social security number is 536-90-6292",
        "ITIN 912-70-1234 for taxpayer",
        "US passport A12345678",
        "call me at 555-123-4567",
        "order 12345678 shipped",
        "ref 987654321",
        "account 1234567890123456",
        "meeting at 3:30 PM on 01/15/2026",
        "zip code 90210, phone (310) 555-0199",
        "employee ID 87654321, badge 00123",
    ];

    for text in en_texts {
        let found = detect(text);
        for e in &found {
            assert!(
                !TR_ONLY.contains(&e.kind),
                "TR false positive on EN text {:?}: found {:?} ({:?})",
                text,
                e.kind,
                e.text
            );
        }
    }
}

#[test]
fn en_rules_do_not_fire_on_tr_traffic() {
    let tr_texts = [
        "TCKN 12345678950",
        "vergi no 2120000004",
        "IBAN TR33 0006 1005 1978 6457 8413 26",
        "Pasaport U12345678",
        "Plaka 34 ABC 123",
        "Cep 0532 123 45 67",
        "kart 4111 1111 1111 1111",
        "mail a@b.com",
        "Firmanın vergi numarası 3949583520.",
        "Sipariş numaranız 12000345671 olarak kaydedildi.",
        "ofis 0212 555 44 33",
    ];

    for text in tr_texts {
        let found = detect(text);
        for e in &found {
            assert!(
                !EN_ONLY.contains(&e.kind),
                "EN false positive on TR text {:?}: found {:?} ({:?})",
                text,
                e.kind,
                e.text
            );
        }
    }
}

#[test]
fn mixed_locale_both_detected() {
    let text = "SSN 536-90-6292 ve TCKN 12345678950";
    let found = detect(text);
    let kinds: Vec<_> = found.iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&EntityType::Ssn), "SSN missing: {found:?}");
    assert!(kinds.contains(&EntityType::Tckn), "TCKN missing: {found:?}");
}

#[test]
fn shared_types_work_in_both() {
    // EMAIL and CREDIT_CARD are locale-independent
    assert!(detect("mail test@example.com")
        .iter()
        .any(|e| e.kind == EntityType::Email));
    assert!(detect("kart 4111 1111 1111 1111")
        .iter()
        .any(|e| e.kind == EntityType::CreditCard));
}
