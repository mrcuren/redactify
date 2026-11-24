//! Cross-locale false-positive tests: TR rules must not fire on EN-only traffic
//! and vice versa. The reverse direction (EN rules on TR traffic) is covered
//! in `en_rules.rs`; this file covers TR rules on EN traffic.

use redactify::{detect, Detector, Entity, EntityType};

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

// ---------------------------------------------------- national-ID packs

/// The opt-in national-ID packs (br, cn, se, fi, no, dk) and the eu VAT pack.
const NATIONAL_ID_LOCALES: &[&str] = &["br", "cn", "se", "fi", "no", "dk", "eu"];

/// Entity types only the national-ID packs produce.
const NATIONAL_ID_TYPES: &[EntityType] = &[
    EntityType::BrCpf,
    EntityType::BrCnpj,
    EntityType::CnResidentId,
    EntityType::SePersonnummer,
    EntityType::FiHetu,
    EntityType::NoFodselsnummer,
    EntityType::DkCpr,
    EntityType::EuVat,
];

fn run(text: &str, locales: &[&str]) -> Vec<Entity> {
    Detector::new().with_locales(locales).detect(text)
}

#[test]
fn national_id_packs_do_not_change_other_locales_digit_shapes() {
    // 11-, 14-, 16- and 18-digit identifiers of OTHER packs next to THEIR
    // cue: enabling every national-ID pack on top must not add, drop or
    // relabel anything (TCKN, PESEL and Steuer-IdNr share the 11-digit
    // CPF / fodselsnummer shape, SIRET the bare 14-digit CNPJ shape, an
    // 18-digit card the resident-ID shape)
    assert!(redactify::valid_fr_siret("73282932000074"));
    assert!(redactify::valid_luhn("622202123456789012"));
    assert!(!redactify::valid_cn_resident_id("622202123456789012"));
    let cases: &[(&str, &[&str])] = &[
        ("TCKN 12345678950", &["tr"]),
        ("PESEL 80010123450", &["pl"]),
        ("Steuer-IdNr 86095742719", &["de"]),
        ("SIRET 73282932000074", &["fr"]),
        ("kart 4111 1111 1111 1111", &["tr"]),
        ("card 622202123456789012 on file", &["en"]),
        ("BSN 111222333", &["nl"]),
        ("NHS 943 476 5919", &["uk"]),
    ];
    for (text, own) in cases {
        let base = run(text, own);
        let mut all = own.to_vec();
        all.extend_from_slice(NATIONAL_ID_LOCALES);
        let with_packs = run(text, &all);
        assert_eq!(
            base, with_packs,
            "national-ID packs changed the result on {text:?}"
        );
        assert!(
            with_packs
                .iter()
                .all(|e| !NATIONAL_ID_TYPES.contains(&e.kind)),
            "{text:?}: {with_packs:?}"
        );
    }
}

#[test]
fn national_ids_are_not_claimed_by_other_packs() {
    // every pack enabled: each national-ID identifier next to its own cue is
    // claimed exactly once, with its own label
    let all: Vec<&str> = [
        "tr", "en", "fr", "es", "nl", "uk", "de", "it", "pl", "ca", "au", "sg", "in", "pt",
    ]
    .iter()
    .chain(NATIONAL_ID_LOCALES)
    .copied()
    .collect();
    let cases = [
        ("CPF 52998224725", EntityType::BrCpf),
        ("CPF 529.982.247-25", EntityType::BrCpf),
        ("CNPJ 12ABC34501DE35", EntityType::BrCnpj),
        ("CNPJ 12.345.678/0001-95", EntityType::BrCnpj),
        ("身份号码 440524188001010014", EntityType::CnResidentId),
        ("personnummer 640823-3234", EntityType::SePersonnummer),
        ("henkilötunnus 131052-308T", EntityType::FiHetu),
        ("fødselsnummer 02013299997", EntityType::NoFodselsnummer),
        ("CPR 070761-4285", EntityType::DkCpr),
        ("VAT DE123456789", EntityType::EuVat),
    ];
    for (text, kind) in cases {
        let ents = run(text, &all);
        assert_eq!(ents.len(), 1, "{text:?}: {ents:?}");
        assert_eq!(ents[0].kind, kind, "{text:?}: {ents:?}");
    }
}

#[test]
fn national_id_types_never_appear_with_the_default_locales() {
    // the national-ID packs are opt-in: default tr+en traffic carrying their
    // identifiers produces none of their types
    for text in [
        "CPF 529.982.247-25",
        "CNPJ 12.ABC.345/01DE-35",
        "id 11010519491231002X",
        "personnummer 640823-3234",
        "hetu 131052-308T",
        "fødselsnummer 02013299997",
        "CPR 070761-4285",
        "VAT ATU12345678",
    ] {
        let ents = detect(text);
        assert!(
            ents.iter().all(|e| !NATIONAL_ID_TYPES.contains(&e.kind)),
            "{text:?}: {ents:?}"
        );
    }
}
