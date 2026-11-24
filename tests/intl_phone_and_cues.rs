//! Compact E.164 phone numbers, the card / phone boundary after `+`,
//! camelCase label cues and Unicode space separators.
//!
//! The inputs are shapes that a narrower rule set misses (no entity, or
//! the wrong one); the negatives pin the false positives each rule could
//! open.

use redactify::{Detector, EntityType, JsonRedactor};
use serde_json::json;

fn found(text: &str, locales: &[&str]) -> Vec<(EntityType, String)> {
    Detector::new()
        .with_locales(locales)
        .detect(text)
        .into_iter()
        .map(|e| (e.kind, e.text))
        .collect()
}

// ------------------------------------------------ compact E.164 phones

#[test]
fn compact_international_phones_are_claimed_whole() {
    for phone in [
        "+447700900123",  // UK mobile (Ofcom drama range)
        "+33612345678",   // France
        "+919848012345",  // India
        "+2348035557890", // Nigeria
        "+12125551234",   // NANP, compact (the NANP rule needs separators)
        "+4915112345678", // Germany: also a Luhn-valid 13-digit run
        "+97144379827",   // UAE
        "+44 7700900123", // `+CC NATIONAL`
        "+91 9848012345", // `+CC NATIONAL`
        "+1 2125551234",  // `+CC NATIONAL`, NANP
    ] {
        let text = format!("call {phone} today");
        assert_eq!(
            found(&text, &["en"]),
            vec![(EntityType::Phone, phone.to_owned())],
            "{text}"
        );
    }
}

#[test]
fn a_compact_phone_is_not_relabelled_as_a_card() {
    // before: CREDIT_CARD "4915112345678" with the `+` left in clear
    let masked = Detector::new().redact("call +4915112345678 today");
    assert!(!masked.contains('+'), "{masked}");
    assert!(!masked.contains("4915112345678"), "{masked}");
}

#[test]
fn compact_runs_without_an_assigned_country_code_stay_unclaimed() {
    for text in [
        "ref +2891234567",       // 2, 28, 289: no such E.164 code
        "ref +11234567890",      // NANP area code cannot start with 1
        "ref +12120551234",      // NANP exchange cannot start with 0
        "ref +4477009",          // too short for E.164
        "ref +4477009001234567", // 16 digits: too long
        "ref +28 7700900123",    // explicit code 28 is not assigned
        "ref +1 1235551234",     // NANP area code cannot start with 1
        "ref +044 7700900123",   // no country code starts with 0
    ] {
        assert!(
            !found(text, &["en"])
                .iter()
                .any(|(k, _)| *k == EntityType::Phone),
            "{text}: {:?}",
            found(text, &["en"])
        );
    }
}

#[test]
fn signed_decimals_are_not_phones() {
    for text in [
        "sqrt2 = +1.4142135623",
        "delta: +1.2345678901",
        "loss +20.123456789",
        "lat +51.50735090",
        "+41.00823660,+28.97835890",
        "offset +7.1234567890e-05",
    ] {
        assert!(
            !found(text, &["en"])
                .iter()
                .any(|(k, _)| *k == EntityType::Phone),
            "{text}: {:?}",
            found(text, &["en"])
        );
    }
}

#[test]
fn a_cc_national_phone_that_passes_luhn_keeps_the_phone_label() {
    // `8613812345678` passes Luhn; the card rule must not outrank the phone
    assert_eq!(
        found("call +86 13812345678", &["en"]),
        vec![(EntityType::Phone, "+86 13812345678".to_owned())]
    );
}

#[test]
fn a_plus_after_a_digit_does_not_start_a_phone() {
    // semver build metadata, arithmetic
    for text in ["build 1.2.3+4477009001234", "total 12+447700900123"] {
        assert!(
            !found(text, &["en"])
                .iter()
                .any(|(k, _)| *k == EntityType::Phone),
            "{text}: {:?}",
            found(text, &["en"])
        );
    }
}

#[test]
fn turkish_compact_phones_keep_their_own_rule() {
    // +90 stays the TR rule's job (the generic rule rejects code 90)
    assert_eq!(
        found("ara +905321234567", &["tr"]),
        vec![(EntityType::Phone, "+905321234567".to_owned())]
    );
}

// ------------------------------------------------- cards after a `+`

#[test]
fn a_card_after_a_plus_is_still_masked_whole() {
    // URL-encoded form body: spaces became `+`
    assert_eq!(
        found("body=my+card+is+4111111111111111", &["en"]),
        vec![(EntityType::CreditCard, "+4111111111111111".to_owned())]
    );
    // grouped digits after `+` are no compact phone
    assert_eq!(
        found("card +4111 1111 1111 1111", &["en"]),
        vec![(EntityType::CreditCard, "+4111 1111 1111 1111".to_owned())]
    );
    // 13-digit Visa test number after `+`: 4 / 42 / 422 is no country code
    assert_eq!(
        found("visa+4222222222222", &["en"]),
        vec![(EntityType::CreditCard, "+4222222222222".to_owned())]
    );
    // a 13-15 digit card whose head IS a country code (378 = San Marino)
    // reads as a compact phone: still masked whole, `+` included, under
    // the PHONE label
    assert_eq!(
        found("amex+378282246310005", &["en"]),
        vec![(EntityType::Phone, "+378282246310005".to_owned())]
    );
    // and the bare card is unchanged
    assert_eq!(
        found("card 4111111111111111", &["en"]),
        vec![(EntityType::CreditCard, "4111111111111111".to_owned())]
    );
}

// ---------------------------------------------------- camelCase cues

#[test]
fn camel_case_labels_unlock_identifier_values() {
    let cases: &[(&str, &[&str], EntityType, &str)] = &[
        (
            "customerSsn: 536906292",
            &["en"],
            EntityType::Ssn,
            "536906292",
        ),
        (
            "employerEin: 10-1234567",
            &["en"],
            EntityType::UsEin,
            "10-1234567",
        ),
        (
            "applicantDni: 12345678Z",
            &["es"],
            EntityType::Dni,
            "12345678Z",
        ),
        (
            "holderPan: AFZPK7190K",
            &["in"],
            EntityType::InPan,
            "AFZPK7190K",
        ),
    ];
    for (text, locales, kind, value) in cases {
        assert_eq!(
            found(text, locales),
            vec![(*kind, (*value).to_owned())],
            "{text}"
        );
    }
}

#[test]
fn camel_case_keys_unlock_values_in_json_documents() {
    let mut doc = json!({"customerSsn": "536906292", "employerEin": "10-1234567"});
    let report = JsonRedactor::new().redact(&mut doc);
    assert!(report.is_complete());
    let text = doc.to_string();
    assert!(!text.contains("536906292"), "{text}");
    assert!(!text.contains("10-1234567"), "{text}");
}

#[test]
fn camel_case_does_not_reopen_the_word_start_traps() {
    let cases: &[(&str, &[&str], EntityType)] = &[
        // the cue starts on a lowercase letter inside the word
        ("className 536906292", &["en"], EntityType::Ssn),
        ("Wisconsin: 123-456-782", &["ca"], EntityType::CaSin),
        ("syntax 5726881770", &["tr"], EntityType::Vkn),
        // the cue must end its camelCase segment, not prefix a longer word
        ("sendTelemetry(5321234567)", &["tr"], EntityType::Phone),
        ("getTaxonomyNode(5726881770)", &["tr"], EntityType::Vkn),
        // names keep the strict word start: no NAME through `name:`
        ("fileName: Annual Report", &["en"], EntityType::Name),
        ("displayName: Data Team", &["en"], EntityType::Name),
        ("userName: John Smith", &["en"], EntityType::Name),
    ];
    for (text, locales, kind) in cases {
        let got = found(text, locales);
        assert!(!got.iter().any(|(k, _)| k == kind), "{text}: {got:?}");
    }
}

// ------------------------------------------- Unicode space separators

#[test]
fn no_break_and_thin_spaces_separate_iban_and_card_groups() {
    // U+00A0 no-break, U+2007 figure, U+2009 thin, U+202F narrow no-break,
    // U+3000 ideographic space: word processors and PDF copies insert them
    for sep in ['\u{a0}', '\u{2007}', '\u{2009}', '\u{202f}', '\u{3000}'] {
        let iban: String = ["DE89", "3704", "0044", "0532", "0130", "00"].join(&sep.to_string());
        let card: String = ["4111", "1111", "1111", "1111"].join(&sep.to_string());
        let text = format!("IBAN {iban} kart {card}");
        assert_eq!(
            found(&text, &["en"]),
            vec![
                (EntityType::Iban, iban.clone()),
                (EntityType::CreditCard, card.clone())
            ],
            "U+{:04X}",
            sep as u32
        );
    }
}
