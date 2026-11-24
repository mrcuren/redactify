//! Turkish identifier shapes and decimal fractions: hyphen-grouped IBANs,
//! the dotted `V.K.N.` label, plate look-alikes in product specifications
//! and float fractions that pass Luhn.
//!
//! Each positive input is a shape a narrower rule set misses, and each
//! negative input one it wrongly claims.

use redactify::{Detector, EntityType};

fn found(text: &str, locales: &[&str]) -> Vec<(EntityType, String)> {
    Detector::new()
        .with_locales(locales)
        .detect(text)
        .into_iter()
        .map(|e| (e.kind, e.text))
        .collect()
}

fn has(text: &str, locales: &[&str], kind: EntityType) -> bool {
    found(text, locales).iter().any(|(k, _)| *k == kind)
}

// ------------------------------------------------------------- IBAN

#[test]
fn hyphen_grouped_ibans_are_claimed() {
    assert_eq!(
        found("IBAN TR33-0006-1005-1978-6457-8413-26", &["tr"]),
        vec![(
            EntityType::Iban,
            "TR33-0006-1005-1978-6457-8413-26".to_owned()
        )]
    );
    // the checksum still decides
    assert!(!has(
        "IBAN TR33-0006-1005-1978-6457-8413-27",
        &["tr"],
        EntityType::Iban
    ));
}

#[test]
fn an_iban_before_a_hyphenated_tail_is_still_claimed() {
    // the variable-length international rule takes no hyphen: a greedy
    // candidate would swallow the tail, fail the length check and leave
    // the IBAN in clear
    for (text, iban) in [
        (
            "statement_DE89370400440532013000-2024.pdf",
            "DE89370400440532013000",
        ),
        ("IBAN DE89370400440532013000-EUR", "DE89370400440532013000"),
        (
            "IBAN: GB82WEST12345698765432-A1B2",
            "GB82WEST12345698765432",
        ),
        ("NL91ABNA0417164300-2024", "NL91ABNA0417164300"),
    ] {
        assert_eq!(
            found(text, &["en"]),
            vec![(EntityType::Iban, iban.to_owned())],
            "{text}"
        );
    }
}

// -------------------------------------------------------------- VKN

#[test]
fn the_dotted_vkn_label_is_a_cue() {
    for text in [
        "V.K.N.: 1234567890",
        "V.K.N 1234567890",
        "v.k.n. 1234567890",
    ] {
        assert_eq!(
            found(text, &["tr"]),
            vec![(EntityType::Vkn, "1234567890".to_owned())],
            "{text}"
        );
    }
    // still a cue-gated rule: no label, no VKN
    assert!(!has("sipariş 1234567890", &["tr"], EntityType::Vkn));
}

// ------------------------------------------------------------ plate

#[test]
fn specification_lists_are_not_plates() {
    for text in [
        "Laptop 16 GB 512 GB SSD",
        "Telefon 12 GB 512 GB model",
        "Laptop 16 gb 512 gb ssd",
        "Paket 12 KG 150 KG taşıma",
        "Ekran 15 CM 120 cm",
    ] {
        assert!(
            !has(text, &["tr"], EntityType::Plaka),
            "{text}: {:?}",
            found(text, &["tr"])
        );
    }
}

#[test]
fn real_plates_are_still_claimed() {
    for (text, plate) in [
        ("Araç plakası 34 AB 123 idi", "34 AB 123"),
        ("plaka 16 GB 512", "16 GB 512"),
        ("34-ABC-123 park etti", "34-ABC-123"),
        ("06 KM 1234 numaralı araç", "06 KM 1234"),
        // one unit alone does not make a specification list
        ("plaka 34 AB 123 KM", "34 AB 123"),
        ("araç plakası 34 AB 123 GR", "34 AB 123"),
        // "Mah." (mahalle) after a plate in an address
        ("Plaka 34 ABC 123 mah. sakini", "34 ABC 123"),
        ("34 AB 1234 Mah. Ataturk Cad.", "34 AB 1234"),
    ] {
        assert_eq!(
            found(text, &["tr"]),
            vec![(EntityType::Plaka, plate.to_owned())],
            "{text}"
        );
    }
}

// ------------------------------------------------------ card / float

#[test]
fn float_fractions_are_not_cards() {
    for text in [
        "score 0.4111111111111111",
        "lat 41.4111111111111111",
        r#"{"p": 0.4111111111111111}"#,
    ] {
        assert!(
            !has(text, &["en"], EntityType::CreditCard),
            "{text}: {:?}",
            found(text, &["en"])
        );
    }
}

#[test]
fn cards_next_to_dots_and_commas_are_still_claimed() {
    for text in [
        "card: 4111111111111111.",
        "card no.4111111111111111",
        "csv 1,4111111111111111,John",
        "kart 4111 1111 1111 1111",
        // a fraction holds no separator: grouped digits after `<digit>.`
        "item 1.4111 1111 1111 1111",
        "step 3.4111-1111-1111-1111",
        // after `<digit>+` or `++` the card starts at its digits
        "qty=2+4111111111111111",
        "pay 1+4111111111111111",
        "c++4111111111111111",
    ] {
        assert!(
            has(text, &["en"], EntityType::CreditCard),
            "{text}: {:?}",
            found(text, &["en"])
        );
    }
}
