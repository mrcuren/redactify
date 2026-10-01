//! Golden vectors - a verified behavior set (run against the differential suite).

use redactify::{
    detect, redact, valid_iban_tr, valid_luhn, valid_plaka, valid_tckn, valid_vkn, EntityType,
};

// ---------------------------------------------------------------- validators

#[test]
fn tckn_vectors() {
    assert!(valid_tckn("12345678950"));
    assert!(valid_tckn("10000000146"));
    assert!(valid_tckn("19191919190")); // negative weighted sum (rem_euclid lock)
    assert!(!valid_tckn("12345678901"));
    assert!(!valid_tckn("00000000000"));
    assert!(!valid_tckn("02345678950"));
    assert!(!valid_tckn("123"));
}

#[test]
fn iban_vectors() {
    assert!(valid_iban_tr("TR33 0006 1005 1978 6457 8413 26"));
    assert!(valid_iban_tr("TR330006100519786457841326"));
    assert!(!valid_iban_tr("TR00 0000 0000 0000 0000 0000 00"));
}

#[test]
fn vkn_luhn_plaka_vectors() {
    assert!(valid_vkn("1234567890"));
    assert!(!valid_vkn("1234567891"));
    assert!(valid_luhn("4111111111111111"));
    assert!(!valid_luhn("4111111111111112"));
    assert!(valid_plaka("34 ABC 123"));
    assert!(!valid_plaka("99 ABC 123")); // 99. il yok
}

// ------------------------------------------------------------------- redact

#[test]
fn quickstart_redact() {
    assert_eq!(
        redact("TCKN'm 12345678950, IBAN TR33 0006 1005 1978 6457 8413 26, mail a@b.com"),
        "TCKN'm [TCKN], IBAN [IBAN], mail [EMAIL]"
    );
}

#[test]
fn no_false_positive_on_random_numbers() {
    // an order number without a checksum is never claimed as a TCKN
    assert_eq!(
        redact("Sipariş numaranız 12000345671 olarak kaydedildi."),
        "Sipariş numaranız 12000345671 olarak kaydedildi."
    );
}

#[test]
fn vkn_needs_context_not_bare_10_digits() {
    assert_eq!(
        redact("Zaman damgası 1719400000 kaydedildi."),
        "Zaman damgası 1719400000 kaydedildi."
    );
    assert_eq!(
        redact("Sipariş 1234567890 hazır."),
        "Sipariş 1234567890 hazır."
    );
    // ipucu varken VKN maskelenir
    assert!(redact("Firmanın vergi numarası 1234567890.").contains("[VKN]"));
    assert!(redact("VKN 1234567890 kullanın.").contains("[VKN]"));
}

// ------------------------------------------------------------------ detect

#[test]
fn edge_probes() {
    let one = |t: &str| -> Vec<(EntityType, String)> {
        detect(t).into_iter().map(|e| (e.kind, e.text)).collect()
    };

    // prefix-less but separator-bearing phone
    assert_eq!(
        one("Cep: 532 123 45 67"),
        vec![(EntityType::Phone, "532 123 45 67".into())]
    );
    // +90-prefixed phone
    assert_eq!(
        one("Bana +90 532 123 45 67"),
        vec![(EntityType::Phone, "+90 532 123 45 67".into())]
    );
    // plate with Turkish letters
    assert_eq!(
        one("Plakam 06 ANK 06"),
        vec![(EntityType::Plaka, "06 ANK 06".into())]
    );
    assert_eq!(
        one("Plaka 06 AAA 9999"),
        vec![(EntityType::Plaka, "06 AAA 9999".into())]
    );
    // two adjacent TCKNs
    assert_eq!(one("12345678950 ve 10000000146").len(), 2);
    // no TCKN inside a 12-digit run (digit boundary)
    assert!(one("ref 123456789501 X").is_empty());
    // tireli kart
    assert_eq!(
        one("4111-1111-1111-1111"),
        vec![(EntityType::CreditCard, "4111-1111-1111-1111".into())]
    );
    // spaceless IBAN
    assert_eq!(
        one("TR330006100519786457841326"),
        vec![(EntityType::Iban, "TR330006100519786457841326".into())]
    );
    // mixed-case e-mail
    assert_eq!(
        one("mail NAME.Mail@Site.COM"),
        vec![(EntityType::Email, "NAME.Mail@Site.COM".into())]
    );
    // multiple PII on one line
    let found =
        one("TCKN 12345678950, vergi no 1234567890, kart 4111 1111 1111 1111, plaka 34 ABC 123");
    let kinds: Vec<_> = found.iter().map(|(k, _)| *k).collect();
    assert!(kinds.contains(&EntityType::Tckn));
    assert!(kinds.contains(&EntityType::Vkn));
    assert!(kinds.contains(&EntityType::CreditCard));
    assert!(kinds.contains(&EntityType::Plaka));
    assert_eq!(found.len(), 4);
}

#[test]
fn tricky_inputs_do_not_panic() {
    // multi-byte edge inputs: detect/redact must never panic
    for t in [
        "",
        "ııııı",
        "😀😀 12345678950 😀",
        "́12345678950", // combining char + TCKN
        "12345678950́", // TCKN + combining char (byte boundary!)
        "\n\t\r",
        "TR",
        "0",
        "vergi",
    ] {
        let _ = detect(t);
        let _ = redact(t);
    }
}

#[test]
fn combining_char_adjacent_tckn_is_still_found() {
    // `(?<!\d)` only forbids DIGIT adjacency; a combining character is not an obstacle.
    assert!(!detect("x́12345678950").is_empty());
}
