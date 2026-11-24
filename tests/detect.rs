//! Overlap resolution, priority and VKN context scenarios - behavior parity tests.

use redactify::{detect, redact, EntityType};

fn kinds(text: &str) -> Vec<EntityType> {
    detect(text).into_iter().map(|e| e.kind).collect()
}

#[test]
fn iban_priority_beats_vkn_inside_it() {
    // 10-digit blocks inside the IBAN body never beat the IBAN, even if the VKN checksum passes.
    let found = kinds("IBAN TR33 0006 1005 1978 6457 8413 26");
    assert_eq!(found, vec![EntityType::Iban]);
}

#[test]
fn credit_card_priority_beats_tckn_when_overlapping() {
    // 4111111111111111 may contain valid 11-digit TCKN substrings;
    // CREDIT_CARD priority (1) beats TCKN (3), so the card wins.
    let found = kinds("kart 4111111111111111");
    assert_eq!(found, vec![EntityType::CreditCard]);
}

#[test]
fn vkn_masked_only_with_cue() {
    assert!(kinds("Firmanın vergi numarası 1234567890.").contains(&EntityType::Vkn));
    assert!(kinds("VKN 1234567890 kullanın.").contains(&EntityType::Vkn));
    assert!(!kinds("Sipariş 1234567890 hazır.").contains(&EntityType::Vkn));
    assert!(!kinds("Zaman damgası 1719400000 kaydedildi.").contains(&EntityType::Vkn));
}

#[test]
fn vkn_cue_window_is_18_chars() {
    // the cue is inside the window: masked
    assert!(kinds("vergi no 1234567890").contains(&EntityType::Vkn));
    // cue on the right: "1234567890 vergi" - immediately right, inside the window
    assert!(kinds("numara 1234567890 vergi").contains(&EntityType::Vkn));
}

#[test]
fn phone_needs_prefix_or_separators() {
    // "0532 123 45 67" -> 0-prefixed: found
    assert!(kinds("Bana 0532 123 45 67'den ara.").contains(&EntityType::Phone));
    // the bare separator-less "5321234567" -> the pattern does not match (separator required)
    assert!(!kinds("kod 5321234567 mi?").contains(&EntityType::Phone));
    // landline (0 212...) is SUPPORTED since 0.3 (separator required after the area code)
    assert!(kinds("ofis 0 212 555 44 33.").contains(&EntityType::Phone));
}

#[test]
fn full_sample_paragraph_end_to_end() {
    let text = "Merhaba, ben Ayşe. TCKN'm 12345678950. \
Maaşımı TR33 0006 1005 1978 6457 8413 26 IBAN'ıma yatırabilirsiniz.\n\
Firmamızın vergi numarası 1234567890. Bana 0532 123 45 67 numaralı telefondan veya ayse@ornek.com.tr adresinden ulaşın.\n\
Aracımın plakası 34 ABC 123. Kartım 4111 1111 1111 1111.\n\n\
NOT: Sipariş numaranız 12000345671 - bu bir TCKN DEĞİL (checksum tutmuyor), maskelenmemeli.";
    let out = redact(text);
    // 7 entities must be masked
    for m in [
        "[TCKN]",
        "[IBAN]",
        "[VKN]",
        "[PHONE]",
        "[EMAIL]",
        "[PLAKA]",
        "[CREDIT_CARD]",
    ] {
        assert!(out.contains(m), "eksik maske: {m}");
    }
    // the order number must stay UNTOUCHED
    assert!(out.contains("12000345671"));
    // no real values must remain
    assert!(!out.contains("12345678950"));
    assert!(!out.contains("4111 1111 1111 1111"));
    // plus the first name in "ben Ayşe" (the lexicon scanner `tr::person`)
    assert!(out.contains("ben [NAME]."), "{out}");
    assert_eq!(detect(text).len(), 8);
}

#[test]
fn entities_are_sorted_left_to_right_and_non_overlapping() {
    let text = "mail a@b.com ve TCKN 12345678950, vergi 1234567890";
    let ents = detect(text);
    let mut sorted = ents.clone();
    sorted.sort_by_key(|e| e.start);
    assert_eq!(ents, sorted);
    for w in ents.windows(2) {
        assert!(w[0].end <= w[1].start, "overlap: {:?}", ents);
    }
}

#[test]
fn allowlisted_winner_does_not_hide_the_overlapping_finding() {
    use redactify::{CustomRule, Detector};
    // "AB-1234" (TCKN tier) outranks the overlapping "1234-CD" (VKN tier);
    // allowlisting the winner lets the loser compete on its own instead
    // of silently suppressing it
    let winner = CustomRule::new(EntityType::Tckn, r"AB-\d{4}").unwrap();
    let loser = CustomRule::new(EntityType::Vkn, r"\d{4}-CD").unwrap();
    let rules = [&winner, &loser];
    let d = Detector::new().with_custom_rules(&rules);
    assert_eq!(d.redact("ref AB-1234-CD x"), "ref [TCKN]-CD x");
    assert_eq!(
        d.with_ignored(&["AB-1234"]).redact("ref AB-1234-CD x"),
        "ref AB-[VKN] x"
    );
}

#[test]
fn normalization_aware_detection_is_sorted_and_non_overlapping() {
    use redactify::Detector;
    // fullwidth TCKN first, then a raw e-mail, then a zero-width-scattered
    // phone: the normalized-view findings are merged in text order
    let text = "\u{FF11}\u{FF12}\u{FF13}\u{FF14}\u{FF15}\u{FF16}\u{FF17}\u{FF18}\u{FF19}\u{FF15}\u{FF10}, \
                a@b.com, 0532\u{200B} 123 45 67";
    let ents = Detector::new().with_normalization(true).detect(text);
    let kinds: Vec<EntityType> = ents.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        vec![EntityType::Tckn, EntityType::Email, EntityType::Phone]
    );
    for w in ents.windows(2) {
        assert!(w[0].end <= w[1].start, "{ents:?}");
    }
    for e in &ents {
        assert_eq!(&text[e.start..e.end], e.text);
    }
}
