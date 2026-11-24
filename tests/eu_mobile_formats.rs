//! National mobile-phone formats of the opt-in EU locales (fr, es, nl,
//! uk, de, it, pt).
//!
//! Policies under test: trunk-0 countries accept the bare form
//! (TR-mobile precedent), no-trunk countries require separators
//! (TR-landline precedent, protecting bare BSN/VKN/order shapes), and
//! the PT_NIF checksum claim outranks the pt phone rule on the shared
//! spaced 3-3-3 shape (checksum beats structural).

use redactify::{detect, Detector, EntityType};

fn kind_of(text: &str, locale: &str) -> Vec<EntityType> {
    Detector::new()
        .with_locales(&[locale])
        .detect(text)
        .into_iter()
        .map(|e| e.kind)
        .collect()
}

#[test]
fn national_mobile_formats_detected_per_locale() {
    // independent public metadata-set example numbers (spaced) + bare trunk forms
    assert_eq!(
        kind_of("rappelle au 06 12 34 56 78 stp", "fr"),
        vec![EntityType::Phone]
    );
    assert_eq!(
        kind_of("bel op 0612345678 aub", "nl"),
        vec![EntityType::Phone]
    );
    assert_eq!(
        kind_of("call 07400 123456 now", "uk"),
        vec![EntityType::Phone]
    );
    assert_eq!(
        kind_of("ruf 01512 3456789 an", "de"),
        vec![EntityType::Phone]
    );
    assert_eq!(
        kind_of("llama al 612 345 678 ya", "es"),
        vec![EntityType::Phone]
    );
    assert_eq!(
        kind_of("chiama il 312 345 6789", "it"),
        vec![EntityType::Phone]
    );
    assert_eq!(
        kind_of("liga para 912 345 678", "pt"),
        vec![EntityType::Phone]
    );
}

#[test]
fn no_trunk_locales_never_claim_bare_runs() {
    // TR-landline precedent: a bare 9/10-digit run is never an ES/IT/PT
    // mobile (keeps BSN/VKN/order shapes unclaimed)
    assert!(kind_of("ref 612345678 aqui", "es").is_empty());
    assert!(kind_of("ref 3123456789 qui", "it").is_empty());
    assert!(kind_of("ref 912345678 aqui", "pt").is_empty());
}

#[test]
fn pt_nif_checksum_beats_pt_phone_on_shared_shape() {
    // 912345675 is a checksum-valid NIF (and a pt-phone-shaped number);
    // with its cue the checksummed claim must win the span
    assert!(redactify::valid_pt_nif("912345675"));
    let kinds = kind_of("nif: 912 345 675 registado", "pt");
    assert_eq!(kinds, vec![EntityType::PtNif]);
    // without a cue the same shape stays a plain phone
    let kinds = kind_of("liga 912 345 678 agora", "pt");
    assert_eq!(kinds, vec![EntityType::Phone]);
}

#[test]
fn fr_nl_same_shape_coexist_as_one_phone() {
    // the FR 06-mobile and NL 06-mobile shapes coincide by design; with
    // both locales active the span resolves to a single PHONE entity
    let kinds: Vec<EntityType> = Detector::new()
        .with_locales(&["fr", "nl"])
        .detect("contact 0612345678 nu")
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert_eq!(kinds, vec![EntityType::Phone]);
}

#[test]
fn locale_isolation_default_never_sees_eu_mobiles() {
    assert!(detect("rappelle au 06 12 34 56 78 stp").is_empty());
    assert!(detect("llama al 612 345 678 ya").is_empty());
    assert!(detect("ruf 01512 3456789 an").is_empty());
}

#[test]
fn digit_heavy_negatives_stay_unclaimed() {
    let negatives = [
        "order 06123456 shipped",     // 8 digits
        "kunde 0512345678 telefon",   // 05 geographic (NL)
        "ref 08 12 34 56 78 special", // 08 FR special services
        "linea 701 234 567 alla",     // 70 ES personal numbers
        "linha 950 123 456 la",       // 95 PT unassigned
    ];
    for t in negatives {
        for loc in ["fr", "es", "nl", "uk", "de", "it", "pt"] {
            assert!(kind_of(t, loc).is_empty(), "FP {loc} on {t:?}");
        }
    }
    // 076 is the UK pager block: excluded by the uk rule specifically
    // (the same digits ARE a legitimate FR 07-mobile shape)
    assert!(kind_of("pager 076 1234566 alt", "uk").is_empty());
}
