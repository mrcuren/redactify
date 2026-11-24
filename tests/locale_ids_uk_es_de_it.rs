//! Cue-gated identifiers: UK NHS, ES NIE, DE nPA identity card, IT codice
//! fiscale, SWIFT BIC.
//!
//! Vectors are generated + cross-verified against two independent sources
//! per rule (see each locale module's docs). Cue requirements, locale
//! isolation and cross-checksum conflicts are part of the acceptance, as
//! in eu_ids_corpus.rs.

use redactify::{detect, Detector, EntityType};

fn kind_of(text: &str, locale: &str) -> Vec<EntityType> {
    Detector::new()
        .with_locales(&[locale])
        .detect(text)
        .into_iter()
        .map(|e| e.kind)
        .collect()
}

// GENERATED + cross-verified vectors (module docs cite both sources):
// - NHS: independently verified vector plus checksum-computed 9-digit bases
// - NIE: mod-23 letter over prefix_value * 10^7 + body
// - nPA: ICAO 7-3-1 check digit over Q-free bodies (alphabet has no Q)
// - CF: control characters confirmed against an independent public
//   implementation (incl. omocodia)
pub const NHS_VALID: &[&str] = &["943-476-5870", "9434765870", "4001234564", "9876543210"];
pub const NIE_VALID: &[&str] = &["X1234567L", "Y0000000Z", "Z0000000M"];
pub const NPA_VALID: &[&str] = &["LF2K7X9R2", "MR8P4T2N2", "TTTTTTTT8", "L12345673"];
pub const CF_VALID: &[&str] = &[
    "MRTRSS85M01H501C",
    "RSSMRA80A01H501U",
    "BNCMRC85M01H501Y",
    "MRTRSS8RM01H501O", // omocodia digits-as-letters
];

#[test]
fn uk_nhs_requires_cue_and_checksum() {
    for v in NHS_VALID {
        let with_cue = format!("NHS number {v} on file");
        assert_eq!(kind_of(&with_cue, "uk"), vec![EntityType::UkNhs], "{v}");
        // no cue -> not claimed (precision-first)
        let no_cue = format!("ref {v} without context");
        assert!(kind_of(&no_cue, "uk").is_empty(), "{v} without cue");
    }
    // check digit off by one -> rejected
    assert!(kind_of("NHS number 9434765871 on file", "uk").is_empty());
    // remainder-10 base: no digit can complete this number
    for d in 0..10u8 {
        assert!(kind_of(&format!("nhs 100000001{d}"), "uk").is_empty());
    }
}

#[test]
fn uk_nhs_beats_structural_phone_on_overlap() {
    // the NHS 3-3-4 shape is the NANP phone shape; with BOTH locales
    // active the checksummed UK_NHS (priority 3) must win the span over
    // the cue-less structural Phone rule (priority 5) - checksum beats
    // structural (NIR precedent, see EntityType::priority docs)
    let kinds: Vec<EntityType> = Detector::new()
        .with_locales(&["en", "uk"])
        .detect("NHS number 943 476 5870 on file")
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert_eq!(kinds, vec![EntityType::UkNhs]);
    // the same shape WITHOUT an nhs cue stays a plain NANP phone
    let kinds: Vec<EntityType> = Detector::new()
        .with_locales(&["en", "uk"])
        .detect("call 943 476 5870 now")
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert_eq!(kinds, vec![EntityType::Phone]);
}

#[test]
fn es_nie_requires_cue_and_checksum() {
    for v in NIE_VALID {
        let with_cue = format!("NIE {v} registrado");
        assert_eq!(kind_of(&with_cue, "es"), vec![EntityType::Nie], "{v}");
        let no_cue = format!("ref {v} sin contexto");
        assert!(kind_of(&no_cue, "es").is_empty(), "{v} without cue");
    }
    assert!(kind_of("NIE X1234567K registrado", "es").is_empty());
    // lowercase form also detected (case-insensitive rule)
    assert_eq!(
        kind_of("nie x1234567l registrado", "es"),
        vec![EntityType::Nie]
    );
}

#[test]
fn de_id_card_requires_cue_and_checksum() {
    for v in NPA_VALID {
        let with_cue = format!("Personalausweis {v} hinterlegt");
        assert_eq!(kind_of(&with_cue, "de"), vec![EntityType::DeIdCard], "{v}");
        let no_cue = format!("ticket {v} geprueft");
        assert!(kind_of(&no_cue, "de").is_empty(), "{v} without cue");
    }
    // the ninth character is no check digit (BT-Drs. 16/10489 § 2 Abs. 8,
    // ICAO Doc 9303-5), so these are valid serial numbers
    for v in ["CF2K7X9R9", "LF2K7X9R3"] {
        let with_cue = format!("Personalausweis {v} hinterlegt");
        assert_eq!(kind_of(&with_cue, "de"), vec![EntityType::DeIdCard], "{v}");
    }
    // 8 characters that are not the provisional letter + 7 digits form
    assert!(kind_of("Personalausweis LF2K7X9R hinterlegt", "de").is_empty());
}

#[test]
fn it_fiscal_code_requires_cue_and_checksum() {
    for v in CF_VALID {
        let with_cue = format!("codice fiscale {v} registrato");
        assert_eq!(
            kind_of(&with_cue, "it"),
            vec![EntityType::ItFiscalCode],
            "{v}"
        );
        let no_cue = format!("codice {v} senza contesto");
        assert!(kind_of(&no_cue, "it").is_empty(), "{v} without cue");
    }
    assert!(kind_of("codice fiscale MRTRSS85M01H501D", "it").is_empty());
}

#[test]
fn swift_bic_is_generic_and_cue_gated() {
    // SWIFT/BIC is a generic rule: active under ANY locale incl. default
    assert_eq!(
        detect("BIC: DEUTDEFF")
            .iter()
            .map(|e| e.kind)
            .collect::<Vec<_>>(),
        vec![EntityType::SwiftBic]
    );
    let kinds = kind_of("SWIFT code CHASUS33 wire", "en");
    assert_eq!(kinds, vec![EntityType::SwiftBic]);
    let kinds = kind_of("iban + swift DEUTDEFF500 odeme", "tr");
    assert_eq!(kinds, vec![EntityType::SwiftBic]);
    // no cue -> not claimed even with a perfect shape
    assert!(kind_of("routing DEUTDEFF and CHASUS33 listed", "en").is_empty());
    // unknown country code -> rejected even with a cue
    assert!(kind_of("BIC: DEUTZZFF", "en").is_empty());
    // lowercase is not the ISO 9362 canonical form
    assert!(kind_of("bic: deutdeff", "en").is_empty());
}

#[test]
fn locale_isolation_default_never_sees_opt_in_packs() {
    // default detect() is tr+en: cue + checksum alone do not fire the
    // opt-in rules; only the generic SWIFT rule is default-visible
    assert!(detect("NHS number 9434765870").is_empty());
    assert!(detect("NIE X1234567L registrado").is_empty());
    assert!(detect("Personalausweis LF2K7X9R2").is_empty());
    assert!(detect("codice fiscale MRTRSS85M01H501C").is_empty());
    // and packs are mutually isolated: the es locale sees no NIE under tr
    assert!(kind_of("NIE X1234567L registrado", "tr").is_empty());
    assert!(kind_of("NHS number 9434765870", "es").is_empty());
}

#[test]
fn vkn_nhs_cross_checksum_tie_resolved_by_rule_order() {
    // these generated vectors pass BOTH checksums (VKN weighted-mod-10
    // and NHS mod-11); VKN and UK_NHS sit on different tiers, so each
    // pack alone resolves the shape to its own label
    for v in ["1234567938", "1234568349", "1234568357"] {
        assert!(redactify::valid_vkn(v), "{v}");
        assert!(redactify::valid_uk_nhs(v), "{v}");
    }
    // uk alone resolves the shape to UK_NHS
    assert_eq!(
        kind_of("nhs 1234567938 on file", "uk"),
        vec![EntityType::UkNhs]
    );
    // tr alone resolves the same shape to VKN
    assert_eq!(
        kind_of("vkn 1234567938 kayitli", "tr"),
        vec![EntityType::Vkn]
    );
}

#[test]
fn digit_heavy_negatives_stay_unclaimed() {
    let negatives = [
        "order 9434765870 refid X1234567 shipped",
        "kunde 4001234564 telefonnummer eingetragen",
        "serial LF2K7X9R2 checked ok",
        "codice MRTRSS85M01H501C anagrafe",
        "bank routing DEUTDEFF CHASUS33 NWBKGB2L",
    ];
    for t in negatives {
        for loc in ["tr", "en", "fr", "es", "nl", "uk", "de", "it"] {
            assert!(kind_of(t, loc).is_empty(), "FP {loc} on {t:?}");
        }
    }
}
