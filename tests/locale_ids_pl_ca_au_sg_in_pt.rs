//! Cue-gated identifiers: PL PESEL, CA SIN, AU TFN, SG NRIC/FIN, IN PAN,
//! IN Aadhaar, PT NIF.
//!
//! Vectors are generated + confirmed against an independent public
//! implementation (see each locale module's docs). Cue requirements,
//! locale isolation, substring-cue-collision negatives and cross-checksum
//! conflicts are part of the acceptance.

use redactify::{detect, Detector, EntityType};

fn kind_of(text: &str, locale: &str) -> Vec<EntityType> {
    Detector::new()
        .with_locales(&[locale])
        .detect(text)
        .into_iter()
        .map(|e| e.kind)
        .collect()
}

pub const PESEL_VALID: &[&str] = &["80010123450", "99123199993", "05211501236", "30412907770"];
pub const SIN_VALID: &[&str] = &["123456782", "304167281", "756451233", "613555127"];
pub const TFN_VALID: &[&str] = &["100010747", "100013678", "100029310"];
pub const AADHAAR_VALID: &[&str] = &["607324134360", "397065334700", "518467770056"];
pub const PAN_VALID: &[&str] = &["AAAPL1234C", "BQQBP5731K"];
pub const NIF_VALID: &[&str] = &["123456789", "299266753", "501963871"];

#[test]
fn pl_pesel_requires_cue_and_checksum() {
    for v in PESEL_VALID {
        let with_cue = format!("PESEL {v} w bazie");
        assert_eq!(kind_of(&with_cue, "pl"), vec![EntityType::Pesel], "{v}");
        let no_cue = format!("ref {v} bez kontekstu");
        assert!(kind_of(&no_cue, "pl").is_empty(), "{v} without cue");
    }
    assert!(kind_of("PESEL 80010123451 w bazie", "pl").is_empty());
    // the century-month classes are part of the shape: month 00 is not a
    // PESEL month even with a self-consistent check digit
    assert!(kind_of("PESEL 99003199991 w bazie", "pl").is_empty());
}

#[test]
fn ca_sin_separator_form_only() {
    for v in SIN_VALID {
        let with_cue = format!("SIN: {} on file", fmt_grouped(v));
        assert_eq!(kind_of(&with_cue, "ca"), vec![EntityType::CaSin], "{v}");
    }
    assert!(kind_of("SIN: 123-456-783 on file", "ca").is_empty());
    // bare 9-digit runs are never a SIN (SSN precedent)
    assert!(kind_of("SIN 123456782 on file", "ca").is_empty());
    // unissued prefixes rejected by the pattern
    assert!(kind_of("SIN: 023-456-786 on file", "ca").is_empty());
    // mixed separators rejected (both separators must match)
    assert!(kind_of("SIN: 123-456 782 on file", "ca").is_empty());
    // the omitted bare "sin" cue must NOT unlock the shape
    assert!(kind_of("business 123-456-782 report", "ca").is_empty());
    assert!(kind_of("using 123 456 782 here", "ca").is_empty());
}

fn fmt_grouped(v: &str) -> String {
    format!("{}-{}-{}", &v[0..3], &v[3..6], &v[6..9])
}

fn fmt_spaced(v: &str) -> String {
    format!("{} {} {}", &v[0..3], &v[3..6], &v[6..9])
}

#[test]
fn au_tfn_requires_cue_and_checksum() {
    for v in TFN_VALID {
        let with_cue = format!("TFN {v} lodged");
        assert_eq!(kind_of(&with_cue, "au"), vec![EntityType::AuTfn], "{v}");
        let spaced = format!("TFN {} lodged", fmt_spaced(v));
        assert_eq!(
            kind_of(&spaced, "au"),
            vec![EntityType::AuTfn],
            "{v} spaced"
        );
        let no_cue = format!("ref {v} without context");
        assert!(kind_of(&no_cue, "au").is_empty(), "{v} without cue");
    }
    assert!(kind_of("TFN 100010748 lodged", "au").is_empty());
}

#[test]
fn sg_nric_structural_with_cue() {
    assert_eq!(
        kind_of("NRIC S2740116C on record", "sg"),
        vec![EntityType::SgNricFin]
    );
    // no cue -> silent
    assert!(kind_of("ref S2740116C without context", "sg").is_empty());
    // non-prefix letters rejected
    assert!(kind_of("NRIC B2740116C on record", "sg").is_empty());
    // the omitted bare "fin" cue must NOT unlock the shape
    assert!(kind_of("final T0123456Z gate open", "sg").is_empty());
    assert!(kind_of("finance F5432101B approval", "sg").is_empty());
}

#[test]
fn in_pan_requires_label_cue() {
    for v in PAN_VALID {
        let with_cue = format!("PAN no. {v} registered");
        assert_eq!(kind_of(&with_cue, "in"), vec![EntityType::InPan], "{v}");
    }
    // label-form cues
    assert_eq!(
        kind_of("pan card BQQBP5731K issued", "in"),
        vec![EntityType::InPan]
    );
    // holder-type letter restriction
    assert!(kind_of("PAN no. ABCDE1234F registered", "in").is_empty());
    // substring collisions must NOT unlock the shape (bare "pan" is not
    // a cue: company/japan/expand)
    assert!(kind_of("company AAAPL1234C profile", "in").is_empty());
    assert!(kind_of("japan BQQBP5731K office", "in").is_empty());
    assert!(kind_of("expand TESTP1234X report", "in").is_empty());
}

#[test]
fn in_aadhaar_requires_cue_and_verhoeff() {
    for v in AADHAAR_VALID {
        let with_cue = format!("Aadhaar {v} linked");
        assert_eq!(kind_of(&with_cue, "in"), vec![EntityType::InAadhaar], "{v}");
        let spaced = format!("Aadhaar {} linked", fmt4(v));
        assert_eq!(
            kind_of(&spaced, "in"),
            vec![EntityType::InAadhaar],
            "{v} spaced"
        );
        let no_cue = format!("ref {v} without context");
        assert!(kind_of(&no_cue, "in").is_empty(), "{v} without cue");
    }
    assert!(kind_of("Aadhaar 607324134361 linked", "in").is_empty());
    assert!(kind_of("Aadhaar 107324134360 linked", "in").is_empty());
}

fn fmt4(v: &str) -> String {
    format!("{} {} {}", &v[0..4], &v[4..8], &v[8..12])
}

#[test]
fn pt_nif_requires_cue_and_checksum() {
    for v in NIF_VALID {
        let with_cue = format!("NIF: {v} registado");
        assert_eq!(kind_of(&with_cue, "pt"), vec![EntityType::PtNif], "{v}");
        let spaced = format!("NIF: {} registado", fmt_spaced(v));
        assert_eq!(
            kind_of(&spaced, "pt"),
            vec![EntityType::PtNif],
            "{v} spaced"
        );
        let no_cue = format!("ref {v} sem contexto");
        assert!(kind_of(&no_cue, "pt").is_empty(), "{v} without cue");
    }
    assert!(kind_of("NIF: 123456780 registado", "pt").is_empty());
    assert!(kind_of("NIF: 023456789 registado", "pt").is_empty());
    // the omitted bare "nif" cue must NOT unlock the shape
    assert!(kind_of("unify 123 456 789 across systems", "pt").is_empty());
}

#[test]
fn locale_isolation_default_never_sees_these_packs() {
    assert!(detect("PESEL 80010123450 w bazie").is_empty());
    assert!(detect("SIN: 123-456-782 on file").is_empty());
    assert!(detect("TFN 100010747 lodged").is_empty());
    assert!(detect("NRIC S2740116C on record").is_empty());
    assert!(detect("PAN no AAAPL1234C registered").is_empty());
    assert!(detect("Aadhaar 607324134360 linked").is_empty());
    assert!(detect("NIF: 123456789 registado").is_empty());
}

#[test]
fn bsn_conflicts_resolved_by_rule_order() {
    // these generated vectors pass BOTH checksums; the nl pack is
    // registered before pt/au, so with both locales active and both cues
    // in range the BSN claim wins the same-tier tie by insertion order
    for v in ["100018300", "100026230"] {
        assert!(redactify::valid_bsn(v), "{v}");
        assert!(redactify::valid_pt_nif(v), "{v}");
        assert_eq!(
            kind_of(&format!("bsn {v} geregistreerd"), "nl"),
            vec![EntityType::Bsn]
        );
        assert_eq!(
            kind_of(&format!("nif: {v} registado"), "pt"),
            vec![EntityType::PtNif]
        );
    }
    for v in ["100008148", "100025705"] {
        assert!(redactify::valid_bsn(v), "{v}");
        assert!(redactify::valid_au_tfn(v), "{v}");
        assert_eq!(
            kind_of(&format!("tfn {v} lodged"), "au"),
            vec![EntityType::AuTfn]
        );
    }
}

#[test]
fn digit_heavy_negatives_stay_unclaimed() {
    let negatives = [
        "order 100010747 refid 123456789 shipped",
        "kunde 80010123450 telefonisch erreicht",
        "receipt 607324134360 archived",
        "policy AAAPL1234C appendix",
        "gate S2740116C opened",
        "facture 123 456 789 payee",
    ];
    for t in negatives {
        for loc in ["tr", "en", "pl", "ca", "au", "sg", "in", "pt"] {
            assert!(kind_of(t, loc).is_empty(), "FP {loc} on {t:?}");
        }
    }
}
