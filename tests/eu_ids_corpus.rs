//! EU identifier-pack corpus.
//!
//! Vectors are GENERATED and machine-verified against the sourced
//! algorithms (IBAN-corpus pattern; no memorized values trusted):
//! - FR NIR: mod-97 key over the first 13 digits, Corsica 2A->19 / 2B->18
//!   (INSEE/Wikipedia, retrieved 2026-10-06); includes the Wikipedia
//!   Corsica transformation example with its computed key.
//! - ES DNI: letter = "TRWAGMYFPDXBNJZSQVHLCKE"[n mod 23].
//! - NL BSN: elfproef with -1 last-digit weight (mod 11); includes both
//!   source-given examples (123456782, 111222333).
//! - UK NINO: structural GOV.UK rules (prefix exclusions D/F/I/Q/U/V + O on
//!   the second letter; unallocated BG/GB/NK/KN/TN/NT/ZZ; suffix A-D).
//!
//! Locale isolation is part of the acceptance: each pack runs ONLY under its
//! own locale tag; the default tr+en set never sees them.

use redactify::{detect, Detector, EntityType};

fn kind_of(text: &str, locale: &str) -> Vec<EntityType> {
    Detector::new()
        .with_locales(&[locale])
        .detect(text)
        .into_iter()
        .map(|e| e.kind)
        .collect()
}

// GENERATED (EU IDs corpus generator); do not hand-edit.
pub const NIR_VALID: &[&str] = &[
    "211113793929546",
    "172046864053736",
    "114013111908229",
    "260105537789616",
    "101022151013731",
    "117039466346834",
    "104111372844688",
    "124051639649614",
    "263072A10406418",
];

pub const NIR_BAD: &[&str] = &[
    "214113793929546",
    "175046864053736",
    "117013111908229",
    "263105537789616",
    "104022151013731",
];

pub const DNI_VALID: &[&str] = &[
    "12345678Z",
    "00000000T",
    "99999999R",
    "43082127E",
    "87654321X",
];

pub const DNI_BAD: &[&str] = &["12345678X", "00000001W", "99999998R"];

pub const BSN_VALID: &[&str] = &[
    "123456782",
    "111222333",
    "937658601",
    "239169694",
    "175810837",
    "577287692",
    "737351718",
    "945912353",
];

pub const BSN_BAD: &[&str] = &["123956782", "111722333", "937158601", "239669694"];

pub const NINO_VALID: &[&str] = &[
    "AB123456C",
    "JL123456B",
    "CE123456",
    "MW123456D",
    "XY123456",
];

pub const NINO_BAD: &[&str] = &[
    "DQ123456C",
    "AO123456C",
    "BG123456C",
    "GB123456C",
    "NK123456C",
    "KN123456C",
    "TN123456C",
    "NT123456C",
    "ZZ123456C",
    "AB123456E",
];

#[test]
fn fr_nir_valid_vectors_detected() {
    for v in NIR_VALID {
        let text = format!("NIR {v} verifie");
        let kinds = kind_of(&text, "fr");
        assert_eq!(kinds, vec![EntityType::Nir], "{v} in {text:?}");
    }
}

#[test]
fn fr_nir_corrupt_rejected() {
    for v in NIR_BAD {
        let text = format!("NIR {v} verifie");
        assert!(kind_of(&text, "fr").is_empty(), "must reject {v}");
    }
}

#[test]
fn fr_nir_spaced_form_detected() {
    let kinds = kind_of("secu 2 63 07 2A 104 064 18 ok", "fr");
    assert_eq!(kinds, vec![EntityType::Nir]);
}

#[test]
fn es_dni_requires_cue_and_letter() {
    for v in DNI_VALID {
        let with_cue = format!("DNI {v} registrado");
        assert_eq!(kind_of(&with_cue, "es"), vec![EntityType::Dni], "{v}");
        // no cue -> not claimed (precision-first)
        let no_cue = format!("ref {v} sin contexto");
        assert!(kind_of(&no_cue, "es").is_empty(), "{v}");
    }
    for v in DNI_BAD {
        let text = format!("DNI {v} registrado");
        assert!(kind_of(&text, "es").is_empty(), "must reject {v}");
    }
}

#[test]
fn nl_bsn_requires_cue_and_elfproef() {
    for v in BSN_VALID {
        assert_eq!(
            kind_of(&format!("bsn {v} geregistreerd"), "nl"),
            vec![EntityType::Bsn],
            "{v}"
        );
        assert!(
            kind_of(&format!("ken {v} zonder",), "nl").is_empty(),
            "{v} without cue"
        );
    }
    for v in BSN_BAD {
        assert!(
            kind_of(&format!("bsn {v} geregistreerd"), "nl").is_empty(),
            "must reject {v}"
        );
    }
}

#[test]
fn uk_nino_structural_rules() {
    for v in NINO_VALID {
        assert_eq!(
            kind_of(&format!("NI number {v} on file"), "uk"),
            vec![EntityType::Nino],
            "{v}"
        );
    }
    for v in NINO_BAD {
        assert!(
            kind_of(&format!("NI number {v} on file"), "uk").is_empty(),
            "must reject {v}"
        );
    }
}

#[test]
fn locale_isolation_default_never_sees_eu_packs() {
    // the default tr+en rule set does NOT include the EU packs: an FR NIR in
    // a plain detect() is not masked (opt-in by locale is the design)
    let nir = NIR_VALID[0];
    assert!(detect(&format!("NIR {nir} ici")).is_empty());
    // and each pack is isolated: es locale does not see an FR NIR
    assert!(kind_of(&format!("DNI {nir}"), "es").is_empty());
}

#[test]
fn digit_heavy_negatives_no_eu_fp() {
    let negatives = [
        "order 123456789 refid 12000345671 tracking",
        "kunde 12345678 telefon 0532 123 45 67",
        "batch 1112223334 shipped",
    ];
    for t in negatives {
        for loc in ["fr", "es", "nl", "uk"] {
            assert!(kind_of(t, loc).is_empty(), "FP {loc} on {t:?}");
        }
    }
}

// ------------------------------------------------------------ DE Steuer-IdNr

/// Official ELSTER Tabelle 2-1 examples (check digit and the Kap. 2.2
/// digit structure; see locales/de/tax_id.rs module docs). The former
/// generated vectors repeated more than one digit value and are invalid.
pub const DE_VALID: &[&str] = &[
    "86095742719",
    "47036892816",
    "65929970489",
    "57549285017",
    "25768131411",
];

#[test]
fn de_tax_id_requires_cue_and_checksum() {
    for v in DE_VALID {
        let with_cue = format!("Steuer-IdNr {v} hinterlegt");
        assert_eq!(kind_of(&with_cue, "de"), vec![EntityType::DeTaxId], "{v}");
        // no cue -> not claimed (precision-first)
        let no_cue = format!("referenz {v} ohne kontext");
        assert!(kind_of(&no_cue, "de").is_empty(), "{v}");
    }
    // single-digit substitution always caught (ISO 7064 property)
    for v in DE_VALID {
        let bad = format!(
            "Steuer-IdNr {}{}",
            &v[..10],
            (v.as_bytes()[10] - b'0' + 1) % 10
        );
        assert!(kind_of(&bad, "de").is_empty(), "must reject {bad}");
    }
}

#[test]
fn de_tax_id_and_tckn_shape_conflict_resolved_by_priority() {
    // 11-digit runs are also the TCKN shape. These generated vectors pass
    // BOTH checksums (TCKN's two check digits AND the ISO 7064 MOD 11,10
    // digit - a ~1/10 coincidence over TCKN-valid numbers); when both
    // locales are active, TCKN (priority 3) must win over DE_TAX_ID (7).
    for v in ["46360516720", "19465306824", "18900253648"] {
        assert!(redactify::valid_tckn(v), "{v}");
        assert!(redactify::valid_de_tax_id(v), "{v}");
        // the value appears twice (two spans); TCKN must win EVERY span and
        // DE_TAX_ID must win none
        let text = format!("steuer-id {v} ve kimlik {v}");
        let kinds: Vec<EntityType> = Detector::new()
            .with_locales(&["de", "tr"])
            .detect(&text)
            .into_iter()
            .map(|e| e.kind)
            .collect();
        assert!(
            !kinds.is_empty() && kinds.iter().all(|k| *k == EntityType::Tckn),
            "TCKN must win: {v} -> {kinds:?}"
        );
    }
    // isolation: the de locale alone resolves the same values to DE_TAX_ID
    // (the tr rules are not loaded)
    let kinds = kind_of("steuer-id 46360516720 hinterlegt", "de");
    assert_eq!(kinds, vec![EntityType::DeTaxId]);
}
