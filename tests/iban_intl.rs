//! International IBAN corpus.
//!
//! Vectors are GENERATED, not memorized: valid IBANs are constructed by
//! computing ISO 13616 check digits over the sourced country-length table
//! (IBAN Register, iban.com, retrieved 2026-10-05; 89 countries); corrupt
//! variants are verified-invalid single-character changes; the
//! "registry examples" were machine-verified (mod-97 + length) before
//! inclusion - two misremembered strings failed verification and were
//! deliberately excluded.

use redactify::{detect, redact, Detector, EntityType};

// GENERATED (IBAN corpus generator); do not hand-edit.
/// (country, valid IBAN): check digits computed via ISO 13616 math from the
/// sourced length table (iban.com IBAN Register, retrieved 2026-10-05;
/// 89 registry countries; experimental/partial list excluded).
pub const VALID: &[(&str, &str)] = &[
    ("AD", "AD72 BP2F U7LZ CR4H W9N1 ET67"),
    ("AE", "AE58 BW9N 1ET6 KYBQ 3GV8 M07"),
    ("AL", "AL50 B3GV 8M0D S5JX AP2F U7LZ CR47"),
    ("AT", "AT84 BAP2 FU7L ZCR4 HW97"),
    ("AZ", "AZ94 BHW9 N1ET 6KYB Q3GV 8M0D S5J7"),
    ("BA", "BA04 BQ3G V8M0 DS5J XAP7"),
    ("BE", "BE21 BXAP 2FU7 LZC7"),
    ("BG", "BG74 B4HW 9N1E T6KY BQ3G V7"),
    ("BH", "BH28 BBQ3 GV8M 0DS5 JXAP 27"),
    ("BI", "BI06 BJXA P2FU 7LZC R4HW 9N1E T67"),
    ("BR", "BR50 BR4H W9N1 ET6K YBQ3 GV8M 0DS5 7"),
    ("BY", "BY38 BYBQ 3GV8 M0DS 5JXA P2FU 7LZ7"),
    ("CH", "CH46 B5JX AP2F U7LZ CR4H 7"),
    ("CR", "CR89 BCR4 HW9N 1ET6 KYBQ 37"),
    ("CY", "CY43 BKYB Q3GV 8M0D S5JX AP2F U7L7"),
    ("CZ", "CZ63 BS5J XAP2 FU7L ZCR4 HW97"),
    ("DE", "DE47 BZCR 4HW9 N1ET 6KYB Q7"),
    ("DJ", "DJ68 B6KY BQ3G V8M0 DS5J XAP2 FU7"),
    ("DK", "DK80 BDS5 JXAP 2FU7 L7"),
    ("DO", "DO32 BLZC R4HW 9N1E T6KY BQ3G V8M7"),
    ("EE", "EE66 BT6K YBQ3 GV8M 0DS7"),
    ("EG", "EG90 B0DS 5JXA P2FU 7LZC R4HW 9N1E 7"),
    ("ES", "ES33 B7LZ CR4H W9N1 ET6K YBQ7"),
    ("FI", "FI75 BET6 KYBQ 3GV8 M7"),
    ("FK", "FK72 BM0D S5JX AP2F U7"),
    ("FO", "FO69 BU7L ZCR4 HW9N 17"),
    ("FR", "FR47 B1ET 6KYB Q3GV 8M0D S5JX AP7"),
    ("GB", "GB36 B8M0 DS5J XAP2 FU7L Z7"),
    ("GE", "GE39 BFU7 LZCR 4HW9 N1ET 67"),
    ("GI", "GI14 BN1E T6KY BQ3G V8M0 DS7"),
    ("GL", "GL87 BV8M 0DS5 JXAP 27"),
    ("GR", "GR28 B2FU 7LZC R4HW 9N1E T6KY BQ7"),
    ("GT", "GT33 B9N1 ET6K YBQ3 GV8M 0DS5 JXA7"),
    ("HN", "HN69 BGV8 M0DS 5JXA P2FU 7LZC R4H7"),
    ("HR", "HR63 BP2F U7LZ CR4H W9N1 7"),
    ("HU", "HU72 BW9N 1ET6 KYBQ 3GV8 M0DS 5JX7"),
    ("IE", "IE47 B3GV 8M0D S5JX AP2F U7"),
    ("IL", "IL39 BAP2 FU7L ZCR4 HW9N 1E7"),
    ("IQ", "IQ97 BHW9 N1ET 6KYB Q3GV 8M7"),
    ("IS", "IS58 BQ3G V8M0 DS5J XAP2 FU7L Z7"),
    ("IT", "IT46 BXAP 2FU7 LZCR 4HW9 N1ET 6K7"),
    ("JO", "JO46 B4HW 9N1E T6KY BQ3G V8M0 DS5J X7"),
    ("KW", "KW08 BBQ3 GV8M 0DS5 JXAP 2FU7 LZCR 47"),
    ("KZ", "KZ56 BJXA P2FU 7LZC R4H7"),
    ("LB", "LB19 BR4H W9N1 ET6K YBQ3 GV8M 0DS7"),
    ("LC", "LC73 BYBQ 3GV8 M0DS 5JXA P2FU 7LZC R4H7"),
    ("LI", "LI59 B5JX AP2F U7LZ CR4H 7"),
    ("LT", "LT82 BCR4 HW9N 1ET6 KYB7"),
    ("LU", "LU23 BKYB Q3GV 8M0D S5J7"),
    ("LV", "LV13 BS5J XAP2 FU7L ZCR4 7"),
    ("LY", "LY56 BZCR 4HW9 N1ET 6KYB Q3GV 7"),
    ("MC", "MC08 B6KY BQ3G V8M0 DS5J XAP2 FU7"),
    ("MD", "MD46 BDS5 JXAP 2FU7 LZCR 4HW7"),
    ("ME", "ME31 BLZC R4HW 9N1E T6KY B7"),
    ("MK", "MK16 BT6K YBQ3 GV8M 0D7"),
    ("MN", "MN87 B0DS 5JXA P2FU 7LZ7"),
    ("MR", "MR03 B7LZ CR4H W9N1 ET6K YBQ3 GV7"),
    ("MT", "MT73 BET6 KYBQ 3GV8 M0DS 5JXA P2FU 7L7"),
    ("MU", "MU23 BM0D S5JX AP2F U7LZ CR4H W9N1 E7"),
    ("NI", "NI69 BU7L ZCR4 HW9N 1ET6 KYBQ 3GV7"),
    ("NL", "NL60 B1ET 6KYB Q3GV 87"),
    ("NO", "NO51 B8M0 DS5J XA7"),
    ("OM", "OM25 BFU7 LZCR 4HW9 N1ET 6K7"),
    ("PK", "PK43 BN1E T6KY BQ3G V8M0 DS57"),
    ("PL", "PL28 BV8M 0DS5 JXAP 2FU7 LZCR 4HW7"),
    ("PS", "PS66 B2FU 7LZC R4HW 9N1E T6KY BQ3G 7"),
    ("PT", "PT57 B9N1 ET6K YBQ3 GV8M 0DS5 7"),
    ("QA", "QA08 BGV8 M0DS 5JXA P2FU 7LZC R4HW 7"),
    ("RO", "RO80 BP2F U7LZ CR4H W9N1 ET67"),
    ("RS", "RS66 BW9N 1ET6 KYBQ 3GV8 M7"),
    ("RU", "RU31 B3GV 8M0D S5JX AP2F U7LZ CR4H W9N1 7"),
    ("SA", "SA40 BAP2 FU7L ZCR4 HW9N 1ET7"),
    ("SC", "SC07 BHW9 N1ET 6KYB Q3GV 8M0D S5JX AP7"),
    ("SD", "SD75 BQ3G V8M0 DS5J X7"),
    ("SE", "SE39 BXAP 2FU7 LZCR 4HW9 N1E7"),
    ("SI", "SI15 B4HW 9N1E T6KY BQ7"),
    ("SK", "SK04 BBQ3 GV8M 0DS5 JXAP 2FU7"),
    ("SM", "SM35 BJXA P2FU 7LZC R4HW 9N1E T67"),
    ("SO", "SO48 BR4H W9N1 ET6K YBQ3 GV7"),
    ("ST", "ST89 BYBQ 3GV8 M0DS 5JXA P2FU 7"),
    ("SV", "SV07 B5JX AP2F U7LZ CR4H W9N1 ET67"),
    ("TL", "TL58 BCR4 HW9N 1ET6 KYBQ 3G7"),
    ("TN", "TN07 BKYB Q3GV 8M0D S5JX AP27"),
    ("TR", "TR05 BS5J XAP2 FU7L ZCR4 HW9N 17"),
    ("UA", "UA45 BZCR 4HW9 N1ET 6KYB Q3GV 8M0D 7"),
    ("VA", "VA84 B6KY BQ3G V8M0 DS5J X7"),
    ("VG", "VG53 BDS5 JXAP 2FU7 LZCR 4HW7"),
    ("XK", "XK83 BLZC R4HW 9N1E T6K7"),
    ("YE", "YE71 BT6K YBQ3 GV8M 0DS5 JXAP 2FU7 L7"),
];

/// (country, corrupted IBAN): a BBAN character changed; verified invalid.
pub const CORRUPT: &[(&str, &str)] = &[
    ("AD", "AD72 0P2F U7LZ CR4H W9N1 ET67"),
    ("AE", "AE58 0W9N 1ET6 KYBQ 3GV8 M07"),
    ("AL", "AL50 03GV 8M0D S5JX AP2F U7LZ CR47"),
    ("AT", "AT84 0AP2 FU7L ZCR4 HW97"),
    ("AZ", "AZ94 0HW9 N1ET 6KYB Q3GV 8M0D S5J7"),
    ("BA", "BA04 0Q3G V8M0 DS5J XAP7"),
    ("BE", "BE21 0XAP 2FU7 LZC7"),
    ("BG", "BG74 04HW 9N1E T6KY BQ3G V7"),
    ("BH", "BH28 0BQ3 GV8M 0DS5 JXAP 27"),
    ("BI", "BI06 0JXA P2FU 7LZC R4HW 9N1E T67"),
    ("BR", "BR50 0R4H W9N1 ET6K YBQ3 GV8M 0DS5 7"),
    ("BY", "BY38 0YBQ 3GV8 M0DS 5JXA P2FU 7LZ7"),
    ("CH", "CH46 05JX AP2F U7LZ CR4H 7"),
    ("CR", "CR89 0CR4 HW9N 1ET6 KYBQ 37"),
    ("CY", "CY43 0KYB Q3GV 8M0D S5JX AP2F U7L7"),
    ("CZ", "CZ63 0S5J XAP2 FU7L ZCR4 HW97"),
    ("DE", "DE47 0ZCR 4HW9 N1ET 6KYB Q7"),
    ("DJ", "DJ68 06KY BQ3G V8M0 DS5J XAP2 FU7"),
    ("DK", "DK80 0DS5 JXAP 2FU7 L7"),
    ("DO", "DO32 0LZC R4HW 9N1E T6KY BQ3G V8M7"),
    ("EE", "EE66 0T6K YBQ3 GV8M 0DS7"),
    ("EG", "EG90 00DS 5JXA P2FU 7LZC R4HW 9N1E 7"),
    ("ES", "ES33 07LZ CR4H W9N1 ET6K YBQ7"),
    ("FI", "FI75 0ET6 KYBQ 3GV8 M7"),
    ("FK", "FK72 0M0D S5JX AP2F U7"),
    ("FO", "FO69 0U7L ZCR4 HW9N 17"),
    ("FR", "FR47 01ET 6KYB Q3GV 8M0D S5JX AP7"),
    ("GB", "GB36 08M0 DS5J XAP2 FU7L Z7"),
    ("GE", "GE39 0FU7 LZCR 4HW9 N1ET 67"),
    ("GI", "GI14 0N1E T6KY BQ3G V8M0 DS7"),
    ("GL", "GL87 0V8M 0DS5 JXAP 27"),
    ("GR", "GR28 02FU 7LZC R4HW 9N1E T6KY BQ7"),
    ("GT", "GT33 09N1 ET6K YBQ3 GV8M 0DS5 JXA7"),
    ("HN", "HN69 0GV8 M0DS 5JXA P2FU 7LZC R4H7"),
    ("HR", "HR63 0P2F U7LZ CR4H W9N1 7"),
    ("HU", "HU72 0W9N 1ET6 KYBQ 3GV8 M0DS 5JX7"),
    ("IE", "IE47 03GV 8M0D S5JX AP2F U7"),
    ("IL", "IL39 0AP2 FU7L ZCR4 HW9N 1E7"),
    ("IQ", "IQ97 0HW9 N1ET 6KYB Q3GV 8M7"),
    ("IS", "IS58 0Q3G V8M0 DS5J XAP2 FU7L Z7"),
    ("IT", "IT46 0XAP 2FU7 LZCR 4HW9 N1ET 6K7"),
    ("JO", "JO46 04HW 9N1E T6KY BQ3G V8M0 DS5J X7"),
    ("KW", "KW08 0BQ3 GV8M 0DS5 JXAP 2FU7 LZCR 47"),
    ("KZ", "KZ56 0JXA P2FU 7LZC R4H7"),
    ("LB", "LB19 0R4H W9N1 ET6K YBQ3 GV8M 0DS7"),
    ("LC", "LC73 0YBQ 3GV8 M0DS 5JXA P2FU 7LZC R4H7"),
    ("LI", "LI59 05JX AP2F U7LZ CR4H 7"),
    ("LT", "LT82 0CR4 HW9N 1ET6 KYB7"),
    ("LU", "LU23 0KYB Q3GV 8M0D S5J7"),
    ("LV", "LV13 0S5J XAP2 FU7L ZCR4 7"),
    ("LY", "LY56 0ZCR 4HW9 N1ET 6KYB Q3GV 7"),
    ("MC", "MC08 06KY BQ3G V8M0 DS5J XAP2 FU7"),
    ("MD", "MD46 0DS5 JXAP 2FU7 LZCR 4HW7"),
    ("ME", "ME31 0LZC R4HW 9N1E T6KY B7"),
    ("MK", "MK16 0T6K YBQ3 GV8M 0D7"),
    ("MN", "MN87 00DS 5JXA P2FU 7LZ7"),
    ("MR", "MR03 07LZ CR4H W9N1 ET6K YBQ3 GV7"),
    ("MT", "MT73 0ET6 KYBQ 3GV8 M0DS 5JXA P2FU 7L7"),
    ("MU", "MU23 0M0D S5JX AP2F U7LZ CR4H W9N1 E7"),
    ("NI", "NI69 0U7L ZCR4 HW9N 1ET6 KYBQ 3GV7"),
    ("NL", "NL60 01ET 6KYB Q3GV 87"),
    ("NO", "NO51 08M0 DS5J XA7"),
    ("OM", "OM25 0FU7 LZCR 4HW9 N1ET 6K7"),
    ("PK", "PK43 0N1E T6KY BQ3G V8M0 DS57"),
    ("PL", "PL28 0V8M 0DS5 JXAP 2FU7 LZCR 4HW7"),
    ("PS", "PS66 02FU 7LZC R4HW 9N1E T6KY BQ3G 7"),
    ("PT", "PT57 09N1 ET6K YBQ3 GV8M 0DS5 7"),
    ("QA", "QA08 0GV8 M0DS 5JXA P2FU 7LZC R4HW 7"),
    ("RO", "RO80 0P2F U7LZ CR4H W9N1 ET67"),
    ("RS", "RS66 0W9N 1ET6 KYBQ 3GV8 M7"),
    ("RU", "RU31 03GV 8M0D S5JX AP2F U7LZ CR4H W9N1 7"),
    ("SA", "SA40 0AP2 FU7L ZCR4 HW9N 1ET7"),
    ("SC", "SC07 0HW9 N1ET 6KYB Q3GV 8M0D S5JX AP7"),
    ("SD", "SD75 0Q3G V8M0 DS5J X7"),
    ("SE", "SE39 0XAP 2FU7 LZCR 4HW9 N1E7"),
    ("SI", "SI15 04HW 9N1E T6KY BQ7"),
    ("SK", "SK04 0BQ3 GV8M 0DS5 JXAP 2FU7"),
    ("SM", "SM35 0JXA P2FU 7LZC R4HW 9N1E T67"),
    ("SO", "SO48 0R4H W9N1 ET6K YBQ3 GV7"),
    ("ST", "ST89 0YBQ 3GV8 M0DS 5JXA P2FU 7"),
    ("SV", "SV07 05JX AP2F U7LZ CR4H W9N1 ET67"),
    ("TL", "TL58 0CR4 HW9N 1ET6 KYBQ 3G7"),
    ("TN", "TN07 0KYB Q3GV 8M0D S5JX AP27"),
    ("TR", "TR05 0S5J XAP2 FU7L ZCR4 HW9N 17"),
    ("UA", "UA45 0ZCR 4HW9 N1ET 6KYB Q3GV 8M0D 7"),
    ("VA", "VA84 06KY BQ3G V8M0 DS5J X7"),
    ("VG", "VG53 0DS5 JXAP 2FU7 LZCR 4HW7"),
    ("XK", "XK83 0LZC R4HW 9N1E T6K7"),
    ("YE", "YE71 0T6K YBQ3 GV8M 0DS5 JXAP 2FU7 L7"),
];

/// registry-published examples, machine-verified (mod-97+length) first.
pub const REGISTRY_EXAMPLES: &[&str] = &[
    "GB82 WEST 1234 5698 7654 32",
    "NL91 ABNA 0417 1643 00",
    "ES91 2100 0418 4502 0005 1332",
    "BE68 5390 0754 7034",
    "CH93 0076 2011 6238 5295 7",
    "AT61 1904 3002 3457 3201",
    "FR14 2004 1010 0505 0001 3M02 606",
    "TR33 0006 1005 1978 6457 8413 26",
    "SE45 5000 0000 0583 9825 7466",
    "PL61 1090 1014 0000 0712 1981 2874",
];

fn ibans(text: &str) -> Vec<(EntityType, String, f32)> {
    detect(text)
        .into_iter()
        .filter(|e| e.kind == EntityType::Iban)
        .map(|e| (e.kind, e.text, e.score))
        .collect()
}

#[test]
fn all_registry_countries_detected() {
    for (cc, iban) in VALID {
        let text = format!("IBAN {iban} kabul edildi.");
        let found = ibans(&text);
        assert_eq!(
            found,
            vec![(EntityType::Iban, (*iban).to_owned(), 1.0)],
            "country {cc}: {found:?} in {text:?}"
        );
    }
}

#[test]
fn corrupt_check_digits_rejected() {
    for (cc, bad) in CORRUPT {
        let text = format!("IBAN {bad} kabul edilmedi.");
        assert!(
            ibans(&text).is_empty(),
            "country {cc} must reject: {text:?}"
        );
    }
}

#[test]
fn registry_examples_detected() {
    for ex in REGISTRY_EXAMPLES {
        let found = ibans(ex);
        assert_eq!(found.len(), 1, "{ex:?}: {found:?}");
        assert_eq!(found[0].1, *ex);
    }
}

#[test]
fn spaceless_form_detected() {
    // spacing is presentation only; the validator strips it
    for ex in ["GB82WEST12345698765432", "NL91ABNA0417164300"] {
        assert!(ibans(&format!("hesap {ex} kapatildi")).len() == 1, "{ex}");
    }
}

#[test]
fn digit_heavy_negatives_produce_no_iban() {
    let negatives = [
        "Sipariş numaranız 12000345671 olarak kaydedildi.",
        "referans 123456789012345678901234 kullanilacak",
        "telefon 0532 123 45 67 arayin",
        "kod 9876 5432 1098 gibi görünüyor",
    ];
    for t in negatives {
        assert!(ibans(t).is_empty(), "false positive on {t:?}");
    }
}

#[test]
fn tr_iban_single_entity_not_duplicated() {
    // both the TR rule and the international rule match; overlap resolution
    // must yield exactly ONE entity with the same span
    let text = "IBAN TR33 0006 1005 1978 6457 8413 26 gecerli";
    assert_eq!(
        ibans(text),
        vec![(
            EntityType::Iban,
            "TR33 0006 1005 1978 6457 8413 26".to_owned(),
            1.0
        )]
    );
    assert_eq!(redact(text), "IBAN [IBAN] gecerli");
}

#[test]
fn threshold_one_keeps_checksum_certain_iban() {
    let ents = Detector::new()
        .with_threshold(0.99)
        .detect("GB82 WEST 1234 5698 7654 32");
    assert_eq!(ents.len(), 1);
}
