//! The India GSTIN and Aadhaar rules and the `kr`, `ng`, `ph`, `za` and
//! `th` packs.
//!
//! Golden vectors come from the official sources cited in each module doc
//! (synthetic structural values are marked as such), followed by cue /
//! no-cue behavior, cross-locale collisions with every pack enabled, the
//! registration order the tier-0 13-digit rules rely on, and the
//! Verhoeff-only rule of the Aadhaar validator.

use redactify::{
    detect, valid_in_aadhaar, valid_in_gstin, valid_kr_brn, valid_kr_frn, valid_kr_passport,
    valid_kr_rrn, valid_luhn, valid_ng_nin, valid_ph_tin, valid_th_tnin,
    valid_za_company_registration, valid_za_id_number, valid_za_phone, valid_za_tax_reference,
    valid_za_vat, DetectionSource, Detector, Entity, EntityType, SUPPORTED_LOCALES,
};

/// The packs under test.
const PACKS: &[&str] = &["kr", "ng", "ph", "za", "th"];

/// Entity types only the rules of these packs produce.
const PACK_TYPES: &[EntityType] = &[
    EntityType::InGstin,
    EntityType::KrBrn,
    EntityType::KrFrn,
    EntityType::KrPassport,
    EntityType::KrRrn,
    EntityType::NgNin,
    EntityType::PhTin,
    EntityType::ZaIdNumber,
    EntityType::ZaTaxReference,
    EntityType::ZaVat,
    EntityType::ZaCompanyRegistration,
    EntityType::ThTnin,
];

fn run(text: &str, locales: &[&str]) -> Vec<Entity> {
    Detector::new().with_locales(locales).detect(text)
}

fn all(text: &str) -> Vec<Entity> {
    run(text, SUPPORTED_LOCALES)
}

/// The single entity of `ents`, or a panic naming the text.
fn one(text: &str, ents: &[Entity]) -> (EntityType, String) {
    assert_eq!(ents.len(), 1, "{text:?}: {ents:?}");
    (ents[0].kind, ents[0].text.clone())
}

// ---------------------------------------------------------------- vectors

#[test]
fn official_valid_vectors() {
    // SARS PAYE BRS v21.2 8.3 / 8.1 worked examples
    assert!(valid_za_id_number("8001015009087"));
    assert!(valid_za_id_number("800101 5009 087"));
    assert!(valid_za_tax_reference("0001339050"));
    assert!(valid_za_tax_reference("0667056642"));
    // Notice 1762 of 1999 examples
    assert!(valid_za_company_registration("2000/000001/07"));
    assert!(valid_za_company_registration("1999/012345/07"));
    // MCST/MOFA press release (2018-10-15) examples
    assert!(valid_kr_passport("M12345678"));
    assert!(valid_kr_passport("M123A4567"));
    // ICASA Numbering Plan Regulations 15(4): test range 0XX 114
    assert!(valid_za_phone("011 114 5678"));
    // UIDAI-scheme Aadhaar vectors
    for v in ["607324134360", "397065334700", "518467770056"] {
        assert!(valid_in_aadhaar(v), "{v}");
    }
}

#[test]
fn structural_vectors_and_derived_invalids() {
    // synthetic structural values (no official full number published)
    assert!(valid_in_gstin("27AFZPK7190K1Z5")); // OECD India PAN example inside
    assert!(valid_kr_rrn("850102-1234567")); // NTS example birth date
    assert!(valid_kr_frn("850102-5123456"));
    assert!(valid_kr_brn("123-45-67890"));
    assert!(valid_ng_nin("12345678901"));
    assert!(valid_ph_tin("123-456-789"));
    assert!(valid_th_tnin("1234567890123"));
    assert!(valid_za_vat("4123456789"));
    assert!(valid_za_phone("082 123 4567"));
    for (ok, v) in [
        (
            valid_in_gstin("27AFZDK7190K1Z5"),
            "GSTIN PAN holder letter D",
        ),
        (valid_in_gstin("27AFZPK0000K1Z5"), "GSTIN PAN serial 0000"),
        (valid_in_gstin("27AFZPK7190K1Z"), "GSTIN 14 characters"),
        (valid_kr_rrn("850230-1234567"), "RRN 30 February"),
        (valid_kr_rrn("850102-0234567"), "RRN gender digit 0"),
        (valid_kr_rrn("850102-5234567"), "RRN with a foreigner digit"),
        (valid_kr_frn("851302-5123456"), "FRN month 13"),
        (valid_kr_frn("850102-9123456"), "FRN gender digit 9"),
        (valid_kr_brn("123-45-6789"), "BRN 3-2-4"),
        (valid_kr_brn("1234-56-78901"), "BRN 4-2-5"),
        (valid_kr_passport("M1234A567"), "passport letter misplaced"),
        (
            valid_kr_passport("MM23A4567"),
            "passport two leading letters",
        ),
        (valid_ng_nin("1234567890"), "NIN 10 digits"),
        (valid_ng_nin("123456789012"), "NIN 12 digits"),
        (valid_ph_tin("123-456-78"), "TIN 8 digits"),
        (valid_th_tnin("0123456789012"), "TNIN person type 0"),
        (valid_th_tnin("9123456789012"), "TNIN person type 9"),
        (valid_th_tnin("6012345678901"), "TNIN prefix 601"),
        (valid_za_id_number("8001015009088"), "ZA ID control figure"),
        (valid_za_id_number("8002305009084"), "ZA ID 30 February"),
        (valid_za_id_number("8001015009384"), "ZA ID citizenship 3"),
        (valid_za_tax_reference("0001339051"), "tax ref check digit"),
        (
            valid_za_tax_reference("4001339052"),
            "tax ref first digit 4",
        ),
        (valid_za_tax_reference("7230767891"), "SARS PAYE reference"),
        (valid_za_vat("412345678"), "VAT 9 digits"),
        (
            valid_za_company_registration("2000/000001/05"),
            "company suffix",
        ),
        (
            valid_za_company_registration("1799/000001/07"),
            "company year",
        ),
        (
            valid_za_company_registration("2000/00001/07"),
            "company serial",
        ),
        (valid_za_phone("080 123 4567"), "toll free"),
        (valid_za_phone("019 123 4567"), "protected area code"),
    ] {
        assert!(!ok, "{v}");
    }
    // the derived ZA invalids that pass Luhn are rejected for the stated
    // reason only
    assert!(valid_luhn("8002305009084") && valid_luhn("8001015009384"));
}

// ---------------------------------------------------------------- cue policy

#[test]
fn cue_gated_rules_need_their_cue() {
    let cases: &[(&str, &str, &str, EntityType)] = &[
        (
            "in",
            "invoice 27AFZPK7190K1Z5 paid",
            "GSTIN 27AFZPK7190K1Z5",
            EntityType::InGstin,
        ),
        (
            "kr",
            "order 850102-1234567",
            "주민등록번호 850102-1234567",
            EntityType::KrRrn,
        ),
        (
            "kr",
            "order 850102-5123456",
            "외국인등록번호 850102-5123456",
            EntityType::KrFrn,
        ),
        (
            "kr",
            "ref 123-45-67890",
            "사업자등록번호 123-45-67890",
            EntityType::KrBrn,
        ),
        (
            "kr",
            "ticket M123A4567",
            "여권번호 M123A4567",
            EntityType::KrPassport,
        ),
        (
            "ng",
            "order 12345678901",
            "NIN: 12345678901",
            EntityType::NgNin,
        ),
        (
            "ph",
            "ref 123-456-789",
            "TIN: 123-456-789",
            EntityType::PhTin,
        ),
        ("ph", "ref 123456789", "TIN no 123456789", EntityType::PhTin),
        (
            "th",
            "order 1234567890123",
            "บัตรประชาชน 1234567890123",
            EntityType::ThTnin,
        ),
        (
            "za",
            "batch 0001339050",
            "SARS tax ref 0001339050",
            EntityType::ZaTaxReference,
        ),
        (
            "za",
            "batch 4123456789",
            "VAT no 4123456789",
            EntityType::ZaVat,
        ),
        (
            "za",
            "file 2000/000001/07",
            "CIPC 2000/000001/07",
            EntityType::ZaCompanyRegistration,
        ),
    ];
    for (pack, bare, cued, kind) in cases {
        assert!(
            run(bare, &[pack]).is_empty(),
            "{bare:?}: {:?}",
            run(bare, &[pack])
        );
        let ents = run(cued, &[pack]);
        assert_eq!(one(cued, &ents).0, *kind, "{cued:?}");
    }
}

#[test]
fn cue_less_rules_and_scores() {
    let za = run("client 8001015009087 on file", &["za"]);
    assert_eq!(one("za id", &za).0, EntityType::ZaIdNumber);
    assert!((za[0].score - 1.0).abs() < f32::EPSILON);
    let phone = run("call 011 114 5678 now", &["za"]);
    assert_eq!(one("za phone", &phone).0, EntityType::Phone);
    assert!((phone[0].score - 0.80).abs() < 1e-6);
    let tax = run("SARS tax ref 0001339050", &["za"]);
    assert!((tax[0].score - 1.0).abs() < f32::EPSILON); // checksum verified
    let rrn = run("RRN 850102-1234567", &["kr"]);
    assert!((rrn[0].score - 0.9).abs() < 1e-6); // format + mandatory cue
}

#[test]
fn cue_words_fit_the_window_and_substring_traps_stay_silent() {
    // the longest cue of each rule still matches behind a separator
    for (pack, text, kind) in [
        ("th", "เลขประจำตัวประชาชน: 1234567890123", EntityType::ThTnin),
        ("kr", "외국인등록번호: 850102-5123456", EntityType::KrFrn),
        (
            "za",
            "close corporation 2000/000001/23",
            EntityType::ZaCompanyRegistration,
        ),
        (
            "za",
            "registration no: 2000/000001/23",
            EntityType::ZaCompanyRegistration,
        ),
        ("ng", "national ID: 12345678901", EntityType::NgNin),
    ] {
        assert_eq!(one(text, &run(text, &[pack])).0, kind, "{text}");
    }
    // bare "nin" / "tin" / "gst" are not cues
    for (pack, text) in [
        ("ng", "running 12345678901 laps"),
        ("ng", "dining 12345678901 table"),
        ("ph", "continue 123456789 later"),
        ("ph", "setting 123-456-789 value"),
        ("in", "angstrom 27AFZPK7190K1Z5 unit"),
    ] {
        assert!(
            run(text, &[pack]).is_empty(),
            "{text}: {:?}",
            run(text, &[pack])
        );
    }
}

// ---------------------------------------------------------------- collisions

#[test]
fn ids_are_claimed_once_with_every_pack_enabled() {
    for (text, kind, value) in [
        (
            "GSTIN: 27AFZPK7190K1Z5",
            EntityType::InGstin,
            "27AFZPK7190K1Z5",
        ),
        (
            "주민등록번호 850102-1234567",
            EntityType::KrRrn,
            "850102-1234567",
        ),
        (
            "외국인등록번호 850102-5123456",
            EntityType::KrFrn,
            "850102-5123456",
        ),
        (
            "사업자등록번호 123-45-67890",
            EntityType::KrBrn,
            "123-45-67890",
        ),
        ("여권번호 M12345678", EntityType::KrPassport, "M12345678"),
        ("여권번호 M123A4567", EntityType::KrPassport, "M123A4567"),
        ("NIN: 12345678901", EntityType::NgNin, "12345678901"),
        ("TIN: 123-456-789", EntityType::PhTin, "123-456-789"),
        ("TIN no 123456789", EntityType::PhTin, "123456789"),
        (
            "บัตรประชาชน 1234567890123",
            EntityType::ThTnin,
            "1234567890123",
        ),
        ("ID 8001015009087", EntityType::ZaIdNumber, "8001015009087"),
        (
            "ID 800101 5009 087",
            EntityType::ZaIdNumber,
            "800101 5009 087",
        ),
        (
            "SARS tax reference 0001339050",
            EntityType::ZaTaxReference,
            "0001339050",
        ),
        ("VAT no 4123456789", EntityType::ZaVat, "4123456789"),
        (
            "CIPC reg no 2000/000001/07",
            EntityType::ZaCompanyRegistration,
            "2000/000001/07",
        ),
        ("call 082 123 4567 today", EntityType::Phone, "082 123 4567"),
        // 07x: the fr/nl mobile rules claim the same span with the same label
        ("call 071 123 4567 today", EntityType::Phone, "071 123 4567"),
    ] {
        let ents = all(text);
        let (k, t) = one(text, &ents);
        assert_eq!((k, t.as_str()), (kind, value), "{text:?}");
    }
}

#[test]
fn tier_0_13_digit_ids_beat_the_card_rule() {
    // Luhn-passing values: without their pack the card rule claims them
    for (pack, text, kind) in [
        ("kr", "RRN 8501021234561", EntityType::KrRrn),
        ("kr", "FRN 8501025123455", EntityType::KrFrn),
        ("th", "Thai ID 1234567890128", EntityType::ThTnin),
        ("za", "ID 8001015009087", EntityType::ZaIdNumber),
    ] {
        let digits: String = text.chars().filter(char::is_ascii_digit).collect();
        assert!(valid_luhn(&digits), "{digits}");
        assert_eq!(
            one(text, &run(text, &[])).0,
            EntityType::CreditCard,
            "{text}"
        );
        assert_eq!(one(text, &run(text, &[pack])).0, kind, "{text}");
        assert_eq!(one(text, &all(text)).0, kind, "{text}");
    }
}

#[test]
fn kr_and_th_are_registered_before_za() {
    // values that are ALSO valid ZA identity numbers (date + citizenship
    // digit + Luhn): a cued Korean/Thai number keeps its label on the
    // equal-tier, equal-span tie; without the cue the ZA rule claims it
    for (text, bare, kind) in [
        (
            "주민등록번호 8501021234082",
            "client 8501021234082",
            EntityType::KrRrn,
        ),
        (
            "외국인등록번호 8501025234088",
            "client 8501025234088",
            EntityType::KrFrn,
        ),
        (
            "บัตรประชาชน 1001015009084",
            "client 1001015009084",
            EntityType::ThTnin,
        ),
    ] {
        let digits: String = text.chars().filter(char::is_ascii_digit).collect();
        assert!(valid_za_id_number(&digits), "{digits}");
        assert_eq!(one(text, &all(text)).0, kind, "{text}");
        assert_eq!(one(text, &run(text, &["za"])).0, EntityType::ZaIdNumber);
        assert_eq!(
            one(bare, &run(bare, &["kr", "th", "za"])).0,
            EntityType::ZaIdNumber
        );
    }
}

#[test]
fn shared_shapes_resolve_as_documented() {
    // SARS tax reference vs the format-only UK UTR on the shared cue
    // "tax reference": checksum beats structural (tier 3 over tier 7)
    let t = "tax reference 0001339050";
    assert_eq!(one(t, &run(t, &["uk"])).0, EntityType::UkUtr);
    assert_eq!(one(t, &run(t, &["uk", "za"])).0, EntityType::ZaTaxReference);
    // ... and a UTR cue alone keeps the UK label
    let utr = "UTR 0001339050";
    assert_eq!(one(utr, &run(utr, &["uk", "za"])).0, EntityType::UkUtr);
    // a K-prefixed UTR is never cut short by the tier-3 rule
    let k = "tax reference K0001339050";
    let ents = run(k, &["uk", "za"]);
    assert_eq!(one(k, &ents), (EntityType::UkUtr, "K0001339050".to_owned()));
    // SARS example 2 also passes the Polish NIP checksum: the tier-3 SARS
    // rule keeps it when both cues are present
    let nip = "tax number 0667056642";
    assert_eq!(one(nip, &run(nip, &["pl"])).0, EntityType::PlNip);
    assert_eq!(
        one(nip, &run(nip, &["pl", "za"])).0,
        EntityType::ZaTaxReference
    );
    // the earlier Korean passport format is the US passport shape: with
    // the shared English cue the en pack (registered first) keeps it, the
    // Korean cue selects the Korean label
    let p = "passport no M12345678";
    assert_eq!(one(p, &all(p)).0, EntityType::UsPassport);
    assert_eq!(one(p, &run(p, &["kr"])).0, EntityType::KrPassport);
    // an 11-digit NIN that also passes both TCKN check digits keeps the
    // cue-less TCKN label when tr is on (masked either way)
    let n = "NIN: 12345678950";
    assert_eq!(one(n, &run(n, &["ng"])).0, EntityType::NgNin);
    assert_eq!(one(n, &run(n, &["tr", "ng"])).0, EntityType::Tckn);
    // a bare nine-digit PH TIN in the ITIN number space (9xx, middle group
    // 70-88) next to "tin" keeps the ITIN label of the default en pack
    // (tier 6 over tier 7; masked either way)
    let itin = "TIN no 912701234";
    assert_eq!(one(itin, &run(itin, &["ph"])).0, EntityType::PhTin);
    assert_eq!(one(itin, &run(itin, &["en", "ph"])).0, EntityType::Itin);
    // a country-prefixed EU VAT number is not cut short by the ZA VAT rule
    let eu = "VAT number PL4123456789";
    assert!(run(eu, &["za"]).is_empty());
    // a 13-digit card number that is also a valid ZA identity number
    // (plausible date, citizenship digit, Luhn) takes the ZA label when za
    // is on; one with an impossible date stays a card
    let card = "card 4001015009081";
    assert_eq!(one(card, &run(card, &["za"])).0, EntityType::ZaIdNumber);
    let visa = "card 4222222222222";
    assert_eq!(one(visa, &run(visa, &["za"])).0, EntityType::CreditCard);
}

#[test]
fn packs_do_not_change_other_packs_results() {
    let cases: &[(&str, &[&str])] = &[
        ("TCKN 12345678950", &["tr"]),
        ("vergi no 1234567890", &["tr"]),
        ("Cep 0532 123 45 67", &["tr"]),
        ("ofis 0212 555 44 33", &["tr"]),
        ("Plaka 34 ABC 123", &["tr"]),
        ("kart 4111 1111 1111 1111", &["tr"]),
        ("SSN 536-90-6292", &["en"]),
        ("call (310) 555-0199", &["en"]),
        ("US passport A12345678", &["en"]),
        ("PESEL 80010123450", &["pl"]),
        ("NIP 123-456-32-18", &["pl"]),
        ("NHS 943 476 5919", &["uk"]),
        ("UTR 1234567890", &["uk"]),
        ("BSN 111222333", &["nl"]),
        ("SIN 046 454 286", &["ca"]),
        ("TFN 123 456 782", &["au"]),
        ("Aadhaar 607324134360", &["in"]),
        ("PAN: AAAPL1234C", &["in"]),
        ("personnummer 640823-3234", &["se"]),
        ("CPR 070761-4285", &["dk"]),
        ("身份号码 440524188001010014", &["cn"]),
        ("06 12 34 56 78", &["fr"]),
        ("VAT DE123456789", &["eu"]),
    ];
    for (text, own) in cases {
        let base = run(text, own);
        let mut with_packs = own.to_vec();
        with_packs.extend_from_slice(PACKS);
        let after = run(text, &with_packs);
        assert_eq!(base, after, "packs changed {text:?}");
        assert!(
            after.iter().all(|e| !PACK_TYPES.contains(&e.kind)),
            "{text:?}: {after:?}"
        );
    }
}

#[test]
fn pack_types_never_appear_with_the_default_locales() {
    for text in [
        "GSTIN: 27AFZPK7190K1Z5",
        "주민등록번호 850102-1234567",
        "외국인등록번호 850102-5123456",
        "사업자등록번호 123-45-67890",
        "여권번호 M123A4567",
        "NIN: 12345678901",
        "TIN: 123-456-789",
        "บัตรประชาชน 1234567890123",
        "ID 8001015009087",
        "SARS tax ref 0001339050",
        "VAT no 4123456789",
        "CIPC 2000/000001/07",
    ] {
        let ents = detect(text);
        assert!(
            ents.iter().all(|e| !PACK_TYPES.contains(&e.kind)),
            "{text:?}: {ents:?}"
        );
    }
}

#[test]
fn rule_ids_name_their_modules() {
    let d = Detector::new().with_locales(SUPPORTED_LOCALES);
    for (text, id) in [
        ("GSTIN: 27AFZPK7190K1Z5", "in_::gstin"),
        ("주민등록번호 850102-1234567", "kr::rrn"),
        ("외국인등록번호 850102-5123456", "kr::frn"),
        ("사업자등록번호 123-45-67890", "kr::brn"),
        ("여권번호 M123A4567", "kr::passport"),
        ("NIN: 12345678901", "ng::nin"),
        ("TIN: 123-456-789", "ph::tin"),
        ("TIN no 123456789", "ph::tin_bare"),
        ("บัตรประชาชน 1234567890123", "th::tnin"),
        ("ID 8001015009087", "za::id_number"),
        ("SARS tax ref 0001339050", "za::tax_reference"),
        ("VAT no 4123456789", "za::vat"),
        ("CIPC 2000/000001/07", "za::company_registration"),
        ("call 082 123 4567", "za::phone"),
    ] {
        let explained = d.explain(text);
        assert_eq!(explained.len(), 1, "{text}: {explained:?}");
        assert!(
            matches!(explained[0].1.source, DetectionSource::Rule { id: got } if got == id),
            "{text}: {:?}",
            explained[0].1.source
        );
    }
}

#[test]
fn locale_codes_are_supported() {
    for code in PACKS {
        assert!(SUPPORTED_LOCALES.contains(code), "{code}");
    }
}

// ---------------------------------------------------------------- Aadhaar

#[test]
fn aadhaar_palindromes_follow_verhoeff_only() {
    // no official source rejects palindromes: 80,153 of the 800,000
    // twelve-digit palindromes with a first digit 2-9 pass Verhoeff and
    // are valid
    for v in ["200009900002", "333333333333", "999999999999"] {
        assert!(valid_in_aadhaar(v), "{v}");
        let text = format!("Aadhaar {v} linked");
        assert_eq!(one(&text, &run(&text, &["in"])).0, EntityType::InAadhaar);
    }
    // palindromes failing Verhoeff stay invalid
    assert!(!valid_in_aadhaar("222222222222"));
    assert!(!valid_in_aadhaar("200000000002"));
}

// ---------------------------------------------------------------- crosscheck

#[test]
fn crosscheck_rows_agree_for_these_validators() {
    // the rows of data/validator_crosscheck.jsonl for the validators of
    // this file (the full file is checked, with its row-count contract, by
    // tests/validator_crosscheck.rs)
    let Ok(data) = std::fs::read_to_string("data/validator_crosscheck.jsonl") else {
        eprintln!("SKIP: data/validator_crosscheck.jsonl not present");
        return;
    };
    let validate = |name: &str, value: &str| -> Option<bool> {
        Some(match name {
            "valid_in_aadhaar" => valid_in_aadhaar(value),
            "valid_in_gstin" => valid_in_gstin(value),
            "valid_kr_brn" => valid_kr_brn(value),
            "valid_kr_frn" => valid_kr_frn(value),
            "valid_kr_passport" => valid_kr_passport(value),
            "valid_kr_rrn" => valid_kr_rrn(value),
            "valid_ng_nin" => valid_ng_nin(value),
            "valid_ph_tin" => valid_ph_tin(value),
            "valid_th_tnin" => valid_th_tnin(value),
            "valid_za_company_registration" => valid_za_company_registration(value),
            "valid_za_id_number" => valid_za_id_number(value),
            "valid_za_phone" => valid_za_phone(value),
            "valid_za_tax_reference" => valid_za_tax_reference(value),
            "valid_za_vat" => valid_za_vat(value),
            _ => return None,
        })
    };
    let mut checked = 0usize;
    let mut mismatches = Vec::new();
    for line in data.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).expect("jsonl row");
        let name = v["validator"].as_str().expect("validator");
        let value = v["value"].as_str().expect("value");
        let expected = v["expected"].as_bool().expect("expected");
        if let Some(got) = validate(name, value) {
            checked += 1;
            if got != expected {
                mismatches.push(format!(
                    "{name}({value:?}) = {got}, reference says {expected}"
                ));
            }
        }
    }
    assert!(
        checked > 0,
        "no rows for these validators in the crosscheck file"
    );
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}
