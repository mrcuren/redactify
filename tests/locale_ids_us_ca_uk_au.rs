//! US (`en`), Canada (`ca`), UK (`uk`) and Australia (`au`) identifiers
//! from official sources, including the SSA rules of `en::ssn` and the
//! Royal Mail letter classes of `uk::postcode`.
//!
//! Every valid vector below is an official example (IRS, 12 CFR 229, CMS,
//! Canada Post, DVLA, Royal Mail, ASIC, SSA) unless marked "derived"; the
//! invalid vectors break exactly one rule the source states.

use redactify::{
    detect, valid_au_acn, valid_ca_postal_code, valid_ssn, valid_uk_driving_licence,
    valid_uk_vehicle_reg, valid_us_aba_routing, valid_us_ein, valid_us_mbi, valid_us_npi,
    DetectionSource, Detector, EntityType, SUPPORTED_LOCALES,
};

/// `(kind, matched text)` for every entity with the given locales.
fn found(text: &str, locales: &[&str]) -> Vec<(EntityType, String)> {
    Detector::new()
        .with_locales(locales)
        .detect(text)
        .into_iter()
        .map(|e| (e.kind, e.text))
        .collect()
}

/// Every pack enabled.
fn all(text: &str) -> Vec<(EntityType, String)> {
    found(text, SUPPORTED_LOCALES)
}

fn one(kind: EntityType, value: &str) -> Vec<(EntityType, String)> {
    vec![(kind, value.to_owned())]
}

/// The kinds of every entity with the given locales.
fn kinds(text: &str, locales: &[&str]) -> Vec<EntityType> {
    found(text, locales).into_iter().map(|(k, _)| k).collect()
}

/// Entity types of the rules under test.
const OWN_KINDS: &[EntityType] = &[
    EntityType::UsAbaRouting,
    EntityType::UsMbi,
    EntityType::UsNpi,
    EntityType::UsEin,
    EntityType::CaPostalCode,
    EntityType::UkDrivingLicence,
    EntityType::UkVehicleRegistration,
    EntityType::AuAcn,
];

// ------------------------------------------------------------ validators

#[test]
fn aba_routing_official_vectors() {
    // IRS Pub 1346 worked example; 12 CFR 229 App. A table entries
    for v in [
        "120139013",
        "0110 0001 5",
        "0711 0711 0",
        "1119 1083 0",
        "1210 0037 4",
        "1250 0050 3",
    ] {
        assert!(valid_us_aba_routing(v), "{v}");
    }
    // IRS 1040 sample-check illustration (weighted sum 101)
    assert!(!valid_us_aba_routing("250250025"));
    // derived: check digit off, prefixes outside 01-12 / 21-32
    for v in [
        "120139014",
        "410000001",
        "610000005",
        "800000006",
        "0110-0001-5",
    ] {
        assert!(!valid_us_aba_routing(v), "{v}");
    }
}

#[test]
fn npi_official_vectors() {
    assert!(valid_us_npi("1234567893")); // CMS worked example
    for v in ["1234567890", "1234567894", "3234567893", "808401234567893"] {
        assert!(!valid_us_npi(v), "{v}");
    }
}

#[test]
fn mbi_official_vectors() {
    assert!(valid_us_mbi("1EG4-TE5-MK73")); // CMS example
    assert!(valid_us_mbi("1EG4TE5MK73"));
    // derived: position 1 = 0, excluded letter, numeric position 11,
    // a single dash, lowercase
    for v in [
        "0EG4TE5MK73",
        "1SG4TE5MK73",
        "1EG4TE5MK7A",
        "1EG4-TE5MK73",
        "1eg4te5mk73",
    ] {
        assert!(!valid_us_mbi(v), "{v}");
    }
}

#[test]
fn ein_prefix_table() {
    // derived (the IRS publishes no full example EIN): campus prefixes
    assert!(valid_us_ein("10-1234567")); // Andover
    assert!(valid_us_ein("31-0000001")); // Small Business Administration
    for v in [
        "07-1234567",
        "00-1234567",
        "49-1234567",
        "123456789",
        "10-123456",
    ] {
        assert!(!valid_us_ein(v), "{v}");
    }
}

#[test]
fn ca_postal_code_official_vectors() {
    assert!(valid_ca_postal_code("T0L 1K0")); // Canada Post guide
    assert!(valid_ca_postal_code("T0L1K0"));
    assert!(!valid_ca_postal_code("T0L-1K0")); // "unacceptable format"
    for v in ["D0L 1K0", "W1A 1A1", "t0l 1k0"] {
        assert!(!valid_ca_postal_code(v), "{v}");
    }
}

#[test]
fn uk_driving_licence_official_vectors() {
    assert!(valid_uk_driving_licence("MORGA 657054 SM 9IJ")); // DVLA INS57P
    assert!(valid_uk_driving_licence("MORGA657054SM9IJ"));
    assert!(valid_uk_driving_licence("MAN99657054SM9IJ")); // derived: INS57P padding
    for v in ["MORGA613054SM9IJ", "MORGA657354SM9IJ", "MO9GA657054SM9IJ"] {
        assert!(!valid_uk_driving_licence(v), "{v}");
    }
}

#[test]
fn uk_vehicle_registration_official_vectors() {
    // DVLA registration styles + the INF104 plate illustration
    for v in ["AA68 ABC", "AA68ABC", "A123 ABC", "ABC 123A", "BD51 SMR"] {
        assert!(valid_uk_vehicle_reg(v), "{v}");
    }
    // dateless style (out of scope) and derived INF104 violations
    for v in [
        "AEZ 121", "AA01 ABC", "IA51 ABC", "QA51 ABC", "AZ51 ABC", "TA51 ABC",
    ] {
        assert!(!valid_uk_vehicle_reg(v), "{v}");
    }
}

#[test]
fn acn_official_vectors() {
    // ASIC worked example and entries of its valid-ACN list
    for v in ["004 085 616", "000 000 019", "005 999 977", "010 749 961"] {
        assert!(valid_au_acn(v), "{v}");
    }
    // ASIC display illustration and derived check-digit breaks
    for v in ["123 456 789", "004 085 617", "000 000 018"] {
        assert!(!valid_au_acn(v), "{v}");
    }
}

// ------------------------------------------------------ cue / no cue

#[test]
fn each_rule_needs_its_cue() {
    let cases: &[(&str, &str, EntityType, &str, &str)] = &[
        // (locale, cued text, kind, value, the same value without a cue)
        (
            "en",
            "routing number 120139013",
            EntityType::UsAbaRouting,
            "120139013",
            "order 120139013 shipped",
        ),
        (
            "en",
            "NPI: 1234567893",
            EntityType::UsNpi,
            "1234567893",
            "batch 1234567893 shipped",
        ),
        (
            "en",
            "MBI 1EG4-TE5-MK73",
            EntityType::UsMbi,
            "1EG4-TE5-MK73",
            "part 1EG4-TE5-MK73 shipped",
        ),
        (
            "en",
            "EIN: 10-1234567",
            EntityType::UsEin,
            "10-1234567",
            "lot 10-1234567 shipped",
        ),
        (
            "ca",
            "postal code T0L 1K0",
            EntityType::CaPostalCode,
            "T0L 1K0",
            "office T0L 1K0 today",
        ),
        (
            "uk",
            "driving licence MORGA 657054 SM 9IJ",
            EntityType::UkDrivingLicence,
            "MORGA 657054 SM 9IJ",
            "ref MORGA 657054 SM 9IJ filed",
        ),
        (
            "uk",
            "number plate AA68 ABC",
            EntityType::UkVehicleRegistration,
            "AA68 ABC",
            "model AA68 ABC launched",
        ),
        (
            "au",
            "ACN 004 085 616",
            EntityType::AuAcn,
            "004 085 616",
            "order 004 085 616 shipped",
        ),
    ];
    for &(locale, cued, kind, value, bare) in cases {
        assert_eq!(found(cued, &[locale]), one(kind, value), "{cued}");
        assert_eq!(all(cued), one(kind, value), "all packs: {cued}");
        assert!(found(bare, &[locale]).is_empty(), "{bare}");
        assert!(all(bare).is_empty(), "all packs: {bare}");
    }
}

#[test]
fn score_reflects_checksum_or_format() {
    let score = |text: &str, locale: &str| {
        let ents = Detector::new().with_locales(&[locale]).detect(text);
        assert_eq!(ents.len(), 1, "{text}: {ents:?}");
        ents[0].score
    };
    // checksum verified: 1.0; format + mandatory cue: 0.9
    assert_eq!(score("routing 120139013", "en"), 1.0);
    assert_eq!(score("NPI 1234567893", "en"), 1.0);
    assert_eq!(score("ACN 004 085 616", "au"), 1.0);
    assert_eq!(score("MBI: 1EG4TE5MK73", "en"), 0.9);
    assert_eq!(score("EIN: 10-1234567", "en"), 0.9);
    assert_eq!(score("postcode T0L 1K0", "ca"), 0.9);
    assert_eq!(score("DVLA MORGA657054SM9IJ", "uk"), 0.9);
    assert_eq!(score("VRN ABC 123A", "uk"), 0.9);
}

#[test]
fn substring_traps_do_not_unlock() {
    for text in [
        "database 120139013",      // "aba" inside a word
        "partner 120139013",       // "rtn" inside a word
        "unpin 1234567893",        // "npi" inside a word
        "combine 1EG4TE5MK73",     // "mbi" inside a word
        "being 10-1234567",        // "ein" inside a word
        "acne 004 085 616",        // "acn" inside a word
        "regular A123 ABC",        // "reg" inside a word
        "classname536906292",      // "ssn" inside a word
        "security code 536906292", // broad SSN boost word
    ] {
        assert!(all(text).is_empty(), "{text}: {:?}", all(text));
    }
}

#[test]
fn us_rules_are_in_the_default_pack() {
    // the en rules ship in the default tr+en set
    let kinds: Vec<EntityType> = detect(
        "routing 120139013, NPI 1234567893, MBI 1EG4TE5MK73, EIN: 10-1234567, SSN: 536906292",
    )
    .into_iter()
    .map(|e| e.kind)
    .collect();
    assert_eq!(
        kinds,
        vec![
            EntityType::UsAbaRouting,
            EntityType::UsNpi,
            EntityType::UsMbi,
            EntityType::UsEin,
            EntityType::Ssn,
        ]
    );
    // the opt-in packs stay opt-in
    assert!(detect("postal code T0L 1K0").is_empty());
    assert!(detect("ACN 004 085 616").is_empty());
    assert!(detect("DVLA MORGA657054SM9IJ").is_empty());
    assert!(detect("number plate AA68 ABC").is_empty());
}

#[test]
fn explain_names_each_rule_and_its_cue() {
    for (text, locale, id, cue) in [
        ("routing 120139013", "en", "en::aba_routing", "routing"),
        ("NPI: 1234567893", "en", "en::npi", "npi:"),
        ("MBI: 1EG4TE5MK73", "en", "en::mbi", "mbi:"),
        ("EIN: 10-1234567", "en", "en::ein", "ein:"),
        ("SSN: 536906292", "en", "en::ssn_bare", "ssn:"),
        (
            "postal code T0L 1K0",
            "ca",
            "ca::postal_code",
            "postal code",
        ),
        ("DVLA MORGA657054SM9IJ", "uk", "uk::driving_licence", "dvla"),
        ("VRN AA68 ABC", "uk", "uk::vehicle_reg", "vrn"),
        ("VRN A123 ABC", "uk", "uk::vehicle_reg_prefix", "vrn"),
        ("VRN ABC 123A", "uk", "uk::vehicle_reg_suffix", "vrn"),
        ("ACN: 004 085 616", "au", "au::acn", "acn:"),
    ] {
        let explained = Detector::new().with_locales(&[locale]).explain(text);
        assert_eq!(explained.len(), 1, "{text}: {explained:?}");
        let why = &explained[0].1;
        assert_eq!(why.source, DetectionSource::Rule { id }, "{text}");
        assert_eq!(why.cue.as_deref(), Some(cue), "{text}");
        assert!(why.validator_passed, "{text}");
    }
}

// ------------------------------------------------------- collisions

#[test]
fn other_packs_shapes_keep_their_labels_with_every_pack_on() {
    // similar digit and letter shapes of other packs, each with its own
    // cue: none may be relabeled as a type of this file
    for text in [
        "TFN 100 010 747",
        "tax file number 100010747",
        "abn 51 824 753 556",
        "medicare 2123 45670 1",
        "SIN: 123-456-782",
        "passport 123456789",
        "BSN 111222333",
        "NHS 943 476 5919",
        "NINO AB 12 34 56 C",
        "vergi no 1234567890",
        "TCKN 12345678950",
        "plaka 34 ABC 123",
        "license plate 34 ABC 123",
        "SWIFT DEUTDEFF",
        "bank routing DEUTDEFF",
        "codice fiscale MRTMTT91D08F205J",
        "PAN: ABCPE1234F",
        "NRIC S1234567D",
        "postcode SW1A 1AA",
        "PLZ: 10115",
        "zip 90210",
        "ITIN 912-70-1234",
        "SSN 536-90-6292",
        "US passport A12345678",
        "IBAN TR33 0006 1005 1978 6457 8413 26",
        "card 4111 1111 1111 1111",
        "call (416) 555-0142",
    ] {
        for (kind, value) in all(text) {
            assert!(
                !OWN_KINDS.contains(&kind),
                "{text:?}: {value:?} relabeled as {kind:?}"
            );
        }
    }
}

#[test]
fn own_values_keep_their_labels_with_every_pack_on() {
    // each official vector, cued, yields exactly its own type with every
    // pack on (no same-span claim of another pack wins)
    for (text, kind, value) in [
        (
            "ABA routing 0110 0001 5",
            EntityType::UsAbaRouting,
            "0110 0001 5",
        ),
        ("RTN: 120139013", EntityType::UsAbaRouting, "120139013"),
        ("NPI 1234567893", EntityType::UsNpi, "1234567893"),
        ("Medicare MBI 1EG4TE5MK73", EntityType::UsMbi, "1EG4TE5MK73"),
        ("FEIN 31-0000001", EntityType::UsEin, "31-0000001"),
        // derived: an ANA NAN code with a Canada Post area letter
        ("code postal H2X 1Y4", EntityType::CaPostalCode, "H2X 1Y4"),
        (
            "licence number MAN99657054SM9IJ",
            EntityType::UkDrivingLicence,
            "MAN99657054SM9IJ",
        ),
        (
            "reg no ABC 123A",
            EntityType::UkVehicleRegistration,
            "ABC 123A",
        ),
        (
            "registration A123 ABC",
            EntityType::UkVehicleRegistration,
            "A123 ABC",
        ),
        ("A.C.N. 010 749 961", EntityType::AuAcn, "010 749 961"),
        ("SSN: 536906292", EntityType::Ssn, "536906292"),
    ] {
        assert_eq!(all(text), one(kind, value), "{text}");
    }
}

#[test]
fn acn_and_tfn_share_a_shape_but_not_a_cue() {
    // 123 456 782 passes neither; 100 010 747 is a TFN; 004 085 616 an ACN
    assert_eq!(
        found("TFN 100 010 747", &["au"]),
        one(EntityType::AuTfn, "100 010 747")
    );
    assert!(found("ACN 100 010 747", &["au"]).is_empty());
    assert!(found("TFN 004 085 616", &["au"]).is_empty());
    // a spaced ABN never yields an ACN for its last nine digits
    assert_eq!(
        found("ABN 51 824 753 556 ACN", &["au"]),
        one(EntityType::AuAbn, "51 824 753 556")
    );
}

#[test]
fn uk_and_ca_postal_shapes_are_disjoint() {
    // A9A 9AA (UK) vs A9A 9A9 (CA): one span can never be both
    assert_eq!(
        found("postcode K1A 0B1", &["uk", "ca"]),
        one(EntityType::CaPostalCode, "K1A 0B1")
    );
    assert_eq!(
        found("postcode W1A 0AX", &["uk", "ca"]),
        one(EntityType::UkPostcode, "W1A 0AX")
    );
}

#[test]
fn bare_ssn_outranks_a_same_span_routing_number_only_with_both_cues() {
    // the IRS Pub 1346 example also has the SSN structure
    assert!(valid_us_aba_routing("120139013") && valid_ssn("120139013"));
    assert_eq!(
        found("routing 120139013", &["en"]),
        one(EntityType::UsAbaRouting, "120139013")
    );
    assert_eq!(
        found("SSN 120139013", &["en"]),
        one(EntityType::Ssn, "120139013")
    );
    // both cues: SSN (tier 6) beats the routing number (tier 7)
    assert_eq!(
        found("SSN or routing 120139013", &["en"]),
        one(EntityType::Ssn, "120139013")
    );
}

// --------------------------------------------------- SSN and postcode rules

#[test]
fn ssn_rejects_the_unissued_900_999_areas() {
    // SSA randomization: areas 000, 666 and 900-999 are never assigned
    assert!(valid_ssn("899-12-3456"));
    for v in ["900-12-3456", "912-12-3456", "999-12-3456", "912123456"] {
        assert!(!valid_ssn(v), "{v}");
    }
    // the formatted rule therefore claims no non-ITIN 9xx shape,
    // while an ITIN-range one keeps its ITIN label
    assert!(detect("ref 912-12-3456 x").is_empty());
    assert!(detect("ITIN: 912-69-1234").is_empty());
    let itin = detect("ref 912-70-1234 x");
    assert_eq!(itin.len(), 1);
    assert_eq!(itin[0].kind, EntityType::Itin);
    // SSA FAQ and history rules stay
    for v in [
        "123-00-6789",
        "123-45-0000",
        "000-12-3456",
        "666-12-3456",
        "078-05-1120",
    ] {
        assert!(!valid_ssn(v), "{v}");
    }
}

#[test]
fn bare_ssn_is_claimed_only_with_an_ssn_cue() {
    for text in [
        "SSN: 536906292",
        "SSN 536906292",
        "ssn#536906292",
        "my SSN is 536906292",
        "536906292 (SSN)",
        "Social Security 536906292",
        "Social Security Number 536906292",
    ] {
        let kinds: Vec<EntityType> = detect(text).into_iter().map(|e| e.kind).collect();
        assert_eq!(kinds, vec![EntityType::Ssn], "{text}");
    }
    for text in [
        "order 536906292 shipped",
        "SSN: 123456789",     // sample sequence
        "SSN: 666906292",     // area 666
        "SSN: 536006292",     // group 00
        "SSN: 5369062921",    // ten digits
        "security 536906292", // broad boost word only
    ] {
        assert!(detect(text).is_empty(), "{text}: {:?}", detect(text));
    }
}

#[test]
fn uk_postcode_accepts_the_royal_mail_ana_letters() {
    // Royal Mail PAF Programmers' Guide Table 16 (W1P 1BB included)
    for pc in [
        "W1P 1BB", "W1V 1AA", "W1X 1AA", "M1 1AA", "EC1A 1BB", "GIR 0AA",
    ] {
        assert_eq!(
            found(&format!("postcode {pc}"), &["uk"]),
            one(EntityType::UkPostcode, pc),
            "{pc}"
        );
    }
    // still outside the list: R (GIR 0AA only), I, L, M, N, O, Q, Y, Z
    for pc in ["W1R 1AA", "W1I 1AA", "W1L 1AA", "W1Q 1AA", "W1Z 1AA"] {
        assert!(found(&format!("postcode {pc}"), &["uk"]).is_empty(), "{pc}");
    }
}

#[test]
fn ssn_keeps_only_ssa_sourced_rejections() {
    // 123-45-6789: never issued (SSA OIG report A-15-06-16037)
    assert!(!valid_ssn("123-45-6789"));
    assert!(kinds("SSN: 123456789", &["en"]).is_empty());
    // repeated digits: no SSA rule, so they are claimed like any SSN
    assert!(valid_ssn("111-11-1111"));
    assert_eq!(kinds("SSN 111-11-1111", &["en"]), vec![EntityType::Ssn]);
    assert_eq!(kinds("SSN: 555555555", &["en"]), vec![EntityType::Ssn]);
    // the area rule (000, 666, 900-999) still applies to them
    for v in ["000-00-0000", "666-66-6666", "999-99-9999", "987-65-4320"] {
        assert!(!valid_ssn(v), "{v}");
    }
    // the separator check is a shape check: mixed separators are no SSN
    // shape, the same digits with matching separators are
    assert!(!valid_ssn("536-90.6292"));
    assert!(valid_ssn("536.90.6292"));
}

#[test]
fn uk_postcode_royal_mail_letter_positions() {
    for pc in ["AJ1 1AA", "AJ12 1AA", "EC1M 1BB", "SW1Z 1AA", "W1P 1BB"] {
        assert_eq!(
            kinds(&format!("postcode {pc}"), &["uk"]),
            vec![EntityType::UkPostcode],
            "{pc}"
        );
    }
    for pc in ["AI1 1AA", "AZ1A 1AA", "QA1 1AA", "W1R 1AA", "EC1A 1AK"] {
        assert!(kinds(&format!("postcode {pc}"), &["uk"]).is_empty(), "{pc}");
    }
}

// ------------------------------------------------- crosscheck rows

#[test]
fn crosscheck_rows_agree_for_these_validators() {
    // the row-count contract lives in validator_crosscheck.rs; this test
    // checks the rows of this file's validators alone, so it stays
    // meaningful while rows of other validators change
    let Ok(data) = std::fs::read_to_string("data/validator_crosscheck.jsonl") else {
        eprintln!("SKIP: data/validator_crosscheck.jsonl not present");
        return;
    };
    let run = |name: &str, value: &str| -> Option<bool> {
        Some(match name {
            "valid_us_aba_routing" => valid_us_aba_routing(value),
            "valid_us_npi" => valid_us_npi(value),
            "valid_us_mbi" => valid_us_mbi(value),
            "valid_us_ein" => valid_us_ein(value),
            "valid_ca_postal_code" => valid_ca_postal_code(value),
            "valid_uk_driving_licence" => valid_uk_driving_licence(value),
            "valid_uk_vehicle_reg" => valid_uk_vehicle_reg(value),
            "valid_au_acn" => valid_au_acn(value),
            _ => return None,
        })
    };
    let mut checked = std::collections::BTreeMap::new();
    let mut mismatches = Vec::new();
    for line in data.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).expect("jsonl row");
        let name = v["validator"].as_str().expect("validator");
        let value = v["value"].as_str().expect("value");
        let expected = v["expected"].as_bool().expect("expected");
        if let Some(got) = run(name, value) {
            *checked.entry(name.to_owned()).or_insert(0usize) += 1;
            if got != expected {
                mismatches.push(format!(
                    "{name}({value:?}) = {got}, reference says {expected}"
                ));
            }
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    if checked.is_empty() {
        eprintln!("SKIP: no rows for these validators in the crosscheck file");
        return;
    }
    assert_eq!(checked.len(), 8, "{checked:?}");
    assert!(checked.values().all(|&n| n >= 50), "{checked:?}");
}
