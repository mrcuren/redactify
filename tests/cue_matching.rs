//! Context-cue matching: which text unlocks a cue-gated value.
//!
//! - Delimited labels: a cue that occurs inside ordinary words is written
//!   as delimited label forms; each test pairs trap words that must not
//!   unlock a value with label forms that still do.
//! - Full official labels are cues in full.
//! - Cue window: a leading cue counts when its END lies within the
//!   18-character window before the match, so a label longer than the
//!   window still unlocks a value it directly precedes. A trailing cue
//!   must lie fully within the window after the match, which keeps the
//!   streaming hold-back bound valid.
//! - The left and right context are searched separately, so a cue is
//!   never assembled from the end of one side and the start of the other.
//! - A short cue (at most 5 characters, starting with an ASCII letter)
//!   counts only where it starts a word.
//! - The explain rows of built-in and custom rules under every cue policy
//!   are pinned in one table.

use redactify::{CustomRule, Detector, EntityType, StreamingGuard};

fn kinds(text: &str, locales: &[&str]) -> Vec<EntityType> {
    Detector::new()
        .with_locales(locales)
        .detect(text)
        .into_iter()
        .map(|e| e.kind)
        .collect()
}

/// The matched cue literal of the single finding in `text`.
fn cue(text: &str, locales: &[&str]) -> Option<String> {
    let explained = Detector::new().with_locales(locales).explain(text);
    assert_eq!(explained.len(), 1, "{text}: {explained:?}");
    explained[0].1.cue.clone()
}

/// Every trap text yields nothing; every label text yields `kind`.
fn check(locales: &[&str], kind: EntityType, traps: &[&str], labels: &[&str]) {
    for t in traps {
        assert!(
            !kinds(t, locales).contains(&kind),
            "trap {t:?} still unlocks {kind:?}"
        );
    }
    for t in labels {
        assert_eq!(kinds(t, locales), vec![kind], "label {t:?}");
    }
}

// ------------------------------------------------------- substring traps

#[test]
fn itin_cue_itin_is_delimited() {
    check(
        &["en"],
        EntityType::Itin,
        &["writing 912701234", "visiting 912701234"],
        &[
            "ITIN: 912701234",
            "ITIN 912701234",
            "ITIN/SSN: 912701234",
            "(ITIN) 912701234",
        ],
    );
}

#[test]
fn itin_cue_tin_is_delimited() {
    // a nine-digit meeting id in the ITIN number space must not be claimed
    // through the "tin" inside "Meeting"
    check(
        &["en"],
        EntityType::Itin,
        &[
            "Meeting ID: 945701234",
            "marketing 912701234",
            "voting 912701234",
            "routing 912701234",
        ],
        &[
            "TIN: 912701234",
            "my TIN 912701234",
            "TIN no 912701234",
            "TIN number 912701234",
            "(TIN) 912701234",
        ],
    );
}

#[test]
fn ein_cue_has_no_one_sided_forms() {
    check(
        &["en"],
        EntityType::UsEin,
        &[
            "protein 10-1234567",
            "Stein 10-1234567",
            "mein 10-1234567",
            "das ist eine 10-1234567",
        ],
        &[
            "EIN: 10-1234567",
            "EIN# 10-1234567",
            "(EIN) 10-1234567",
            "the EIN 10-1234567",
            "FEIN 10-1234567",
        ],
    );
}

#[test]
fn us_passport_cue_states_needs_a_leading_space() {
    check(
        &["en"],
        EntityType::UsPassport,
        &["estates A12345678"],
        &["United States passport A12345678", "US states A12345678"],
    );
}

#[test]
fn zip_cue_is_delimited() {
    check(
        &["en"],
        EntityType::UsZip,
        &["zipped 90210", "zipper 90210"],
        &["ZIP: 90210", "ZIP 90210", "zip code 90210", "ZIP+4 90210"],
    );
}

#[test]
fn dni_cue_dni_is_delimited() {
    check(
        &["es"],
        EntityType::Dni,
        &["midnight 12345678Z", "samordningsnummer 12345678Z"],
        &["DNI: 12345678Z", "DNI 12345678Z", "DNIe: 12345678Z"],
    );
}

#[test]
fn dni_cue_nif_is_delimited() {
    check(
        &["es"],
        EntityType::Dni,
        &[
            "significant 12345678Z",
            "manifest 12345678Z",
            "unify 12345678Z",
        ],
        &["NIF 12345678Z", "NIF/CIF: 12345678Z", "NIF: 12345678Z"],
    );
}

#[test]
fn nie_cue_is_delimited() {
    check(
        &["es"],
        EntityType::Nie,
        &[
            "companies X1234567L",
            "Daniel X1234567L",
            "denied X1234567L",
            "funktioniert X1234567L",
        ],
        &["NIE: X1234567L", "NIE X1234567L", "su NIE X1234567L"],
    );
}

#[test]
fn nip_cues_nip_and_vat_are_delimited() {
    check(
        &["pl"],
        EntityType::PlNip,
        &[
            "manipulate 1231216692",
            "snippet 1231216692",
            "private 1231216692",
            "motivation 1231216692",
        ],
        &[
            "NIP: 1231216692",
            "NIP 123-121-66-92",
            "nr NIP 1231216692",
            "NIP-u 1231216692",
            "VAT: 1231216692",
        ],
    );
}

#[test]
fn bic_cue_is_delimited() {
    // SWIFT/BIC is always on (no locale needed)
    check(
        &[],
        EntityType::SwiftBic,
        &["bicycle DEUTDEFF", "ubicaci\u{f3}n DEUTDEFF"],
        &["BIC: DEUTDEFF", "BIC DEUTDEFF", "BIC/SWIFT DEUTDEFF"],
    );
}

#[test]
fn uk_vat_cues_vat_and_gb_are_delimited() {
    check(
        &["uk"],
        EntityType::UkVat,
        &[
            "private 999999973",
            "innovative 999999973",
            "LGBTQ 999999973",
            "GBP 999999973",
        ],
        &[
            "VAT: 999999973",
            "VAT No 999 9999 73",
            "VAT-ID 999999973",
            "GB: 999999973",
        ],
    );
}

#[test]
fn utr_cue_is_delimited() {
    check(
        &["uk"],
        EntityType::UkUtr,
        &[
            "nutrition 1234567890",
            "neutral 1234567890",
            "autre 1234567890",
        ],
        &["UTR: 1234567890", "UTR 1234567890", "utr number 1234567890"],
    );
}

#[test]
fn nric_cue_is_delimited() {
    check(
        &["sg"],
        EntityType::SgNricFin,
        &["enrich S2740116C", "enrichment S2740116C"],
        &[
            "NRIC: S2740116C",
            "NRIC S2740116C",
            "NRIC/FIN No: S2740116C",
        ],
    );
}

#[test]
fn abn_cues_abn_and_acn_are_delimited() {
    check(
        &["au"],
        EntityType::AuAbn,
        &["abnormal 51824753556", "acne 51824753556"],
        &["ABN: 51824753556", "ABN 51824753556", "ACN 51824753556"],
    );
}

#[test]
fn de_passport_cue_pass_is_delimited() {
    check(
        &["de"],
        EntityType::DePassport,
        &[
            "Passwort: C3JJ4789L",
            "password C3JJ4789L",
            "passiert C3JJ4789L",
        ],
        &[
            "Pass-Nr. C3JJ4789L",
            "Pass: C3JJ4789L",
            "Passnummer C3JJ4789L",
            "Reisepass C3JJ4789L",
        ],
    );
    // an Italian passport number is not taken by the German rule through
    // the "pass" inside "passaporto"
    assert_eq!(
        kinds("passaporto CA1234567", &["de", "it"]),
        vec![EntityType::ItPassport]
    );
}

#[test]
fn tnin_cue_is_delimited() {
    check(
        &["th"],
        EntityType::ThTnin,
        &["drottning 1234567890123"],
        &["TNIN: 1234567890123", "TNIN 1234567890123"],
    );
}

// ---------------------------------------------------- full official labels

#[test]
fn vehicle_registration_number_label() {
    assert_eq!(
        kinds("Vehicle registration number: AB12 CDE", &["uk"]),
        vec![EntityType::UkVehicleRegistration]
    );
    // "registration number" reaches 18 characters past its own end, which
    // its "registration" part alone does not
    assert_eq!(
        cue("Registration number of the car: AB12 CDE", &["uk"]).as_deref(),
        Some("registration number")
    );
}

#[test]
fn restored_labels_are_cues_in_full() {
    for (text, locale, label) in [
        (
            "Goods and Services Tax Identification Number: 27AFZPK7190K1Z5",
            "in",
            "goods and services tax identification number",
        ),
        (
            "Goods and Services Tax No. 27AFZPK7190K1Z5",
            "in",
            "goods and services tax",
        ),
        (
            "\u{e40}\u{e25}\u{e02}\u{e1b}\u{e23}\u{e30}\u{e08}\u{e33}\u{e15}\u{e31}\u{e27}\u{e1b}\u{e23}\u{e30}\u{e0a}\u{e32}\u{e0a}\u{e19} 1234567890123",
            "th",
            "\u{e40}\u{e25}\u{e02}\u{e1b}\u{e23}\u{e30}\u{e08}\u{e33}\u{e15}\u{e31}\u{e27}\u{e1b}\u{e23}\u{e30}\u{e0a}\u{e32}\u{e0a}\u{e19}",
        ),
        (
            "Krankenversichertennummer: E543768738",
            "de",
            "krankenversichertennummer",
        ),
        (
            "Versichertennummer E543768738",
            "de",
            "versichertennummer",
        ),
        (
            "Rentenversicherungsnummer: 15070649C103",
            "de",
            "rentenversicherungsnummer",
        ),
        (
            "Sozialversicherungsnummer 15070649C103",
            "de",
            "sozialversicherungsnummer",
        ),
        (
            "Versicherungsnummer 15070649C103",
            "de",
            "versicherungsnummer",
        ),
        (
            "Betriebsst\u{e4}ttennummer: 021234567",
            "de",
            "betriebsst\u{e4}ttennummer",
        ),
        (
            "Steueridentifikationsnummer: 86095742719",
            "de",
            "steueridentifikationsnummer",
        ),
        (
            "National Identification Number: 12345678901",
            "ng",
            "national identification number",
        ),
        (
            "National Identity Number: 12345678901",
            "ng",
            "national identity number",
        ),
        (
            "Australian Company Number: 004 085 616",
            "au",
            "australian company number",
        ),
        (
            "N\u{fa}mero de Identidad de Extranjero: X1234567L",
            "es",
            "n\u{fa}mero de identidad de extranjero",
        ),
        (
            "National Health Service number: 943 476 5870",
            "uk",
            "national health service",
        ),
        ("Bank Identifier Code: DEUTDEFF", "en", "bank identifier code"),
    ] {
        assert_eq!(cue(text, &[locale]).as_deref(), Some(label), "{text}");
    }
}

#[test]
fn long_official_labels_reach_the_value() {
    // short prefixes such as "national id" or "gst no" end too far before
    // the value or do not occur at all; the full label reaches it
    assert_eq!(
        kinds("National Identification Number: 12345678901", &["ng"]),
        vec![EntityType::NgNin]
    );
    assert_eq!(
        kinds(
            "Goods and Services Tax Identification Number: 27AFZPK7190K1Z5",
            &["in"]
        ),
        vec![EntityType::InGstin]
    );
}

// ------------------------------------------------ cue window, leading side

#[test]
fn long_label_ending_inside_the_window_unlocks_the_value() {
    // "registration" starts 21 characters before the value and ends 9
    // characters before it
    let text = "Vehicle registration number: AB12 CDE";
    assert_eq!(
        kinds(text, &["uk"]),
        vec![EntityType::UkVehicleRegistration],
        "{text}"
    );
    let d = Detector::new().with_locales(&["uk"]);
    let explained = d.explain(text);
    assert_eq!(explained[0].1.cue.as_deref(), Some("registration"));
}

#[test]
fn leading_gap_is_bounded_by_the_window() {
    // the gap between the cue's end and the value is what the window
    // bounds: 18 characters still count, 19 do not
    let rule = CustomRule::new(EntityType::Itin, r"\b\d{6}\b")
        .expect("pattern compiles")
        .with_cue(&["customerreference"]);
    let rules = [&rule];
    let d = Detector::new().with_custom_rules(&rules);
    let at = |gap: usize| format!("customerreference{}482913", "-".repeat(gap));
    assert_eq!(d.detect(&at(18)).len(), 1, "{}", at(18));
    assert!(d.detect(&at(19)).is_empty(), "{}", at(19));
}

#[test]
fn trailing_cue_must_still_lie_fully_inside_the_window() {
    // the trailing side: the cue starts 10 characters after the
    // value but ends 22 characters after it, outside the 18-character
    // window, so it does not count; a cue fully inside it does
    let rule = CustomRule::new(EntityType::Itin, r"\b\d{6}\b")
        .expect("pattern compiles")
        .with_cue(&["registration"]);
    let rules = [&rule];
    let d = Detector::new().with_custom_rules(&rules);
    assert!(d.detect("482913 ---------registration").is_empty());
    assert_eq!(d.detect("482913 -----registration").len(), 1);
}

#[test]
fn stream_matches_batch_for_a_long_leading_label() {
    // the leading cue lies before the value, so the streaming guard (which
    // keeps the whole open line) masks exactly what the batch path masks,
    // for every split point; the long newline-free line exercises the
    // intra-line early emission (the label sits far from the line start)
    let long = format!(
        "{}Vehicle registration number: AB12 CDE {}",
        "lorem ipsum ".repeat(20),
        "dolor sit ".repeat(20)
    );
    for text in [
        "Vehicle registration number: AB12 CDE and more text after it\n",
        long.as_str(),
    ] {
        let batch = redactify::Guard::new(redactify::GuardTarget::UserPrompt)
            .with_locales(&["uk"])
            .sanitize(text)
            .text;
        assert!(batch.contains("[UK_VEHICLE_REGISTRATION]"), "{batch}");
        let mut early = 0;
        for cut in 1..text.len() {
            if !text.is_char_boundary(cut) {
                continue;
            }
            let mut g =
                StreamingGuard::new(redactify::GuardTarget::UserPrompt).with_locales(&["uk"]);
            let mut out = String::new();
            for chunk in [&text[..cut], &text[cut..]] {
                for ev in g.push(chunk) {
                    if let redactify::GuardEvent::Segment { text, .. } = ev {
                        early += usize::from(!text.ends_with('\n'));
                        out.push_str(&text);
                    }
                }
            }
            for ev in g.finish() {
                if let redactify::GuardEvent::Segment { text, .. } = ev {
                    out.push_str(&text);
                }
            }
            assert_eq!(out, batch, "cut {cut}");
        }
        if !text.ends_with('\n') {
            assert!(early > 0, "no intra-line segment was emitted");
        }
    }
}

// ------------------------------------------------------- context junction

#[test]
fn cue_is_not_assembled_across_the_match() {
    // "va" before the value and "t" after it must not read as the cue
    // "vat"
    assert!(
        !kinds("va999999973t", &["uk"]).contains(&EntityType::UkVat),
        "{:?}",
        kinds("va999999973t", &["uk"])
    );
    let rule = CustomRule::new(EntityType::Itin, r"\d{6}")
        .expect("pattern compiles")
        .with_cue(&["vat"]);
    let rules = [&rule];
    let d = Detector::new().with_custom_rules(&rules);
    assert!(d.detect("va482913t").is_empty());
    // a real cue on either side still counts (a short cue must start a
    // word, so the trailing one is not glued to the value)
    assert_eq!(d.detect("vat482913").len(), 1);
    assert_eq!(d.detect("482913 vat").len(), 1);
}

// ------------------------------------------- short cues start a word

#[test]
fn short_cues_inside_a_word_unlock_nothing() {
    // a cue of at most 5 characters starting with an ASCII letter counts
    // only where it starts a word (also at the start of the text)
    let cases: &[(&str, &[&str], EntityType)] = &[
        ("syntax 999999973", &["uk"], EntityType::UkVat),
        ("Wisconsin: 123-456-782", &["ca"], EntityType::CaSin),
        ("Benin: 12345678901", &["ng"], EntityType::NgNin),
        ("span: ABCPE1234F", &["in"], EntityType::InPan),
        ("femenino AB 12 34 56 C", &["uk"], EntityType::Nino),
        ("username: John Smith", &["en"], EntityType::Name),
        // a name outside the Turkish lexicon: only the labeled rule's
        // cue could claim it (the lexicon scanner `tr::person` claims a
        // lexicon name like "Ahmet Yılmaz" here without any cue)
        (
            "Bu kısım Jean Dupont tarafından yazıldı",
            &["tr"],
            EntityType::Name,
        ),
        ("xenophobic DEUTDEFF", &["en"], EntityType::SwiftBic),
        ("bypass C3JJ4789L", &["de"], EntityType::DePassport),
    ];
    for (text, locales, kind) in cases {
        assert!(
            !kinds(text, locales).contains(kind),
            "{text}: {:?}",
            kinds(text, locales)
        );
    }
}

#[test]
fn short_cues_at_a_word_start_and_long_compound_cues_still_unlock() {
    let cases: &[(&str, &[&str], EntityType)] = &[
        // a short cue at the start of the text or after a non-alphanumeric
        ("TAX: 999999973", &["uk"], EntityType::UkVat),
        ("VAT 999999973", &["uk"], EntityType::UkVat),
        ("SIN: 123-456-782", &["ca"], EntityType::CaSin),
        ("NIN: 12345678901", &["ng"], EntityType::NgNin),
        ("PAN: ABCPE1234F", &["in"], EntityType::InPan),
        ("NINO AB 12 34 56 C", &["uk"], EntityType::Nino),
        ("Name: John Smith", &["en"], EntityType::Name),
        ("İsim: Ahmet Yılmaz", &["tr"], EntityType::Name),
        ("BIC DEUTDEFF", &["en"], EntityType::SwiftBic),
        ("ITIN: 912-70-1234", &["en"], EntityType::Itin),
        ("DNIe: 12345678Z", &["es"], EntityType::Dni),
        // no right-side condition: a Turkish suffix keeps the cue
        (
            "Firmanın vergisi 1234567890 olarak",
            &["tr"],
            EntityType::Vkn,
        ),
        // compounds whose own longer cue unlocks them
        ("Reisepass C3JJ4789L", &["de"], EntityType::DePassport),
        ("ITIN 912-70-1234 for taxpayer", &["en"], EntityType::Itin),
        ("GSTIN: 27AFZPK7190K1Z5", &["in"], EntityType::InGstin),
    ];
    for (text, locales, kind) in cases {
        assert!(
            kinds(text, locales).contains(kind),
            "{text}: {:?}",
            kinds(text, locales)
        );
    }
}

// ------------------------------------------------------- SIRET priority

#[test]
fn cued_siret_outranks_the_card_claim() {
    assert!(redactify::valid_fr_siret("73282932000074"));
    assert!(redactify::valid_luhn("73282932000074"));
    for text in [
        "SIRET 73282932000074",
        "SIRET 732 829 320 00074",
        "Numéro SIREN/SIRET : 12345678200002",
        "insee 55512345400020",
    ] {
        assert_eq!(kinds(text, &["fr"]), vec![EntityType::FrSiret], "{text}");
    }
    // uncued, or without the fr pack: the cue-less card claim stays
    assert_eq!(
        kinds("ref 73282932000074 ok", &["fr"]),
        vec![EntityType::CreditCard]
    );
    assert_eq!(
        kinds("SIRET 73282932000074", &["tr", "en"]),
        vec![EntityType::CreditCard]
    );
    // a real card next to a SIRET keeps its own label
    assert_eq!(
        kinds("carte 4111 1111 1111 1111 et SIRET 73282932000074", &["fr"]),
        vec![EntityType::CreditCard, EntityType::FrSiret]
    );
}

// --------------------------------------------------------------- eu::vat

#[test]
fn eu_vat_short_names_inside_words_unlock_nothing() {
    for t in [
        "private DE123456789 room",
        "elevator ATU12345678 stuck",
        "derivative IT12345678901 priced",
        "duomenu tvarkymo LT123456789 ok",
        "varstva SI12345678 podatkov",
        "la direttiva IT12345678901 vale",
    ] {
        assert!(!kinds(t, &["eu"]).contains(&EntityType::EuVat), "{t}");
    }
}

#[test]
fn eu_vat_delimited_names_still_unlock_the_value() {
    for t in [
        "VAT DE123456789",
        "VAT: DE123456789",
        "Our VAT number is DE123456789",
        "DE123456789 (VAT)",
        "N° TVA FRXX 123456789",
        "TVA : FRXX 123456789",
        "partita IVA IT12345678901",
        "P.IVA IT12345678901",
        "NIF-IVA ESX1234567B",
        "USt / MwSt-Nr. DE123456789",
    ] {
        assert_eq!(kinds(t, &["eu"]), vec![EntityType::EuVat], "{t}");
    }
}

#[test]
fn eu_vat_line_start_labels_unlock_and_words_do_not() {
    let eu = |t: &str| {
        redactify::Detector::new()
            .with_locales(&["eu"])
            .detect(t)
            .into_iter()
            .filter(|e| e.kind == redactify::EntityType::EuVat)
            .count()
    };
    // line-start labels (word-start short cues followed by a space)
    assert_eq!(eu("TVA FR40303265045"), 1);
    assert_eq!(eu("IVA IT00743110157"), 1);
    assert_eq!(eu("PIVA IT00743110157"), 1);
    // the same letters inside words or glued to a word unlock nothing
    assert_eq!(eu("tvarkymas FR40303265045"), 0);
    assert_eq!(eu("direttiva IT00743110157"), 0);
    assert_eq!(eu("sopiva IT00743110157"), 0);
}

// --------------------------------------------- explain rows per cue policy

/// One explain row: entity span, kind, score and every explanation field.
fn rows(d: &Detector<'_>, text: &str) -> Vec<String> {
    let report = d.scan(text);
    let mut out: Vec<String> = d
        .explain(text)
        .into_iter()
        .map(|(e, w)| {
            format!(
                "{}..{} {:?} {} {:?} {} {:?} {} {:?}",
                e.start,
                e.end,
                e.kind,
                e.score,
                w.source,
                w.validator_passed,
                w.cue,
                w.base_score,
                w.view
            )
        })
        .collect();
    out.push(format!(
        "errors {} {:?}",
        report.engine_errors, report.error_spans
    ));
    out
}

#[test]
fn cue_policy_explain_rows_of_built_in_and_custom_rules() {
    let plain = CustomRule::new(EntityType::Itin, r"ORC-\d{4}").unwrap();
    let required = CustomRule::new(EntityType::Vkn, r"REF\d{6}")
        .unwrap()
        .with_cue(&["Ticket", "M\u{fc}\u{15f}teri No"]);
    let boosted = CustomRule::new(EntityType::Passport, r"PX\d{5}")
        .unwrap()
        .with_score(0.5)
        .with_cue_boost(&["pasaport"], 0.95);
    let validated = CustomRule::new(EntityType::Itin, r"\bZ\d{4}\b")
        .unwrap()
        .with_validator(|v| v.ends_with('7'));
    // nested alternation + atomic group: exhausts the backtrack budget on
    // a long a/b run that is not followed by the `Q`
    let backtracking = CustomRule::new(EntityType::Itin, r"(a|b|ab)*(?>Q)").unwrap();
    let rules = [&plain, &required, &boosted, &validated, &backtracking];
    let d = Detector::new().with_custom_rules(&rules);
    let texts: &[&str] = &[
        // built-in RequiredCue: with, without and Turkish-cased cue
        "vergi no 1234567890",
        "kod 1234567890 x",
        "VERG\u{130} NO 1234567890",
        // built-in Boost: with and without cue
        "Plaka 34 ABC 123 kayitli",
        "yolda 34 ABC 123 var",
        // built-in None
        "TCKN 12345678950, mail a@b.com",
        // custom None / RequiredCue / Boost / validator
        "bkz ORC-1234 x",
        "Ticket REF123456 acildi",
        "M\u{dc}\u{15e}TER\u{130} NO: REF654321",
        "REF123456 tek basina",
        "pasaport PX12345 ve PX54321 bitti uzak uzak uzak uzak uzak",
        "PX12345",
        "kod Z1237 ve Z1238",
        // multi-line with CRLF and a backtracking line
        "vergi no 1234567890\r\nTicket REF111111\nabababababababababababababababababababababab Q\nORC-9999",
    ];
    // one pinned row list per text
    let expected: &[&[&str]] = &[
        &[
            r#"9..19 Vkn 1 Rule { id: "tr::vkn" } true Some("vergi") 1 Raw"#,
            "errors 0 []",
        ],
        &["errors 0 []"],
        &[
            r#"10..20 Vkn 1 Rule { id: "tr::vkn" } true Some("vergi") 1 Raw"#,
            "errors 0 []",
        ],
        &[
            r#"6..16 Plaka 0.95 Rule { id: "tr::plaka" } true Some("plaka") 0.85 Raw"#,
            "errors 0 []",
        ],
        &[
            r#"6..16 Plaka 0.85 Rule { id: "tr::plaka" } true None 0.85 Raw"#,
            "errors 0 []",
        ],
        &[
            r#"5..16 Tckn 1 Rule { id: "tr::tckn" } true None 1 Raw"#,
            r#"23..30 Email 0.85 Rule { id: "generic::email" } false None 0.85 Raw"#,
            "errors 0 []",
        ],
        &[
            "4..12 Itin 0.8 Custom { index: 0 } false None 0.8 Raw",
            "errors 0 []",
        ],
        &[
            r#"7..16 Vkn 0.8 Custom { index: 1 } false Some("ticket") 0.8 Raw"#,
            "errors 0 []",
        ],
        &[
            "15..24 Vkn 0.8 Custom { index: 1 } false Some(\"m\u{fc}\u{15f}teri no\") 0.8 Raw",
            "errors 0 []",
        ],
        &["errors 0 []"],
        &[
            r#"9..16 Passport 0.95 Custom { index: 2 } false Some("pasaport") 0.5 Raw"#,
            // a leading cue counts when it ENDS within the window:
            // "pasaport" starts 20 characters before PX54321 but ends 12
            // characters before it
            r#"20..27 Passport 0.95 Custom { index: 2 } false Some("pasaport") 0.5 Raw"#,
            "errors 0 []",
        ],
        &[
            "0..7 Passport 0.5 Custom { index: 2 } false None 0.5 Raw",
            "errors 0 []",
        ],
        &[
            "4..9 Itin 0.8 Custom { index: 3 } true None 0.8 Raw",
            "errors 0 []",
        ],
        &[
            r#"9..19 Vkn 1 Rule { id: "tr::vkn" } true Some("vergi") 1 Raw"#,
            r#"28..37 Vkn 0.8 Custom { index: 1 } false Some("ticket") 0.8 Raw"#,
            "85..93 Itin 0.8 Custom { index: 0 } false None 0.8 Raw",
            "errors 1 [(38, 84)]",
        ],
    ];
    assert_eq!(expected.len(), texts.len());
    for (text, want) in texts.iter().zip(expected) {
        assert_eq!(rows(&d, text), *want, "{text:?}");
    }
}
