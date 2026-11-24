//! German, Italian, Swedish and Singapore identifiers (de, it, se, sg):
//! golden vectors from the official sources cited in each module doc,
//! cue / no-cue behavior, cross-locale collisions with every locale
//! enabled, and the source-based rules of de::id_card, de::tax_id,
//! it::fiscal_code, tr::plaka and the Swedish eu::vat form.

use redactify::{
    detect, valid_de_bsnr, valid_de_id_card, valid_de_kfz, valid_de_kvnr, valid_de_lanr,
    valid_de_rvnr, valid_de_tax_id, valid_de_tax_number, valid_eu_vat, valid_it_fiscal_code,
    valid_it_numeric_fiscal_code, valid_it_passport, valid_plaka, valid_se_organisationsnummer,
    valid_sg_uen, valid_tckn, Detector, EntityType, SUPPORTED_LOCALES,
};

fn kinds(text: &str, locales: &[&str]) -> Vec<EntityType> {
    Detector::new()
        .with_locales(locales)
        .detect(text)
        .into_iter()
        .map(|e| e.kind)
        .collect()
}

fn all(text: &str) -> Vec<(EntityType, String)> {
    Detector::new()
        .with_locales(SUPPORTED_LOCALES)
        .detect(text)
        .into_iter()
        .map(|e| (e.kind, e.text))
        .collect()
}

// ------------------------------------------------------------ golden vectors

/// ELSTER Tabelle 4-1 test numbers: (ELSTER form, printed Bescheid form).
const STNR_OFFICIAL: &[(&str, &str)] = &[
    ("2866081508156", "66815/08156"),
    ("9198081508152", "198/815/08152"),
    ("9296081508153", "296/815/08153"),
    ("1197081508154", "97/815/08154"),
    ("3098081508157", "098/815/08157"),
    ("2497012301233", "97 123 01233"),
    ("2293081508150", "93/815/08150"),
    ("2653081508158", "053 815 08158"),
    ("4098081508157", "098/815/08157"),
    ("2388081508158", "88/815/08158"),
    ("5400081508159", "400/8150/8159"),
    ("5500081508151", "500/8150/8151"),
    ("5600081508154", "600/8150/8154"),
    ("2799081508152", "99/815/08152"),
    ("1096081508187", "096/815/08187"),
    ("3248081508156", "248/815/08156"),
    ("3198081508152", "198/815/08152"),
    ("2138081508154", "38/815/08154"),
    ("4198081508152", "198/815/08152"),
];

/// ELSTER Tabelle 2-1 Steuer-IdNr examples ("ID laut Konzept des ITZ BUND").
const IDNR_OFFICIAL: &[&str] = &[
    "86095742719",
    "47036892816",
    "65929970489",
    "57549285017",
    "25768131411",
];

#[test]
fn de_golden_vectors() {
    for (elster, printed) in STNR_OFFICIAL {
        assert!(valid_de_tax_number(elster), "{elster}");
        assert!(valid_de_tax_number(printed), "{printed}");
    }
    for v in [
        "2866081508157",
        "2866181508156",
        "2866000008150",
        "198/815/08153",
    ] {
        assert!(!valid_de_tax_number(v), "{v}");
    }
    // KBV Prüfpaket test data; KVDT rule 054 pseudo number
    assert!(valid_de_kvnr("E543768738") && valid_de_kvnr("G894698435"));
    assert!(!valid_de_kvnr("E543768739") && !valid_de_kvnr("T555558879"));
    // ANRV § 4 Abs. 3 (computed); KVDT rule 050 pseudo LANR
    for v in ["123456601", "100000601", "987654400"] {
        assert!(valid_de_lanr(v), "{v}");
    }
    assert!(!valid_de_lanr("123456701") && !valid_de_lanr("555555500"));
    // KBV guideline § 6 + Anlage 1 (structural)
    assert!(valid_de_bsnr("021234567") && valid_de_bsnr("351712345"));
    assert!(!valid_de_bsnr("041234567") && !valid_de_bsnr("991234567"));
    // § 2 Abs. 6 VKVV (computed); the DRV glossary example fails the
    // published algorithm (it yields check digit 1)
    assert!(valid_de_rvnr("15070649C103") && valid_de_rvnr("65170839J081"));
    assert!(!valid_de_rvnr("65170839J088") && !valid_de_rvnr("15070649C104"));
    assert!(!valid_de_rvnr("15071349C107")); // month 13, check digit fits
                                             // FZV § 9, Anlage 1, Anlage 4 (structural)
    for v in ["B AB 1234", "HH-A 1", "M-XY 999", "KA EF 1H", "TÜ-A 12E"] {
        assert!(valid_de_kfz(v), "{v}");
    }
    for v in ["B AB 01", "ABC DE 1234", "B ÄB 12"] {
        assert!(!valid_de_kfz(v), "{v}");
    }
}

#[test]
fn it_se_sg_golden_vectors() {
    // MAE decree (GU 19-05-2010): 2 letters + 7 digits
    assert!(valid_it_passport("YA1234567"));
    assert!(!valid_it_passport("YA123456") && !valid_it_passport("Y12345678"));
    // DM 13813 Art. 9 (computed)
    assert!(valid_it_numeric_fiscal_code("12345678903"));
    assert!(valid_it_numeric_fiscal_code("01234567897"));
    assert!(!valid_it_numeric_fiscal_code("12345678904"));
    assert!(!valid_it_numeric_fiscal_code("00000000000"));
    // Lag (1974:174) 4 § + SKV 709: ten digits, third digit at least 2
    assert!(valid_se_organisationsnummer("5560000000"));
    assert!(valid_se_organisationsnummer("556000-0000"));
    assert!(!valid_se_organisationsnummer("5510000000"));
    assert!(!valid_se_organisationsnummer("556000000"));
    // LTA VRL/17/2019 (the circular's illustrative format C value)
    assert!(valid_sg_uen("T09LL0001B"));
    assert!(!valid_sg_uen("T09LL001B") && !valid_sg_uen("Q09LL0001B"));
}

// -------------------------------------------------------------- cue policy

#[test]
fn rules_require_their_cue() {
    let cases: &[(&str, &str, EntityType, &str)] = &[
        (
            "Steuernummer: ",
            "2866081508156",
            EntityType::DeTaxNumber,
            "de",
        ),
        ("St.-Nr. ", "198/815/08152", EntityType::DeTaxNumber, "de"),
        (
            "Finanzamt, Steuernummer ",
            "053 815 08158",
            EntityType::DeTaxNumber,
            "de",
        ),
        (
            "Krankenversichertennummer: ",
            "E543768738",
            EntityType::DeKvnr,
            "de",
        ),
        (
            "Rentenversicherungsnummer: ",
            "15070649C103",
            EntityType::DeRvnr,
            "de",
        ),
        (
            "Sozialversicherungsnummer ",
            "65170839J081",
            EntityType::DeRvnr,
            "de",
        ),
        ("LANR ", "987654400", EntityType::DeLanr, "de"),
        (
            "Betriebsstättennummer: ",
            "021234567",
            EntityType::DeBsnr,
            "de",
        ),
        ("Kfz-Kennzeichen ", "B AB 1234", EntityType::DeKfz, "de"),
        ("passaporto n. ", "YA1234567", EntityType::ItPassport, "it"),
        (
            "codice fiscale ",
            "01234567897",
            EntityType::ItFiscalCode,
            "it",
        ),
        (
            "Organisationsnummer: ",
            "556000-0000",
            EntityType::SeOrganisationsnummer,
            "se",
        ),
        ("UEN: ", "T09LL0001B", EntityType::SgUen, "sg"),
    ];
    for (cue, value, kind, locale) in cases {
        let with_cue = format!("{cue}{value} ok");
        let found = Detector::new().with_locales(&[*locale]).detect(&with_cue);
        assert_eq!(found.len(), 1, "{with_cue}: {found:?}");
        assert_eq!(found[0].kind, *kind, "{with_cue}");
        assert_eq!(found[0].text, *value);
        // no cue: never claimed (a 13-digit Luhn run would be the card
        // rule's claim, which none of these vectors is)
        let bare = format!("ref {value} ok");
        assert!(kinds(&bare, &[locale]).is_empty(), "{bare}");
    }
}

#[test]
fn scores_follow_the_policy() {
    let score =
        |text: &str, locale: &str| Detector::new().with_locales(&[locale]).detect(text)[0].score;
    // checksum verified + mandatory cue: 1.0
    for (t, l) in [
        ("Steuernummer 198/815/08152", "de"),
        ("KVNR E543768738", "de"),
        ("RVNR 15070649C103", "de"),
        ("LANR 123456601", "de"),
        ("C.F. 12345678903", "it"),
    ] {
        assert!((score(t, l) - 1.0).abs() < 1e-6, "{t}");
    }
    // format + mandatory cue: 0.9
    for (t, l) in [
        ("BSNR 021234567", "de"),
        ("Kennzeichen B AB 1234", "de"),
        ("Personalausweis LF2K7X9RZ", "de"),
        ("passaporto YA1234567", "it"),
        ("orgnr 5560000000", "se"),
        ("UEN: 53012345D", "sg"),
    ] {
        assert!((score(t, l) - 0.9).abs() < 1e-6, "{t}");
    }
}

#[test]
fn labels_and_priorities() {
    for (kind, label, tier) in [
        (EntityType::DeTaxNumber, "DE_TAX_NUMBER", 0),
        (EntityType::DeKvnr, "DE_KVNR", 7),
        (EntityType::DeRvnr, "DE_RVNR", 7),
        (EntityType::DeLanr, "DE_LANR", 7),
        (EntityType::DeBsnr, "DE_BSNR", 7),
        (EntityType::DeKfz, "DE_KFZ", 7),
        (EntityType::ItPassport, "IT_PASSPORT", 6),
        (
            EntityType::SeOrganisationsnummer,
            "SE_ORGANISATIONSNUMMER",
            7,
        ),
        (EntityType::SgUen, "SG_UEN", 7),
    ] {
        assert_eq!(kind.as_str(), label);
        assert_eq!(label.parse::<EntityType>(), Ok(kind));
        assert_eq!(kind.priority(), tier, "{label}");
    }
    assert!(EntityType::DeTaxNumber.priority() < EntityType::CreditCard.priority());
}

#[test]
fn opt_in_types_never_appear_with_the_default_locales() {
    for text in [
        "Steuernummer: 2866081508156",
        "Steuernummer 198/815/08152",
        "KVNR E543768738",
        "RVNR 15070649C103",
        "LANR 123456601",
        "BSNR 021234567",
        "Kennzeichen B AB 1234",
        "passaporto YA1234567",
        "codice fiscale 01234567897",
        "orgnr 556000-0000",
        "UEN: T09LL0001B",
        "Personalausweis LF2K7X9RZ",
    ] {
        for e in detect(text) {
            assert!(
                !matches!(
                    e.kind,
                    EntityType::DeTaxNumber
                        | EntityType::DeKvnr
                        | EntityType::DeRvnr
                        | EntityType::DeLanr
                        | EntityType::DeBsnr
                        | EntityType::DeKfz
                        | EntityType::ItPassport
                        | EntityType::ItFiscalCode
                        | EntityType::SeOrganisationsnummer
                        | EntityType::SgUen
                        | EntityType::DeIdCard
                ),
                "{text}: {e:?}"
            );
        }
    }
}

// ------------------------------------------- cross-locale collisions (all on)

#[test]
fn rules_keep_their_label_with_every_locale_enabled() {
    for (text, kind, value) in [
        ("LANR 123456601", EntityType::DeLanr, "123456601"),
        ("LANR 912345901", EntityType::DeLanr, "912345901"),
        ("BSNR 021234567", EntityType::DeBsnr, "021234567"),
        ("BSNR 912345678", EntityType::DeBsnr, "912345678"),
        ("KVNR G894698435", EntityType::DeKvnr, "G894698435"),
        (
            "Versicherungsnummer 15070649C103",
            EntityType::DeRvnr,
            "15070649C103",
        ),
        ("Kennzeichen B AB 1234H", EntityType::DeKfz, "B AB 1234H"),
        (
            "Steuernummer 400/8150/8159",
            EntityType::DeTaxNumber,
            "400/8150/8159",
        ),
        (
            "Steuernummer 97 123 01233",
            EntityType::DeTaxNumber,
            "97 123 01233",
        ),
        ("passaporto YA1234567", EntityType::ItPassport, "YA1234567"),
        (
            "codice fiscale 01234567897",
            EntityType::ItFiscalCode,
            "01234567897",
        ),
        (
            "orgnr 5551234567",
            EntityType::SeOrganisationsnummer,
            "5551234567",
        ),
        (
            "organisationsnummer 556000-0000",
            EntityType::SeOrganisationsnummer,
            "556000-0000",
        ),
        ("UEN: 53012345D", EntityType::SgUen, "53012345D"),
        ("UEN: S99PF1234K", EntityType::SgUen, "S99PF1234K"),
        (
            "Personalausweis LF2K7X9RZ",
            EntityType::DeIdCard,
            "LF2K7X9RZ",
        ),
        ("VAT SE123456789001", EntityType::EuVat, "SE123456789001"),
    ] {
        assert_eq!(all(text), vec![(kind, value.to_owned())], "{text}");
    }
}

#[test]
fn checksummed_tax_number_outranks_the_card_rule() {
    // official NRW test numbers that also pass Luhn: with a cue the tax
    // number (tier 0) wins the span, without a cue the always-on card rule
    // keeps its claim
    for v in ["5400081508159", "5600081508154"] {
        assert!(redactify::valid_luhn(v), "{v}");
        assert_eq!(
            all(&format!("Steuernummer: {v}")),
            vec![(EntityType::DeTaxNumber, v.to_owned())]
        );
        assert_eq!(
            all(&format!("Akte {v}")),
            vec![(EntityType::CreditCard, v.to_owned())]
        );
    }
}

#[test]
fn other_packs_keep_their_labels_with_every_locale_enabled() {
    // 8- to 12-character shapes of other packs next to their own cue: the
    // rules of this file (9-digit LANR/BSNR, 9-character identity card,
    // 10-digit organisationsnummer, UEN formats) must not relabel them
    for (text, kind, value) in [
        (
            "identity card S2740116C",
            EntityType::SgNricFin,
            "S2740116C",
        ),
        ("NRIC S2740116C", EntityType::SgNricFin, "S2740116C"),
        ("DNI 12345678Z", EntityType::Dni, "12345678Z"),
        ("BSN 111222333", EntityType::Bsn, "111222333"),
        ("passport 123456789", EntityType::UkPassport, "123456789"),
        ("TFN 123456782", EntityType::AuTfn, "123456782"),
        (
            "Steuer-IdNr 86095742719",
            EntityType::DeTaxId,
            "86095742719",
        ),
        ("vergi no 1234567890", EntityType::Vkn, "1234567890"),
        (
            "personnummer 640823-3234",
            EntityType::SePersonnummer,
            "640823-3234",
        ),
        ("CPR 070761-4285", EntityType::DkCpr, "070761-4285"),
        ("pesel 80010123450", EntityType::Pesel, "80010123450"),
        ("utr 1234567890", EntityType::UkUtr, "1234567890"),
        ("Reisepass C3JJ4789L", EntityType::DePassport, "C3JJ4789L"),
    ] {
        assert_eq!(all(text), vec![(kind, value.to_owned())], "{text}");
    }
}

#[test]
fn documented_tie_outcomes() {
    // An 11-digit value valid as TCKN and as a numeric codice fiscale: the
    // cue-less TCKN claim (tier 3, default pack) outranks IT_FISCAL_CODE
    // (tier 7); the value is masked either way.
    assert!(valid_tckn("10000000900") && valid_it_numeric_fiscal_code("10000000900"));
    assert_eq!(
        kinds("codice fiscale 10000000900", &["tr", "it"]),
        vec![EntityType::Tckn]
    );
    assert_eq!(
        kinds("codice fiscale 10000000900", &["it"]),
        vec![EntityType::ItFiscalCode]
    );
    // An Italian passport number that also fits the German passport shape:
    // the de::passport cues are delimited label forms ("pass ", "pass:",
    // ...), so "passaporto" does not unlock the German rule and the
    // Italian label holds with both packs enabled.
    assert_eq!(
        kinds("passaporto CA1234567", &["it"]),
        vec![EntityType::ItPassport]
    );
    assert_eq!(
        kinds("passaporto CA1234567", &["de", "it"]),
        vec![EntityType::ItPassport]
    );
    // LANR and BSNR share the 9-digit shape: a value valid as both, near
    // both cues, keeps the checksummed LANR label (registered first)
    assert!(valid_de_lanr("123456601") && valid_de_bsnr("123456601"));
    assert_eq!(
        kinds("LANR/BSNR 123456601", &["de"]),
        vec![EntityType::DeLanr]
    );
}

// ------------------------------------------------------ source-based rules

#[test]
fn de_id_card_is_format_only() {
    // BT-Drs. 16/10489 § 2 Abs. 8 + ICAO Doc 9303-5: the ninth character is
    // not a check digit; a letter or a digit may stand in every position
    assert!(valid_de_id_card("LF2K7X9R3")); // no check digit
    assert!(valid_de_id_card("CF2K7X9R9")); // C as the first letter
    assert!(valid_de_id_card("L01X00T4K")); // ninth character a letter
    assert!(valid_de_id_card("T1234567")); // provisional identity card
    assert!(!valid_de_id_card("LF2K7X9R") && !valid_de_id_card("lf2k7x9r2"));
    assert_eq!(
        kinds("Personalausweis L01X00T4K hinterlegt", &["de"]),
        vec![EntityType::DeIdCard]
    );
    // "identity card" is no cue of the German rule: with de + sg enabled a
    // Singapore NRIC next to it keeps its label
    assert_eq!(
        kinds("identity card S2740116C", &["de", "sg"]),
        vec![EntityType::SgNricFin]
    );
    assert!(kinds("identity card LF2K7X9RZ", &["de"]).is_empty());
}

#[test]
fn de_id_card_uses_the_pauswv_character_set() {
    for v in [
        "LF2K7X9RZ",
        "CFGHJKLMN",
        "PRTVWXYZ9",
        "L01X00T47",
        "T1234567",
    ] {
        assert!(valid_de_id_card(v), "{v}");
    }
    for v in [
        "BEANTRAGT",
        "LF2K7X9RA",
        "LF2K7X9RO",
        "LF2K7X9RQ",
        "LF2K7X9RS",
    ] {
        assert!(!valid_de_id_card(v), "{v}");
    }
    assert_eq!(
        kinds("Personalausweis LF2K7X9RZ hinterlegt", &["de"]),
        vec![EntityType::DeIdCard]
    );
    assert!(kinds("Personalausweis BEANTRAGT, Abholung Montag", &["de"]).is_empty());
}

#[test]
fn de_tax_id_applies_the_elster_structure() {
    for v in IDNR_OFFICIAL {
        assert!(valid_de_tax_id(v), "{v}");
        assert_eq!(
            kinds(&format!("Steuer-IdNr {v}"), &["de"]),
            vec![EntityType::DeTaxId],
            "{v}"
        );
    }
    // these values pass the check digit but repeat more than
    // one digit value among the first ten (ELSTER Kap. 2.2)
    for v in [
        "97144838384",
        "78010311476",
        "35301272329",
        "63110672067",
        "77001612415",
        "47325308701",
    ] {
        assert!(!valid_de_tax_id(v), "{v}");
        assert!(
            kinds(&format!("Steuer-IdNr {v}"), &["de"]).is_empty(),
            "{v}"
        );
    }
    // the official test number keeps its leading zero (never real data)
    assert!(!valid_de_tax_id("02476291358"));
    // tripled digit: two adjacent are allowed (official 65929970489), three
    // in a row are not
    assert!(valid_de_tax_id("65929970489"));
}

#[test]
fn it_fiscal_code_day_range() {
    // DM 13813 Art. 5: 01-31 (male) / 41-71 (female); checksum-valid codes
    // with any other day are rejected
    assert!(valid_it_fiscal_code("MRTRSS85M01H501C"));
    assert!(valid_it_fiscal_code("MRTRSS8RM01H501O"));
    assert!(!valid_it_fiscal_code("DDDFFF00A00A000T")); // day 00
    assert!(!valid_it_fiscal_code("RSSMRA80A35H501K")); // day 35
    assert!(kinds("codice fiscale RSSMRA80A35H501K", &["it"]).is_empty());
    assert_eq!(
        kinds("codice fiscale MRTRSS85M01H501C", &["it"]),
        vec![EntityType::ItFiscalCode]
    );
}

#[test]
fn tr_plaka_kty_groups() {
    // KTY m. 55/1: exactly 2+3, 1+4, 3+2, 2+4, 1+5, 3+3
    for v in [
        "34 AB 123",
        "06 A 1234",
        "35 ABC 12",
        "34 AB 1234",
        "34 A 12345",
        "34 ABC 123",
    ] {
        assert!(valid_plaka(v), "{v}");
        assert_eq!(
            detect(&format!("plaka {v}"))
                .into_iter()
                .map(|e| (e.kind, e.text))
                .collect::<Vec<_>>(),
            vec![(EntityType::Plaka, (*v).to_owned())],
            "{v}"
        );
    }
    for v in [
        "34 A 12",
        "34 ABC 1234",
        "82 AB 123",
        "34 A 123",
        "34 AB 12",
    ] {
        assert!(!valid_plaka(v), "{v}");
    }
    // plate-like values outside the KTY groups
    for v in [
        "67 RAN 0100",
        "16 AY 14",
        "53 MYP 4473",
        "10 J 21",
        "66 AKG 4377",
        "69 IFB 6823",
        "56 I 072",
        "50 B 554",
        "29 A 686",
        "28 HU 60",
        "30 VMN 0626",
        "06 AAA 9999",
    ] {
        assert!(!valid_plaka(v), "{v}");
        assert!(detect(&format!("plaka {v}")).is_empty(), "{v}");
    }
    // no plate candidates outside the KTY groups: ISO 8601 times and a
    // CNPJ fragment ("01T00" = 1 letter + 2 digits, "01DE-35" = 2 + 2)
    assert!(detect("created 2023-11-01T00:00:00Z").is_empty());
    assert!(detect("updated 2024-06-05T12:30").is_empty());
    // DD-MON-YYYY dates are no 3 letters + 4 digits plates
    assert!(detect("visit on 01-JAN-2022 confirmed").is_empty());
    assert!(detect("CNPJ 12.ABC.345/01DE-35")
        .iter()
        .all(|e| e.kind != EntityType::Plaka));
}

#[test]
fn eu_vat_sweden_ends_in_01() {
    assert!(valid_eu_vat("SE999999999901"));
    assert!(!valid_eu_vat("SE999999999999"));
    assert_eq!(
        kinds("VAT SE556000000001", &["eu"]),
        vec![EntityType::EuVat]
    );
    assert!(kinds("VAT SE556000000002", &["eu"]).is_empty());
}
