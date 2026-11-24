//! National-ID packs `br` (CPF, CNPJ), `cn` (resident ID), `se`
//! (personnummer), `fi` (henkilötunnus), `no` (fødselsnummer / d-nummer),
//! `dk` (CPR) and the `eu` VAT pack, through the public `Detector` surface.
//!
//! Policies under test (each rule file documents its official source):
//! formatted CPF/CNPJ, the resident ID and the HETU are claimed cue-less;
//! the Swedish separator form is claimed cue-less at 0.85 and boosted to
//! 1.0 by a cue; bare CPF/CNPJ/personnummer, the fødselsnummer, the CPR
//! number and EU VAT numbers need a cue; CPR (date only) and EU VAT
//! (format only) score 0.9.

use redactify::{Detector, EntityType, MaskStyle};

fn detect_in(text: &str, locales: &[&str]) -> Vec<(EntityType, String, f32)> {
    Detector::new()
        .with_locales(locales)
        .detect(text)
        .into_iter()
        .map(|e| (e.kind, e.text, e.score))
        .collect()
}

fn one(text: &str, locales: &[&str]) -> (EntityType, String, f32) {
    let ents = detect_in(text, locales);
    assert_eq!(ents.len(), 1, "{text:?}: {ents:?}");
    ents.into_iter().next().unwrap()
}

#[test]
fn official_examples_are_detected_with_their_label() {
    let cases: &[(&str, &[&str], EntityType, &str)] = &[
        (
            "CPF do titular: 529.982.247-25",
            &["br"],
            EntityType::BrCpf,
            "529.982.247-25",
        ),
        (
            "CNPJ 12.ABC.345/01DE-35 (novo formato)",
            &["br"],
            EntityType::BrCnpj,
            "12.ABC.345/01DE-35",
        ),
        (
            "matriz 12.345.678/0001-95",
            &["br"],
            EntityType::BrCnpj,
            "12.345.678/0001-95",
        ),
        (
            "公民身份号码 11010519491231002X",
            &["cn"],
            EntityType::CnResidentId,
            "11010519491231002X",
        ),
        (
            "Personnummer 640823-3234",
            &["se"],
            EntityType::SePersonnummer,
            "640823-3234",
        ),
        (
            "hetu 131052-308T",
            &["fi"],
            EntityType::FiHetu,
            "131052-308T",
        ),
        (
            "fødselsnummer 30108299939",
            &["no"],
            EntityType::NoFodselsnummer,
            "30108299939",
        ),
        (
            "CPR-nummer 07 07 61-4285",
            &["dk"],
            EntityType::DkCpr,
            "07 07 61-4285",
        ),
        (
            "USt-IdNr. / MwSt ATU12345678",
            &["eu"],
            EntityType::EuVat,
            "ATU12345678",
        ),
    ];
    for (text, locales, kind, span) in cases {
        let (k, t, _) = one(text, locales);
        assert_eq!(k, *kind, "{text:?}");
        assert_eq!(t, *span, "{text:?}");
    }
}

#[test]
fn scores_follow_the_documented_cue_policy() {
    // checksum-verified, cue-less shapes: 1.0
    assert_eq!(one("x 529.982.247-25", &["br"]).2, 1.0);
    assert_eq!(one("x 12.ABC.345/01DE-35", &["br"]).2, 1.0);
    assert_eq!(one("x 440524188001010014", &["cn"]).2, 1.0);
    assert_eq!(one("x 131052-308T", &["fi"]).2, 1.0);
    // Swedish separator form: cue-less 0.85, boosted to 1.0 by a cue
    assert!((one("x 640823-3234", &["se"]).2 - 0.85).abs() < 1e-6);
    assert_eq!(one("samordningsnummer 640883-3231", &["se"]).2, 1.0);
    // cue-required checksummed forms: 1.0
    assert_eq!(one("cpf 52998224725", &["br"]).2, 1.0);
    assert_eq!(one("cnpj 12ABC34501DE35", &["br"]).2, 1.0);
    assert_eq!(one("personnummer 196408233234", &["se"]).2, 1.0);
    assert_eq!(one("d-nummer 41019012393", &["no"]).2, 1.0);
    // date-only CPR and format-only VAT: 0.9
    assert!((one("CPR 070761-4285", &["dk"]).2 - 0.9).abs() < 1e-6);
    assert!((one("VAT NL123456789B01", &["eu"]).2 - 0.9).abs() < 1e-6);
}

#[test]
fn cue_required_forms_stay_silent_without_their_cue() {
    for (text, locales) in [
        ("pedido 52998224725 enviado", &["br"][..]),
        ("lote 12ABC34501DE35 enviado", &["br"]),
        ("order 196408233234 shipped", &["se"]),
        ("ordre 30108299939 sendt", &["no"]),
        ("ordre 070761-4286 sendt", &["dk"]),
        ("pallet ATU12345678 stacked", &["eu"]),
    ] {
        assert!(detect_in(text, locales).is_empty(), "{text:?}");
    }
}

#[test]
fn checksum_failures_are_never_claimed_even_with_a_cue() {
    for (text, locales) in [
        ("CPF 529.982.247-26", &["br"][..]),
        ("CNPJ 12.ABC.345/01DE-36", &["br"]),
        ("身份号码 11010519491231002Y", &["cn"]),
        ("身份号码 110105194912310021", &["cn"]),
        ("personnummer 640823-3235", &["se"]),
        ("henkilötunnus 131052-308U", &["fi"]),
        ("fødselsnummer 02013299998", &["no"]),
        ("CPR 310261-4285", &["dk"]), // 31 February
        ("VAT ES123456789", &["eu"]), // ES: both ends numeric
    ] {
        assert!(detect_in(text, locales).is_empty(), "{text:?}");
    }
}

#[test]
fn priority_tiers_keep_the_national_label_over_a_card_reading() {
    // both values also pass Luhn: the card rule must not relabel them
    assert!(redactify::valid_luhn("440524188001010014"));
    assert_eq!(
        one("id 440524188001010014", &["cn"]).0,
        EntityType::CnResidentId
    );
    assert!(redactify::valid_luhn("11222363000198"));
    assert_eq!(one("CNPJ 11222363000198", &["br"]).0, EntityType::BrCnpj);
    // without the cn pack the same 18 digits are a Luhn-valid card
    assert_eq!(
        one("id 440524188001010014", &["tr"]).0,
        EntityType::CreditCard
    );
}

#[test]
fn danish_and_swedish_shapes_coexist() {
    // the CPR office's own example also passes the Swedish
    // samordningsnummer date (61 - 60) and Luhn check
    assert!(redactify::valid_se_personnummer("070761-4285"));
    let both = ["se", "dk"];
    // a "cpr" cue keeps the Danish label (tier 3, dk registered first)
    assert_eq!(one("CPR 070761-4285", &both).0, EntityType::DkCpr);
    // without a cue only the cue-less Swedish separator rule can claim it
    let (k, _, score) = one("ref 070761-4285", &both);
    assert_eq!(k, EntityType::SePersonnummer);
    assert!((score - 0.85).abs() < 1e-6);
    // a Swedish number is never a CPR number (day 64 does not exist)
    assert_eq!(
        one("personnummer 640823-3234", &both).0,
        EntityType::SePersonnummer
    );
}

#[test]
fn eu_vat_wins_over_a_national_digit_rule_by_span() {
    // PL NIP and EU VAT share tier 7: the prefixed VAT span is longer
    let nip = "1234563218";
    assert!(redactify::valid_pl_nip(nip));
    let text = format!("NIP / VAT PL{nip}");
    let (k, t, _) = one(&text, &["pl", "eu"]);
    assert_eq!(k, EntityType::EuVat);
    assert_eq!(t, format!("PL{nip}"));
}

#[test]
fn nordic_document_redacts_every_identifier() {
    let text = "Kund: personnummer 640823-3234, Kunde: CPR 290236-9234, \
                Asiakas: hetu 010594Y9032, Kunde: fødselsnummer 02013299997.";
    let out = Detector::new()
        .with_locales(&["se", "dk", "fi", "no"])
        .with_mask_style(MaskStyle::Label)
        .redact(text);
    assert_eq!(
        out,
        "Kund: personnummer [SE_PERSONNUMMER], Kunde: CPR [DK_CPR], \
         Asiakas: hetu [FI_HETU], Kunde: fødselsnummer [NO_FODSELSNUMMER]."
    );
}

#[test]
fn labels_parse_back() {
    for kind in [
        EntityType::BrCpf,
        EntityType::BrCnpj,
        EntityType::CnResidentId,
        EntityType::SePersonnummer,
        EntityType::FiHetu,
        EntityType::NoFodselsnummer,
        EntityType::DkCpr,
        EntityType::EuVat,
    ] {
        assert_eq!(kind.as_str().parse::<EntityType>(), Ok(kind));
        assert_eq!(kind.to_string(), kind.as_str());
    }
    let err = "BR-CPF".parse::<EntityType>().unwrap_err();
    let _: &redactify::EntityTypeParseError = &err;
    assert!(err.to_string().contains("BR-CPF"));
}

#[cfg(feature = "serde")]
#[test]
fn serde_labels_equal_as_str() {
    for kind in [
        EntityType::BrCpf,
        EntityType::BrCnpj,
        EntityType::CnResidentId,
        EntityType::SePersonnummer,
        EntityType::FiHetu,
        EntityType::NoFodselsnummer,
        EntityType::DkCpr,
        EntityType::EuVat,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, format!("\"{}\"", kind.as_str()));
        let back: EntityType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kind);
    }
}
