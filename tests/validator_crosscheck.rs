//! Independent cross-verification of the locale checksum validators.
//!
//! `data/validator_crosscheck.jsonl` is produced by a separate Python
//! re-implementation kept outside this repository - every published
//! algorithm implemented again (written from the same spec docs the Rust
//! code cites). Every row is a value the Python side computed as valid
//! (checksum-completed, plus separator-stripping variants) or corrupted to
//! invalid; this test feeds each row to the Rust validator and asserts
//! agreement. ANY disagreement is a transcription bug in one of the two
//! implementations and must be investigated, never silenced.

use redactify::{
    valid_au_abn, valid_au_acn, valid_au_medicare, valid_au_tfn, valid_br_cnpj, valid_br_cpf,
    valid_bsn, valid_ca_postal_code, valid_ca_sin, valid_cn_resident_id, valid_credit_card,
    valid_de_bsnr, valid_de_id_card, valid_de_kfz, valid_de_kvnr, valid_de_lanr, valid_de_rvnr,
    valid_de_tax_id, valid_de_tax_number, valid_dk_cpr, valid_dni, valid_eu_vat, valid_fi_hetu,
    valid_fr_siret, valid_iban, valid_in_aadhaar, valid_in_gstin, valid_it_fiscal_code,
    valid_it_numeric_fiscal_code, valid_it_passport, valid_kr_brn, valid_kr_frn, valid_kr_passport,
    valid_kr_rrn, valid_luhn, valid_ng_nin, valid_nie, valid_nir, valid_no_fodselsnummer,
    valid_pesel, valid_ph_tin, valid_pl_nip, valid_plaka, valid_pt_nif,
    valid_se_organisationsnummer, valid_se_personnummer, valid_sg_uen, valid_tckn, valid_th_tnin,
    valid_uk_driving_licence, valid_uk_vat, valid_uk_vehicle_reg, valid_us_aba_routing,
    valid_us_ein, valid_us_mbi, valid_us_npi, valid_vkn, valid_za_company_registration,
    valid_za_id_number, valid_za_phone, valid_za_tax_reference, valid_za_vat,
};

fn run(name: &str, value: &str) -> bool {
    match name {
        "valid_tckn" => valid_tckn(value),
        "valid_vkn" => valid_vkn(value),
        "valid_credit_card" => valid_credit_card(value),
        "valid_iban" => valid_iban(value),
        "valid_dni" => valid_dni(value),
        "valid_nie" => valid_nie(value),
        "valid_pesel" => valid_pesel(value),
        "valid_pl_nip" => valid_pl_nip(value),
        "valid_it_fiscal_code" => valid_it_fiscal_code(value),
        "valid_bsn" => valid_bsn(value),
        "valid_uk_vat" => valid_uk_vat(value),
        "valid_au_abn" => valid_au_abn(value),
        "valid_au_tfn" => valid_au_tfn(value),
        "valid_au_medicare" => valid_au_medicare(value),
        "valid_ca_sin" => valid_ca_sin(value),
        "valid_pt_nif" => valid_pt_nif(value),
        "valid_nir" => valid_nir(value),
        "valid_de_tax_id" => valid_de_tax_id(value),
        "valid_de_id_card" => valid_de_id_card(value),
        "valid_in_aadhaar" => valid_in_aadhaar(value),
        "valid_fr_siret" => valid_fr_siret(value),
        "valid_luhn" => valid_luhn(value),
        "valid_br_cpf" => valid_br_cpf(value),
        "valid_br_cnpj" => valid_br_cnpj(value),
        "valid_cn_resident_id" => valid_cn_resident_id(value),
        "valid_se_personnummer" => valid_se_personnummer(value),
        "valid_fi_hetu" => valid_fi_hetu(value),
        "valid_no_fodselsnummer" => valid_no_fodselsnummer(value),
        "valid_dk_cpr" => valid_dk_cpr(value),
        "valid_eu_vat" => valid_eu_vat(value),
        "valid_us_aba_routing" => valid_us_aba_routing(value),
        "valid_us_npi" => valid_us_npi(value),
        "valid_us_mbi" => valid_us_mbi(value),
        "valid_us_ein" => valid_us_ein(value),
        "valid_ca_postal_code" => valid_ca_postal_code(value),
        "valid_uk_driving_licence" => valid_uk_driving_licence(value),
        "valid_uk_vehicle_reg" => valid_uk_vehicle_reg(value),
        "valid_au_acn" => valid_au_acn(value),
        "valid_de_bsnr" => valid_de_bsnr(value),
        "valid_de_kfz" => valid_de_kfz(value),
        "valid_de_kvnr" => valid_de_kvnr(value),
        "valid_de_lanr" => valid_de_lanr(value),
        "valid_de_rvnr" => valid_de_rvnr(value),
        "valid_de_tax_number" => valid_de_tax_number(value),
        "valid_it_numeric_fiscal_code" => valid_it_numeric_fiscal_code(value),
        "valid_it_passport" => valid_it_passport(value),
        "valid_plaka" => valid_plaka(value),
        "valid_se_organisationsnummer" => valid_se_organisationsnummer(value),
        "valid_sg_uen" => valid_sg_uen(value),
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
        other => panic!("unknown validator {other}"),
    }
}

#[test]
fn rust_and_python_implementations_agree_row_by_row() {
    let data = std::fs::read_to_string("data/validator_crosscheck.jsonl")
        .expect("data/validator_crosscheck.jsonl (run from repo root)");
    let mut checked = 0usize;
    let mut mismatches: Vec<String> = Vec::new();
    for line in data.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let name = v["validator"].as_str().unwrap();
        let value = v["value"].as_str().unwrap();
        let expected = v["expected"].as_bool().unwrap();
        let got = run(name, value);
        if got != expected {
            mismatches.push(format!(
                "{name}({value:?}) = {got}, reference says {expected}"
            ));
        }
        checked += 1;
    }
    assert_eq!(
        checked, 3257,
        "row count is part of the contract (regenerate with the external re-implementation)"
    );
    assert!(
        mismatches.is_empty(),
        "{} disagreement(s) between the Rust and Python implementations:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
