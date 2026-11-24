# validator_crosscheck.jsonl - provenance

Producer: a separate Python re-implementation of the validators
(deterministic, seed 20261017), kept outside this repository (the
repository holds Rust code only); the vectors in this file are its output.
Purpose: independent cross-verification of the locale checksum, birth-date
and format validators.

Method: the Python file contains an INDEPENDENT re-implementation of every
algorithm, written from the same published-spec documentation the Rust code
cites (official registries, government and tax-authority texts, independent
public formulations, ICAO/ISO texts as recorded in each `src/pii/locales/**`
file header). The BR, CN, SE, FI, NO, DK and EU VAT implementations are
written from the official texts quoted in their module docs (Receita Federal, GB 11643-1999,
Skatteverket SKV 704, Finnish decree 690/2022, Skatteetaten, CPR-kontoret,
the VIES structure table) with deliberately different formulations (weight
lists instead of modular weight formulas, lookup tables instead of
formulas, candidate enumeration instead of the remainder-range shortcut).
It generates, per validator:

- 25 VALID vectors (random digits/letters + check digit/letter computed by
  the Python implementation; for the format-only `valid_eu_vat` and the
  date-only `valid_dk_cpr`, values drawn inside the published structure),
  every third one re-formatted with the separators the Rust validator
  strips (IBAN spaces, card groups, TFN/Medicare/SIN/NIF/Aadhaar
  separators, the CPF/CNPJ masks, the Swedish and Danish hyphen forms);
- 25 INVALID vectors (one digit corrupted, verified invalid by the Python
  side before emission; `valid_eu_vat` breaks the length or the country
  prefix instead, since it has no check digit).

Known-good anchor vectors are asserted against the Python implementations
BEFORE generation, so a transcription bug in the generator fails at the
source instead of producing mass false mismatches: the repo's own doctest
vectors (`4111111111111111`, `51824753556`, `607324134360`,
`TR33...413 26`, `80010123450`, `12345678950`) and the official worked
examples of the official sources (`12ABC34501DE35`, `12.345.678/0001-95`,
`11010519491231002X`, `440524188001010014`, `640823-3234`,
`196408233234`, `02013299997`, `30108299920`, `30108299939`,
`07 07 61-4285`; the format-only FAQ illustration `AA345678/0003-29` is
asserted INVALID).

Composition: 3,257 rows across 61 validators
(valid_tckn, valid_vkn, valid_credit_card, valid_iban, valid_dni,
valid_nie, valid_pesel, valid_pl_nip, valid_it_fiscal_code, valid_bsn,
valid_uk_vat, valid_au_abn, valid_au_tfn, valid_au_medicare, valid_ca_sin,
valid_pt_nif, valid_nir, valid_de_tax_id, valid_de_id_card,
valid_in_aadhaar, valid_fr_siret, valid_br_cpf, valid_br_cnpj,
valid_cn_resident_id, valid_se_personnummer, valid_fi_hetu,
valid_no_fodselsnummer, valid_dk_cpr, valid_eu_vat, valid_us_aba_routing,
valid_us_npi, valid_us_mbi, valid_us_ein, valid_ca_postal_code,
valid_uk_driving_licence, valid_uk_vehicle_reg, valid_au_acn, valid_de_kvnr,
valid_de_lanr, valid_de_bsnr, valid_de_rvnr, valid_de_kfz,
valid_de_tax_number, valid_it_numeric_fiscal_code, valid_it_passport,
valid_se_organisationsnummer, valid_sg_uen, valid_plaka, valid_in_gstin,
valid_kr_rrn, valid_kr_frn, valid_kr_brn, valid_kr_passport, valid_ng_nin,
valid_ph_tin, valid_th_tnin, valid_za_id_number, valid_za_tax_reference,
valid_za_vat, valid_za_company_registration, valid_za_phone).

Consumer: `tests/validator_crosscheck.rs` - every row is fed to the Rust
validator; ANY disagreement fails the build with the offending vectors
listed. All 3,257 rows agree (zero divergence).

After touching a validator, regenerate the vectors with that external
implementation and update the row-count contract in the test if the
count changes.
