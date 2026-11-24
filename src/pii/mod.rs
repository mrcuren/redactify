//! PII detection core (L1 layer): the generic engine, locale rule sets and
//! reversible pseudonymization (vault).
//!
//! Structure: `rule.rs` defines the rule model, `locales/<iso>/` provide the
//! rules (validator + pattern + cue policy per identifier, one file each),
//! `detect.rs` is the shared engine (line-scoped scan, scoring, overlap
//! resolution), `redact.rs` masks the results, and `vault.rs` provides
//! reversible pseudonymization for LLM round-trips.

mod context;
pub(crate) mod custom;
mod detect;
mod entity;
pub(crate) mod lang_gate;
pub(crate) mod locales;
mod ner;
mod redact;
mod rule;
pub(crate) mod tr_suffix;
pub(crate) mod vault;

pub use custom::{
    CustomRule, CustomRuleError, CustomRuleSpec, CustomRules, CustomRulesError,
    LINEAR_MAX_PATTERN_BYTES, LINEAR_MIN_MATCH_LEN,
};
pub use detect::{DetectionSource, DetectionView, Explanation};
pub use entity::{
    CustomLabel, CustomLabelError, Entity, EntityType, EntityTypeParseError, MAX_CUSTOM_LABELS,
    MAX_CUSTOM_LABEL_LEN,
};
pub use locales::au::abn::valid_au_abn;
pub use locales::au::acn::valid_au_acn;
pub use locales::au::medicare::valid_au_medicare;
pub use locales::au::phone::valid_au_phone;
pub use locales::au::tfn::valid_au_tfn;
pub use locales::br::cnpj::valid_br_cnpj;
pub use locales::br::cpf::valid_br_cpf;
pub use locales::ca::postal_code::valid_ca_postal_code;
pub use locales::ca::sin::valid_ca_sin;
pub use locales::cn::resident_id::valid_cn_resident_id;
pub use locales::crypto::{valid_btc_address, valid_eth_address};
pub use locales::de::bsnr::valid_de_bsnr;
pub use locales::de::id_card::valid_de_id_card;
pub use locales::de::kfz::valid_de_kfz;
pub use locales::de::kvnr::valid_de_kvnr;
pub use locales::de::lanr::valid_de_lanr;
pub use locales::de::rvnr::valid_de_rvnr;
pub use locales::de::tax_id::valid_de_tax_id;
pub use locales::de::tax_number::valid_de_tax_number;
pub use locales::dk::cpr::valid_dk_cpr;
pub use locales::en::aba_routing::valid_us_aba_routing;
pub use locales::en::ein::valid_us_ein;
pub use locales::en::mbi::valid_us_mbi;
pub use locales::en::npi::valid_us_npi;
pub use locales::en::phone::valid_us_phone;
pub use locales::en::ssn::valid_ssn;
pub use locales::en::us_passport::valid_us_passport;
pub use locales::es::dni::valid_dni;
pub use locales::es::nie::valid_nie;
pub use locales::eu::vat::valid_eu_vat;
pub use locales::fi::hetu::valid_fi_hetu;
pub use locales::fr::nir::valid_nir;
pub use locales::fr::siret::valid_fr_siret;
pub use locales::generic::{
    valid_credit_card, valid_intl_phone, valid_ip_address, valid_luhn, valid_public_ip_address,
    valid_url,
};
pub use locales::iban::valid_iban;
pub use locales::in_::aadhaar::valid_in_aadhaar;
pub use locales::in_::gstin::valid_in_gstin;
pub use locales::in_::pan::valid_in_pan;
pub use locales::in_::phone::valid_in_phone;
pub use locales::it::fiscal_code::valid_it_fiscal_code;
pub use locales::it::numeric_fiscal_code::valid_it_numeric_fiscal_code;
pub use locales::it::passport::valid_it_passport;
pub use locales::kr::brn::valid_kr_brn;
pub use locales::kr::frn::valid_kr_frn;
pub use locales::kr::passport::valid_kr_passport;
pub use locales::kr::rrn::valid_kr_rrn;
pub use locales::ng::nin::valid_ng_nin;
pub use locales::nl::bsn::valid_bsn;
pub use locales::no::fodselsnummer::valid_no_fodselsnummer;
pub use locales::ph::tin::valid_ph_tin;
pub use locales::pl::nip::valid_pl_nip;
pub use locales::pl::pesel::valid_pesel;
pub use locales::pl::phone::valid_pl_phone;
pub use locales::pt::nif::valid_pt_nif;
pub use locales::se::organisationsnummer::valid_se_organisationsnummer;
pub use locales::se::personnummer::valid_se_personnummer;
pub use locales::sg::nric_fin::valid_sg_nric_fin;
pub use locales::sg::phone::valid_sg_phone;
pub use locales::sg::uen::valid_sg_uen;
pub use locales::swift::valid_swift_bic;
pub use locales::th::tnin::valid_th_tnin;
pub use locales::tr::iban::valid_iban_tr;
pub use locales::tr::passport::valid_passport;
pub use locales::tr::plaka::valid_plaka;
pub use locales::tr::tckn::valid_tckn;
pub use locales::tr::vkn::valid_vkn;
pub use locales::uk::driving_licence::valid_uk_driving_licence;
pub use locales::uk::nhs::valid_uk_nhs;
pub use locales::uk::nino::valid_nino;
pub use locales::uk::vat::valid_uk_vat;
pub use locales::uk::vehicle_reg::valid_uk_vehicle_reg;
pub use locales::vin::valid_vin;
pub use locales::za::company_registration::valid_za_company_registration;
pub use locales::za::id_number::valid_za_id_number;
pub use locales::za::phone::valid_za_phone;
pub use locales::za::tax_reference::valid_za_tax_reference;
pub use locales::za::vat::valid_za_vat;
pub use locales::SUPPORTED_LOCALES;
pub use ner::{MockNameRecognizer, NerHealth, NerRecognizer};
pub use vault::{RestoreOptions, StreamRestorer, Vault, VaultError, MAX_VAULT_ENTRIES};

pub(crate) use detect::{detect, run, EngineOpts, EngineOutput};
// the JSON redactor's tail bound is pinned against the cue window by a test
#[cfg(test)]
pub(crate) use detect::CUE_WINDOW;
pub(crate) use redact::{replace_spans, ReplaceSpan};
