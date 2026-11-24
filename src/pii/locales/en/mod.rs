//! English (US) identifier rules: SSN, ITIN, US passports, MRN,
//! ZIP code, ABA routing number, NPI, MBI, EIN, labeled-context person
//! names.

pub(crate) mod aba_routing;
pub(crate) mod ein;
pub(crate) mod itin;
pub(crate) mod mbi;
pub(crate) mod mrn;
pub(crate) mod name;
pub(crate) mod npi;
pub(crate) mod phone;
pub(crate) mod ssn;
pub(crate) mod us_passport;
pub(crate) mod zip;
