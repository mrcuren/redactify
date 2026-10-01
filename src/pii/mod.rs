//! PII detection core (L1 layer): the generic engine, locale rule sets and
//! reversible anonymization (vault).
//!
//! Structure: `rule.rs` defines the rule model, `locales/<iso>/` provide the
//! rules (validator + pattern + cue policy per identifier, one file each),
//! `detect.rs` is the shared engine (line-scoped scan, scoring, overlap
//! resolution), `redact.rs` masks the results, and `vault.rs` provides
//! reversible anonymization for LLM round-trips.

mod context;
mod detect;
mod entity;
pub(crate) mod locales;
mod redact;
mod rule;
pub mod vault;

pub use detect::{detect, detect_with_locales, detect_with_threshold};
pub use entity::{Entity, EntityType};
pub use locales::en::ssn::valid_ssn;
pub use locales::en::us_passport::valid_us_passport;
pub use locales::generic::valid_luhn;
pub use locales::tr::iban::valid_iban_tr;
pub use locales::tr::passport::valid_passport;
pub use locales::tr::plaka::valid_plaka;
pub use locales::tr::tckn::valid_tckn;
pub use locales::tr::vkn::valid_vkn;
pub use redact::{redact, redact_with_mask};
pub use vault::Vault;
