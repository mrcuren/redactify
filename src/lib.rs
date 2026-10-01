//! # redactify
//!
//! **Checksum-validated** PII (personally identifiable information) detection and
//! redaction. This release ships with the Turkish identifier set; the architecture
//! (pattern + validator + priority) extends to any country's structured identifiers.
//!
//! Structured identifiers carry math: a **TCKN** has 11 digits and two check digits,
//! a **VKN** has its own checksum, an **IBAN** is mod-97, and a **plate** encodes one
//! of 81 provinces. Treating a bare 11-digit number as a "TCKN" floods you with false
//! positives; **validating the checksum** makes redaction precise. This release
//! detects and masks:
//!
//! - [`TCKN`](EntityType::Tckn) - 11 digits, checksum-validated
//! - [`IBAN-TR`](EntityType::Iban) - ISO-13616 mod-97 validated
//! - [`VKN`](EntityType::Vkn) - 10 digits + context rule
//! - [`Passport`](EntityType::Passport) - `U` + 8 digits + context rule
//! - [`Plate`](EntityType::Plaka) - 81-province aware
//! - [`Phone`](EntityType::Phone), [`Email`](EntityType::Email), [`CreditCard`](EntityType::CreditCard) - structural/Luhn validated
//!
//! # Quick start
//!
//! ```
//! use redactify::{detect, redact, EntityType};
//!
//! // 1) Masking:
//! assert_eq!(
//!     redact("TCKN'm 12345678950, IBAN TR33 0006 1005 1978 6457 8413 26, mail a@b.com"),
//!     "TCKN'm [TCKN], IBAN [IBAN], mail [EMAIL]"
//! );
//!
//! // 2) A non-checksum order number stays UNCHANGED (precision):
//! let s = "Sipariş numaranız 12000345671 olarak kaydedildi.";
//! assert_eq!(redact(s), s);
//!
//! // 3) Typed spans:
//! let ents = detect("Beni 0532 123 45 67'den ara.");
//! assert_eq!(ents[0].kind, EntityType::Phone);
//! assert_eq!(&ents[0].text, "0532 123 45 67");
//! ```
//!
//! # Honest limits
//!
//! - Checksums cut false positives but do **not** guarantee real-world recall:
//!   messy formatting and OCR noise remain hard.
//! - The VKN has a single check digit (~10% of random strings pass); therefore a
//!   bare VKN is only masked when a `vergi`/`VKN` cue appears nearby. This trades
//!   recall for precision deliberately.
//! - Names/addresses carry no checksum -> out of scope. This is an **identifier
//!   redactor**, not a full anonymizer, and it offers no KVKK compliance guarantee.
//!
//! # Layout
//!
//! - [`pii`]: the L1 detection core (private module; re-exported flat here).
//! - [`guard`]: the L0/L4 deterministic guard rules and normalization.
//! - [`policy`]: signal + PII decision making.
//!
//! # Dependency note
//!
//! Dependencies are minimal and auditable: `fancy-regex` (lookaround-capable
//! backtracking engine), `unicode-normalization` and `base64` (guardrails L0).

#![deny(missing_docs)]

pub mod guard;
mod pii;
pub mod policy;

pub use guard::normalize;
pub use pii::{
    detect, detect_with_locales, detect_with_threshold, redact, redact_with_mask, valid_iban_tr,
    valid_luhn, valid_passport, valid_plaka, valid_ssn, valid_tckn, valid_us_passport, valid_vkn,
    Entity, EntityType, Vault,
};
