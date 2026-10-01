//! Entity types and span representation for detected PII.
//!
//! [`Entity::start`] / [`Entity::end`] are **byte offsets**; they come from regex
//! match boundaries and therefore always sit on UTF-8 character boundaries
//! (slicing never panics).

use std::fmt;

/// Detectable PII entity types.
///
/// The entity with the lower `priority()` wins among overlapping candidates
/// (e.g. digit groups inside an IBAN can never be claimed as a VKN).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EntityType {
    /// Turkish IBAN (TR + 24 digits, mod-97 validated).
    Iban,
    /// Credit/bank card (Luhn validated).
    CreditCard,
    /// Vehicle plate (81-province aware).
    Plaka,
    /// Turkish national ID (11 digits, two check digits).
    Tckn,
    /// E-mail address.
    Email,
    /// Phone number (prefixed or separator-bearing mobile; landline with separators).
    Phone,
    /// Turkish passport number (biometric: `U` + 8 digits; context cue required).
    Passport,
    /// US Social Security Number (separator-bearing format + structural rules).
    Ssn,
    /// US Individual Taxpayer Identification Number (`9xx` + restricted middle).
    Itin,
    /// US passport number (Next Generation: one letter + 8 digits; cue required).
    UsPassport,
    /// Turkish tax number (10 digits, single check digit + context rule).
    Vkn,
}

impl EntityType {
    /// Priority in overlap resolution: the lower value wins.
    ///
    /// IBAN(0) < CREDIT_CARD(1) < PLAKA(2) < TCKN(3) < EMAIL(4) < PHONE(5)
    /// < PASSPORT(6) < VKN(7)
    #[must_use]
    pub const fn priority(self) -> u8 {
        match self {
            Self::Iban => 0,
            Self::CreditCard => 1,
            Self::Plaka => 2,
            Self::Tckn => 3,
            Self::Email => 4,
            Self::Phone => 5,
            Self::Passport | Self::Ssn | Self::Itin | Self::UsPassport => 6,
            Self::Vkn => 7,
        }
    }

    /// Canonical short label (`"TCKN"`, `"IBAN"`, ...).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tckn => "TCKN",
            Self::Iban => "IBAN",
            Self::CreditCard => "CREDIT_CARD",
            Self::Plaka => "PLAKA",
            Self::Vkn => "VKN",
            Self::Phone => "PHONE",
            Self::Email => "EMAIL",
            Self::Passport => "PASSPORT",
            Self::Ssn => "SSN",
            Self::Itin => "ITIN",
            Self::UsPassport => "US_PASSPORT",
        }
    }
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A validated, non-overlapping PII span.
///
/// Note: `Eq` is not derived because of `score: f32` (f32 has no total equality).
#[derive(Debug, Clone, PartialEq)]
pub struct Entity {
    /// Entity type.
    pub kind: EntityType,
    /// Span start (byte offset, inclusive).
    pub start: usize,
    /// Span end (byte offset, exclusive).
    pub end: usize,
    /// The raw matched text.
    pub text: String,
    /// Confidence score (0.0-1.0):
    /// - **1.0** - checksum verified (TCKN/IBAN/card/VKN; mathematical certainty),
    /// - **0.95** - plate + a nearby context cue ("plaka", "araç plakasi", ...),
    /// - **0.9** - passport (format + mandatory context cue; no checksum),
    /// - **0.85** - plate (format+province) or e-mail (strict regex),
    /// - **0.80** - phone (structural pattern; no model-based validation).
    ///
    /// Detections below a score cutoff can be dropped with
    /// [`crate::detect_with_threshold`].
    pub score: f32,
}

impl Entity {
    /// Byte length of the span.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the span is empty (spans are never empty in this API; kept for completeness).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.end == self.start
    }
}
