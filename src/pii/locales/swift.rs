//! SWIFT BIC (ISO 9362): validator + rule.
//! Evidence (two independent sources, retrieved 2026-10-08):
//! An independent public implementation of ISO 9362:2022: length 8 or
//!   11; strict SWIFT-compliant structure `[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}`
//!   plus an optional `[A-Z0-9]{3}` branch code (`XXX` = primary
//!   office); the country code (positions 5-6) must exist in ISO
//!   3166-1 alpha-2. ISO 9362:2022 also permits digits in the 4-letter
//!   party prefix; the stricter letters-only form is used here (current
//!   SWIFT registration policy, and fewer word-shape false positives).
//! A commercial DLP vendor's published sensitive-information-type
//!   definition "SWIFT code": documents the ISO 9362
//!   association and the Checksum: No property, keywords "swift code",
//!   "bic number/code", "bank identifier code".
//! The ISO 3166-1 alpha-2 list below was generated from an
//! independent public country-code dataset (ISO OBP-derived, 249
//! codes, sorted for binary search) and is cross-checked against this
//! crate's 89-country IBAN registry in tests.
//!
//! A cue is REQUIRED: no checksum exists (passport/VKN precedent).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make a BIC candidate claimable (lowercase matching).
/// A leading cue counts when its END lies within the 18-character cue
/// window before the value (`pii::context`), so the full keyword "bank
/// identifier code" is a cue; "bank identifier" stays for its shorter
/// variants and a trailing mention (a trailing cue must lie entirely
/// inside the window). "bic" is delimited (`bic:`, `bic/` ...): bare, it
/// is a substring of "bicycle" and the Spanish "ubicacion" (residual:
/// words that end in "bic" before a delimiter, e.g. "Arabic ").
pub(super) const CUES: &[&str] = &[
    "swift",
    "bic:",
    "bic ",
    "bic#",
    "bic-",
    "bic/",
    "(bic)",
    "bank identifier code",
    "bank identifier",
];

/// ISO 3166-1 alpha-2 country codes (249, sorted; binary-searched).
const ISO_3166_1_ALPHA_2: &[&str; 249] = &[
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
    "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS",
    "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
    "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE",
    "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
    "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
    "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM",
    "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC",
    "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK",
    "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
    "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG",
    "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
    "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS",
    "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO",
    "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
    "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW",
];

/// Returns `true` if `bic` is a structurally valid SWIFT BIC: 8 or 11
/// uppercase characters, a 4-letter institution code, an existing ISO
/// 3166-1 alpha-2 country code, an alphanumeric location code and an
/// optional alphanumeric branch code.
///
/// # Examples
/// ```
/// use redactify::valid_swift_bic;
/// assert!(valid_swift_bic("DEUTDEFF"));
/// assert!(valid_swift_bic("DEUTDEFF500")); // 11-char with branch code
/// assert!(!valid_swift_bic("DEUTDEFF5"));  // 9 chars
/// assert!(!valid_swift_bic("DEUTZZFF"));   // ZZ is not a country code
/// assert!(!valid_swift_bic("deutdeff"));   // lowercase
/// ```
#[must_use]
pub fn valid_swift_bic(bic: &str) -> bool {
    let b = bic.as_bytes();
    if b.len() != 8 && b.len() != 11 {
        return false;
    }
    if !b
        .iter()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return false;
    }
    if !b[..4].iter().all(u8::is_ascii_uppercase) {
        return false;
    }
    // `str` orders by bytes, so a byte-wise search over the sorted table
    // equals a search for the two-letter code (no UTF-8 conversion)
    ISO_3166_1_ALPHA_2
        .binary_search_by(|code| code.as_bytes().cmp(&b[4..6]))
        .is_ok()
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::SwiftBic,
        r"(?<![A-Z0-9])[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?(?![A-Z0-9])",
        Some(valid_swift_bic),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::{valid_swift_bic, ISO_3166_1_ALPHA_2};

    #[test]
    fn structure() {
        assert!(valid_swift_bic("DEUTDEFF"));
        assert!(valid_swift_bic("DEUTDEFF500")); // 11-char with branch
        assert!(valid_swift_bic("NWBKGB2L")); // digit in location code
        assert!(!valid_swift_bic("DEUTDEFF5")); // 9 chars
        assert!(!valid_swift_bic("DEUTDEFF5000")); // 12 chars
        assert!(!valid_swift_bic("DEUTZZFF")); // country ZZ unassigned
        assert!(!valid_swift_bic("deutdeff")); // lowercase
        assert!(!valid_swift_bic("DEU1DEFF")); // digit in institution code
    }

    #[test]
    fn country_list_covers_iban_registry() {
        // internal consistency: every country in this crate's IBAN
        // registry must be a valid ISO 3166-1 alpha-2 code, except XK
        // (Kosovo): the IBAN registry uses it, but ISO 3166-1 keeps it
        // in the user-assigned range, so it is not in the list above
        for (code, _len) in crate::pii::locales::iban::IBAN_LENGTHS {
            if *code == "XK" {
                assert!(!ISO_3166_1_ALPHA_2.binary_search(code).is_ok());
                continue;
            }
            assert!(
                ISO_3166_1_ALPHA_2.binary_search(code).is_ok(),
                "IBAN country {code} missing from the ISO 3166 list"
            );
        }
    }
}
