//! Canadian postal code: validator + detection rule.
//!
//! Official sources (retrieved 2026-10-30):
//!
//! 1. Canada Post, "Addressing guidelines - Postal codes", sections "The
//!    structure of the postal code" and "Forward Sortation Area"
//!    (<https://www.canadapost-postescanada.ca/cpc/en/support/articles/addressing-guidelines/postal-codes.page>):
//!    "The postal code is a six-character uniformly structured,
//!    alphanumeric code in the form "ANA NAN" where "A" is an alphabetic
//!    character and "N" is a numeric character. [...] The first character
//!    of the FSA segment identifies one of the 18 major geographic areas"
//!    (the table lists A, B, C, E, G, H, J, K, L, M, N, P, R, S, T, V, X,
//!    Y); "An urban postal code: numerals 1 to 9 (for example, M2T) A rural
//!    postal code: numeral 0 (zero) (for example, A0A)".
//! 2. Canada Post Addressing Guidelines (Canadian Addressing Guide),
//!    "Postal Code" address-line rule, Internet Archive copy of 2021-02-11
//!    (<http://web.archive.org/web/20210211033837/https://www.canadapost.ca/tools/pg/manual/PGaddress-e.asp>):
//!    "Postal Code - Should be printed in uppercase [...] with one space
//!    between the first three and the last three characters. A hyphen
//!    should not be used (ex. of unacceptable format: T0L-1K0)."
//!
//! Accepted spellings: uppercase `ANA NAN` and the spaceless `ANANAN`; the
//! hyphenated form the guide calls unacceptable is not claimed. The 3rd
//! and 5th letters are not restricted: no retrieved official text
//! excludes letters there (recall-first).
//!
//! Format only: no check character exists, so a cue is REQUIRED and the
//! score is 0.9 (UK postcode precedent). Region names ("canada",
//! "ontario", ...) are not cues: they occur in ordinary prose.

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make a postal-code candidate claimable.
pub(super) const CUES: &[&str] = &["postal code", "code postal", "postcode"];

/// The 18 first letters of the Canada Post major geographic areas.
const AREA_LETTERS: &[u8; 18] = b"ABCEGHJKLMNPRSTVXY";

/// Returns `true` if `s` is a Canadian postal code in the Canada Post form
/// `ANA NAN` (one space) or `ANANAN`, uppercase, whose first letter is one
/// of the 18 major geographic areas.
///
/// # Examples
/// ```
/// use redactify::valid_ca_postal_code;
/// assert!(valid_ca_postal_code("T0L 1K0")); // Canada Post guide example
/// assert!(valid_ca_postal_code("T0L1K0"));
/// assert!(!valid_ca_postal_code("T0L-1K0")); // "unacceptable format"
/// assert!(!valid_ca_postal_code("D0L 1K0")); // D is not an area letter
/// ```
#[must_use]
pub fn valid_ca_postal_code(s: &str) -> bool {
    let b = s.as_bytes();
    let code: [u8; 6] = match b.len() {
        6 => [b[0], b[1], b[2], b[3], b[4], b[5]],
        7 if b[3] == b' ' => [b[0], b[1], b[2], b[4], b[5], b[6]],
        _ => return false,
    };
    AREA_LETTERS.contains(&code[0])
        && code[1].is_ascii_digit()
        && code[2].is_ascii_uppercase()
        && code[3].is_ascii_digit()
        && code[4].is_ascii_uppercase()
        && code[5].is_ascii_digit()
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::CaPostalCode,
        r"(?<![A-Za-z0-9])[ABCEGHJ-NPRSTVXY][0-9][A-Z] ?[0-9][A-Z][0-9](?![A-Za-z0-9])",
        Some(valid_ca_postal_code),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_ca_postal_code;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn format_vectors() {
        assert!(valid_ca_postal_code("T0L 1K0"));
        assert!(valid_ca_postal_code("T0L1K0"));
        assert!(valid_ca_postal_code("M2T 1A1")); // urban FSA example
        assert!(valid_ca_postal_code("A0A 1B1")); // rural FSA example
        assert!(!valid_ca_postal_code("T0L-1K0"));
        assert!(!valid_ca_postal_code("D0L 1K0"));
        assert!(!valid_ca_postal_code("W1A 1A1")); // W is not an area letter
        assert!(!valid_ca_postal_code("t0l 1k0")); // lowercase
        assert!(!valid_ca_postal_code("T0L  1K0")); // two spaces
        assert!(!valid_ca_postal_code("T0L 1K"));
        assert!(!valid_ca_postal_code(""));
    }

    #[test]
    fn cue_required() {
        let kinds = |t: &str| -> Vec<EntityType> {
            engine_detect(t, &["ca"])
                .into_iter()
                .map(|e| e.kind)
                .collect()
        };
        assert_eq!(
            kinds("postal code T0L 1K0 Alberta"),
            vec![EntityType::CaPostalCode]
        );
        assert_eq!(
            kinds("Code postal : H2X1Y4"),
            vec![EntityType::CaPostalCode]
        );
        assert!(kinds("Ontario T0L 1K0 office").is_empty());
        assert!(kinds("postal code T0L-1K0").is_empty());
    }
}
