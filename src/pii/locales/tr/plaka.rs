//! Turkish vehicle plate: validator + detection rule (province + alphabet + cue boost).

use fancy_regex::Regex;
use std::sync::LazyLock;

static PLAKA_FULL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\d{2})\s?([A-PR-VY-Z]{1,3})\s?(\d{2,4})$")
        .expect("embedded plate pattern compiles")
});

/// Returns `true` if `plate` is a valid Turkish plate.
///
/// Rules (aligned with the registration alphabet and regulation):
/// - province code 01-81 (`99 ABC 123` is invalid - there is no province 99),
/// - letter group is **1-3 letters, excluding Q/W/X** (`[A-PR-VY-Z]` - not in
///   the Turkish plate alphabet; C/G/I/O/S/U with diacritics are not used in
///   registration either),
/// - serial is **2-4 digits** (`34 ABC 12345` is invalid - no 5th digit),
/// - the separator is a space or a hyphen (`34 ABC 123`, `34-ABC-123`).
///
/// # Examples
/// ```
/// use redactify::valid_plaka;
/// assert!(valid_plaka("34 ABC 123"));
/// assert!(valid_plaka("34-ABC-123"));  // hyphenated form
/// assert!(valid_plaka("06 ank 06"));   // lowercase is uppercased
/// assert!(!valid_plaka("99 ABC 123")); // no province 99
/// assert!(!valid_plaka("34 QWX 123")); // Q/W/X not in the plate alphabet
/// assert!(!valid_plaka("34 ABC 12345")); // serial is at most 4 digits
/// ```
#[must_use]
pub fn valid_plaka(plate: &str) -> bool {
    // Normalize the hyphenated form to the spaced one (34-ABC-123 -> 34 ABC 123).
    let up: String = plate
        .trim()
        .replace('-', " ")
        .chars()
        .flat_map(char::to_uppercase)
        .collect();
    match PLAKA_FULL.captures(&up) {
        Ok(Some(c)) => {
            let prov = c.get(1).map_or("", |m| m.as_str());
            matches!(prov.parse::<u8>(), Ok(p) if (1..=81).contains(&p))
        }
        _ => false,
    }
}

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that boost plate confidence from 0.85 to 0.95.
pub(super) const CUES: &[&str] = &[
    "plaka",
    "arac plakasi",
    "plaka numarasi",
    "kayit plakasi",
    "tr plaka",
    "license plate",
    "number plate",
    "plate",
    "tasit plakasi",
    "kayit",
];

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Plaka,
        r"(?<!\w)\d{2}(?:\s|-)?[A-PR-VY-Z]{1,3}(?:\s|-)?\d{2,4}(?!\w)",
        Some(valid_plaka),
        ContextPolicy::Boost(CUES, 0.95),
        0.85
    )
}

#[cfg(test)]
mod tests {
    use super::valid_plaka;

    #[test]
    fn golden_vectors() {
        assert!(valid_plaka("34 ABC 123"));
        assert!(valid_plaka("34-ABC-123")); // hyphenated form
        assert!(valid_plaka("06 ANK 06"));
        assert!(valid_plaka("06 AAA 9999")); // 4 digits: upper bound
        assert!(valid_plaka(" 06 ank 06 ")); // trim + uppercase
        assert!(!valid_plaka("99 ABC 123")); // no province 99
        assert!(!valid_plaka("00 ABC 123")); // no province 00
        assert!(!valid_plaka("34 ABC 1")); // serial needs at least 2 digits
        assert!(!valid_plaka("34 ABC 12345")); // serial is at most 4 digits
        assert!(!valid_plaka("34 QWX 123")); // Q/W/X not in the registration alphabet
        assert!(!valid_plaka("34 ÇĞŞ 123")); // diacritic letters not in the registration alphabet
        assert!(!valid_plaka(""));
        assert!(!valid_plaka("34 ABC 123 X"));
    }
}
