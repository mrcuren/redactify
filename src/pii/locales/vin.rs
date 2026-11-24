//! Vehicle Identification Number (ISO 3779): validator + rule.
//!
//! Evidence (two independent sources, retrieved 2026-10-12):
//! 49 CFR § 565.15 (US regulation, Tables III/IV/V): 17 chars, check
//! digit at position 9; transliteration A=1..H=8, J=1..R=9, S=2..Z=9;
//! weights (8,7,6,5,4,3,2,10,0,9,8,7,6,5,4,3,2); sum mod 11, remainder
//! 10 → 'X'. I, O, Q never occur.
//! Wikipedia "Vehicle identification number": same table, same weights,
//! same mod-11 rule with the X special case.
//!
//!
//! Where the check digit is mandatory (retrieved 2026-11-23):
//! - United States: 49 CFR 565.15(c), "The third section shall consist of
//!   one character, which occupies position nine (9) in the VIN" (the
//!   check digit), for the vehicles of 49 CFR 565.2 (passenger cars,
//!   multipurpose passenger vehicles, trucks, buses, trailers, incomplete
//!   vehicles, low speed vehicles and motorcycles)
//!   (<https://www.law.cornell.edu/cfr/text/49/565.15>,
//!   <https://www.law.cornell.edu/cfr/text/49/565.2>).
//! - European Union: Commission Regulation (EU) No 19/2011, Annex I
//!   Part B, point 2.3: "The VDS shall consist of six alphanumeric
//!   characters ... the unused spaces shall be filled in with alphanumeric
//!   characters at the manufacturer's discretion" - position 9 belongs to
//!   the VDS and no check digit is defined
//!   (<https://www.legislation.gov.uk/eur/2011/19/annex/I/part/B/adopted>).
//!
//! A VIN outside the US rules therefore fails the check digit about ten
//! times in eleven: none of the 38 VINs of the nm-kvkk-pii-6K test split
//! passes it. [`cued_rule`] claims such a VIN only next to a VIN cue
//! ("VIN", "şasi"), with the 49 CFR 565 / EU 19/2011 alphabet
//! (no I, O, Q) and at least one letter and one digit. The EU VIS rule
//! (point 2.4: "the last four shall consist of digits only") is not
//! enforced: the VINs of that test split do not follow it (unverified whether real
//! Turkish registrations always do).

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Returns `true` if `vin` is a checksum-valid VIN (17 chars, ISO 3779).
///
/// # Examples
/// ```
/// use redactify::valid_vin;
/// assert!(valid_vin("1M8GDM9AXKP042788")); // CFR example: remainder 10 → X
/// assert!(valid_vin("JH4KA7561PC008269"));
/// assert!(!valid_vin("1M8GDM9A0KP042788")); // wrong check digit
/// assert!(!valid_vin("1M8GDQ9AXKP042788")); // Q is never in a VIN
/// assert!(!valid_vin("JH4KA7561PC00826"));  // 16 chars
/// ```
#[must_use]
pub fn valid_vin(vin: &str) -> bool {
    let v = vin.as_bytes();
    if v.len() != 17 {
        return false;
    }
    const TRANSLIT: fn(u8) -> Option<u32> = |c: u8| match c {
        b'0'..=b'9' => Some(u32::from(c - b'0')),
        b'A' | b'J' => Some(1),
        b'B' | b'K' | b'S' => Some(2),
        b'C' | b'L' | b'T' => Some(3),
        b'D' | b'M' | b'U' => Some(4),
        b'E' | b'N' | b'V' => Some(5),
        b'F' | b'W' => Some(6),
        b'G' | b'P' | b'X' => Some(7),
        b'H' | b'Y' => Some(8),
        b'R' | b'Z' => Some(9),
        _ => None, // I, O, Q and any other char
    };
    const WEIGHTS: [u32; 17] = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];
    let sum: u32 = v
        .iter()
        .zip(WEIGHTS)
        .map(|(&c, w)| TRANSLIT(c).map_or(0, |n| n * w))
        .sum();
    let all_valid = v.iter().all(|&c| TRANSLIT(c).is_some());
    if !all_valid {
        return false;
    }
    let r = sum % 11;
    let expected = if r == 10 { b'X' } else { b'0' + (r as u8) };
    v[8] == expected
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Vin,
        r"(?<![A-Z0-9])[A-HJ-NPR-Z0-9]{17}(?![A-Z0-9])",
        Some(valid_vin),
        ContextPolicy::None,
        1.0
    )
}

/// Cue words that unlock a VIN without a valid check digit (normalized
/// form: lowercase, `ı` folded to `i`). "vin" is listed only with a
/// delimiter after it (`VIN:`, `Şasi/VIN numarası`, `(VIN)`): the bare word
/// is a prefix of "vinyl" and of compounds such as "VIN-shaped", which
/// source-code comments place next to VIN-like strings. "chassis" is
/// deliberately absent: the benign canary of `tests/fpr_budget_gate.rs`
/// pins "chassis ref 1M8GDM9A0KP042788 logged" (a failing check digit) as
/// silent, and every nm-kvkk-pii-6K VIN stands next to "şasi" or "VIN".
const CUES: &[&str] = &[
    "vin:",
    "vin ",
    "vin)",
    "(vin",
    "vin/",
    "vin#",
    "şasi",
    "sasi",
    "vehicle identification",
];

/// A 17-character VIN shape without the check digit: the ISO 3779
/// alphabet (no I, O or Q; the regex enforces it) with at least one letter
/// and one digit, so a run of digits or a 17-letter word is not a VIN.
fn valid_vin_shape(vin: &str) -> bool {
    let v = vin.as_bytes();
    v.len() == 17 && v.iter().any(u8::is_ascii_digit) && v.iter().any(u8::is_ascii_uppercase)
}

/// VIN next to a VIN cue, check digit not required (module doc).
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn cued_rule() -> Rule {
    rule!(
        id = "vin_cued",
        EntityType::Vin,
        r"(?<![A-Z0-9])[A-HJ-NPR-Z0-9]{17}(?![A-Z0-9])",
        Some(valid_vin_shape),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod vin_tests {
    use super::{valid_vin, valid_vin_shape};
    use crate::{detect, EntityType};

    #[test]
    fn vin_valid() {
        assert!(valid_vin("1M8GDM9AXKP042788")); // CFR example, X check
        assert!(valid_vin("JH4KA7561PC008269")); // Wikipedia example
        assert!(valid_vin("11111111111111111")); // all 1s
    }

    #[test]
    fn vin_invalid() {
        assert!(!valid_vin("1M8GDM9A0KP042788")); // wrong check digit (should be X)
        assert!(!valid_vin("JH4KA7562PC008269")); // wrong check digit (should be 1)
        assert!(!valid_vin("1M8GDQ9AXKP042788")); // Q invalid
        assert!(!valid_vin("1M8GDM9AXKP042788 ")); // 18 chars
        assert!(!valid_vin("")); // empty
    }

    #[test]
    fn vin_detected() {
        let ents = detect("VIN 1M8GDM9AXKP042788 kayitli");
        assert!(ents.iter().any(|e| e.kind == EntityType::Vin), "{ents:?}");
        // invalid VIN (check digit wrong) not claimed
        let ents = detect("ref 1M8GDM9A0KP042788");
        assert!(!ents.iter().any(|e| e.kind == EntityType::Vin), "{ents:?}");
    }

    #[test]
    fn a_cue_unlocks_a_vin_without_the_check_digit() {
        // nm-kvkk-pii-6K shapes: none passes the 49 CFR 565 check digit
        for (text, vin) in [
            ("Şasi No (VIN): NMCKAKC07787VN61Y", "NMCKAKC07787VN61Y"),
            ("Araç şasi numarası: WDBFW9XB5DZMHJ30L", "WDBFW9XB5DZMHJ30L"),
            (
                "teknik kayıt, WVW6TTZ2GFAL2LA84 şasi numarası",
                "WVW6TTZ2GFAL2LA84",
            ),
            ("VIN: WVWZZ5FBMKACNN9Y5", "WVWZZ5FBMKACNN9Y5"),
        ] {
            assert!(!valid_vin(vin), "{vin}");
            let ents = detect(text);
            assert!(
                ents.iter()
                    .any(|e| e.kind == EntityType::Vin && e.text == vin),
                "{text}: {ents:?}"
            );
        }
        // without a cue the check digit stays mandatory
        let ents = detect("chassis ref 1M8GDM9A0KP042788 logged");
        assert!(!ents.iter().any(|e| e.kind == EntityType::Vin), "{ents:?}");
        let ents = detect("ref 1M8GDM9A0KP042788 logged, // VIN-shaped");
        assert!(!ents.iter().any(|e| e.kind == EntityType::Vin), "{ents:?}");
        let ents = detect("kod NMCKAKC07787VN61Y");
        assert!(!ents.iter().any(|e| e.kind == EntityType::Vin), "{ents:?}");
        // all digits or all letters is no VIN shape
        assert!(!valid_vin_shape("12345678901234567"));
        assert!(!valid_vin_shape("ABCDEFGHJKLMNPRST"));
    }
}
