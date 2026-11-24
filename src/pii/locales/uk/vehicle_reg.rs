//! UK (GB) vehicle registration number: validator + detection rules.
//!
//! Official sources:
//!
//! 1. DVLA leaflet INF104 "Vehicle registration numbers and number plates"
//!    (4/22), sections 03 "Vehicle registration number format" and 05
//!    "DVLA memory tags and age identifiers"
//!    (<https://assets.publishing.service.gov.uk/media/6694e379fc8e12ac3edafc60/inf104-vehicle-registration-numbers-and-number-plates.pdf>,
//!    retrieved 2026-10-31): "The current vehicle registration format was
//!    introduced on 1 September 2001. It consists of: 2 letter memory tag
//!    (these refer to the region in the country where a vehicle is first
//!    registered) 2 numbers (these tell you when it was issued) a space and
//!    3 letters chosen at random". The memory-tag table lists the region
//!    letters A, B, C, D, E, F, G, H, K, L, M, N, O, P, R, S, V, W, Y, and
//!    states "We will not use I, Q or Z in local memory tags identifiers
//!    [...] We will only use Z as a random letter". The age-identifier
//!    table runs from "Sept 2001 - Feb 2002 51" and "March 2002 - Aug
//!    2002 02" to "March 2029 - Aug 2029 29" and "Sept 2029 - Feb 2030
//!    79".
//! 2. DVLA Personalised Registrations, "Registration Styles"
//!    (<https://dvlaregistrations.dvla.gov.uk/help/search.html>, retrieved
//!    2026-10-30): "'Prefix' style are the registrations that were used
//!    prior to 2001 and consist of; 1 letter, 1-3 numbers and then 3
//!    letters. A123 ABC 'Suffix' style are the registrations that were used
//!    prior to 1983 and consist of; 3 letters, 1-3 numbers and then 1
//!    letter. ABC 123A".
//!
//! Three rules share the validator:
//! - `uk::vehicle_reg` (current style, `AA68 ABC`): first memory-tag letter
//!   from the INF104 region list, second letter not `I`, `Q` or `Z`, age
//!   identifier `02`-`29` or `51`-`79` (the published table; codes past it
//!   are not accepted), three random letters `A`-`Z`;
//! - `uk::vehicle_reg_prefix` (`A123 ABC`) and `uk::vehicle_reg_suffix`
//!   (`ABC 123A`): letters and 1-3 digits as the DVLA styles state.
//!
//! The space before the random letters (or around the digits) is optional.
//! The "dateless" style (3 letters + 3 digits) is out of scope,
//! and so are the pre-2001 historic tags. The INF104 table
//! omits a few region pairs (`FO`, `FU`, `NF`; `MN` is reserved for the
//! Isle of Man); the rule follows the letter rules quoted above rather
//! than the pair list (recall-first).
//!
//! Format only: no check character exists, so a cue is REQUIRED and the
//! score is 0.9. Bare "reg", "mot", "car" and "vehicle" are not cues
//! (substrings of "regular", "motion", "card"; "vehicle" alone is prose).

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, two_digits, ContextPolicy, Rule};

/// Cue words that make a registration candidate claimable. A leading cue
/// counts when its END lies within the 18-character cue window before the
/// value (`pii::context`), so "registration" unlocks every label that ends
/// in it or shortly after it ("Vehicle registration number: AB12 CDE").
/// The full DVLA labels "registration number" and "registration mark"
/// follow it: they reach a value up to 18 characters past their own end,
/// beyond the reach of their "registration" part; "vehicle registration
/// number" (the INF104 term) names the full label. The reported cue is the
/// first listed one that is found.
pub(super) const CUES: &[&str] = &[
    "registration",
    "registration number",
    "registration mark",
    "vehicle registration number",
    "reg number",
    "reg no",
    "number plate",
    "licence plate",
    "license plate",
    "vrn",
];

/// INF104 region letters (first memory-tag letter).
const REGION_LETTERS: &[u8; 19] = b"ABCDEFGHKLMNOPRSVWY";

/// Current style (`AA68 ABC`): region letter, tag letter, INF104 age
/// identifier, optional space, three random letters.
fn current_style(b: &[u8]) -> bool {
    let rest = match b.len() {
        7 => &b[4..],
        8 if b[4] == b' ' => &b[5..],
        _ => return false,
    };
    if !(REGION_LETTERS.contains(&b[0])
        && b[1].is_ascii_uppercase()
        && !matches!(b[1], b'I' | b'Q' | b'Z')
        && b[2].is_ascii_digit()
        && b[3].is_ascii_digit())
    {
        return false;
    }
    let age = two_digits(&b[2..4]);
    matches!(age, 2..=29 | 51..=79) && rest.iter().all(u8::is_ascii_uppercase)
}

/// Run lengths of a token read as letters, an optional space, digits, an
/// optional space and letters.
struct Runs {
    lead: usize,
    lead_space: bool,
    digits: usize,
    tail: usize,
}

/// The [`Runs`] of `b`, or `None` when `b` has any other shape.
fn letter_digit_letter(b: &[u8]) -> Option<Runs> {
    let take =
        |from: usize, pred: fn(&u8) -> bool| b[from..].iter().take_while(|x| pred(x)).count();
    let mut i = 0;
    let lead = take(i, u8::is_ascii_uppercase);
    i += lead;
    let lead_space = b.get(i) == Some(&b' ');
    i += usize::from(lead_space);
    let digits = take(i, u8::is_ascii_digit);
    i += digits;
    if b.get(i) == Some(&b' ') {
        i += 1;
    }
    let tail = take(i, u8::is_ascii_uppercase);
    i += tail;
    (i == b.len()).then_some(Runs {
        lead,
        lead_space,
        digits,
        tail,
    })
}

/// Returns `true` if `s` is a GB vehicle registration number in one of
/// the DVLA styles: current (`AA68 ABC`, INF104 memory tag and age
/// identifier, optional space before the random letters), prefix
/// (`A123 ABC`, optional space before the letters) or suffix (`ABC 123A`,
/// optional spaces around the digits). Uppercase only.
///
/// # Examples
/// ```
/// use redactify::valid_uk_vehicle_reg;
/// assert!(valid_uk_vehicle_reg("AA68 ABC")); // DVLA current-style example
/// assert!(valid_uk_vehicle_reg("A123 ABC")); // prefix style
/// assert!(valid_uk_vehicle_reg("ABC 123A")); // suffix style
/// assert!(!valid_uk_vehicle_reg("AA01 ABC")); // 01 is not an age identifier
/// assert!(!valid_uk_vehicle_reg("AEZ 121")); // dateless style: out of scope
/// ```
#[must_use]
pub fn valid_uk_vehicle_reg(s: &str) -> bool {
    let b = s.as_bytes();
    if current_style(b) {
        return true;
    }
    let Some(r) = letter_digit_letter(b) else {
        return false;
    };
    // the current style (2 letters + 2 digits + 3 letters) is decided by
    // `current_style` alone; the older styles have one letter on one side
    let prefix = r.lead == 1 && !r.lead_space && (1..=3).contains(&r.digits) && r.tail == 3;
    let suffix = r.lead == 3 && (1..=3).contains(&r.digits) && r.tail == 1;
    prefix || suffix
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        id = "uk::vehicle_reg",
        EntityType::UkVehicleRegistration,
        r"(?<![A-Za-z0-9])[A-HK-PRSVWY][A-HJ-PR-Y](?:0[2-9]|[12][0-9]|5[1-9]|[67][0-9]) ?[A-Z]{3}(?![A-Za-z0-9])",
        Some(valid_uk_vehicle_reg),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn prefix_rule() -> Rule {
    rule!(
        id = "uk::vehicle_reg_prefix",
        EntityType::UkVehicleRegistration,
        r"(?<![A-Za-z0-9])[A-Z][0-9]{1,3} ?[A-Z]{3}(?![A-Za-z0-9])",
        Some(valid_uk_vehicle_reg),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn suffix_rule() -> Rule {
    rule!(
        id = "uk::vehicle_reg_suffix",
        EntityType::UkVehicleRegistration,
        r"(?<![A-Za-z0-9])[A-Z]{3} ?[0-9]{1,3} ?[A-Z](?![A-Za-z0-9])",
        Some(valid_uk_vehicle_reg),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_uk_vehicle_reg as ok;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn current_style_vectors() {
        assert!(ok("AA68 ABC"));
        assert!(ok("AA68ABC"));
        assert!(ok("BD51 SMR")); // INF104 plate illustration
        assert!(ok("YY79 ZZZ")); // Z only as a random letter
        assert!(ok("WA02 ABC"));
        assert!(!ok("AA01 ABC")); // 01 not in the age table
        assert!(!ok("AA50 ABC")); // 50 not in the age table
        assert!(!ok("AA80 ABC")); // 80 past the published table
        assert!(!ok("IA51 ABC")); // I is not a region letter
        assert!(!ok("QA51 ABC")); // Q is not a region letter
        assert!(!ok("TA51 ABC")); // T is not in the region table
        assert!(!ok("AZ51 ABC")); // Z is never a tag letter
        assert!(!ok("AI51 ABC")); // I is never a tag letter
        assert!(!ok("AA68 AB")); // two random letters
        assert!(!ok("aa68 abc")); // lowercase
        assert!(!ok("AA68  ABC")); // two spaces
    }

    #[test]
    fn older_style_vectors() {
        assert!(ok("A123 ABC")); // DVLA prefix example
        assert!(ok("A1 ABC"));
        assert!(ok("A123ABC"));
        assert!(ok("ABC 123A")); // DVLA suffix example
        assert!(ok("ABC 1 A"));
        assert!(ok("ABC123A"));
        assert!(!ok("A1234 ABC")); // four digits
        assert!(!ok("A 123 ABC")); // the prefix letter is not spaced off
        assert!(!ok("AB123 ABC")); // two leading letters
        assert!(!ok("AEZ 121")); // dateless
        assert!(!ok("ABC 123AB"));
        assert!(!ok(""));
    }

    #[test]
    fn cue_required() {
        let kinds = |t: &str| -> Vec<EntityType> {
            engine_detect(t, &["uk"])
                .into_iter()
                .map(|e| e.kind)
                .collect()
        };
        for text in [
            "vehicle registration AA68 ABC",
            "Registration No. AA68 ABC",
            "reg no: A123 ABC",
            "number plate ABC 123A",
            "VRN AA68ABC",
        ] {
            assert_eq!(
                kinds(text),
                vec![EntityType::UkVehicleRegistration],
                "{text}"
            );
        }
        assert!(kinds("model AA68 ABC launched").is_empty());
        assert!(kinds("regular A123 ABC").is_empty());
        assert!(kinds("registration AA01 ABC").is_empty());
    }
}
