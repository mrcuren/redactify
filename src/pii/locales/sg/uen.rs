//! Singapore Unique Entity Number (UEN): format validator + rule. FORMAT
//! ONLY - the check letter's algorithm is not officially published.
//!
//! Official source (retrieved 2026-10-31): Land Transport Authority,
//! Circular VRL/17/2019 of 3 October 2019, "OCOE Open Bidding System - Use
//! Only the Unique Entity Number (UEN)",
//! <https://onemotoring.lta.gov.sg/content/dam/onemotoring/pdf/Circulars%20to%20ESAs/2019/VRL_17_2019.pdf>,
//! UEN format table (reproducing the registry's table): "A Businesses
//! registered with ACRA nnnnnnnnX (9 characters) | B Local companies
//! registered with ACRA yyyynnnnnX (10 characters) | C All other entities
//! which will be issued new UEN TyyPQnnnnX (10 characters) | 'n' = a
//! number 'P' = an alphabetical letter 'Q' = an alpha-numeric digit 'PQ'
//! = Entity-type 'Tyy' / 'Syy' / 'yyyy' = year of issuance 'X' = a check
//! alphabetical letter ... 'T' represents '20', 'S' represents '19' and
//! 'R' represents '18'".
//!
//! Not applied (no retrievable official source): the check-letter
//! algorithm, the entity-type code list (registry page unreachable) and
//! any bound on the year of issuance (a "not after this year" bound would
//! also need a clock, which the wasm32 core does not use).
//!
//! Cue policy: no verifiable check character, so a cue is REQUIRED (score
//! 0.9, format + mandatory cue). A bare `uen` would match inside common
//! words ("frequency", "fluent", German "neuen"), so only label forms are
//! cues; a "UEN 201912345A" label without a colon or "no" is therefore not
//! claimed (the Indian PAN precedent).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (lowercase): label forms of "UEN", the full name and the
/// registry's acronym followed by a delimiter.
pub(super) const CUES: &[&str] = &[
    "uen:",
    "uen no",
    "uen number",
    "unique entity",
    "acra ",
    "acra:",
];

/// Returns `true` if `uen` has one of the three UEN formats: `A` = eight
/// digits + a check letter; `B` = a four-digit year + five digits + a
/// check letter; `C` = `T`/`S`/`R` + a two-digit year + an entity-type
/// letter + an alphanumeric character + four digits + a check letter.
/// Letters are uppercase; the check letter is not verified.
///
/// # Examples
/// ```
/// use redactify::valid_sg_uen;
/// assert!(valid_sg_uen("T09LL0001B")); // the source's illustrative format C value
/// assert!(valid_sg_uen("53012345D"));  // format A shape
/// assert!(valid_sg_uen("201912345A")); // format B shape
/// assert!(!valid_sg_uen("T09LL001B")); // three digits
/// assert!(!valid_sg_uen("Q09LL0001B")); // prefix not T/S/R
/// ```
#[must_use]
pub fn valid_sg_uen(uen: &str) -> bool {
    let b = uen.as_bytes();
    let digits = |s: &[u8]| s.iter().all(u8::is_ascii_digit);
    let upper = u8::is_ascii_uppercase;
    match b.len() {
        9 => digits(&b[..8]) && upper(&b[8]),
        10 if b[0].is_ascii_digit() => digits(&b[..9]) && upper(&b[9]),
        10 => {
            matches!(b[0], b'T' | b'S' | b'R')
                && digits(&b[1..3])
                && upper(&b[3])
                && (upper(&b[4]) || b[4].is_ascii_digit())
                && digits(&b[5..9])
                && upper(&b[9])
        }
        _ => false,
    }
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::SgUen,
        r"(?<![A-Za-z0-9])(?:\d{8}[A-Z]|\d{9}[A-Z]|[TSR]\d{2}[A-Z][A-Z0-9]\d{4}[A-Z])(?![A-Za-z0-9])",
        Some(valid_sg_uen),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::{valid_sg_uen, CUES};
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn structure() {
        for v in ["T09LL0001B", "S99PF1234K", "R85LP0001Z", "T09L50001B"] {
            assert!(valid_sg_uen(v), "{v}");
        }
        for v in [
            "T09LL001B",   // three digits
            "Q09LL0001B",  // prefix
            "T0LLL0001B",  // year not two digits
            "T095L0001B",  // entity-type letter missing
            "T09LL0001b",  // lowercase check letter
            "5301234D",    // seven digits
            "53012345",    // no check letter
            "2019123456A", // eleven characters
        ] {
            assert!(!valid_sg_uen(v), "{v}");
        }
    }

    #[test]
    fn rule_requires_a_label_cue() {
        let ents = engine_detect("UEN: T09LL0001B registered", &["sg"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::SgUen);
        for cue in CUES {
            let text = format!("{cue} 201912345A");
            assert_eq!(engine_detect(&text, &["sg"]).len(), 1, "{text}");
        }
        assert!(engine_detect("ref T09LL0001B closed", &["sg"]).is_empty());
        // substring traps of a bare "uen" do not unlock the shape
        assert!(engine_detect("frequency 53012345D logged", &["sg"]).is_empty());
        assert!(engine_detect("die neuen 53012345D Akten", &["sg"]).is_empty());
    }
}
