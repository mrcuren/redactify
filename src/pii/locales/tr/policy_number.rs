//! Insurance policy number (poliçe numarası): digit groups + mandatory cue.
//!
//! Format only (cue required): each insurer numbers its policies its own
//! way and no public standard or checksum exists. Accepted shapes: 6-20
//! digits in one run or in up to three hyphen-separated groups, with an
//! optional 2-5 letter prefix (`8482398145`, `7745-495174`,
//! `POL-2020-968665`). The run is claimed only next to a policy-number cue
//! (`Poliçe No:`, `poliçe numarası`, `... numaralı poliçe`); a bare
//! `poliçe` is not a cue, so `Poliçe primi: 125000` stays clean.

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Policy-number cues (normalized: lowercase, `ı -> i`).
pub(super) const CUES: &[&str] = &[
    "poliçe no",
    "police no",
    "poliçe numara",
    "police numara",
    "poliçenin numara",
    "policenin numara",
    "numarali poliçe",
    "numarali police",
    "poliçe kod",
    "poliçe bilgi",
    "poliçesi numara",
    "policesi numara",
    // `Sigorta poliçesi: ...`, `... numaralı sigorta poliçesi`
    "sigorta poliçe",
    "sigorta police",
    "numarali sigorta",
    "policy no",
    "policy number",
];

/// An optional 2-5 letter prefix, then 1-3 hyphen-separated digit groups
/// (the first of at least 2 digits) with 6-20 digits in total.
fn valid_policy_number(s: &str) -> bool {
    let digits_part = match s.split_once('-') {
        Some((prefix, rest)) if prefix.bytes().all(|b| b.is_ascii_uppercase()) => {
            if !(2..=5).contains(&prefix.len()) {
                return false;
            }
            rest
        }
        _ => s,
    };
    let groups: Vec<&str> = digits_part.split('-').collect();
    let digits: usize = groups.iter().map(|g| g.len()).sum();
    groups.len() <= 3
        && groups[0].len() >= 2
        && groups
            .iter()
            .all(|g| !g.is_empty() && g.bytes().all(|b| b.is_ascii_digit()))
        && (6..=20).contains(&digits)
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    // whole letter/digit runs (leftmost-first + greedy), shape checked by
    // the validator: no boundary assertion (cost note in `super::address`)
    rule!(
        EntityType::PolicyNumber,
        r"(?:[A-Z]+-)?[0-9]+(?:-[0-9]+)*",
        Some(valid_policy_number),
        ContextPolicy::RequiredCue(CUES),
        0.85
    )
}

#[cfg(test)]
mod tests {
    use crate::pii::entity::EntityType;

    fn policies(text: &str) -> Vec<String> {
        crate::pii::detect::engine_detect(text, &["tr"])
            .into_iter()
            .filter(|e| e.kind == EntityType::PolicyNumber)
            .map(|e| e.text)
            .collect()
    }

    #[test]
    fn policy_number_needs_its_cue() {
        assert_eq!(policies("Poliçe No: 8115633890\n"), vec!["8115633890"]);
        assert_eq!(
            policies("Poliçe numarası: POL-2020-968665"),
            vec!["POL-2020-968665"]
        );
        assert_eq!(
            policies("Bu teminatlar 2359-765774 numaralı poliçe üzerinde"),
            vec!["2359-765774"]
        );
        assert_eq!(
            policies("düzenlenen poliçenin numarası 7745-495174 olup"),
            vec!["7745-495174"]
        );
        for text in [
            "Poliçe primi: 125000",
            "Poliçe No: 12345",
            "Sipariş No: POL-2020-968665",
            "Poliçe başlangıç tarihi: 01.01.2024",
        ] {
            assert!(policies(text).is_empty(), "{text}: {:?}", policies(text));
        }
    }
}
