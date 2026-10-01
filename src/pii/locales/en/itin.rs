//! US Individual Taxpayer Identification Number (ITIN): detection rule.
//!
//! Source of the pattern: the open-source industry PII analyzer (US ITIN
//! recognizer, medium-strength pattern). An ITIN starts with `9`, the middle
//! group is restricted to the `50-65`, `70-88`, `90-92`, `94-99` ranges, and the
//! format is `9xx[- ]YY[- ]xxxx`. The structure itself is restrictive enough;
/// no checksum exists, so a nearby tax cue raises confidence.
use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that raise ITIN confidence from 0.75 to 0.95 (industry context list).
pub(super) const CUES: &[&str] = &[
    "individual",
    "taxpayer",
    "itin",
    "tax",
    "payer",
    "taxid",
    "tin",
];

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Itin,
        r"(?<!\d)9\d{2}[-. ](5\d|6[0-5]|7\d|8[0-8]|9([0-2]|[4-9]))[-. ]\d{4}(?!\d)",
        None,
        ContextPolicy::Boost(CUES, 0.95),
        0.75
    )
}

/// Separator-less ITIN variant. The source analyzer scores this form "weak"
/// (0.3 without a cue); in our single-decision model a bare 9-digit number is
/// never claimed, so this variant requires a tax cue outright.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn bare_rule() -> Rule {
    rule!(
        EntityType::Itin,
        r"(?<!\d)9\d{2}(5\d|6[0-5]|7\d|8[0-8]|9([0-2]|[4-9]))\d{4}(?!\d)",
        None,
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use crate::{detect, EntityType};

    #[test]
    fn itin_detected_with_and_without_cue() {
        let with = detect("ITIN: 912-70-1234");
        assert!(with
            .iter()
            .any(|e| e.kind == EntityType::Itin && e.score == 0.95));

        let bare = detect("ref 912-70-1234 x");
        assert!(bare
            .iter()
            .any(|e| e.kind == EntityType::Itin && e.score == 0.75));
    }

    #[test]
    fn middle_group_range_is_enforced() {
        // middle 69 is outside 50-65/70-88/90-92/94-99 -> not an ITIN
        assert!(!detect("ITIN: 912-69-1234")
            .iter()
            .any(|e| e.kind == EntityType::Itin));
    }
}
