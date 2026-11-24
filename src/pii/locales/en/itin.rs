//! US Individual Taxpayer Identification Number (ITIN): detection rule.
//!
//! Official sources (IRS, retrieved 2026-10-30):
//!
//! 1. Internal Revenue Manual 3.21.263 "IRS Individual Taxpayer
//!    Identification Number (ITIN) Real-Time System (RTS)", section
//!    3.21.263.2 (08-28-2025) "Overview"
//!    (<https://www.irs.gov/irm/part3/irm_03-021-263r>): "The ITIN will be
//!    in the format of an SSN and begin with the number "9". The fourth
//!    and fifth numbers will range from: 50-65 70-88 90-92 94-99 Note: "89"
//!    and "93" are NOT used as fourth and fifth numbers for ITINs but are
//!    reserved for other programs."
//! 2. IRS page "Taxpayer identification numbers (TIN)", section ITIN
//!    (<https://www.irs.gov/tin/taxpayer-identification-numbers-tin>): "It
//!    is a 9-digit number, beginning with the number "9", formatted like an
//!    SSN (NNN-NN-NNNN)."
//!
//! The patterns follow exactly that: `9`, two digits, a middle group in
//! the IRM ranges, four digits; separated (`-`, `.` or space) or bare. No
//! checksum exists. The separated form is claimed cue-less at 0.75 and
//! boosted to 0.95 by a cue; the bare nine digits need a cue (0.9).
//!
//! Cues: the labels "ITIN" and "TIN" are delimited (`itin:`, `tin:`,
//! `(tin)`, ` tin ` ...): bare "itin" is a substring of "writing" and
//! "visiting", bare "tin" of "meeting", "routing", "marketing" and "voting"
//! (a nine-digit meeting id in the ITIN number space next to "Meeting ID"
//! was claimed). "tin " (trailing space only) is not a form because many
//! words end in "tin" ("Martin", "Austin", "Latin", "bulletin"); words
//! ending in "tin" before a colon or " no" ("Martin:", "Bulletin No.")
//! remain a known residual. "tax" stays bare: delimiting it would drop the
//! labels "taxes", "taxpayer" and "taxation" (residual: "syntax", "taxi").

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words: they raise the separated form from 0.75 to 0.95 and are
/// required by the bare form (delimited label forms, module doc).
pub(super) const CUES: &[&str] = &[
    "individual",
    "taxpayer",
    "itin:",
    "itin#",
    "itin ",
    "itin/",
    "(itin)",
    "tax",
    "payer",
    "taxid",
    "tin:",
    "tin#",
    "(tin)",
    " tin ",
    "tin no",
    "tin number",
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

/// Separator-less ITIN variant: a bare 9-digit number is never claimed on
/// its own, so this variant requires a cue outright.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn bare_rule() -> Rule {
    rule!(
        id = "en::itin_bare",
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
