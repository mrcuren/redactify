//! US Social Security Number (SSN): validator + detection rules.
//!
//! Official sources (SSA; the live pages answer 403, read through the
//! Internet Archive copies; retrieved 2026-10-30):
//!
//! 1. "Social Security Number Randomization"
//!    (<http://web.archive.org/web/20261021192236/https://www.ssa.gov/employer/randomization.html>):
//!    "The Social Security Administration (SSA) changed the way Social
//!    Security Numbers (SSNs) are issued on June 25, 2011. [...] Previously
//!    unassigned area numbers were introduced for assignment excluding area
//!    numbers 000, 666 and 900-999."
//! 2. "Social Security Number Randomization Frequently Asked Questions"
//!    (<http://web.archive.org/web/20261021192235/https://www.ssa.gov/employer/randomizationfaqs.html>):
//!    "SSN randomization will not assign group number 00 or serial number
//!    0000. SSNs containing group number 00 or serial number 0000 will
//!    continue to be invalid."
//! 3. "Social Security Cards Issued by Woolworth" (SSA History)
//!    (<http://web.archive.org/web/20261015220617/https://www.ssa.gov/history/ssn/misused.html>):
//!    "The most misused SSN of all time was (078-05-1120). [...] SSA acted
//!    to eliminate the problem by voiding the number".
//! 4. SSA Office of the Inspector General, evaluation report A-15-06-16037
//!    (18 May 2007), "Federal Employees' Compensation Act: A Nationwide
//!    Review of Federal Employees Who Received Compensation for Lost Wages
//!    for Periods When "Earned Wages" Were Reported on the Social Security
//!    Administration's Master Earnings File", section "Invalid and
//!    Incorrect SSNs"
//!    (<https://oig-files.ssa.gov/audits/full/html/A-15-06-16037.html>;
//!    the host did not resolve from here, read through the Internet
//!    Archive copy
//!    <http://web.archive.org/web/20260430232333/https://oig-files.ssa.gov/audits/full/html/A-15-06-16037.html>,
//!    retrieved 2026-10-31): "Invalid SSNs are SSNs that were never issued
//!    by SSA. [...] An example of an invalid SSN entered to facilitate a
//!    claim would be 123-45-6789."
//!
//! Nine identical digits are not rejected. No SSA text
//! states that such numbers are never issued (the POMS section RM
//! 10201.035 "Invalid Social Security Numbers (SSNs)", TN 2 (06-11),
//! <https://secure.ssa.gov/poms.nsf/lnx/0110201035>, retrieved 2026-10-31,
//! defines "An invalid (or impossible) SSN is one that we never assigned"
//! and lists only the area 000 / 666 / 900-999, group 00 and serial 0000
//! rules; a search of ssa.gov found no repeated-digit rule); masking a dummy
//! value is harmless while dropping a real one would leak it (the
//! repeated-digit TCKN precedent). `000-00-0000`, `666-66-6666` and
//! `999-99-9999` stay rejected by the area rule, as does `987654320`
//! (its area 987 is in the unissued 900-999 range).
//!
//! The separator check (both separators the same character) is a pattern
//! shape, not a validity claim: it keeps a run such as `536-90.6292`,
//! whose mixed separators are not the `NNN-NN-NNNN` shape, out of the
//! claim; the same digits written with matching separators or bare are
//! claimed as usual.
//!
//! Two rules share the validator:
//! - `en::ssn`: the `NNN-NN-NNNN` shape (separators `-`, `.` or space),
//!   claimed cue-less at 0.75 and boosted to 0.95 by a cue;
//! - `en::ssn_bare`: nine contiguous digits, claimed only with an SSN cue
//!   (0.9: format plus a mandatory cue). It is registered after the bare
//!   ITIN rule, so an ITIN-range run keeps its ITIN label (and the
//!   900-999 rejection keeps every other `9xx` run unclaimed). Its cue list
//!   is narrower than the boost list: a bare "social" or "security" would
//!   unlock any nine-digit run ("security code 123456789"), and a bare
//!   "ssn" is a substring of "classname" and "helplessness".

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Returns `true` if `s` is a structurally valid SSN (no check digit
/// exists).
///
/// Rules:
/// - area (first three digits) `000`, `666` and `900`-`999` are never
///   issued, group `00` and serial `0000` are invalid (SSA),
/// - `078-05-1120` was voided by the SSA, and `123-45-6789` is an SSN the
///   SSA never issued (SSA OIG report A-15-06-16037),
/// - both separators must be the same character (a pattern-shape check,
///   not a validity claim),
/// - every check compares the DIGITS, so the bare nine-digit form follows
///   the same rules.
///
/// # Examples
/// ```
/// use redactify::valid_ssn;
/// assert!(valid_ssn("536-90-6292"));
/// assert!(valid_ssn("536 90 6292"));  // space is a valid separator
/// assert!(valid_ssn("536906292"));    // bare form, same rules
/// assert!(!valid_ssn("536-90.6292")); // mismatched separators
/// assert!(!valid_ssn("666-45-6789")); // area 666 is never issued
/// assert!(!valid_ssn("912-12-3456")); // areas 900-999 are never issued
/// assert!(!valid_ssn("123-45-6789")); // never issued (SSA OIG)
/// assert!(valid_ssn("111-11-1111"));  // repeated digits: no SSA rule
/// ```
#[must_use]
pub fn valid_ssn(s: &str) -> bool {
    let mut seps: Vec<char> = s
        .chars()
        .filter(|c| *c == '.' || *c == '-' || *c == ' ')
        .collect();
    seps.dedup();
    if seps.len() > 1 {
        return false; // mismatched separators
    }
    let d: Vec<char> = s.chars().filter(char::is_ascii_digit).collect();
    if d.len() != 9 {
        return false;
    }
    let g2: String = d[3..5].iter().collect();
    let g3: String = d[5..].iter().collect();
    let area: String = d[..3].iter().collect();
    // SSA: areas 000, 666 and 900-999 are never assigned
    if g2 == "00" || g3 == "0000" || area == "000" || area == "666" || d[0] == '9' {
        return false;
    }
    // the voided number and the never-issued example are rejected on their
    // DIGITS (separators stripped)
    !matches!(
        d.iter().collect::<String>().as_str(),
        "123456789" | "078051120"
    )
}

/// Cue words that raise SSN confidence from 0.75 to 0.95 (the formatted
/// rule only).
pub(super) const CUES: &[&str] = &["social", "security", "ssn", "ssns", "ssid"];

/// Cue words required by the bare nine-digit rule (delimited "ssn" label
/// forms and the spelled-out name).
pub(super) const BARE_CUES: &[&str] = &[
    "ssn:",
    "ssn#",
    "ssn=",
    "ssn ",
    " ssn",
    "(ssn)",
    "social security",
    "security number",
];

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Ssn,
        r"(?<!\d)\d{3}[-. ]\d{2}[-. ]\d{4}(?!\d)",
        Some(valid_ssn),
        ContextPolicy::Boost(CUES, 0.95),
        0.75
    )
}

/// Bare nine-digit SSN: claimed only with an SSN cue nearby.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn bare_rule() -> Rule {
    rule!(
        id = "en::ssn_bare",
        EntityType::Ssn,
        r"(?<!\d)\d{9}(?!\d)",
        Some(valid_ssn),
        ContextPolicy::RequiredCue(BARE_CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_ssn;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn golden_vectors() {
        assert!(valid_ssn("536-90-6292"));
        assert!(valid_ssn("536.90.6292"));
        assert!(valid_ssn("536 90 6292"));
        assert!(valid_ssn("899-12-3456")); // highest issuable area
        assert!(!valid_ssn("536-90.6292")); // mismatched separators

        // repeated digits: no SSA rule rejects them
        assert!(valid_ssn("111-11-1111"));
        assert!(valid_ssn("555555555"));
        assert!(valid_ssn("888 88 8888"));
        // except where an SSA rule applies (area 000 / 666 / 9xx)
        assert!(!valid_ssn("000-00-0000"));
        assert!(!valid_ssn("666-66-6666"));
        assert!(!valid_ssn("999-99-9999"));
        assert!(!valid_ssn("123-00-6789")); // group 2 all zeros
        assert!(!valid_ssn("123-45-0000")); // group 3 all zeros
        assert!(!valid_ssn("000-45-6789")); // area 000 never issued
        assert!(!valid_ssn("666-45-6789")); // area 666 never issued
        assert!(!valid_ssn("900-12-3456")); // areas 900-999 never issued
        assert!(!valid_ssn("912-12-3456"));
        assert!(!valid_ssn("999-12-3456"));
        assert!(!valid_ssn("123456789")); // never issued (SSA OIG), bare
        assert!(!valid_ssn("123-45-6789")); // never issued, with separators
        assert!(!valid_ssn("987-65-4320")); // area 987 (900-999) never issued
        assert!(!valid_ssn("078-05-1120")); // voided by the SSA
        assert!(!valid_ssn(""));
    }

    #[test]
    fn bare_form_needs_an_ssn_cue() {
        let kinds = |t: &str| -> Vec<(EntityType, f32)> {
            engine_detect(t, &["en"])
                .into_iter()
                .map(|e| (e.kind, e.score))
                .collect()
        };
        assert_eq!(kinds("SSN: 536906292"), vec![(EntityType::Ssn, 0.9)]);
        assert_eq!(kinds("my SSN 536906292"), vec![(EntityType::Ssn, 0.9)]);
        assert_eq!(
            kinds("social security 536906292"),
            vec![(EntityType::Ssn, 0.9)]
        );
        assert!(kinds("order 536906292 shipped").is_empty());
        // the broad boost words do not unlock the bare form
        assert!(kinds("security code 536906292").is_empty());
        assert!(kinds("classname536906292").is_empty());
        // an ITIN-range run is never an SSN (area 9xx); with an ITIN cue
        // the bare ITIN rule claims it
        assert!(kinds("SSN: 912701234").is_empty());
        assert_eq!(kinds("ITIN/SSN: 912701234"), vec![(EntityType::Itin, 0.9)]);
        // a non-ITIN 9xx run is no SSN either
        assert!(kinds("SSN: 912123456").is_empty());
    }
}
