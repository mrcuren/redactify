//! Danish CPR personnummer: validator + rule. Date validation
//! ONLY - deliberately no modulus 11 check.
//!
//! Official source (retrieved 2026-10-29): CPR-kontoret, "Personnummeret i
//! CPR-systemet", dated 1 July 2008:
//! <https://www.cpr.dk/media/12066/personnummeret-i-cpr.pdf> (served from
//! <https://cdn9.cpr.dk/cpr/media/12066/personnummeret-i-cpr.pdf>).
//!
//! - Section "Personnumre til kvinder og mænd med kontrolciffer": numbers
//!   with a control digit are assigned first; "Når de ca. 540 personnumre,
//!   der er til rådighed på hver fødselsdato, er tildelt ..., vil CPR's
//!   program ... tildele personnumre efter følgende regler".
//! - Sections "Personnumre til kvinder uden kontrolciffer" / "... mænd uden
//!   kontrolciffer": "Herefter tildeles personnumre uden kontrolciffer"
//!   and "Hvis der fremkommer personnummer, der opfylder modulus 11, kan det
//!   ikke benyttes efter denne nye metode". A valid CPR number therefore
//!   need NOT satisfy modulus 11, and a modulus 11 filter would drop real
//!   numbers.
//! - Section "Personnummerets opbygning": "1 - 2 position angiver
//!   personens fødselsdag. 3 - 4 position angiver personens fødselsmåned.
//!   5 - 6 position angiver personens fødselsår, uden århundrede. 7 - 10
//!   position er et løbenummer." and "Kombinationen af cifrene i
//!   positionerne 5, 6 og 7 angiver personens århundrede". Century table
//!   (løbenummer range, year range -> century): 0001-0999, 1000-1999,
//!   2000-2999, 3000-3999: 00-99 -> 1900-1999; 4000-4999 and 9000-9999:
//!   00-36 -> 2000-2036, 37-99 -> 1937-1999; 5000-5999 ... 8000-8999:
//!   00-57 -> 2000-2057, 58-99 -> 1858-1899. Day 01-31, month 01-12.
//! - "BILAG": the modulus 11 weights 4 3 2 7 6 5 4 3 2 1 and the example
//!   number `07 07 61-4285` (it satisfies modulus 11; the validator does
//!   not use that property).
//!
//! The validator checks the shape, the løbenummer range (0001-9999: the
//! table starts at 0001) and a real calendar date in the century the
//! table assigns.
//!
//! Cue policy: a cue is REQUIRED and the score is 0.9 (format + mandatory
//! cue, no checksum): a date-valid `DDMMYY-SSSS` shape is common in
//! ordinary text. Cues are the names used by the source.
//!
//! Priority: TCKN tier 3 and registered before the `se` pack. The shape is
//! also the Swedish `YYMMDD-NNNC` shape and the source's own example
//! `070761-4285` passes the Swedish samordningsnummer date (day 61 - 60)
//! and Luhn check, so with both packs enabled a cued CPR number keeps the
//! Danish label instead of the cue-less Swedish claim.

use crate::pii::entity::EntityType;

use crate::pii::locales::{
    code_chars, days_in_month, is_leap_year, rule, two_digits, ContextPolicy, Rule,
};

/// Cue words (the identifier names used by the source).
pub(super) const CUES: &[&str] = &["cpr", "personnummer"];

/// Returns `true` if `cpr` is a structurally valid Danish CPR number:
/// 10 digits (`DDMMYY-SSSS`, `DDMMYYSSSS` or the source's `DD MM YY-SSSS`;
/// spaces and `-` are ignored), løbenummer 0001-9999 and a real calendar
/// birth date in the century given by the CPR office's table (position 7
/// together with the year). No modulus 11 check: the CPR office issues
/// numbers without a control digit.
///
/// # Examples
/// ```
/// use redactify::valid_dk_cpr;
/// assert!(valid_dk_cpr("070761-4285")); // CPR office example
/// assert!(valid_dk_cpr("070761-4286")); // fails modulus 11, still valid
/// assert!(!valid_dk_cpr("310261-4285")); // 31 February
/// assert!(!valid_dk_cpr("070761-0000")); // løbenummer starts at 0001
/// ```
#[must_use]
pub fn valid_dk_cpr(cpr: &str) -> bool {
    let Some(d) = code_chars::<10>(cpr, u8::is_ascii_digit, b" -") else {
        return false;
    };
    if &d[6..] == b"0000" {
        return false;
    }
    let day = two_digits(&d[0..2]);
    let month = two_digits(&d[2..4]);
    let yy = two_digits(&d[4..6]);
    // "Kombinationen af cifrene i positionerne 5, 6 og 7 angiver personens
    // århundrede"
    let century = match (d[6] - b'0', yy) {
        (0..=3, _) | (4 | 9, 37..=99) => 1900,
        (4 | 9, _) | (5..=8, 0..=57) => 2000,
        _ => 1800, // 5000-8999 with year 58-99
    };
    day >= 1 && day <= days_in_month(month, is_leap_year(century + yy))
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::DkCpr,
        r"(?<![\d\-])(?:\d{6}-?\d{4}|\d{2} \d{2} \d{2}-\d{4})(?![\d\-])",
        Some(valid_dk_cpr),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_dk_cpr;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    /// The appendix modulus 11 check, used here ONLY to prove that the
    /// validator ignores it.
    fn mod11(s: &str) -> bool {
        let w = [4, 3, 2, 7, 6, 5, 4, 3, 2, 1];
        let sum: u32 = s
            .bytes()
            .filter(u8::is_ascii_digit)
            .zip(w)
            .map(|(c, w)| u32::from(c - b'0') * w)
            .sum();
        sum % 11 == 0
    }

    #[test]
    fn source_example_and_no_modulus_11() {
        assert!(mod11("0707614285"));
        assert!(valid_dk_cpr("07 07 61-4285"));
        assert!(valid_dk_cpr("070761-4285"));
        assert!(valid_dk_cpr("0707614285"));
        // the same birth date with a serial that fails modulus 11 is a
        // legitimately issued shape (numbers without a control digit)
        assert!(!mod11("0707614286"));
        assert!(valid_dk_cpr("070761-4286"));
    }

    #[test]
    fn century_table_drives_the_leap_day() {
        // 29 Feb 00: serial 0xxx-3xxx -> 1900 (not leap), 4xxx -> 2000
        assert!(!valid_dk_cpr("290200-1234"));
        assert!(valid_dk_cpr("290200-4234"));
        // 5000-8999 with year 58-99 -> 1858-1899: 1896 leap, 1900 n/a
        assert!(valid_dk_cpr("290296-5234"));
        // 29 Feb 1897 does not exist
        assert!(!valid_dk_cpr("290297-5234"));
        // 9000-9999: 00-36 -> 2000s (2036 leap), 37-99 -> 1900s
        assert!(valid_dk_cpr("290236-9234"));
        assert!(!valid_dk_cpr("290237-9234"));
    }

    #[test]
    fn invalid_shapes() {
        for v in [
            "320761-4285",  // day 32
            "071361-4285",  // month 13
            "000761-4285",  // day 0
            "070761-0000",  // løbenummer 0000
            "070761-428",   // 9 digits
            "070761-42851", // 11 digits
            "070761/4285",  // foreign separator
        ] {
            assert!(!valid_dk_cpr(v), "{v}");
        }
    }

    #[test]
    fn cue_is_required() {
        assert!(engine_detect("ordre 070761-4285 sendt", &["dk"]).is_empty());
        let ents = engine_detect("CPR-nr. 070761-4285", &["dk"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::DkCpr);
        assert!((ents[0].score - 0.9).abs() < 1e-6);
        let spaced = engine_detect("personnummer 07 07 61-4285", &["dk"]);
        assert_eq!(spaced.len(), 1, "{spaced:?}");
        assert_eq!(spaced[0].text, "07 07 61-4285");
    }
}
