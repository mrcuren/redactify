//! Italian codice fiscale: validator + rule.
//!
//! Official source (retrieved 2026-10-30): Decreto ministeriale 23
//! dicembre 1976 (n. 13813), "Sistemi di codificazione dei soggetti da
//! iscrivere all'anagrafe tributaria", Gazzetta Ufficiale n. 345 of 29
//! December 1976, Supplemento ordinario,
//! <https://www.gazzettaufficiale.it/eli/gu/1976/12/29/345/so/0/sg/pdf>
//! (decree number confirmed by Agenzia delle Entrate, Circolare n. 34/E of
//! 20 July 2011). Art. 2: the 16-character layout. Art. 5: the month
//! letters A B C D E H L M P R S T, and "per i soggetti maschili il giorno
//! di nascita figura invariato, con i numeri da uno a trentuno ... Per i
//! soggetti femminili il giorno di nascita viene aumentato di quaranta
//! unità, per cui esso figura con i numeri da quarantuno a settantuno."
//! Art. 6 (omocodia): the digits 0-9 of the numeric positions may be
//! replaced by L M N P Q R S T U V. Art. 7: the odd/even value tables and
//! the mod-26 control character, identical to the tables below.
//!
//! The validator enforces the Art. 7 control character and the Art. 5
//! day field (after decoding Art. 6 omocodia letters): 01-31 or 41-71.
//! The day is not checked against the month length (the decree states
//! only the ranges).
//!
//! Earlier evidence (two independent implementations, retrieved 2026-10-08):
//! An independent public implementation: 16 characters laid out as
//!   `[A-Z]{6}` (surname/name) + `[0-9LMNPQRSTUV]{2}` (birth year) +
//!   `[ABCDEHLMPRST]` (birth month) + `[0-9LMNPQRSTUV]{2}` (birth day,
//!   +40 for women) + `[A-Z]` + `[0-9LMNPQRSTUV]{3}` (comune code) +
//!   control character; L-U are the omocodia substitutes for digits and
//!   remain checksum-valid. Control character: positions 1,3,...,15 use
//!   a dedicated lookup table, positions 2,4,...,14 use the alphabet
//!   value (digits 0-9, A=0..Z=25), total mod 26 indexes A-Z.
//! An independent public rule set: the identical two-table
//!   mod-26 checksum; context "codice fiscale", "cf".
//!   (A commercial DLP vendor's published sensitive-information-type
//!   definition "Italy fiscal code" documents the same 16-character
//!   format with Checksum: Yes.)
//! The golden vectors below were additionally confirmed by running
//! that independent public implementation itself (four valid vectors
//! including an omocodia one).
//!
//! A cue is REQUIRED: a single control character admits ~4% of random
//! 16-char shapes (DNI precedent - precision-first).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make a codice fiscale candidate claimable (public rule
/// set context list plus the English term from the DLP keyword list).
pub(super) const CUES: &[&str] = &["codice fiscale", "fiscal code", "cf"];

/// Odd-position (1st, 3rd, ...) lookup values: digits 0-9 share their
/// values with letters A-J; K-Z have their own (table from both sources).
const fn odd_value(c: u8) -> Option<u32> {
    match c {
        b'0' | b'A' => Some(1),
        b'1' | b'B' => Some(0),
        b'2' | b'C' => Some(5),
        b'3' | b'D' => Some(7),
        b'4' | b'E' => Some(9),
        b'5' | b'F' => Some(13),
        b'6' | b'G' => Some(15),
        b'7' | b'H' => Some(17),
        b'8' | b'I' => Some(19),
        b'9' | b'J' => Some(21),
        b'K' => Some(2),
        b'L' => Some(4),
        b'M' => Some(18),
        b'N' => Some(20),
        b'O' => Some(11),
        b'P' => Some(3),
        b'Q' => Some(6),
        b'R' => Some(8),
        b'S' => Some(12),
        b'T' => Some(14),
        b'U' => Some(16),
        b'V' => Some(10),
        b'W' => Some(22),
        b'X' => Some(25),
        b'Y' => Some(24),
        b'Z' => Some(23),
        _ => None,
    }
}

/// Even-position (2nd, 4th, ...) value: digits 0-9 keep their value,
/// letters use their alphabet index (A=0..Z=25).
const fn even_value(c: u8) -> Option<u32> {
    match c {
        b'0'..=b'9' => Some((c - b'0') as u32),
        b'A'..=b'Z' => Some((c - b'A') as u32),
        _ => None,
    }
}

/// Art. 6 omocodia: a numeric position holds a digit or its substitute
/// letter (L=0, M=1, N=2, P=3, Q=4, R=5, S=6, T=7, U=8, V=9).
const fn omocodia_digit(c: u8) -> Option<u32> {
    match c {
        b'0'..=b'9' => Some((c - b'0') as u32),
        b'L' => Some(0),
        b'M' => Some(1),
        b'N' => Some(2),
        b'P' => Some(3),
        b'Q' => Some(4),
        b'R' => Some(5),
        b'S' => Some(6),
        b'T' => Some(7),
        b'U' => Some(8),
        b'V' => Some(9),
        _ => None,
    }
}

/// Art. 5 day field (positions 10-11): 01-31 (male) or 41-71 (female).
fn day_ok(b: &[u8]) -> bool {
    match (omocodia_digit(b[9]), omocodia_digit(b[10])) {
        (Some(t), Some(u)) => matches!(t * 10 + u, 1..=31 | 41..=71),
        _ => false,
    }
}

/// Returns `true` if `cf` is a valid Italian codice fiscale: 16
/// uppercase alphanumeric characters, a birth-day field (positions 10-11,
/// omocodia letters decoded) of 01-31 or 41-71 (DM 13813 Art. 5), and the
/// mod-26 control character over the first fifteen (Art. 7). The rest of
/// the position layout is enforced by the rule pattern.
///
/// # Examples
/// ```
/// use redactify::valid_it_fiscal_code;
/// assert!(valid_it_fiscal_code("MRTRSS85M01H501C")); // independently verified
/// assert!(valid_it_fiscal_code("MRTRSS8RM01H501O")); // omocodia form
/// assert!(!valid_it_fiscal_code("MRTRSS85M01H501D")); // control off
/// assert!(!valid_it_fiscal_code("MRTRSS85M01H501"));  // 15 chars
/// assert!(!valid_it_fiscal_code("RSSMRA80A35H501K")); // day 35 (control fits)
/// ```
#[must_use]
pub fn valid_it_fiscal_code(cf: &str) -> bool {
    let b = cf.as_bytes();
    if b.len() != 16 {
        return false;
    }
    if !b
        .iter()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return false;
    }
    if !day_ok(b) {
        return false;
    }
    let mut total: u32 = 0;
    for (i, &c) in b[..15].iter().enumerate() {
        let v = if i % 2 == 0 {
            odd_value(c)
        } else {
            even_value(c)
        };
        match v {
            Some(v) => total += v,
            None => return false,
        }
    }
    b[15] == b'A' + (total % 26) as u8
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::ItFiscalCode,
        r"(?<![A-Z0-9])[A-Z]{6}[0-9LMNPQRSTUV]{2}[ABCDEHLMPRST][0-9LMNPQRSTUV]{2}[A-Z][0-9LMNPQRSTUV]{3}[A-Z](?![A-Z0-9])",
        Some(valid_it_fiscal_code),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_it_fiscal_code;

    #[test]
    fn control_char_math() {
        // vectors confirmed against an independent public implementation (see module docs)
        for cf in [
            "MRTRSS85M01H501C",
            "RSSMRA80A01H501U",
            "BNCMRC85M01H501Y",
            "MRTRSS8RM01H501O", // omocodia year digits as letters
        ] {
            assert!(valid_it_fiscal_code(cf), "{cf}");
        }
        // a wrong control character is always rejected
        assert!(!valid_it_fiscal_code("MRTRSS85M01H501D"));
        assert!(!valid_it_fiscal_code("RSSMRA80A01H501V"));
        // DM 13813 Art. 5: checksum-valid codes with a day outside 01-31 /
        // 41-71 are rejected (day 00, day 35)
        assert!(!valid_it_fiscal_code("DDDFFF00A00A000T"));
        assert!(!valid_it_fiscal_code("RSSMRA80A35H501K"));
        // lowercase and short forms are rejected (uppercase canonical)
        assert!(!valid_it_fiscal_code("mrtrss85m01h501c"));
        assert!(!valid_it_fiscal_code("MRTRSS85M01H501"));
    }

    #[test]
    fn odd_table_independent_transcription() {
        // recompute one control character with an independently written
        // table (flat arrays, different arrangement than the match above)
        let keys = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let odd_vals = [
            1u32, 0, 5, 7, 9, 13, 15, 17, 19, 21, // 0-9
            1, 0, 5, 7, 9, 13, 15, 17, 19, 21, // A-J (same as digits)
            2, 4, 18, 20, 11, 3, 6, 8, 12, 14, // K-T
            16, 10, 22, 25, 24, 23, // U-Z
        ];
        let base = "RSSMRA80A01H501";
        let mut total: u32 = 0;
        for (i, c) in base.bytes().enumerate() {
            let even = if c.is_ascii_digit() {
                u32::from(c - b'0')
            } else {
                u32::from(c - b'A')
            };
            let odd = odd_vals[keys.iter().position(|&k| k == c).unwrap()];
            total += if i % 2 == 0 { odd } else { even };
        }
        assert_eq!(char::from_u32(u32::from(b'A') + total % 26), Some('U'));
    }

    /// Completes a 15-character body with its Art. 7 control character
    /// (brute force over A-Z through the validator's checksum path is not
    /// used: the day check would hide the control character).
    fn complete(body: &str) -> String {
        let keys = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let odd_vals = [
            1u32, 0, 5, 7, 9, 13, 15, 17, 19, 21, 1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20,
            11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23,
        ];
        let total: u32 = body
            .bytes()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    odd_vals[keys.iter().position(|&k| k == c).unwrap()]
                } else if c.is_ascii_digit() {
                    u32::from(c - b'0')
                } else {
                    u32::from(c - b'A')
                }
            })
            .sum();
        format!("{body}{}", char::from(b'A' + (total % 26) as u8))
    }

    #[test]
    fn day_field_ranges() {
        // Art. 5: male 01-31, female 41-71; every other value is rejected
        // even with a correct control character
        for day in 0..100u32 {
            let cf = complete(&format!("RSSMRA80A{day:02}H501"));
            let expected = (1..=31).contains(&day) || (41..=71).contains(&day);
            assert_eq!(valid_it_fiscal_code(&cf), expected, "{cf}");
        }
        // Art. 6 omocodia in the day field: "M1" = 11, "QM" = 41, "LL" = 00
        assert!(valid_it_fiscal_code(&complete("RSSMRA80AM1H501")));
        assert!(valid_it_fiscal_code(&complete("RSSMRA80AQMH501")));
        assert!(!valid_it_fiscal_code(&complete("RSSMRA80ALLH501")));
        // a letter that is not an omocodia substitute is not a day digit
        assert!(!valid_it_fiscal_code(&complete("RSSMRA80AA1H501")));
    }
}
