//! Swedish personnummer and samordningsnummer: validator + rules.
//!
//! Official source (retrieved 2026-10-29): Skatteverket, "Personnummer",
//! SKV 704 utgåva 8 (utgiven i september 2007), served by the Swedish
//! government e-identification framework's mirror of Skatteverket
//! publications: <https://docs.swedenconnect.se/technical-framework/mirror/skv/skv704-8.pdf>.
//!
//! - "Personnumret består av följande tre delar: Födelsetid,
//!   Födelsenummer, Kontrollsiffra" with the example `64 08 23 - 323 4`;
//!   "Födelsetiden anges med sex siffror": year (two digits), month, day.
//! - "Födelsenumret består av tre siffror. Det är något av talen 001-999".
//! - "Mellan födelsetiden och födelsenumret finns ett bindestreck (-), som
//!   byts ut mot ett plustecken (+) det år en person fyller 100 år."
//! - "Ett samordningsnummer påminner om personnummer, men siffran för
//!   födelsedag är ökad med talet 60."
//! - "Personnummer i ADB-system": stored "med tolv siffror, där de två
//!   inledande siffrorna anger under vilket århundrade en person är född.
//!   Siffran för århundrade kan vara 18, 19 eller ... 20", example
//!   `196408233234`.
//! - "Beräkning av kontrollsiffra: Kontrollsiffran bestäms enligt den s.k.
//!   modulus-10-metoden med vikterna 1 och 2": the nine digits of year,
//!   month, day and number "multipliceras växelvis med 2 och 1"; "Lägg
//!   samman siffrorna i produkterna. OBS! 12 räknas som 1 + 2.";
//!   "Entalssiffran i siffersumman dras från talet 10."; "Restsiffran blir
//!   kontrollsiffra. Är resten 10, blir kontrollsiffran 0." Worked
//!   example: `640823-3234` (digit sum 36, 10 - 6 = 4).
//!
//! The validator enforces exactly these rules plus a real calendar date
//! (day minus 60 for a samordningsnummer). Without the century (10-digit
//! forms) 29 February is accepted for every year divisible by 4.
//!
//! Cue policy: the separator form `YYMMDD-NNNC` / `YYMMDD+NNNC` is the
//! printed form of the source -> claimed cue-less at 0.85 (single check
//! digit: ~10% of random shapes pass it, the date filters the rest) and
//! raised to 1.0 by a cue. Bare 10- and 12-digit runs collide with phone,
//! order and other national-ID shapes -> a cue is REQUIRED (1.0). Cues are
//! the identifier names used by the source.

use crate::pii::entity::EntityType;

use crate::pii::locales::{
    days_in_month, is_leap_two_digit_year, is_leap_year, luhn_valid, rule, two_digits,
    ContextPolicy, Rule,
};

/// Cue words (the source's own names for the identifier).
pub(super) const CUES: &[&str] = &["personnummer", "personnumret", "samordningsnummer"];

/// Returns `true` if `pnr` is a valid Swedish personnummer or
/// samordningsnummer in one of the source's forms: `YYMMDD-NNNC`,
/// `YYMMDD+NNNC`, `YYMMDDNNNC` or the 12-digit stored form `CCYYMMDDNNNC`
/// (century 18, 19 or 20). Checks the calendar date (samordningsnummer:
/// day + 60), the birth number 001-999 and the modulus-10 check digit with
/// weights 2 and 1.
///
/// # Examples
/// ```
/// use redactify::valid_se_personnummer;
/// assert!(valid_se_personnummer("640823-3234")); // SKV 704 worked example
/// assert!(valid_se_personnummer("196408233234")); // stored 12-digit form
/// assert!(valid_se_personnummer("640883-3231")); // samordningsnummer (day 23 + 60)
/// assert!(!valid_se_personnummer("640823-3235")); // check digit off
/// ```
#[must_use]
pub fn valid_se_personnummer(pnr: &str) -> bool {
    let b = pnr.as_bytes();
    let mut d = [0u8; 10];
    let century = match b.len() {
        10 => {
            d.copy_from_slice(b);
            None
        }
        11 if matches!(b[6], b'-' | b'+') => {
            d[..6].copy_from_slice(&b[..6]);
            d[6..].copy_from_slice(&b[7..]);
            None
        }
        12 => {
            d.copy_from_slice(&b[2..]);
            if !b[..2].iter().all(u8::is_ascii_digit) {
                return false;
            }
            let c = two_digits(&b[..2]);
            if !(18..=20).contains(&c) {
                return false;
            }
            Some(c)
        }
        _ => return false,
    };
    if !d.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let yy = two_digits(&d[0..2]);
    let month = two_digits(&d[2..4]);
    let raw_day = two_digits(&d[4..6]);
    let day = if raw_day > 60 { raw_day - 60 } else { raw_day };
    let leap = match century {
        Some(c) => is_leap_year(c * 100 + yy),
        None => is_leap_two_digit_year(yy),
    };
    if day == 0 || day > days_in_month(month, leap) || &d[6..9] == b"000" {
        return false;
    }
    // modulus-10 with weights 2,1,2,... over the first nine digits (adding
    // the DIGITS of each product) and check digit (10 - sum mod 10) mod 10:
    // exactly the Luhn check over all ten digits
    luhn_valid(&d)
}

/// Separator form `YYMMDD-NNNC` / `YYMMDD+NNNC`: cue-less 0.85, cue 1.0.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::SePersonnummer,
        r"(?<![\d+\-])\d{6}[\-+]\d{4}(?![\d\-])",
        Some(valid_se_personnummer),
        ContextPolicy::Boost(CUES, 1.0),
        0.85
    )
}

/// Bare 10-digit and 12-digit (century-prefixed) forms: cue required.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn bare_rule() -> Rule {
    rule!(
        id = "se::personnummer_bare",
        EntityType::SePersonnummer,
        r"(?<![\d+\-])(?:(?:18|19|20)\d{10}|\d{10})(?![\d\-])",
        Some(valid_se_personnummer),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_se_personnummer;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn skv704_worked_example() {
        // 6 4 0 8 2 3 3 2 3 x 2 1 2 1 2 1 2 1 2 -> 12 4 0 8 4 3 6 2 6,
        // digit sum 1+2+4+0+8+4+3+6+2+6 = 36, 10 - 6 = 4
        assert_eq!(1 + 2 + 4 + 8 + 4 + 3 + 6 + 2 + 6, 36);
        assert!(valid_se_personnummer("640823-3234"));
        assert!(valid_se_personnummer("6408233234"));
        assert!(valid_se_personnummer("196408233234"));
        // centenarian separator
        assert!(valid_se_personnummer("640823+3234"));
    }

    #[test]
    fn invalid_shapes_and_dates() {
        for v in [
            "640823-3235",  // check digit off
            "640823-0008",  // birth number 000 (check digit computed valid)
            "641323-3237",  // month 13 (check digit computed valid)
            "640832-3233",  // day 32 (check digit computed valid)
            "640853-3237",  // day 53, neither real nor + 60 (check valid)
            "640823*3234",  // unknown separator
            "216408233234", // century 21
            "64082332345",  // 11 digits, no separator
        ] {
            assert!(!valid_se_personnummer(v), "{v}");
        }
        // samordningsnummer: day + 60
        assert!(valid_se_personnummer("640883-3231"));
        // 29 February: century-aware in the 12-digit form (same check
        // digit: the century is not part of the modulus-10 input)
        assert!(valid_se_personnummer("200002291235"));
        assert!(!valid_se_personnummer("190002291235"));
        // without the century, 29 February of a year divisible by 4 passes
        assert!(valid_se_personnummer("000229-1235"));
    }

    #[test]
    fn separator_form_boosts_bare_form_needs_cue() {
        let ents = engine_detect("kund 640823-3234 registrerad", &["se"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::SePersonnummer);
        assert!((ents[0].score - 0.85).abs() < 1e-6);
        let cued = engine_detect("personnummer 640823-3234", &["se"]);
        assert!((cued[0].score - 1.0).abs() < 1e-6, "{cued:?}");

        assert!(engine_detect("order 6408233234 sent", &["se"]).is_empty());
        let bare = engine_detect("Personnummer: 196408233234", &["se"]);
        assert_eq!(bare.len(), 1, "{bare:?}");
        assert_eq!(bare[0].text, "196408233234");
    }
}
