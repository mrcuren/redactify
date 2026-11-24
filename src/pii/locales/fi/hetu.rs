//! Finnish henkilötunnus (personal identity code, "HETU"): validator +
//! rule.
//!
//! Official source (retrieved 2026-10-29): Finlex, Government Decree
//! 690/2022 "Valtioneuvoston asetus väestötietojärjestelmästä annetun
//! valtioneuvoston asetuksen 2 §:n muuttamisesta" (given in Helsinki on
//! 8 July 2022, in force 1 January 2023), amending section 2 of decree
//! 128/2010: <https://www.finlex.fi/fi/laki/alkup/2022/20220690>. Section 2:
//!
//! - "Henkilötunnus muodostuu syntymäajasta, yksilönumerosta ja
//!   tarkistusmerkistä mainitussa järjestyksessä."
//! - "Syntymäaika merkitään kuudella numerolla, joista ensimmäinen ja
//!   toinen ilmaisevat päivän, kolmas ja neljäs kuukauden, viides
//!   vuosikymmenen ja kuudes vuoden." (DDMMYY)
//! - "Yksilönumero muodostuu välimerkistä ja kolminumeroisesta luvusta ...
//!   Välimerkkinä on 1 päivänä tammikuuta 2000 tai sen jälkeen
//!   syntyneillä kirjain A, B, C, D, E tai F, 1900-luvulla syntyneillä
//!   yhdysmerkki (-) tai kirjain Y, X, W, V tai U, ja 1800-luvulla
//!   syntyneillä plusmerkki (+)."
//! - "Tarkistusmerkki on numero tai kirjain. Se saadaan jakamalla
//!   syntymäajan ja yksilönumeroon sisältyvän kolminumeroisen luvun
//!   muodostama yhdeksännumeroinen luku 31:llä, jolloin tarkistusmerkki
//!   määräytyy jakojäännöksen mukaan" - remainder table (Jakojäännös ->
//!   Tarkistusmerkki): 0-9 -> `0`-`9`, 10 A, 11 B, 12 C, 13 D, 14 E, 15 F,
//!   16 H, 17 J, 18 K, 19 L, 20 M, 21 N, 22 P, 23 R, 24 S, 25 T, 26 U,
//!   27 V, 28 W, 29 X, 30 Y.
//!
//! The decree fixes no range for the three-digit number. Statistics
//! Finland's concept definition (source organisation DVV,
//! <https://stat.fi/meta/kas/hetu.html>, retrieved 2026-10-29) narrows it
//! to "juokseva numero väliltä 002-899" for codes of registered persons;
//! the validator follows the decree text and accepts every three-digit
//! number (recall-first; the mod-31 check and the calendar date keep the
//! precision). The decree contains no worked example: test vectors are
//! computed from the remainder table above and cross-checked by a
//! separate Python re-implementation kept outside this repository
//! (`data/validator_crosscheck.jsonl`, `tests/validator_crosscheck.rs`).
//!
//! Cue policy: none (claimed cue-less at 1.0, TCKN tier): the century sign
//! narrows the shape and the mod-31 check character rejects 30 of 31
//! random candidates on top of the calendar-date filter.

use crate::pii::entity::EntityType;

use crate::pii::locales::{days_in_month, is_leap_year, rule, two_digits, ContextPolicy, Rule};

/// Decree 690/2022 section 2 remainder table: index = remainder mod 31.
const CHECK_CHARS: &[u8; 31] = b"0123456789ABCDEFHJKLMNPRSTUVWXY";

/// Returns `true` if `hetu` is a valid Finnish henkilötunnus: `DDMMYY` +
/// a century sign (`+` 1800s; `-`, `Y`, `X`, `W`, `V`, `U` 1900s; `A`-`F`
/// 2000s) + three digits + the check character of the 9-digit number
/// `DDMMYYNNN` mod 31. The birth date must be a real calendar date in the
/// century the sign selects. Letters are uppercase.
///
/// # Examples
/// ```
/// use redactify::valid_fi_hetu;
/// assert!(valid_fi_hetu("131052-308T"));
/// assert!(valid_fi_hetu("010594Y9032")); // 2023 century sign (1900s)
/// assert!(valid_fi_hetu("020304B5671")); // 2023 century sign (2000s)
/// assert!(!valid_fi_hetu("131052-308U")); // check character off
/// assert!(!valid_fi_hetu("131052G308T")); // G is not a century sign
/// ```
#[must_use]
pub fn valid_fi_hetu(hetu: &str) -> bool {
    let b = hetu.as_bytes();
    if b.len() != 11 || !b[..6].iter().chain(&b[7..10]).all(u8::is_ascii_digit) {
        return false;
    }
    let century = match b[6] {
        b'+' => 1800,
        b'-' | b'Y' | b'X' | b'W' | b'V' | b'U' => 1900,
        b'A'..=b'F' => 2000,
        _ => return false,
    };
    let day = two_digits(&b[0..2]);
    let month = two_digits(&b[2..4]);
    let year = century + two_digits(&b[4..6]);
    if day == 0 || day > days_in_month(month, is_leap_year(year)) {
        return false;
    }
    let n = b[..6]
        .iter()
        .chain(&b[7..10])
        .fold(0u32, |acc, &c| acc * 10 + u32::from(c - b'0'));
    b[10] == CHECK_CHARS[(n % 31) as usize]
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::FiHetu,
        r"(?<![0-9A-Za-z])\d{6}[\-+A-FU-Y]\d{3}[0-9A-FHJ-NPR-Y](?![0-9A-Za-z])",
        Some(valid_fi_hetu),
        ContextPolicy::None,
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::{valid_fi_hetu, CHECK_CHARS};
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn remainder_table_matches_the_decree() {
        // the decree omits G, I, O, Q and Z
        assert_eq!(CHECK_CHARS.len(), 31);
        for absent in b"GIOQZ" {
            assert!(!CHECK_CHARS.contains(absent));
        }
        assert_eq!(CHECK_CHARS[10], b'A');
        assert_eq!(CHECK_CHARS[16], b'H');
        assert_eq!(CHECK_CHARS[22], b'P');
        assert_eq!(CHECK_CHARS[30], b'Y');
    }

    #[test]
    fn every_century_sign() {
        // 131052308 % 31 = 25 -> T
        assert_eq!(131_052_308 % 31, 25);
        for v in [
            "131052-308T",
            "010594Y9032",
            "150788U1241",
            "010101A123N",
            "290200A002C", // 29 Feb 2000 (leap)
            "020304B5671",
            "311299+999E",
        ] {
            assert!(valid_fi_hetu(v), "{v}");
        }
        // the 2023 signs X, W, V and C, D, E, F share the check arithmetic
        for (sign, ok) in [
            ('X', true),
            ('W', true),
            ('V', true),
            ('C', true),
            ('F', true),
            ('G', false),
            ('Z', false),
            ('a', false),
        ] {
            assert_eq!(valid_fi_hetu(&format!("131052{sign}308T")), ok, "{sign}");
        }
    }

    #[test]
    fn invalid_dates_and_checks() {
        assert!(!valid_fi_hetu("131052-308U")); // check off
        assert!(!valid_fi_hetu("131052-309T")); // number off
        assert!(!valid_fi_hetu("290200-002C")); // 29 Feb 1900 does not exist
        assert!(!valid_fi_hetu("321052-308T")); // day 32
        assert!(!valid_fi_hetu("131352-308T")); // month 13
        assert!(!valid_fi_hetu("131052-308t")); // lowercase check char
        assert!(!valid_fi_hetu("131052-30T")); // too short
    }

    #[test]
    fn rule_claims_cue_less() {
        let ents = engine_detect("asiakas 131052-308T rekisteröity", &["fi"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::FiHetu);
        assert_eq!(ents[0].text, "131052-308T");
        assert!(engine_detect("koodi 131052-308U", &["fi"]).is_empty());
        assert!(engine_detect("ref X131052-308T", &["fi"]).is_empty());
    }
}
