//! German tax number (Steuernummer) of the Länder tax offices: validator +
//! rules (the 13-digit ELSTER form and the printed Bescheid forms).
//!
//! Official source (retrieved 2026-10-30, re-read 2026-10-31):
//! Bayerisches Landesamt für Steuern (ELSTER), "Prüfung der Steuer- und
//! Steueridentifikationsnummer sowie der Ordnungskriterien bei der
//! Grundsteuer" (Stand: 02. September 2026),
//! <https://download.elster.de/download/schnittstellen/Pruefung_der_Steuer_und_Steueridentifikatsnummer.pdf>.
//!
//! - Kap. 3: "Somit ist das ELSTER-Steuernummerformat für alle
//!   Bundesländer außer NRW: FFFF0BBBUUUUP und für NRW: FFFF0BBBBUUUP"
//!   (F = Bundesfinanzamtsnummer, B = Bezirksnummer, U =
//!   Unterscheidungsnummer, P = Prüfziffer).
//! - Kap. 4, Tabelle 4-1: the printed Bescheid layouts per Land: BW
//!   `FFBBB/UUUUP`; BY, BB, MV, SL, SN, ST, TH `FFF/BBB/UUUUP`; BE, HH, NI,
//!   RP, SH `FF/BBB/UUUUP`; HB `FF BBB UUUUP`; HE `0FF BBB UUUUP`; NRW
//!   `FFF/BBBB/UUUP`, with one official test number per Land. "In Hessen
//!   wird die führende 0 häufig von Steuerberatern weggelassen (bei
//!   Eingabe in externem Programm berücksichtigen!)."
//! - Kap. 5: "Die Steuernummer im ELSTER-Steuernummerformat ist
//!   13stellig anzugeben", only digits, "Die 5. Stelle ... muss per
//!   Definition immer 0 sein"; "Die Bezirksnummer (alle Länder außer NRW:
//!   Format BBB) darf nicht 000, 998 oder 999 sein"; NRW Bezirk not 0000,
//!   0998, 0999; in the Bavarian programming group (BY, BB, MV, SL, SN,
//!   ST, TH) "darf die Bezirksnummer nicht unter 100 sein"; "In NRW muss
//!   die Kombination aus Unterscheidungsnummer und Prüfziffer (UUUP) stets
//!   größer als 0009 sein."
//! - Kap. 6.1: "Gültige Steuernummern haben immer eine einstellige
//!   Prüfziffer." Kap. 6.3-6.6.3 and 7: modified 11er method (RP: factors
//!   0 0 1 2 0 1 2 1 2 1 2 1, a two-digit product becomes its last digit
//!   plus one, check = distance of the sum to the next multiple of 10);
//!   2er method (BW, HE, SH: summands 0 0 9 8 0 7 6 5 4 3 2 1, factors 0 0
//!   512 256 0 128 64 32 16 8 4 2, repeated digit sums, "Endet die sich
//!   ergebende Summe mit einer "0", so ist die Prüfziffer = 0"); 11er
//!   method with the Land factors of Kap. 6.6.3 (BY, BB, MV, SL, SN, ST,
//!   TH 0 5 4 3 0 2 7 6 5 4 3 2; HB, HH 0 0 4 3 0 2 7 6 5 4 3 2; NI 0 0 2 9
//!   0 8 7 6 5 4 3 2; Berlin-A 0 0 0 0 0 7 6 5 8 4 3 2; Berlin-B 0 0 2 9 0
//!   8 7 6 5 4 3 2; check = distance of the sum to the next multiple of
//!   11, 0 when divisible) and NRW (0 3 2 1 0 7 6 5 4 3 2 1, "Der nicht
//!   durch 11 teilbare Rest ist die Prüfziffer"); Kap. 7.2 table: which
//!   Berlin Finanzamt (BUFA 1113-1198) uses Berlin-A or Berlin-B, by
//!   Bezirk range.
//! - Kap. 8 table "Landesnummer": the leading digits of the
//!   Bundesfinanzamtsnummer per Land (BW 28, BY 9, BE 11, BB 30, HB 24, HH
//!   22, HE 26, MV 40, NI 23, NRW 5, RP 27, SL 10, SN 32, ST 31, SH 21, TH
//!   41), consistent with every Tabelle 4-1 test number.
//!
//! Reading notes: when the RP modified 11er sum is already a multiple of
//! 10 the check digit is taken as 0 (the text only says "nächst höhere
//! durch 10 teilbare Zahl"; the 2er method states the 0 explicitly). The
//! membership of the Bundesfinanzamtsnummer in ELSTER's list of supported
//! tax offices (a separate download) is not checked; an unknown Land
//! prefix or an unlisted Berlin office is rejected. Printed forms are
//! validated against every Land whose layout matches (the printed digits
//! are exactly the ones with a non-zero factor); the older RP layout
//! `FF/BBB/UUUU/P`, the spaced SH layout and the Bavarian form without
//! `FFF` are not accepted.
//!
//! Cue policy: a single check digit, so a cue is REQUIRED (score 1.0).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (lowercase): the identifier's names and the issuing office.
pub(super) const CUES: &[&str] = &["steuernummer", "steuer-nr", "st.-nr", "stnr", "finanzamt"];

/// Land of a Bundesfinanzamtsnummer (Kap. 8 "Landesnummer").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Land {
    Bw,
    By,
    Be,
    Bb,
    Hb,
    Hh,
    He,
    Mv,
    Ni,
    Nw,
    Rp,
    Sl,
    Sn,
    St,
    Sh,
    Th,
}

const fn land_of(d0: u8, d1: u8) -> Option<Land> {
    Some(match (d0, d1) {
        (b'9', _) => Land::By,
        (b'5', _) => Land::Nw,
        (b'2', b'8') => Land::Bw,
        (b'1', b'1') => Land::Be,
        (b'3', b'0') => Land::Bb,
        (b'2', b'4') => Land::Hb,
        (b'2', b'2') => Land::Hh,
        (b'2', b'6') => Land::He,
        (b'4', b'0') => Land::Mv,
        (b'2', b'3') => Land::Ni,
        (b'2', b'7') => Land::Rp,
        (b'1', b'0') => Land::Sl,
        (b'3', b'2') => Land::Sn,
        (b'3', b'1') => Land::St,
        (b'2', b'1') => Land::Sh,
        (b'4', b'1') => Land::Th,
        _ => return None,
    })
}

/// 11er factors of the Bavarian programming group (Kap. 6.6.3).
const F11_BY: [u32; 12] = [0, 5, 4, 3, 0, 2, 7, 6, 5, 4, 3, 2];
/// 11er factors of Bremen and Hamburg.
const F11_HB_HH: [u32; 12] = [0, 0, 4, 3, 0, 2, 7, 6, 5, 4, 3, 2];
/// 11er factors of Niedersachsen (identical to Berlin-B).
const F11_NI_BE_B: [u32; 12] = [0, 0, 2, 9, 0, 8, 7, 6, 5, 4, 3, 2];
/// 11er factors of Berlin-A.
const F11_BE_A: [u32; 12] = [0, 0, 0, 0, 0, 7, 6, 5, 8, 4, 3, 2];
/// NRW factors (remainder variant).
const F11_NW: [u32; 12] = [0, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1];

fn weighted(d: &[u32; 13], f: &[u32; 12]) -> u32 {
    d.iter().zip(f).map(|(a, b)| a * b).sum()
}

/// 11er method (all Länder except NRW): `None` for the never-issued
/// two-digit check value 10.
fn check_11er(d: &[u32; 13], f: &[u32; 12]) -> Option<u32> {
    let r = weighted(d, f) % 11;
    let p = if r == 0 { 0 } else { 11 - r };
    (p < 10).then_some(p)
}

/// NRW 11er method: the remainder itself (10 is never issued).
fn check_nw(d: &[u32; 13]) -> Option<u32> {
    let p = weighted(d, &F11_NW) % 11;
    (p < 10).then_some(p)
}

/// 2er method (BW, HE, SH).
fn check_2er(d: &[u32; 13]) -> u32 {
    const SUMMAND: [u32; 12] = [0, 0, 9, 8, 0, 7, 6, 5, 4, 3, 2, 1];
    const FACTOR: [u32; 12] = [0, 0, 512, 256, 0, 128, 64, 32, 16, 8, 4, 2];
    let mut total = 0;
    for i in 0..12 {
        let mut v = ((d[i] + SUMMAND[i]) % 10) * FACTOR[i];
        while v > 9 {
            let mut q = 0;
            while v > 0 {
                q += v % 10;
                v /= 10;
            }
            v = q;
        }
        total += v;
    }
    if total % 10 == 0 {
        0
    } else {
        10 - total % 10
    }
}

/// Modified 11er method (RP).
fn check_mod11_rp(d: &[u32; 13]) -> u32 {
    const FACTOR: [u32; 12] = [0, 0, 1, 2, 0, 1, 2, 1, 2, 1, 2, 1];
    let total: u32 = d
        .iter()
        .zip(FACTOR)
        .map(|(&a, f)| {
            let p = a * f;
            if p > 9 {
                p % 10 + 1
            } else {
                p
            }
        })
        .sum();
    (10 - total % 10) % 10
}

/// Berlin method per Kap. 7.2 (`true` = Berlin-B); `None` for an office
/// the table does not list.
const fn berlin_uses_b(bufa: u32, bezirk: u32) -> Option<bool> {
    Some(match bufa {
        1113 | 1114 | 1117 | 1120 | 1121 | 1123 | 1124 | 1125 => matches!(bezirk, 201..=693),
        1116 => matches!(bezirk, 1..=29 | 201..=693 | 875..=899),
        1119 => matches!(bezirk, 201..=639 | 680 | 684),
        1115 | 1118 | 1131..=1138 | 1194..=1198 => true,
        1127 | 1129 | 1130 => false,
        _ => return None,
    })
}

fn number(d: &[u32]) -> u32 {
    d.iter().fold(0, |acc, &x| acc * 10 + x)
}

/// Kap. 5 formal checks plus the Land check digit on the 13-digit ELSTER
/// form.
fn valid_elster(b: &[u8; 13]) -> bool {
    if !b.iter().all(u8::is_ascii_digit) || b[4] != b'0' {
        return false;
    }
    let Some(land) = land_of(b[0], b[1]) else {
        return false;
    };
    let mut d = [0u32; 13];
    for (x, &c) in d.iter_mut().zip(b) {
        *x = u32::from(c - b'0');
    }
    let expected = if land == Land::Nw {
        let bezirk = number(&d[5..9]);
        if matches!(bezirk, 0 | 998 | 999) || number(&d[9..13]) <= 9 {
            return false;
        }
        check_nw(&d)
    } else {
        let bezirk = number(&d[5..8]);
        if matches!(bezirk, 0 | 998 | 999) {
            return false;
        }
        match land {
            Land::By | Land::Bb | Land::Mv | Land::Sl | Land::Sn | Land::St | Land::Th => {
                if bezirk < 100 {
                    return false;
                }
                check_11er(&d, &F11_BY)
            }
            Land::Hb | Land::Hh => check_11er(&d, &F11_HB_HH),
            Land::Ni => check_11er(&d, &F11_NI_BE_B),
            Land::Be => match berlin_uses_b(number(&d[..4]), bezirk) {
                Some(true) => check_11er(&d, &F11_NI_BE_B),
                Some(false) => check_11er(&d, &F11_BE_A),
                None => None,
            },
            Land::Bw | Land::He | Land::Sh => Some(check_2er(&d)),
            Land::Rp => Some(check_mod11_rp(&d)),
            Land::Nw => None,
        }
    };
    expected == Some(d[12])
}

/// Builds the ELSTER form `prefix + printed digits` with the format `0`
/// inserted after the four-digit Bundesfinanzamtsnummer.
fn elster_from(prefix: &[u8], digits: &[u8]) -> Option<[u8; 13]> {
    let mut out = [0u8; 13];
    let mut it = prefix.iter().chain(digits.iter());
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = if i == 4 { b'0' } else { *it.next()? };
    }
    it.next().is_none().then_some(out)
}

/// Validates a printed form against every Land whose layout matches.
fn valid_printed(s: &str) -> bool {
    let (sep, groups): (u8, Vec<&str>) = if s.contains('/') {
        (b'/', s.split('/').collect())
    } else {
        (b' ', s.split(' ').collect())
    };
    if !groups
        .iter()
        .all(|g| !g.is_empty() && g.bytes().all(|c| c.is_ascii_digit()))
    {
        return false;
    }
    let lens: Vec<usize> = groups.iter().map(|g| g.len()).collect();
    let digits: Vec<u8> = groups.concat().into_bytes();
    let prefixes: &[&[u8]] = match (sep, lens.as_slice()) {
        // BW FFBBB/UUUUP
        (b'/', [5, 5]) => &[b"28"],
        // BY, BB, MV, SL, SN, ST, TH FFF/BBB/UUUUP: identical factors and
        // formal checks, and the Land digit carries factor 0
        (b'/', [3, 3, 5]) => &[b"9"],
        // BE, HH, NI, RP, SH FF/BBB/UUUUP
        (b'/', [2, 3, 5]) => &[b"11", b"22", b"23", b"27", b"21"],
        // NRW FFF/BBBB/UUUP
        (b'/', [3, 4, 4]) => &[b"5"],
        // HB FF BBB UUUUP, or HE with the leading 0 omitted
        (b' ', [2, 3, 5]) => &[b"24", b"26"],
        // HE 0FF BBB UUUUP
        (b' ', [3, 3, 5]) if digits[0] == b'0' => {
            return elster_from(b"26", &digits[1..]).is_some_and(|e| valid_elster(&e));
        }
        _ => return false,
    };
    prefixes
        .iter()
        .any(|p| elster_from(p, &digits).is_some_and(|e| valid_elster(&e)))
}

/// Returns `true` if `stnr` is a valid German Steuernummer, either in the
/// 13-digit ELSTER form `FFFF0BBBUUUUP` (NRW `FFFF0BBBBUUUP`) or in one of
/// the printed Bescheid layouts of ELSTER Tabelle 4-1 (`FFBBB/UUUUP`,
/// `FFF/BBB/UUUUP`, `FF/BBB/UUUUP`, `FFF/BBBB/UUUP`, `FF BBB UUUUP`,
/// `0FF BBB UUUUP`). Checks the Kap. 5 formal rules (fifth digit 0,
/// excluded Bezirk values, Bavarian-group Bezirk at least 100, NRW
/// `UUUP` above 0009), the Land given by the Bundesfinanzamtsnummer and
/// that Land's check-digit method (Kap. 6-7).
///
/// # Examples
/// ```
/// use redactify::valid_de_tax_number;
/// assert!(valid_de_tax_number("9198081508152")); // ELSTER test number (BY)
/// assert!(valid_de_tax_number("198/815/08152")); // its printed form
/// assert!(valid_de_tax_number("5400081508159")); // NRW
/// assert!(!valid_de_tax_number("9198081508153")); // check digit off
/// assert!(!valid_de_tax_number("9198181508152")); // fifth digit not 0
/// ```
#[must_use]
pub fn valid_de_tax_number(stnr: &str) -> bool {
    match <&[u8; 13]>::try_from(stnr.as_bytes()) {
        Ok(b) if b.iter().all(u8::is_ascii_digit) => valid_elster(b),
        _ => valid_printed(stnr),
    }
}

/// The 13-digit ELSTER form. Priority tier 0 (see `EntityType::priority`):
/// about 10% of valid values also pass Luhn, and the cue-less 13-19 digit
/// card rule must not relabel them.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        id = "de::tax_number",
        EntityType::DeTaxNumber,
        r"(?<!\d)\d{4}0\d{8}(?!\d)",
        Some(valid_de_tax_number),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

/// The printed Bescheid layouts (slash- or space-separated groups).
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn printed_rule() -> Rule {
    rule!(
        id = "de::tax_number_printed",
        EntityType::DeTaxNumber,
        concat!(
            r"(?<![\d/])(?:\d{5}/\d{5}|\d{2,3}/\d{3}/\d{5}|\d{3}/\d{4}/\d{4})(?![\d/])",
            r"|(?<!\d)(?<!\d )0?\d{2} \d{3} \d{5}(?!\d)(?! \d)"
        ),
        Some(valid_de_tax_number),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::{berlin_uses_b, valid_de_tax_number, CUES};
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    /// ELSTER Tabelle 4-1: (ELSTER form, printed Bescheid form).
    const OFFICIAL: &[(&str, &str)] = &[
        ("2866081508156", "66815/08156"),   // BW
        ("9198081508152", "198/815/08152"), // BY
        ("9296081508153", "296/815/08153"), // BY
        ("1197081508154", "97/815/08154"),  // BE (Berlin-B office 1197)
        ("3098081508157", "098/815/08157"), // BB
        ("2497012301233", "97 123 01233"),  // HB
        ("2293081508150", "93/815/08150"),  // HH
        ("2653081508158", "053 815 08158"), // HE
        ("4098081508157", "098/815/08157"), // MV
        ("2388081508158", "88/815/08158"),  // NI
        ("5400081508159", "400/8150/8159"), // NRW
        ("5500081508151", "500/8150/8151"), // NRW
        ("5600081508154", "600/8150/8154"), // NRW
        ("2799081508152", "99/815/08152"),  // RP
        ("1096081508187", "096/815/08187"), // SL
        ("3248081508156", "248/815/08156"), // SN
        ("3198081508152", "198/815/08152"), // ST
        ("2138081508154", "38/815/08154"),  // SH
        ("4198081508152", "198/815/08152"), // TH
    ];

    #[test]
    fn official_test_numbers_pass_in_both_forms() {
        for (elster, printed) in OFFICIAL {
            assert!(valid_de_tax_number(elster), "{elster}");
            assert!(valid_de_tax_number(printed), "{printed}");
        }
        // HE without the leading 0 (Tabelle 4-1 note on tax advisers)
        assert!(valid_de_tax_number("53 815 08158"));
    }

    #[test]
    fn every_other_check_digit_is_rejected() {
        for (elster, _) in OFFICIAL {
            let good = elster.as_bytes()[12];
            for d in b'0'..=b'9' {
                if d != good {
                    let bad = format!("{}{}", &elster[..12], char::from(d));
                    assert!(!valid_de_tax_number(&bad), "{bad}");
                }
            }
        }
    }

    #[test]
    fn formal_rules() {
        assert!(!valid_de_tax_number("2866181508156")); // fifth digit not 0
        assert!(!valid_de_tax_number("2866000008150")); // Bezirk 000
        assert!(!valid_de_tax_number("9198099908152")); // Bezirk 999
        assert!(!valid_de_tax_number("9198099808152")); // Bezirk 998
        assert!(!valid_de_tax_number("9198009908151")); // Bavarian Bezirk < 100
        assert!(!valid_de_tax_number("5400000008159")); // NRW Bezirk 0000
        assert!(!valid_de_tax_number("5400081500009")); // NRW UUUP 0009
        assert!(!valid_de_tax_number("6198081508152")); // no Land 6
        assert!(!valid_de_tax_number("1122081508154")); // Berlin office not listed
        assert!(!valid_de_tax_number("286608150815"));
        assert!(!valid_de_tax_number("28660815081560"));
        assert!(!valid_de_tax_number("198/815/0815"));
        assert!(!valid_de_tax_number("198-815-08152"));
        assert!(!valid_de_tax_number("198/815 08152"));
    }

    #[test]
    fn berlin_method_table() {
        assert_eq!(berlin_uses_b(1197, 815), Some(true));
        assert_eq!(berlin_uses_b(1113, 200), Some(false));
        assert_eq!(berlin_uses_b(1113, 201), Some(true));
        assert_eq!(berlin_uses_b(1113, 694), Some(false));
        assert_eq!(berlin_uses_b(1116, 29), Some(true));
        assert_eq!(berlin_uses_b(1116, 30), Some(false));
        assert_eq!(berlin_uses_b(1116, 875), Some(true));
        assert_eq!(berlin_uses_b(1119, 680), Some(true));
        assert_eq!(berlin_uses_b(1119, 681), Some(false));
        assert_eq!(berlin_uses_b(1127, 500), Some(false));
        assert_eq!(berlin_uses_b(1126, 500), None);
    }

    #[test]
    fn rules_require_a_cue() {
        for (elster, printed) in OFFICIAL {
            for v in [elster, printed] {
                let text = format!("Steuernummer: {v}");
                let ents = engine_detect(&text, &["de"]);
                assert_eq!(ents.len(), 1, "{text}: {ents:?}");
                assert_eq!(ents[0].kind, EntityType::DeTaxNumber);
                assert_eq!(ents[0].text, *v);
                // no cue: never a tax number (a Luhn-passing 13-digit run
                // is still the always-on card rule's claim)
                assert!(engine_detect(&format!("Akte {v} abgelegt"), &["de"])
                    .iter()
                    .all(|e| e.kind != EntityType::DeTaxNumber));
            }
        }
        for cue in CUES {
            let text = format!("{cue} 198/815/08152");
            assert_eq!(engine_detect(&text, &["de"]).len(), 1, "{text}");
        }
        // a spaced group inside a longer spaced digit run is not a candidate
        assert!(engine_detect("Steuernummer 1 97 123 01233", &["de"]).is_empty());
    }
}
