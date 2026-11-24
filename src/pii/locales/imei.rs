//! Mobile equipment identity (IMEI / IMEISV): validators + rules.
//!
//! Official source: GSMA PRD TS.06 "IMEI Allocation and Approval Process",
//! version 27.0, 06 January 2025
//! (<https://imeidb.gsma.com/imei/resources/documents/TS.06%20v27.0.pdf>,
//! retrieved 2026-11-23):
//!
//! - section 5: "The 'IMEI' consists of a number of fields totalling 15
//!   digits", laid out as `NNXXXXXX ZZZZZZ A` (TAC, serial number, check
//!   digit);
//! - section 5.1.2: "The first two digits of the TAC are the RB [Reporting
//!   Body] Identifier"; Annex A lists them. Table 1 (currently
//!   allocating): `00` test ME, `01` CTIA, `35` TÜV SÜD (BABT), `86` TAF
//!   (China), `98` reserved ("a few TAC codes had previously been assigned
//!   from this block"), `99` Global Hexadecimal Administrator. Table 2 (no
//!   longer allocating, IMEIs still in use): `10`, `30`, `33`, `44`, `45`,
//!   `49`, `50`-`54`, `91`;
//! - section 5.1.5: "The Check Digit shall be calculated according to Luhn
//!   formula (ISO/IEC 7812, see 3GPP 22.016)";
//! - Annex C.3: the IMEISV is `NNXXXXXX ZZZZZZ SS`, the first 14 IMEI
//!   digits plus a 2-digit software version number, "00 - 98. 99 is
//!   reserved for future use" (no check digit).
//!
//! The test-ME identifier `00` is left out: section 9 says "ME with Test
//! IMEI cannot be supplied to the market", and a `00`-led digit run is far
//! more often something else.
//!
//! Cue policy. A 15-digit IMEI is claimed WITHOUT a cue: it is a
//! Luhn-valid 15-digit run that a plain Luhn card rule would mask anyway,
//! so claiming the reporting-body subset as IMEI adds no masking surface;
//! it gives those values their own label (the card rule rejects 15-digit
//! runs outside the published card ranges, see `generic::card_number`).
//! In the nm-kvkk-pii-6K test split all 39 device identifiers are such
//! IMEIs, and the 18-character cue window misses the label of several of
//! them ("cihaz bilgileri ekranında 867236055436929 numarası"). Next to an
//! "imei" cue the reporting-body check is dropped ([`cued_rule`]):
//! labelled fixtures hold "IMEI numarası 437905244025352" and
//! "IMEI: 944739086974724" (prefixes 43 and 94, in no Annex A table),
//! which would otherwise stay in clear. The 16-digit IMEISV has no check
//! digit and the card shape, so it is claimed only by the cue-gated rule
//! (the cue "imei" also covers "IMEISV" and "IMEI SV"). Both forms share
//! that rule: each extra rule scans every line once more (about 70 ms per
//! 25 000 nm-kvkk/piimask lines for this pattern, with fancy-regex 0.20).
//!
//! Printed forms: the contiguous 15 digits, or the TS.06 fields separated
//! by a space or hyphen: TAC + serial + check digit (`35152420 568191 3`)
//! or the TAC split into its reporting-body and model parts
//! (`35-152420-568191-3`).

use crate::pii::entity::EntityType;
use crate::pii::locales::{luhn_valid, rule, token_rest, ContextPolicy, Rule};

/// Reporting Body Identifiers of TS.06 Annex A (tables 1 and 2, without
/// the test identifier `00`), sorted for binary search.
const REPORTING_BODIES: [u8; 17] = [
    1, 10, 30, 33, 35, 44, 45, 49, 50, 51, 52, 53, 54, 86, 91, 98, 99,
];

/// The ASCII digits of `s` when every other byte is a space or hyphen and
/// there are exactly `N` digits.
fn digits_of<const N: usize>(s: &str) -> Option<[u8; N]> {
    crate::pii::locales::code_chars::<N>(s, u8::is_ascii_digit, b" -")
}

/// Whether the first two digits are an allocated reporting body.
fn known_reporting_body(d: &[u8]) -> bool {
    let rb = (d[0] - b'0') * 10 + (d[1] - b'0');
    REPORTING_BODIES.binary_search(&rb).is_ok()
}

/// Returns `true` for a valid IMEI: 15 digits (spaces or hyphens between
/// the fields allowed), a TS.06 reporting-body prefix and a Luhn check
/// digit.
pub(crate) fn valid_imei(s: &str) -> bool {
    digits_of::<15>(s).is_some_and(|d| known_reporting_body(&d) && luhn_valid(&d))
}

/// Returns `true` for a structurally valid IMEISV: 16 digits, a TS.06
/// reporting-body prefix and a software version number other than the
/// reserved `99`.
pub(crate) fn valid_imeisv(s: &str) -> bool {
    digits_of::<16>(s).is_some_and(|d| known_reporting_body(&d) && &d[14..] != b"99")
}

/// The cue-gated forms (module doc): 15 digits with a Luhn check digit and
/// any prefix, or a structurally valid 16-digit IMEISV.
fn valid_cued_imei(s: &str) -> bool {
    digits_of::<15>(s).is_some_and(|d| luhn_valid(&d)) || valid_imeisv(s)
}

/// The cue that unlocks [`cued_rule`] (normalized form; it is also the
/// start of "imeisv" and "imei sv").
const CUES: &[&str] = &["imei"];

/// The 15-digit IMEI, cue-less (module doc).
///
/// IMEI is top tier (it must outrank the card rule), and a top-tier span
/// wins every overlap, so it must never be a fragment of a larger entity.
/// The match therefore takes the whole token around the digits (letters,
/// `@`, `/`, `_` included; whitespace, sentence punctuation and `=` end
/// it) and the validator accepts only digits with field separators: a run
/// inside an e-mail local part (`user351524205681913@x.com`, never
/// `user[IMEI]@x.com`), a URL path or an
/// alphanumeric token comes with its letters and is rejected. The same
/// token makes a longer digit run one candidate (rejected by length). An
/// optional `1-3 digits + [.,]` in front takes the integer part of a
/// decimal number into the match, so its fraction (`0.351524205681913`)
/// is rejected too.
///
/// Without lookarounds the pattern runs on the regex crate's automata
/// instead of the fancy-regex backtracker, so a long hostile line has no
/// backtrack budget to exhaust.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Imei,
        concat!(
            r"(?:[0-9]{1,3}[.,])?",
            token_rest!(),
            r"[0-9]{2}(?:[0-9]{13}|[0-9]{6}[ -][0-9]{6}[ -][0-9]|[ -][0-9]{6}[ -][0-9]{6}[ -][0-9])",
            token_rest!()
        ),
        Some(valid_imei),
        ContextPolicy::None,
        1.0
    )
}

/// The 15-digit IMEI with any prefix and the 16-digit IMEISV, only next to
/// an "imei" cue (module doc). Score 0.9: a cue plus a Luhn digit without
/// the reporting-body structure, or the IMEISV structure without any check
/// digit. Whole token as in [`rule`].
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn cued_rule() -> Rule {
    rule!(
        id = "imei_cued",
        EntityType::Imei,
        concat!(
            r"(?:[0-9]{1,3}[.,])?",
            token_rest!(),
            r"[0-9]{2}(?:[0-9]{13,14}|[0-9]{6}[ -][0-9]{6}[ -][0-9]{1,2}|[ -][0-9]{6}[ -][0-9]{6}[ -][0-9]{1,2})",
            token_rest!()
        ),
        Some(valid_cued_imei),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::{valid_imei, valid_imeisv, REPORTING_BODIES};
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn reporting_bodies_are_sorted_for_binary_search() {
        assert!(REPORTING_BODIES.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn imei_validator_table() {
        for (s, ok) in [
            // nm-kvkk-pii-6K device identifiers (TÜV SÜD 35, TAF 86)
            ("351524205681913", true),
            ("867236052295187", true),
            ("35-152420-568191-3", true),
            ("35152420 568191 3", true),
            ("351524205681914", false), // check digit
            ("286014552090041", false), // Luhn-valid, 28 is no reporting body
            ("001524205681917", false), // Luhn-valid test identifier 00
            ("35152420568191", false),  // 14 digits
            ("35152420_568191_3", false),
        ] {
            assert_eq!(valid_imei(s), ok, "{s}");
        }
    }

    #[test]
    fn imeisv_validator_table() {
        assert!(valid_imeisv("3515242056819100"));
        assert!(valid_imeisv("35 152420 568191 98"));
        assert!(!valid_imeisv("3515242056819199")); // SVN 99 reserved
        assert!(!valid_imeisv("2815242056819100")); // no reporting body
    }

    fn imeis(text: &str) -> Vec<String> {
        engine_detect(text, &["tr", "en"])
            .into_iter()
            .filter(|e| e.kind == EntityType::Imei)
            .map(|e| e.text)
            .collect()
    }

    #[test]
    fn imei_outranks_the_card_rule() {
        let ents = engine_detect("Cihaz kimliği: 351524205681913", &["tr"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::Imei);
        assert_eq!(imeis("cihaz 867236055436929 numarası"), ["867236055436929"]);
        // the fraction of a decimal number is no IMEI
        assert!(imeis("oran 0.351524205681913").is_empty());
        assert!(imeis("oran 1234,351524205681913").is_empty());
        // a list of IMEIs: each one
        assert_eq!(
            imeis("cihazlar 351524205681913,867236055436929"),
            ["351524205681913", "867236055436929"]
        );
        // `key=value`
        assert_eq!(imeis("device imei=351524205681913 ok"), ["351524205681913"]);
    }

    #[test]
    fn imei_never_takes_digits_out_of_an_email_a_url_or_a_token() {
        for (text, kind, whole) in [
            (
                "user351524205681913@x.com",
                EntityType::Email,
                "user351524205681913@x.com",
            ),
            (
                "IMEI: user351524205681913@x.com",
                EntityType::Email,
                "user351524205681913@x.com",
            ),
            (
                "351524205681913@x.com",
                EntityType::Email,
                "351524205681913@x.com",
            ),
            (
                "https://x.com/d/351524205681913/info",
                EntityType::Url,
                "https://x.com/d/351524205681913/info",
            ),
        ] {
            let got: Vec<(EntityType, String)> = engine_detect(text, &["tr", "en"])
                .into_iter()
                .map(|e| (e.kind, e.text))
                .collect();
            assert_eq!(got, vec![(kind, whole.to_owned())], "{text}");
        }
        for text in [
            "SN A351524205681913",
            "kod 351524205681913B",
            "1351524205681913",
        ] {
            assert!(imeis(text).is_empty(), "{text}: {:?}", imeis(text));
        }
    }

    #[test]
    fn an_imei_cue_lifts_the_reporting_body_check() {
        assert_eq!(
            imeis("IMEI numarası 437905244025352, mobil"),
            ["437905244025352"]
        );
        assert!(imeis("numara 437905244025352").is_empty());
        // the check digit stays
        assert!(imeis("IMEI: 437905244025353").is_empty());
    }

    #[test]
    fn imeisv_needs_its_cue() {
        assert_eq!(imeis("IMEISV: 3515242056819100"), ["3515242056819100"]);
        assert!(imeis("ref 3515242056819100").is_empty());
    }

    #[test]
    fn long_hostile_lines_complete_within_the_backtrack_budget() {
        for r in [super::rule(), super::cued_rule()] {
            for unit in ["a", "a:", "1", "1 ", "1-", "0.", "a1"] {
                let text = unit.repeat(200_000 / unit.len());
                assert!(
                    r.regex.find_iter(&text).all(|m| m.is_ok()),
                    "{} on {unit:?}",
                    r.id
                );
            }
        }
    }
}
