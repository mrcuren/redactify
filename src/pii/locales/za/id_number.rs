//! South African identity number: validator + rule.
//!
//! Official sources:
//!
//! 1. Identification Regulations, 1998 (GN R.978, GG 19098, 31 July 1998),
//!    regulation 3 as amended by GN R.275 (GG 21015, 1 April 2000)
//!    (Acts Online republication),
//!    <https://www.acts.co.za/identification-act-1997/r978_3__identity_number.php>
//!    (retrieved 2026-10-30): "The identity number referred to in section 7
//!    shall consist of 13 digits ... (a) the first six digits shall
//!    represent the date of birth of the person as follows: Digits 1 and
//!    2, the year of birth; digits 3 and 4 the month of birth; and digits
//!    5 and 6, the day of birth; (b) digit 7 shall indicate the gender ...;
//!    (c) digits 8 to 10, inclusive, shall represent a serial number; (d)
//!    digit 11 shall represent the citizen of the person as follows: S A
//!    Citizen 0, Non-SA Citizen 1; (e) digit 12 shall represent the index
//!    number 8 ... the 12th digit would be number 9; and (f) digit 13
//!    shall be a control figure determined by the computer."
//! 2. South African Revenue Service, PAYE Employer Reconciliation BRS
//!    V21.2 (Oct-22, "Official Publication"),
//!    <https://www.sars.gov.za/sars_paye_brs-paye-employer-reconciliation_v21-2>,
//!    Appendix B 8.3 "Modulus 13 check on ID Number" (retrieved
//!    2026-10-30), worked on the example "800101 5009 087": "a. Add all
//!    the digits in the odd positions (excluding last digit). ... b. Move
//!    the even positions into a field and multiply the number by 2. ... c.
//!    Add the digits of the result in b). ... d. Add the answer in [2] to
//!    the answer in [1]. ... e. Subtract the second digit (i.e. 3) from
//!    10. The number must tally with the last number in the ID Number. If
//!    the result is 2 digits, the last digit is used". This computation is
//!    the Luhn check: doubling the number formed by the even-position
//!    digits and summing the digits of the product equals doubling each
//!    digit and subtracting 9 from every product above 9 (a carry out of
//!    a digit of 5 or more lowers the digit sum by exactly 9, and a digit
//!    below 5 never produces a carry); the research run found 0
//!    disagreements over 200,000 random 13-digit values.
//! 3. SARS, "South Africa - Information on Tax Identification Numbers"
//!    (country sheet published on the OECD AEOI portal, 2020),
//!    <https://www.oecd.org/content/dam/oecd/en/topics/policy-issue-focus/aeoi/south-africa-tin.pdf>,
//!    Appendix II (retrieved 2026-10-30): "The next digit (C) indicates
//!    the South African citizen status with 0 denoting South African
//!    Citizen. 1 denoting permanent resident and 2 denoting refugee. ...
//!    The last digit (Z) is a checksum digit ... called the Luhn
//!    algorithm."
//!
//! The validator checks 13 digits (spaces ignored, as in the SARS example
//! spelling `800101 5009 087`), a real calendar date `YYMMDD` (the century
//! is not encoded: 29 February is accepted for every year divisible by
//! four), digit 11 in {0, 1, 2} (regulation 3(d) plus the refugee value of
//! the SARS sheet) and the Luhn control figure. Digit 12 is not restricted
//! (SARS IT3s BRS Appendix J: "Usually 8, or 9 [can be other values]").
//! A future birth date is not rejected: the engine reads no clock.
//!
//! Cue policy: none, score 1.0 (checksum verified). The always-on card
//! rule already claims every Luhn-passing 13-digit run without a cue; this
//! rule adds the date and citizenship checks on top and gives such a run
//! its correct label when the `za` pack is enabled.
//!
//! Priority: tier 0 (CN_RESIDENT_ID precedent) so the label beats the
//! card rule on the same span. The `kr` and `th` packs, whose cue-gated
//! 13-digit rules share tier 0, are registered before `za`.

use crate::pii::entity::EntityType;
use crate::pii::locales::{
    code_chars, days_in_month, is_leap_two_digit_year, luhn_valid, rule, two_digits, ContextPolicy,
    Rule,
};

/// Returns `true` if `id` is a valid South African identity number: 13
/// digits (spaces ignored), a real calendar birth date `YYMMDD`, a
/// citizenship digit (11th) of 0, 1 or 2 and a valid Luhn control figure
/// (the SARS "modulus 13" computation).
///
/// # Examples
/// ```
/// use redactify::valid_za_id_number;
/// assert!(valid_za_id_number("8001015009087")); // SARS example
/// assert!(valid_za_id_number("800101 5009 087"));
/// assert!(!valid_za_id_number("8001015009088")); // control figure off
/// assert!(!valid_za_id_number("8002305009084")); // 30 February
/// assert!(!valid_za_id_number("8001015009384")); // citizenship digit 3
/// ```
#[must_use]
pub fn valid_za_id_number(id: &str) -> bool {
    let Some(d) = code_chars::<13>(id, u8::is_ascii_digit, b" ") else {
        return false;
    };
    let yy = two_digits(&d[0..2]);
    let month = two_digits(&d[2..4]);
    let day = two_digits(&d[4..6]);
    day >= 1
        && day <= days_in_month(month, is_leap_two_digit_year(yy))
        && matches!(d[10], b'0'..=b'2')
        && luhn_valid(&d)
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::ZaIdNumber,
        r"(?<!\d)\d{6} ?\d{4} ?\d{3}(?!\d)",
        Some(valid_za_id_number),
        ContextPolicy::None,
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_za_id_number;
    use crate::pii::detect::engine_detect;
    use crate::pii::locales::luhn_valid;
    use crate::EntityType;

    /// The SARS BRS 8.3 steps, transcribed literally (odd positions
    /// summed, even positions read as one number and doubled, digits of
    /// the product summed, 10 minus the last digit of the total).
    fn sars_modulus_13(id: &str) -> bool {
        let d: Vec<u32> = id.bytes().map(|b| u32::from(b - b'0')).collect();
        let odd: u32 = d.iter().take(12).step_by(2).sum();
        let even: u64 = d
            .iter()
            .skip(1)
            .take(12)
            .step_by(2)
            .fold(0, |n, &x| n * 10 + u64::from(x));
        let doubled: u32 = (even * 2)
            .to_string()
            .bytes()
            .map(|b| u32::from(b - b'0'))
            .sum();
        (10 - (odd + doubled) % 10) % 10 == d[12]
    }

    #[test]
    fn sars_steps_equal_luhn() {
        // the SARS worked example: 13 + 20 = 33, 10 - 3 = 7
        assert!(sars_modulus_13("8001015009087"));
        // deterministic sweep (multiplicative walk over 13-digit values)
        let mut x: u64 = 1_000_000_000_007;
        for _ in 0..20_000 {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1) % 10_000_000_000_000;
            let s = format!("{x:013}");
            assert_eq!(sars_modulus_13(&s), luhn_valid(s.as_bytes()), "{s}");
        }
    }

    #[test]
    fn date_citizenship_and_control_figure() {
        for v in [
            "8001015009087",
            "800101 5009 087",
            "0002295009084",
            "9602295009082",
        ] {
            assert!(valid_za_id_number(v), "{v}");
        }
        for v in [
            "8001015009088",   // control figure
            "8002305009084",   // 30 February, Luhn passes
            "8001015009384",   // citizenship 3, Luhn passes
            "8013015009082",   // month 13, Luhn passes
            "8702295009081",   // 29 February of a year never leap, Luhn passes
            "800101500908",    // 12 digits
            "800101-5009-087", // foreign separator
        ] {
            assert!(!valid_za_id_number(v), "{v}");
        }
        assert!(luhn_valid(b"8002305009084") && luhn_valid(b"8001015009384"));
    }

    #[test]
    fn cue_less_and_outranks_the_card_rule() {
        for text in ["client 8001015009087 on file", "ID 800101 5009 087"] {
            let ents = engine_detect(text, &["za"]);
            assert_eq!(ents.len(), 1, "{text}: {ents:?}");
            assert_eq!(ents[0].kind, EntityType::ZaIdNumber);
            assert!((ents[0].score - 1.0).abs() < f32::EPSILON);
        }
        // without the pack the same value is masked by the card rule
        let card = engine_detect("client 8001015009087 on file", &[]);
        assert_eq!(card.len(), 1, "{card:?}");
        assert_eq!(card[0].kind, EntityType::CreditCard);
        // a Luhn-passing run with an impossible date stays a card number
        let other = engine_detect("client 8002305009084 on file", &["za"]);
        assert_eq!(other.len(), 1, "{other:?}");
        assert_eq!(other[0].kind, EntityType::CreditCard);
    }
}
