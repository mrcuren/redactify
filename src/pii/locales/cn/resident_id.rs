//! Chinese citizen identification number (公民身份号码, the number printed
//! on the resident identity card): validator + rule.
//!
//! Official source (retrieved 2026-10-29): national standard GB 11643-1999
//! "公民身份号码 / Citizen identification number" (approved 1999-01-19,
//! implemented 1999-07-01, replaces GB 11643-1989), full text hosted by the
//! Beijing Municipal Commission of Housing and Urban-Rural Development:
//! <https://zjw.beijing.gov.cn/Portals/0/zhuanti/fazhan/%E8%BA%AB%E4%BB%BD%E8%AF%81GB11643-1999.pdf>.
//!
//! - 5.1: "公民身份号码是特征组合码，由十七位数字本体码和一位数字校验码组成。
//!   排列顺序从左至右依次为：六位数字地址码，八位数字出生日期码，三位数字顺序码和
//!   一位数字校验码。" (17-digit master number + 1 check character: 6-digit
//!   address code, 8-digit birth-date code, 3-digit sequence code.)
//! - 5.1.2: "表示编码对象出生的年、月、日，按GB/T 7408的规定执行。年、月、日代码
//!   之间不用分隔符。" (birth year, month and day, YYYYMMDD, no separators.)
//! - 5.1.4: "校验码采用 ISO 7064:1983,MOD 11-2校验码系统。" 5.1.4.1, formula
//!   (1): sum over i = 1..18 of (a_i x W_i) ≡ 1 (mod 11), i counted from the
//!   right including the check character, W_i = 2^(i-1) (mod 11); table 1
//!   lists W_18..W_2 = 7 9 10 5 8 4 2 1 6 3 7 9 10 5 8 4 2 and W_1 = 1.
//!   5.1.4.2: "当a1值等于10时，用罗马数字符 X表示。" (a check value of 10
//!   is written as the Roman numeral X.)
//! - 5.2: "公民身份号码的各特征码依次连接，不留空格" (codes concatenated, no
//!   spaces).
//! - Annex A worked examples: `11010519491231002X` (Beijing, born
//!   1949-12-31) and `440524188001010014` (Guangdong, born 1880-01-01);
//!   Annex B recomputes both check characters (sums 167 -> X, 195 -> 4).
//!
//! Deliberate precision bound (derived, not a format claim): the birth year
//! must lie in 1800-2099. The standard's own examples span 1880-1966, a
//! citizen issued a number under the 1999 standard cannot be born before
//! 1800, and 2100 is in the future. Measured on 2,000,000 random 18-digit
//! strings: 0.331% pass the checksum + calendar date with any year,
//! 0.0108% with the 1800-2099 bound. The address code is NOT checked
//! against GB/T 2260 (the region table was not retrieved).
//!
//! Cue policy: none (claimed cue-less at 1.0): the MOD 11-2 check plus the
//! embedded calendar date reject ~99.99% of random 18-digit runs.
//! Collision analysis vs 18-19 digit cards (the generic card rule accepts
//! 13-19 digits): ~10.0% of valid digit-final resident IDs also pass Luhn
//! (measured on 200,000 generated IDs), so the resident ID shares the top
//! priority tier with IBAN/NIR (a cue-less Luhn claim must not relabel
//! it); conversely only 0.0105% of Luhn-valid 18-digit numbers pass this
//! validator, and 19-digit cards never match the 18-character shape.

use crate::pii::entity::EntityType;

use crate::pii::locales::{days_in_month, is_leap_year, rule, two_digits, ContextPolicy, Rule};

/// GB 11643-1999 table 1: weights W_18..W_2 for the 17 master digits
/// (left to right); the check character carries W_1 = 1.
const WEIGHTS: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];

/// Returns `true` if `id` is a valid Chinese citizen identification number
/// (GB 11643-1999): 17 digits + a check character `0`-`9` or uppercase
/// `X`, an embedded real calendar birth date `YYYYMMDD` (positions 7-14,
/// year 1800-2099) and the ISO 7064 MOD 11-2 relation
/// `sum(a_i * W_i) ≡ 1 (mod 11)` with `X` = 10.
///
/// # Examples
/// ```
/// use redactify::valid_cn_resident_id;
/// assert!(valid_cn_resident_id("11010519491231002X")); // GB 11643 annex A1
/// assert!(valid_cn_resident_id("440524188001010014")); // annex A2
/// assert!(!valid_cn_resident_id("110105194912310021")); // check char off
/// assert!(!valid_cn_resident_id("11010519491231002x")); // X is uppercase
/// ```
#[must_use]
pub fn valid_cn_resident_id(id: &str) -> bool {
    let b = id.as_bytes();
    if b.len() != 18 || !b[..17].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let check = match b[17] {
        c @ b'0'..=b'9' => u32::from(c - b'0'),
        b'X' => 10,
        _ => return false,
    };
    let year = two_digits(&b[6..8]) * 100 + two_digits(&b[8..10]);
    let month = two_digits(&b[10..12]);
    let day = two_digits(&b[12..14]);
    if !(1800..=2099).contains(&year) || day == 0 || day > days_in_month(month, is_leap_year(year))
    {
        return false;
    }
    let sum: u32 = b[..17]
        .iter()
        .zip(WEIGHTS)
        .map(|(&c, w)| u32::from(c - b'0') * w)
        .sum();
    // formula (1): the check character enters with weight W_1 = 1
    (sum + check) % 11 == 1
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::CnResidentId,
        r"(?<![0-9A-Za-z])\d{17}[0-9X](?![0-9A-Za-z])",
        Some(valid_cn_resident_id),
        ContextPolicy::None,
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::{valid_cn_resident_id, WEIGHTS};
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn weights_follow_the_standard_formula() {
        // W_i = 2^(i-1) mod 11 for i = 18..2 (left to right)
        for (k, &w) in WEIGHTS.iter().enumerate() {
            let i = 18 - k as u32;
            assert_eq!(w, 2u32.pow(i - 1) % 11, "position {i}");
        }
    }

    #[test]
    fn annex_examples_and_corruptions() {
        assert!(valid_cn_resident_id("11010519491231002X"));
        assert!(valid_cn_resident_id("440524188001010014"));
        // annex B sums
        let sum = |s: &str| -> u32 {
            s.bytes()
                .zip(WEIGHTS)
                .map(|(c, w)| u32::from(c - b'0') * w)
                .sum()
        };
        assert_eq!(sum("11010519491231002"), 167);
        assert_eq!(sum("44052418800101001"), 195);
        // corrupted check character / digit
        assert!(!valid_cn_resident_id("110105194912310029"));
        assert!(!valid_cn_resident_id("440524188001010015"));
        assert!(!valid_cn_resident_id("440524188001010024"));
        // leap-day birth dates: 1980-02-29 ok, 1900-02-29 impossible
        assert!(valid_cn_resident_id("320106198002291230"));
        assert!(valid_cn_resident_id("110101200002290018"));
        // (check character computed valid: only the date rule rejects it)
        assert!(!valid_cn_resident_id("110101190002290011"));
        // month 13 / day 32 / year outside 1800-2099, even with a valid check
        for body in [
            "11010519491331002",
            "11010519491232002",
            "11010517991231002",
            "11010521001231002",
        ] {
            for c in "0123456789X".chars() {
                assert!(!valid_cn_resident_id(&format!("{body}{c}")), "{body}{c}");
            }
        }
        // shape errors
        assert!(!valid_cn_resident_id("11010519491231002"));
        assert!(!valid_cn_resident_id("11010519491231002XX"));
        assert!(!valid_cn_resident_id("1101051949123100AX"));
    }

    #[test]
    fn cue_less_claim_outranks_a_luhn_card_reading() {
        // annex A2 also passes Luhn: tier 0 keeps the resident-ID label
        assert!(crate::valid_luhn("440524188001010014"));
        let ents = engine_detect("身份号码 440524188001010014", &["cn"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::CnResidentId);
        let ents = engine_detect("id 11010519491231002X ok", &["cn"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::CnResidentId);
        // embedded in a longer alphanumeric token: not claimed
        assert!(engine_detect("ref A11010519491231002X", &["cn"]).is_empty());
    }
}
