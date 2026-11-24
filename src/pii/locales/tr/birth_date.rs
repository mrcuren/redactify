//! Date of birth: calendar-validated date + mandatory birth cue.
//!
//! Format only: a date carries no checksum and most dates in a document
//! are not birth dates (issue dates, deadlines, timestamps), so a date is
//! claimed only next to a birth cue (`Doğum tarihi:`, `doğum tarihi
//! 02.06.1972 olarak`, `12.03.1985 doğumlu`). Accepted spellings: the
//! numeric Turkish form `GG.AA.YYYY` (also with `/` or `-` as separator,
//! one separator kind per date), ISO 8601 `YYYY-AA-GG`, and the written
//! form `15 Mayıs 1985` with a Turkish month name (in any case, with or
//! without diacritics). The date must exist in the Gregorian calendar
//! (leap years included) and the year must lie in 1900-2099; a
//! slash-separated date whose first two fields only form a date in
//! month-first order (`06/15/2004`, the US order) is accepted as well.
//!
//! The pattern matches whole digit runs and whole words (leftmost-first,
//! greedy) and the validator checks the field lengths, so it needs no
//! look-around and no word-boundary assertion and runs on the regex
//! engine's DFA path. Look-around guards exhausted the backtracking budget
//! on a 200,000-character line of `1 ` (tests in `super`); a Unicode `\b`
//! makes the DFA give up on Turkish text (cost note in [`super::address`]).

use crate::pii::entity::EntityType;

use super::gazetteer::fold;
use crate::pii::locales::{days_in_month, is_leap_year, rule, ContextPolicy, Rule};

/// Birth cues (normalized: lowercase, `ı -> i`). `doğum` also covers
/// `doğumlu` after the date and `Doğum Tarihi` before it; `doğmuş` /
/// `doğdu` cover `... tarihinde doğmuş`. The English labels of
/// bilingual forms are cues too (numeric dates only).
///
/// Form labels: a cue unlocks a value when it ENDS at most `CUE_WINDOW`
/// (18) characters before it, so the longer labels of printed forms are
/// cues of their own, each ending right before its value: `Doğum Yeri ve Tarihi: Erzurum, 12.03.1985`, `Doğum
/// Yeri/Tarihi: Erzurum / 12.03.1985`, `Doğum Tarihi (gün/ay/yıl):
/// 12.03.1985` (the cue ends at the opening parenthesis, so any short
/// format hint fits) and dot leaders of up to 16 characters after `Doğum
/// tarihi`. The global window stays as it is; a longer leader or a long
/// place name between label and date is still missed.
pub(super) const CUES: &[&str] = &[
    "doğum",
    "dogum",
    "doğum tarihi",
    "dogum tarihi",
    "doğum tarihi (",
    "dogum tarihi (",
    "doğum yeri ve tarihi",
    "dogum yeri ve tarihi",
    "doğum yeri/tarihi",
    "dogum yeri/tarihi",
    "doğum yeri / tarihi",
    "dogum yeri / tarihi",
    "doğmuş",
    "dogmus",
    "doğdu",
    "dogdu",
    "d. tarihi",
    "d.tarihi",
    "doğ. tar",
    "dog. tar",
    "date of birth",
    "dateofbirth",
    "birth date",
    "birthdate",
    "dob",
];

/// Turkish month names, folded (see [`fold`]), January first.
const MONTHS: [&str; 12] = [
    "ocak", "subat", "mart", "nisan", "mayis", "haziran", "temmuz", "agustos", "eylul", "ekim",
    "kasim", "aralik",
];

/// Whether `day`/`month`/`year` is a real date with a year in 1900-2099.
fn real_date(day: u32, month: u32, year: u32) -> bool {
    (1900..=2099).contains(&year) && day >= 1 && day <= days_in_month(month, is_leap_year(year))
}

/// Parses an ASCII digit run of 1-4 digits.
fn number(s: &str) -> Option<u32> {
    (!s.is_empty() && s.len() <= 4 && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.bytes().fold(0, |n, b| n * 10 + u32::from(b - b'0')))
}

/// Returns `true` if `s` is a real calendar date in one of the accepted
/// spellings (module docs).
#[must_use]
pub(crate) fn valid_birth_date(s: &str) -> bool {
    // written form: `15 Mayıs 1985`
    let words: Vec<&str> = s.split_whitespace().collect();
    if let [day, month, year] = words.as_slice() {
        let folded = fold(month);
        return match (
            number(day),
            MONTHS.iter().position(|m| *m == folded),
            number(year),
        ) {
            (Some(d), Some(m), Some(y)) if day.len() <= 2 && year.len() == 4 => {
                real_date(d, u32::try_from(m).map_or(0, |m| m + 1), y)
            }
            _ => false,
        };
    }
    let Some(sep) = s.bytes().find(|b| matches!(b, b'.' | b'/' | b'-')) else {
        return false;
    };
    let parts: Vec<&str> = s.split(char::from(sep)).collect();
    let [a, b, c] = parts.as_slice() else {
        return false;
    };
    let (Some(a_n), Some(b_n), Some(c_n)) = (number(a), number(b), number(c)) else {
        return false;
    };
    if a.len() == 4 {
        // ISO 8601 `YYYY-MM-DD`
        return sep == b'-' && b.len() == 2 && c.len() == 2 && real_date(c_n, b_n, a_n);
    }
    a.len() <= 2
        && b.len() <= 2
        && c.len() == 4
        && (real_date(a_n, b_n, c_n) || (sep == b'/' && real_date(b_n, a_n, c_n)))
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    // whole digit runs and whole words (leftmost-first + greedy), lengths
    // checked by the validator: no boundary assertion needed (module docs)
    rule!(
        EntityType::DateOfBirth,
        concat!(
            r"[0-9]+(?:\.[0-9]+\.|/[0-9]+/|-[0-9]+-)[0-9]+",
            r"|[0-9]+\s+(?:[Oo]cak|OCAK|[ŞşSs]ubat|[ŞS]UBAT|[Mm]art|MART|[Nn]isan|N[İI]SAN",
            r"|[Mm]ay[ıi]s|MAYIS|[Hh]aziran|HAZ[İI]RAN|[Tt]emmuz|TEMMUZ|[Aa][ğg]ustos|A[ĞG]USTOS",
            r"|[Ee]yl[üu]l|EYL[ÜU]L|[Ee]kim|EK[İI]M|[Kk]as[ıi]m|KASIM|[Aa]ral[ıi]k|ARALIK)",
            r"\p{L}*\s+[0-9]+"
        ),
        Some(valid_birth_date),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_birth_date;
    use crate::pii::entity::EntityType;

    fn births(text: &str) -> Vec<String> {
        crate::pii::detect::engine_detect(text, &["tr"])
            .into_iter()
            .filter(|e| e.kind == EntityType::DateOfBirth)
            .map(|e| e.text)
            .collect()
    }

    #[test]
    fn validator_table() {
        for ok in [
            "18.10.1982",
            "1.2.1990",
            "29.02.2000",
            "29/02/1996",
            "06/15/2004",
            "1985-03-12",
            "15 Mayıs 1985",
            "15 MAYIS 1985",
            "3 subat 1971",
            "31 Aralık 1999",
        ] {
            assert!(valid_birth_date(ok), "{ok}");
        }
        for no in [
            "29.02.1900",
            "31.04.1985",
            "32.01.1985",
            "00.01.1985",
            "12.13.1985",
            "12.03.1899",
            "12.03.2100",
            "12.03-1985",
            "1985.03.12",
            "15 Mayısı 1985",
            "31 Şubat 1985",
            "12.03.85",
            "",
        ] {
            assert!(!valid_birth_date(no), "{no}");
        }
    }

    #[test]
    fn birth_cue_is_required() {
        assert_eq!(births("Doğum Tarihi: 23.06.1971\n"), vec!["23.06.1971"]);
        assert_eq!(
            births("Sigortalının doğum tarihi 16.08.1992 olarak beyan edilmiştir."),
            vec!["16.08.1992"]
        );
        assert_eq!(
            births("Kendisi 12 Mart 1980 doğumludur."),
            vec!["12 Mart 1980"]
        );
        assert_eq!(births("DOĞUM TARİHİ: 1985-03-12"), vec!["1985-03-12"]);
        // dates without a birth cue stay clean
        for text in [
            "Düzenleme Tarihi: 14.02.2025",
            "Bağış Tarihi: 15 Mayıs 2025",
            "Toplantı 12.03.2024 tarihinde yapıldı.",
            "Doğum izni bitti, işe dönüş tarihi uzun bir aradan sonra 01.09.2024 oldu.",
        ] {
            assert!(births(text).is_empty(), "{text}: {:?}", births(text));
        }
    }

    #[test]
    fn form_labels_longer_than_the_window_unlock_their_value() {
        for text in [
            "Doğum Yeri ve Tarihi: Erzurum, 12.03.1985",
            "Doğum Yeri/Tarihi: Erzurum / 12.03.1985",
            "DOĞUM YERİ / TARİHİ: Erzurum / 12.03.1985",
            "Doğum Tarihi (gün/ay/yıl): 12.03.1985",
            "Doğum tarihi (GG.AA.YYYY): 12.03.1985",
            "Doğum tarihi..............: 12.03.1985",
        ] {
            assert_eq!(births(text), vec!["12.03.1985"], "{text}");
        }
        // the same layouts without a birth label stay clean
        for text in [
            "Düzenleme Yeri ve Tarihi: Erzurum, 12.03.2024",
            "Düzenleme Tarihi (gün/ay/yıl): 12.03.2024",
            "Teslim tarihi..............: 12.03.2024",
        ] {
            assert!(births(text).is_empty(), "{text}: {:?}", births(text));
        }
    }
}
