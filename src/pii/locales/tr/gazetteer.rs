//! Turkish province/district gazetteer: name folding, the allocation-free
//! lookup used by the address and place-of-birth validators, and the regex
//! alternation of the address rule's trailing locality.
//!
//! The name table itself is generated ([`super::places::PLACES`], 81
//! provinces and 973 districts from the MIT-licensed `turkiye-api`
//! datasets; source, commit and SHA-256 in that module and in
//! `data/tr_places.SOURCES.md`).

use std::sync::LazyLock;

use super::places::PLACES;

/// The folded form of one character: Turkish letters map to their ASCII
/// base letter (`İ I ı i î -> i`, `ş -> s`, `ç -> c`, `ğ -> g`, `ö -> o`,
/// `ü û -> u`, `â -> a`), ASCII letters to lowercase, the combining dot
/// above (U+0307, what lowercasing `İ` leaves behind) to nothing; every
/// other character is kept (lowercased).
fn fold_char(c: char, out: &mut String) {
    match turkish_base(c) {
        Some(base) => out.push(base),
        None if c == '\u{0307}' => {}
        None => out.extend(c.to_lowercase()),
    }
}

/// The ASCII base letter of a Turkish letter with a diacritic or a
/// Turkish-specific case form (`İ I ı î -> i`, ...), `None` otherwise.
const fn turkish_base(c: char) -> Option<char> {
    match c {
        'İ' | 'I' | 'ı' | 'î' | 'Î' => Some('i'),
        'Ş' | 'ş' => Some('s'),
        'Ç' | 'ç' => Some('c'),
        'Ğ' | 'ğ' => Some('g'),
        'Ö' | 'ö' => Some('o'),
        'Ü' | 'ü' | 'û' | 'Û' => Some('u'),
        'Â' | 'â' => Some('a'),
        _ => None,
    }
}

/// Longest folded key in [`PLACES`], in bytes (`mustafakemalpasa`; checked
/// by a test).
const MAX_PLACE_LEN: usize = 16;

/// Folds `s` for case- and diacritic-insensitive comparison of Turkish
/// words (see [`fold_char`]): `"İZMİR"`, `"İzmir"` and `"Izmir"` all fold
/// to `"izmir"`. The generator of [`PLACES`] applies the same mapping.
pub(super) fn fold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        fold_char(c, &mut out);
    }
    out
}

/// Whether `name` (one or more words separated by whitespace, in any case,
/// with or without Turkish diacritics) is a province or district.
///
/// Allocation-free: the name is folded (as [`fold`] does, whitespace runs
/// collapsed to one space) into a stack buffer of [`MAX_PLACE_LEN`] bytes;
/// a longer name or any character outside the folded ASCII alphabet ends
/// the lookup early. It runs once per capitalized word of the scanned
/// text (the place-of-birth validator), so it must stay cheap.
pub(super) fn is_place(name: &str) -> bool {
    let mut buf = [0u8; MAX_PLACE_LEN];
    let mut n = 0usize;
    let mut gap = false;
    for c in name.chars() {
        let folded = match turkish_base(c) {
            Some(base) => base,
            None if c == '\u{0307}' => continue,
            None if c.is_whitespace() => {
                gap = n > 0;
                continue;
            }
            None if c.is_ascii_alphanumeric() => c.to_ascii_lowercase(),
            None => return false,
        };
        for b in gap.then_some(b' ').into_iter().chain([folded as u8]) {
            let Some(slot) = buf.get_mut(n) else {
                return false;
            };
            *slot = b;
            n += 1;
        }
        gap = false;
    }
    std::str::from_utf8(&buf[..n]).is_ok_and(|key| PLACES.binary_search(&key).is_ok())
}

/// The character class that matches every spelling of the folded letter
/// `c` the pattern accepts: the Turkish letter and its ASCII base in both
/// cases (`i` covers `i ı İ I`), uppercase only for the first letter.
fn push_class(c: char, first: bool, out: &mut String) {
    let variants: &str = match (c, first) {
        ('i', true) => "İI",
        ('i', false) => "iıİI",
        ('s', true) => "SŞ",
        ('s', false) => "sşSŞ",
        ('c', true) => "CÇ",
        ('c', false) => "cçCÇ",
        ('g', true) => "GĞ",
        ('g', false) => "gğGĞ",
        ('o', true) => "OÖ",
        ('o', false) => "oöOÖ",
        ('u', true) => "UÜÛ",
        ('u', false) => "uüûUÜÛ",
        ('a', true) => "AÂ",
        ('a', false) => "aâAÂ",
        (' ', _) => {
            out.push_str(r"\s+");
            return;
        }
        (d, _) if d.is_ascii_digit() => {
            out.push(d);
            return;
        }
        (l, true) => {
            out.push(l.to_ascii_uppercase());
            return;
        }
        (l, false) => {
            out.push('[');
            out.push(l);
            out.push(l.to_ascii_uppercase());
            out.push(']');
            return;
        }
    };
    out.push('[');
    out.push_str(variants);
    out.push(']');
}

/// A regex group (`(?:...)`, no capture, no look-around) matching any
/// gazetteer name with an uppercase first letter, in title case, upper
/// case or ASCII-folded spelling (`İzmir`, `İZMİR`, `Izmir`). Longer
/// names come first, so the leftmost-first alternation prefers
/// `Merkezefendi` over its prefix `Merkez`. Built once (about 1,000
/// alternatives).
pub(super) static PLACE_PATTERN: LazyLock<String> = LazyLock::new(|| {
    let mut names: Vec<&str> = PLACES.to_vec();
    names.sort_by(|a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
    let mut out = String::with_capacity(PLACES.len() * 40);
    out.push_str("(?:");
    for (i, name) in names.iter().enumerate() {
        if i > 0 {
            out.push('|');
        }
        let mut first = true;
        for c in name.chars() {
            push_class(c, first, &mut out);
            first = c == ' ';
        }
    }
    out.push(')');
    out
});

#[cfg(test)]
mod tests {
    use super::{fold, is_place, PLACES, PLACE_PATTERN};

    #[test]
    fn table_is_sorted_unique_and_folded() {
        assert!(PLACES.windows(2).all(|w| w[0] < w[1]), "sorted + unique");
        assert_eq!(
            PLACES.iter().map(|p| p.len()).max(),
            Some(super::MAX_PLACE_LEN)
        );
        for p in PLACES {
            assert_eq!(fold(p), *p, "{p} is already folded");
        }
        // 81 provinces + 973 districts, minus names shared after folding
        // (51 districts are called "Merkez")
        assert_eq!(PLACES.len(), 979);
    }

    #[test]
    fn provinces_and_districts_in_any_spelling() {
        for name in [
            "İzmir",
            "İZMİR",
            "Izmir",
            "izmir",
            "Kahramanmaraş",
            "Şanlıurfa",
            "SANLIURFA",
            "Çiğli",
            "Kınık",
            "Şereflikoçhisar",
            "19 Mayıs",
            "19  MAYIS",
            "Merkez",
            "Merkezefendi",
        ] {
            assert!(is_place(name), "{name}");
        }
        for name in ["Ahmet", "Teslimat", "Adres", "Mahallesi", "", "İzmirli"] {
            assert!(!is_place(name), "{name}");
        }
    }

    #[test]
    fn pattern_matches_whole_names_only_in_accepted_spellings() {
        let re = fancy_regex::Regex::new(&format!("^{}$", *PLACE_PATTERN)).expect("compiles");
        let is_match = |s: &str| re.is_match(s).expect("no backtracking");
        for ok in [
            "İzmir",
            "İZMİR",
            "Izmir",
            "Kınık",
            "KINIK",
            "Kinik",
            "19 Mayıs",
            "Bornova",
        ] {
            assert!(is_match(ok), "{ok}");
        }
        // lowercase first letter, unknown names
        for no in ["izmir", "Ahmet", "Izmirli", ""] {
            assert!(!is_match(no), "{no}");
        }
    }
}
