//! Turkish postal address: anchor grammar + province/district gazetteer.
//!
//! Format (no checksum exists): a Turkish address is written as a chain of
//! named units - neighbourhood (`Mahallesi`, `Mah.`), street (`Caddesi`,
//! `Cad.`, `Sokak`, `Sk.`, `Bulvarı`, `Çıkmazı`, `Meydanı`, `Yolu`) -
//! followed by the door number (`No: 12`, `No:47/3`, `28/5`), the flat
//! (`Daire: 3`, `D:14`, `Kat: 6`), the postal code (5 digits) and the
//! district/province (`Çiğli/İzmir`). The unit vocabulary (mahalle,
//! cadde, sokak, bulvar, meydan; il, ilçe, posta kodu as address
//! components) is the one defined by the Adres ve Numaralamaya İlişkin
//! Yönetmelik, Resmî Gazete 2006-07-31, sayı 26245, md. 4 (text read at
//! <https://www.alomaliye.com/2006/07/31/adres-ve-numaralamaya-iliskin-yonetmelik/>,
//! retrieved 2026-11-23). Format only: the rule never checks that the
//! street exists.
//!
//! Policy (precision first; the published heuristic "two anchors, or one
//! anchor + province/district + number", implemented independently):
//!
//! - The pattern needs a named unit (words + neighbourhood/street keyword)
//!   followed by at least one more unit, so a lone `Atatürk Caddesi` or
//!   `Kurtuluş Mahallesi'nde` in prose never matches.
//! - The validator then requires a door or flat number next to a named
//!   unit, or two named units plus a trailing gazetteer locality or postal
//!   code. `Kızılay Mahallesi Atatürk Caddesi'nde yürüdük` stays clean.
//! - The trailing locality is matched against the gazetteer
//!   ([`super::gazetteer`]), so the span stops at the last real district
//!   or province: `... No:5 Kadıköy/İstanbul Telefon: ...` ends at
//!   `İstanbul`.
//!
//! The span covers the whole address, from the first named unit through
//! the postal code / province. A label written without a colon right
//! before the first unit (`Teslimat Adresi Kalemköy Mahallesi ...`) is
//! swallowed into the span (masking stays complete); with a colon it is
//! not.
//!
//! Engine cost: the pattern has no look-around, no back-reference and no
//! word-boundary assertion, so the regex engine runs it on its DFA path
//! on any text. (A Unicode `\b` makes that engine give up on non-ASCII
//! input: with `\b` in these rules, a 200,000-character line of `ü`
//! takes 2.06 s against 0.14 s without the rules.)
//! Word ends are enforced by consuming whole words instead: a keyword
//! stem (`Mah`, `Sok`, ...) takes the rest of its word, a trailing place
//! name likewise, and the validator then classifies whole tokens, so
//! `Mahmut` or `Sokullu` are never keywords and `Ankaralı` is not a place.

use std::sync::LazyLock;

use crate::pii::entity::EntityType;

use super::gazetteer::{fold, is_place, PLACE_PATTERN};
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// A name word of a unit: starts with an uppercase letter, a digit or an
/// opening parenthesis (`Evka 3`, `119/5`, `273.`, `Cumhuriyet-2`,
/// `9sokak`, `20.(220)`, `Tol (muzkent)`, `Ölçü (*)`).
const NAME_WORD: &str = r"[\p{Lu}0-9(][\p{L}\p{M}0-9'’._/()*-]*";

/// Neighbourhood and street keyword stems (mahalle, cadde, sokak, bulvar,
/// çıkmaz, meydan, yol; title, lower and upper case), each followed by
/// the rest of its word and an optional abbreviation dot. Which words are
/// real keywords is decided by [`is_unit_keyword`] on the whole token.
const KEYWORD: &str = concat!(
    r"(?:[Mm]ah|MAH|[Mm]h|MH|[Cc]ad|CAD|[Cc]d|CD|[Ss]ok|SOK|[Ss]k",
    r"|[Bb]ulv|BULV|[Bb]lv|BLV|[Çç]ıkmaz|ÇIKMAZ|[Mm]eydan|MEYDAN|[Yy]olu|YOLU)",
    r"[\p{L}\p{M}]*\.?"
);

/// The address pattern (see the module docs), assembled once.
static PATTERN: LazyLock<String> = LazyLock::new(|| {
    let named = format!(r"{NAME_WORD}(?:\s+{NAME_WORD}){{0,3}}\s+{KEYWORD}");
    // Door and flat numbers are whole digit runs (greedy `[0-9]+`, and
    // whatever follows inside the match is a separator). The `/` of a
    // door/flat pair (`47/3`) takes no spaces: `No: 5 / 4111111111111111`
    // ends at `No: 5` and leaves the card number to its own rule (no
    // spaced pair occurs in the `nm-kvkk-pii-6K` train split).
    let door = r"(?:[Nn]o|NO)\s*[:.]?\s*[0-9]+[A-Za-z]?(?:/[0-9]+[A-Za-z]?)?";
    let bare_door = r"[0-9]+[A-Za-z]?/[0-9]+[A-Za-z]?";
    let flat = r"(?:[Dd]aire|DA[İI]RE|[Kk]at|KAT|[Bb]lok|BLOK|[Dd]\s*:)\s*[:.]?\s*[0-9]+[A-Za-z]?";
    // A Turkish postal code has exactly 5 digits. Without look-around, a
    // 5-digit match is kept from being the first 5 digits of a longer run
    // (a phone, a TCKN) by what must follow it inside the match: a
    // separator and a further unit or place, or the end of the line. An
    // open-ended `[0-9]{5,}` would swallow `05322345678` after `İstanbul`;
    // the phone (or TCKN) would then win the overlap and the whole address
    // would be lost.
    let postal = r"[0-9]{5}";
    let sep = r"(?:\s*[,/]\s*|\s+-\s+|\s+)";
    let place = &*PLACE_PATTERN;
    let unit = format!(r"(?:{named}|{door}|{bare_door}|{flat})");
    format!(
        r"{named}(?:(?:{sep}{postal})?{sep}{unit})+(?:(?:{sep}{postal})?(?:{sep}{place}[\p{{L}}\p{{M}}]*){{1,2}})?(?:{sep}{postal}$)?"
    )
});

/// Is `t` (folded, trailing dot removed) a neighbourhood or street keyword?
fn is_unit_keyword(t: &str) -> bool {
    matches!(
        t,
        "mahallesi"
            | "mahalle"
            | "mah"
            | "mh"
            | "caddesi"
            | "cadde"
            | "cad"
            | "cd"
            | "sokagi"
            | "sokak"
            | "sok"
            | "sk"
            | "bulvari"
            | "bulvar"
            | "bulv"
            | "blv"
            | "cikmazi"
            | "cikmaz"
            | "meydani"
            | "yolu"
    )
}

/// Door/flat label words (folded, trailing `:`/`.` removed).
fn is_door_label(t: &str) -> bool {
    matches!(t, "no" | "daire" | "kat" | "blok" | "d")
}

/// `true` for `12`, `12a`, `47/3`, `28/5b`: a door or flat number.
fn is_number_token(t: &str) -> bool {
    let mut parts = t.split('/');
    let ok = |p: &str| {
        let digits = p.trim_end_matches(|c: char| c.is_ascii_alphabetic());
        !digits.is_empty()
            && digits.len() + 1 >= p.len()
            && digits.bytes().all(|b| b.is_ascii_digit())
    };
    parts.next().is_some_and(ok) && parts.all(ok)
}

/// The validator: a door/flat number next to a named unit, or two named
/// units plus a trailing gazetteer locality or postal code.
fn valid_address(candidate: &str) -> bool {
    let folded = fold(candidate);
    let tokens: Vec<&str> = folded
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|t| !t.is_empty())
        .collect();
    let mut named = 0usize;
    let mut door = false;
    for (i, raw) in tokens.iter().enumerate() {
        let t = raw.trim_end_matches('.');
        if is_unit_keyword(t) {
            named += 1;
            continue;
        }
        // `no:12`, `d:14`, `daire:3`, or `no` / `no:` + `12`
        let (label, rest) = match t.find(|c: char| c == ':' || c == '.' || c.is_ascii_digit()) {
            Some(at) => t.split_at(at),
            None => (t, ""),
        };
        if is_door_label(label) {
            let rest = rest.trim_start_matches([':', '.']);
            let number = if rest.is_empty() {
                tokens.get(i + 1).copied().unwrap_or("")
            } else {
                rest
            };
            if is_number_token(number) {
                door = true;
            }
            continue;
        }
        // a bare `28/5` is a door number unless it names the next street
        // (`119/5 Sk.`)
        if t.contains('/') && is_number_token(t) {
            let names_next = tokens
                .get(i + 1)
                .is_some_and(|n| is_unit_keyword(n.trim_end_matches('.')));
            if !names_next {
                door = true;
            }
        }
    }
    if named == 0 || !ends_cleanly(&tokens) {
        return false;
    }
    if door {
        return true;
    }
    named >= 2 && trailing_locality(&tokens)
}

/// Whether the candidate's last word (after its last `/`, abbreviation
/// dot removed) can end an address: a number, a unit keyword, or a
/// gazetteer place (one word, or two as in `19 Mayıs`). The pattern lets
/// a keyword stem or a place name take the rest of its word, so a last
/// word such as `Sokullu` or `Ankaralı` lands here and the candidate is
/// rejected rather than cut inside a word.
fn ends_cleanly(tokens: &[&str]) -> bool {
    let Some(last) = tokens.last() else {
        return false;
    };
    let word = last
        .rsplit('/')
        .next()
        .unwrap_or(last)
        .trim_end_matches('.');
    if word.is_empty() || word.bytes().any(|b| b.is_ascii_digit()) || is_unit_keyword(word) {
        return true;
    }
    is_place(word)
        || tokens.len() >= 2 && {
            let before = tokens[tokens.len() - 2];
            is_place(&format!(
                "{} {word}",
                before.rsplit('/').next().unwrap_or(before)
            ))
        }
}

/// Whether the address ends in a gazetteer district/province (`Çiğli/İzmir`,
/// `Kırklareli`) or a postal code.
fn trailing_locality(tokens: &[&str]) -> bool {
    let Some(last) = tokens.last() else {
        return false;
    };
    if last.len() == 5 && last.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    last.rsplit('/').next().is_some_and(is_place)
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Address,
        &PATTERN,
        Some(valid_address),
        ContextPolicy::None,
        0.85
    )
}

#[cfg(test)]
mod tests {
    use super::{is_number_token, valid_address};
    use crate::pii::entity::EntityType;

    fn addresses(text: &str) -> Vec<String> {
        crate::pii::detect::engine_detect(text, &["tr"])
            .into_iter()
            .filter(|e| e.kind == EntityType::Address)
            .map(|e| e.text)
            .collect()
    }

    #[test]
    fn full_addresses_are_one_span() {
        for (text, want) in [
            (
                "Teslimat Adresi: Kalemköy Mahallesi Papatya Sokak No:32 D:14 35990 Kınık/İzmir\n",
                "Kalemköy Mahallesi Papatya Sokak No:32 D:14 35990 Kınık/İzmir",
            ),
            (
                "Adres: Gazi Mustafa Kemalpaşa Mah., Ahiler Cd., No: 85, Kat: 6, Daire: 11, 06890 Kızılcahamam / Ankara",
                "Gazi Mustafa Kemalpaşa Mah., Ahiler Cd., No: 85, Kat: 6, Daire: 11, 06890 Kızılcahamam / Ankara",
            ),
            (
                "teslimat adresi Hacıhızır Mahallesi Dileğim Sokak 44/23 İzmit Kocaeli olarak kaydedildi.",
                "Hacıhızır Mahallesi Dileğim Sokak 44/23 İzmit Kocaeli",
            ),
            (
                "Adres: Bilinmeyen 14 Sokak No:47/3, Kurtuluş Mahallesi, Pehlivanköy, Kırklareli 39600",
                "Bilinmeyen 14 Sokak No:47/3, Kurtuluş Mahallesi, Pehlivanköy, Kırklareli 39600",
            ),
            (
                "İkamet: Evka 3 Mah. 119/5 Sk. No:69 D:24 35050 Bornova/İzmir",
                "Evka 3 Mah. 119/5 Sk. No:69 D:24 35050 Bornova/İzmir",
            ),
            (
                "ADRES: ATATÜRK CAD. NO:5 KADIKÖY/İSTANBUL",
                "ATATÜRK CAD. NO:5 KADIKÖY/İSTANBUL",
            ),
        ] {
            assert_eq!(addresses(text), vec![want.to_owned()], "{text}");
        }
    }

    #[test]
    fn span_stops_at_the_last_gazetteer_locality() {
        // a further capitalized word on the same line is not a place
        assert_eq!(
            addresses("Adres: Yalı Mah. 6471/8 Sok. No:105 Daire:24 Karşıyaka/İzmir Telefon: 0532"),
            vec!["Yalı Mah. 6471/8 Sok. No:105 Daire:24 Karşıyaka/İzmir".to_owned()]
        );
    }

    #[test]
    fn prose_mentions_without_a_door_number_stay_clean() {
        for text in [
            "Atatürk Caddesi bugün trafiğe kapalı.",
            "Kurtuluş Mahallesi'nde yeni bir park açıldı.",
            "Kızılay Mahallesi Atatürk Caddesi'nde yürüyüş yaptık.",
            "Ses CD 12345 adet satıldı.",
            "Madde 5 uyarınca No: 12 sayılı karar",
            "Mahmut Bey Sokak arasında 2024 yılında",
            "Bağdat Caddesi ile İstiklal Caddesi karşılaştırıldı.",
        ] {
            assert!(addresses(text).is_empty(), "{text}: {:?}", addresses(text));
        }
    }

    #[test]
    fn validator_table() {
        assert!(valid_address("Bağdat Caddesi No:5 Daire:10"));
        assert!(valid_address("Sazlı Sokak No:45/21, Tatlıca Mah."));
        assert!(valid_address("Kalemköy Mahallesi Papatya Sokak 35990"));
        assert!(valid_address("Kurtuluş Mah. Atatürk Cad. Çankaya/Ankara"));
        // one named unit and no door number
        assert!(!valid_address("Kurtuluş Mah. Atatürk Cad. Ahmet"));
        assert!(!valid_address("Ses CD 12345"));
        // `119/5` names the street, it is not a door number
        assert!(!valid_address("Evka Mah. 119/5 Sk."));
        // a last word taken by a keyword stem or a place prefix
        assert!(!valid_address("Bağdat Caddesi No:5 Ahmet Sokullu"));
        assert!(!valid_address("Bağdat Caddesi No:5 Ankaralı"));
        assert!(valid_address("Bağdat Caddesi No:5 Atakum/19 Mayıs"));
        assert!(is_number_token("47/3") && is_number_token("12a") && is_number_token("5"));
        assert!(!is_number_token("") && !is_number_token("abc") && !is_number_token("1/"));
    }
}
