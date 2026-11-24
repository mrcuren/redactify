//! Turkish suffix repair for restored placeholder values.
//!
//! An LLM inflects a placeholder by its own guess (`[NAME_1]'e`); the
//! restored value needs the suffix shaped for ITS pronunciation:
//! `Ayşe'ye`, `Kemal'e`, `12345678950'ye`, `TDK'ye`. [`repair_into`] parses
//! the suffix written after the apostrophe into morphemes and generates
//! them again for the value's phonological tail ([`tail_of`]).
//!
//! # Sources
//!
//! TDK Yazım Kılavuzu (<https://tdk.gov.tr/icerik/yazim-kurallari/>), read
//! 2026-11-23:
//!
//! - *Kesme İşareti*: suffixes on proper names, abbreviations and numbers
//!   are separated by an apostrophe (`Fatih Sultan Mehmet'e`, `TDK'nin`,
//!   `TV'ye`, `1985'te`, `657'yle`).
//! - *Kısaltmalar*: an upper-case abbreviation takes the suffix of its
//!   LAST LETTER's name (`BDT'ye`, `TDK'den`, `THY'de`, `TL'nin`); one read
//!   as a word takes the word's suffix (`NATO'dan`, `BOTAŞ'ın`); a final
//!   hard consonant does not soften (`RTÜK'e`, `TÜBİTAK'ın`); a lower-case
//!   abbreviation is read as its full word (`kg'dan`), which is unknowable
//!   here, so it is not repaired.
//! - *Büyük Ünlü Uyumu*: some loanwords whose last vowel is back but whose
//!   final sound is front take front suffixes (`alkolü`, `helalimiz`,
//!   `saate`, `santraller`).
//! - *Küçük Ünlü Uyumu* (four-way harmony of the high vowel) and *Ünsüz
//!   Uyumu* (a word ending in a hard consonant takes a suffix beginning
//!   with a hard consonant: `çiçekten`).
//!
//! The front-suffix lexicon ([`FRONT_FINAL`]) holds only words whose entry
//! in the TDK Güncel Türkçe Sözlük (`sozluk.gov.tr/gts`) gives a front
//! suffix (`taki`) despite a back last vowel: `kemal -li`, `celal -li`,
//! `cemal -li`, `hilal -li`, `ikbal -li`, `hayal -li`, `visal -li`,
//! `resul -lü`, the Yazım Kılavuzu examples above, `ihtimal -li`,
//! `rol -lü`, `gol -lü`, `usul -lü`, `hal -li`. A circumflex does NOT mark
//! a front suffix by itself (`rüzgâr`, `dükkân` have no `taki`: regular
//! back suffixes), so `â`/`û` count as back vowels.
//!
//! Numbers are read by their last spoken word (`…50` → *elli* → `'ye`,
//! `…146` → *altı* → `'ya`, `1.000` → *bin* → `'e`).
//!
//! Known limits (the suffix is then shaped by spelling, not sound): foreign
//! names whose pronunciation differs from their spelling, upper-case
//! abbreviations that contain a vowel but are spelled out (`ABD` reads as
//! a word here: `ABD'a`), and possessive suffixes (`'si`, `'m`), which are
//! not parsed and so are left exactly as the model wrote them.

/// A Turkish vowel (the eight of the alphabet).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Vowel {
    A,
    E,
    /// dotless `ı`
    Ih,
    I,
    O,
    Oe,
    U,
    Ue,
}

impl Vowel {
    /// The vowel class of a lower-case letter; accented Latin vowels count
    /// as their base vowel, a circumflex as the plain vowel (see module
    /// docs).
    fn of(c: char) -> Option<Self> {
        Some(match c {
            'a' | 'â' | 'á' | 'à' => Self::A,
            'e' | 'é' | 'è' | 'ê' | 'ë' | 'ä' => Self::E,
            'ı' => Self::Ih,
            'i' | 'î' | 'í' | 'ì' | 'ï' => Self::I,
            'o' | 'ó' | 'ò' | 'ô' => Self::O,
            'ö' => Self::Oe,
            'u' | 'û' | 'ú' | 'ù' => Self::U,
            'ü' => Self::Ue,
            _ => return None,
        })
    }

    const fn front(self) -> bool {
        matches!(self, Self::E | Self::I | Self::Oe | Self::Ue)
    }

    const fn round(self) -> bool {
        matches!(self, Self::O | Self::Oe | Self::U | Self::Ue)
    }

    /// The front counterpart (palatal final sound).
    const fn fronted(self) -> Self {
        match self {
            Self::A => Self::E,
            Self::Ih => Self::I,
            Self::O => Self::Oe,
            Self::U => Self::Ue,
            v => v,
        }
    }
}

/// How a word ends, for buffer consonants and consonant harmony.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    Vowel,
    /// `f s t k ç ş h p` (and `q`, `x` of foreign spellings)
    Voiceless,
    Voiced,
}

/// The phonological tail of a value: its last vowel and its final sound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tail {
    vowel: Vowel,
    end: End,
}

/// Turkish-aware lower case of one letter (`I` → `ı`, `İ` → `i`).
fn lower(c: char) -> char {
    match c {
        'I' => 'ı',
        'İ' => 'i',
        c => {
            let mut l = c.to_lowercase();
            match (l.next(), l.next()) {
                (Some(x), None) => x,
                _ => c,
            }
        }
    }
}

/// Turkish-aware upper case of one letter (`i` → `İ`, `ı` → `I`).
fn upper(c: char) -> char {
    match c {
        'i' => 'İ',
        'ı' => 'I',
        c => {
            let mut u = c.to_uppercase();
            match (u.next(), u.next()) {
                (Some(x), None) => x,
                _ => c,
            }
        }
    }
}

/// The final-sound class of a lower-case letter.
fn end_of(c: char) -> End {
    if Vowel::of(c).is_some() {
        End::Vowel
    } else if matches!(c, 'f' | 's' | 't' | 'k' | 'ç' | 'ş' | 'h' | 'p' | 'q' | 'x') {
        End::Voiceless
    } else {
        End::Voiced
    }
}

/// Words with a back last vowel that take FRONT suffixes (TDK Güncel
/// Türkçe Sözlük `taki`, see the module docs), sorted.
const FRONT_FINAL: [&str; 23] = [
    "alkol", "celal", "cemal", "gol", "hakikat", "hal", "hayal", "helal", "hilal", "idrak",
    "ihtimal", "ikbal", "kabul", "kemal", "kontrol", "protokol", "resul", "rol", "saat", "sadakat",
    "santral", "usul", "visal",
];

/// Lexicon key of a letter: lower case without the circumflex.
fn lexicon_fold(c: char) -> char {
    match lower(c) {
        'â' => 'a',
        'î' => 'i',
        'û' => 'u',
        c => c,
    }
}

/// The tail of a word read as spelled (letters only, at least one vowel).
fn word_tail(word: &str) -> Option<Tail> {
    let end = end_of(lower(word.chars().next_back()?));
    let vowel = word.chars().rev().find_map(|c| Vowel::of(lower(c)))?;
    let front_final = FRONT_FINAL
        .iter()
        .any(|w| w.chars().eq(word.chars().map(lexicon_fold)));
    Some(Tail {
        vowel: if front_final { vowel.fronted() } else { vowel },
        end,
    })
}

const UNITS: [&str; 10] = [
    "sıfır", "bir", "iki", "üç", "dört", "beş", "altı", "yedi", "sekiz", "dokuz",
];
const TENS: [&str; 10] = [
    "", "on", "yirmi", "otuz", "kırk", "elli", "altmış", "yetmiş", "seksen", "doksan",
];
const SCALES: [&str; 5] = ["bin", "milyon", "milyar", "trilyon", "katrilyon"];

/// The last spoken word of the number that ends `value` (which ends in an
/// ASCII digit). A trailing all-zero group of exactly three digits after a
/// `.` or space thousands separator belongs to the same number (`1.000` is
/// *bin*); other separators end the number (`0532 234 56 78` → *sekiz*).
fn number_word(value: &str) -> Option<&'static str> {
    let b = value.as_bytes();
    let mut i = b.len();
    let mut zeros = 0usize;
    loop {
        let end = i;
        while i > 0 && b[i - 1].is_ascii_digit() {
            i -= 1;
        }
        let group = &b[i..end];
        for &d in group.iter().rev() {
            if d == b'0' {
                zeros += 1;
                continue;
            }
            let d = usize::from(d - b'0');
            return match zeros {
                0 => Some(UNITS[d]),
                1 => Some(TENS[d]),
                2 => Some("yüz"),
                z => SCALES.get(z / 3 - 1).copied(),
            };
        }
        if group.len() == 3
            && i >= 2
            && matches!(b[i - 1], b'.' | b' ')
            && b[i - 2].is_ascii_digit()
        {
            i -= 1;
            continue;
        }
        return Some(UNITS[0]);
    }
}

/// The tail of an upper-case letter read by its name (`B` *be*, `K` *ke*,
/// `Q` *kü*, `X` *iks*, `W` *(çift) ve*).
fn letter_tail(c: char) -> Option<Tail> {
    match c {
        'Q' => Some(Tail {
            vowel: Vowel::Ue,
            end: End::Vowel,
        }),
        'X' => Some(Tail {
            vowel: Vowel::I,
            end: End::Voiceless,
        }),
        'A'..='Z' | 'Ç' | 'Ğ' | 'Ş' => Some(Tail {
            vowel: Vowel::E,
            end: End::Vowel,
        }),
        _ => None,
    }
}

/// The phonological tail of `value`, or `None` when it cannot be known
/// (the value ends in neither a letter nor a digit, or in a lower-case
/// vowelless abbreviation such as `kg`).
pub(crate) fn tail_of(value: &str) -> Option<Tail> {
    let last = value.chars().next_back()?;
    if last.is_ascii_digit() {
        return word_tail(number_word(value)?);
    }
    if !last.is_alphabetic() {
        return None;
    }
    let start = value
        .char_indices()
        .rev()
        .take_while(|&(_, c)| c.is_alphabetic())
        .last()
        .map_or(0, |(i, _)| i);
    let word = &value[start..];
    if word.chars().any(|c| Vowel::of(lower(c)).is_some()) {
        word_tail(word)
    } else if word.chars().all(char::is_uppercase) {
        letter_tail(last)
    } else {
        None
    }
}

/// One symbol of a suffix template (archiphonemes in the usual notation).
#[derive(Clone, Copy)]
enum Sym {
    /// a fixed letter
    L(char),
    /// two-way vowel `a/e`
    A,
    /// four-way vowel `ı/i/u/ü`
    I,
    /// `d/t` (consonant harmony)
    D,
    /// `c/ç` (consonant harmony)
    C,
    /// buffer `y` after a vowel
    Y,
    /// buffer `n` after a vowel
    N,
}

/// The suffixes repaired (nominal inflection after an apostrophe).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Morph {
    /// plural `-lAr`
    Pl,
    /// genitive `-(n)In`
    Gen,
    /// dative `-(y)A`
    Dat,
    /// accusative `-(y)I`
    Acc,
    /// locative `-DA`
    Loc,
    /// ablative `-DAn`
    Abl,
    /// instrumental `-(y)lA`
    Ins,
    /// equative `-CA`
    Equ,
    /// relative `-ki` (after the locative or genitive)
    Ki,
    /// copula `-DIr`
    Cop,
    /// past copula `-(y)DI`
    Past,
    /// evidential copula `-(y)mIş`
    Evid,
    /// conditional copula `-(y)sA`
    Cond,
}

impl Morph {
    const fn template(self) -> &'static [Sym] {
        use Sym::{A, C, D, I, L, N, Y};
        match self {
            Self::Pl => &[L('l'), A, L('r')],
            Self::Gen => &[N, I, L('n')],
            Self::Dat => &[Y, A],
            Self::Acc => &[Y, I],
            Self::Loc => &[D, A],
            Self::Abl => &[D, A, L('n')],
            Self::Ins => &[Y, L('l'), A],
            Self::Equ => &[C, A],
            Self::Ki => &[L('k'), L('i')],
            Self::Cop => &[D, I, L('r')],
            Self::Past => &[Y, D, I],
            Self::Evid => &[Y, L('m'), I, L('ş')],
            Self::Cond => &[Y, L('s'), A],
        }
    }
}

/// The longest suffix (in letters) that is parsed; a longer one is left as
/// written.
pub(crate) const MAX_SUFFIX_CHARS: usize = 24;
/// The most morphemes in one parse (`-lAr -DA -ki -lAr -DAn -DIr`).
const MAX_MORPHS: usize = 6;

/// Every end position of `t` matched against `s[pos..]`, accepting ANY
/// harmonic variant (the model's suffix need not be correct). At most two
/// (a template has at most one optional buffer).
fn recognize(t: &[Sym], s: &[char], pos: usize, ends: &mut Vec<usize>) {
    let Some((&first, rest)) = t.split_first() else {
        ends.push(pos);
        return;
    };
    let at = s.get(pos).copied();
    let ok = |set: &[char]| at.is_some_and(|c| set.contains(&c));
    match first {
        Sym::L(c) if at == Some(c) => recognize(rest, s, pos + 1, ends),
        Sym::A if ok(&['a', 'e']) => recognize(rest, s, pos + 1, ends),
        Sym::I if ok(&['ı', 'i', 'u', 'ü']) => recognize(rest, s, pos + 1, ends),
        Sym::D if ok(&['d', 't']) => recognize(rest, s, pos + 1, ends),
        Sym::C if ok(&['c', 'ç']) => recognize(rest, s, pos + 1, ends),
        Sym::Y | Sym::N => {
            let buffer = if matches!(first, Sym::Y) { 'y' } else { 'n' };
            if at == Some(buffer) {
                recognize(rest, s, pos + 1, ends);
            }
            recognize(rest, s, pos, ends);
        }
        _ => {}
    }
}

/// Morphotactic states of the parser.
#[derive(Clone, Copy)]
enum State {
    Start,
    AfterPl,
    AfterCase(Morph),
    AfterKi,
    AfterKiPl,
    AfterKiCase,
    Done,
}

impl State {
    /// The morphemes allowed next, in the order they are tried.
    fn next(self) -> &'static [(Morph, Self)] {
        use Morph::{Abl, Acc, Cond, Cop, Dat, Equ, Evid, Gen, Ins, Ki, Loc, Past, Pl};
        macro_rules! cases_then {
            ($($m:ident => $s:expr),* ; copulas) => {
                &[$(($m, $s),)* (Cop, State::Done), (Past, State::Done), (Evid, State::Done), (Cond, State::Done)]
            };
        }
        match self {
            Self::Start => cases_then!(
                Pl => Self::AfterPl, Gen => Self::AfterCase(Gen), Dat => Self::AfterCase(Dat),
                Acc => Self::AfterCase(Acc), Loc => Self::AfterCase(Loc), Abl => Self::AfterCase(Abl),
                Ins => Self::AfterCase(Ins), Equ => Self::AfterCase(Equ); copulas),
            Self::AfterPl => cases_then!(
                Gen => Self::AfterCase(Gen), Dat => Self::AfterCase(Dat),
                Acc => Self::AfterCase(Acc), Loc => Self::AfterCase(Loc), Abl => Self::AfterCase(Abl),
                Ins => Self::AfterCase(Ins), Equ => Self::AfterCase(Equ); copulas),
            Self::AfterCase(Loc | Gen) => cases_then!(Ki => Self::AfterKi; copulas),
            Self::AfterCase(_) | Self::AfterKiCase => cases_then!(; copulas),
            Self::AfterKi => cases_then!(Pl => Self::AfterKiPl; copulas),
            Self::AfterKiPl => cases_then!(
                Gen => Self::AfterKiCase, Dat => Self::AfterKiCase, Acc => Self::AfterKiCase,
                Loc => Self::AfterKiCase, Abl => Self::AfterKiCase, Ins => Self::AfterKiCase;
                copulas),
            Self::Done => &[],
        }
    }
}

/// Parses `s` (lower case) completely into `out`; the first parse in the
/// documented order wins (longer variants first at each step).
fn parse(s: &[char], pos: usize, state: State, out: &mut Vec<Morph>) -> bool {
    if pos == s.len() {
        return pos > 0;
    }
    if out.len() == MAX_MORPHS {
        return false;
    }
    let mut ends = Vec::with_capacity(2);
    for &(m, next) in state.next() {
        ends.clear();
        recognize(m.template(), s, pos, &mut ends);
        ends.sort_unstable_by(|a, b| b.cmp(a));
        for &e in &ends {
            if e == pos {
                continue;
            }
            out.push(m);
            if parse(s, e, next, out) {
                return true;
            }
            out.pop();
        }
    }
    false
}

/// Generates `morphs` after a value with tail `tail` into `out`.
fn generate(mut tail: Tail, morphs: &[Morph], upper_case: bool, out: &mut String) {
    let mut push = |c: char, tail: &mut Tail| {
        out.push(if upper_case { upper(c) } else { c });
        match Vowel::of(c) {
            Some(v) => {
                tail.vowel = v;
                tail.end = End::Vowel;
            }
            None => tail.end = end_of(c),
        }
    };
    for m in morphs {
        for &sym in m.template() {
            let c = match sym {
                Sym::L(c) => c,
                Sym::A => {
                    if tail.vowel.front() {
                        'e'
                    } else {
                        'a'
                    }
                }
                Sym::I => match (tail.vowel.front(), tail.vowel.round()) {
                    (false, false) => 'ı',
                    (true, false) => 'i',
                    (false, true) => 'u',
                    (true, true) => 'ü',
                },
                Sym::D => {
                    if tail.end == End::Voiceless {
                        't'
                    } else {
                        'd'
                    }
                }
                Sym::C => {
                    if tail.end == End::Voiceless {
                        'ç'
                    } else {
                        'c'
                    }
                }
                Sym::Y | Sym::N => {
                    if tail.end != End::Vowel {
                        continue;
                    }
                    if matches!(sym, Sym::Y) {
                        'y'
                    } else {
                        'n'
                    }
                }
            };
            push(c, &mut tail);
        }
    }
}

/// Appends to `out` the suffix `written` (the letters after the
/// apostrophe) repaired for a value with tail `tail`; returns `false`, and
/// appends nothing, when `written` is not a suffix chain this module
/// parses (then the caller keeps it verbatim). The letter case of
/// `written` is kept (all lower or all upper case; mixed case is not
/// parsed).
pub(crate) fn repair_into(tail: Tail, written: &str, out: &mut String) -> bool {
    let mut chars: Vec<char> = Vec::with_capacity(MAX_SUFFIX_CHARS);
    let all_upper = written.chars().all(char::is_uppercase);
    for c in written.chars() {
        if chars.len() == MAX_SUFFIX_CHARS || !(all_upper || c.is_lowercase()) {
            return false;
        }
        chars.push(lower(c));
    }
    let mut morphs = Vec::with_capacity(MAX_MORPHS);
    if !parse(&chars, 0, State::Start, &mut morphs) {
        return false;
    }
    generate(tail, &morphs, all_upper, out);
    true
}

/// `written` repaired for `value`, or `None` when either is not handled.
#[cfg(test)]
pub(crate) fn repaired(value: &str, written: &str) -> Option<String> {
    let mut out = String::new();
    repair_into(tail_of(value)?, written, &mut out).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::{number_word, repaired, FRONT_FINAL};

    /// `(value, [dative, genitive, locative, accusative, ablative,
    /// instrumental])` as TDK spells them after an apostrophe.
    const TABLE: &[(&str, [&str; 6])] = &[
        // vowel-final, back / front
        ("Ayşe Kaya", ["ya", "nın", "da", "yı", "dan", "yla"]),
        ("Ayşe", ["ye", "nin", "de", "yi", "den", "yle"]),
        ("Ali", ["ye", "nin", "de", "yi", "den", "yle"]),
        ("Duru", ["ya", "nun", "da", "yu", "dan", "yla"]),
        ("Ünlü", ["ye", "nün", "de", "yü", "den", "yle"]),
        ("Banu", ["ya", "nun", "da", "yu", "dan", "yla"]),
        // consonant-final, voiced
        ("Okan", ["a", "ın", "da", "ı", "dan", "la"]),
        ("Onur", ["a", "un", "da", "u", "dan", "la"]),
        ("Emel", ["e", "in", "de", "i", "den", "le"]),
        ("Gönül", ["e", "ün", "de", "ü", "den", "le"]),
        // consonant-final, voiceless (fortis): d -> t, no softening
        ("Ahmet", ["e", "in", "te", "i", "ten", "le"]),
        ("Mehmet Öztürk", ["e", "ün", "te", "ü", "ten", "le"]),
        ("Burak", ["a", "ın", "ta", "ı", "tan", "la"]),
        ("Yusuf", ["a", "un", "ta", "u", "tan", "la"]),
        ("Ferah", ["a", "ın", "ta", "ı", "tan", "la"]),
        ("Yeşilçay", ["a", "ın", "da", "ı", "dan", "la"]),
        ("Barış", ["a", "ın", "ta", "ı", "tan", "la"]),
        ("Ilgaz Koç", ["a", "un", "ta", "u", "tan", "la"]),
        // palatal final sound (TDK lexicon)
        ("Kemal", ["e", "in", "de", "i", "den", "le"]),
        ("Mustafa Kemal", ["e", "in", "de", "i", "den", "le"]),
        ("Celâl", ["e", "in", "de", "i", "den", "le"]),
        ("Resul", ["e", "ün", "de", "ü", "den", "le"]),
        ("Saat", ["e", "in", "te", "i", "ten", "le"]),
        // circumflex alone is not palatal (rüzgâr, dükkân: back suffixes)
        ("Rüzgâr", ["a", "ın", "da", "ı", "dan", "la"]),
        // upper-case names are words (TDK: RTÜK'e, TÜBİTAK'ın)
        ("AHMET YILMAZ", ["a", "ın", "da", "ı", "dan", "la"]),
        ("TÜBİTAK", ["a", "ın", "ta", "ı", "tan", "la"]),
        ("RTÜK", ["e", "ün", "te", "ü", "ten", "le"]),
        ("NATO", ["ya", "nun", "da", "yu", "dan", "yla"]),
        // upper-case abbreviations: the last letter's name
        ("TDK", ["ye", "nin", "de", "yi", "den", "yle"]),
        ("THY", ["ye", "nin", "de", "yi", "den", "yle"]),
        ("TL", ["ye", "nin", "de", "yi", "den", "yle"]),
        ("BM", ["ye", "nin", "de", "yi", "den", "yle"]),
        ("XQ", ["ye", "nün", "de", "yü", "den", "yle"]),
        ("TRX", ["e", "in", "te", "i", "ten", "le"]),
        // numbers: the last spoken word
        ("12345678950", ["ye", "nin", "de", "yi", "den", "yle"]), // elli
        ("10000000146", ["ya", "nın", "da", "yı", "dan", "yla"]), // altı
        ("0532 234 56 78", ["e", "in", "de", "i", "den", "le"]),  // sekiz
        (
            "TR85 1870 6695 8688 2745 6305 22",
            ["ye", "nin", "de", "yi", "den", "yle"],
        ), // iki
        ("1985", ["e", "in", "te", "i", "ten", "le"]),            // beş
        ("2019", ["a", "un", "da", "u", "dan", "la"]),            // dokuz
        ("657", ["ye", "nin", "de", "yi", "den", "yle"]),         // yedi (TDK: 657'yle)
        ("3", ["e", "ün", "te", "ü", "ten", "le"]),               // üç
        ("4", ["e", "ün", "te", "ü", "ten", "le"]),               // dört
        ("1", ["e", "in", "de", "i", "den", "le"]),               // bir
        ("40", ["a", "ın", "ta", "ı", "tan", "la"]),              // kırk
        ("60", ["a", "ın", "ta", "ı", "tan", "la"]),              // altmış
        ("70", ["e", "in", "te", "i", "ten", "le"]),              // yetmiş
        ("80", ["e", "in", "de", "i", "den", "le"]),              // seksen
        ("90", ["a", "ın", "da", "ı", "dan", "la"]),              // doksan
        ("30", ["a", "un", "da", "u", "dan", "la"]),              // otuz
        ("10", ["a", "un", "da", "u", "dan", "la"]),              // on
        ("20", ["ye", "nin", "de", "yi", "den", "yle"]),          // yirmi
        ("100", ["e", "ün", "de", "ü", "den", "le"]),             // yüz
        ("1.000", ["e", "in", "de", "i", "den", "le"]),           // bin
        ("5000", ["e", "in", "de", "i", "den", "le"]),            // bin
        ("2000000", ["a", "un", "da", "u", "dan", "la"]),         // milyon
        ("3000000000", ["a", "ın", "da", "ı", "dan", "la"]),      // milyar
        ("0", ["a", "ın", "da", "ı", "dan", "la"]),               // sıfır
        ("34 ABC 123", ["e", "ün", "te", "ü", "ten", "le"]),      // üç
        // e-mail / URL: the final word as spelled
        ("ayse.kaya@example.com", ["a", "un", "da", "u", "dan", "la"]),
    ];

    /// The six case suffixes as an LLM may have written them (every
    /// harmonic variant, with and without the buffer letter).
    const WRITTEN: [&[&str]; 6] = [
        &["a", "e", "ya", "ye"],
        &["ın", "in", "un", "ün", "nın", "nin", "nun", "nün"],
        &["da", "de", "ta", "te"],
        &["ı", "i", "u", "ü", "yı", "yi", "yu", "yü"],
        &["dan", "den", "tan", "ten"],
        &["la", "le", "yla", "yle"],
    ];

    #[test]
    fn every_written_variant_repairs_to_the_tdk_form() {
        for (value, expected) in TABLE {
            for (case, variants) in WRITTEN.iter().enumerate() {
                for w in *variants {
                    assert_eq!(
                        repaired(value, w).as_deref(),
                        Some(expected[case]),
                        "{value} + '{w}"
                    );
                }
            }
        }
    }

    #[test]
    fn chains_plural_relative_and_copulas() {
        let cases: &[(&str, &str, &str)] = &[
            ("Ayşe", "lara", "lere"),
            ("Kaya", "lerin", "ların"),
            ("Ahmet", "dakiler", "tekiler"),
            ("Ahmet", "deki", "teki"),
            ("Ayşe", "nınki", "ninki"),
            ("Ahmet", "dekilerden", "tekilerden"),
            ("Ayşe", "dir", "dir"),
            ("Ahmet", "dir", "tir"),
            ("Kaya", "dir", "dır"),
            ("Ayşe", "dı", "ydi"),
            ("Ahmet", "ydı", "ti"),
            ("Ayşe", "miş", "ymiş"),
            ("Ahmet", "ymış", "miş"),
            ("Ayşe", "sa", "yse"),
            ("Ahmet", "yse", "se"),
            ("Ahmet", "ce", "çe"),
            ("Kaya", "ce", "ca"),
            ("Ayşe", "deydi", "deydi"),
            ("Ahmet", "lerdi", "lerdi"),
            ("Kaya", "larda", "larda"),
            ("Kemal", "ların", "lerin"),
        ];
        for (value, written, want) in cases {
            assert_eq!(
                repaired(value, written).as_deref(),
                Some(*want),
                "{value} + '{written}"
            );
        }
    }

    #[test]
    fn letter_case_of_the_suffix_is_kept() {
        assert_eq!(repaired("Ayşe", "E").as_deref(), Some("YE"));
        assert_eq!(repaired("Kaya", "İN").as_deref(), Some("NIN"));
        assert_eq!(repaired("AHMET", "in").as_deref(), Some("in"));
        assert_eq!(repaired("Ahmet", "De"), None);
    }

    #[test]
    fn unparsed_suffixes_and_unknown_tails_are_refused() {
        // English clitics, possessives, nonsense, too long
        for w in [
            "s",
            "ll",
            "re",
            "ve",
            "d",
            "m",
            "t",
            "si",
            "ki",
            "n",
            "xyz",
            "",
            "lerlerlerlerlerlerlerler",
        ] {
            assert_eq!(repaired("Ayşe", w), None, "'{w}");
        }
        // values whose pronunciation is unknowable
        for v in ["kg", "a@b.com.", "Ayşe)", "", "--"] {
            assert_eq!(repaired(v, "e"), None, "{v}");
        }
    }

    #[test]
    fn number_words() {
        let cases = [
            ("7", "yedi"),
            ("17291716060", "altmış"),
            ("1 000", "bin"),
            ("12.000.000", "milyon"),
            ("56 00", "sıfır"),
            ("1,000", "sıfır"),
            ("1000000000000000000", "bin"), // 10^18: beyond katrilyon? no: z = 18
        ];
        for (n, w) in &cases[..6] {
            assert_eq!(number_word(n), Some(*w), "{n}");
        }
        // 10^18 has 18 trailing zeros: past the last scale, unknown
        assert_eq!(number_word(cases[6].0), None);
    }

    #[test]
    fn lexicon_is_sorted_and_lower_case() {
        assert!(FRONT_FINAL.windows(2).all(|w| w[0] < w[1]));
        assert!(FRONT_FINAL
            .iter()
            .all(|w| w.chars().all(char::is_lowercase)));
    }
}
