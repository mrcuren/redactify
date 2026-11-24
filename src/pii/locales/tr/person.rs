//! Turkish person names **without a label cue**: a lexicon scanner over
//! the capitalized words of one line.
//!
//! The labeled rule ([`super::name`]) claims a capitalized sequence only
//! next to a cue ("Ad Soyad:"). Most names in free text have none
//! ("Bu rapor Ayşe Demir tarafından hazırlandı"), so this scanner decides
//! from the words themselves, looked up in [`super::person_lexicon`]:
//! is the word a first or a last name, how common is it as a name, and is
//! it also a Turkish word ("Kaya" = rock, "Deniz" = sea, "Sevinç" = joy)?
//!
//! # Evidence
//!
//! Turkish capitalizes common nouns only at a sentence start and in
//! headings, so a capitalized name word is weak evidence where a common
//! word could stand capitalized (line start, after a colon, inside a
//! Title Case heading) and strong evidence mid-sentence. A word is
//! **strong** when it is a name, not a frequent word, not a proper noun
//! (place, nationality, month), and either common as a name or no word at
//! all ("Ahmet", "Yılmaz", "Öztürk"; not "Kaya", "Deniz", "Türk").
//!
//! A **run** is up to four adjacent capitalized name words, all Title
//! case, all upper case, or Title case followed by upper case ("Ahmet
//! YILMAZ"), separated by a short whitespace run (tab, several spaces,
//! no-break or thin space) or an underscore, or by a bare `;` or `,`
//! (a table cell) before a last name; a word with an apostrophe suffix
//! ends it. A hyphenated compound of lexicon names is one word ("Ayşe-Nur",
//! "Yılmaz-Kaya"). A run of two or more words starting with a first name is a
//! name when one of these holds:
//!
//! 1. the first word is strong ("Ahmet Kaya");
//! 2. the first word is a common first name, another word is strong and
//!    no capitalized non-name word is adjacent ("Deniz Öztürk");
//! 3. an honorific ("Sayın", "Dr", "Bey", "Hanım") or a name label
//!    ("Soyadı:") is adjacent;
//! 4. the last word is a last name, no capitalized word is adjacent and
//!    the run either follows a lowercase word (mid-sentence: "dosyada
//!    Deniz Kaya"), is the whole value after a colon ("Sigortalı: Umut
//!    Doğan") or is the next item of a list whose previous item was
//!    claimed ("cc: Deniz Kaya, Umut Doğan, Barış Güneş").
//!
//! A single word is a name after an honorific or greeting, as the whole
//! value of a name label, with an apostrophe suffix when strong and not a
//! locative ("Ahmet'in", not "Alsancak'ta"), or as a strong first name
//! that is not a dictionary word (or a common one, mid-sentence). A word
//! outside the lexicon that is a common strong name plus a case suffix written
//! without the apostrophe ("Ahmetin", "Ayşeye", "Mehmede" with the
//! softened `t`) counts like the apostrophe form inside a run or
//! mid-sentence, and like the bare name otherwise (alone at a line start
//! only a strong first name that is no dictionary word counts: there
//! "Malike" and "Bilgini" were mostly words). Any other word outside
//! the lexicon counts after an honorific or a name label, or before a
//! strong last name ("Yağızalp Öztürk").
//!
//! A run is **not** a name when an organisation, address, hospital,
//! market or trade word follows within three capitalized words ("Ahmet
//! Yılmaz Holding", "Fevzi Çakmak Caddesi", "Kanuni Sultan Süleyman
//! Hastanesi", "Selin Ofis Mobilyaları", "... A.Ş."), when a `/` touches
//! it ("Fatih/İstanbul"), or when it is the value of a label that names a
//! thing ("Ürün adı: Sultan Çay", "Marka:").
//!
//! A name is masked **whole**: a claim that ends in a given name takes in
//! a following Title-case word outside the lexicon ("Ahmet Yağızalp"),
//! and a last name written before a comma at the start of a field joins
//! the given name after it ("Yılmaz, Ahmet").
//!
//! # Span
//!
//! The span covers the name words only: a title ("Dr."), an honorific
//! ("Bey") and a case suffix stay visible ("Ahmet'in" masks to
//! "[NAME_1]'in", "Ahmetin" to "[NAME_1]in"), so the text keeps its
//! grammar for a model and the
//! restore stays byte exact (the vault keeps the original).
//!
//! # Scores
//!
//! [`SCORE_CUE`] (an honorific, greeting or label decided it, or the run
//! starts with a strong first name) and [`SCORE_PLAIN`] (every other
//! accepted name), below the 0.9 of checksum-validated identifiers.
//!
//! # Measured (development split, not the test sets)
//!
//! The thresholds above were chosen on the `train` split of
//! `newmindai/nm-kvkk-pii-6K` (Apache-2.0, revision `0dfe459`, 5,178
//! documents; the reported test and piimask numbers are separate):
//! person-name overlap F1 0.982 (P 0.990, R 0.974).
//!
//! # Limits
//!
//! - Line scoped, like every rule: a surname mentioned alone on a later
//!   line is not linked to the full name above.
//! - Lowercase names ("ahmet yılmaz") and initials ("A. Yılmaz") are not
//!   claimed; neither is "YILMAZ Ahmet" (surname first) beyond its first
//!   name.
//! - Names that are only frequent words ("Umut", "Deniz") stay unclaimed
//!   alone at a line start unless an honorific, label or apostrophe
//!   suffix supports them; names of public figures ("Mustafa Kemal") are
//!   claimed like any other name.
//!
//! # Streaming bound
//!
//! The decision reads at most three tokens (each at most
//! [`super::person_lexicon::MAX_KEY`] characters when it counts) and one
//! character after a run of at most four such words, and the stream guard
//! holds back every trailing run of up to four capitalized words, so an
//! emitted prefix never loses or gains a name (`policy::stream`).

use super::person_lexicon::{fold, lookup, Flags, MAX_KEY};
use crate::pii::entity::EntityType;
use crate::pii::locales::LineScanner;

/// Score of a name decided by an honorific, a greeting, a name label, or
/// a run that starts with a strong first name.
pub(crate) const SCORE_CUE: f32 = 0.85;

/// Score of every other accepted name.
pub(crate) const SCORE_PLAIN: f32 = 0.75;

/// Most name words in one run (the stream guard holds four).
const MAX_RUN: usize = 4;

/// How far (characters) after a run the organisation lookahead reaches.
const ORG_REACH: usize = 40;

/// Longest whitespace run between two words of one name (characters;
/// whitespace is a gap character for the stream guard's holdback, so it
/// does not widen the streaming bound).
const MAX_NAME_GAP: usize = 8;

/// Lowercase words that join list items ("Ayşe ve Fatma").
const LIST_JOINERS: &[&str] = &["ve", "ile", "veya", "and"];

/// Labels whose value names a thing, folded ("Ürün adı:", "Marka:"): a
/// name-shaped value after them is a product or brand ("Ürün adı: Sultan
/// Çay"), never claimed.
const THING_LABELS: &[&str] = &[
    "urun", "marka", "firma", "sirket", "proje", "kampanya", "model", "magaza", "kurum", "kurulus",
    "otel", "restoran", "program", "etkinlik", "film", "kitap",
];

/// The scanner as the engine registers it.
pub(crate) fn scanner() -> LineScanner {
    LineScanner {
        id: "tr::person",
        kind: EntityType::Name,
        scan: scan_line,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Case {
    /// First letter uppercase ("Ahmet", "McDonald").
    Title,
    /// Two or more letters, all uppercase ("AHMET").
    Upper,
    /// Anything else ("ahmet").
    Lower,
}

/// One word of the line.
struct Tok {
    /// Byte offset of the word.
    start: usize,
    /// Byte offset after the word, before an apostrophe suffix (or before
    /// a joined case suffix, see `joined`).
    end: usize,
    /// Byte offset after the suffix (`end` without one).
    full_end: usize,
    case: Case,
    /// Folded length in characters (also for words that cannot fold).
    key_len: usize,
    flags: Flags,
    /// The suffix after `end` is joined without an apostrophe ("Ahmetin";
    /// `end` is then the end of the name stem).
    joined: bool,
}

impl Tok {
    const fn suffixed(&self) -> bool {
        self.full_end != self.end
    }

    const fn capitalized(&self) -> bool {
        !matches!(self.case, Case::Lower)
    }

    const fn is(&self, bits: u16) -> bool {
        self.flags.any(bits)
    }

    /// A first or last name.
    const fn is_name(&self) -> bool {
        self.is(Flags::FIRST | Flags::LAST)
    }

    /// Module doc, "strong".
    const fn strong(&self) -> bool {
        self.is_name()
            && !self.is(Flags::FREQUENT_WORD | Flags::PROPER)
            && (self.is(Flags::COMMON) || !self.is(Flags::DICTIONARY | Flags::INFLECTED))
    }

    /// An honorific, greeting or organisation word: never part of a name
    /// ("Sevgili" is also a rare first name, but "Sevgili Necla" greets
    /// Necla).
    const fn context_word(&self) -> bool {
        self.is(Flags::PRE_HONORIFIC | Flags::POST_HONORIFIC | Flags::ORG | Flags::GREETING)
    }

    /// A capitalized lexicon name that may join a run.
    const fn name_word(&self) -> bool {
        self.is_name() && self.capitalized() && self.key_len >= 2 && !self.context_word()
    }

    /// A Title-case word outside the lexicon that may still be a name.
    const fn unknown_name_shape(&self) -> bool {
        matches!(self.case, Case::Title)
            && self.key_len >= 3
            && self.key_len <= MAX_KEY
            && !self.is_name()
            && !self.is(Flags::FREQUENT_WORD | Flags::PROPER)
            && !self.context_word()
    }
}

fn is_letter(c: char) -> bool {
    c.is_alphabetic() || c == '\u{307}'
}

/// Appends the words of `line` to `out`: letter runs joined by inner
/// hyphens, each with an optional apostrophe suffix (`'` or `’` followed
/// by letters).
fn tokenize(line: &str, out: &mut Vec<Tok>) {
    let mut chars = line.char_indices().peekable();
    let letters_from = |at: usize| line[at..].chars().next().is_some_and(char::is_alphabetic);
    while let Some((start, c)) = chars.next() {
        if !c.is_alphabetic() {
            continue;
        }
        let mut end = start + c.len_utf8();
        while let Some(&(i, c)) = chars.peek() {
            if is_letter(c) || (c == '-' && letters_from(i + 1)) {
                end = i + c.len_utf8();
                chars.next();
            } else {
                break;
            }
        }
        let mut full_end = end;
        if let Some(&(i, c @ ('\'' | '\u{2019}'))) = chars.peek() {
            if letters_from(i + c.len_utf8()) {
                chars.next();
                full_end = i + c.len_utf8();
                while let Some(&(i, c)) = chars.peek() {
                    if is_letter(c) {
                        full_end = i + c.len_utf8();
                        chars.next();
                    } else {
                        break;
                    }
                }
            }
        }
        out.push(word(line, start, end, full_end));
    }
}

/// Classifies one word (case, folded length, lexicon flags).
fn word(line: &str, start: usize, end: usize, full_end: usize) -> Tok {
    let base = &line[start..end];
    let letters = base.chars().filter(|c| c.is_alphabetic());
    let (mut count, mut upper) = (0, true);
    for c in letters {
        count += 1;
        upper &= c.is_uppercase();
    }
    let case = if count >= 2 && upper {
        Case::Upper
    } else if base.chars().next().is_some_and(char::is_uppercase) {
        Case::Title
    } else {
        Case::Lower
    };
    let mut buf = [0; MAX_KEY];
    let (key_len, mut flags, folded) = match fold(base, &mut buf) {
        Some(key) => (key.len(), lookup(key), true),
        None => {
            let key_len = base.chars().filter(|&c| c != '\u{307}').count();
            let flags = if key_len <= MAX_KEY {
                hyphenated(base)
            } else {
                Flags::default()
            };
            (key_len, flags, false)
        }
    };
    let mut end = end;
    let mut joined = false;
    if folded && case != Case::Lower && full_end == end && flags == Flags::default() {
        if let Some((stem_chars, stem_flags)) = joined_suffix(&buf[..key_len]) {
            // the stem's characters fold one to one (U+0307 aside), so the
            // raw stem ends after `stem_chars` letters of the word
            let mut seen = 0;
            for (i, c) in base.char_indices() {
                if c == '\u{307}' {
                    continue;
                }
                if seen == stem_chars {
                    end = start + i;
                    break;
                }
                seen += 1;
            }
            flags = stem_flags;
            joined = true;
        }
    }
    Tok {
        start,
        end,
        full_end,
        case,
        key_len,
        flags,
        joined,
    }
}

/// Case suffixes written without an apostrophe ("Ahmetin", "Ayşeye"),
/// folded: genitive, dative, instrumental, locative and ablative. Plural
/// and derivational endings are left out ("Erenler" is a place), and so
/// is the accusative `-i`/`-u`, which turns adjectives and nouns into a
/// name plus a suffix ("Seçili" read as "Seçil" + `-i`; measured on the
/// nm-kvkk train split).
const JOINED_SUFFIXES: &[&str] = &[
    "nin", "nun", "yla", "yle", "dan", "den", "tan", "ten", "in", "un", "ya", "ye", "la", "le",
    "da", "de", "ta", "te", "a", "e",
];

/// A word outside the lexicon read as a strong name plus a joined case
/// suffix: `(stem length, stem flags)`. The stem has at least three
/// letters and is a strong, common name ([`Tok::strong`] with
/// [`Flags::COMMON`]: "Soyadı" is "soyad", a rare surname, plus a suffix,
/// and stays a word); a stem ending in `b`, `d` or `g` is also tried with
/// the voiceless consonant the suffix softened ("Mehmede" -> "mehmet").
fn joined_suffix(key: &[u8]) -> Option<(usize, Flags)> {
    if key.len() < 4 || !key.iter().all(u8::is_ascii_lowercase) {
        return None;
    }
    JOINED_SUFFIXES.iter().find_map(|suffix| {
        let stem = key.strip_suffix(suffix.as_bytes())?;
        if stem.len() < 3 {
            return None;
        }
        let strong = |flags: Flags| {
            flags.any(Flags::FIRST | Flags::LAST)
                && flags.has(Flags::COMMON)
                && !flags.any(Flags::FREQUENT_WORD | Flags::PROPER)
        };
        let flags = lookup(stem);
        if strong(flags) {
            return Some((stem.len(), flags));
        }
        let (&last, head) = stem.split_last()?;
        let hard = match last {
            b'b' => b'p',
            b'd' => b't',
            b'g' => b'k',
            _ => return None,
        };
        let mut buf = [0; MAX_KEY];
        buf[..head.len()].copy_from_slice(head);
        buf[head.len()] = hard;
        let flags = lookup(&buf[..stem.len()]);
        strong(flags).then_some((stem.len(), flags))
    })
}

/// The flags of a hyphenated compound whose parts are all lexicon names
/// ("Ayşe-Nur", "Yılmaz-Kaya", "YILMAZ-ÖZTÜRK"); empty flags otherwise.
/// The compound is a first name when its first part is one, a last name
/// when its last part is one and common when any part is; the word
/// evidence (frequent word, dictionary, proper noun) holds only when every
/// part carries it, since a compound of names is itself name evidence.
/// Without this the compound was a word outside the lexicon: "Ayşe
/// Yılmaz-Kaya" masked only "Ayşe", "Ayşe-Nur Demir" nothing. Parts of
/// fewer than three letters and proper nouns keep a compound out ("Türk-İş"
/// is a union).
fn hyphenated(base: &str) -> Flags {
    const ALL_PARTS: u16 =
        Flags::FREQUENT_WORD | Flags::DICTIONARY | Flags::INFLECTED | Flags::PROPER;
    let mut parts = base.split('-').peekable();
    let (mut all, mut any, mut out) = (u16::MAX, 0, 0);
    let mut first = true;
    while let Some(part) = parts.next() {
        let mut buf = [0; MAX_KEY];
        let Some(key) = fold(part, &mut buf) else {
            return Flags::default();
        };
        let flags = lookup(key);
        if key.len() < 3 || !flags.any(Flags::FIRST | Flags::LAST) || flags.any(Flags::PROPER) {
            return Flags::default();
        }
        if first {
            out |= flags.bits() & (Flags::FIRST | Flags::FIRST_PRIMARY);
            first = false;
        }
        if parts.peek().is_none() {
            out |= flags.bits() & Flags::LAST;
        }
        all &= flags.bits();
        any |= flags.bits();
    }
    if first {
        return Flags::default();
    }
    Flags::from_bits(out | (any & Flags::COMMON) | (all & ALL_PARTS))
}

/// One space (or no-break space) between two words.
fn single_space(gap: &str) -> bool {
    gap == " " || gap == "\u{a0}"
}

/// A gap that may separate the words of one name: a short run of
/// horizontal whitespace (spaces, tabs, no-break, thin and ideographic
/// spaces; at most [`MAX_NAME_GAP`] characters) or an underscore
/// (`Ahmet_Yilmaz`). Joining on one space or no-break space only would
/// mask just the first name of `Ahmet\tYılmaz` and `Ahmet  Yılmaz` and
/// leave the surname visible.
fn name_gap(gap: &str) -> bool {
    gap == "_"
        || (!gap.is_empty()
            && gap.chars().count() <= MAX_NAME_GAP
            && gap.chars().all(|c| c.is_whitespace() && c != '\r'))
}

/// A table separator without spaces (`Ahmet;Yılmaz;12345678950`,
/// `Ahmet,Yılmaz,...`): joins a name to a following last name only.
fn table_gap(gap: &str) -> bool {
    gap == ";" || gap == ","
}

/// Only whitespace, or a dot with whitespace ("Dr. Ahmet").
fn space_or_dot(gap: &str) -> bool {
    matches!(gap.trim(), "" | ".")
}

/// Name labels whose value is a person's (whole or part of the) name,
/// folded (`ad soyad:`, `kızlık soyadı:`).
const LABELS: &[&str] = &[
    "ad",
    "adi",
    "soyad",
    "soyadi",
    "isim",
    "ismi",
    "soyisim",
    "soyismi",
    "ad soyad",
    "adi soyadi",
    "adi ve soyadi",
    "ikinci ad",
    "ikinci adi",
    "kizlik soyadi",
    "onceki soyadi",
];

/// Person nouns that may precede a label ("Müşteri adı:"), folded; any
/// other word before "adı:" names a thing ("Kampanya adı:").
const PERSON_NOUNS: &[&str] = &[
    "musteri",
    "hasta",
    "baba",
    "anne",
    "annesinin",
    "babasinin",
    "anne kizlik",
    "uye",
    "sigortali",
    "calisan",
    "personel",
    "ogrenci",
    "veli",
    "danisan",
    "katilimci",
    "yetkili",
    "es",
    "esinin",
    "kefil",
    "basvuran",
    "basvuru sahibi",
    "hesap sahibi",
    "kart sahibi",
    "alici",
    "gonderen",
];

/// Folds `text` for the label comparison (lowercase, Turkish letters to
/// ASCII; other characters lowercased as they are).
fn fold_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let mut buf = [0; MAX_KEY];
        match fold(c.encode_utf8(&mut [0; 4]), &mut buf) {
            Some(key) => out.extend(key.iter().map(|&b| char::from(b))),
            None => out.extend(c.to_lowercase()),
        }
    }
    out
}

/// Whether `before` (the line up to a word) ends with a name label and
/// its `:` or `=`: the label starts the line or follows `|`, `,`, `;`,
/// `(`, a tab, two spaces, or a person noun ("Hasta adı:").
fn after_name_label(before: &str) -> bool {
    let b = before.trim_end();
    let Some(b) = b.strip_suffix([':', '=']) else {
        return false;
    };
    let b = b.trim_end();
    // the longest label with the longest person noun is 30 characters
    let tail_start = b.char_indices().rev().nth(40).map_or(0, |(i, _)| i);
    let tail = fold_text(&b[tail_start..]);
    LABELS.iter().any(|label| {
        let Some(pre) = tail.strip_suffix(label) else {
            return false;
        };
        if pre.chars().next_back().is_some_and(|c| c.is_alphanumeric()) {
            return false; // "soyad" inside "xsoyad"
        }
        let trimmed = pre.trim_end();
        let gap = &pre[trimmed.len()..];
        let spaces = gap.chars().count();
        (trimmed.is_empty() && tail_start == 0)
            || trimmed.ends_with(['|', ',', ';', '('])
            || gap.contains('\t')
            || spaces >= 2
            || (spaces >= 1
                && PERSON_NOUNS.iter().any(|noun| {
                    trimmed
                        .strip_suffix(noun)
                        .is_some_and(|p| !p.chars().next_back().is_some_and(char::is_alphanumeric))
                }))
    })
}

/// Whether `before` ends with a label naming a thing and its `:`: one of
/// [`THING_LABELS`], alone or before "adı" / "ismi" ("Marka:", "Ürün
/// adı:", "Proje ismi:"). Any other "X adı:" may name a person ("Abone
/// adı:", "Aday adı:", "Yolcu adı:"; measured on the nm-kvkk train split:
/// reading every such label as a thing lost 37 names).
fn after_thing_label(before: &str) -> bool {
    let Some(b) = before.trim_end().strip_suffix(':') else {
        return false;
    };
    let b = b.trim_end();
    let tail_start = b.char_indices().rev().nth(24).map_or(0, |(i, _)| i);
    let tail = fold_text(&b[tail_start..]);
    let mut words = tail.split_whitespace().rev();
    match words.next() {
        Some(w) if THING_LABELS.contains(&w) => true,
        Some("adi" | "ismi") => words.next().is_some_and(|w| THING_LABELS.contains(&w)),
        _ => false,
    }
}

/// Folded locative and ablative suffixes ("'da", "'ndan", "'teki"): a
/// place takes them far more often than a person.
fn locative(suffix: &str) -> bool {
    let s = fold_text(suffix);
    let s = s.strip_prefix('n').unwrap_or(&s);
    matches!(
        s,
        "da" | "de"
            | "ta"
            | "te"
            | "dan"
            | "den"
            | "tan"
            | "ten"
            | "daki"
            | "deki"
            | "taki"
            | "teki"
    )
}

/// The context of one candidate run `toks[i..=j]` on `line`.
struct Ctx<'a> {
    line: &'a str,
    toks: &'a [Tok],
}

impl Ctx<'_> {
    fn gap(&self, a: usize, b: usize) -> &str {
        &self.line[self.toks[a].full_end..self.toks[b].start]
    }

    /// The word before `i` when only whitespace or a dot separates them
    /// and it carries no suffix.
    fn prev(&self, i: usize) -> Option<&Tok> {
        let p = i.checked_sub(1)?;
        (space_or_dot(self.gap(p, i)) && !self.toks[p].suffixed()).then(|| &self.toks[p])
    }

    /// The word right before `i` (one space).
    fn adjacent_prev(&self, i: usize) -> Option<&Tok> {
        let p = i.checked_sub(1)?;
        single_space(self.gap(p, i)).then(|| &self.toks[p])
    }

    /// The word right after `j` (one space) when `j` has no suffix.
    fn adjacent_next(&self, j: usize) -> Option<&Tok> {
        let n = j + 1;
        (n < self.toks.len() && !self.toks[j].suffixed() && single_space(self.gap(j, n)))
            .then(|| &self.toks[n])
    }

    /// Whether an organisation or address word follows the run ending at
    /// `j` (after an optional post-honorific at `k`): up to three
    /// capitalized words within [`ORG_REACH`] characters.
    fn org_follows(&self, j: usize, k: usize) -> bool {
        let last = &self.toks[j];
        if last.suffixed() {
            return false;
        }
        for k2 in k..self.toks.len().min(k + 3) {
            let t = &self.toks[k2];
            if !t.capitalized()
                || !space_or_dot(self.gap(k2 - 1, k2))
                || self.line[last.full_end..t.start].chars().count() > ORG_REACH
            {
                return false;
            }
            if t.is(Flags::ORG) || (t.key_len == 1 && self.is_as(t.start)) {
                return true;
            }
            if t.suffixed() {
                return false;
            }
        }
        false
    }

    /// "A.Ş." (or "A.Ş", "A.S.") at `at`.
    fn is_as(&self, at: usize) -> bool {
        let s: String = self.line[at..]
            .chars()
            .take(4)
            .filter(|&c| c != ' ')
            .collect();
        matches!(s.as_str(), "A.Ş." | "A.Ş" | "A.S.")
    }

    /// Whether the run at `i` is the next item of a list whose previous
    /// item was claimed (`last` is the last word of the previous claim):
    /// "Deniz Kaya, Umut Doğan", "Ayşe Kaya ve Umut Doğan". Without it,
    /// only the first item of "cc: Deniz Kaya, Umut Doğan, Barış
    /// Güneş" would be masked.
    fn listed(&self, i: usize, last: Option<usize>) -> bool {
        let Some(last) = last else {
            return false;
        };
        if last + 1 == i {
            return matches!(self.gap(last, i).trim(), "," | ";");
        }
        if last + 2 == i {
            let joiner = &self.toks[last + 1];
            return single_space(self.gap(last, last + 1))
                && single_space(self.gap(last + 1, i))
                && LIST_JOINERS.contains(&&self.line[joiner.start..joiner.full_end]);
        }
        false
    }

    /// Widens an accepted claim `toks[i..=j]` so that a name is masked
    /// whole: `(first, last)` word indices. To the left, a last name
    /// written before a comma ("Yılmaz, Ahmet", the surname-first list
    /// form) that starts the line or a field and is not part of the
    /// previous claim (`claimed`); to the right, a Title-case word outside
    /// the lexicon after a given name ("Ahmet Xyzoğlu"), within the run
    /// bound.
    fn widen(&self, i: usize, j: usize, claimed: Option<usize>) -> (usize, usize) {
        let toks = self.toks;
        let mut first = i;
        if i >= 1 && claimed != Some(i - 1) {
            let p = &toks[i - 1];
            let starts_field = i == 1 || !single_space(self.gap(i - 2, i - 1));
            if matches!(self.gap(i - 1, i), ", " | ",")
                && starts_field
                && p.capitalized()
                && p.is(Flags::LAST)
                && (p.strong() || p.is(Flags::COMMON))
                && !p.is(Flags::PROPER)
                && !p.context_word()
                && !p.suffixed()
                && p.key_len <= MAX_KEY
            {
                first = i - 1;
            }
        }
        let mut last = j;
        let end = &toks[j];
        if j + 1 < toks.len()
            && j + 1 - first < MAX_RUN
            && !end.suffixed()
            && end.flags.has(Flags::FIRST | Flags::FIRST_PRIMARY)
            && name_gap(self.gap(j, j + 1))
        {
            let next = &toks[j + 1];
            let after_capitalized = j + 2 < toks.len()
                && !next.suffixed()
                && single_space(self.gap(j + 1, j + 2))
                && toks[j + 2].capitalized();
            // a plural-possessive noun is no surname ("Ülkü Ocakları")
            let noun = fold_text(&self.line[next.start..next.end]);
            let noun = noun.ends_with("lari") || noun.ends_with("leri");
            if next.unknown_name_shape() && !after_capitalized && !noun {
                last = j + 1;
            }
        }
        (first, last)
    }

    /// The scanner's decision for the run `toks[i..=j]`, with its score.
    fn decide_run(
        &self,
        i: usize,
        j: usize,
        field: bool,
        listed: bool,
        before: &str,
    ) -> Option<f32> {
        let toks = self.toks;
        let (head, last) = (&toks[i], &toks[j]);
        let prev = self.prev(i);
        let mut k = j + 1;
        let mut hon_post = false;
        if let Some(next) = self.adjacent_next(j) {
            if next.is(Flags::POST_HONORIFIC) {
                hon_post = true;
                k += 1;
            }
        }
        let touches_slash =
            self.line[..head.start].ends_with('/') || self.line[last.full_end..].starts_with('/');
        if self.org_follows(j, k) || touches_slash {
            return None;
        }
        let hon = hon_post
            || prev.is_some_and(|p| {
                p.is(Flags::PRE_HONORIFIC) || (p.is(Flags::GREETING) && head.is(Flags::FIRST))
            });
        let adj_prev = self.adjacent_prev(i).filter(|p| !p.suffixed());
        let mid = adj_prev.is_some_and(|p| p.case == Case::Lower);
        let phrase = adj_prev.is_some_and(|p| p.capitalized() && !p.is(Flags::PRE_HONORIFIC))
            || self
                .adjacent_next(j)
                .is_some_and(|n| n.capitalized() && !n.is(Flags::POST_HONORIFIC));
        let rest = self.line[last.full_end..].trim_start_matches(' ');
        // the value ends at a separator, the line end, or a sentence-final
        // dot ("çalışan: Şadan Tekin. ...")
        let value_ends = rest
            .chars()
            .next()
            .map_or(true, |c| matches!(c, '|' | ',' | ';' | '(' | ')' | '\r'))
            || rest
                .strip_prefix('.')
                .is_some_and(|r| r.is_empty() || r.starts_with(' '));
        let whole_value = before.trim_end_matches(' ').ends_with(':') && value_ends;
        if j > i {
            let first = head.is(Flags::FIRST);
            if first && head.strong() {
                return Some(SCORE_CUE);
            }
            if hon || field {
                return Some(SCORE_CUE);
            }
            let title = head.case == Case::Title;
            if first
                && title
                && !phrase
                && ((head.is(Flags::COMMON) && toks[i + 1..=j].iter().any(Tok::strong))
                    || (last.is(Flags::LAST) && (mid || whole_value || listed)))
            {
                return Some(SCORE_PLAIN);
            }
            return None;
        }
        let t = head;
        if hon && (!t.is(Flags::FREQUENT_WORD) || t.is(Flags::COMMON)) {
            return Some(SCORE_CUE);
        }
        if field && (!t.is(Flags::FREQUENT_WORD) || whole_value) {
            return Some(SCORE_CUE);
        }
        if t.suffixed() {
            let apostrophe = if t.joined {
                0
            } else {
                self.line[t.end..].chars().next().map_or(1, char::len_utf8)
            };
            // a joined suffix alone counts only mid-sentence: at a line
            // or sentence start it is mostly a capitalized word
            // ("Malike", "Bilgini", "Rızanın"; measured on the nm-kvkk
            // train split: +111 false positives, no true positive)
            if t.strong()
                && (!t.joined || mid)
                && !locative(&self.line[t.end + apostrophe..t.full_end])
            {
                return Some(SCORE_PLAIN);
            }
        }
        let plain_first = t.flags.has(Flags::FIRST | Flags::FIRST_PRIMARY)
            && !t.is(Flags::FREQUENT_WORD | Flags::PROPER)
            && t.case == Case::Title;
        if plain_first && ((mid && t.is(Flags::COMMON)) || (t.strong() && !t.is(Flags::DICTIONARY)))
        {
            return Some(SCORE_PLAIN);
        }
        None
    }

    /// The decision for a word `i` outside the lexicon (module doc):
    /// `Some((end, score, next))` with the claimed span end, its score and
    /// the index to continue from.
    fn decide_unknown(&self, i: usize, field: bool) -> Option<(usize, f32, usize)> {
        let toks = self.toks;
        let t = &toks[i];
        if field
            && t.capitalized()
            && t.key_len >= 2
            && !t.is(Flags::FREQUENT_WORD | Flags::PROPER)
            && !t.context_word()
        {
            // the whole value: following capitalized words of the same
            // field join ("Adı: Jean Dupont"), so no part stays visible
            let mut j = i;
            while j + 1 < toks.len()
                && j - i + 1 < MAX_RUN
                && !toks[j].suffixed()
                && name_gap(self.gap(j, j + 1))
            {
                let next = &toks[j + 1];
                if !next.capitalized()
                    || next.key_len > MAX_KEY
                    || next.is(Flags::FREQUENT_WORD | Flags::PROPER)
                    || next.context_word()
                {
                    break;
                }
                j += 1;
            }
            return Some((toks[j].end, SCORE_CUE, j + 1));
        }
        if !t.unknown_name_shape() {
            return None;
        }
        let honorific_before = self.prev(i).is_some_and(|p| p.is(Flags::PRE_HONORIFIC));
        if !t.suffixed() && i + 1 < toks.len() && name_gap(self.gap(i, i + 1)) {
            let next = &toks[i + 1];
            let after =
                (i + 2 < toks.len() && !next.suffixed() && single_space(self.gap(i + 1, i + 2)))
                    .then(|| &toks[i + 2]);
            let phrase = self
                .adjacent_prev(i)
                .is_some_and(|p| p.capitalized() && !p.is(Flags::PRE_HONORIFIC))
                || after.is_some_and(|a| a.capitalized() && !a.is(Flags::POST_HONORIFIC));
            let org = after.is_some_and(|a| a.is(Flags::ORG));
            if next.case == Case::Title
                && next.is(Flags::LAST)
                && next.key_len <= MAX_KEY
                && (next.strong() || honorific_before)
                && !phrase
                && !org
            {
                return Some((next.end, SCORE_PLAIN, i + 2));
            }
        }
        if honorific_before {
            return Some((t.end, SCORE_CUE, i + 1));
        }
        None
    }
}

/// Scans one line and appends each person name as `(start, end, score)`
/// byte offsets into `line` (module doc).
pub(crate) fn scan_line(line: &str, out: &mut Vec<(usize, usize, f32)>) {
    // a line without an uppercase letter holds no candidate
    if !line.chars().any(char::is_uppercase) {
        return;
    }
    let mut toks = Vec::new();
    tokenize(line, &mut toks);
    let ctx = Ctx { line, toks: &toks };
    let n = toks.len();
    // the last word of the previous claim (list items, left widening)
    let mut claimed: Option<usize> = None;
    let mut i = 0;
    while i < n {
        let t = &toks[i];
        let before = &line[..t.start];
        // the label checks read back from the word: only for capitalized
        // words that could start a name
        let field = t.capitalized() && after_name_label(before);
        if t.capitalized() && !field && after_thing_label(before) {
            i += 1;
            continue;
        }
        if !t.name_word() || t.key_len > MAX_KEY {
            match ctx.decide_unknown(i, field) {
                Some((end, score, next)) => {
                    out.push((t.start, end, score));
                    claimed = Some(next - 1);
                    i = next;
                }
                None => i += 1,
            }
            continue;
        }
        let mut j = i;
        while j + 1 < n && j - i + 1 < MAX_RUN && !toks[j].suffixed() {
            let (gap, next) = (ctx.gap(j, j + 1), &toks[j + 1]);
            let joins = name_gap(gap) || (table_gap(gap) && next.is(Flags::LAST));
            if !joins
                || !next.name_word()
                || next.key_len > MAX_KEY
                || !(next.case == t.case || (t.case == Case::Title && next.case == Case::Upper))
            {
                break;
            }
            j += 1;
        }
        let listed = ctx.listed(i, claimed);
        match ctx.decide_run(i, j, field, listed, before) {
            Some(score) => {
                let (first, last) = ctx.widen(i, j, claimed);
                out.push((toks[first].start, toks[last].end, score));
                claimed = Some(last);
                i = last + 1;
            }
            None => i += 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{after_name_label, scan_line};

    fn names(line: &str) -> Vec<&str> {
        let mut out = Vec::new();
        scan_line(line, &mut out);
        out.iter().map(|&(s, e, _)| &line[s..e]).collect()
    }

    #[test]
    fn full_names_in_free_text() {
        assert_eq!(
            names("Bu rapor Ayşe Demir tarafından hazırlandı."),
            ["Ayşe Demir"]
        );
        assert_eq!(names("Ahmet Yılmaz bugün aradı."), ["Ahmet Yılmaz"]);
        assert_eq!(
            names("Şefika Zeynep Aydoğdu adlı kişi"),
            ["Şefika Zeynep Aydoğdu"]
        );
        assert_eq!(names("Can Ece Sevinç geldi"), ["Can Ece Sevinç"]);
    }

    #[test]
    fn case_variants() {
        assert_eq!(names("imza: Ahmet YILMAZ"), ["Ahmet YILMAZ"]);
        assert_eq!(names("AHMET YILMAZ başvurdu"), ["AHMET YILMAZ"]);
        // a single all-caps word needs a suffix or a cue
        assert_eq!(names("AHMET'in dosyası"), ["AHMET"]);
        assert!(names("ACİL DURUM").is_empty());
    }

    #[test]
    fn suffixes_stay_outside_the_span() {
        assert_eq!(names("Dosya Ahmet'in masasında."), ["Ahmet"]);
        assert_eq!(names("Bunu Ayşe'ye ilet."), ["Ayşe"]);
        assert_eq!(names("Ahmet Yılmaz'ın telefonu"), ["Ahmet Yılmaz"]);
        assert_eq!(names("dosyayı Ayşe’ye verdim"), ["Ayşe"]);
        // a locative suffix alone marks a place, not a person
        assert!(names("İzmir Alsancak'ta yeni ofis").is_empty());
    }

    #[test]
    fn joined_suffixes_keep_the_stem_only() {
        assert_eq!(names("dosya Ahmetin masasında"), ["Ahmet"]);
        assert_eq!(names("bunu Ayşeye ilet"), ["Ayşe"]);
        // softened final consonant: Mehmet + e
        assert_eq!(names("bunu Mehmede söyledim"), ["Mehmed"]);
        // inside a run the joined suffix ends the name at any position
        assert_eq!(names("Ahmet Yılmazın telefonu"), ["Ahmet Yılmaz"]);
        // dictionary words with a suffix, plural place names, and a lone
        // joined form at a line start (mostly a capitalized word there)
        for text in [
            "Kalemin ucu kırık",
            "Demirin fiyatı",
            "Erenler'e gittik",
            "Malike sunulur.",
        ] {
            assert!(names(text).is_empty(), "{text:?}");
        }
        // a strong first name counts at a line start like its bare form
        assert_eq!(names("Ahmetin dosyası hazır"), ["Ahmet"]);
    }

    #[test]
    fn honorifics_and_greetings() {
        assert_eq!(names("Sayın Yılmaz, başvurunuz alındı."), ["Yılmaz"]);
        assert_eq!(names("Kaya Bey toplantıda"), ["Kaya"]);
        assert_eq!(names("Dr. Neval Dinçer muayene etti"), ["Neval Dinçer"]);
        assert_eq!(names("Merhaba Demet, nasılsın?"), ["Demet"]);
        // an unknown word after a title still counts
        assert_eq!(names("Av. Zühtü geldi"), ["Zühtü"]);
        // but not a frequent word
        assert!(names("Sayın İlgili,").is_empty());
    }

    #[test]
    fn name_labels() {
        assert_eq!(names("Soyadı: Hocaoğlu"), ["Hocaoğlu"]);
        assert_eq!(names("Kızlık Soyadı: Çulçu"), ["Çulçu"]);
        assert_eq!(names("Hasta adı: Feride"), ["Feride"]);
        // "adı:" after a thing is not a name label
        assert!(names("Kampanya adı: Bahar Dönemi").is_empty());
        assert!(after_name_label("Adı Soyadı: "));
        assert!(after_name_label("No: 5 | Soyadı: "));
        assert!(!after_name_label("Proje adı: "));
        assert!(!after_name_label("Soyadı"));
    }

    #[test]
    fn organisations_and_addresses_are_not_names() {
        assert!(names("Ahmet Yılmaz Holding hisseleri").is_empty());
        assert!(names("Ahmet Yılmaz Portföy Yönetimi A.Ş. açıkladı").is_empty());
        assert!(names("Fevzi Çakmak Caddesi No: 5").is_empty());
        assert!(names("Mimar Sinan Güzel Sanatlar Üniversitesi").is_empty());
        assert!(names("adres: Merkez Mah. Fatih/İstanbul").is_empty());
    }

    #[test]
    fn words_that_are_names_need_more_evidence() {
        // frequent words alone at a line start
        assert!(names("Deniz kenarında yürüdük.").is_empty());
        assert!(names("Umut verici bir gelişme.").is_empty());
        assert!(names("Ayda bir kez toplanır.").is_empty());
        assert!(names("Türk lirası ile ödenir.").is_empty());
        // a Title Case heading of words
        assert!(names("İsabetli Serbest Atış: 2").is_empty());
        // but a capitalized pair mid-sentence is a name
        assert_eq!(names("dosyada Deniz Kaya imzalı"), ["Deniz Kaya"]);
    }

    #[test]
    fn unknown_first_name_before_a_strong_surname() {
        // "Yağızalp" (a recent compound name) is not in the lexicon
        assert_eq!(
            names("Bu plan, Yağızalp Öztürk tarafından"),
            ["Yağızalp Öztürk"]
        );
        // a dictionary word ("cebbar", tyrant) that is also a rare name
        // does not start a name at a sentence start
        assert!(names("Bu plan, Cebbar Öztürk tarafından").is_empty());
    }

    #[test]
    fn english_and_benign_text_stays_clean() {
        for text in [
            "Can you help me with this?",
            "The quick brown fox jumps over the lazy dog",
            "Sipariş numaranız 12000345671 olarak kaydedildi.",
            "merhaba dunya bugun hava cok guzel",
            "LUTFEN bu metni Turkceye cevir",
            "",
            "   ",
        ] {
            assert!(names(text).is_empty(), "{text:?}");
        }
    }

    #[test]
    fn a_name_is_masked_whole_across_separators() {
        // never the first name alone with the surname visible
        for (text, want) in [
            ("Ahmet\tYılmaz\t12345678950", "Ahmet\tYılmaz"),
            ("Ahmet;Yılmaz;12345678950", "Ahmet;Yılmaz"),
            ("Ahmet,Yılmaz,12345678950", "Ahmet,Yılmaz"),
            ("Ahmet  Yılmaz geldi", "Ahmet  Yılmaz"),
            ("Ahmet\u{2009}Yılmaz geldi", "Ahmet\u{2009}Yılmaz"),
            ("Ahmet\u{3000}Yılmaz geldi", "Ahmet\u{3000}Yılmaz"),
            ("Ahmet_Yilmaz geldi", "Ahmet_Yilmaz"),
            ("AHMET\tYILMAZ", "AHMET\tYILMAZ"),
            ("Ayşe Yılmaz-Kaya geldi", "Ayşe Yılmaz-Kaya"),
            ("Ayşe-Nur Demir geldi", "Ayşe-Nur Demir"),
            ("Ahmet YILMAZ-ÖZTÜRK", "Ahmet YILMAZ-ÖZTÜRK"),
            ("Yılmaz, Ahmet", "Yılmaz, Ahmet"),
            ("dün Ahmet Yağızalp geldi", "Ahmet Yağızalp"),
            // a name label claims its whole value, also outside the lexicon
            ("Adı: Jean Dupont", "Jean Dupont"),
        ] {
            assert_eq!(names(text), [want], "{text:?}");
        }
        // a union with a two-letter part is no hyphenated name, and a
        // kinship word stays outside the name
        assert_eq!(names("Ahmet Yılmaz Türk-İş üyesi"), ["Ahmet Yılmaz"]);
        assert_eq!(names("Sevgili Necla Teyze'nin hesabı"), ["Necla"]);
        // a comma with a space is a list, not a table cell
        assert_eq!(names("dün Ayşe, Fatma ve Zeynep geldi").len(), 3);
    }

    #[test]
    fn every_list_item_is_evaluated() {
        assert_eq!(
            names("cc: Deniz Kaya, Umut Doğan, Barış Güneş"),
            ["Deniz Kaya", "Umut Doğan", "Barış Güneş"]
        );
        assert_eq!(
            names("Katılımcılar: Ahmet Yılmaz, Umut Doğan ve Bahar Kaya"),
            ["Ahmet Yılmaz", "Umut Doğan", "Bahar Kaya"]
        );
    }

    #[test]
    fn product_hospital_market_and_shop_names_are_not_persons() {
        for text in [
            "Ürün adı: Sultan Çay",
            "Marka: Selin Kaya",
            "Kanuni Sultan Süleyman Hastanesi",
            "Ali Paşa Çarşısı",
            "Selin Ofis Mobilyaları",
        ] {
            assert!(names(text).is_empty(), "{text:?}: {:?}", names(text));
        }
    }

    #[test]
    fn runs_hold_at_most_four_words() {
        let found = names("Ahmet Mehmet Ali Veli Hasan");
        assert!(found.iter().all(|n| n.split(' ').count() <= 4), "{found:?}");
    }

    #[test]
    fn spans_are_on_char_boundaries_for_any_input() {
        // multi-byte letters, combining marks and stray apostrophes
        for text in [
            "İ\u{307}smail Öz'",
            "’Ayşe’’",
            "Ş'ş Ğ-ğ -Ahmet- 'Ali'",
            "a\u{307}\u{307} Ç\u{307}",
        ] {
            let mut out = Vec::new();
            scan_line(text, &mut out);
            for (s, e, _) in out {
                assert!(text.is_char_boundary(s) && text.is_char_boundary(e) && s < e);
            }
        }
    }
}
