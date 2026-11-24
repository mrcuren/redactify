//! The lexicon behind the label-free Turkish person-name scanner
//! ([`super::person`]): one open-addressing hash table from a folded word
//! to its evidence flags, built once from three compiled-in data files.
//!
//! Data (each file holds `@flags` section lines followed by one folded
//! key per line; see `person_lexicon.SOURCES.md` for provenance, licences
//! and checksums):
//!
//! - `person_names.txt`: 33,861 first and last names with population
//!   frequency classes, built from `mkozturk/trnames` (MIT License);
//! - `person_words.txt`: 15,330 words with word evidence (frequent
//!   lowercase word, dictionary headword, inflected dictionary word,
//!   proper noun), derived from Zemberek-NLP (Apache License 2.0);
//! - `person_context.txt`: honorifics, greetings and organisation or
//!   address words (project-curated).
//!
//! Keys are **folded**: lowercase ASCII with the Turkish letters mapped to
//! their base letter (`ç`→`c`, `ğ`→`g`, `ı`/`İ`/`I`→`i`, `ö`→`o`,
//! `ş`→`s`, `ü`→`u`, circumflexes dropped), because the name source is
//! itself folded ("YUKSEL" for "Yüksel"). Folding merges a few pairs
//! ("Can" and the district "Çan"); the word evidence then applies to both.
//!
//! Cost: the table is built on first use (one pass over the 0.4 MB blob,
//! no per-key allocation: each slot packs the key's byte offset in the blob
//! and its flags into one `u32`), so its heap is one `Box<[u32]>` of
//! 65,536 slots (256 KiB) for the whole process; a lookup folds the token
//! into a stack buffer, hashes it once (FNV-1a) and probes linearly, O(1)
//! expected per token.
//!
//! Overhead (release build, against the tree without the scanner): the
//! first `detect` call takes about 2 ms longer (8.8-9.7 ms against
//! 6.8-7.7 ms; regexes and table are built lazily), peak RSS of the bench
//! process grows by about 1 MB, and the release CLI binary by 339,048
//! bytes.

use std::sync::LazyLock;

/// The three data files as one blob (each file ends with a newline).
const DATA: &str = concat!(
    include_str!("person_names.txt"),
    include_str!("person_words.txt"),
    include_str!("person_context.txt"),
);

/// Longest folded key the lexicon holds (bytes = characters, ASCII);
/// longer tokens are never looked up.
pub(super) const MAX_KEY: usize = 20;

/// Number of low bits of a slot that hold the flags; the byte offset of
/// the key (plus one, so `0` marks an empty slot) sits above them.
const FLAG_BITS: u32 = 12;

/// The evidence flags of one folded key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Flags(u16);

impl Flags {
    /// A first name (`F`).
    pub(super) const FIRST: u16 = 1;
    /// A last name (`L`).
    pub(super) const LAST: u16 = 1 << 1;
    /// A common name: population share at least 1e-4 as a first or as a
    /// last name (`c`).
    pub(super) const COMMON: u16 = 1 << 2;
    /// A first name at least as frequent as the same last name (`p`).
    pub(super) const FIRST_PRIMARY: u16 = 1 << 3;
    /// Among the 10,000 most frequent tokens in its lowercase form (`w`).
    pub(super) const FREQUENT_WORD: u16 = 1 << 4;
    /// A dictionary headword (`m`).
    pub(super) const DICTIONARY: u16 = 1 << 5;
    /// A dictionary word plus a case or derivational suffix (`i`).
    pub(super) const INFLECTED: u16 = 1 << 6;
    /// A proper noun that is not (only) a person name: a place, a
    /// nationality, a month (`n`).
    pub(super) const PROPER: u16 = 1 << 7;
    /// An organisation or address word ("Holding", "Caddesi") (`o`).
    pub(super) const ORG: u16 = 1 << 8;
    /// An honorific or title before a name ("Sayın", "Dr") (`h`).
    pub(super) const PRE_HONORIFIC: u16 = 1 << 9;
    /// An honorific after a name ("Bey", "Hanım") (`b`).
    pub(super) const POST_HONORIFIC: u16 = 1 << 10;
    /// A greeting before a first name ("Merhaba", "Sevgili") (`g`).
    pub(super) const GREETING: u16 = 1 << 11;

    /// The flags of the given bits (the constants above).
    pub(super) const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// The raw bits.
    pub(super) const fn bits(self) -> u16 {
        self.0
    }

    /// Whether every bit of `bits` is set.
    pub(super) const fn has(self, bits: u16) -> bool {
        self.0 & bits == bits
    }

    /// Whether any bit of `bits` is set.
    pub(super) const fn any(self, bits: u16) -> bool {
        self.0 & bits != 0
    }

    /// The flags named by the letters of an `@` section line.
    fn parse(letters: &str) -> Self {
        Self(letters.bytes().fold(0, |acc, b| {
            acc | match b {
                b'F' => Self::FIRST,
                b'L' => Self::LAST,
                b'c' => Self::COMMON,
                b'p' => Self::FIRST_PRIMARY,
                b'w' => Self::FREQUENT_WORD,
                b'm' => Self::DICTIONARY,
                b'i' => Self::INFLECTED,
                b'n' => Self::PROPER,
                b'o' => Self::ORG,
                b'h' => Self::PRE_HONORIFIC,
                b'b' => Self::POST_HONORIFIC,
                b'g' => Self::GREETING,
                _ => panic!("unknown lexicon flag {:?}", char::from(b)),
            }
        }))
    }
}

/// The hash table: `slots[i]` is `0` (empty) or `((offset + 1) <<
/// FLAG_BITS) | flags`, where `offset` is the byte offset of the key's
/// line in [`DATA`].
struct Table {
    slots: Box<[u32]>,
}

static TABLE: LazyLock<Table> = LazyLock::new(Table::build);

/// FNV-1a, 32 bits (deterministic: the keys are fixed and an input token
/// can only probe, never insert, so the probe lengths are fixed by the
/// data).
fn hash(key: &[u8]) -> u32 {
    key.iter().fold(0x811c_9dc5, |h: u32, &b| {
        (h ^ u32::from(b)).wrapping_mul(0x0100_0193)
    })
}

/// The key stored at a non-empty slot.
fn key_at(slot: u32) -> &'static [u8] {
    let start = (slot >> FLAG_BITS) as usize - 1;
    let rest = &DATA.as_bytes()[start..];
    let len = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
    &rest[..len]
}

impl Table {
    fn build() -> Self {
        let keys = DATA
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with(['#', '@']))
            .count();
        // load factor at most 5/8 (duplicate keys across files make the
        // real factor lower)
        let mut slots = vec![0u32; (keys * 8 / 5).next_power_of_two()].into_boxed_slice();
        let mask = slots.len() - 1;
        assert!(
            DATA.len() < (1 << (32 - FLAG_BITS)),
            "lexicon blob too large"
        );
        let mut flags = Flags::default();
        let mut offset = 0usize;
        for line in DATA.split_inclusive('\n') {
            let key = line.trim_end_matches('\n');
            if let Some(letters) = key.strip_prefix('@') {
                flags = Flags::parse(letters);
            } else if !key.is_empty() && !key.starts_with('#') {
                let mut i = hash(key.as_bytes()) as usize & mask;
                loop {
                    let slot = slots[i];
                    if slot == 0 {
                        // offset < 2^20 (asserted above): the shift cannot overflow
                        let at = u32::try_from(offset + 1).expect("offset fits");
                        slots[i] = (at << FLAG_BITS) | u32::from(flags.0);
                        break;
                    }
                    if key_at(slot) == key.as_bytes() {
                        slots[i] = slot | u32::from(flags.0);
                        break;
                    }
                    i = (i + 1) & mask;
                }
            }
            offset += line.len();
        }
        Self { slots }
    }

    fn get(&self, key: &[u8]) -> Flags {
        let mask = self.slots.len() - 1;
        let mut i = hash(key) as usize & mask;
        loop {
            let slot = self.slots[i];
            if slot == 0 {
                return Flags::default();
            }
            if key_at(slot) == key {
                // the low FLAG_BITS bits are the flags
                return Flags((slot & ((1 << FLAG_BITS) - 1)) as u16);
            }
            i = (i + 1) & mask;
        }
    }
}

/// The evidence flags of an already folded key (empty flags when the key
/// is not in the lexicon).
pub(super) fn lookup(key: &[u8]) -> Flags {
    if key.is_empty() || key.len() > MAX_KEY {
        return Flags::default();
    }
    TABLE.get(key)
}

/// The folded form of one Turkish letter (module doc), `None` for a
/// character the lexicon cannot hold (a digit, a letter outside the
/// Turkish alphabet). U+0307 (the combining dot `to_lowercase` leaves
/// after `İ`) folds to nothing (`Some(None)`).
fn fold_char(c: char) -> Option<Option<u8>> {
    Some(Some(match c {
        'a'..='z' => c as u8,
        'A'..='Z' => c.to_ascii_lowercase() as u8,
        'ç' | 'Ç' => b'c',
        'ğ' | 'Ğ' => b'g',
        'ı' | 'İ' => b'i',
        'ö' | 'Ö' => b'o',
        'ş' | 'Ş' => b's',
        'ü' | 'Ü' => b'u',
        'â' | 'Â' => b'a',
        'î' | 'Î' => b'i',
        'û' | 'Û' => b'u',
        '\u{307}' => return Some(None),
        _ => return None,
    }))
}

/// Folds `word` into `buf` (module doc): the folded key, or `None` when a
/// character cannot be folded or the key is longer than [`MAX_KEY`].
pub(super) fn fold<'b>(word: &str, buf: &'b mut [u8; MAX_KEY]) -> Option<&'b [u8]> {
    let mut n = 0;
    for c in word.chars() {
        if let Some(b) = fold_char(c)? {
            *buf.get_mut(n)? = b;
            n += 1;
        }
    }
    Some(&buf[..n])
}

#[cfg(test)]
mod tests {
    use super::{fold, lookup, Flags, MAX_KEY, TABLE};

    fn flags(word: &str) -> Flags {
        let mut buf = [0; MAX_KEY];
        fold(word, &mut buf).map_or_else(Flags::default, lookup)
    }

    #[test]
    fn folding_maps_turkish_letters_to_their_base() {
        let mut buf = [0; MAX_KEY];
        assert_eq!(fold("Yüksel", &mut buf), Some(&b"yuksel"[..]));
        assert_eq!(fold("ÇAĞLAR", &mut buf), Some(&b"caglar"[..]));
        assert_eq!(fold("Işık", &mut buf), Some(&b"isik"[..]));
        // the decomposed dotted capital (I + U+0307) folds like İ
        assert_eq!(fold("I\u{307}smail", &mut buf), Some(&b"ismail"[..]));
        assert_eq!(fold("İSMAİL", &mut buf), Some(&b"ismail"[..]));
        assert_eq!(fold("Hâkim", &mut buf), Some(&b"hakim"[..]));
        assert_eq!(fold("José", &mut buf), None);
        assert_eq!(fold("a1", &mut buf), None);
        assert_eq!(fold(&"a".repeat(MAX_KEY + 1), &mut buf), None);
    }

    #[test]
    fn lexicon_holds_the_expected_evidence() {
        let ahmet = flags("Ahmet");
        assert!(ahmet.has(Flags::FIRST | Flags::COMMON | Flags::FIRST_PRIMARY));
        assert!(!ahmet.any(Flags::FREQUENT_WORD | Flags::DICTIONARY | Flags::PROPER));
        // Yılmaz: the most frequent surname, also a first name
        assert!(flags("YILMAZ").has(Flags::LAST | Flags::COMMON));
        // Kaya: a surname that is also a frequent word ("rock")
        assert!(flags("Kaya").has(Flags::LAST | Flags::FREQUENT_WORD));
        assert!(flags("Türkiye").has(Flags::PROPER));
        assert!(flags("Holding").has(Flags::ORG));
        assert!(flags("Sayın").has(Flags::PRE_HONORIFIC));
        assert!(flags("Hanım").has(Flags::POST_HONORIFIC));
        assert!(flags("Merhaba").has(Flags::GREETING));
        assert_eq!(flags("Xqzw"), Flags::default());
        assert_eq!(flags(""), Flags::default());
    }

    #[test]
    fn every_key_is_found_with_its_section_flags() {
        // every key line of the blob is reachable and carries (at least)
        // the flags of its section: the table neither drops nor shadows
        let mut section = Flags::default();
        let mut keys = 0;
        for line in super::DATA.lines() {
            if let Some(letters) = line.strip_prefix('@') {
                section = Flags::parse(letters);
            } else if !line.is_empty() && !line.starts_with('#') {
                assert!(
                    line.len() <= MAX_KEY && line.bytes().all(|b| b.is_ascii_lowercase()),
                    "{line:?}"
                );
                assert!(TABLE.get(line.as_bytes()).has(section.0), "{line:?}");
                keys += 1;
            }
        }
        assert!(keys > 45_000, "{keys}");
        let used = TABLE.slots.iter().filter(|&&s| s != 0).count();
        assert!(
            used * 8 <= TABLE.slots.len() * 5,
            "load {used}/{}",
            TABLE.slots.len()
        );
    }
}
