//! KVKK article 6 **special categories of personal data** ("özel nitelikli
//! kişisel veri"), detected only where the text ties them to a person.
//!
//! # Categories
//!
//! Law No. 6698 art. 6(1) lists the categories as a closed list ("ırk,
//! etnik köken, siyasi düşünce, felsefi inanç, din, mezhep veya diğer
//! inançlar, kılık ve kıyafet, dernek, vakıf ya da sendika üyeliği,
//! sağlık, cinsel hayat, ceza mahkûmiyeti ve güvenlik tedbirleriyle
//! ilgili veriler ile biyometrik ve genetik veriler";
//! <https://www.mevzuat.gov.tr/mevzuat?MevzuatNo=6698&MevzuatTur=1&MevzuatTertip=5>).
//! Each group of that list is one [`Category`] and one entity type
//! (`SPECIAL_HEALTH`, `SPECIAL_GENETIC`, `SPECIAL_BIOMETRIC`,
//! `SPECIAL_SEX_LIFE`, `SPECIAL_CRIMINAL`, `SPECIAL_BELIEF`,
//! `SPECIAL_ETHNICITY`, `SPECIAL_POLITICAL`, `SPECIAL_ATTIRE`,
//! `SPECIAL_MEMBERSHIP`); race and ethnic origin share one type, and so do
//! philosophical belief, religion, sect and other beliefs, as the law
//! groups them. The term lists (`special_terms.txt`) and their sources are
//! documented in `special_terms.SOURCES.md`.
//!
//! # Linkage (precision first)
//!
//! A bare term in general text ("diyabet hastalarında kan şekeri",
//! "cami") is not personal data: only a mention tied to a person is
//! claimed. A finding comes from one of three paths:
//!
//! 1. **Record field:** a label naming the category, then `:` and a short
//!    value ("Tanı: Tip 2 diyabet", "Kan grubu: A Rh+", "Etnik köken:
//!    ..."). The label must be the whole field label (line start, or after
//!    `|`, `;` or a tab), at most [`LABEL_MAX`] characters and six words,
//!    and end with a head phrase of the category; the value runs to the
//!    end of the field and holds at most [`FIELD_MAX`] characters. A value
//!    that only states absence ("Yok", "Bulunmamaktadır", "... değil") is
//!    left alone. The value is masked as a whole: a record field is about
//!    the record's subject.
//! 2. **Blood group:** an ABO/Rh value ("0 Rh-", "AB Rh(+)", "B pozitif")
//!    right after "kan grubu" or its possessive forms ("kan grubum", "kan
//!    grubunuz"), optionally with a `:` between (KVKK guidance: the blood
//!    group is health data); not when it is followed by "olan" ("...
//!    olanlar evrensel vericidir" describes a group of people, not a
//!    person).
//! 3. **Term with a person link:** a term of the category's list
//!    (inflected forms included) that either carries a first- or
//!    second-person suffix itself ("diyabetim", "Müslümanım",
//!    "sendikalıyım") or has, in the same sentence and within the bounded
//!    window below, a first/second-person pronoun or verb ("ben",
//!    "kullanıyorum"), a singular person noun ("hastanın", "müşteri",
//!    "eşim"), an honorific, a person name (the [`super::person`]
//!    scanner run on the window), an 11-digit run or an e-mail sign.
//!    Plural person nouns ("hastalarında") do not link. A term written in
//!    capitals is read as the person scanner reads an all-caps word: it
//!    needs stronger evidence, because headings are written so
//!    ("DİYABET YÖNETİM PLANI", "HASTA BİLGİLENDİRME: DİYABET"). A
//!    pronoun, person noun, honorific or past-tense verb alone does not
//!    link it; a person name, a present, future or necessitative
//!    first/second-person verb ("KULLANIYORUM"), an 11-digit run or an
//!    e-mail sign does ("MÜŞTERİ NURAY ÇAKIR KANSER TEDAVİSİ GÖRÜYOR").
//!
//! # Span
//!
//! The term or the field value; a case or person suffix stays visible
//! ("diyabetim" masks to "[SPECIAL_HEALTH_1]im"), as for names.
//!
//! # Streaming bound
//!
//! Every decision about a span starting at byte `p` reads the line from
//! before `p` (the field label, the link window) up to at most 128
//! characters after `p`, never further: a term is evaluated on the line
//! cut [`REACH`] characters after the matched word, and its span starts
//! at most [`MODIFIER_MAX`] characters before it (the modifiers of a
//! condition); a field value reads [`FIELD_MAX`] + 2 characters. That
//! stays below the stream guard's intra-line holdback (132 characters,
//! `policy::stream::L1_HOLDBACK`), so an emitted prefix never loses or
//! gains a finding.
//!
//! # Cost
//!
//! The engine runs one [`LineScanner`] per category (a scanner reports one
//! entity type), the ten back to back on the same line slice in
//! [`Category::ALL`] order. Each line is analysed once for all ten, at any
//! line length: the first scanner analyses it and keeps the hits in a
//! per-thread memo keyed by the slice's address and length, and each
//! following scanner reuses them only when it is the next one in that
//! order on the same slice (otherwise it analyses the line itself, so a
//! scanner called alone stays correct). The line is never copied, and the
//! last scanner releases the hits. The analysis is one Aho-Corasick pass
//! over the raw line (patterns pre-expanded to lower, upper, title and
//! diacritic-free forms, so the line is never folded) plus a label check
//! at each `:`; the windowed link check runs only for candidate terms.

use std::cell::RefCell;
use std::sync::LazyLock;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

use super::person;
use super::person_lexicon::{fold, lookup, Flags, MAX_KEY};
use crate::pii::entity::EntityType;
use crate::pii::locales::LineScanner;

/// The term lists (see `special_terms.SOURCES.md`).
const DATA: &str = include_str!("special_terms.txt");

/// Score of a blood-group value after "kan grubu".
pub(crate) const SCORE_BLOOD: f32 = 0.9;
/// Score of a record-field value and of a term with its own first- or
/// second-person suffix.
pub(crate) const SCORE_FIELD: f32 = 0.85;
/// Score of a term linked to a person by its sentence window.
pub(crate) const SCORE_LINKED: f32 = 0.75;

/// How far (characters) after a matched term's start its decision may
/// read: term, suffix, extension and the forward link window together.
/// With [`MODIFIER_MAX`] it stays below the stream guard's 132-character
/// holdback (module doc).
const REACH: usize = 96;
/// Longest run of condition modifiers (characters, with their spaces) a
/// span may take before the matched term.
const MODIFIER_MAX: usize = 32;
/// Longest record-field value (characters).
const FIELD_MAX: usize = 100;

// the streaming bound of the module doc, against the stream guard's
// 132-character intra-line holdback (`policy::stream::L1_HOLDBACK`)
const _: () = assert!(REACH + MODIFIER_MAX < 132 && FIELD_MAX + 2 < 132);
/// How far (characters) before a term the link window reaches.
const WINDOW_BACK: usize = 100;
/// Longest record-field label (characters).
const LABEL_MAX: usize = 60;
/// Longest folded suffix after a term (characters).
const SUFFIX_MAX: usize = 16;
/// Hit capacity the per-thread memo keeps between lines; a larger buffer
/// (a long, term-dense line) is released by the last scanner.
const MEMO_KEEP: usize = 256;

/// One group of KVKK art. 6(1) (module doc).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Category {
    /// Health, including disability, blood group, medication and
    /// treatment ("sağlık").
    Health,
    /// Genetic data ("genetik veri").
    Genetic,
    /// Biometric data ("biyometrik veri").
    Biometric,
    /// Sexual life ("cinsel hayat").
    SexLife,
    /// Criminal convictions and security measures ("ceza mahkûmiyeti ve
    /// güvenlik tedbirleri").
    Criminal,
    /// Philosophical belief, religion, sect or other beliefs.
    Belief,
    /// Race and ethnic origin.
    Ethnicity,
    /// Political opinion.
    Political,
    /// Appearance and dress ("kılık ve kıyafet").
    Attire,
    /// Membership of an association, foundation or trade union.
    Membership,
}

impl Category {
    /// Every category, in registration order.
    pub(crate) const ALL: [Self; 10] = [
        Self::Health,
        Self::Genetic,
        Self::Biometric,
        Self::SexLife,
        Self::Criminal,
        Self::Belief,
        Self::Ethnicity,
        Self::Political,
        Self::Attire,
        Self::Membership,
    ];

    /// The entity type the category's scanner reports.
    pub(crate) const fn kind(self) -> EntityType {
        match self {
            Self::Health => EntityType::SpecialHealth,
            Self::Genetic => EntityType::SpecialGenetic,
            Self::Biometric => EntityType::SpecialBiometric,
            Self::SexLife => EntityType::SpecialSexLife,
            Self::Criminal => EntityType::SpecialCriminal,
            Self::Belief => EntityType::SpecialBelief,
            Self::Ethnicity => EntityType::SpecialEthnicity,
            Self::Political => EntityType::SpecialPolitical,
            Self::Attire => EntityType::SpecialAttire,
            Self::Membership => EntityType::SpecialMembership,
        }
    }

    /// The scanner id reported by explanations.
    pub(crate) const fn id(self) -> &'static str {
        match self {
            Self::Health => "tr::special_health",
            Self::Genetic => "tr::special_genetic",
            Self::Biometric => "tr::special_biometric",
            Self::SexLife => "tr::special_sex_life",
            Self::Criminal => "tr::special_criminal",
            Self::Belief => "tr::special_belief",
            Self::Ethnicity => "tr::special_ethnicity",
            Self::Political => "tr::special_political",
            Self::Attire => "tr::special_attire",
            Self::Membership => "tr::special_membership",
        }
    }

    /// The category of a data-file section name.
    fn from_section(name: &str) -> Option<Self> {
        Some(match name {
            "health" => Self::Health,
            "genetic" => Self::Genetic,
            "biometric" => Self::Biometric,
            "sex_life" => Self::SexLife,
            "criminal" => Self::Criminal,
            "belief" => Self::Belief,
            "ethnicity" => Self::Ethnicity,
            "political" => Self::Political,
            "attire" => Self::Attire,
            "membership" => Self::Membership,
            _ => return None,
        })
    }

    /// The folded field-label heads of the category (module doc, path 1):
    /// a label names the category when it equals a head or ends with one
    /// after a space.
    const fn label_heads(self) -> &'static [&'static str] {
        match self {
            Self::Health => &[
                "tani",
                "tanisi",
                "teshis",
                "teshisi",
                "hastalik",
                "hastaligi",
                "hastaliklar",
                "hastaliklari",
                "rahatsizlik",
                "rahatsizligi",
                "tibbi durum",
                "tibbi durumu",
                "suregelen durum",
                "eslik eden durum",
                "klinik on bilgi",
                "tedavi protokolu",
                "tedavi yaklasimi",
                "tibbi hizmet",
                "saglik durumu",
                "kan grubu",
                "kan grubu bilgisi",
                "ilac",
                "ilaci",
                "ilaclar",
                "ilaclari",
                "ilac adi",
                "ilac tedavisi",
                "tedavi",
                "tedavisi",
                "tibbi islem",
                "tibbi islemi",
                "tibbi islemler",
                "cerrahi islem",
                "ameliyat",
                "engellilik durumu",
                "engel durumu",
                "maluliyet durumu",
                "alerji",
                "alerjiler",
                "alerjisi",
                "ruh sagligi durumu",
            ],
            Self::Genetic => &[
                "genetik veri",
                "genetik veri referansi",
                "genetik test sonucu",
                "genetik analiz sonucu",
                "genetik profil",
                "dna profili",
                "dna analizi",
            ],
            Self::Biometric => &[
                "biyometrik veri",
                "biyometrik veri referansi",
                "biyometrik veri turu",
                "biyometrik kayit",
                "biyometrik kayit referansi",
                "biyometrik kayit durumu",
                "parmak izi sablonu referansi",
                "yuz tanima kodu referansi",
                "iris tarama referansi",
                "biyometrik sablon",
                "parmak izi",
                "parmak izi sablonu",
                "yuz tanima verisi",
                "iris verisi",
            ],
            Self::SexLife => &[
                "cinsel yonelim",
                "cinsel yonelimi",
                "cinsel hayat",
                "cinsel yasam",
            ],
            Self::Criminal => &[
                "adli sicil",
                "adli sicil kaydi",
                "adli sicil durumu",
                "sabika kaydi",
                "mahkumiyet",
                "mahkumiyet durumu",
                "mahkumiyet bilgisi",
                "guvenlik tedbiri",
            ],
            Self::Belief => &[
                "din",
                "dini",
                "dini inanc",
                "dini inanci",
                "dini inanc beyani",
                "inanc beyani",
                "mezhep",
                "mezhebi",
                "felsefi inanc",
            ],
            Self::Ethnicity => &[
                "etnik koken",
                "etnik kokeni",
                "etnik koken beyani",
                "etnik kimlik",
            ],
            Self::Political => &[
                "siyasi parti",
                "siyasi gorus",
                "siyasi gorusu",
                "siyasi dusunce",
                "siyasi yonelim",
                "siyasi egilim",
                "siyasi aidiyet",
                "parti yonelimi",
                "parti uyeligi",
                "uye oldugu parti",
            ],
            Self::Attire => &["kilik kiyafet", "kilik ve kiyafet"],
            Self::Membership => &[
                "sendika",
                "sendikasi",
                "sendika uyeligi",
                "uye oldugu sendika",
                "dernek uyeligi",
                "uye oldugu dernek",
                "vakif uyeligi",
                "uye oldugu vakif",
            ],
        }
    }
}

/// The category scanners as the engine registers them, in
/// [`Category::ALL`] order.
pub(crate) fn scanners() -> [LineScanner; 10] {
    [
        scanner::<0>(),
        scanner::<1>(),
        scanner::<2>(),
        scanner::<3>(),
        scanner::<4>(),
        scanner::<5>(),
        scanner::<6>(),
        scanner::<7>(),
        scanner::<8>(),
        scanner::<9>(),
    ]
}

fn scanner<const C: usize>() -> LineScanner {
    let cat = Category::ALL[C];
    LineScanner {
        id: cat.id(),
        kind: cat.kind(),
        scan: scan_category::<C>,
    }
}

/// One finding of the line analysis (byte offsets into the line).
#[derive(Clone, Copy, Debug, PartialEq)]
struct Hit {
    cat: Category,
    start: usize,
    end: usize,
    score: f32,
}

/// `Memo::next` when no scanner may reuse the hits.
const NO_SCANNER: usize = usize::MAX;

/// The analysis of the line the category scanners are on (module doc,
/// Cost). Invariant: when `next` is not [`NO_SCANNER`], scanners
/// `0..next` have just run, back to back on this thread, on the slice
/// `key` (address, length), and `hits` is its analysis. Between two
/// consecutive scanner calls of one engine pass the slice stays borrowed,
/// so the same address and length mean the same line.
struct Memo {
    key: (usize, usize),
    next: usize,
    hits: Vec<Hit>,
}

thread_local! {
    static MEMO: RefCell<Memo> = const {
        RefCell::new(Memo {
            key: (0, 0),
            next: NO_SCANNER,
            hits: Vec::new(),
        })
    };
}

/// The scanner of category `ALL[C]`: the shared analysis, filtered.
fn scan_category<const C: usize>(line: &str, out: &mut Vec<(usize, usize, f32)>) {
    let want = Category::ALL[C];
    let emit = |hits: &[Hit], out: &mut Vec<(usize, usize, f32)>| {
        out.extend(
            hits.iter()
                .filter(|h| h.cat == want)
                .map(|h| (h.start, h.end, h.score)),
        );
    };
    let key = (line.as_ptr() as usize, line.len());
    let shared = MEMO.try_with(|memo| {
        let mut memo = memo.borrow_mut();
        let memo = &mut *memo;
        if C == 0 {
            // invalid until the analysis completes (a panic leaves no
            // half-written memo behind)
            memo.next = NO_SCANNER;
            memo.hits.clear();
            analyze(line, &mut memo.hits);
            memo.key = key;
        } else if memo.next != C || memo.key != key {
            return false;
        }
        emit(&memo.hits, out);
        if C + 1 == Category::ALL.len() {
            memo.next = NO_SCANNER;
            memo.hits.clear();
            memo.hits.shrink_to(MEMO_KEEP);
        } else {
            memo.next = C + 1;
        }
        true
    });
    // out of order (a scanner called alone), or the thread's memo is gone
    // (thread teardown): analyse the line here
    if !matches!(shared, Ok(true)) {
        let mut hits = Vec::new();
        analyze(line, &mut hits);
        emit(&hits, out);
    }
}

// ------------------------------------------------------------- lexicon

/// The term may take Turkish suffixes (otherwise only an apostrophe
/// suffix, and only on a capitalized term).
const INFLECT: u8 = 1;
/// A medication: a following dose ("1000 mg", "5 mg tablet") joins the
/// span.
const MEDICATION: u8 = 1 << 1;
/// Only a capitalized occurrence counts ("Roman" the people, not
/// "roman" the novel).
const CAPITAL: u8 = 1 << 2;
/// An origin word that counts only with a following "kökenli" ("Kafkas
/// kökenli"); every ethnicity term takes the "kökenli" into its span.
const ORIGIN: u8 = 1 << 3;
/// The blood-group cue ("kan grubu"): the value after it is the finding.
const BLOOD: u8 = 1 << 4;
/// An organisation head ("Partisi", "Derneği"): the capitalized words
/// before it are the name, and the name with the head is the term.
const ORG_HEAD: u8 = 1 << 5;
/// Membership organisation: the link window must also hold "üye".
const NEEDS_MEMBER: u8 = 1 << 6;
/// A generic word ("hastalık", "ameliyat"): only its own first or second
/// person suffix links it, never the window.
const SELF_ONLY: u8 = 1 << 7;

/// One term of the data file.
#[derive(Clone, Copy, Debug)]
struct Term {
    cat: Category,
    flags: u8,
}

/// The automaton over every pattern variant and its term table.
struct Lexicon {
    ac: AhoCorasick,
    /// Term index of each pattern.
    pattern_term: Vec<u32>,
    terms: Vec<Term>,
}

static LEXICON: LazyLock<Lexicon> = LazyLock::new(|| build_lexicon(DATA));

/// Parses the data file: `@<section> [flags]` lines (flags: `i` inflect,
/// `m` medication, `c` capital, `o` origin, `b` blood cue, `p`
/// organisation head, `u` needs "üye", `s` self only, `x` exact: a
/// no-op naming a section without `i`) and one lowercase
/// term per line.
fn build_lexicon(data: &str) -> Lexicon {
    let mut terms = Vec::new();
    let mut patterns: Vec<String> = Vec::new();
    let mut pattern_term = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut section: Option<Term> = None;
    for line in data.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(header) = line.strip_prefix('@') {
            let mut parts = header.split_whitespace();
            let cat = parts
                .next()
                .and_then(Category::from_section)
                .expect("special_terms.txt: known section");
            let mut flags = 0;
            for c in parts.next().unwrap_or("").chars() {
                flags |= match c {
                    'i' => INFLECT,
                    'm' => MEDICATION,
                    'c' => CAPITAL,
                    'o' => ORIGIN,
                    'b' => BLOOD,
                    'p' => ORG_HEAD,
                    'u' => NEEDS_MEMBER,
                    's' => SELF_ONLY,
                    'x' => 0,
                    _ => panic!("special_terms.txt: unknown flag {c}"),
                };
            }
            section = Some(Term { cat, flags });
            continue;
        }
        let term = section.expect("special_terms.txt: term before a section");
        let index = u32::try_from(terms.len()).expect("term count fits u32");
        terms.push(term);
        // a capital-only term keeps its diacritics: "Kurt" (a surname, and
        // "wolf") is not "Kürt"
        let folded = term.flags & CAPITAL == 0;
        for variant in variants(line, term.flags & INFLECT != 0, folded) {
            // the automaton is ASCII case-insensitive: one pattern per
            // ASCII-lowercased spelling
            if seen.insert(variant.to_ascii_lowercase()) {
                patterns.push(variant);
                pattern_term.push(index);
            }
        }
    }
    let ac = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::Standard)
        .build(&patterns)
        .expect("special-category patterns compile");
    Lexicon {
        ac,
        pattern_term,
        terms,
    }
}

/// The Turkish upper case of one character (`i` -> `İ`, `ı` -> `I`).
fn upper_tr(c: char) -> char {
    match c {
        'i' => 'İ',
        'ı' => 'I',
        _ => c.to_uppercase().next().unwrap_or(c),
    }
}

/// A Turkish letter folded to its base letter (`ç` -> `c`, `ı`/`İ` ->
/// `i`); other characters unchanged.
fn base_letter(c: char) -> char {
    match c {
        'ç' => 'c',
        'Ç' => 'C',
        'ğ' => 'g',
        'Ğ' => 'G',
        'ı' => 'i',
        'İ' => 'I',
        'ö' => 'o',
        'Ö' => 'O',
        'ş' => 's',
        'Ş' => 'S',
        'ü' => 'u',
        'Ü' => 'U',
        'â' => 'a',
        'î' => 'i',
        'û' => 'u',
        _ => c,
    }
}

/// The spellings a lowercase term is searched in: as written, Turkish
/// upper case, title case, and (when `folded`) without diacritics (each
/// also with the
/// final consonant softened before a vowel suffix, `k` -> `ğ`, `t` ->
/// `d`, `p` -> `b`, `ç` -> `c`, when the term inflects). The automaton is
/// ASCII case-insensitive, so ASCII case mixes need no variant.
fn variants(term: &str, inflect: bool, folded: bool) -> Vec<String> {
    let mut stems = vec![term.to_owned()];
    if inflect {
        let mut chars: Vec<char> = term.chars().collect();
        let soft = match chars.last() {
            Some('k') => Some('ğ'),
            Some('t') => Some('d'),
            Some('p') => Some('b'),
            Some('ç') => Some('c'),
            _ => None,
        };
        if let Some(soft) = soft {
            if let Some(last) = chars.last_mut() {
                *last = soft;
            }
            stems.push(chars.into_iter().collect());
        }
    }
    let mut out = Vec::new();
    for stem in stems {
        let upper: String = stem.chars().map(upper_tr).collect();
        let mut title = String::new();
        for (i, c) in stem.chars().enumerate() {
            title.push(if i == 0 { upper_tr(c) } else { c });
        }
        if folded {
            out.push(stem.chars().map(base_letter).collect());
        }
        out.extend([stem, upper, title]);
    }
    out
}

// ------------------------------------------------------------ analysis

/// Analyses one line into `hits` (module doc).
fn analyze(line: &str, hits: &mut Vec<Hit>) {
    let start = hits.len();
    if line.contains(':') {
        record_fields(line, hits);
    }
    let lexicon = &*LEXICON;
    let mut found = Vec::new();
    for m in lexicon.ac.find_overlapping_iter(line) {
        let term = lexicon.terms[lexicon.pattern_term[m.pattern().as_usize()] as usize];
        if let Some(hit) = candidate(line, m.start(), m.end(), term) {
            found.push(hit);
        }
    }
    let mut all = hits.split_off(start);
    all.extend(found);
    dedupe(all, hits);
}

/// Appends `all` to `hits`, keeping per category the earliest-starting
/// (then longest) hit of every overlapping group.
fn dedupe(mut all: Vec<Hit>, hits: &mut Vec<Hit>) {
    all.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    // in start order, a hit overlaps a kept hit of its category exactly
    // when it starts before the furthest end kept so far in that category
    // (every kept hit starts at or before it): one comparison per hit
    let mut kept_end = [0usize; Category::ALL.len()];
    for h in all {
        let end = &mut kept_end[h.cat as usize];
        if h.start >= *end {
            *end = h.end;
            hits.push(h);
        }
    }
}

/// The line cut `chars` characters after byte `at` (on a char boundary).
fn reach_end(line: &str, at: usize, chars: usize) -> usize {
    line[at..]
        .char_indices()
        .nth(chars)
        .map_or(line.len(), |(i, _)| at + i)
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '\u{307}'
}

/// Decides one automaton match `[s, e)` of `term` (module doc, paths 2
/// and 3); reads only the line up to [`REACH`] characters after `s`.
fn candidate(full: &str, s: usize, e: usize, term: Term) -> Option<Hit> {
    let line = &full[..reach_end(full, s, REACH)];
    if e > line.len() {
        return None;
    }
    let matched = &line[s..e];
    // "-Sen" joins the word before it; every other term starts a word
    if !matched.starts_with('-') && line[..s].chars().next_back().is_some_and(is_word_char) {
        return None;
    }
    let first = matched.chars().find(|c| c.is_alphabetic())?;
    if term.flags & (CAPITAL | ORG_HEAD) != 0 && !first.is_uppercase() {
        return None;
    }
    // the rest of the word after the match, then an apostrophe suffix
    let (suffix_start, suffix_end, apostrophe) = word_rest(line, e)?;
    let raw_suffix = &line[suffix_start..suffix_end];
    if matched.ends_with(|c: char| c.is_ascii_digit())
        && line[e..].starts_with(|c: char| c.is_ascii_digit())
    {
        return None;
    }
    let mut buf = [0; MAX_KEY];
    let suffix = if raw_suffix.is_empty() {
        &[][..]
    } else {
        fold(raw_suffix, &mut buf).filter(|s| s.len() <= SUFFIX_MAX)?
    };
    if term.flags & BLOOD != 0 {
        // the cue as written or with a possessive ending: "kan grubum",
        // "kan grubun", "kan grubumuz", "kan grubunuz"; any other suffix
        // ("kan grubunu", "kan grubuna") does not introduce a value
        if apostrophe || !matches!(suffix, b"" | b"m" | b"n" | b"muz" | b"nuz") {
            return None;
        }
        return blood_value(line, suffix_end);
    }
    let inflect = term.flags & INFLECT != 0;
    if !suffix.is_empty() && !inflect && !(apostrophe && first.is_uppercase()) {
        return None;
    }
    // a capital-only word joins only a person or plural suffix without an
    // apostrophe ("Romanım", "Kürtler"; not "Romanian"), and the joined
    // word must not be an ordinary word ("Lazım" is "necessary", not a
    // person of the Laz people)
    if term.flags & CAPITAL != 0 && !apostrophe && !suffix.is_empty() {
        if !personal_suffix(suffix) && !matches!(suffix, b"ler" | b"lar") {
            return None;
        }
        let mut wbuf = [0; MAX_KEY];
        let word = &line[s..suffix_end];
        if fold(word, &mut wbuf).is_some_and(|k| {
            lookup(k).any(Flags::FREQUENT_WORD | Flags::DICTIONARY | Flags::INFLECTED)
        }) {
            return None;
        }
    }
    if !suffix.is_empty() && !suffix_ok(suffix, 0) {
        return None;
    }
    let (mut start, mut end) = (s, e);
    if term.flags & ORG_HEAD != 0 {
        start = org_name_start(line, s)?;
        // "Siyasi Parti:" is a field label; "FARMASÖTİK PARTİ" a heading
        let name = &line[start..e];
        if line[suffix_end..].trim_start().starts_with(':')
            || name
                .chars()
                .filter(|c| c.is_alphabetic())
                .all(char::is_uppercase)
        {
            return None;
        }
    } else if term.cat == Category::Health && term.flags & MEDICATION == 0 {
        start = modifier_start(line, s);
    }
    let mut personal = personal_suffix(suffix);
    if suffix.is_empty() {
        if term.flags & MEDICATION != 0 {
            end = dose_end(line, e);
        }
        if term.cat == Category::Ethnicity {
            if let Some((origin_end, origin_personal)) = origin_word(line, e) {
                end = origin_end;
                personal = origin_personal;
            } else if term.flags & ORIGIN != 0 {
                return None;
            }
        }
    } else if term.flags & ORIGIN != 0 {
        return None;
    }
    if personal && term.flags & NEEDS_MEMBER == 0 {
        return Some(Hit {
            cat: term.cat,
            start,
            end,
            score: SCORE_FIELD,
        });
    }
    // generic words need their own suffix
    if term.flags & SELF_ONLY != 0 {
        return None;
    }
    // a term written in capitals may be a heading ("DİYABET YÖNETİM
    // PLANI"): it links only on strong evidence (module doc, path 3)
    let all_caps = term.flags & (CAPITAL | ORG_HEAD) == 0
        && matched.chars().filter(|c| c.is_alphabetic()).count() >= 2
        && matched
            .chars()
            .filter(|c| c.is_alphabetic())
            .all(char::is_uppercase);
    let window = Window::around(line, start, end.max(suffix_end));
    // at a sentence start every word is capitalized, so a capital-only
    // term ("Roman") proves nothing there without its own suffix
    if term.flags & CAPITAL != 0
        && !personal
        && line[window.start..start]
            .chars()
            .all(|c| !c.is_alphanumeric())
    {
        return None;
    }
    let member_ok = term.flags & NEEDS_MEMBER == 0 || window.has_member_word(line);
    let linked = match window.link(line) {
        Link::TermInName => return None,
        Link::Strong => true,
        Link::Marker => !all_caps,
        Link::None => false,
    };
    (member_ok && (personal || linked)).then_some(Hit {
        cat: term.cat,
        start,
        end,
        score: SCORE_LINKED,
    })
}

/// After a match ending at `e`: `(suffix start, suffix end, apostrophe)`
/// of the letters that continue the word, or of an apostrophe suffix.
/// `None` when the word continues with a digit.
fn word_rest(line: &str, e: usize) -> Option<(usize, usize, bool)> {
    let rest = &line[e..];
    let letters = rest
        .char_indices()
        .find(|&(_, c)| !(c.is_alphabetic() || c == '\u{307}'))
        .map_or(rest.len(), |(i, _)| i);
    if letters > 0 {
        if rest[letters..].starts_with(|c: char| c.is_ascii_digit()) {
            return None;
        }
        return Some((e, e + letters, false));
    }
    if rest.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    if let Some(after) = rest
        .strip_prefix('\'')
        .or_else(|| rest.strip_prefix('\u{2019}'))
    {
        let n = after
            .char_indices()
            .find(|&(_, c)| !c.is_alphabetic())
            .map_or(after.len(), |(i, _)| i);
        if n > 0 {
            let s = e + (rest.len() - after.len());
            return Some((s, s + n, true));
        }
    }
    Some((e, e, false))
}

/// Folded Turkish suffix morphemes (the high vowels fold to `i` and `u`):
/// plural, possessive, case, derivational `-li`/`-lik`/`-siz`/`-ci`, and
/// person and tense copulas.
const MORPHEMES: &[&str] = &[
    "ler", "lar", "leri", "lari", "im", "um", "m", "in", "un", "n", "i", "u", "si", "su", "imiz",
    "umuz", "miz", "muz", "iniz", "uniz", "niz", "nuz", "yi", "yu", "ye", "ya", "e", "a", "ne",
    "na", "ni", "nu", "nin", "nun", "de", "da", "te", "ta", "den", "dan", "ten", "tan", "nde",
    "nda", "nden", "ndan", "le", "la", "yle", "yla", "ki", "li", "lu", "lik", "luk", "siz", "suz",
    "ci", "cu", "yim", "yum", "sin", "sun", "iz", "uz", "yiz", "yuz", "dir", "dur", "tir", "tur",
    "di", "du", "ti", "tu", "ydi", "ydu", "mis", "mus", "ymis", "ymus", "ken", "yken",
];

/// Whether a folded suffix splits into at most four morphemes.
fn suffix_ok(s: &[u8], depth: usize) -> bool {
    if s.is_empty() {
        return true;
    }
    depth < 4
        && MORPHEMES.iter().any(|m| {
            s.strip_prefix(m.as_bytes())
                .is_some_and(|rest| suffix_ok(rest, depth + 1))
        })
}

/// Whether a folded suffix marks the first or second person: a first
/// person singular possessive (with an optional case: "diyabetim",
/// "kanserimden"), or a first/second person copula, optionally after
/// `-li`/`-siz`/`-ci` ("Müslümanım", "astımlıyım", "sendikalısınız").
fn personal_suffix(s: &[u8]) -> bool {
    let s = strip_any(s, &["ler", "lar"]);
    // "cezaevindeyim", "hapisteyim": a locative before the copula
    let located = strip_any(s, &["nde", "nda", "de", "da", "te", "ta"]);
    if located.len() < s.len() {
        let l = located.strip_prefix(b"y").unwrap_or(located);
        return matches!(l, b"im" | b"um" | b"sin" | b"sun" | b"siniz" | b"sunuz");
    }
    let s = strip_any(s, &["li", "lu", "ci", "cu", "siz", "suz"]);
    let s = s.strip_prefix(b"y").unwrap_or(s);
    for first in [&b"im"[..], b"um", b"m"] {
        if let Some(rest) = s.strip_prefix(first) {
            return matches!(
                rest,
                b"" | b"i"
                    | b"u"
                    | b"e"
                    | b"a"
                    | b"de"
                    | b"da"
                    | b"den"
                    | b"dan"
                    | b"in"
                    | b"un"
                    | b"le"
                    | b"la"
                    | b"dir"
                    | b"dur"
                    | b"deki"
                    | b"daki"
            );
        }
    }
    for second in [&b"sin"[..], b"sun"] {
        if let Some(rest) = s.strip_prefix(second) {
            return matches!(rest, b"" | b"iz" | b"uz");
        }
    }
    false
}

/// `s` without the first of `set` it starts with (unchanged otherwise).
fn strip_any<'a>(s: &'a [u8], set: &[&str]) -> &'a [u8] {
    set.iter()
        .find_map(|p| s.strip_prefix(p.as_bytes()))
        .unwrap_or(s)
}

/// The blood-group value after the cue word ending at `from` (module doc,
/// path 2): skips up to 24 characters of `:`, spaces, "bilgisi" and
/// "olarak", then reads `0`/`O`/`A`/`B`/`AB` and an Rh sign or word.
fn blood_value(line: &str, from: usize) -> Option<Hit> {
    let mut at = from;
    let limit = reach_end(line, from, 24);
    loop {
        let rest = &line[at..limit];
        let trimmed = rest.trim_start_matches([' ', ':', ',', '\t', '-', '\u{a0}']);
        let skipped = rest.len() - trimmed.len();
        let word = ["bilgisi", "olarak", "Bilgisi"]
            .iter()
            .find_map(|w| trimmed.strip_prefix(w))
            .map(|r| trimmed.len() - r.len());
        match (skipped, word) {
            (0, None) => break,
            (n, w) => at += n + w.unwrap_or(0),
        }
        if at >= limit {
            return None;
        }
    }
    let value_start = at;
    let rest = &line[at..];
    let group = ["AB", "A", "B", "0", "O"]
        .iter()
        .find(|g| rest.starts_with(*g))?;
    let mut pos = at + group.len();
    if line[pos..].starts_with(|c: char| c.is_alphanumeric()) {
        // "A" of "Aile", "0" of "05..." (an Rh letter is checked below)
        if !line[pos..].starts_with(['R', 'r']) {
            return None;
        }
    }
    let after_space = |p: usize| p + line[p..].len() - line[p..].trim_start_matches(' ').len();
    let mut q = after_space(pos);
    if line[q..]
        .get(..2)
        .is_some_and(|w| w.eq_ignore_ascii_case("rh"))
    {
        q = after_space(q + 2);
    }
    if let Some(sign) = ["(+)", "(-)", "+", "-", "\u{2212}"]
        .iter()
        .find(|s| line[q..].starts_with(*s))
    {
        pos = q + sign.len();
    } else {
        let word = line[q..].get(..7).map(str::to_ascii_lowercase);
        if !word.is_some_and(|w| w == "pozitif" || w == "negatif") {
            return None;
        }
        pos = q + 7;
        // "pozitifliği" and the like: not a bare value
        if line[pos..].starts_with(char::is_alphabetic) {
            return None;
        }
    }
    let tail = line[pos..].trim_start();
    let mut buf = [0; MAX_KEY];
    let next = tail
        .split(|c: char| !c.is_alphabetic())
        .next()
        .unwrap_or("");
    if fold(next, &mut buf).is_some_and(|w| w.starts_with(b"olan")) {
        return None;
    }
    Some(Hit {
        cat: Category::Health,
        start: value_start,
        end: pos,
        score: SCORE_BLOOD,
    })
}

/// The start of the capitalized organisation name before the head word
/// at `head` ("Yeni Ufuklar Partisi", "Eğitim-Sen"): up to four Title or
/// upper-case words joined by single spaces (or the hyphen of "-Sen").
fn org_name_start(line: &str, head: usize) -> Option<usize> {
    let mut start = head;
    let mut words = 0;
    let mut at = head;
    while words < 4 {
        let before = &line[..at];
        let gap = if before.ends_with(' ') || before.ends_with('-') {
            1
        } else if words == 0 && line[head..].starts_with('-') {
            0
        } else {
            break;
        };
        let word_end = at - gap;
        let word = &line[..word_end];
        let word_start = word
            .char_indices()
            .rev()
            .take_while(|&(_, c)| c.is_alphabetic() || c == '\u{307}')
            .last()
            .map(|(i, _)| i)?;
        if !line[word_start..word_end]
            .chars()
            .next()
            .is_some_and(char::is_uppercase)
        {
            break;
        }
        start = word_start;
        at = word_start;
        words += 1;
    }
    (words > 0).then_some(start)
}

/// Folded severity, type and course words a condition name takes before
/// it ("Tip 2 diyabet", "esansiyel hipertansiyon", "ileri evre ...").
const MODIFIERS: &[&str] = &[
    "agir",
    "akut",
    "esansiyel",
    "hafif",
    "kronik",
    "mevsimsel",
    "semptomatik",
    "yaygin",
];

/// The start of the condition name at `s` with the modifiers before it
/// (at most three, single spaces): [`MODIFIERS`], "tip 1"/"tip 2",
/// "ileri evre"/"ileri derece(de)", "orta düzey(de)"/"orta dereceli".
fn modifier_start(line: &str, s: usize) -> usize {
    let mut start = s;
    for _ in 0..3 {
        let Some((w1, k1)) = prev_word(line, start) else {
            break;
        };
        let pair =
            |firsts: &[&str]| prev_word(line, w1).filter(|(_, k)| firsts.contains(&k.as_str()));
        let next = if MODIFIERS.binary_search(&k1.as_str()).is_ok() {
            Some(w1)
        } else if matches!(k1.as_str(), "1" | "2") {
            pair(&["tip"]).map(|(w, _)| w)
        } else if matches!(k1.as_str(), "evre" | "derece" | "derecede") {
            pair(&["ileri"]).map(|(w, _)| w)
        } else if matches!(k1.as_str(), "duzey" | "duzeyde" | "dereceli") {
            pair(&["orta"]).map(|(w, _)| w)
        } else {
            None
        };
        match next {
            Some(w) if line[w..s].chars().count() <= MODIFIER_MAX => start = w,
            _ => break,
        }
    }
    start
}

/// The word that ends one space before byte `at`: its start and its
/// folded form (digits kept), when it is at most [`MAX_KEY`] characters.
fn prev_word(line: &str, at: usize) -> Option<(usize, String)> {
    let before = line[..at].strip_suffix(' ')?;
    let start = before
        .char_indices()
        .rev()
        .take_while(|&(_, c)| c.is_alphanumeric() || c == '̇')
        .last()
        .map(|(i, _)| i)?;
    let word = &before[start..];
    if word.chars().count() > MAX_KEY {
        return None;
    }
    if word.bytes().all(|b| b.is_ascii_digit()) {
        return Some((start, word.to_owned()));
    }
    let mut key = String::new();
    fold_phrase(word, &mut key);
    (!key.is_empty() && !key.contains(' ')).then_some((start, key))
}

/// The end of a dose after a medication ending at `e` ("1000 mg",
/// "5 mg tablet", "1 g"); `e` when none follows.
fn dose_end(line: &str, e: usize) -> usize {
    let rest = &line[e..];
    let Some(num) = rest.strip_prefix(' ') else {
        return e;
    };
    let digits = num
        .char_indices()
        .find(|&(_, c)| !(c.is_ascii_digit() || c == ',' || c == '.'))
        .map_or(num.len(), |(i, _)| i);
    if digits == 0 || !num.starts_with(|c: char| c.is_ascii_digit()) {
        return e;
    }
    let after = num[digits..].trim_start_matches(' ');
    let unit = ["mg", "mcg", "µg", "g", "ml", "mL", "IU", "ünite"]
        .iter()
        .filter(|u| {
            after.starts_with(*u) && !after[u.len()..].starts_with(|c: char| c.is_alphanumeric())
        })
        .map(|u| u.len())
        .max();
    let Some(unit) = unit else {
        return e;
    };
    let mut end = line.len() - after.len() + unit;
    let form_rest = &line[end..];
    for form in [" tablet", " film tablet", " kapsül", " ampul", " şurup"] {
        if let Some(r) = form_rest.strip_prefix(form) {
            if !r.starts_with(|c: char| c.is_alphanumeric()) {
                end += form.len();
                break;
            }
        }
    }
    end
}

/// A "kökenli" after an origin word ending at `e`: `(end of "kökenli",
/// personal suffix on it)`.
fn origin_word(line: &str, e: usize) -> Option<(usize, bool)> {
    let rest = line[e..].strip_prefix(' ')?;
    let n = rest
        .char_indices()
        .find(|&(_, c)| !c.is_alphabetic())
        .map_or(rest.len(), |(i, _)| i);
    let mut buf = [0; MAX_KEY];
    let word = fold(&rest[..n], &mut buf)?;
    let suffix = word.strip_prefix(b"kokenli")?;
    if !suffix_ok(suffix, 0) {
        return None;
    }
    let base = e + 1;
    let stem_len = rest[..n].char_indices().nth(7).map_or(n, |(i, _)| i);
    Some((base + stem_len, personal_suffix(suffix)))
}

// --------------------------------------------------------------- links

/// The link window of a term: same sentence, [`WINDOW_BACK`] characters
/// before it and up to the reach cut after it (module doc, path 3).
struct Window {
    start: usize,
    end: usize,
    term: (usize, usize),
}

/// The verdict of [`Window::link`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Link {
    /// Nothing ties the term to a person.
    None,
    /// A pronoun, singular person noun or honorific ([`MARKERS`]), or a
    /// first person copula or past verb ending ([`person_verb`]) does.
    Marker,
    /// A person name, an unambiguous first/second-person verb ending, an
    /// 11-digit run or an e-mail sign does: evidence a heading does not
    /// carry.
    Strong,
    /// The term lies inside a person name the name scanner finds.
    TermInName,
}

/// Folded first/second person pronouns, singular person nouns and
/// honorifics that tie a term to a person (module doc, path 3).
const MARKERS: &[&str] = &[
    "abim",
    "ablam",
    "annem",
    "anneme",
    "annemin",
    "arkadasim",
    "arkadasimin",
    "av",
    "babam",
    "babama",
    "babamin",
    "bana",
    "basvuran",
    "basvuranin",
    "bay",
    "bayan",
    "ben",
    "bende",
    "benden",
    "beni",
    "benim",
    "bey",
    "cocugum",
    "cocugumun",
    "danisan",
    "danisana",
    "danisanda",
    "danisani",
    "danisanin",
    "doc",
    "dr",
    "esim",
    "esime",
    "esimin",
    "hanim",
    "hasta",
    "hastada",
    "hastadan",
    "hastam",
    "hastamiz",
    "hastamizin",
    "hastanin",
    "hastaya",
    "hastayi",
    "kardesim",
    "kardesimin",
    "karim",
    "katilimci",
    "katilimcida",
    "katilimcinin",
    "katilimciya",
    "kendim",
    "kendime",
    "kendimi",
    "kizim",
    "kizimin",
    "kocam",
    "komsum",
    "musteri",
    "musteride",
    "musterimiz",
    "musterimizin",
    "musterinin",
    "musteriye",
    "musteriyi",
    "muvekkil",
    "muvekkile",
    "muvekkilim",
    "muvekkilimin",
    "muvekkilin",
    "oglum",
    "oglumun",
    "op",
    "prof",
    "sana",
    "sayin",
    "sen",
    "sende",
    "senden",
    "seni",
    "senin",
    "sigortali",
    "sigortalida",
    "sigortalinin",
    "sigortaliya",
    "sigortaliyi",
    "siz",
    "sizde",
    "sizden",
    "size",
    "sizi",
    "sizin",
    "uzm",
];

/// Folded word endings of first/second person verbs: present
/// continuous, future, evidential, necessitative and simple past.
const VERB_ENDINGS: &[&str] = &[
    "iyorum",
    "uyorum",
    "iyorsun",
    "uyorsun",
    "iyorsunuz",
    "uyorsunuz",
    "acagim",
    "ecegim",
    "acaksin",
    "eceksin",
    "misim",
    "musum",
    "maliyim",
    "meliyim",
    "malisin",
    "melisin",
];

/// Folded words that end like a first person past verb but are not one
/// (nouns in `-im`/`-um` after `d`/`t`: "yönetim" is "management").
const NOT_PAST_VERBS: &[&str] = &[
    "adim", "denetim", "egitim", "gozetim", "hadim", "iletim", "isletim", "kadim", "ogretim",
    "tuketim", "tum", "uretim", "yardim", "yonetim", "zadim",
];

impl Window {
    fn around(line: &str, start: usize, end: usize) -> Self {
        let back = line[..start]
            .char_indices()
            .rev()
            .nth(WINDOW_BACK - 1)
            .map_or(0, |(i, _)| i);
        let mut ws = back;
        // the sentence starts after the last terminator before the term
        for (i, c) in line[back..start].char_indices() {
            if is_terminator(line, back + i, c) {
                ws = back + i + c.len_utf8();
            }
        }
        let mut we = line.len();
        for (i, c) in line[end..].char_indices() {
            if is_terminator(line, end + i, c) {
                we = end + i;
                break;
            }
        }
        Self {
            start: ws,
            end: we,
            term: (start, end),
        }
    }

    /// The words of the window outside the term, folded.
    fn words<'a>(&self, line: &'a str) -> impl Iterator<Item = (usize, &'a str)> + 'a {
        let (ts, te) = self.term;
        let (ws, we) = (self.start, self.end);
        line[ws..we]
            .split(|c: char| !(c.is_alphabetic() || c == '\u{307}'))
            .filter(|w| !w.is_empty())
            .map(move |w| (w.as_ptr() as usize - line.as_ptr() as usize, w))
            .filter(move |&(at, w)| at + w.len() <= ts || at >= te)
    }

    /// What the window says about the term: part of a person name (a
    /// surname such as "Sakallı"), tied to a person, or neither.
    fn link(&self, line: &str) -> Link {
        let text = &line[self.start..self.end];
        let mut names = Vec::new();
        if text.chars().any(char::is_uppercase) {
            person::scan_line(text, &mut names);
        }
        let (ts, te) = (self.term.0 - self.start, self.term.1 - self.start);
        if names.iter().any(|&(s, e, _)| s < te && ts < e) {
            return Link::TermInName;
        }
        if !names.is_empty() || text.contains('@') || has_digit_run(text, 11) {
            return Link::Strong;
        }
        let mut link = Link::None;
        let mut buf = [0; MAX_KEY];
        for (_, word) in self.words(line) {
            let Some(key) = fold(word, &mut buf) else {
                continue;
            };
            let Ok(key) = std::str::from_utf8(key) else {
                continue;
            };
            match person_verb(key) {
                Some(Link::Strong) => return Link::Strong,
                Some(_) => link = Link::Marker,
                None if MARKERS.binary_search(&key).is_ok() => link = Link::Marker,
                None => {}
            }
        }
        link
    }

    /// Whether the window holds a membership word ("üye", "üyesi",
    /// "üyeliği", "üyesiyim").
    fn has_member_word(&self, line: &str) -> bool {
        let mut buf = [0; MAX_KEY];
        self.words(line).any(|(_, w)| {
            fold(w, &mut buf).is_some_and(|k| k.starts_with(b"uye") && suffix_ok(&k[3..], 0))
        })
    }
}

/// A sentence terminator at byte `i`: `!`, `?`, or a `.` followed by
/// whitespace that does not end a short capitalized abbreviation
/// ("Dr.", "Av.", "Uzm.").
fn is_terminator(line: &str, i: usize, c: char) -> bool {
    match c {
        '!' | '?' => true,
        '.' => {
            let after = line[i + 1..].chars().next();
            if !after.map_or(true, char::is_whitespace) {
                return false;
            }
            let word: Vec<char> = line[..i]
                .chars()
                .rev()
                .take_while(|c| c.is_alphabetic())
                .collect();
            !(word.len() <= 4 && word.last().is_some_and(|c| c.is_uppercase()))
        }
        _ => false,
    }
}

/// Whether a folded word is a first/second person verb form, and how
/// strong that evidence is: [`Link::Strong`] for the unambiguous endings
/// of [`VERB_ENDINGS`], [`Link::Marker`] for a copula or simple past
/// ending, which some nouns share.
fn person_verb(key: &str) -> Option<Link> {
    if key.len() >= 6 && VERB_ENDINGS.iter().any(|e| key.ends_with(e)) {
        return Some(Link::Strong);
    }
    // a first person copula on a noun ("üyesiyim", "hastayım"); shorter
    // words ending so are mostly nouns ("giyim", "deyim", "boyum")
    if key.len() >= 7 && (key.ends_with("yim") || key.ends_with("yum")) {
        return Some(Link::Marker);
    }
    (key.len() >= 5
        && ["dim", "dum", "tim", "tum"]
            .iter()
            .any(|e| key.ends_with(e))
        && !NOT_PAST_VERBS.contains(&key))
    .then_some(Link::Marker)
}

/// Whether `text` holds a run of at least `n` ASCII digits.
fn has_digit_run(text: &str, n: usize) -> bool {
    let mut run = 0;
    for b in text.bytes() {
        if b.is_ascii_digit() {
            run += 1;
            if run >= n {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

// ------------------------------------------------------- record fields

/// Folded values that only state absence (module doc, path 1).
const NULL_VALUES: &[&str] = &[
    "-",
    "belirtilmedi",
    "belirtilmemis",
    "bildirilmedi",
    "bilinmiyor",
    "bulunmamaktadir",
    "bulunmuyor",
    "hayir",
    "n a",
    "none",
    "temiz",
    "yok",
    "yoktur",
];

/// Appends the record-field values of the line (module doc, path 1).
fn record_fields(line: &str, hits: &mut Vec<Hit>) {
    let mut label = String::new();
    for (colon, _) in line.match_indices(':') {
        // the label is the field segment before the colon: read back at
        // most LABEL_MAX + 1 characters (a longer segment is no label, and
        // an unbounded look-back made colon-dense lines quadratic)
        let floor = line[..colon]
            .char_indices()
            .rev()
            .nth(LABEL_MAX)
            .map_or(0, |(i, _)| i);
        let Some(seg_start) = line[floor..colon]
            .rfind(['|', ';', '\t', ':'])
            .map(|i| floor + i + 1)
            .or((floor == 0).then_some(0))
        else {
            continue;
        };
        let raw = line[seg_start..colon].trim();
        if raw.is_empty() || raw.chars().count() > LABEL_MAX {
            continue;
        }
        fold_phrase(raw, &mut label);
        // "Ayakta tedavi:", "Yatarak tedavi:", "Acil diş tedavisi:": the
        // coverage lines of an insurance plan, not a person's treatment
        if label.split(' ').count() > 6
            || ["ayakta ", "yatarak ", "acil "]
                .iter()
                .any(|p| label.starts_with(p))
        {
            continue;
        }
        let Some(cat) = Category::ALL.into_iter().find(|c| {
            c.label_heads().iter().any(|h| {
                label
                    .strip_suffix(h)
                    .is_some_and(|pre| pre.is_empty() || pre.ends_with(' '))
            })
        }) else {
            continue;
        };
        if let Some((s, e)) = field_value(line, colon + 1) {
            hits.push(Hit {
                cat,
                start: s,
                end: e,
                score: SCORE_FIELD,
            });
        }
    }
}

/// The value of a field whose `:` ends at `from`: up to the next `|`,
/// `;`, tab or the line end, trimmed, at most [`FIELD_MAX`] characters,
/// not a null value.
fn field_value(line: &str, from: usize) -> Option<(usize, usize)> {
    let cut = reach_end(line, from, FIELD_MAX + 2);
    let rest = &line[from..cut];
    let end_rel = rest.find(['|', ';', '\t']);
    let value_raw = &rest[..end_rel.unwrap_or(rest.len())];
    if end_rel.is_none() && cut < line.len() {
        return None; // longer than the bound: a sentence, not a value
    }
    let lead = value_raw.len() - value_raw.trim_start().len();
    let value = value_raw.trim().trim_end_matches(['.', ',']).trim_end();
    if value.is_empty()
        || value.chars().count() > FIELD_MAX
        || !value.starts_with(|c: char| c.is_alphanumeric())
    {
        return None;
    }
    let mut key = String::new();
    fold_phrase(value, &mut key);
    if key.is_empty() || NULL_VALUES.contains(&key.as_str()) || !informative(&key) {
        return None;
    }
    let s = from + lead;
    Some((s, s + value.len()))
}

/// Whether a folded field value says something about its subject: not a
/// negation ("Engelli değil", "Beyan edilmedi", "bildirilmemiştir"), not
/// an amount or a coverage term of an insurance table ("36,50 EUR",
/// "Poliçe kapsamında"), not a bare "good"/"healthy".
fn informative(key: &str) -> bool {
    let words: Vec<&str> = key.split(' ').collect();
    let negated = words.iter().any(|w| {
        matches!(
            *w,
            "degil" | "yok" | "yoktur" | "bulunmamaktadir" | "bulunmuyor" | "hayir"
        )
    }) || words.last().is_some_and(|w| {
        [
            "medi", "madi", "memis", "mamis", "memistir", "mamistir", "mez", "maz",
        ]
        .iter()
        .any(|n| w.ends_with(n))
    });
    let coverage = words.iter().any(|w| {
        matches!(
            *w,
            "eur"
                | "euro"
                | "tl"
                | "usd"
                | "dolar"
                | "police"
                | "kapsaminda"
                | "kapsamindadir"
                | "teminat"
                | "limitleri"
                | "plan"
        )
    });
    let bare_good = matches!(
        key,
        "iyi" | "saglikli" | "normal" | "klinik olarak saglikli"
    );
    !(negated || coverage || bare_good)
}

/// Folds a short phrase into `out`: letters folded to lowercase ASCII,
/// digits kept, any other run of characters one space, trailing number
/// words dropped ("İlaç 1" -> "ilac").
fn fold_phrase(text: &str, out: &mut String) {
    out.clear();
    let mut buf = [0; MAX_KEY];
    let mut cbuf = [0; 4];
    for c in text.chars() {
        let folded = if c.is_ascii_digit() {
            Some(c as u8)
        } else {
            fold(c.encode_utf8(&mut cbuf), &mut buf).and_then(|k| k.first().copied())
        };
        match folded {
            Some(b) => out.push(char::from(b)),
            None if c == '\u{307}' => {}
            None => {
                if !out.is_empty() && !out.ends_with(' ') {
                    out.push(' ');
                }
            }
        }
    }
    while out.ends_with(|c: char| c == ' ' || c.is_ascii_digit()) {
        out.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::{analyze, personal_suffix, suffix_ok, Category, Hit, MARKERS, MODIFIERS};

    fn found(line: &str) -> Vec<(Category, &str)> {
        let mut hits = Vec::new();
        analyze(line, &mut hits);
        let mut out: Vec<(Category, &str)> = hits
            .iter()
            .map(|h: &Hit| (h.cat, &line[h.start..h.end]))
            .collect();
        out.sort_by_key(|&(_, s)| s.as_ptr());
        out
    }

    #[test]
    fn markers_are_sorted_for_binary_search() {
        assert!(MARKERS.windows(2).all(|w| w[0] < w[1]), "MARKERS unsorted");
        assert!(
            MODIFIERS.windows(2).all(|w| w[0] < w[1]),
            "MODIFIERS unsorted"
        );
    }

    #[test]
    fn suffix_grammar() {
        for s in [
            "im", "imden", "ler", "lari", "li", "liyim", "inin", "si", "yla",
        ] {
            assert!(suffix_ok(s.as_bytes(), 0), "{s}");
        }
        for s in ["ojen", "amik", "k", "xyz"] {
            assert!(!suffix_ok(s.as_bytes(), 0), "{s}");
        }
        for s in ["im", "um", "imden", "liyim", "yim", "sin", "siniz", "lerim"] {
            assert!(personal_suffix(s.as_bytes()), "{s}");
        }
        for s in ["", "i", "in", "ler", "li", "si", "inin", "de"] {
            assert!(!personal_suffix(s.as_bytes()), "{s}");
        }
    }

    #[test]
    fn record_fields_mask_the_value() {
        assert_eq!(
            found("Tanı: Esansiyel hipertansiyon"),
            [(Category::Health, "Esansiyel hipertansiyon")]
        );
        assert_eq!(
            found("Kullanılan ilaç: Metformin 1000 mg"),
            [(Category::Health, "Metformin 1000 mg")]
        );
        assert_eq!(
            found("Etnik köken beyanı: Laz kökenli"),
            [(Category::Ethnicity, "Laz kökenli")]
        );
        assert_eq!(
            found("Siyasi Parti: Yeni Ufuklar Partisi"),
            [(Category::Political, "Yeni Ufuklar Partisi")]
        );
        assert_eq!(
            found("Biyometrik veri referansı: Parmak izi şablonu"),
            [(Category::Biometric, "Parmak izi şablonu")]
        );
        // absence, a thing's label, a date label: nothing
        for line in [
            "Kronik hastalık: Yok",
            "Engellilik durumu: Engelli değil",
            "Tanı tarihi: 12.03.2024",
            "Kampanya adı: Bahar",
        ] {
            assert!(found(line).is_empty(), "{line}");
        }
    }

    #[test]
    fn blood_groups_after_the_cue() {
        assert_eq!(found("Kan grubu: AB Rh+"), [(Category::Health, "AB Rh+")]);
        assert_eq!(
            found("acil durum kartında kan grubu 0 Rh- olarak kayıtlıdır"),
            [(Category::Health, "0 Rh-")]
        );
        assert_eq!(
            found("Kan Grubu: AB Rh Pozitif"),
            [(Category::Health, "AB Rh Pozitif")]
        );
        assert!(found("kan grubu 0 Rh- olanlar evrensel vericidir").is_empty());
        assert!(found("kan grubu testi yapıldı").is_empty());
    }

    #[test]
    fn blood_group_cue_takes_possessive_forms_and_a_colon() {
        assert_eq!(
            found("Kan grubum A Rh+, sigorta formuna yazmam gerekiyor mu?"),
            [(Category::Health, "A Rh+")]
        );
        assert_eq!(
            found("Benim kan grubum 0 Rh- olarak biliniyor."),
            [(Category::Health, "0 Rh-")]
        );
        assert_eq!(
            found("Sistemde kan grubunuz B Rh+ görünüyor."),
            [(Category::Health, "B Rh+")]
        );
        // mid-sentence, too long before the colon to be a field label
        assert_eq!(
            found("dün akşam acil serviste yapılan tahlile göre hastanın kan grubu: AB Rh- çıktı"),
            [(Category::Health, "AB Rh-")]
        );
        assert_eq!(found("KAN GRUBUM: 0 RH+"), [(Category::Health, "0 RH+")]);
        for line in [
            "Kan grubunuz nedir?",
            "kan grubunu öğrenmek için test yaptırdım",
            "kan grubuna göre beslenme önerileri",
        ] {
            assert!(found(line).is_empty(), "{line}: {:?}", found(line));
        }
    }

    #[test]
    fn capitalized_terms_link_on_strong_evidence_only() {
        // a person name in the sentence
        assert_eq!(
            found("MÜŞTERİ NURAY ÇAKIR KANSER TEDAVİSİ GÖRÜYOR, KREDİ ERTELEME TALEBİ VAR"),
            [(Category::Health, "KANSER")]
        );
        // a first person verb
        assert_eq!(
            found("HER GÜN İNSÜLİN KULLANIYORUM"),
            [(Category::Health, "İNSÜLİN")]
        );
        // headings: a person noun alone does not link a capitalized term
        for line in [
            "DİYABET YÖNETİM PLANI",
            "DİYABET EĞİTİMİ ALDIM",
            "HASTA BİLGİLENDİRME: DİYABET",
            "HASTA DİYABET EĞİTİMİ",
            "MÜŞTERİ KANSER TARAMASI KAMPANYASI",
        ] {
            assert!(found(line).is_empty(), "{line}: {:?}", found(line));
        }
        // the same words in lower case keep the person-noun link
        assert_eq!(
            found("Müşteri kanser tedavisi görüyor."),
            [(Category::Health, "kanser")]
        );
        // a noun ending like a past verb is no link ("yönetim")
        assert!(found("Diyabet yönetim planı hazırlandı.").is_empty());
    }

    #[test]
    fn dedupe_keeps_the_earliest_longest_hit_per_category() {
        let hit = |cat, start, end| Hit {
            cat,
            start,
            end,
            score: 0.75,
        };
        let all = vec![
            hit(Category::Health, 5, 9),
            hit(Category::Health, 0, 4),
            hit(Category::Health, 0, 6),
            hit(Category::Belief, 2, 8),
            hit(Category::Health, 6, 7),
            hit(Category::Health, 4, 5),
            hit(Category::Belief, 8, 10),
        ];
        let mut hits = Vec::new();
        super::dedupe(all, &mut hits);
        let got: Vec<_> = hits.iter().map(|h| (h.cat, h.start, h.end)).collect();
        // [0, 6) swallows [0, 4), [4, 5) and [5, 9); [6, 7) starts at its
        // end and stays; another category overlaps freely; touching spans
        // of one category both stay
        assert_eq!(
            got,
            [
                (Category::Health, 0, 6),
                (Category::Belief, 2, 8),
                (Category::Health, 6, 7),
                (Category::Belief, 8, 10),
            ]
        );
    }

    /// Every category scanner's output on `line`, called back to back in
    /// registration order as the engine calls them.
    fn by_scanners(line: &str) -> Vec<Vec<(usize, usize, f32)>> {
        super::scanners()
            .iter()
            .map(|s| {
                let mut out = Vec::new();
                (s.scan)(line, &mut out);
                out
            })
            .collect()
    }

    /// The expected output of each category on `line`: one analysis,
    /// filtered.
    fn by_analysis(line: &str) -> Vec<Vec<(usize, usize, f32)>> {
        let mut hits = Vec::new();
        analyze(line, &mut hits);
        Category::ALL
            .iter()
            .map(|&c| {
                hits.iter()
                    .filter(|h| h.cat == c)
                    .map(|h| (h.start, h.end, h.score))
                    .collect()
            })
            .collect()
    }

    #[test]
    fn shared_analysis_matches_one_analysis_per_scanner() {
        let lines = [
            "Tanı: Tip 2 diyabet | Kan grubu: A Rh+ | Etnik köken: Kürt",
            "Ben Müslümanım, sendikalıyım ve Yeni Ufuklar Partisi üyesiyim.",
            "Diyabet hastalarında kan şekeri takibi önemlidir.",
            "",
        ];
        for line in lines {
            assert_eq!(by_scanners(line), by_analysis(line), "{line}");
        }
        // a long term-dense line: the same, in one shared analysis
        let long = "Diyabetim var, kan grubum A Rh+. ".repeat(40_000);
        assert_eq!(by_scanners(&long), by_analysis(&long));
    }

    #[test]
    fn a_scanner_out_of_order_analyses_the_line_itself() {
        let scanners = super::scanners();
        let a = String::from("Diyabetim var ve Müslümanım.");
        let b = String::from("Kan grubum 0 Rh- ve sendikalıyım.");
        let run = |i: usize, line: &str| {
            let mut out = Vec::new();
            (scanners[i].scan)(line, &mut out);
            out
        };
        let (want_a, want_b) = (by_analysis(&a), by_analysis(&b));
        // the leader on `a`, then another line: no reuse of `a`'s hits
        assert_eq!(run(0, &a), want_a[0]);
        assert_eq!(run(1, &b), want_b[1]);
        // the same address with another length (a prefix of `b`)
        assert_eq!(run(0, &b), want_b[0]);
        let prefix = &b[..10];
        assert_eq!(run(1, prefix), by_analysis(prefix)[1]);
        // a scanner skipped, a scanner called alone, a repeated call
        assert_eq!(run(0, &a), want_a[0]);
        assert_eq!(run(5, &a), want_a[5]);
        assert_eq!(run(9, &b), want_b[9]);
        assert_eq!(run(9, &b), want_b[9]);
    }

    #[test]
    fn terms_need_a_person_link() {
        assert_eq!(found("Diyabetim var."), [(Category::Health, "Diyabet")]);
        assert_eq!(
            found("Ben Müslümanım ve oruç tutuyorum."),
            [(Category::Belief, "Müslüman")]
        );
        assert_eq!(
            found("Hastanın bilinen tanısı hipertansiyon olarak kaydedildi."),
            [(Category::Health, "hipertansiyon")]
        );
        assert_eq!(
            found("Ahmet Yılmaz sendika üyesi olarak çalışıyor."),
            [(Category::Membership, "sendika üyesi")]
        );
        for line in [
            "Diyabet hastalarında kan şekeri takibi önemlidir.",
            "Cami avlusunda toplanıldı.",
            "Hipertansiyon dünyada yaygın bir hastalıktır.",
            "Sendika genel kurulu yarın toplanıyor.",
            "Roman okumayı seviyorum.",
            "Lazım olan belgeler listede yer alıyor.",
        ] {
            assert!(found(line).is_empty(), "{line}: {:?}", found(line));
        }
    }

    #[test]
    fn condition_modifiers_join_the_span() {
        assert_eq!(
            found("Hastada Tip 2 diyabet ve esansiyel hipertansiyon izlendi."),
            [
                (Category::Health, "Tip 2 diyabet"),
                (Category::Health, "esansiyel hipertansiyon")
            ]
        );
        assert_eq!(
            found("Hastanın ileri evre astım tanısı var."),
            [(Category::Health, "ileri evre astım")]
        );
    }

    #[test]
    fn organisation_names() {
        assert_eq!(
            found("Yeni Ufuklar Partisi üyesiyim."),
            [(Category::Political, "Yeni Ufuklar Partisi")]
        );
        assert_eq!(
            found("Eğitim-Sen üyesiyim."),
            [(Category::Membership, "Eğitim-Sen")]
        );
        // a union named without a membership word stays unclaimed
        assert!(found("Eğitim-Sen bugün açıklama yaptı, ben okudum.").is_empty());
    }

    #[test]
    fn spans_are_on_char_boundaries_and_long_lines_finish() {
        for text in [
            "İ\u{307}laç: ğ",
            "kan grubu Ü",
            "Tanı:",
            "Tanı: ",
            ":::",
            "diyabetim'",
            "Ş:Ç|Ğ;İ",
        ] {
            let mut hits = Vec::new();
            analyze(text, &mut hits);
            for h in hits {
                assert!(text.is_char_boundary(h.start) && text.is_char_boundary(h.end));
                assert!(h.start < h.end);
            }
        }
        for unit in ["diyabet ", "Tanı: x ", "ben ", "kan grubu A Rh+ ", "ü:"] {
            let text = unit.repeat(200_000 / unit.len());
            let mut hits = Vec::new();
            analyze(&text, &mut hits);
        }
    }
}
