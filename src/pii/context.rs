//! Context-cue mechanism shared by every locale rule.
//!
//! Rules declare cue lists (`ContextPolicy::RequiredCue` / `Boost`); this
//! module answers the single question: "is a cue close enough to this
//! match?" The two sides of a match are measured differently:
//!
//! - **Leading** (before the match): a cue counts when it ENDS within
//!   `window` characters before the match start. The window bounds the gap
//!   between a label and its value, not the label's length, so a label
//!   longer than the window ("Vehicle registration number: AB12 CDE")
//!   still unlocks the value it directly precedes.
//! - **Trailing** (after the match): a cue counts only when it lies
//!   ENTIRELY within `window` characters after the match end, so the reach
//!   after a value stays bounded by the window alone (the streaming guard's
//!   hold-back is derived from that bound, see `policy::stream`).
//!
//! The two sides are searched separately: a cue is never assembled from
//! the end of the leading context and the start of the trailing one.
//! Windows are **character** based (not bytes); `char_indices` walks
//! correctly across multi-byte Turkish letters.
//!
//! **Word start** (both sides): a cue of at most [`WORD_START_CUE_CHARS`]
//! characters whose first character is an ASCII letter counts only where
//! it starts a word: at the start of the text, or after a character that
//! is not alphanumeric (looked up in the text itself, also when it lies
//! before the searched context; a U+0307 there is skipped, as
//! normalization drops it). Measured on the repository's data sets and
//! test literals, every occurrence of such a cue inside a word was a trap
//! (`tax` in "syntax", `sin:` in "Wisconsin:", `nin:` in "Benin:", `pan:`
//! in "span:", `nino` in "femenino", `isim` in "kısım", `name:` in
//! "username:", `bic ` in "xenophobic", `pass ` in "bypass", `cp` in
//! "tcpstream", `cf` in "fcf", `ssn` in "classname", `plate` in
//! "template") or a compound with its own longer cue ("reisepass",
//! "taxpayer", "gstin", "itin:", "dnie:"). There is no condition on the
//! right side, so a Turkish suffix keeps the cue ("vergisi" for `vergi`).
//! Longer cues (compound tails such as `sichertennummer`) and cues that
//! start with another character (a space, punctuation, a digit or a
//! non-ASCII letter) are unaffected.
//!
//! **camelCase start** (on the value's line, identifier kinds only): an
//! uppercase character right after a lowercase one also starts a word,
//! so `customerSsn: 536906292`, `employerEin: 10-1234567` and
//! `holderPan: AFZPK7190K` - the `"{key}: {value}"` lines the JSON
//! redactor builds from camelCase keys - unlock their value. The cue must
//! also END its segment (no lowercase letter after it): `sendTelemetry`
//! holds `tel` and `getTaxonomyNode` holds `tax`, and neither is a label.
//! None of the traps above is affected: in each the cue starts on a
//! lowercase letter (`className` keeps its `ssn` after an `a`). The engine asks for it only
//! for identifier kinds (`EntityType::priority` below 8): a NAME or
//! ADDRESS is a free capitalized sequence, and `fileName: Annual Report`
//! must not become a name through `name:`. Caller-supplied context texts
//! keep the plain word start.

/// Longest cue (in characters) that must start a word when its first
/// character is an ASCII letter (module doc).
const WORD_START_CUE_CHARS: usize = 5;

/// Is any cue from `cues` close enough to the match? See [`find_cue`].
#[cfg(test)]
pub(crate) fn has_cue<S: AsRef<str>>(
    text: &str,
    start: usize,
    end: usize,
    cues: &[S],
    window: usize,
) -> bool {
    find_cue(text, start, end, cues, window, false).is_some()
}

/// The first cue of `cues` (in list order) that ends within `window`
/// characters before the match `[start, end)` or lies entirely within
/// `window` characters after it, at a word start when the cue is short
/// (module doc), or `None`.
///
/// Each side is lowercased with an `ı->i` normalization ([`normalize_tr`])
/// and searched for each cue as a substring - this is how the Turkish
/// dotted/dotless-i problem is avoided. Cues must therefore already be in
/// normalized form (every built-in cue list is; custom-rule cues are
/// normalized when the rule is built). The returned value is the
/// configured cue literal, never text taken from the input.
///
/// With `camel_case`, a short cue also starts a word at a lowercase to
/// uppercase change (`customerSsn`, `employerEin`; module doc).
pub(crate) fn find_cue<'c, S: AsRef<str>>(
    text: &str,
    start: usize,
    end: usize,
    cues: &'c [S],
    window: usize,
    camel_case: bool,
) -> Option<&'c str> {
    let longest = cues.iter().map(|c| c.as_ref().chars().count()).max()?;
    // leading side: the window, plus room for the longest cue to start
    // before it (U+0307 normalizes to nothing, so it is not counted as room)
    let window_start = chars_before(text, start, window, |_| true);
    let lead_start = chars_before(text, window_start, longest, |c| c != '\u{307}');
    let lead = normalize_tr(&text[lead_start..start]);
    // where the window begins inside `lead`: normalization maps every
    // character on its own except for the Greek final-sigma choice, and
    // both sigma forms are two bytes long, so the normalized head is
    // exactly the part of `lead` before the window
    let window_at = normalize_tr(&text[lead_start..window_start]).len();
    let trail = normalize_tr(&text[end..chars_after(text, end, window)]);
    cues.iter().map(AsRef::as_ref).find(|c| {
        if starts_words_only(c) {
            let camel = camel_case.then_some(*c);
            occurrences(&lead, c)
                .any(|at| at + c.len() >= window_at && starts_word(text, lead_start, at, camel))
                || occurrences(&trail, c).any(|at| starts_word(text, end, at, camel))
        } else {
            // the last occurrence ends furthest right (all have one length)
            lead.rfind(c).is_some_and(|at| at + c.len() >= window_at) || trail.contains(c)
        }
    })
}

/// Caller-supplied context texts (for example the previous turn of a chat
/// or call transcript, which asks for the value the input answers),
/// normalized once per engine pass.
///
/// A cue counts when it occurs ANYWHERE in one of the texts, under the
/// same rules as on the value's line: [`normalize_tr`] folding and the
/// word-start rule for short cues (module doc). There is no window: the
/// caller decides which text the input answers, so it should pass only
/// that text.
///
/// Cost: each distinct cue is searched once per engine pass, in time
/// linear in the texts (every match of a rule asks with the same cues; a
/// search per match took matches x context, and the word-start check
/// walking from the text start per occurrence made one search quadratic).
pub(crate) struct ExternalContext<'t> {
    /// The texts as given (word starts are looked up here).
    raw: &'t [&'t str],
    /// [`normalize_tr`] of each text (cues are searched here).
    normalized: Vec<String>,
    /// Whether each cue asked so far occurs in the texts (the answer
    /// depends on the cue alone).
    seen: std::cell::RefCell<std::collections::HashMap<String, bool>>,
}

impl<'t> ExternalContext<'t> {
    /// Normalizes `raw` once (no allocation when it is empty).
    pub(crate) fn new(raw: &'t [&'t str]) -> Self {
        Self {
            raw,
            normalized: raw.iter().map(|t| normalize_tr(t)).collect(),
            seen: std::cell::RefCell::default(),
        }
    }

    /// The first cue of `cues` (in list order) that occurs in one of the
    /// texts, or `None`. Like [`find_cue`], the returned value is the
    /// configured cue literal.
    pub(crate) fn find_cue<'c, S: AsRef<str>>(&self, cues: &'c [S]) -> Option<&'c str> {
        if self.raw.is_empty() {
            return None;
        }
        cues.iter().map(AsRef::as_ref).find(|c| self.occurs(c))
    }

    /// Whether `cue` occurs in one of the texts (searched on first use).
    fn occurs(&self, cue: &str) -> bool {
        if let Some(&hit) = self.seen.borrow().get(cue) {
            return hit;
        }
        let hit = self.raw.iter().zip(&self.normalized).any(|(raw, norm)| {
            if starts_words_only(cue) {
                occurs_at_word_start(raw, norm, cue)
            } else {
                norm.contains(cue)
            }
        });
        self.seen.borrow_mut().insert(cue.to_owned(), hit);
        hit
    }
}

/// Whether an occurrence of `cue` in `norm` (= `normalize_tr(text)`)
/// starts a word of `text`: [`starts_word`]`(text, 0, at)` for each
/// occurrence, in one forward walk over `text` (the occurrences come in
/// increasing order, so the character each one maps to never moves back).
fn occurs_at_word_start(text: &str, norm: &str, cue: &str) -> bool {
    let mut chars = text.chars().peekable();
    // the normalized offset of the character under the cursor, and the
    // last character before it that is not U+0307
    let mut normalized = 0;
    let mut before: Option<char> = None;
    occurrences(norm, cue).any(|at| {
        while let Some(&c) = chars.peek() {
            let len = normalized_len(c);
            if normalized >= at && len > 0 {
                break;
            }
            normalized += len;
            if c != '\u{307}' {
                before = Some(c);
            }
            chars.next();
        }
        // past the last character `starts_word` falls back to the text
        // start, which starts a word
        chars.peek().is_none() || !before.is_some_and(char::is_alphanumeric)
    })
}

/// Whether `cue` counts only at a word start (module doc): at most
/// [`WORD_START_CUE_CHARS`] characters, the first an ASCII letter.
fn starts_words_only(cue: &str) -> bool {
    cue.starts_with(|c: char| c.is_ascii_alphabetic())
        && cue.chars().count() <= WORD_START_CUE_CHARS
}

/// Every byte offset at which `cue` occurs in `hay`, overlapping
/// occurrences included.
fn occurrences<'a>(hay: &'a str, cue: &'a str) -> impl Iterator<Item = usize> + 'a {
    let mut from = 0;
    std::iter::from_fn(move || {
        let at = from + hay.get(from..)?.find(cue)?;
        from = at + hay[at..].chars().next().map_or(1, char::len_utf8);
        Some(at)
    })
}

/// Whether the character at byte offset `at` of `normalize_tr(&text[from..])`
/// (any end) starts a word of `text`: the character before it in `text`,
/// skipping U+0307, is absent or not alphanumeric. Every character
/// normalizes to at most one character (`İ` to `i` once U+0307 is
/// dropped), so `at` always falls on the normalized form of one raw
/// character, which this walk finds.
///
/// With `camel_cue` (the cue found at `at`), an uppercase character right
/// after a lowercase one starts a word too (`customerSsn`), when the cue
/// also ends its camelCase segment: no lowercase letter follows it
/// (`sendTelemetry` holds `tel`, `getTaxonomyNode` holds `tax`, and
/// neither is that label).
fn starts_word(text: &str, from: usize, at: usize, camel_cue: Option<&str>) -> bool {
    let mut normalized = 0;
    let mut raw = from;
    for (i, c) in text[from..].char_indices() {
        let len = normalized_len(c);
        if normalized >= at && len > 0 {
            raw = from + i;
            break;
        }
        normalized += len;
    }
    match text[..raw].chars().rev().find(|&c| c != '\u{307}') {
        None => true,
        Some(before) if !before.is_alphanumeric() => true,
        Some(before) => camel_cue.is_some_and(|cue| {
            let mut rest = text[raw..].chars().filter(|&c| c != '\u{307}');
            before.is_lowercase()
                && rest.next().is_some_and(char::is_uppercase)
                && !rest
                    .nth(cue.chars().count() - 1)
                    .is_some_and(char::is_lowercase)
        }),
    }
}

/// The byte length of `c` after [`normalize_tr`] (`char::to_lowercase`
/// differs from the string form only in the Greek final-sigma choice, and
/// both sigma forms are two bytes long).
fn normalized_len(c: char) -> usize {
    c.to_lowercase()
        .map(|l| match l {
            '\u{131}' => 1,
            '\u{307}' => 0,
            l => l.len_utf8(),
        })
        .sum()
}

/// The byte offset `n` counted characters before `from` (the text start
/// when fewer precede it): walks back over every character and counts
/// those for which `counts` holds. The offset sits on a character
/// boundary (slicing is panic-free).
fn chars_before(text: &str, from: usize, n: usize, counts: impl Fn(char) -> bool) -> usize {
    let mut at = from;
    let mut seen = 0;
    for (i, c) in text[..from].char_indices().rev() {
        if seen == n {
            break;
        }
        at = i;
        if counts(c) {
            seen += 1;
        }
    }
    at
}

/// The byte offset `n` characters after `from` (the text end when fewer
/// follow it), on a character boundary.
fn chars_after(text: &str, from: usize, n: usize) -> usize {
    text[from..]
        .char_indices()
        .nth(n)
        .map_or(text.len(), |(i, _)| from + i)
}

/// Lowercase plus `ı`->`i` (normalize the dot problem to the ASCII side) and
/// strip U+0307 (combining dot above): Rust's `to_lowercase` maps capital
/// dotted `İ` to `i` + U+0307, which would otherwise break cue matching for
/// cues whose critical letters follow an `İ` (e.g. "İsim" vs the cue "isim").
pub(crate) fn normalize_tr(s: &str) -> String {
    s.to_lowercase().replace('ı', "i").replace('\u{307}', "")
}

#[cfg(test)]
mod tests {
    use super::has_cue;

    #[test]
    fn the_forward_walk_equals_starts_word_per_occurrence() {
        use super::{normalize_tr, occurrences, occurs_at_word_start, starts_word};
        // letters, a digit, a space, a dotted capital whose U+0307 folds
        // away, a lone U+0307 and a sigma (final and non-final forms)
        const ALPHABET: [char; 9] = [
            'x', 't', 'a', ' ', '\u{130}', '\u{307}', '\u{3a3}', 'T', '1',
        ];
        let mut checked = 0;
        for len in 0..=5u32 {
            for n in 0..ALPHABET.len().pow(len) {
                let mut text = String::new();
                let mut k = n;
                for _ in 0..len {
                    text.push(ALPHABET[k % ALPHABET.len()]);
                    k /= ALPHABET.len();
                }
                let norm = normalize_tr(&text);
                for cue in ["ta", "tax", "i", "x", "\u{3c3}"] {
                    let per_occurrence =
                        occurrences(&norm, cue).any(|at| starts_word(&text, 0, at, None));
                    assert_eq!(
                        occurs_at_word_start(&text, &norm, cue),
                        per_occurrence,
                        "{text:?} / {cue:?}"
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked > 300_000, "{checked}");
    }

    const CUES: &[&str] = &["vergi", "tax"];

    fn pos(text: &str, needle: &str) -> (usize, usize) {
        let s = text.find(needle).expect("needle present");
        (s, s + needle.len())
    }

    #[test]
    fn cue_present_and_absent() {
        let with = "Firmanın vergi numarası 1234567890.";
        let (s, e) = pos(with, "1234567890");
        assert!(has_cue(with, s, e, CUES, 18));

        let without = "Sipariş 1234567890 hazır.";
        let (s, e) = pos(without, "1234567890");
        assert!(!has_cue(without, s, e, CUES, 18));
    }

    #[test]
    fn cue_beyond_window_is_ignored() {
        let t = "vergi çok uzakta........................ 1234567890.";
        let (s, e) = pos(t, "1234567890");
        assert!(!has_cue(t, s, e, CUES, 18));
    }

    #[test]
    fn multibyte_turkish_counts_characters_not_bytes() {
        // 'ı' is 2 bytes. "vergi no ıııııııı " is 18 CHARACTERS but 26 BYTES.
        // The window opens CHARACTER based -> "vergi" stays inside it. A byte-based
        // walk would only see "o ıııııııı" and the cue would escape - this test
        // locks in character-based semantics.
        let t = "vergi no ıııııııı 1234567890";
        let s = t.find("1234567890").expect("vkn present");
        assert!(has_cue(t, s, s + 10, CUES, 18));
    }

    #[test]
    fn cue_matches_uppercase_despite_turkish_i() {
        // "VERGİ NUMARASI" - Unicode lowercasing maps 'I'->'i'; it must match the
        // cue "vergi" (i-normalized).
        let t = "VERGİ NUMARASI: 1234567890";
        let (s, e) = pos(t, "1234567890");
        assert!(has_cue(t, s, e, CUES, 18));
    }

    #[test]
    fn cue_matches_dotted_capital_i_prefix() {
        // 'İ' lowercases to i + U+0307; without stripping the combining dot the
        // cue "isim" could never match "İsim".
        let cues = &["isim"];
        let t = "İsim: 5321234567";
        let (s, e) = pos(t, "5321234567");
        assert!(has_cue(t, s, e, cues, 18));
        assert_eq!(super::normalize_tr("İSİM"), "isim");
    }

    #[test]
    fn find_cue_returns_the_first_configured_cue_literal() {
        let t = "VERGİ tax no: 1234567890";
        let (s, e) = pos(t, "1234567890");
        // both cues are present; list order decides, and the returned
        // value is the configured literal, not the input's "VERGİ"
        assert_eq!(super::find_cue(t, s, e, CUES, 18, false), Some("vergi"));
        let reversed = ["tax", "vergi"];
        assert_eq!(super::find_cue(t, s, e, &reversed, 18, false), Some("tax"));
        let owned = vec!["no:".to_owned()];
        assert_eq!(super::find_cue(t, s, e, &owned, 18, false), Some("no:"));
        assert_eq!(super::find_cue(t, s, e, &["plaka"], 18, false), None);
    }

    #[test]
    fn every_built_in_cue_is_already_normalized() {
        // find_cue normalizes the CONTEXT only: a cue that is not itself
        // in normalized form (uppercase, dotless i, U+0307) could never
        // match. Every locale pack is on, so every registered rule's cue
        // list is checked.
        use crate::pii::locales::{rules_for_locales, ContextPolicy, SUPPORTED_LOCALES};
        let mut checked = 0;
        for rule in rules_for_locales(SUPPORTED_LOCALES) {
            let cues: &[&str] = match rule.context {
                ContextPolicy::RequiredCue(c) | ContextPolicy::Boost(c, _) => c,
                ContextPolicy::None => continue,
            };
            for cue in cues {
                assert_eq!(
                    super::normalize_tr(cue),
                    *cue,
                    "cue {cue:?} of rule {} is not normalized",
                    rule.id
                );
                assert!(!cue.is_empty(), "empty cue in rule {}", rule.id);
                checked += 1;
            }
        }
        assert!(checked > 0);
    }

    #[test]
    fn leading_cue_counts_when_its_end_is_within_the_window() {
        // the window bounds the gap after the cue, not the cue's length:
        // a gap of 18 characters counts, 19 do not, whatever the cue length
        let cues = &["registration"];
        for gap in [0, 1, 17, 18] {
            let t = format!("registration{}AB12CDE", " ".repeat(gap));
            let (s, e) = pos(&t, "AB12CDE");
            assert!(has_cue(&t, s, e, cues, 18), "gap {gap}");
        }
        let t = format!("registration{}AB12CDE", " ".repeat(19));
        let (s, e) = pos(&t, "AB12CDE");
        assert!(!has_cue(&t, s, e, cues, 18));
        // multi-byte gap characters count as characters
        let t = format!("vergi{}1234567890", "ı".repeat(18));
        let (s, e) = pos(&t, "1234567890");
        assert!(has_cue(&t, s, e, CUES, 18));
        let t = format!("vergi{}1234567890", "ı".repeat(19));
        let (s, e) = pos(&t, "1234567890");
        assert!(!has_cue(&t, s, e, CUES, 18));
    }

    #[test]
    fn trailing_cue_must_lie_fully_inside_the_window() {
        // unchanged trailing side: the cue's END must be within 18
        // characters after the match
        let cues = &["registration"];
        let t = format!("AB12CDE{}registration", " ".repeat(6));
        let (s, e) = pos(&t, "AB12CDE");
        assert!(has_cue(&t, s, e, cues, 18));
        let t = format!("AB12CDE{}registration", " ".repeat(7));
        let (s, e) = pos(&t, "AB12CDE");
        assert!(!has_cue(&t, s, e, cues, 18));
    }

    #[test]
    fn cue_is_never_assembled_across_the_match() {
        // "va" + match + "t" must not read as "vat" (the sides stay separate)
        let t = "va999999973t";
        let (s, e) = pos(t, "999999973");
        assert!(!has_cue(t, s, e, &["vat"], 18));
        assert!(!has_cue("tax999tax", 3, 6, &["xt", "axt"], 18));
        assert!(has_cue("vat999", 3, 6, &["vat"], 18));
        // a short cue glued to the value's end does not start a word
        assert!(has_cue("999 vat", 0, 3, &["vat"], 18));
        assert!(!has_cue("999vat", 0, 3, &["vat"], 18));
    }

    #[test]
    fn decomposed_dotted_capital_i_inside_a_leading_cue_still_counts() {
        // "VERGI" + U+0307 is the decomposed "VERGİ": six characters that
        // normalize to the five-character cue; ending exactly 18 characters
        // before the value it must still be found whole
        let t = format!("VERGI\u{307}{}1234567890", "-".repeat(18));
        let (s, e) = pos(&t, "1234567890");
        assert!(has_cue(&t, s, e, CUES, 18));
    }

    #[test]
    fn final_sigma_in_the_leading_context_keeps_the_window_offset() {
        // `to_lowercase` picks the final-sigma form by context; both forms
        // are two bytes, so the window offset inside the normalized lead is
        // unaffected (a cue right after a Greek word is still found, a cue
        // beyond the window is still not)
        let t = format!("ΟΔΟΣ vergi{}1234567890", "-".repeat(18));
        let (s, e) = pos(&t, "1234567890");
        assert!(has_cue(&t, s, e, CUES, 18));
        let t = format!("vergi ΟΔΟΣ{}1234567890", "-".repeat(18));
        let (s, e) = pos(&t, "1234567890");
        assert!(!has_cue(&t, s, e, CUES, 18));
        assert!(has_cue(&t, s, e, &["οδος"], 18));
    }

    #[test]
    fn empty_cue_list_finds_nothing() {
        let none: &[&str] = &[];
        assert_eq!(
            super::find_cue("vergi 1234567890", 6, 16, none, 18, false),
            None
        );
    }

    #[test]
    fn short_cues_count_only_at_a_word_start() {
        let at = |t: &str, cues: &[&str]| {
            let (s, e) = pos(t, "1234567890");
            has_cue(t, s, e, cues, 18)
        };
        // inside a word: no (leading and trailing side)
        assert!(!at("syntax 1234567890", &["tax"]));
        assert!(!at("Wisconsin: 1234567890", &["sin:"]));
        assert!(!at("1234567890 syntax", &["tax"]));
        assert!(!at("1234567890tax", &["tax"]));
        // at the start of the text or after a non-alphanumeric: yes
        assert!(at("tax 1234567890", &["tax"]));
        assert!(at("TAX: 1234567890", &["tax"]));
        assert!(at("(tax) 1234567890", &["tax"]));
        assert!(at("e-tax 1234567890", &["tax"]));
        assert!(at("1234567890, tax", &["tax"]));
        // no right-side condition: a Turkish suffix keeps the cue
        assert!(at("Firmanın vergisi 1234567890", CUES));
        // the character before the searched context decides too: here the
        // look-back starts at the cue, and "syn" lies before it
        let t = format!("syntax{}1234567890", " ".repeat(18));
        assert!(!at(&t, &["tax"]));
        let t = format!("   tax{}1234567890", " ".repeat(18));
        assert!(at(&t, &["tax"]));
        // a Turkish letter before the cue is alphanumeric
        assert!(!at("kısım 1234567890", &["isim"]));
        assert!(at("İsim 1234567890", &["isim"]));
        // U+0307 before the cue is skipped (normalization drops it)
        assert!(!at("x\u{307}isim 1234567890", &["isim"]));
        assert!(at(" \u{307}isim 1234567890", &["isim"]));
        // unaffected: longer cues, and cues that do not start with an ASCII
        // letter (a space, punctuation, a non-ASCII letter)
        assert!(at("Versichertennummer 1234567890", &["sichertennummer"]));
        assert!(!at("xtaxes 1234567890", &["taxes"])); // 5 characters: bounded
        assert!(at("xtaxid: 1234567890", &["taxid:"])); // 6 characters: not
        assert!(at("syn tax 1234567890", &[" tax"]));
        assert!(at("xαφμ 1234567890", &["αφμ"]));
    }

    #[test]
    fn word_start_cues_match_the_built_in_trap_and_compound_cases() {
        // the real cue lists: no trap unlocks, each compound
        // is still found through its own longer cue
        use crate::pii::locales::{rules_for_locales, ContextPolicy, SUPPORTED_LOCALES};
        let rules = rules_for_locales(SUPPORTED_LOCALES);
        let cues_of = |id: &str| -> &'static [&'static str] {
            let rule = rules.iter().find(|r| r.id == id).expect("rule registered");
            match rule.context {
                ContextPolicy::RequiredCue(c) | ContextPolicy::Boost(c, _) => c,
                ContextPolicy::None => panic!("{id} has no cue list"),
            }
        };
        let found = |id: &str, before: &str| {
            let t = format!("{before}1234567890");
            super::find_cue(&t, before.len(), t.len(), cues_of(id), 18, false)
        };
        for (id, trap) in [
            ("uk::vat", "syntax "),
            ("en::itin", "syntax "),
            ("ca::sin", "Wisconsin: "),
            ("ng::nin", "Benin: "),
            ("ng::nin", "TNIN: "),
            ("in_::pan", "span: "),
            ("uk::nino", "femenino "),
            ("swift", "xenophobic "),
            ("de::passport", "bypass "),
            ("fr::postal", "tcpstream "),
            ("it::fiscal_code", "FCF "),
            ("tr::plaka", "template "),
            ("en::itin", "GSTIN: "),
            ("ph::tin", "GSTIN: "),
            ("es::nie", "DNIe: "),
        ] {
            assert_eq!(found(id, trap), None, "{id} {trap:?}");
        }
        for (id, compound, cue) in [
            ("de::passport", "Reisepass ", "reisepass"),
            ("en::itin", "Taxpayer ", "taxpayer"),
            ("in_::gstin", "GSTIN: ", "gstin"),
            ("en::itin", "ITIN: ", "itin:"),
            ("es::dni", "DNIe: ", "dnie:"),
        ] {
            assert_eq!(found(id, compound), Some(cue), "{id} {compound:?}");
        }
    }
}
