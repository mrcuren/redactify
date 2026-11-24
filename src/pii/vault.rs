//! Reversible pseudonymization (vault pattern): mask PII before an LLM call,
//! restore it in the LLM response. The model never sees real identifiers.
//!
//! The flow:
//!
//! ```text
//! User prompt (with PII)
//!     |
//!     v
//! Vault::pseudonymize()  -->  "[TCKN_1]" placeholder + vault
//!     |
//!     v
//! LLM call (placeholder text only; the model cannot leak what it never saw)
//!     |
//!     v
//! LLM response (may reference "[TCKN_1]")
//!     |
//!     v
//! vault.restore()  -->  real value restored; user sees natural text
//! ```
//!
//! A streamed LLM response is restored chunk by chunk with
//! [`Vault::restorer`]: a placeholder split across chunks is held back only
//! as long as it can still complete.
//!
//! # Altered placeholders and Turkish suffixes
//!
//! LLMs rewrite placeholders. By default ([`RestoreOptions::TOLERANT`])
//! the restore also accepts these renderings of a placeholder the vault
//! issued (shown for `[NAME_1]`), as observed in LLM-style responses:
//!
//! | Form | Example |
//! |---|---|
//! | exact (also [`RestoreOptions::STRICT`]) | `[NAME_1]` |
//! | other brackets | `<NAME_1>`, `{NAME_1}` |
//! | doubled brackets | `[[NAME_1]]`, `<<NAME_1>>`, `{{NAME_1}}` |
//! | markdown-escaped | `\[NAME\_1\]`, `\<NAME_1\>`, `\{NAME_1\}`, `[NAME\_1]` |
//! | HTML / JSON escaped | `&lt;NAME_1&gt;`, `&#91;NAME_1&#93;`, `\u003cNAME_1\u003e`, `\u005bNAME_1\u005d` |
//! | any letter case inside delimiters | `[name_1]`, `<Name_1>` |
//! | up to two spaces inside delimiters | `[ NAME_1 ]` |
//! | zero-padded number | `[NAME_01]` |
//! | translated label | `[PERSON_1]`, `[ISIM_1]`, `[İSİM_1]`, `[KİŞİ_1]`, `<TELEFON_1>`, `[EPOSTA_1]` |
//! | bare: upper case, in prose (see below) | `Kayıt: NAME_1 doğrulandı.` |
//!
//! A rendering is restored only when its label and number resolve to an
//! entry of THIS vault, so it is never a guess: `[NAME]`, `[1]`,
//! `[NAME_3]` in a vault without `NAME_3`, another vault's `[EMAIL_1]`
//! and a lower-case bare `name_1` are left as they are.
//!
//! A bare (bracket-less) `PHONE_1` is restored only where it reads as a
//! dropped bracket in prose, never where it reads as an identifier: not
//! inside an inline code span or a fenced code block; not after a word
//! character, a backtick or one of `.` `$` `@` `#` `-` `/` `\` `:` `>`
//! `%` (`obj.PHONE_1`, `$PHONE_1`,
//! `Foo::PHONE_1`); not before a word character, `(`, `[`, `` ` ``, `:`,
//! `.x`, `-x`, `->` (`PHONE_1_MAX`, `PHONE_1()`, `PHONE_1.len`, a
//! `PHONE_1:` key); not before `=` after at most two spaces
//! (`const PHONE_1 = 5`, `PHONE_1=x`); not between matching quotes
//! (`"PHONE_1"`). The code context is tracked from the start of the text
//! (and across stream chunks), so restore a whole answer, or stream it
//! through one [`Vault::restorer`], rather than restoring pieces of it
//! separately. Mismatched
//! delimiters are not consumed: in `[NAME_1>` only the bare `NAME_1` is
//! restored (`[Ayşe Kaya>`). Translated labels come from a fixed table (Turkish
//! and English names of the built-in labels: `PERSON`, `ISIM`, `KISI`,
//! `AD_SOYAD` → `NAME`; `TELEFON`, `TEL`, `PHONE_NUMBER` → `PHONE`;
//! `EPOSTA`, `E_POSTA`, `E_MAIL`, `MAIL` → `EMAIL`; `ADRES` → `ADDRESS`;
//! `KART`, `KREDI_KARTI`, `CARD` → `CREDIT_CARD`; `IP` → `IP_ADDRESS`;
//! `PASAPORT` → `PASSPORT`; `PLATE` → `PLAKA`), used only when the vault
//! has no label of that name. Turkish letters in a label fold to ASCII.
//!
//! A placeholder followed by an apostrophe (`'` or `’`) and a Turkish
//! suffix gets the suffix the RESTORED value takes, by TDK vowel harmony,
//! consonant harmony and buffer consonants: `[NAME_1]'e` → `Ayşe'ye`,
//! `Kemal'e`; `[TCKN_1]'in` → `12345678950'nin`; numbers by their last
//! spoken word, upper-case abbreviations by their last letter's name.
//! Case, plural, relative `-ki` and copula suffixes are parsed; anything
//! else (`'s`, a possessive) is left as written. A suffix written
//! directly after the placeholder (`[NAME_1]e`) is not touched.
//!
//! The byte-exact round trip `restore(pseudonymize(x)) == x` holds in
//! every mode: [`Vault::pseudonymize`] skips the numbers of placeholder-shaped
//! text already in the prompt (`[NAME_1]` in the prompt makes the real
//! name `[NAME_2]`), and when the pseudonymized prompt itself contains an
//! accepted rendering (the prompt's `[Ayşe Kaya]` became `[[NAME_1]]`,
//! its `Kaya'e` became `[NAME_1]'e`), that rendering is exempted for that
//! entry, so it restores verbatim. The exemptions live in the vault: a
//! vault rebuilt with [`Vault::from_entries`] has none.
//!
//! Tolerant restore applies to vaults whose every key has the canonical
//! `LABEL_N` shape (every vault [`Vault::pseudonymize`] returns); a vault
//! with another key restores strictly. In a stream, a placeholder at the
//! end of a chunk is held back until the next character shows whether a
//! suffix follows.
//!
//! # Examples
//! ```
//! use redactify::Vault;
//!
//! let prompt = "My TCKN is 12345678950 and email is a@b.com";
//! let (anon, vault) = Vault::pseudonymize(prompt);
//! assert!(!anon.contains("12345678950"));
//! assert!(!anon.contains("a@b.com"));
//! assert!(anon.contains("[TCKN_1]"));
//! assert!(anon.contains("[EMAIL_1]"));
//!
//! // Simulated LLM response referencing the placeholders
//! let llm_response = "I see your TCKN is [TCKN_1] and email is [EMAIL_1].";
//! let restored = vault.restore(llm_response);
//! assert!(restored.contains("12345678950"));
//! assert!(restored.contains("a@b.com"));
//! assert!(!restored.contains("[TCKN_1]"));
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, MatchKind};

use crate::pii::entity::Entity;
use crate::pii::redact::replace_spans;

mod tolerant;
use tolerant::{Code, Ctx, Exempt, Index};

/// The largest number of entries [`Vault::try_from_entries`] accepts: a
/// restore table rebuilt from untrusted input (an HTTP or tool-call
/// payload) must stay bounded.
pub const MAX_VAULT_ENTRIES: usize = 10_000;

/// Error of [`Vault::try_from_entries`].
///
/// # Examples
/// ```
/// use redactify::{Vault, VaultError, MAX_VAULT_ENTRIES};
///
/// let too_many = (0..=MAX_VAULT_ENTRIES).map(|i| (format!("X_{i}"), String::new()));
/// assert_eq!(
///     Vault::try_from_entries(too_many),
///     Err(VaultError::TooManyEntries { limit: MAX_VAULT_ENTRIES })
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VaultError {
    /// More than `limit` entries were given.
    #[error("vault entries exceed the {limit}-entry limit")]
    TooManyEntries {
        /// The entry limit ([`MAX_VAULT_ENTRIES`]).
        limit: usize,
    },
    /// A JSON restore-table entry ([`Vault::try_from_json_entries`]) is
    /// not an object with string fields `placeholder` and `original`.
    #[error("vault entry {index} needs string fields `placeholder` and `original`")]
    InvalidEntry {
        /// The position of the entry in the table.
        index: usize,
    },
}

/// A vault that stores the mapping between placeholders and original PII values.
///
/// Created by [`Vault::pseudonymize`], consumed by [`Vault::restore`] (or
/// chunk by chunk through [`Vault::restorer`]). The vault is deliberately
/// not `Serialize` (avoid accidental persistence of real PII); it lives
/// only for the duration of one LLM round-trip.
#[derive(Clone)]
pub struct Vault {
    /// Maps placeholder (e.g. `"TCKN_1"`) -> original value (e.g. `"12345678950"`).
    entries: BTreeMap<String, String>,
    /// Renderings the tolerant restore must leave verbatim, by entry index
    /// (key order), sorted: they occur in the pseudonymized prompt itself.
    exempt: Vec<(u32, Exempt)>,
    /// The placeholder-token automaton, built on first restore (derived
    /// from `entries`, which never change after construction).
    matcher: OnceLock<Option<Matcher>>,
    /// The tolerant-form index (`None`: some key is not `LABEL_N`).
    tolerant: OnceLock<Option<Index>>,
}

impl PartialEq for Vault {
    /// Two vaults are equal when they hold the same entries and the same
    /// round-trip exemptions (see the module docs).
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries && self.exempt == other.exempt
    }
}

impl fmt::Debug for Vault {
    /// Shows only counts, never a placeholder or an original value
    /// (C-DEBUG).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("entries", &self.entries.len())
            .field("exempt", &self.exempt.len())
            .finish()
    }
}

/// How [`Vault::restore_with`] and [`Vault::restorer_with`] treat
/// placeholders an LLM has altered (see the module docs for the accepted
/// forms and the suffix rules).
///
/// # Examples
/// ```
/// use redactify::{RestoreOptions, Vault};
///
/// let (_, vault) = Vault::pseudonymize("Ad Soyad: Ayşe Kaya");
/// let reply = "Kayıt: <NAME_1> doğrulandı, [NAME_1]'e ulaşıldı.";
/// assert_eq!(
///     vault.restore(reply), // RestoreOptions::TOLERANT
///     "Kayıt: Ayşe Kaya doğrulandı, Ayşe Kaya'ya ulaşıldı."
/// );
/// assert_eq!(
///     vault.restore_with(reply, RestoreOptions::STRICT),
///     "Kayıt: <NAME_1> doğrulandı, Ayşe Kaya'e ulaşıldı."
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RestoreOptions {
    /// Restore the altered renderings of an issued placeholder
    /// (`<NAME_1>`, `[name_1]`, `[PERSON_1]`, ...).
    pub altered_forms: bool,
    /// Reshape a Turkish suffix after an apostrophe for the restored
    /// value (`[NAME_1]'e` → `Ayşe'ye`).
    pub suffix_repair: bool,
}

impl RestoreOptions {
    /// Only the exact `[LABEL_N]` token is restored; suffixes are kept as
    /// written (the behavior before tolerant restore).
    pub const STRICT: Self = Self {
        altered_forms: false,
        suffix_repair: false,
    };
    /// Altered forms and suffix repair (the default).
    pub const TOLERANT: Self = Self {
        altered_forms: true,
        suffix_repair: true,
    };

    /// These options with altered-form restore switched on or off.
    #[must_use]
    pub const fn with_altered_forms(mut self, on: bool) -> Self {
        self.altered_forms = on;
        self
    }

    /// These options with suffix repair switched on or off.
    #[must_use]
    pub const fn with_suffix_repair(mut self, on: bool) -> Self {
        self.suffix_repair = on;
        self
    }

    const fn is_strict(self) -> bool {
        !self.altered_forms && !self.suffix_repair
    }
}

impl Default for RestoreOptions {
    /// [`RestoreOptions::TOLERANT`].
    fn default() -> Self {
        Self::TOLERANT
    }
}

/// The token automaton shared by [`Vault::restore`] and
/// [`StreamRestorer`]: ONE aho-corasick automaton over every `[KEY]`
/// token (leftmost-first, patterns in key order), so a restore is a single
/// O(text) pass instead of one scan per entry.
#[derive(Clone)]
struct Matcher {
    /// Pattern `i` is the token of the `i`-th entry in key order.
    ac: AhoCorasick,
    /// Every token, sorted, for the "can this tail still become a token"
    /// test of the stream restorer.
    sorted_tokens: Vec<String>,
    /// Length in bytes of the longest token.
    max_len: usize,
}

impl Matcher {
    /// Builds the automaton; `None` only if the automaton would exceed the
    /// library's size limits (callers fall back to the linear scan).
    fn build(entries: &BTreeMap<String, String>) -> Option<Self> {
        let tokens: Vec<String> = entries.keys().map(|k| format!("[{k}]")).collect();
        // leftmost-first in key order reproduces the documented semantics
        // exactly: the earliest token in the text wins, and among tokens
        // starting at the same position the first entry in key order
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&tokens)
            .ok()?;
        let max_len = tokens.iter().map(String::len).max().unwrap_or(0);
        let mut sorted_tokens = tokens;
        sorted_tokens.sort_unstable();
        Some(Self {
            ac,
            sorted_tokens,
            max_len,
        })
    }

    /// Is `tail` a PROPER prefix of some token (it could still grow into
    /// one with more input)?
    fn is_proper_prefix(&self, tail: &str) -> bool {
        // the tokens starting with `tail` form one contiguous run of the
        // sorted list, beginning at its lower bound; `tail` itself, if it
        // is a token, is the first of that run
        let i = self.sorted_tokens.partition_point(|t| t.as_str() < tail);
        self.sorted_tokens[i..]
            .iter()
            .take(2)
            .any(|t| t.len() > tail.len() && t.starts_with(tail))
    }

    /// Restores every token of `text` (`originals[i]` = value of pattern
    /// `i`) and appends the result to `out`.
    fn restore_into(&self, text: &str, originals: &[&str], out: &mut String) {
        let mut last = 0;
        for m in self.ac.find_iter(text) {
            out.push_str(&text[last..m.start()]);
            out.push_str(originals[m.pattern().as_usize()]);
            last = m.end();
        }
        out.push_str(&text[last..]);
    }
}

/// The round-trip exemptions of a fresh vault: restores the pseudonymized
/// prompt `anon` tolerantly and exempts, per entry, every rendering or
/// suffix whose tolerant restore differs from the strict one (the strict
/// restore reproduces the prompt exactly), until the tolerant restore
/// reproduces `text`. Each round adds at least one exemption, so this
/// ends; if it ever ended without reproducing `text`, every entry is
/// exempted wholesale (tolerant restore then equals the strict one).
fn exemptions(index: &Index, originals: &[&str], text: &str, anon: &str) -> Vec<(u32, Exempt)> {
    let mut exempt: Vec<(u32, Exempt)> = Vec::new();
    let mut out = String::with_capacity(text.len());
    let mut scratch = String::new();
    // a hit deviates at most twice (its suffix, then its form)
    for _ in 0..=2 * originals.len() + 2 {
        let mut found: Vec<(u32, Result<tolerant::Form, Box<str>>)> = Vec::new();
        out.clear();
        let ctx = Ctx {
            index,
            originals,
            exempt: &exempt,
            forms: true,
            suffixes: true,
            skip: &[],
        };
        ctx.drive(
            anon,
            None,
            &mut Code::default(),
            true,
            &mut out,
            &mut scratch,
            &mut |hit, anon, repaired| {
                let written = &anon[hit.suffix_start..hit.suffix_end];
                if hit.suffix_end > hit.end && repaired != written {
                    found.push((hit.entry, Err(written.into())));
                } else if !hit.exact {
                    found.push((hit.entry, Ok(hit.form)));
                }
            },
        );
        if found.is_empty() {
            if out == text {
                return exempt;
            }
            break;
        }
        for (entry, what) in found {
            let i = match exempt.binary_search_by_key(&entry, |(e, _)| *e) {
                Ok(i) => i,
                Err(i) => {
                    exempt.insert(i, (entry, Exempt::default()));
                    i
                }
            };
            let x = &mut exempt[i].1;
            match what {
                Ok(form) => x.forms |= form.bit(),
                Err(suffix) if !x.suffixes.contains(&suffix) => x.suffixes.push(suffix),
                Err(_) => {}
            }
        }
    }
    (0..originals.len())
        .filter_map(|e| Some((u32::try_from(e).ok()?, Exempt::all())))
        .collect()
}

impl Vault {
    /// A vault over already-collected entries.
    fn with_entries(entries: BTreeMap<String, String>) -> Self {
        Self {
            entries,
            exempt: Vec::new(),
            matcher: OnceLock::new(),
            tolerant: OnceLock::new(),
        }
    }

    /// The token automaton (built once per vault).
    fn matcher(&self) -> Option<&Matcher> {
        self.matcher
            .get_or_init(|| Matcher::build(&self.entries))
            .as_ref()
    }

    /// The tolerant-form index (built once per vault), `None` when some
    /// key is not canonical.
    fn tolerant_index(&self) -> Option<&Index> {
        self.tolerant
            .get_or_init(|| Index::build(self.entries.keys().map(String::as_str)))
            .as_ref()
    }

    /// The tolerant scanner for `opts`, or `None` for a strict restore.
    fn ctx<'a>(&'a self, originals: &'a [&'a str], opts: RestoreOptions) -> Option<Ctx<'a>> {
        if opts.is_strict() {
            return None;
        }
        Some(Ctx {
            index: self.tolerant_index()?,
            originals,
            exempt: &self.exempt,
            forms: opts.altered_forms,
            suffixes: opts.suffix_repair,
            skip: &[],
        })
    }

    /// The original values in key order (pattern order of the matcher).
    fn originals(&self) -> Vec<&str> {
        self.entries.values().map(String::as_str).collect()
    }

    /// Pseudonymizes `text`: every detected PII entity is replaced with a typed,
    /// sequentially numbered placeholder. Returns the pseudonymized text and the
    /// vault needed to restore the originals later.
    ///
    /// Placeholders follow the format `[{TYPE}_{N}]` where `TYPE` is the entity
    /// label (TCKN, IBAN, EMAIL, ...) and `N` is a per-type counter starting at 1.
    /// The same original value always gets the same placeholder within one vault.
    ///
    /// This is the default raw-text configuration (tr+en locale set, no
    /// normalization pass); for options use
    /// [`Detector::pseudonymize`](crate::Detector::pseudonymize).
    ///
    /// # Examples
    /// ```
    /// use redactify::Vault;
    ///
    /// let (anon, _) = Vault::pseudonymize("TCKN 12345678950 and TCKN 12345678950");
    /// // Both occurrences map to the same placeholder
    /// assert_eq!(anon.matches("[TCKN_1]").count(), 2);
    /// ```
    #[must_use]
    pub fn pseudonymize(text: &str) -> (String, Self) {
        Self::pseudonymize_entities(text, &crate::pii::detect::detect(text))
    }

    /// The pseudonymization pass over ALREADY-DETECTED entities (the shared
    /// body of [`Vault::pseudonymize`] and the detection builder's
    /// `pseudonymize`), through the one span-replacement loop: entities may
    /// be unsorted; overlapping entities become ONE placeholder covering
    /// their union (no tail of a longer span leaks), typed by the longest
    /// span; invalid spans are skipped.
    pub(crate) fn pseudonymize_entities(text: &str, entities: &[Entity]) -> (String, Self) {
        let mut entries: BTreeMap<String, String> = BTreeMap::new();
        // original value -> placeholder (same value, same placeholder)
        let mut by_value: BTreeMap<String, String> = BTreeMap::new();
        let mut type_counters: BTreeMap<&'static str, u64> = BTreeMap::new();
        // numbers of placeholder-shaped text already in the prompt: never
        // issued, so the restore cannot rewrite that text
        let reserved = if entities.is_empty() {
            Vec::new()
        } else {
            tolerant::reserved(text)
        };
        let is_reserved = |label: &str, n: u64| {
            reserved
                .binary_search_by(|(l, m)| (&**l, *m).cmp(&(label, n)))
                .is_ok()
        };
        let out = replace_spans(text, entities, |kind, region| {
            let placeholder = if let Some(existing) = by_value.get(region) {
                existing.clone()
            } else {
                let label = kind.as_str();
                let n = type_counters.entry(label).or_insert(0);
                *n += 1;
                while is_reserved(label, *n) {
                    *n += 1;
                }
                let placeholder = format!("{label}_{n}");
                by_value.insert(region.to_owned(), placeholder.clone());
                entries.insert(placeholder.clone(), region.to_owned());
                placeholder
            };
            format!("[{placeholder}]")
        });
        let index = Index::build(entries.keys().map(String::as_str));
        let exempt = match &index {
            Some(index) => {
                let originals: Vec<&str> = entries.values().map(String::as_str).collect();
                exemptions(index, &originals, text, &out)
            }
            None => Vec::new(),
        };
        let vault = Self {
            entries,
            exempt,
            matcher: OnceLock::new(),
            tolerant: OnceLock::from(index),
        };
        (out, vault)
    }

    /// Restores original PII values in an LLM response by replacing every
    /// known placeholder with its original value from the vault.
    ///
    /// Placeholders that the vault does not know (e.g. the LLM hallucinated
    /// `[TCKN_99]`) are left as-is - the vault never guesses. One left-to-right
    /// pass: the earliest placeholder wins (among placeholders starting at
    /// the same position, the first in key order), and restored values are
    /// never re-scanned, so an original that itself contains a
    /// placeholder-shaped token survives verbatim.
    ///
    /// # Examples
    /// ```
    /// use redactify::Vault;
    ///
    /// let (_, vault) = Vault::pseudonymize("TCKN 12345678950");
    /// let restored = vault.restore("Your [TCKN_1] is valid. [TCKN_99] unknown.");
    /// assert!(restored.contains("12345678950"));
    /// assert!(restored.contains("[TCKN_99]")); // unknown -> left as-is
    /// ```
    ///
    /// Altered placeholder renderings and Turkish suffixes are handled as
    /// described in the module docs ([`RestoreOptions::TOLERANT`]); for the
    /// exact-token-only restore use [`Vault::restore_with`] with
    /// [`RestoreOptions::STRICT`].
    #[must_use]
    pub fn restore(&self, text: &str) -> String {
        self.restore_with(text, RestoreOptions::default())
    }

    /// [`Vault::restore`] with explicit [`RestoreOptions`].
    ///
    /// # Examples
    /// ```
    /// use redactify::{RestoreOptions, Vault};
    ///
    /// let (_, vault) = Vault::pseudonymize("TCKN 12345678950");
    /// let reply = "[tckn_1] / [TCKN_1]'in";
    /// assert_eq!(vault.restore(reply), "12345678950 / 12345678950'nin");
    /// assert_eq!(
    ///     vault.restore_with(reply, RestoreOptions::STRICT),
    ///     "[tckn_1] / 12345678950'in"
    /// );
    /// // forms only, suffixes as written
    /// let forms_only = RestoreOptions::TOLERANT.with_suffix_repair(false);
    /// assert_eq!(
    ///     vault.restore_with(reply, forms_only),
    ///     "12345678950 / 12345678950'in"
    /// );
    /// ```
    #[must_use]
    pub fn restore_with(&self, text: &str, opts: RestoreOptions) -> String {
        let originals = self.originals();
        let mut out = String::with_capacity(text.len());
        if let Some(ctx) = self.ctx(&originals, opts) {
            let mut scratch = String::new();
            ctx.drive(
                text,
                None,
                &mut Code::default(),
                true,
                &mut out,
                &mut scratch,
                &mut |_, _, _| {},
            );
            return out;
        }
        let Some(matcher) = self.matcher() else {
            return self.restore_linear(text);
        };
        matcher.restore_into(text, &originals, &mut out);
        out
    }

    /// [`Vault::restore_with`] over the whole of `text` in one pass (one
    /// code context from its start), restoring nothing that touches a
    /// `skip` range (sorted, disjoint byte ranges; the code context is
    /// still tracked through them). The text is restored in two halves
    /// that share that context, split at `mark` (a line start, `0` or
    /// `text.len()`: no rendering spans a line break, so the split changes
    /// nothing); returns the restored text and the output offset of
    /// `mark`.
    #[cfg(feature = "api")]
    pub(crate) fn restore_skipping(
        &self,
        text: &str,
        opts: RestoreOptions,
        skip: &[(usize, usize)],
        mark: usize,
    ) -> (String, usize) {
        let originals = self.originals();
        let mut out = String::with_capacity(text.len());
        let halves = [(0, mark), (mark, text.len())];
        if let Some(ctx) = self.ctx(&originals, opts) {
            let mut code = Code::default();
            let mut scratch = String::new();
            let mut mark_out = 0;
            for (i, &(from, to)) in halves.iter().enumerate() {
                let shifted: Vec<(usize, usize)> = skip
                    .iter()
                    .filter(|&&(s, e)| s < to && e > from)
                    .map(|&(s, e)| (s.max(from) - from, e.min(to) - from))
                    .collect();
                let half = Ctx {
                    skip: &shifted,
                    ..ctx
                };
                let prev = text[..from].chars().next_back();
                half.drive(
                    &text[from..to],
                    prev,
                    &mut code,
                    true,
                    &mut out,
                    &mut scratch,
                    &mut |_, _, _| {},
                );
                if i == 0 {
                    mark_out = out.len();
                }
            }
            return (out, mark_out);
        }
        // strict: exact tokens only, no context; the pieces outside `skip`
        // (and the two halves) are restored on their own
        let mut mark_out = 0;
        for (i, &(from, to)) in halves.iter().enumerate() {
            let mut at = from;
            let pieces = skip
                .iter()
                .map(|&(s, e)| (s.clamp(from, to), e.clamp(from, to)))
                .filter(|&(s, e)| s < e)
                .chain(std::iter::once((to, to)));
            for (s, e) in pieces {
                if at < s {
                    match self.matcher() {
                        Some(m) => m.restore_into(&text[at..s], &originals, &mut out),
                        None => out.push_str(&self.restore_linear(&text[at..s])),
                    }
                }
                out.push_str(&text[s.max(at)..e.max(at)]);
                at = at.max(e);
            }
            if i == 0 {
                mark_out = out.len();
            }
        }
        (out, mark_out)
    }

    /// The reference restore: one `find` per token at every step. Same
    /// result as the automaton; used only if the automaton cannot be built.
    fn restore_linear(&self, text: &str) -> String {
        // single pass, earliest-match-first: restored content is never
        // re-scanned. Sequential `.replace` calls would rescan it, so an
        // ORIGINAL value containing another entry's placeholder token (or
        // a restored value growing a token) would corrupt the round trip.
        let tokens: Vec<(String, &str)> = self
            .entries
            .iter()
            .map(|(k, v)| (format!("[{k}]"), v.as_str()))
            .collect();
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        loop {
            let mut best: Option<(usize, &(String, &str))> = None;
            for entry in &tokens {
                if let Some(pos) = rest.find(entry.0.as_str()) {
                    match best {
                        Some((b, _)) if b <= pos => {}
                        _ => best = Some((pos, entry)),
                    }
                }
            }
            let Some((pos, (token, original))) = best else {
                out.push_str(rest);
                break;
            };
            out.push_str(&rest[..pos]);
            out.push_str(original);
            rest = &rest[pos + token.len()..];
        }
        out
    }

    /// A streaming restorer over this vault: feed an LLM response chunk by
    /// chunk with [`StreamRestorer::push`] and end with
    /// [`StreamRestorer::finish`]; the concatenated output equals
    /// [`Vault::restore`] of the whole response, whatever the chunk
    /// boundaries.
    ///
    /// # Examples
    /// ```
    /// use redactify::Vault;
    ///
    /// let (_, vault) = Vault::pseudonymize("TCKN 12345678950");
    /// let mut r = vault.restorer();
    /// let mut out = String::new();
    /// for chunk in ["Your TCKN is [TC", "KN_1", "], noted."] {
    ///     out.push_str(&r.push(chunk));
    /// }
    /// out.push_str(&r.finish());
    /// assert_eq!(out, "Your TCKN is 12345678950, noted.");
    /// ```
    #[must_use]
    pub fn restorer(&self) -> StreamRestorer<'_> {
        self.restorer_with(RestoreOptions::default())
    }

    /// [`Vault::restorer`] with explicit [`RestoreOptions`]; the
    /// concatenated output equals [`Vault::restore_with`] with the same
    /// options.
    ///
    /// # Examples
    /// ```
    /// use redactify::{RestoreOptions, Vault};
    ///
    /// let (_, vault) = Vault::pseudonymize("Ad Soyad: Ayşe Kaya");
    /// let mut r = vault.restorer_with(RestoreOptions::TOLERANT);
    /// let mut out = r.push("Not: <NAM");
    /// out += &r.push("E_1>'");
    /// out += &r.push("e ulaşıldı.");
    /// out += &r.finish();
    /// assert_eq!(out, "Not: Ayşe Kaya'ya ulaşıldı.");
    /// ```
    #[must_use]
    pub fn restorer_with(&self, opts: RestoreOptions) -> StreamRestorer<'_> {
        let tolerant = if opts.is_strict() {
            None
        } else {
            self.tolerant_index().map(|_| opts)
        };
        StreamRestorer {
            matcher: if tolerant.is_some() {
                None
            } else {
                self.matcher()
            },
            tolerant,
            originals: self.originals(),
            vault: self,
            pending: String::new(),
            prev: None,
            code: Code::default(),
            scratch: String::new(),
        }
    }

    /// Returns the number of unique PII entries stored in the vault.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the vault holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns an iterator over `(placeholder, original)` pairs.
    pub fn entries_iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.entries.iter()
    }

    /// Rebuilds a vault from previously persisted `(placeholder, original)`
    /// pairs (the exact shape [`Vault::entries_iter`] yields), enabling
    /// stateless round-trips across process boundaries - e.g. pseudonymize in
    /// one HTTP request, restore in another.
    ///
    /// Placeholders are taken verbatim and the entry count is unbounded;
    /// for entries from untrusted input use [`Vault::try_from_entries`].
    ///
    /// # Examples
    /// ```
    /// use redactify::Vault;
    ///
    /// let (anon, vault) = Vault::pseudonymize("TCKN 12345678950");
    /// let entries: Vec<(String, String)> = vault
    ///     .entries_iter()
    ///     .map(|(p, o)| (p.to_owned(), o.to_owned()))
    ///     .collect();
    /// let rebuilt = Vault::from_entries(entries);
    /// assert_eq!(rebuilt.restore(&anon), "TCKN 12345678950");
    /// ```
    #[must_use]
    pub fn from_entries<I: IntoIterator<Item = (String, String)>>(entries: I) -> Self {
        Self::with_entries(entries.into_iter().collect())
    }

    /// Like [`Vault::from_entries`], for entries from untrusted input: a
    /// placeholder may be given as it appears in pseudonymized text
    /// (`"[TCKN_1]"`; one enclosing pair of square brackets is stripped)
    /// or bare (`"TCKN_1"`), and more than [`MAX_VAULT_ENTRIES`] entries
    /// are refused.
    ///
    /// # Errors
    /// [`VaultError::TooManyEntries`] when the input holds more than
    /// [`MAX_VAULT_ENTRIES`] entries (counted before deduplication).
    ///
    /// # Examples
    /// ```
    /// use redactify::Vault;
    ///
    /// let vault = Vault::try_from_entries([
    ///     ("[TCKN_1]".to_owned(), "12345678950".to_owned()),
    ///     ("EMAIL_1".to_owned(), "a@b.com".to_owned()),
    /// ])
    /// .unwrap();
    /// assert_eq!(vault.original_for("TCKN_1"), Some("12345678950"));
    /// assert_eq!(
    ///     vault.restore("[TCKN_1] / [EMAIL_1]"),
    ///     "12345678950 / a@b.com"
    /// );
    /// ```
    pub fn try_from_entries<I: IntoIterator<Item = (String, String)>>(
        entries: I,
    ) -> Result<Self, VaultError> {
        let mut map = BTreeMap::new();
        for (count, (placeholder, original)) in entries.into_iter().enumerate() {
            if count >= MAX_VAULT_ENTRIES {
                return Err(VaultError::TooManyEntries {
                    limit: MAX_VAULT_ENTRIES,
                });
            }
            let key = match placeholder
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
            {
                Some(bare) => bare.to_owned(),
                None => placeholder,
            };
            map.insert(key, original);
        }
        Ok(Self::with_entries(map))
    }

    /// [`Vault::try_from_entries`] over a JSON restore table: an array of
    /// `{"placeholder": "...", "original": "..."}` objects (the shape the
    /// REST and MCP pseudonymize operations return; other members of an entry
    /// are ignored). Only the first [`MAX_VAULT_ENTRIES`] + 1 entries are
    /// read: one entry past the limit is enough to refuse the table.
    ///
    /// # Errors
    /// [`VaultError::InvalidEntry`] for the first entry (within that
    /// prefix) without string `placeholder` and `original` fields, else
    /// [`VaultError::TooManyEntries`] when the table holds more than
    /// [`MAX_VAULT_ENTRIES`] entries.
    ///
    /// # Examples
    /// ```
    /// use redactify::{Vault, VaultError};
    /// use serde_json::json;
    ///
    /// let table = json!([{"placeholder": "[TCKN_1]", "original": "12345678950"}]);
    /// let vault = Vault::try_from_json_entries(table.as_array().unwrap()).unwrap();
    /// assert_eq!(vault.restore("[TCKN_1]"), "12345678950");
    ///
    /// let bad = json!([{"placeholder": "TCKN_1"}]);
    /// assert_eq!(
    ///     Vault::try_from_json_entries(bad.as_array().unwrap()),
    ///     Err(VaultError::InvalidEntry { index: 0 })
    /// );
    /// ```
    pub fn try_from_json_entries(entries: &[serde_json::Value]) -> Result<Self, VaultError> {
        let mut pairs = Vec::with_capacity(entries.len().min(MAX_VAULT_ENTRIES + 1));
        for (index, entry) in entries.iter().take(MAX_VAULT_ENTRIES + 1).enumerate() {
            let (Some(placeholder), Some(original)) = (
                entry.get("placeholder").and_then(serde_json::Value::as_str),
                entry.get("original").and_then(serde_json::Value::as_str),
            ) else {
                return Err(VaultError::InvalidEntry { index });
            };
            pairs.push((placeholder.to_owned(), original.to_owned()));
        }
        Self::try_from_entries(pairs)
    }

    /// Returns the placeholder for a given original value, if stored.
    #[must_use]
    pub fn placeholder_for(&self, original: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(_, v)| v == &original)
            .map(|(k, _)| k.as_str())
    }

    /// Returns the original value for a given placeholder, if stored.
    #[must_use]
    pub fn original_for(&self, placeholder: &str) -> Option<&str> {
        self.entries.get(placeholder).map(String::as_str)
    }
}

/// Restores a streamed LLM response chunk by chunk (see
/// [`Vault::restorer`]).
///
/// Every chunk is restored in one pass over the vault's token automaton.
/// Output is held back only while it may still be the start of a
/// placeholder: from the earliest `[` within the last `longest token - 1`
/// bytes whose remainder is a proper prefix of some placeholder token.
/// Everything before that point is final and returned immediately, so the
/// concatenation of every [`push`](StreamRestorer::push) result and the
/// [`finish`](StreamRestorer::finish) result is exactly
/// [`Vault::restore`] of the whole stream.
///
/// In tolerant mode (the default) the same holds for every accepted
/// rendering and suffix: output is held back from a position whose
/// restore decision needs more input (an open delimiter, an upper-case
/// word that may be a bare placeholder, a placeholder that may be
/// followed by an apostrophe suffix). That window is bounded (under 250
/// bytes at most), so memory stays bounded whatever the stream length.
pub struct StreamRestorer<'v> {
    vault: &'v Vault,
    /// The strict automaton (`None` in tolerant mode).
    matcher: Option<&'v Matcher>,
    /// Tolerant mode and its options (`None`: strict).
    tolerant: Option<RestoreOptions>,
    originals: Vec<&'v str>,
    /// Input received but not yet emitted (a possible token start).
    pending: String,
    /// The last input character before `pending` (tolerant mode).
    prev: Option<char>,
    /// The code context at the start of `pending` (tolerant mode).
    code: Code,
    /// The repaired-suffix buffer (tolerant mode).
    scratch: String,
}

impl StreamRestorer<'_> {
    /// Tolerant mode: restores `pending` (with `eof` at the end of the
    /// stream) and drops what became final.
    fn drive_tolerant(&mut self, opts: RestoreOptions, eof: bool) -> Option<String> {
        let ctx = self.vault.ctx(&self.originals, opts)?;
        let mut out = String::with_capacity(self.pending.len());
        let cut = ctx.drive(
            &self.pending,
            self.prev,
            &mut self.code,
            eof,
            &mut out,
            &mut self.scratch,
            &mut |_, _, _| {},
        );
        if let Some(c) = self.pending[..cut].chars().next_back() {
            self.prev = Some(c);
        }
        self.pending.drain(..cut);
        Some(out)
    }
}

impl StreamRestorer<'_> {
    /// Feeds the next chunk; returns the restored text that is final now.
    ///
    /// # Examples
    /// ```
    /// use redactify::Vault;
    ///
    /// let (_, vault) = Vault::pseudonymize("mail a@b.com");
    /// let mut r = vault.restorer();
    /// assert_eq!(r.push("write to [EMA"), "write to ");
    /// assert_eq!(r.push("IL_1] now"), "a@b.com now");
    /// assert_eq!(r.finish(), "");
    /// ```
    #[must_use]
    pub fn push(&mut self, chunk: &str) -> String {
        self.pending.push_str(chunk);
        if let Some(opts) = self.tolerant {
            if let Some(out) = self.drive_tolerant(opts, false) {
                return out;
            }
        }
        let Some(matcher) = self.matcher else {
            // no automaton: hold everything until finish (still exact)
            return String::new();
        };
        let buf = self.pending.as_str();
        // hold-back candidates: a '[' close enough to the end that the
        // remainder is shorter than the longest token, and the remainder
        // is a proper prefix of some token
        let window = buf.len().saturating_sub(matcher.max_len.saturating_sub(1));
        let holds: Vec<usize> = buf.as_bytes()[window..]
            .iter()
            .enumerate()
            .filter(|&(_, &b)| b == b'[')
            .map(|(i, _)| window + i)
            // '[' is ASCII: every hold position is a char boundary
            .filter(|&p| matcher.is_proper_prefix(&buf[p..]))
            .collect();
        let hold_from = |cursor: usize| {
            holds
                .iter()
                .copied()
                .find(|&p| p >= cursor)
                .unwrap_or(buf.len())
        };
        let mut out = String::with_capacity(buf.len());
        let mut cursor = 0;
        for m in matcher.ac.find_iter(buf) {
            // a match starting at or after a possible (incomplete) token
            // start could still be superseded: stop there
            if m.start() >= hold_from(cursor) {
                break;
            }
            out.push_str(&buf[cursor..m.start()]);
            out.push_str(self.originals[m.pattern().as_usize()]);
            cursor = m.end();
        }
        let cut = hold_from(cursor);
        out.push_str(&buf[cursor..cut]);
        self.pending.drain(..cut);
        out
    }

    /// Ends the stream: restores and returns whatever is still held back.
    ///
    /// # Examples
    /// ```
    /// use redactify::Vault;
    ///
    /// let (_, vault) = Vault::pseudonymize("TCKN 12345678950");
    /// let mut r = vault.restorer();
    /// assert_eq!(r.push("[TCKN_"), "");
    /// // the stream ended inside a would-be token: it is emitted verbatim
    /// assert_eq!(r.finish(), "[TCKN_");
    /// ```
    #[must_use]
    pub fn finish(&mut self) -> String {
        if let Some(opts) = self.tolerant {
            if let Some(out) = self.drive_tolerant(opts, true) {
                return out;
            }
        }
        let rest = std::mem::take(&mut self.pending);
        match self.matcher {
            Some(matcher) => {
                let mut out = String::with_capacity(rest.len());
                matcher.restore_into(&rest, &self.originals, &mut out);
                out
            }
            None => self.vault.restore_linear(&rest),
        }
    }
}

impl fmt::Debug for StreamRestorer<'_> {
    /// Shows only sizes, never the held-back response text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamRestorer")
            .field("entries", &self.originals.len())
            .field("pending_bytes", &self.pending.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{RestoreOptions, Vault, VaultError, MAX_VAULT_ENTRIES};
    use crate::pii::entity::{Entity, EntityType};

    #[cfg(feature = "api")]
    #[test]
    fn skipping_restore_keeps_ranges_and_one_code_context() {
        let v = Vault::from_entries([("PHONE_1".to_owned(), "0532".to_owned())]);
        let tolerant = RestoreOptions::TOLERANT;
        // a skipped range is copied, the rest restored
        let text = "[PHONE_1] x//[PHONE_1] PHONE_1";
        let (out, mark) = v.restore_skipping(text, tolerant, &[(10, 22)], text.len());
        assert_eq!(out, "0532 x//[PHONE_1] 0532");
        assert_eq!(mark, out.len());
        // the backtick inside the skipped range still opens a code span
        let text = "`a//b PHONE_1` PHONE_1";
        let (out, _) = v.restore_skipping(text, tolerant, &[(0, 5)], 0);
        assert_eq!(out, "`a//b PHONE_1` 0532");
        // a fence opened before the mark holds after it; the mark maps to
        // the output position of the line start
        let text = "[PHONE_1]\n```\nPHONE_1";
        let (out, mark) = v.restore_skipping(text, tolerant, &[], 14);
        assert_eq!(out, "0532\n```\nPHONE_1");
        assert_eq!(&out[mark..], "PHONE_1");
        assert_eq!(out, v.restore_with(text, tolerant));
        // a rendering reaching into a skipped range is not taken; a shorter
        // one wholly outside it is judged on its own
        let (out, _) = v.restore_skipping("[PHONE_1]", tolerant, &[(8, 9)], 0);
        assert_eq!(out, "[0532]");
        let (out, _) = v.restore_skipping("[PHONE_1]", tolerant, &[(1, 9)], 0);
        assert_eq!(out, "[PHONE_1]");
        // strict: exact tokens outside the ranges, either half
        let strict = RestoreOptions::STRICT;
        let text = "[PHONE_1] <PHONE_1>\n[PHONE_1] [PHONE_1]";
        let (out, mark) = v.restore_skipping(text, strict, &[(30, 39)], 20);
        assert_eq!(out, "0532 <PHONE_1>\n0532 [PHONE_1]");
        assert_eq!(&out[mark..], "0532 [PHONE_1]");
    }

    fn vault(pairs: &[(&str, &str)]) -> Vault {
        Vault::from_entries(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        )
    }

    /// Restores `text` through the restorer, split into chunks at `cuts`
    /// (sorted char boundaries).
    fn streamed(v: &Vault, text: &str, cuts: &[usize]) -> String {
        let mut r = v.restorer();
        let mut out = String::new();
        let mut prev = 0;
        for &c in cuts {
            out.push_str(&r.push(&text[prev..c]));
            prev = c;
        }
        out.push_str(&r.push(&text[prev..]));
        out.push_str(&r.finish());
        out
    }

    #[test]
    fn restore_never_rescans_restored_content() {
        // a sequential replace would re-scan restored text and corrupt the
        // round trip: the NAME_1 original embeds a TCKN_1 token that must
        // survive restoration verbatim
        let vault = vault(&[
            ("NAME_1", "literal [TCKN_1] inside"),
            ("TCKN_1", "12345678950"),
        ]);
        let restored = vault.restore("a [NAME_1] b [TCKN_1] c");
        assert_eq!(restored, "a literal [TCKN_1] inside b 12345678950 c");
        assert_eq!(vault.restore_linear("a [NAME_1] b [TCKN_1] c"), restored);
    }

    #[test]
    fn automaton_and_linear_restore_agree_on_tricky_tables() {
        // keys whose tokens are prefixes of each other ("[A]" / "[A]]"),
        // nested brackets, an empty key, adjacent and overlapping tokens
        let tables: [&[(&str, &str)]; 3] = [
            &[("A", "x"), ("A]", "y"), ("", "empty"), ("[B", "z")],
            &[("TCKN_1", "1"), ("TCKN_10", "10"), ("TCKN_1]", "w")],
            &[],
        ];
        let texts = [
            "",
            "[A]] [A] [] [[B] [[A]]",
            "[TCKN_1][TCKN_10][TCKN_1]] [TCKN_",
            "no tokens at all [ ] ]]",
            "\u{fc}[A]\u{131}[TCKN_10]\u{15f}",
        ];
        for table in tables {
            let v = vault(table);
            for text in texts {
                let full = v.restore(text);
                assert_eq!(full, v.restore_linear(text), "{table:?} / {text:?}");
                // every single split point (char boundaries)
                for cut in (0..=text.len()).filter(|&i| text.is_char_boundary(i)) {
                    assert_eq!(
                        streamed(&v, text, &[cut]),
                        full,
                        "{table:?} / {text:?} @ {cut}"
                    );
                }
                // one char per chunk
                let cuts: Vec<usize> = text.char_indices().map(|(i, _)| i).skip(1).collect();
                assert_eq!(
                    streamed(&v, text, &cuts),
                    full,
                    "{table:?} / {text:?} char-wise"
                );
            }
        }
    }

    #[test]
    fn restorer_holds_back_only_a_possible_token_start() {
        let v = vault(&[("TCKN_1", "12345678950")]);
        let mut r = v.restorer_with(RestoreOptions::STRICT);
        // a '[' that cannot start a token is not held back
        assert_eq!(r.push("array[0] and [TC"), "array[0] and ");
        assert_eq!(r.push("KN_2] stays, "), "[TCKN_2] stays, ");
        assert_eq!(r.push("[TCKN_1]"), "12345678950");
        assert_eq!(r.finish(), "");
        let dbg = format!("{r:?}");
        assert!(dbg.contains("pending_bytes: 0"), "{dbg}");

        // tolerant: a complete token also waits for the next character
        // (an apostrophe suffix may follow), nothing else changes
        let mut r = v.restorer();
        assert_eq!(r.push("array[0] and [TC"), "array[0] and ");
        assert_eq!(r.push("KN_2] stays, "), "[TCKN_2] stays, ");
        assert_eq!(r.push("[TCKN_1]"), "");
        assert_eq!(r.push("'e "), "12345678950'ye ");
        assert_eq!(r.push("TCKN_"), "");
        assert_eq!(r.finish(), "TCKN_");
        let dbg = format!("{r:?}");
        assert!(dbg.contains("pending_bytes: 0"), "{dbg}");
    }

    #[test]
    fn try_from_entries_strips_brackets_and_caps_the_count() {
        let v = Vault::try_from_entries([
            ("[TCKN_1]".to_owned(), "12345678950".to_owned()),
            ("EMAIL_1".to_owned(), "a@b.com".to_owned()),
            // only ONE enclosing pair is stripped; a lone bracket stays
            ("[[X_1]]".to_owned(), "x".to_owned()),
            ("[Y_1".to_owned(), "y".to_owned()),
        ])
        .unwrap();
        assert_eq!(v.original_for("TCKN_1"), Some("12345678950"));
        assert_eq!(v.original_for("EMAIL_1"), Some("a@b.com"));
        assert_eq!(v.original_for("[X_1]"), Some("x"));
        assert_eq!(v.original_for("[Y_1"), Some("y"));
        let at_limit = (0..MAX_VAULT_ENTRIES).map(|i| (format!("K_{i}"), i.to_string()));
        assert_eq!(
            Vault::try_from_entries(at_limit).unwrap().len(),
            MAX_VAULT_ENTRIES
        );
        let over = (0..=MAX_VAULT_ENTRIES).map(|i| (format!("K_{i}"), i.to_string()));
        assert_eq!(
            Vault::try_from_entries(over),
            Err(VaultError::TooManyEntries {
                limit: MAX_VAULT_ENTRIES
            })
        );
    }

    #[test]
    fn overlapping_entities_become_one_placeholder_without_a_tail_leak() {
        // a Name and an Address may overlap (priority-8 coexistence): the
        // old cursor loop skipped the second span and leaked its tail
        let text = "Ahmet Yilmaz Caddesi 5 burada";
        let ents = vec![
            Entity {
                kind: EntityType::Name,
                start: 0,
                end: 12,
                text: "Ahmet Yilmaz".into(),
                score: 0.9,
            },
            Entity {
                kind: EntityType::Address,
                start: 6,
                end: 22,
                text: "Yilmaz Caddesi 5".into(),
                score: 0.9,
            },
        ];
        let (anon, v) = Vault::pseudonymize_entities(text, &ents);
        assert_eq!(anon, "[ADDRESS_1] burada");
        assert_eq!(v.original_for("ADDRESS_1"), Some("Ahmet Yilmaz Caddesi 5"));
        assert_eq!(v.restore(&anon), text);
    }

    #[test]
    fn equality_and_debug_ignore_the_cached_automaton() {
        let a = vault(&[("TCKN_1", "12345678950")]);
        let b = a.clone();
        let _ = a.restore("[TCKN_1]"); // builds a's automaton only
        assert_eq!(a, b);
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
        // counts only, never a placeholder or an original (C-DEBUG)
        assert_eq!(format!("{a:?}"), "Vault { entries: 1, exempt: 0 }");
        let (_, sealed) = Vault::pseudonymize("Ad Soyad: Ay\u{15f}e Kaya, TCKN 12345678950");
        let dbg = format!("{sealed:?}");
        assert!(
            !dbg.contains("12345678950") && !dbg.contains("Kaya"),
            "{dbg}"
        );
        assert!(!dbg.contains("TCKN") && !dbg.contains("NAME"), "{dbg}");
        assert_eq!(format!("{:#?}", sealed).matches(':').count(), 2);
    }

    #[test]
    fn opt_in_locale_pack_is_visible_to_the_vault() {
        // the default tr+en rule set cannot see a German Steuer-IdNr (11
        // contiguous digits, cue present); opting in the de pack must make
        // the vault flow mask it (parity with locale-aware detection,
        // which the REST/MCP layers do not expose yet)
        let text = "IdNr 86095742719 in der Akte";
        let (anon_default, _) = Vault::pseudonymize(text);
        assert!(anon_default.contains("86095742719"), "{anon_default}");

        let ents = crate::pii::detect::engine_detect(text, &["de"]);
        let (anon_de, vault) = Vault::pseudonymize_entities(text, &ents);
        assert!(!anon_de.contains("86095742719"), "{anon_de}");
        assert!(anon_de.contains("[DE_TAX_ID_1]"), "{anon_de}");
        assert_eq!(vault.restore(&anon_de), text);
    }

    #[test]
    fn empty_locale_slice_matches_default_pseudonymize() {
        // documented contract: empty slice = the default tr+en set, so the
        // two entry points must agree byte for byte
        let text = "TCKN 12345678950, mail a@b.com";
        let (a, va) = Vault::pseudonymize(text);
        let (b, vb) =
            Vault::pseudonymize_entities(text, &crate::pii::detect::engine_detect(text, &[]));
        assert_eq!(a, b);
        assert_eq!(va, vb);
    }

    #[test]
    fn round_trip_single_pii() {
        let (anon, vault) = Vault::pseudonymize("TCKN 12345678950");
        assert!(anon.contains("[TCKN_1]"));
        assert!(!anon.contains("12345678950"));
        assert_eq!(vault.len(), 1);

        let restored = vault.restore(&anon);
        assert_eq!(restored, "TCKN 12345678950");
    }

    #[test]
    fn round_trip_multiple_types() {
        let text = "TCKN 12345678950, IBAN TR33 0006 1005 1978 6457 8413 26, mail a@b.com";
        let (anon, vault) = Vault::pseudonymize(text);
        assert!(anon.contains("[TCKN_1]"));
        assert!(anon.contains("[IBAN_1]"));
        assert!(anon.contains("[EMAIL_1]"));
        assert_eq!(vault.len(), 3);

        let restored = vault.restore(&anon);
        assert_eq!(restored, text);
    }

    #[test]
    fn same_value_same_placeholder() {
        let (anon, _) = Vault::pseudonymize("TCKN 12345678950 ve tekrar 12345678950");
        assert_eq!(anon.matches("[TCKN_1]").count(), 2);
    }

    #[test]
    fn different_values_different_placeholders() {
        let text = "TCKN 12345678950 ve TCKN 10000000146";
        let (anon, vault) = Vault::pseudonymize(text);
        assert!(anon.contains("[TCKN_1]"));
        assert!(anon.contains("[TCKN_2]"));
        assert_eq!(vault.len(), 2);
    }

    #[test]
    fn llm_response_restoration() {
        let (_, vault) = Vault::pseudonymize("SSN 536-90-6292 ve TCKN 12345678950");

        // Simulated LLM response that references the placeholders
        let response = "I found your SSN [SSN_1] and TCKN [TCKN_1]. Is this correct?";
        let restored = vault.restore(response);
        assert!(restored.contains("536-90-6292"));
        assert!(restored.contains("12345678950"));
        assert!(!restored.contains("[SSN_1]"));
        assert!(!restored.contains("[TCKN_1]"));
    }

    #[test]
    fn unknown_placeholder_left_as_is() {
        let (_, vault) = Vault::pseudonymize("TCKN 12345678950");
        let result = vault.restore("ref [TCKN_1] and [TCKN_99]");
        assert!(result.contains("12345678950"));
        assert!(result.contains("[TCKN_99]")); // not in vault -> untouched
    }

    #[test]
    fn no_pii_returns_unchanged() {
        let (anon, vault) = Vault::pseudonymize("hello world no PII");
        assert_eq!(anon, "hello world no PII");
        assert!(vault.is_empty());
    }

    #[test]
    fn cross_locale_vault() {
        let text = "SSN 536-90-6292 ve TCKN 12345678950";
        let (anon, vault) = Vault::pseudonymize(text);
        assert_eq!(vault.len(), 2);
        let restored = vault.restore(&anon);
        assert_eq!(restored, text);
    }

    #[test]
    fn lookup_helpers() {
        let (_, vault) = Vault::pseudonymize("TCKN 12345678950");
        assert_eq!(vault.placeholder_for("12345678950"), Some("TCKN_1"));
        assert_eq!(vault.original_for("TCKN_1"), Some("12345678950"));
        assert_eq!(vault.original_for("TCKN_99"), None);
    }

    #[test]
    fn vkn_with_cue_is_vaulted() {
        let (anon, vault) = Vault::pseudonymize("vergi no 1234567890");
        assert!(anon.contains("[VKN_1]"));
        assert_eq!(vault.len(), 1);
    }

    #[test]
    fn empty_text() {
        let (anon, vault) = Vault::pseudonymize("");
        assert_eq!(anon, "");
        assert!(vault.is_empty());
    }

    fn name(start: usize, end: usize, text: &str) -> Entity {
        Entity {
            kind: EntityType::Name,
            start,
            end,
            text: text[start..end].into(),
            score: 0.9,
        }
    }

    #[test]
    fn prompt_renderings_are_exempted_per_entry() {
        // the prompt wraps one name in brackets and misspells a suffix of
        // the other: both must restore verbatim, the rest stays tolerant
        let text = "[Kaya] ile Ahmet'a yazdı";
        let ents = [name(1, 5, text), name(11, 16, text)];
        let (anon, v) = Vault::pseudonymize_entities(text, &ents);
        assert_eq!(anon, "[[NAME_1]] ile [NAME_2]'a yazdı");
        assert_eq!(v.exempt.len(), 2);
        for opts in [
            RestoreOptions::STRICT,
            RestoreOptions::TOLERANT,
            RestoreOptions::TOLERANT.with_altered_forms(false),
            RestoreOptions::TOLERANT.with_suffix_repair(false),
        ] {
            assert_eq!(v.restore_with(&anon, opts), text, "{opts:?}");
        }
        assert_eq!(v.restore("[[NAME_1]] [[NAME_2]]"), "[Kaya] Ahmet");
        assert_eq!(v.restore("[NAME_2]'a [NAME_2]'ın"), "Ahmet'a Ahmet'in");
        assert_eq!(v.restore("[NAME_1]'e"), "Kaya'ya");
        // exemptions take part in equality, never in Debug's content
        assert_ne!(v, Vault::from_entries(v.entries.clone()));
        assert_eq!(format!("{v:?}"), "Vault { entries: 2, exempt: 2 }");
    }

    #[test]
    fn a_double_bracket_after_a_suffix_is_exempted_in_both() {
        let text = "[Kaya]'e";
        let (anon, v) = Vault::pseudonymize_entities(text, &[name(1, 5, text)]);
        assert_eq!(anon, "[[NAME_1]]'e");
        assert_eq!(v.restore(&anon), text);
        assert_eq!(v.restore("<NAME_1>'e"), "Kaya'e");
        assert_eq!(v.restore("<NAME_1>'de"), "Kaya'da");
    }
}
