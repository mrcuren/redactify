//! Tolerant placeholder matching: the altered placeholder forms an LLM
//! writes (`<NAME_1>`, `[name_1]`, `\[NAME\_1\]`, `[PERSON_1]`, ...) and
//! the Turkish suffix after a placeholder (`[NAME_1]'e`), for vaults whose
//! every key has the canonical `LABEL_N` shape. The accepted forms are
//! documented on [`Vault`](super::Vault).
//!
//! One scanner serves the batch restore and the stream restorer: a decision
//! at a position depends only on a bounded window of the text after it and
//! on the character before it, and a decision that would need text past
//! the end of a stream chunk is reported as [`More`] instead of being made.
//! The stream restorer then holds the text from that position back, so its
//! output equals the batch output whatever the chunk boundaries.

use crate::pii::tr_suffix::{repair_into, tail_of, MAX_SUFFIX_CHARS};

/// Longest label-and-number run (in bytes) the scanner reads.
const MAX_RUN: usize = 96;
/// Most significant digits of a placeholder number.
const MAX_DIGITS: usize = 18;
/// Most spaces accepted inside a delimiter on each side (`[ NAME_1 ]`).
const MAX_SPACES: usize = 2;

/// A placeholder rendering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Form {
    Square,
    SquareDouble,
    Angle,
    AngleDouble,
    Curly,
    CurlyDouble,
    EscSquare,
    EscAngle,
    EscCurly,
    JsonAngle,
    JsonSquare,
    HtmlAngle,
    HtmlSquare,
    Bare,
}

impl Form {
    pub(super) const fn bit(self) -> u16 {
        1 << self as u16
    }
}

/// The delimited forms, in the order they are tried at one position
/// (a longer opening before its own prefix). Compared ASCII
/// case-insensitively (`<`, `&LT;`).
const DELIMS: [(Form, &str, &str); 13] = [
    (Form::SquareDouble, "[[", "]]"),
    (Form::Square, "[", "]"),
    (Form::AngleDouble, "<<", ">>"),
    (Form::Angle, "<", ">"),
    (Form::CurlyDouble, "{{", "}}"),
    (Form::Curly, "{", "}"),
    (Form::EscSquare, "\\[", "\\]"),
    (Form::EscAngle, "\\<", "\\>"),
    (Form::EscCurly, "\\{", "\\}"),
    (Form::JsonAngle, "\\u003c", "\\u003e"),
    (Form::JsonSquare, "\\u005b", "\\u005d"),
    (Form::HtmlAngle, "&lt;", "&gt;"),
    (Form::HtmlSquare, "&#91;", "&#93;"),
];

/// Translated labels: `(alias, built-in label)`, sorted by alias. An alias
/// is used only when the vault has no label of that exact name.
pub(super) const ALIASES: [(&str, &str); 18] = [
    ("ADRES", "ADDRESS"),
    ("AD_SOYAD", "NAME"),
    ("CARD", "CREDIT_CARD"),
    ("EPOSTA", "EMAIL"),
    ("E_MAIL", "EMAIL"),
    ("E_POSTA", "EMAIL"),
    ("IP", "IP_ADDRESS"),
    ("ISIM", "NAME"),
    ("KART", "CREDIT_CARD"),
    ("KISI", "NAME"),
    ("KREDI_KARTI", "CREDIT_CARD"),
    ("MAIL", "EMAIL"),
    ("PASAPORT", "PASSPORT"),
    ("PERSON", "NAME"),
    ("PHONE_NUMBER", "PHONE"),
    ("PLATE", "PLAKA"),
    ("TEL", "PHONE"),
    ("TELEFON", "PHONE"),
];

/// The decision needs text past the end of the current stream chunk.
#[derive(Debug)]
pub(super) struct More;

type Scan<T> = Result<Option<T>, More>;

/// Forms and suffixes NOT restored tolerantly for one entry, because the
/// pseudonymized prompt itself contains them (restoring them would break the
/// byte-exact round trip): the prompt's `[Ayşe Kaya]` became
/// `[[NAME_1]]`, its `Kaya'e` became `[NAME_1]'e`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Exempt {
    /// [`Form::bit`] set of exempt forms.
    pub(super) forms: u16,
    /// Exempt suffixes, as written after the apostrophe.
    pub(super) suffixes: Vec<Box<str>>,
    /// No suffix is repaired (the safety net, see `exemptions`).
    pub(super) all_suffixes: bool,
}

impl Exempt {
    /// Exempts everything: tolerant restore of the entry is the strict one.
    pub(super) fn all() -> Self {
        Self {
            forms: u16::MAX,
            suffixes: Vec::new(),
            all_suffixes: true,
        }
    }
}

/// Splits a canonical key `LABEL_N` (label: an ASCII upper-case letter,
/// then upper-case letters, digits and `_`, not ending in `_`; number:
/// 1 to [`MAX_DIGITS`] digits without a leading zero).
pub(super) fn split_key(key: &str) -> Option<(&str, u64)> {
    let (label, number) = key.rsplit_once('_')?;
    let label_ok = label.starts_with(|c: char| c.is_ascii_uppercase())
        && !label.ends_with('_')
        && label
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    let number_ok = !number.is_empty()
        && number.len() <= MAX_DIGITS
        && !number.starts_with('0')
        && number.bytes().all(|b| b.is_ascii_digit());
    if !(label_ok && number_ok) {
        return None;
    }
    Some((label, number.parse().ok()?))
}

/// A label letter: ASCII or Turkish.
fn is_label_letter(c: char) -> bool {
    c.is_ascii_alphabetic() || "çğıöşüÇĞİÖŞÜ".contains(c)
}

/// Can `c` start a bare (undelimited) placeholder: an upper-case label
/// letter.
fn is_upper_label_letter(c: char) -> bool {
    c.is_ascii_uppercase() || "ÇĞİÖŞÜ".contains(c)
}

/// A word character for the bare form's boundaries.
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// A label as written, normalized for lookup: `\` removed, ASCII upper
/// case, Turkish letters folded to ASCII (`İSİM` → `ISIM`). `None` when
/// it holds another character or is longer than `buf`.
pub(super) fn normalize<'b>(raw: &str, buf: &'b mut [u8; MAX_RUN]) -> Option<&'b [u8]> {
    let mut n = 0;
    for c in raw.chars() {
        let b = match c {
            '\\' => continue,
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' => (c as u8).to_ascii_uppercase(),
            'ı' | 'İ' => b'I',
            'ş' | 'Ş' => b'S',
            'ç' | 'Ç' => b'C',
            'ğ' | 'Ğ' => b'G',
            'ö' | 'Ö' => b'O',
            'ü' | 'Ü' => b'U',
            _ => return None,
        };
        *buf.get_mut(n)? = b;
        n += 1;
    }
    Some(&buf[..n])
}

/// The canonical label an alias stands for.
pub(super) fn alias_target(norm: &[u8]) -> Option<&'static str> {
    ALIASES
        .binary_search_by(|(a, _)| a.as_bytes().cmp(norm))
        .ok()
        .map(|i| ALIASES[i].1)
}

/// The `(label, number) -> entry` index of a vault with canonical keys.
#[derive(Clone, Debug)]
pub(super) struct Index {
    /// Distinct labels, sorted.
    labels: Vec<Box<str>>,
    /// `(label index, number, entry index)`, sorted.
    slots: Vec<(u32, u64, u32)>,
}

impl Index {
    /// The index over `keys` (in entry order), or `None` if some key is not
    /// canonical (the vault then restores strictly).
    pub(super) fn build<'a>(keys: impl Iterator<Item = &'a str> + Clone) -> Option<Self> {
        let mut labels: Vec<Box<str>> = Vec::new();
        for key in keys.clone() {
            labels.push(split_key(key)?.0.into());
        }
        labels.sort_unstable();
        labels.dedup();
        let mut slots = Vec::with_capacity(labels.len());
        for (entry, key) in keys.enumerate() {
            let (label, n) = split_key(key)?;
            let l = labels.binary_search_by(|x| (**x).cmp(label)).ok()?;
            slots.push((u32::try_from(l).ok()?, n, u32::try_from(entry).ok()?));
        }
        slots.sort_unstable();
        Some(Self { labels, slots })
    }

    /// The label index for a normalized label, and whether an alias was
    /// used.
    fn label(&self, norm: &[u8]) -> Option<(u32, bool)> {
        let find = |l: &[u8]| {
            self.labels
                .binary_search_by(|x| x.as_bytes().cmp(l))
                .ok()
                .and_then(|i| u32::try_from(i).ok())
        };
        find(norm)
            .map(|i| (i, false))
            .or_else(|| find(alias_target(norm)?.as_bytes()).map(|i| (i, true)))
    }

    fn entry(&self, label: u32, n: u64) -> Option<u32> {
        self.slots
            .binary_search_by(|&(l, m, _)| (l, m).cmp(&(label, n)))
            .ok()
            .map(|i| self.slots[i].2)
    }
}

/// A restored placeholder.
#[derive(Debug)]
pub(super) struct Hit {
    /// End of the placeholder itself.
    pub(super) end: usize,
    pub(super) entry: u32,
    pub(super) form: Form,
    /// The exact `[LABEL_N]` token (what the strict restore matches).
    pub(super) exact: bool,
    /// Start of the suffix letters (after the apostrophe), if a suffix is
    /// repaired; the repaired letters are in the scanner's scratch buffer.
    pub(super) suffix_start: usize,
    /// End of everything consumed (`end` when no suffix is repaired).
    pub(super) suffix_end: usize,
}

/// The byte at `i`, `None` at the end of the text, [`More`] at the end of
/// a chunk.
fn byte_at(b: &[u8], i: usize, eof: bool) -> Scan<u8> {
    match b.get(i) {
        Some(&x) => Ok(Some(x)),
        None if eof => Ok(None),
        None => Err(More),
    }
}

/// The char at `i` (a char boundary), like [`byte_at`].
fn char_at(text: &str, i: usize, eof: bool) -> Scan<char> {
    match text.get(i..).and_then(|s| s.chars().next()) {
        Some(c) => Ok(Some(c)),
        None if eof => Ok(None),
        None => Err(More),
    }
}

/// Does `pat` start at `i` (ASCII case-insensitive)?
fn starts(b: &[u8], i: usize, pat: &str, eof: bool) -> Result<bool, More> {
    let avail = b.get(i..).unwrap_or_default();
    let pat = pat.as_bytes();
    let n = avail.len().min(pat.len());
    if !avail[..n].eq_ignore_ascii_case(&pat[..n]) {
        Ok(false)
    } else if n == pat.len() {
        Ok(true)
    } else if eof {
        Ok(false)
    } else {
        Err(More)
    }
}

/// `LABEL SEP DIGITS` at a position.
struct Core {
    label_start: usize,
    label_end: usize,
    digits_start: usize,
    end: usize,
    /// The separator was `\_`.
    escaped: bool,
}

/// Parses the maximal run of label letters, digits, `_` and `\_` at `q`
/// (starting with a letter) and splits it at its last separator into a
/// label and an all-digit number.
fn core(text: &str, q: usize, eof: bool) -> Scan<Core> {
    let b = text.as_bytes();
    let mut i = q;
    let mut sep: Option<(usize, bool)> = None;
    loop {
        if i - q >= MAX_RUN {
            return Ok(None);
        }
        let Some(c) = char_at(text, i, eof)? else {
            break;
        };
        match c {
            '\\' if i > q => {
                if byte_at(b, i + 1, eof)? == Some(b'_') {
                    sep = Some((i + 1, true));
                    i += 2;
                } else {
                    break;
                }
            }
            '_' if i > q => {
                sep = Some((i, false));
                i += 1;
            }
            c if is_label_letter(c) || (i > q && c.is_ascii_digit()) => i += c.len_utf8(),
            _ => break,
        }
    }
    let Some((us, escaped)) = sep else {
        return Ok(None);
    };
    let label_end = if escaped { us - 1 } else { us };
    let digits = &b[us + 1..i];
    if label_end == q || digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Ok(None);
    }
    Ok(Some(Core {
        label_start: q,
        label_end,
        digits_start: us + 1,
        end: i,
        escaped,
    }))
}

/// Markdown code context, carried from the start of the text (and across
/// stream chunks): a bare placeholder is never filled inside a code span
/// or a fenced block, where `PHONE_1` is an identifier, not a dropped
/// bracket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Code {
    /// Inside a fenced block (a line opening with three or more backticks).
    fence: bool,
    /// Inside an inline code span (an odd backtick run on this line).
    inline: bool,
    /// Only spaces so far on this line.
    line_blank: bool,
    /// The previous byte ended a backtick run of three or more that
    /// reached the end of a stream chunk: further backticks continue it.
    tick_run: bool,
}

impl Default for Code {
    fn default() -> Self {
        Self {
            fence: false,
            inline: false,
            line_blank: true,
            tick_run: false,
        }
    }
}

impl Code {
    /// Can a bare placeholder be filled here?
    const fn prose(self) -> bool {
        !self.fence && !self.inline
    }
}

/// A character before a bare placeholder that makes it part of an
/// identifier or path (`obj.PHONE_1`, `$PHONE_1`, `--PHONE_1`,
/// `Foo::PHONE_1`, `a->PHONE_1`, `` `PHONE_1 ``).
fn identifier_before(c: char) -> bool {
    is_word_char(c) || ".$@#-/\\`:>%".contains(c)
}

/// Does the text after a bare placeholder ending at `end` make it an
/// identifier: a word character, a call or index (`(`, `[`), a member,
/// scope or kebab continuation (`.x`, `::`, `-x`, `->`), a key (`:`), an
/// assignment or comparison (`=` after at most two spaces), a closing
/// backtick, or a closing quote matching the one before (`"PHONE_1"`).
fn identifier_after(text: &str, end: usize, prev: Option<char>, eof: bool) -> Result<bool, More> {
    let b = text.as_bytes();
    match char_at(text, end, eof)? {
        Some(c) if is_word_char(c) || "([`:".contains(c) => return Ok(true),
        Some(q @ ('"' | '\'')) if prev == Some(q) => return Ok(true),
        Some(c @ ('.' | '-')) => {
            let next = char_at(text, end + 1, eof)?;
            if next.is_some_and(is_word_char) || (c == '-' && next == Some('>')) {
                return Ok(true);
            }
        }
        _ => {}
    }
    let mut i = end;
    while i < end + 2 && byte_at(b, i, eof)? == Some(b' ') {
        i += 1;
    }
    Ok(byte_at(b, i, eof)? == Some(b'='))
}

/// The scanner over one vault and one set of restore options.
pub(super) struct Ctx<'a> {
    pub(super) index: &'a Index,
    pub(super) originals: &'a [&'a str],
    /// Sorted by entry.
    pub(super) exempt: &'a [(u32, Exempt)],
    pub(super) forms: bool,
    pub(super) suffixes: bool,
    /// Byte ranges of the text (sorted, disjoint) where nothing is
    /// restored; the code context is still tracked through them.
    pub(super) skip: &'a [(usize, usize)],
}

impl Ctx<'_> {
    /// Whether `[start, end)` touches a skipped range.
    fn skipped(&self, start: usize, end: usize) -> bool {
        let i = self.skip.partition_point(|&(_, e)| e <= start);
        self.skip
            .get(i)
            .is_some_and(|&(s, _)| s < end.max(start + 1))
    }

    fn exempt(&self, entry: u32) -> Option<&Exempt> {
        self.exempt
            .binary_search_by_key(&entry, |(e, _)| *e)
            .ok()
            .map(|i| &self.exempt[i].1)
    }

    /// Restores `text` into `out`, calling `on_hit` for every restored
    /// placeholder; returns how much of `text` is final (all of it when
    /// `eof`; else up to a position whose decision needs more input).
    /// `prev` is the character before `text`; `code` is the code context
    /// at its start, advanced to the returned position.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn drive(
        &self,
        text: &str,
        prev: Option<char>,
        code: &mut Code,
        eof: bool,
        out: &mut String,
        scratch: &mut String,
        on_hit: &mut dyn FnMut(&Hit, &str, &str),
    ) -> usize {
        let b = text.as_bytes();
        let mut copied = 0;
        let mut p = 0;
        while p < b.len() {
            let x = b[p];
            if x == b'`' {
                if code.tick_run {
                    p += 1;
                    continue;
                }
                let run = b[p..].iter().take_while(|&&c| c == b'`').count();
                let at_end = p + run == b.len() && !eof;
                if at_end && run < 3 {
                    // one or two backticks may still grow into a fence
                    out.push_str(&text[copied..p]);
                    return p;
                }
                if run >= 3 && code.line_blank {
                    code.fence = !code.fence;
                    code.inline = false;
                } else if !code.fence {
                    code.inline = !code.inline;
                }
                code.line_blank = false;
                code.tick_run = at_end;
                p += run;
                continue;
            }
            code.tick_run = false;
            let candidate = matches!(x, b'[' | b'<' | b'{' | b'\\' | b'&')
                || (self.forms
                    && code.prose()
                    && (x.is_ascii_uppercase() || matches!(x, 0xC3..=0xC5)));
            if candidate && !self.skipped(p, p + 1) {
                let before = if p == 0 {
                    prev
                } else {
                    text[..p].chars().next_back()
                };
                match self.scan_at(text, p, before, eof, scratch) {
                    Ok(Some(hit)) if !self.skipped(p, hit.suffix_end) => {
                        out.push_str(&text[copied..p]);
                        out.push_str(self.originals[hit.entry as usize]);
                        if hit.suffix_end > hit.end {
                            out.push_str(&text[hit.end..hit.suffix_start]);
                            out.push_str(scratch);
                        }
                        on_hit(&hit, text, scratch);
                        p = hit.suffix_end;
                        copied = p;
                        code.line_blank = false;
                        continue;
                    }
                    // no placeholder here, or one that reaches into a
                    // skipped range
                    Ok(_) => {}
                    Err(More) => {
                        out.push_str(&text[copied..p]);
                        return p;
                    }
                }
            }
            match x {
                b'\n' => {
                    code.line_blank = true;
                    code.inline = false;
                }
                b' ' | b'\t' | b'\r' => {}
                _ => code.line_blank = false,
            }
            p += match x {
                0..=0x7F => 1,
                0x80..=0xDF => 2,
                0xE0..=0xEF => 3,
                _ => 4,
            };
        }
        out.push_str(&text[copied..]);
        b.len()
    }

    /// The placeholder starting at `p`, if any.
    fn scan_at(
        &self,
        text: &str,
        p: usize,
        prev: Option<char>,
        eof: bool,
        scratch: &mut String,
    ) -> Scan<Hit> {
        let b = text.as_bytes();
        if matches!(b[p], b'[' | b'<' | b'{' | b'\\' | b'&') {
            for (form, open, close) in DELIMS {
                if starts(b, p, open, eof)? {
                    if let Some(hit) = self.delimited(text, p, form, open, close, eof, scratch)? {
                        return Ok(Some(hit));
                    }
                }
            }
            return Ok(None);
        }
        let c = text[p..].chars().next().unwrap_or(' ');
        if !self.forms || !is_upper_label_letter(c) || prev.is_some_and(identifier_before) {
            return Ok(None);
        }
        let Some(core) = core(text, p, eof)? else {
            return Ok(None);
        };
        // upper case as issued, and in prose, not in an identifier context
        if text[core.label_start..core.label_end]
            .chars()
            .any(char::is_lowercase)
            || identifier_after(text, core.end, prev, eof)?
        {
            return Ok(None);
        }
        self.hit(text, core.end, Form::Bare, &core, false, eof, scratch)
    }

    #[allow(clippy::too_many_arguments)]
    fn delimited(
        &self,
        text: &str,
        p: usize,
        form: Form,
        open: &str,
        close: &str,
        eof: bool,
        scratch: &mut String,
    ) -> Scan<Hit> {
        let b = text.as_bytes();
        let mut q = p + open.len();
        let mut spaces = 0;
        while spaces < MAX_SPACES && byte_at(b, q, eof)? == Some(b' ') {
            q += 1;
            spaces += 1;
        }
        let lead = spaces;
        let Some(core) = core(text, q, eof)? else {
            return Ok(None);
        };
        let mut r = core.end;
        spaces = 0;
        while spaces < MAX_SPACES && byte_at(b, r, eof)? == Some(b' ') {
            r += 1;
            spaces += 1;
        }
        if !starts(b, r, close, eof)? {
            return Ok(None);
        }
        let spaced = lead + spaces > 0;
        self.hit(text, r + close.len(), form, &core, spaced, eof, scratch)
    }

    /// Resolves a parsed placeholder against the vault and reads its
    /// suffix.
    #[allow(clippy::too_many_arguments)]
    fn hit(
        &self,
        text: &str,
        end: usize,
        form: Form,
        core: &Core,
        spaced: bool,
        eof: bool,
        scratch: &mut String,
    ) -> Scan<Hit> {
        let raw = &text[core.label_start..core.label_end];
        let digits = text[core.digits_start..core.end].trim_start_matches('0');
        if digits.is_empty() || digits.len() > MAX_DIGITS {
            return Ok(None);
        }
        let mut buf = [0u8; MAX_RUN];
        let Some((label, via_alias)) = normalize(raw, &mut buf).and_then(|n| self.index.label(n))
        else {
            return Ok(None);
        };
        let Some(entry) = digits.parse().ok().and_then(|n| self.index.entry(label, n)) else {
            return Ok(None);
        };
        let exact = form == Form::Square
            && !spaced
            && !via_alias
            && !core.escaped
            && digits.len() == core.end - core.digits_start
            && *self.index.labels[label as usize] == *raw;
        let exempt = self.exempt(entry);
        if !exact && (!self.forms || exempt.is_some_and(|x| x.forms & form.bit() != 0)) {
            return Ok(None);
        }
        let mut hit = Hit {
            end,
            entry,
            form,
            exact,
            suffix_start: end,
            suffix_end: end,
        };
        if self.suffixes {
            if let Some((s, e)) = self.suffix(text, end, entry, exempt, eof, scratch)? {
                hit.suffix_start = s;
                hit.suffix_end = e;
            }
        }
        Ok(Some(hit))
    }

    /// The apostrophe suffix after a placeholder ending at `end`, repaired
    /// into `scratch`: `(letters start, letters end)`. `None` when there is
    /// none, it is not parsed, it is exempt, or the value's pronunciation
    /// is unknown (the suffix then stays as written).
    fn suffix(
        &self,
        text: &str,
        end: usize,
        entry: u32,
        exempt: Option<&Exempt>,
        eof: bool,
        scratch: &mut String,
    ) -> Scan<(usize, usize)> {
        let Some(apostrophe) = char_at(text, end, eof)? else {
            return Ok(None);
        };
        if apostrophe != '\'' && apostrophe != '\u{2019}' {
            return Ok(None);
        }
        let start = end + apostrophe.len_utf8();
        let mut i = start;
        let mut letters = 0;
        while let Some(c) = char_at(text, i, eof)? {
            if !c.is_alphabetic() {
                break;
            }
            letters += 1;
            if letters > MAX_SUFFIX_CHARS {
                return Ok(None);
            }
            i += c.len_utf8();
        }
        let written = &text[start..i];
        if written.is_empty()
            || exempt.is_some_and(|x| x.all_suffixes || x.suffixes.iter().any(|s| **s == *written))
        {
            return Ok(None);
        }
        let Some(tail) = tail_of(self.originals[entry as usize]) else {
            return Ok(None);
        };
        scratch.clear();
        Ok(repair_into(tail, written, scratch).then_some((start, i)))
    }
}

/// Every `(label, number)` a tolerant scan could read in `text`, for the
/// pseudonymizer to skip: each run `LABEL_N` (or `LABEL\_N`) anywhere in the
/// text, its label normalized as the scanner does and, for an alias, also
/// its target label. Over-reserving only skips a number.
pub(super) fn reserved(text: &str) -> Vec<(Box<str>, u64)> {
    let mut out: Vec<(Box<str>, u64)> = Vec::new();
    let b = text.as_bytes();
    for (us, _) in text.match_indices('_') {
        let digits_end = us
            + 1
            + b[us + 1..]
                .iter()
                .take_while(|d| d.is_ascii_digit())
                .count();
        let digits = text[us + 1..digits_end].trim_start_matches('0');
        let Ok(n) = digits.parse::<u64>() else {
            continue;
        };
        if digits.len() > MAX_DIGITS {
            continue;
        }
        let label_end = if us > 0 && b[us - 1] == b'\\' {
            us - 1
        } else {
            us
        };
        // walk back over the run (a `\` only directly before a `_`)
        let mut start = label_end;
        let mut next = '_';
        for (i, c) in text[..label_end].char_indices().rev() {
            let in_run =
                is_label_letter(c) || c.is_ascii_digit() || c == '_' || (c == '\\' && next == '_');
            if !in_run || label_end - i > MAX_RUN {
                break;
            }
            start = i;
            next = c;
        }
        let mut buf = [0u8; MAX_RUN];
        let Some(norm) = normalize(&text[start..label_end], &mut buf) else {
            continue;
        };
        // the scanner reads a run from its start only (a delimiter or a
        // word boundary precedes it), so the whole run's label is the one
        // to reserve; `normalize` yields ASCII only
        if let (false, Ok(label)) = (norm.is_empty(), std::str::from_utf8(norm)) {
            out.push((label.into(), n));
            if let Some(target) = alias_target(norm) {
                out.push((target.into(), n));
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::{alias_target, normalize, reserved, split_key, ALIASES, MAX_RUN};
    use crate::pii::entity::EntityType;

    #[test]
    fn canonical_keys() {
        assert_eq!(split_key("NAME_1"), Some(("NAME", 1)));
        assert_eq!(split_key("DE_TAX_ID_12"), Some(("DE_TAX_ID", 12)));
        assert_eq!(split_key("X1_2"), Some(("X1", 2)));
        for bad in [
            "NAME_01", "NAME_0", "NAME_", "_1", "name_1", "NAME__1", "1A_1", "NAME_1a", "", "NAME",
        ] {
            assert_eq!(split_key(bad), None, "{bad}");
        }
        assert_eq!(split_key("A_1234567890123456789"), None); // 19 digits
    }

    #[test]
    fn aliases_are_sorted_and_name_built_in_labels_only() {
        assert!(ALIASES.windows(2).all(|w| w[0].0 < w[1].0));
        for (alias, target) in ALIASES {
            assert!(alias.parse::<EntityType>().is_err(), "{alias}");
            assert!(target.parse::<EntityType>().is_ok(), "{target}");
            assert_eq!(alias_target(alias.as_bytes()), Some(target));
        }
    }

    #[test]
    fn labels_normalize_like_the_scanner_reads_them() {
        let mut buf = [0u8; MAX_RUN];
        assert_eq!(normalize("İsim", &mut buf), Some(&b"ISIM"[..]));
        assert_eq!(normalize("kişi", &mut buf), Some(&b"KISI"[..]));
        assert_eq!(normalize(r"DE\_TAX\_ID", &mut buf), Some(&b"DE_TAX_ID"[..]));
        assert_eq!(normalize("NAMÉ", &mut buf), None);
    }

    #[test]
    fn reservations_cover_every_readable_shape() {
        let r =
            reserved(r"a [NAME_1] <isim_02> TCKN\_3 x_y_4 KİŞİ_5 [_6] 7_8 Z_99999999999999999999");
        let has = |l: &str, n: u64| r.iter().any(|(a, m)| &**a == l && *m == n);
        assert!(has("NAME", 1));
        assert!(has("ISIM", 2) && has("NAME", 2));
        assert!(has("TCKN", 3));
        assert!(has("X_Y", 4));
        assert!(has("KISI", 5) && has("NAME", 5));
        assert!(!r
            .iter()
            .any(|(_, m)| *m == 6 || *m == 99_999_999_999_999_999));
        assert!(reserved("no underscore here").is_empty());
    }
}
