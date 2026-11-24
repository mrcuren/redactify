//! Credential / secret detection (L0 input / L4 output defense).
//!
//! Deterministic, offline detection of leaked API keys, tokens and private
//! key material. Three tiers, following the crate's score convention
//! (0.9 / 0.6 / 0.4):
//!
//! - **0.9 vendor-validated**: a vendor key prefix plus its documented
//!   length/charset shape (AWS, GitHub, Slack, Stripe, OpenAI, Anthropic,
//!   Google, GitLab, npm, PyPI, SendGrid, Telegram, Twilio, Doppler), a PEM
//!   private-key block (header, body and END line masked as one span), a
//!   Slack webhook URL, a structurally validated JWT, or a 40-char AWS
//!   secret behind an `aws ... secret` cue.
//! - **0.6 context-confirmed**: a credential assignment
//!   (`password=`, `api_key:`, `DB_PASSWORD=`, `"password": "..."`,
//!   Turkish `sifre:` / `parola=`), a Bearer header, URL userinfo
//!   (`user:pass@host`), or a weaker vendor shape (test keys, legacy bare
//!   `sk-`, loose `xox*-`).
//! - **0.4 entropy-only**: a cue-adjacent (`key`, `token`, `secret`, ...)
//!   run of at least 20 chars whose Shannon entropy clears a per-charset
//!   floor. Bare high-entropy runs with NO cue never fire (the PII layer's
//!   cue-required invariant: git logs are full of SHAs).
//!
//! True online verification of a vendor key (e.g. an AWS STS call) is
//! deliberately out of scope: the core never touches the network. A 0.9
//! score means "vendor shape confirmed", not "key is live".
//!
//! Evidence hygiene: [`GuardSignal::evidence`] carries only a 4-char prefix
//! and the length (`"AKIA...(len 20)"`, the form every guard signal uses),
//! never the full secret (the audit layer must not become the leak).
//! Two-source notes per rule family live in `data/secrets_corpus.SOURCES.md`.
//!
//! Detection ([`find_secret_spans`], [`secrets_risk`]) scans the text it is
//! given; the guard decision runs it once per scan view. Masking
//! ([`mask_secrets`]) replaces the secrets of the raw text AND of its
//! normalized view, mapped back to raw offsets ([`find_secret_mask_spans`]),
//! so a key the decision saw through the normalized view never stays in
//! the masked text.
//!
//! # Examples
//! ```
//! use redactify::guard::{secrets_risk, SignalKind};
//!
//! let sigs = secrets_risk("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
//! assert_eq!(sigs[0].kind, SignalKind::Secrets);
//! assert!(sigs[0].score >= 0.9);
//! // evidence never echoes the full key
//! assert!(!sigs[0].evidence.contains("N7EXAMPLE"));
//! ```

use crate::guard::normalize::{align_for_scan, normalize_for_scan, ScanAlignment};
use crate::guard::rules::evidence_preview;
use crate::guard::{GuardSignal, SignalKind};
use fancy_regex::Regex;
use std::sync::LazyLock;

/// One secret location, for span-based masking ([`mask_secrets`]).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct SecretFinding {
    /// Byte offset of the first char of the secret.
    pub start: usize,
    /// Byte offset one past the last char of the secret.
    pub end: usize,
    /// Vendor/transport label (`AWS_ACCESS_KEY`, `GITHUB_TOKEN`, ...).
    pub vendor: &'static str,
    /// Tier score (0.9 vendor-validated, 0.6 context, 0.4 entropy).
    pub score: f32,
}

/// A compiled secret rule.
struct SecretRule {
    regex: Regex,
    vendor: &'static str,
    score: f32,
}

fn table(rules: &[(&'static str, &'static str)], score: f32) -> Vec<SecretRule> {
    rules
        .iter()
        .map(|(p, vendor)| SecretRule {
            regex: Regex::new(p).expect("valid inline pattern"),
            vendor,
            score,
        })
        .collect()
}

/// Vendor-validated table (0.9). Shapes and lengths are cross-checked
/// against each vendor's own token-format documentation and a second
/// source per family (see data/secrets_corpus.SOURCES.md). Every pattern
/// contains a literal from [`VENDOR_MARKERS`] (unit-tested invariant).
static VENDOR_RULES: LazyLock<Vec<SecretRule>> = LazyLock::new(|| {
    table(
        &[
            // AWS access key id: 4-char prefix family + 16 x [A-Z0-9]
            (
                r"(?<![A-Za-z0-9])(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Za-z0-9])",
                "AWS_ACCESS_KEY",
            ),
            // GitHub classic PATs (ghp/gho/ghu/ghs/ghr + 36 alnum)
            (
                r"(?<![A-Za-z0-9_])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}(?![A-Za-z0-9])",
                "GITHUB_TOKEN",
            ),
            // GitHub fine-grained PAT (github_pat_ + 82)
            (
                r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{82}(?![A-Za-z0-9_])",
                "GITHUB_TOKEN",
            ),
            // Slack classic token: xox[baprse]-<10-13d>-<10-13d>-<24 alnum>
            (
                r"(?<![A-Za-z0-9-])xox[abcdeoprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}(?![A-Za-z0-9-])",
                "SLACK_TOKEN",
            ),
            // Slack app-level token
            (
                r"(?<![A-Za-z0-9-])xapp-1-[A-Za-z0-9-]{20,}(?![A-Za-z0-9-])",
                "SLACK_APP_TOKEN",
            ),
            // Twilio Account SID and API Key SID: the vendor schema
            // patterns `^AC[0-9a-fA-F]{32}$` and `^SK[0-9a-fA-F]{32}$`
            (
                r"(?<![A-Za-z0-9])AC[0-9a-fA-F]{32}(?![0-9a-fA-F])",
                "TWILIO_SID",
            ),
            (
                r"(?<![A-Za-z0-9])SK[0-9a-fA-F]{32}(?![0-9a-fA-F])",
                "TWILIO_KEY",
            ),
            // Google OAuth refresh/access token
            (
                r"(?<![A-Za-z0-9])GOCSPX-[A-Za-z0-9_-]{28,}(?![A-Za-z0-9_-])",
                "GOOGLE_OAUTH",
            ),
            // Slack incoming webhook URL (the /services/ path is the secret)
            (
                r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9]{20,}",
                "SLACK_WEBHOOK",
            ),
            // Stripe live secret / restricted keys
            (
                r"(?<![A-Za-z0-9_])(?:sk|rk)_live_[A-Za-z0-9]{24,}(?![A-Za-z0-9_])",
                "STRIPE_KEY",
            ),
            // OpenAI project keys; legacy bare sk- is the 0.6 tier below
            (
                r"(?<![A-Za-z0-9_-])sk-proj-[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])",
                "OPENAI_KEY",
            ),
            // Anthropic keys carry the sk-ant- marker
            (
                r"(?<![A-Za-z0-9_-])sk-ant-(?:api0[0-9]-)?[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])",
                "ANTHROPIC_KEY",
            ),
            // Google API key: AIza + 35 url-safe chars
            (
                r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])",
                "GOOGLE_API_KEY",
            ),
            // GitLab personal access token
            (
                r"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])",
                "GITLAB_TOKEN",
            ),
            // npm granular automation token
            (
                r"(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9_])",
                "NPM_TOKEN",
            ),
            // PyPI upload token: pypi- + base64("api.python.org") prefix
            (
                r"(?<![A-Za-z0-9_-])pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}(?![A-Za-z0-9_-])",
                "PYPI_TOKEN",
            ),
            // SendGrid API key: SG.<16-32>.<16-64>
            (
                r"(?<![A-Za-z0-9_.-])SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}(?![A-Za-z0-9_-])",
                "SENDGRID_KEY",
            ),
            // Telegram bot token: 8-10 digits, colon, AA marker + tail.
            // Observed tails vary (the documented example carries 32; most
            // live tokens 33-35) - the digits:AA anchor is the real signal.
            (
                r"(?<![0-9])[0-9]{8,10}:AA[A-Za-z0-9_-]{30,40}(?![A-Za-z0-9_-])",
                "TELEGRAM_TOKEN",
            ),
            // Doppler auth tokens: dp.<type>. + 40-44 alnum, service tokens
            // with an optional [a-z0-9_-]{2,35} environment segment (the
            // vendor's "Auth Token Formats" reference states each format)
            (
                r"(?<![A-Za-z0-9_.-])dp\.(?:(?:pt|ct|sa|said|scim|audit)\.|st\.(?:[a-z0-9_-]{2,35}\.)?)[A-Za-z0-9]{40,44}(?![A-Za-z0-9])",
                "DOPPLER_TOKEN",
            ),
            // PEM private key header; the finding is extended over the
            // whole block (body and END line) by `pem_block`
            (PEM_HEADER_PATTERN, PEM_VENDOR),
            // AWS secret access key: 40 base64 chars behind an aws-secret cue
            (
                r#"(?i)aws[^\n]{0,30}?(?:secret|sk)[^\n]{0,20}?[=:\s]["']?[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"#,
                "AWS_SECRET_KEY",
            ),
        ],
        0.9,
    )
});

/// The vendor label of a PEM private-key block.
const PEM_VENDOR: &str = "PEM_PRIVATE_KEY";

/// The `-----BEGIN ... PRIVATE KEY-----` header line. No look-around, so
/// it runs on the linear-time engine.
const PEM_HEADER_PATTERN: &str =
    r"-----BEGIN (?:RSA |EC |ECDSA |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----";

/// [`PEM_HEADER_PATTERN`] on its own, for [`open_pem_block_start`].
static PEM_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(PEM_HEADER_PATTERN).expect("valid inline pattern"));

/// Longest PEM block masked as one span, in bytes from the `-----BEGIN`
/// marker. The largest private keys in use stay well below it: an RSA
/// 16384-bit PKCS#8 key is about 12.7 KiB of PEM, a 4096-bit one about
/// 3.3 KiB, an OpenSSH Ed25519 key about 0.4 KiB. It bounds the block
/// scan and the lines a stream holds while a block is open.
pub(crate) const PEM_BLOCK_MAX: usize = 16 * 1024;

/// Line breaks one separator run between two block lines may hold: two
/// blank lines at most (an encrypted PEM puts one between its
/// `Proc-Type` / `DEK-Info` headers and the body).
const PEM_MAX_BREAKS: usize = 3;

/// A token sharing its line with another token (a body whose line breaks
/// were collapsed to spaces) is key material only when it is at least this
/// long or directly precedes the END marker: prose words after a bare
/// header stay unmasked.
const PEM_INLINE_MIN: usize = 16;

/// Longest `Proc-Type:` / `DEK-Info:` header line, in bytes.
const PEM_HEADER_LINE_MAX: usize = 128;

/// One PEM block scanned from its header ([`pem_block`]).
struct PemBlock {
    /// End of the masked block (exclusive).
    end: usize,
    /// The scan ran out of text while the block could still grow (a later
    /// line could add body or the END marker).
    open: bool,
}

/// The `-----END ... PRIVATE KEY-----` marker at `pos`: its end, if any.
fn pem_end_marker(b: &[u8], pos: usize) -> Option<usize> {
    const KINDS: [&[u8]; 7] = [
        b"",
        b"RSA ",
        b"EC ",
        b"ECDSA ",
        b"DSA ",
        b"OPENSSH ",
        b"ENCRYPTED ",
    ];
    let rest = b.get(pos..)?.strip_prefix(b"-----END ")?;
    KINDS.iter().find_map(|kind| {
        let r = rest.strip_prefix(*kind)?.strip_prefix(b"PRIVATE KEY")?;
        let r = r.strip_prefix(b" BLOCK").unwrap_or(r);
        r.strip_prefix(b"-----").map(|tail| b.len() - tail.len())
    })
}

/// A line break at `i`: `\n`, `\r`, or the escaped `\n` / `\r` of a JSON
/// or shell string (backslash + letter). Returns its byte length.
fn pem_line_break(b: &[u8], i: usize) -> Option<usize> {
    match b.get(i)? {
        b'\n' | b'\r' => Some(1),
        b'\\' if matches!(b.get(i + 1), Some(b'n' | b'r')) => Some(2),
        _ => None,
    }
}

/// Skips the separator run at `i` (spaces, tabs and line breaks); returns
/// its end and the number of `\n` breaks (real or escaped) in it.
fn pem_separators(b: &[u8], mut i: usize) -> (usize, usize) {
    let mut breaks = 0;
    loop {
        match b.get(i) {
            Some(b' ' | b'\t') => i += 1,
            _ => match pem_line_break(b, i) {
                Some(n) => {
                    if b[i + n - 1] == b'n' || b[i] == b'\n' {
                        breaks += 1;
                    }
                    i += n;
                }
                None => return (i, breaks),
            },
        }
    }
}

const fn is_base64_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=')
}

/// Scans the PEM block whose header spans `start..header_end` of `text`.
///
/// The block is the header, then every following body line, then the END
/// marker: a body line is a base64 token (any length) alone on its line,
/// a `Proc-Type:` / `DEK-Info:` header line, or, when the line breaks were
/// collapsed to spaces, a run of base64 tokens of [`PEM_INLINE_MIN`] chars
/// or more (a shorter one only right before the END marker). Line breaks
/// may be real or escaped (`\n` inside a JSON string), with at most
/// [`PEM_MAX_BREAKS`] in a row. The block ends at the END marker; without
/// one (a truncated paste) it ends after the last body token, so the
/// header and every base64-looking line that follows it are masked while
/// trailing prose is not. A token that would push the block past
/// [`PEM_BLOCK_MAX`] bytes ends it (never half a token). The scan touches
/// every byte at most twice: linear, and bounded by [`PEM_BLOCK_MAX`].
fn pem_block(text: &str, start: usize, header_end: usize) -> PemBlock {
    let b = text.as_bytes();
    let limit = start.saturating_add(PEM_BLOCK_MAX);
    let closed = |end| PemBlock { end, open: false };
    let mut end = header_end;
    let mut pos = header_end;
    // no other token precedes the next one on its line
    let mut line_start = true;
    loop {
        let (next, breaks) = pem_separators(b, pos);
        if breaks > PEM_MAX_BREAKS || next > limit {
            return closed(end);
        }
        if next >= b.len() {
            return PemBlock { end, open: true };
        }
        line_start |= breaks > 0;
        pos = next;
        if let Some(e) = pem_end_marker(b, pos) {
            return closed(if e <= limit { e } else { end });
        }
        let rest = &b[pos..];
        if line_start && (rest.starts_with(b"Proc-Type:") || rest.starts_with(b"DEK-Info:")) {
            let scan = &rest[..rest.len().min(PEM_HEADER_LINE_MAX + 1)];
            let Some(len) = scan
                .iter()
                .position(|&c| matches!(c, b'\n' | b'\r' | b'\\'))
                .or((scan.len() == rest.len()).then_some(rest.len()))
            else {
                return closed(end); // over-long header line
            };
            let trimmed = rest[..len].trim_ascii_end().len();
            if pos + trimmed > limit {
                return closed(end);
            }
            end = pos + trimmed;
            pos = end;
            line_start = false;
            continue;
        }
        let run = rest.iter().take_while(|&&c| is_base64_byte(c)).count();
        if run == 0 {
            return closed(end);
        }
        let after = pos + run;
        let quote = matches!(b.get(after), Some(b'"' | b'\'' | b'`'));
        let boundary = after == b.len()
            || quote
            || matches!(b[after], b' ' | b'\t')
            || pem_line_break(b, after).is_some()
            || pem_end_marker(b, after).is_some();
        if !boundary {
            return closed(end); // not a clean token (`abc.def`, `x-y`)
        }
        // what follows on the same line, past spaces and tabs
        let k = after
            + b[after..]
                .iter()
                .take_while(|&&c| matches!(c, b' ' | b'\t'))
                .count();
        let ends_line = k == b.len()
            || quote
            || pem_line_break(b, k).is_some()
            || matches!(b[k], b'"' | b'\'' | b'`');
        let before_end = pem_end_marker(b, k).is_some();
        let accept =
            (line_start && (ends_line || before_end)) || run >= PEM_INLINE_MIN || before_end;
        if !accept || after > limit {
            return closed(end);
        }
        end = after;
        pos = after;
        line_start = false;
        if quote {
            return closed(end); // the enclosing string ends here
        }
        if after == b.len() {
            return PemBlock { end, open: true };
        }
    }
}

/// The start of a PEM private-key block that is still OPEN at the end of
/// `text` (its scan ran out of text while a later line could still extend
/// the masked span), in the raw text or in its normalized view, whose
/// secrets are masked too; `None` when no block is open. A block found in
/// the normalized view reports the raw start of its header's LINE (no
/// normalization step creates or removes a `\n`). The streaming guard
/// holds the lines from here on until the block closes, which it does
/// within [`PEM_BLOCK_MAX`] bytes. Only the last header can head an open
/// block: a block never runs past a later `-----BEGIN`.
pub(crate) fn open_pem_block_start(text: &str) -> Option<usize> {
    fn open_in(view: &str) -> Option<usize> {
        if !view.contains("PRIVATE KEY") {
            return None;
        }
        let mut last = None;
        for m in PEM_HEADER.find_iter(view) {
            match m {
                Ok(m) => last = Some(m),
                // the pattern runs on the linear engine and cannot fail;
                // were it to, holding everything only delays emission
                Err(_) => return Some(0),
            }
        }
        let m = last?;
        pem_block(view, m.start(), m.end())
            .open
            .then_some(m.start())
    }
    let raw = open_in(text);
    if text.is_ascii() {
        return raw;
    }
    let norm = normalize_for_scan(text);
    if norm == text {
        return raw;
    }
    let mapped = open_in(&norm).map(|s| {
        let line = norm.as_bytes()[..s].iter().filter(|&&c| c == b'\n').count();
        line_starts(text).get(line).copied().unwrap_or(0)
    });
    match (raw, mapped) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Weaker vendor shapes (0.6).
static CONTEXT_RULES: LazyLock<Vec<SecretRule>> = LazyLock::new(|| {
    table(
        &[
            // Stripe test keys are credentials, just not production ones
            (
                r"(?<![A-Za-z0-9_])(?:sk|rk)_test_[A-Za-z0-9]{24,}(?![A-Za-z0-9_])",
                "STRIPE_TEST_KEY",
            ),
            // Legacy OpenAI key body: bare sk- + >= 32 token chars
            (
                r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9]{32,}(?![A-Za-z0-9-])",
                "OPENAI_KEY",
            ),
            // Loose modern Slack token shapes (xoxb-... with >= 20 payload)
            (
                r"(?<![A-Za-z0-9-])xox[abcdeoprs]-[A-Za-z0-9-]{20,}(?![A-Za-z0-9-])",
                "SLACK_TOKEN",
            ),
            // Azure storage AccountKey assignment (50+ base64 chars)
            (
                r"(?i)\bAccountKey=([A-Za-z0-9+/=]{50,})(?![A-Za-z0-9+/=])",
                "AZURE_STORAGE_KEY",
            ),
        ],
        0.6,
    )
});

/// Generic credential assignments / transports (0.6). Group 1 is the secret
/// span; values run through [`plausible_value`] so placeholders never fire.
///
/// The credential-assignment key is matched by its LAST name segment, so
/// prefixed environment keys count as well as bare ones: `DB_PASSWORD`,
/// `MAIL_PASSWORD`, `APP_SECRET`, `STRIPE_SECRET_KEY`, `GITHUB_TOKEN`,
/// Laravel's `APP_KEY`, Spring's `spring.datasource.password`. A word
/// boundary alone missed them: `_` is a word character, so `\bpassword` never
/// matched inside `DB_PASSWORD`. Keys where the credential word is only a
/// qualifier stay out because the word must END the key (`PASSWORD_RESET_URL`,
/// `TOKEN_EXPIRY`), and a bare `key` is not a credential word (`CACHE_KEY`,
/// `SORT_KEY`). A bare `token` is not one either - it is too common in prose
/// and logs and stays with the entropy backstop (0.4) - so `token` counts
/// only as the last segment of a prefixed key (`GITHUB_TOKEN`). The key may
/// be quoted (`"password": "..."` in JSON, `'api_key': '...'`). The pattern
/// has no look-around, so it runs on the linear-time engine.
///
/// Turkish keys: `sifre` (also spelled with s-cedilla, U+015F, and a
/// dotted or dotless i) and `parola` ("password"), also with the possessive
/// and second-person suffixes a Turkish form puts on the label (`-si`,
/// `-niz`, `-n`), in any case. A prefix segment may hold non-ASCII letters
/// (`gecici_parola` written with c-cedilla). The word must still END the
/// key and be followed by `:` or `=`, so a password-length setting
/// (`parola uzunlugu: 12`) and a reset link label stay clean; the Turkish
/// cases are tested in `tests/tr_record_fields.rs`.
///
/// An UNQUOTED credential value is checked as code first: a value that
/// reads the secret from elsewhere (`os.environ["DB_PASSWORD"]`,
/// `System.getenv("X")`, `process.env.API_KEY`, see [`is_code_expression`])
/// is not a credential. The value class stops at a quote, so an unquoted
/// value with a quote inside its token is masked up to the next whitespace
/// ([`whole_token_end`]): no mask ever leaves half a token in clear.
static ASSIGNMENT_RULES: LazyLock<Vec<SecretRule>> = LazyLock::new(|| {
    table(
        &[
            (
                concat!(
                    r#"(?i)\b(?:(?:[\p{L}0-9]+[_.-])*"#,
                    r"(?:password|passwd|pwd|secret|api[_-]?key|apikey|app[_-]?key|access[_-]?key",
                    r"|secret[_-]?(?:access[_-]?)?key|private[_-]?key|encryption[_-]?key|signing[_-]?key",
                    r"|master[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret",
                    r"|[\x{15F}s][i\x{131}\x{130}]fre(?:s[i\x{131}\x{130}]|n[i\x{131}\x{130}]z|n)?",
                    r"|parola(?:s[i\x{131}\x{130}]|n[i\x{131}\x{130}]z|n)?)",
                    r"|(?:[a-z0-9]+[_.-])+token)",
                    r#"\b["']?\s*[=:]\s*["']?([^\s"']{8,})["']?"#,
                ),
                "CREDENTIAL_ASSIGNMENT",
            ),
            (
                r"(?i)\bauthorization\b\s*[:=]\s*bearer\s+([A-Za-z0-9._+/=-]{16,})",
                "BEARER_TOKEN",
            ),
            // RFC 3986 userinfo: scheme://(user:pass)@host
            (
                r#"[A-Za-z][A-Za-z0-9+.-]{1,20}://([^\s/:@?"'<>]{1,64}:[^\s/@]{1,128})@"#,
                "URL_CREDENTIALS",
            ),
        ],
        0.6,
    )
});

/// Cue words that allow the entropy backstop (0.4). Bare entropy never
/// fires (PII-layer cue-required invariant).
static ENTROPY_CUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(?:key|token|secret|passwd|password|pwd|credential)\b[^\n]{0,24}?["']?([A-Za-z0-9+/=_-]{20,256})["']?"#,
    )
    .expect("valid inline pattern")
});

/// JWT shape (header validation promotes to 0.9, shape alone stays 0.6).
static JWT_SHAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
        .expect("valid inline pattern")
});

/// Scans the text and returns every secret signal (start order).
/// Overlapping matches from different rules collapse to the highest-score
/// (then longest) span.
#[must_use]
pub fn secrets_risk(text: &str) -> Vec<GuardSignal> {
    let spans = find_secret_spans(text);
    spans
        .into_iter()
        .map(|s| {
            let value = &text[s.start..s.end];
            GuardSignal {
                kind: SignalKind::Secrets,
                score: s.score,
                evidence: evidence_preview(value),
                rationale: format!("secret detected: {} ({})", s.vendor, tier_name(s.score)),
            }
        })
        .collect()
}

/// Vendor literals (CASE-SENSITIVE). Every VENDOR/CONTEXT/JWT pattern
/// contains at least one of these literals verbatim, so an Aho-Corasick
/// miss proves none of them can match - the whole regex pass is skipped.
/// (aho-corasick is already in the dependency tree via fancy-regex ->
/// regex-automata; the direct dependency adds zero new code to the build.)
const VENDOR_MARKER_LITERALS: &[&str] = &[
    "AKIA",
    "AGPA",
    "AIDA",
    "AROA",
    "AIPA",
    "ANPA",
    "ANVA",
    "ASIA",
    "ABIA",
    "ACCA",
    "A3T",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "xoxa",
    "xoxb",
    "xoxo",
    "xoxc",
    "xoxd",
    "xapp",
    "GOCSPX-",
    "AC",
    "SK",
    "xoxp",
    "xoxr",
    "xoxs",
    "xoxe",
    "hooks.slack.com/services",
    "sk_live_",
    "rk_live_",
    "sk_test_",
    "rk_test_",
    "sk-proj-",
    "sk-ant-",
    "sk-",
    "AIza",
    "glpat-",
    "npm_",
    "pypi-AgEIcHlwaS5vcmc",
    "SG.",
    ":AA",
    "PRIVATE KEY",
    "eyJ",
    "dp.pt.",
    "dp.ct.",
    "dp.st.",
    "dp.sa.",
    "dp.said.",
    "dp.scim.",
    "dp.audit.",
];

/// The Aho-Corasick automaton over [`VENDOR_MARKER_LITERALS`].
static VENDOR_MARKERS: LazyLock<aho_corasick::AhoCorasick> = LazyLock::new(|| {
    aho_corasick::AhoCorasick::new(VENDOR_MARKER_LITERALS).expect("static marker table")
});

/// Cue literals (ASCII-CASE-INSENSITIVE). Every assignment / entropy /
/// AWS-secret pattern contains at least one (the URL-credential rule's is
/// the scheme separator `://`).
const CUE_MARKER_LITERALS: &[&str] = &[
    "aws",
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "api-key",
    "access_token",
    "auth_token",
    "client_secret",
    "private_key",
    "token",
    "key",
    "credential",
    // Turkish credential keys. The automaton folds ASCII case only, so the
    // literals are the part of the key every accepted spelling shares: the
    // `sifre` key is (case-insensitively) one of `s S` + s-cedilla in both
    // cases + long s (U+017F, it case-folds to `s`), then one of `i I`,
    // dotless i (U+0131), dotted capital I (U+0130), then `fre` in any
    // ASCII case. Every such spelling contains `ifre` (ASCII case free),
    // `\u{131}fre` or `\u{130}fre`; `parola` is ASCII only. Whole
    // spellings would miss mixed forms (dotted capital I after a lowercase
    // s, any dotless i). The superset is checked exhaustively in
    // `turkish_key_prefilter_covers_every_spelling_the_regex_accepts`.
    "ifre",
    "\u{131}fre",
    "\u{130}fre",
    "parola",
    "authorization",
    "bearer",
    "accountkey",
    "://",
];

/// The ASCII-case-insensitive automaton over [`CUE_MARKER_LITERALS`].
static CUE_MARKERS: LazyLock<aho_corasick::AhoCorasick> = LazyLock::new(|| {
    aho_corasick::AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(CUE_MARKER_LITERALS)
        .expect("static cue table")
});

fn has_vendor_marker(text: &str) -> bool {
    VENDOR_MARKERS.find_iter(text).next().is_some()
}

fn has_cue_marker(text: &str) -> bool {
    CUE_MARKERS.find_iter(text).next().is_some()
}

/// Returns the non-overlapping secret spans in start order (score desc,
/// then length desc, decide which span survives an overlap).
///
/// This scans `text` exactly as given (the guard decision runs it once
/// per scan view); the spans to MASK in a raw text, including secrets
/// only its normalized view reveals, come from [`find_secret_mask_spans`].
#[must_use]
pub fn find_secret_spans(text: &str) -> Vec<SecretFinding> {
    // fast negative path: each rule's regex carries at least one literal
    // from the marker tables above, so NO marker => NO rule can fire.
    // Secret-free text would otherwise pay the full ~150 us regex pass;
    // the AC scan is ~1-2 us.
    let vendor_hit = has_vendor_marker(text);
    let cue_hit = if vendor_hit {
        true
    } else {
        has_cue_marker(text)
    };
    if !vendor_hit && !cue_hit {
        return Vec::new();
    }
    // Past this point at least one marker matched and the vendor, context
    // and JWT tables always run: the VENDOR table's one case-INSENSITIVE
    // member (the aws-secret-cue rule, whose literal "aws" lives in the
    // case-insensitive cue set) needs the vendor pass on a cue-only hit, so
    // the gate is all-or-nothing by design (an over-broad gate can only cost
    // speed, never change results).
    let mut all: Vec<SecretFinding> = Vec::new();
    // engine errors must not read as "scan clean": any regex engine
    // failure surfaces as a zero-length SCAN_ERROR finding, a visible
    // Log-tier signal that masks nothing (over-masking a whole text on a
    // transient internal error would be its own failure mode)
    let mut engine_error = false;

    for tier in [&*VENDOR_RULES, &*CONTEXT_RULES] {
        for rule in tier.iter() {
            for m in rule.regex.find_iter(text) {
                let Ok(m) = m else {
                    engine_error = true;
                    continue;
                };
                // a PEM header masks its whole block, body and END line
                let end = if rule.vendor == PEM_VENDOR {
                    pem_block(text, m.start(), m.end()).end
                } else {
                    m.end()
                };
                all.push(SecretFinding {
                    start: m.start(),
                    end,
                    vendor: rule.vendor,
                    score: rule.score,
                });
            }
        }
    }
    if cue_hit {
        // assignments: group 1 is the secret value (mask only the value)
        for rule in ASSIGNMENT_RULES.iter() {
            for c in rule.regex.captures_iter(text) {
                let Ok(c) = c else {
                    engine_error = true;
                    continue;
                };
                let Some(g) = c.get(1) else { continue };
                if !plausible_value(g.as_str()) {
                    continue;
                }
                let mut end = g.end();
                let quoted = matches!(text.as_bytes()[..g.start()].last(), Some(b'"' | b'\''));
                if rule.vendor == "CREDENTIAL_ASSIGNMENT" && !quoted {
                    // an unquoted value that READS the secret from
                    // elsewhere is code, not a credential
                    if is_code_expression(&text[g.start()..]) {
                        continue;
                    }
                    end = whole_token_end(text, end);
                }
                all.push(SecretFinding {
                    start: g.start(),
                    end,
                    vendor: rule.vendor,
                    score: rule.score,
                });
            }
        }
    }
    // JWT: shape match + base64url JSON header check promotes to 0.9
    for m in JWT_SHAPE.find_iter(text) {
        let Ok(m) = m else {
            engine_error = true;
            continue;
        };
        let full = m.as_str();
        let header_end = full.find('.').unwrap_or(full.len());
        let (score, vendor) = if jwt_header_is_json(&full[..header_end]) {
            (0.9, "JWT")
        } else {
            (0.6, "JWT_SHAPE")
        };
        all.push(SecretFinding {
            start: m.start(),
            end: m.end(),
            vendor,
            score,
        });
    }
    if cue_hit {
        // entropy backstop (0.4), cue-adjacent only
        for c in ENTROPY_CUE.captures_iter(text) {
            let Ok(c) = c else {
                engine_error = true;
                continue;
            };
            let Some(g) = c.get(1) else { continue };
            if plausible_value(g.as_str()) && high_entropy(g.as_str()) {
                all.push(SecretFinding {
                    start: g.start(),
                    end: g.end(),
                    vendor: "HIGH_ENTROPY",
                    score: 0.4,
                });
            }
        }
    }

    if engine_error {
        all.push(SecretFinding {
            start: 0,
            end: 0, // zero-length: visible in signals, masks nothing
            vendor: "SCAN_ERROR",
            score: 0.4,
        });
    }
    resolve_overlaps(all)
}

/// Overlap resolution: score desc, then longer span, then earliest start.
fn resolve_overlaps(mut spans: Vec<SecretFinding>) -> Vec<SecretFinding> {
    spans.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then((b.end - b.start).cmp(&(a.end - a.start)))
            .then(a.start.cmp(&b.start))
    });
    let mut kept: Vec<SecretFinding> = Vec::new();
    for s in spans {
        if kept.iter().any(|k| s.start < k.end && k.start < s.end) {
            continue;
        }
        kept.push(s);
    }
    kept.sort_by_key(|s| s.start);
    kept
}

/// Placeholder/liveness check for assignment values: rejects documented
/// placeholder words, template holes and mask runs. A value passes when it
/// contains a digit or symbol and has at least 8 alphanumerics, or is at
/// least 16 alphanumerics of pure letters.
fn plausible_value(v: &str) -> bool {
    // token-level placeholders: SUBSTRING matches like "value"/"your_"
    // would reject real credentials such as "MySecureValue123x!"; "xxxxx"
    // stays a substring - it is a mask-run detector, not a word
    const PLACEHOLDER_TOKENS: &[&str] = &[
        "changeme",
        "change",
        "me",
        "placeholder",
        "example",
        "dummy",
        "redacted",
        "mask",
        "your",
        "yours",
        "todo",
        "value",
        "insert",
        "here",
        "secret",
        "password",
        "token",
        "key",
        "test",
    ];
    let lower = v.to_ascii_lowercase();
    if lower.contains("xxxxx") {
        return false;
    }
    // reject when a token IS a placeholder word, or extends one by a tiny
    // suffix ("changeme123", "value99"); longer tails are real words
    // ("keymaster99" passes)
    let placeholderish = lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .any(|t| {
            PLACEHOLDER_TOKENS
                .iter()
                .any(|p| t == *p || (t.starts_with(p) && t.len() - p.len() <= 3))
        });
    if placeholderish {
        return false;
    }
    if v.starts_with("${") || v.starts_with('<') || v.starts_with('[') {
        return false;
    }
    let alnum = v.chars().filter(|c: &char| c.is_alphanumeric()).count();
    if alnum < 8 {
        return false;
    }
    let has_digit = v.bytes().any(|b| b.is_ascii_digit());
    let has_symbol = v.bytes().any(|b| !b.is_ascii_alphanumeric());
    (has_digit || has_symbol) || alnum >= 16
}

/// Longest code expression [`is_code_expression`] parses, in bytes (a
/// longer one is not recognized, so its value stays masked).
const CODE_EXPR_MAX: usize = 256;

/// Member-access roots whose dotted paths read configuration, not a
/// literal (`process.env.API_KEY`, `settings.SECRET`), ASCII lowercase.
const CONFIG_ROOTS: &[&str] = &[
    "process.env.",
    "import.meta.env.",
    "os.environ.",
    "deno.env.",
    "env.",
    "environ.",
    "config.",
    "settings.",
    "secrets.",
    "vault.",
];

const fn is_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'$'
}

/// The end of the identifier path at `i` (`a`, `a.b`, `A::b`, `a->b`), or
/// `None` when no identifier starts there.
fn ident_path(b: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let first = *b.get(i)?;
        if !(first.is_ascii_alphabetic() || first == b'_' || first == b'$') {
            return None;
        }
        i += b[i..].iter().take_while(|&&c| is_ident_byte(c)).count();
        let sep = match b.get(i..) {
            Some([b'.', ..]) => 1,
            Some([b':', b':', ..] | [b'-', b'>', ..]) => 2,
            _ => return Some(i),
        };
        match b.get(i + sep) {
            Some(&c) if c.is_ascii_alphabetic() || c == b'_' || c == b'$' => i += sep,
            _ => return Some(i),
        }
    }
}

/// Whether the text between a call's or subscript's brackets is an
/// argument list code reads a secret with: empty, or comma-separated
/// quoted strings (`"DB_PASSWORD"`, `''`), plus identifier paths (`path`,
/// `cfg.name`) when the callee is `qualified`. Anything else - a number, a
/// symbol, a nested call - makes the value a literal: `Summer2024(!)`,
/// `Tr0ub4dor(2024)` and `Hunter2(x)` are passwords that only look like
/// calls, and they must stay masked.
fn simple_arguments(inner: &[u8], qualified: bool) -> bool {
    if inner.trim_ascii().is_empty() {
        return true;
    }
    inner.split(|&c| c == b',').all(|item| {
        let item = item.trim_ascii();
        match item {
            [q @ (b'"' | b'\''), body @ .., last] if last == q => !body.contains(q),
            _ => qualified && ident_path(item, 0) == Some(item.len()),
        }
    })
}

/// Whether the unquoted assignment value starting `expr` is a code
/// expression that reads the secret from elsewhere rather than the secret
/// itself: a call or subscript on an identifier path, possibly chained
/// (`os.environ["DB_PASSWORD"]`, `os.getenv("X")`, `System.getenv("X")`,
/// `ENV.fetch("X")`, `config.get("a")`, `load_secret()`,
/// `vault.read(p)["data"]`), or a dotted path under a configuration root
/// ([`CONFIG_ROOTS`]: `process.env.API_KEY`). The brackets must close on
/// the line, hold [`simple_arguments`], and the expression must end at a
/// non-identifier character, so unquoted passwords such as
/// `Pa55(word)xyz!` and `Summer2024(!)` are still values. Parses
/// at most [`CODE_EXPR_MAX`] bytes (linear, bounded).
fn is_code_expression(expr: &str) -> bool {
    let b = &expr.as_bytes()[..expr.len().min(CODE_EXPR_MAX)];
    let Some(path_end) = ident_path(b, 0) else {
        return false;
    };
    // `os.getenv`, `Foo::get`, `a->b`: a member or namespaced callee
    let qualified = b[..path_end]
        .iter()
        .any(|&c| matches!(c, b'.' | b':' | b'>'));
    let mut i = path_end;
    let mut applied = false;
    loop {
        match b.get(i) {
            Some(&open @ (b'(' | b'[')) => {
                let close = if open == b'(' { b')' } else { b']' };
                let mut depth = 0usize;
                let mut closed_at = None;
                for (j, &c) in b.iter().enumerate().skip(i) {
                    if c == b'\n' {
                        break;
                    }
                    if c == open {
                        depth += 1;
                    } else if c == close {
                        depth -= 1;
                        if depth == 0 {
                            closed_at = Some(j);
                            break;
                        }
                    }
                }
                let Some(j) = closed_at else { return false };
                if !simple_arguments(&b[i + 1..j], qualified) {
                    return false;
                }
                i = j + 1;
                applied = true;
            }
            Some(b'.') if applied => match ident_path(b, i + 1) {
                Some(k) => i = k,
                None => return false,
            },
            _ => break,
        }
    }
    if b.get(i).is_some_and(|&c| is_ident_byte(c)) {
        return false;
    }
    if applied {
        return true;
    }
    let path = expr[..path_end].to_ascii_lowercase();
    CONFIG_ROOTS.iter().any(|root| path.starts_with(root))
}

/// The end of an unquoted assignment value that stopped at `end`: the
/// value class stops at a quote, so a quote INSIDE the token
/// (`abc12345"def"`) would leave the token's tail in clear; the value then
/// runs to the next whitespace. A quote that closes the value (followed by
/// a non-word character, `abc12345",`) keeps `end`.
fn whole_token_end(text: &str, end: usize) -> usize {
    let b = text.as_bytes();
    let mid_token = matches!(b.get(end), Some(b'"' | b'\''))
        && b.get(end + 1)
            .is_some_and(|&c| c.is_ascii_alphanumeric() || c == b'_');
    if !mid_token {
        return end;
    }
    text[end..]
        .char_indices()
        .find(|&(_, c)| c.is_whitespace())
        .map_or(text.len(), |(i, _)| end + i)
}

/// Charset-aware Shannon entropy gate. A run qualifies when its observed
/// bits/char clears the floor for its charset class: hex 3.2 (random hex is
/// 4.0), base64ish 4.2 (natural-language base64ish text sits near 4),
/// generic alnum+symbol 3.8. Length >= 20 is enforced by the cue regex.
/// Thresholds sit above the 3.0 floor common in independent public rule
/// sets, to keep the benign canary at zero.
fn high_entropy(v: &str) -> bool {
    let bytes = v.as_bytes();
    if bytes.iter().all(|b| b.is_ascii_hexdigit() || *b == b'-') {
        // strip separators (UUID dashes) before measuring density
        let dense: Vec<u8> = bytes.iter().copied().filter(|b| *b != b'-').collect();
        return dense.len() >= 20 && shannon(&dense) >= 3.2;
    }
    let sh = shannon(bytes);
    let base64ish = bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-'));
    if base64ish {
        return sh >= 4.2;
    }
    sh >= 3.8
}

/// Shannon entropy in bits/char over byte frequencies.
fn shannon(bytes: &[u8]) -> f32 {
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f32;
    let mut h = 0.0f32;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f32 / n;
        h -= p * p.log2();
    }
    h
}

/// Decodes the JWT header segment and checks it parses as a JSON object
/// mentioning an `alg` field (serde_json is already a core dependency).
fn jwt_header_is_json(header_b64: &str) -> bool {
    use base64::Engine;
    let mut buf = [0u8; 512];
    match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode_slice(header_b64, &mut buf) {
        Ok(len) => match std::str::from_utf8(&buf[..len]) {
            Ok(s) => match serde_json::from_str::<serde_json::Value>(s) {
                Ok(v) => v.get("alg").is_some(),
                Err(_) => false,
            },
            Err(_) => false,
        },
        Err(_) => false,
    }
}

/// The spans the secret MASKING functions replace ([`mask_secrets`],
/// [`mask_secrets_with`] and every sanitize / JSON / REST / MCP path that
/// masks through them): the secrets of the raw text UNITED with the
/// secrets of its normalized scan view
/// ([`normalize_for_scan`]: NFKC, invisible stripping, confusable fold)
/// mapped back to raw byte offsets. The guard decision scans every view on
/// its own ([`secrets_risk`] per view), so a key split by a zero-width
/// character or written with a fullwidth or lookalike letter is both
/// decided on AND masked. [`find_secret_spans`] stays the raw-view scan.
///
/// The spans are sorted by start and pairwise disjoint (a sorted,
/// non-overlapping list is what span-by-span renderers need): overlapping
/// raw and normalized findings merge into ONE span covering their union,
/// so no tail of either can leak, labeled with the group's highest-score
/// finding (then the longest, then the earliest: the overlap order of
/// [`find_secret_spans`]). A zero-length `SCAN_ERROR` health marker
/// (engine error in either scan, see [`mask_secrets_with`]) is kept once.
///
/// A normalized finding `[s, e)` maps to the raw span
/// `[start[s], end[e])` of the crate's line-wise alignment (a span start
/// reads the producing cluster's raw START, a span end its raw END, so an
/// NFKC expansion such as U+00BC never under-masks on either side). The
/// mapping fails closed: a finding on a line that could not be aligned
/// (defensive: it should not happen) masks every raw LINE it touches (no
/// normalization step creates or removes a `\n`, so line `k` of the view
/// is line `k` of the raw text), and the whole text if the line counts
/// ever disagree.
///
/// # Examples
/// ```
/// use redactify::guard::{find_secret_spans, secrets::find_secret_mask_spans};
///
/// let text = "key AKIA\u{200B}IOSFODNN7EXAMPLE end";
/// assert!(find_secret_spans(text).is_empty()); // the raw view sees no key
/// let spans = find_secret_mask_spans(text);
/// assert_eq!(spans.len(), 1);
/// assert_eq!(spans[0].vendor, "AWS_ACCESS_KEY");
/// assert_eq!(&text[spans[0].start..spans[0].end], "AKIA\u{200B}IOSFODNN7EXAMPLE");
/// ```
#[must_use]
pub fn find_secret_mask_spans(text: &str) -> Vec<SecretFinding> {
    secret_mask_spans_with(text, align_for_scan)
}

/// [`find_secret_mask_spans`] with the aligner as a parameter (the seam
/// the fail-closed tests use to simulate an alignment failure).
fn secret_mask_spans_with(
    text: &str,
    align: impl FnOnce(&str) -> ScanAlignment,
) -> Vec<SecretFinding> {
    let raw = find_secret_spans(text);
    if text.is_ascii() {
        return raw; // ASCII is its own normalized view
    }
    let norm = normalize_for_scan(text);
    if norm == text {
        return raw;
    }
    let found = find_secret_spans(&norm);
    if found.is_empty() {
        return raw;
    }
    // the alignment is computed only when the view holds a finding
    let mapped = map_to_raw(text, &norm, &align(text), &found);
    merge_mask_spans(text, raw.into_iter().chain(mapped).collect())
}

/// Byte offset of the start of every line of `s` (`[0]` for one line).
fn line_starts(s: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(s.match_indices('\n').map(|(i, _)| i + 1))
        .collect()
}

/// End (exclusive, without its `\n`) of line `k` of `s`.
fn line_end(starts: &[usize], s: &str, k: usize) -> usize {
    starts.get(k + 1).map_or(s.len(), |&next| next - 1)
}

/// Maps the `found` spans of the normalized view `norm` back to raw
/// offsets through the alignment `a` (see [`find_secret_mask_spans`] for
/// the fail-closed line policy). A line maps precisely only when it was
/// aligned AND its aligned view equals its line in `norm`. Zero-length
/// findings (the health marker) pass through.
fn map_to_raw(
    text: &str,
    norm: &str,
    a: &ScanAlignment,
    found: &[SecretFinding],
) -> Vec<SecretFinding> {
    let raw_starts = line_starts(text);
    let norm_starts = line_starts(norm);
    let view_starts = line_starts(&a.normalized);
    let same_lines = norm_starts.len() == raw_starts.len()
        && view_starts.len() == raw_starts.len()
        && a.start.len() == a.normalized.len() + 1
        && a.end.len() == a.normalized.len() + 1;
    let precise: Vec<bool> = if same_lines {
        (0..raw_starts.len())
            .map(|k| {
                // `unaligned` is in text order
                let aligned = a
                    .unaligned
                    .binary_search_by_key(&raw_starts[k], |&(s, _)| s)
                    .is_err();
                let view = &a.normalized[view_starts[k]..line_end(&view_starts, &a.normalized, k)];
                aligned && view == &norm[norm_starts[k]..line_end(&norm_starts, norm, k)]
            })
            .collect()
    } else {
        Vec::new()
    };
    let line_of = |off: usize| norm_starts.partition_point(|&st| st <= off) - 1;
    found
        .iter()
        .map(|f| {
            if f.start >= f.end {
                return f.clone();
            }
            let (start, end) = if same_lines {
                let (first, last) = (line_of(f.start), line_of(f.end - 1));
                if precise[first..=last].iter().all(|&p| p) {
                    let s = f.start - norm_starts[first] + view_starts[first];
                    let e = f.end - norm_starts[last] + view_starts[last];
                    crate::guard::normalize::trim_directional_edges(text, a.start[s], a.end[e])
                } else {
                    (raw_starts[first], line_end(&raw_starts, text, last))
                }
            } else {
                (0, text.len())
            };
            SecretFinding {
                start,
                end,
                ..f.clone()
            }
        })
        .collect()
}

/// Sorts `spans` and merges every group of overlapping spans into one
/// span over the group's union (the grouping [`crate::pii::replace_spans`]
/// applies), labeled with the group's highest-score, then longest, then
/// earliest member. Invalid spans (out of bounds, off a char boundary)
/// are dropped; zero-length health markers are kept once, as `0..0` at
/// the front.
fn merge_mask_spans(text: &str, spans: Vec<SecretFinding>) -> Vec<SecretFinding> {
    let mut marker: Option<SecretFinding> = None;
    let mut valid: Vec<SecretFinding> = Vec::with_capacity(spans.len());
    for s in spans {
        if s.start == s.end {
            // position-free health marker: kept at 0..0, like the raw scan's
            marker.get_or_insert(SecretFinding {
                start: 0,
                end: 0,
                ..s
            });
        } else if s.start < s.end
            && s.end <= text.len()
            && text.is_char_boundary(s.start)
            && text.is_char_boundary(s.end)
        {
            valid.push(s);
        }
    }
    valid.sort_by_key(|s| s.start);
    let mut out: Vec<SecretFinding> = marker.into_iter().collect();
    let mut i = 0usize;
    while i < valid.len() {
        let mut label = valid[i].clone();
        let (start, mut end) = (valid[i].start, valid[i].end);
        let mut j = i + 1;
        while j < valid.len() && valid[j].start < end {
            let s = &valid[j];
            let better = match s.score.partial_cmp(&label.score) {
                Some(std::cmp::Ordering::Greater) => true,
                Some(std::cmp::Ordering::Equal) => s.end - s.start > label.end - label.start,
                _ => false,
            };
            if better {
                label = s.clone();
            }
            end = end.max(s.end);
            j += 1;
        }
        out.push(SecretFinding {
            start,
            end,
            ..label
        });
        i = j;
    }
    out
}

/// Masks every secret span with a typed placeholder: the spans of
/// [`find_secret_mask_spans`] (raw view united with the normalized view).
///
/// # Examples
/// ```
/// use redactify::guard::mask_secrets;
///
/// let out = mask_secrets("key AKIAIOSFODNN7EXAMPLE leaked");
/// assert!(out.contains("[SECRET:AWS_ACCESS_KEY]"));
/// // a zero-width split key is masked as one range
/// assert_eq!(
///     mask_secrets("key AKIA\u{200B}IOSFODNN7EXAMPLE leaked"),
///     "key [SECRET:AWS_ACCESS_KEY] leaked"
/// );
/// ```
#[must_use]
pub fn mask_secrets(text: &str) -> String {
    mask_secrets_with(text, None)
}

/// [`mask_secrets`] with a custom placeholder format; `{VENDOR}` in `fmt`
/// receives the vendor label (default `[SECRET:{VENDOR}]`).
///
/// A zero-length finding (the `SCAN_ERROR` health marker of an engine
/// error) masks nothing: it is visible in [`secrets_risk`], never written
/// into the text.
///
/// # Examples
/// ```
/// use redactify::guard::mask_secrets_with;
///
/// let out = mask_secrets_with("key AKIAIOSFODNN7EXAMPLE", Some("<{VENDOR}>"));
/// assert_eq!(out, "key <AWS_ACCESS_KEY>");
/// ```
#[must_use]
pub fn mask_secrets_with(text: &str, fmt: Option<&str>) -> String {
    mask_findings(text, &find_secret_mask_spans(text), fmt)
}

/// The masking step of [`mask_secrets_with`] over given findings, through
/// the crate's one span-replacement loop (which skips empty and invalid
/// spans); `None` is the default `[SECRET:{VENDOR}]` format. Shared by
/// every site that renders secret placeholders (e.g. JSON leaves).
pub(crate) fn mask_findings(text: &str, findings: &[SecretFinding], fmt: Option<&str>) -> String {
    let fmt = fmt.unwrap_or("[SECRET:{VENDOR}]");
    crate::pii::replace_spans(text, findings, |vendor, _| fmt.replace("{VENDOR}", vendor))
}

impl crate::pii::ReplaceSpan for SecretFinding {
    type Label = &'static str;

    fn byte_range(&self) -> (usize, usize) {
        (self.start, self.end)
    }

    fn label(&self) -> &'static str {
        self.vendor
    }

    fn rank(&self) -> u8 {
        0 // resolved findings never overlap: the tie-break is never needed
    }
}

fn tier_name(score: f32) -> &'static str {
    if score >= 0.9 {
        "vendor-validated"
    } else if score >= 0.6 {
        "context-confirmed"
    } else {
        "entropy-only"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slack_xoxo_user_token_detected() {
        // the xox* regex classes admit 'o' (user tokens), so VENDOR_MARKERS
        // must contain "xoxo": a marker miss skips the whole regex pass
        let token = "xoxo-123456789012-123456789012-abcdef0123456789abcdef01";
        let sigs = secrets_risk(&format!("leaked {token} in logs"));
        assert!(!sigs.is_empty(), "xoxo user token must be detected");
        assert!(sigs[0].score >= 0.9);
        assert_eq!(sigs[0].evidence.len(), 4 + "...(len 20)".len());
    }

    #[test]
    fn new_token_families_detected() {
        // xoxc/xoxd classes, xapp-, Twilio AC/SK and GOCSPX families
        let cases = [
            (
                "leaked xoxc-123456789012-123456789012-abcdef0123456789abcdef01",
                "SLACK_TOKEN",
            ),
            (
                "leaked xoxd-1234567890-abcdef0123456789abcdef012345",
                "SLACK_TOKEN",
            ),
            (
                "leaked xapp-1-A0123456789abcdef0123456789abcdef",
                "SLACK_APP_TOKEN",
            ),
            ("sid AC0123456789abcdef0123456789abcdef here", "TWILIO_SID"),
            ("tok SK0123456789abcdef0123456789abcdef here", "TWILIO_KEY"),
            ("g GOCSPX-abcdefghijklmnopqrstuvwxyz012345", "GOOGLE_OAUTH"),
        ];
        for (text, vendor) in cases {
            let spans = find_secret_spans(text);
            assert!(
                spans.iter().any(|s| s.vendor == vendor),
                "{vendor} not detected in {text}: {spans:?}"
            );
        }
    }

    #[test]
    fn twilio_sids_follow_the_vendor_schema() {
        // Twilio Key Resource v2010: `^AC[0-9a-fA-F]{32}$` (Account SID) and
        // `^SK[0-9a-fA-F]{32}$` (API Key SID), both 34 characters
        for (sid, vendor) in [
            ("AC0123456789abcdef0123456789abcdef", "TWILIO_SID"),
            ("AC0123456789ABCDEF0123456789ABCDEF", "TWILIO_SID"),
            ("SK0123456789abcdef0123456789abcdef", "TWILIO_KEY"),
            ("SK0123456789ABCDEF0123456789abcdef", "TWILIO_KEY"),
        ] {
            let spans = find_secret_spans(&format!("id {sid} end"));
            assert_eq!(spans.len(), 1, "{sid}: {spans:?}");
            assert_eq!(spans[0].vendor, vendor, "{sid}");
            assert!((spans[0].score - 0.9).abs() < 1e-6, "{sid}");
        }
        // 31 or 33 hex digits after the prefix: not the 34-character schema
        for sid in [
            "AC0123456789abcdef0123456789abcde",
            "SK0123456789abcdef0123456789abcdef0",
        ] {
            assert!(
                find_secret_spans(&format!("id {sid} end")).is_empty(),
                "{sid}"
            );
        }
        // one rule per prefix: the former TWILIO_TOKEN / TWILIO_KEY pair
        // matched the same `SK` shape
        let sk_rules = VENDOR_RULES
            .iter()
            .chain(CONTEXT_RULES.iter())
            .filter(|r| r.regex.as_str().contains("SK["))
            .count();
        assert_eq!(sk_rules, 1);
    }

    #[test]
    fn plausible_placeholders_rejected_without_killing_real_values() {
        // substring placeholders ("value", "your_") would reject REAL
        // credentials; token/prefix matching keeps placeholder rejection
        // while letting real values through
        let real = "password: MySecureValue123x!";
        let spans = find_secret_spans(real);
        assert!(
            spans
                .iter()
                .any(|s| s.vendor == "ASSIGNMENT" || s.score >= 0.6),
            "real-ish value must survive plausible: {spans:?}"
        );
        let ph = "password: your_p4ssw0rd_here_99xx";
        let spans = find_secret_spans(ph);
        assert!(
            spans.iter().all(|s| s.score < 0.6),
            "placeholder words must stay rejected: {spans:?}"
        );
    }

    #[test]
    fn aws_key_detected() {
        let sigs = secrets_risk("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].evidence, "AKIA...(len 20)");
        assert!(sigs[0].score >= 0.9);
    }

    #[test]
    fn aws_other_prefixes_detected() {
        // 4-char prefixes take exactly 16 more [A-Z0-9] chars; A3T takes 17
        // (A3T + one [A-Z0-9] belongs to the prefix family itself)
        for p in [
            "AROA", "ABIA", "ASIA", "AGPA", "ANPA", "AIDA", "AIPA", "ANVA", "ACCA",
        ] {
            let id = format!("{p}{}", "QYLOMOTPEXAMPLE1");
            let spans = find_secret_spans(&id);
            assert!(!spans.is_empty(), "prefix {p} not detected");
            assert_eq!(spans[0].vendor, "AWS_ACCESS_KEY");
        }
        let a3t = format!("A3T{}", "QYLOMOTPEXAMPLE12");
        assert_eq!(find_secret_spans(&a3t)[0].vendor, "AWS_ACCESS_KEY");
    }

    #[test]
    fn github_tokens_detected() {
        let body = "A".repeat(36);
        for p in ["ghp", "gho", "ghu", "ghs", "ghr"] {
            let t = format!("{p}_{body}");
            let spans = find_secret_spans(&t);
            assert_eq!(spans[0].vendor, "GITHUB_TOKEN", "prefix {p}");
            assert!(spans[0].score >= 0.9);
        }
        let fine = format!("github_pat_{}", "a".repeat(82));
        assert_eq!(find_secret_spans(&fine)[0].vendor, "GITHUB_TOKEN");
    }

    #[test]
    fn slack_classic_and_webhook() {
        let t = "xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx";
        let spans = find_secret_spans(t);
        assert!(spans
            .iter()
            .any(|s| s.vendor == "SLACK_TOKEN" && s.score >= 0.9));

        let hook =
            "https://hooks.slack.com/services/T12345678/B12345678/ABCDEFGHIJKLMNOPQRST12345678";
        assert!(find_secret_spans(hook)
            .iter()
            .any(|s| s.vendor == "SLACK_WEBHOOK"));
    }

    #[test]
    fn stripe_live_higher_than_test() {
        let live = find_secret_spans("sk_live_AbCdEfGhIjKlMnOpQrStUvWxYz12");
        assert!(live.iter().any(|s| s.score >= 0.9));
        let test = find_secret_spans("sk_test_AbCdEfGhIjKlMnOpQrStUvWxYz12");
        assert!(test.iter().any(|s| s.score == 0.6));
    }

    #[test]
    fn openai_and_anthropic() {
        let proj = format!("sk-proj-{}", "a".repeat(40));
        assert!(!find_secret_spans(&proj).is_empty());
        let ant = format!("sk-ant-api03-{}", "b".repeat(40));
        let spans = find_secret_spans(&ant);
        assert!(spans.iter().any(|s| s.vendor == "ANTHROPIC_KEY"));
    }

    #[test]
    fn doppler_token_formats() {
        // the vendor-published examples of every documented format
        let body = "bAqhcVzrhy5cRHkOlNTc0Ve6w5NUDCpcutm8vGE9myi";
        for prefix in [
            "dp.pt.",
            "dp.ct.",
            "dp.st.",
            "dp.st.dev.",
            "dp.sa.",
            "dp.said.",
            "dp.scim.",
            "dp.audit.",
        ] {
            let t = format!("DOPPLER_TOKEN={prefix}{body} ok");
            let spans = find_secret_spans(&t);
            assert!(
                spans.iter().any(|s| s.vendor == "DOPPLER_TOKEN"
                    && s.score >= 0.9
                    && t[s.start..s.end] == format!("{prefix}{body}")),
                "{prefix}: {spans:?}"
            );
        }
        // deliberately invalid: body too short / too long, unknown type,
        // environment segment with uppercase letters
        for bad in [
            format!("dp.pt.{}", &body[..39]),
            format!("dp.pt.{body}{}", "x".repeat(2)),
            format!("dp.zz.{body}"),
            format!("dp.st.PRD.{body}"),
        ] {
            assert!(
                find_secret_spans(&bad)
                    .iter()
                    .all(|s| s.vendor != "DOPPLER_TOKEN"),
                "{bad}"
            );
        }
    }

    #[test]
    fn google_gitlab_npm_pypi_sendgrid_telegram() {
        let g = format!("AIza{}", "a".repeat(35));
        assert!(find_secret_spans(&g)
            .iter()
            .any(|s| s.vendor == "GOOGLE_API_KEY"));
        let gl = format!("glpat-{}", "a1".repeat(12));
        assert!(find_secret_spans(&gl)
            .iter()
            .any(|s| s.vendor == "GITLAB_TOKEN"));
        let npm = format!("npm_{}", "a".repeat(36));
        assert!(find_secret_spans(&npm)
            .iter()
            .any(|s| s.vendor == "NPM_TOKEN"));
        let pypi = format!("pypi-AgEIcHlwaS5vcmc{}", "a".repeat(60));
        assert!(find_secret_spans(&pypi)
            .iter()
            .any(|s| s.vendor == "PYPI_TOKEN"));
        let sg = format!("SG.{}.{}", "a".repeat(20), "b".repeat(30));
        assert!(find_secret_spans(&sg)
            .iter()
            .any(|s| s.vendor == "SENDGRID_KEY"));
        let tg = format!("1234567890:AA{}", "c".repeat(33));
        assert!(find_secret_spans(&tg)
            .iter()
            .any(|s| s.vendor == "TELEGRAM_TOKEN"));
    }

    #[test]
    fn pem_header_detected() {
        let pem =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        assert!(find_secret_spans(pem)
            .iter()
            .any(|s| s.vendor == "PEM_PRIVATE_KEY"));
        // OPENSSH + EC variants too
        assert!(find_secret_spans("-----BEGIN OPENSSH PRIVATE KEY-----")
            .iter()
            .any(|s| s.vendor == "PEM_PRIVATE_KEY"));
        assert!(find_secret_spans("-----BEGIN EC PRIVATE KEY-----")
            .iter()
            .any(|s| s.vendor == "PEM_PRIVATE_KEY"));
    }

    #[test]
    fn aws_secret_with_cue() {
        let line = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let spans = find_secret_spans(line);
        assert!(spans
            .iter()
            .any(|s| s.vendor == "AWS_SECRET_KEY" && s.score >= 0.9));
    }

    #[test]
    fn jwt_valid_header_scores_higher() {
        // header {"alg":"HS256","typ":"JWT"}
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let spans = find_secret_spans(jwt);
        assert!(spans.iter().any(|s| s.vendor == "JWT" && s.score >= 0.9));

        // shape without a JSON header stays 0.6
        let fake = format!("eyJaaaaaaaaaaaaaaaa.{}.", "b".repeat(20));
        let spans2 = find_secret_spans(&fake);
        assert!(spans2
            .iter()
            .any(|s| s.vendor == "JWT_SHAPE" && s.score == 0.6));
    }

    #[test]
    fn assignment_and_bearer_and_url_credentials() {
        let spans = find_secret_spans("password = hunter2secure42!");
        assert!(spans.iter().any(|s| s.vendor == "CREDENTIAL_ASSIGNMENT"));

        let bearer = "Authorization: Bearer AbCdEf123456789012345678";
        assert!(find_secret_spans(bearer)
            .iter()
            .any(|s| s.vendor == "BEARER_TOKEN"));

        let url = "postgres://admin:S3cr3tPass@db.example.com/prod";
        let spans = find_secret_spans(url);
        assert!(spans.iter().any(|s| s.vendor == "URL_CREDENTIALS"));
        // the masked text never contains the password
        let masked = mask_secrets(url);
        assert!(!masked.contains("S3cr3tPass"));
    }

    #[test]
    fn prefixed_and_quoted_credential_keys_are_masked() {
        const V: &str = "Sup3rS3cret!2026x";
        for key in [
            "DB_PASSWORD=",
            "MAIL_PASSWORD=",
            "db_password: ",
            "APP_SECRET=",
            "JWT_SECRET=",
            "STRIPE_SECRET_KEY=",
            "PUSHER_APP_KEY=",
            "GITHUB_TOKEN=",
            "SESSION_TOKEN=",
            "ENCRYPTION_KEY=",
            "export AWS_SECRET_ACCESS_KEY=",
            "spring.datasource.password=",
            "\"password\": \"",
            "{\"db_password\":\"",
            "'api_key': '",
        ] {
            let text = format!("{key}{V}");
            let masked = mask_secrets(&text);
            assert!(!masked.contains(V), "{text} -> {masked}");
        }
        // Laravel APP_KEY (the value is the whole `base64:...` string)
        let laravel = "APP_KEY=base64:q1w2e3r4t5y6u7i8o9p0a1s2d3f4g5h6j7k8l9z0x1c=";
        assert!(!mask_secrets(laravel).contains("q1w2e3r4"));
    }

    /// Every character the case-insensitive regex class `class` accepts,
    /// as computed by `regex-syntax` (the parser the regex engine uses).
    fn case_insensitive_chars(class: &str) -> Vec<char> {
        use regex_syntax::hir::{Class, HirKind};
        let hir = regex_syntax::ParserBuilder::new()
            .case_insensitive(true)
            .build()
            .parse(class)
            .expect("class parses");
        match hir.kind() {
            HirKind::Class(Class::Unicode(c)) => {
                c.iter().flat_map(|r| r.start()..=r.end()).collect()
            }
            other => panic!("{class}: {other:?}"),
        }
    }

    #[test]
    fn turkish_key_prefilter_covers_every_spelling_the_regex_accepts() {
        // the per-position classes of the Turkish keys in ASSIGNMENT_RULES
        let s1 = case_insensitive_chars(r"[\x{15F}s]");
        let s2 = case_insensitive_chars(r"[i\x{131}\x{130}]");
        // s, S, s-cedilla in both cases, long s (case-folds to s)
        assert_eq!(s1, ['S', 's', '\u{15e}', '\u{15f}', '\u{17f}']);
        // i, I, dotted capital I, dotless i
        assert_eq!(s2, ['I', 'i', '\u{130}', '\u{131}']);
        let fre: Vec<Vec<char>> = ["f", "r", "e"]
            .iter()
            .map(|c| case_insensitive_chars(c))
            .collect();
        let mut checked = 0;
        for &a in &s1 {
            for &b in &s2 {
                for &f in &fre[0] {
                    for &r in &fre[1] {
                        for &e in &fre[2] {
                            let key: String = [a, b, f, r, e].iter().collect();
                            // the prefilter sees every spelling ...
                            assert!(has_cue_marker(&key), "{key:?}");
                            // ... and the assignment rule masks the value
                            let text = format!("{key}: Xk1!m7Pq9");
                            let spans = find_secret_spans(&text);
                            assert_eq!(spans.len(), 1, "{text:?}: {spans:?}");
                            assert_eq!(&text[spans[0].start..], "Xk1!m7Pq9", "{text:?}");
                            checked += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(checked, 5 * 4 * 8);
        // `parola`: ASCII letters only, so the ASCII-case-insensitive
        // literal covers every spelling
        for c in ["p", "a", "r", "o", "l"] {
            assert!(case_insensitive_chars(c).iter().all(char::is_ascii), "{c}");
        }
        // suffixed labels, and a line whose other marker already runs the
        // regex
        for text in [
            "S\u{130}FRES\u{130}: Xk1!m7Pq9",
            "\u{15e}\u{131}fren\u{131}z: Xk1!m7Pq9",
            "PAROLANIZ: Xk1!m7Pq9",
            "token yok; S\u{130}FRE: Xk1!m7Pq9",
        ] {
            let spans = find_secret_spans(text);
            assert_eq!(spans.len(), 1, "{text:?}: {spans:?}");
        }
    }

    #[test]
    fn credential_word_must_end_the_key() {
        // the credential word only qualifies the key, or a bare `key`
        for text in [
            "PASSWORD_RESET_URL=https://example.com/reset/form",
            "TOKEN_EXPIRY=3600000000",
            "PASSWORD_MIN_LENGTH=12",
            "PASSWORD_HASH_ALGO=argon2id",
            "CACHE_KEY=users_list_v2",
            "SORT_KEY=created_at_desc",
            "PRIMARY_KEY=customer_id",
            "max_tokens: 4096000000",
            "OLDPWD=/home/user/project",
            "the token: is required in each request header",
        ] {
            assert!(
                find_secret_spans(text).is_empty(),
                "fired: {text} -> {:?}",
                find_secret_spans(text)
            );
        }
        // placeholders behind a prefixed key stay unfired too
        for text in [
            "DB_PASSWORD=${DB_PASS}",
            "DB_PASSWORD=changeme",
            "APP_SECRET=your_secret_here",
        ] {
            assert!(
                find_secret_spans(text).is_empty(),
                "placeholder fired: {text}"
            );
        }
    }

    #[test]
    fn bare_token_keeps_the_entropy_tier() {
        // a bare `token:` is not a credential assignment (0.6 is the
        // SECRETS block line): a short value stays silent and a long
        // high-entropy value stays at the 0.4 backstop
        assert!(find_secret_spans("token: abcd1234ef").is_empty());
        let spans = find_secret_spans("token: a3f1b2c9d8e7f0a1b2c3d4e5f6a7b8c9");
        assert!(
            spans.iter().all(|s| s.vendor == "HIGH_ENTROPY"),
            "{spans:?}"
        );
        // a prefixed `*_TOKEN` key is a credential assignment
        let spans = find_secret_spans("GITHUB_TOKEN=tok42AbCdEf98765!");
        assert!(
            spans.iter().any(|s| s.vendor == "CREDENTIAL_ASSIGNMENT"),
            "{spans:?}"
        );
    }

    #[test]
    fn placeholders_never_fire() {
        for t in [
            "password = changeme",
            "api_key: <your_key_here>",
            r"password=${DB_PASS}",
            "token: redacted",
            "secret: xxxxxxxx",
        ] {
            assert!(
                find_secret_spans(t).is_empty(),
                "placeholder fired: {t} -> {:?}",
                find_secret_spans(t)
            );
        }
    }

    #[test]
    fn entropy_requires_cue_and_floor() {
        // random-looking base64 with cue
        let with_cue = "the api key is 3q2+7wJalrXUtnFEMIK7MDENGbPxRfiCY";
        assert!(find_secret_spans(with_cue)
            .iter()
            .any(|s| s.vendor == "HIGH_ENTROPY"));
        // same run without any cue: silent (git-log invariant)
        let no_cue = "commit 3q2+7wJalrXUtnFEMIK7MDENGbPxRfiCY merged";
        assert!(find_secret_spans(no_cue).is_empty());
        // low-entropy value with cue stays silent
        let low = "the key is aaaaaaaaaaaaaaaaaaaaaa";
        assert!(find_secret_spans(low).is_empty());
    }

    #[test]
    fn benign_corpus_silent() {
        for t in [
            "The quick brown fox jumps over the lazy dog",
            "order id ORD-123456789012 shipped",
            "version 2.4.1 released on 2024-01-15",
            "sunucu 10.0.0.5 uzerinden yanit verdi",
            "ISBN 978-3-16-148410-0 available",
            "team standup at 9, retro at 14",
            "sk-attention mechanism explained in the paper",
            "TR33 0006 1005 1978 6457 8413 26 IBAN transfer", // PII, not a secret
        ] {
            assert!(
                find_secret_spans(t).is_empty(),
                "benign fired: {t} -> {:?}",
                find_secret_spans(t)
            );
        }
    }

    #[test]
    fn overlaps_collapse_to_best() {
        // AWS key id next to its 40-char secret shape: both 0.9, no overlap
        let line = "AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKE1";
        let spans = find_secret_spans(line);
        for w in spans.windows(2) {
            assert!(w[0].end <= w[1].start, "overlap survived: {spans:?}");
        }
    }

    #[test]
    fn mask_replaces_value_and_keeps_rest() {
        let out = mask_secrets("prefix AKIAIOSFODNN7EXAMPLE suffix");
        assert_eq!(out, "prefix [SECRET:AWS_ACCESS_KEY] suffix");
        let custom = mask_secrets_with("key AKIAIOSFODNN7EXAMPLE", Some("<{VENDOR}>"));
        assert_eq!(custom, "key <AWS_ACCESS_KEY>");
    }

    #[test]
    fn zero_length_scan_error_finding_masks_nothing() {
        // the zero-length SCAN_ERROR health finding must not insert
        // "[SECRET:SCAN_ERROR]" at offset 0 of the masked text
        let text = "key AKIAIOSFODNN7EXAMPLE end";
        let findings = [
            SecretFinding {
                start: 0,
                end: 0,
                vendor: "SCAN_ERROR",
                score: 0.4,
            },
            SecretFinding {
                start: 4,
                end: 24,
                vendor: "AWS_ACCESS_KEY",
                score: 0.9,
            },
        ];
        let out = mask_findings(text, &findings, None);
        assert_eq!(out, "key [SECRET:AWS_ACCESS_KEY] end");
        // a SCAN_ERROR-only result leaves the text untouched
        assert_eq!(mask_findings(text, &findings[..1], None), text);
    }

    /// One witness per VENDOR_RULES / CONTEXT_RULES entry, in table order
    /// (synthetic or deliberately invalid values).
    const RULE_WITNESSES: &[&str] = &[
        // VENDOR_RULES
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "github_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
        "xapp-1-A0123456789abcdef0123456789abcdef",
        "AC0123456789ABCDEF0123456789abcdef",
        "SK0123456789abcdef0123456789ABCDEF",
        "GOCSPX-abcdefghijklmnopqrstuvwxyz012345",
        "https://hooks.slack.com/services/T12345678/B12345678/ABCDEFGHIJKLMNOPQRST12345678",
        "sk_live_AbCdEfGhIjKlMnOpQrStUvWx",
        "sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sk-ant-api03-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "AIzaSyA1234567890abcdefghijklmnopqrstuv",
        "glpat-ab12cd34ef56gh78ijklmnop",
        "npm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "pypi-AgEIcHlwaS5vcmcBaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "SG.AAAAAAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "1234567890:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw",
        "dp.pt.bAqhcVzrhy5cRHkOlNTc0Ve6w5NUDCpcutm8vGE9myi",
        "-----BEGIN RSA PRIVATE KEY-----",
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        // CONTEXT_RULES
        "sk_test_AbCdEfGhIjKlMnOpQrStUvWx",
        "sk-AbCdEfGhIjKlMnOpQrStUvWxYz012345",
        "xoxd-1234567890-abcdef0123456789abcdef012345",
        "AccountKey=eByt0p6cqOdzL3Zw0GF0YlJmTnZMNFV1V2pNd0Azb0YzQWJjZA==",
    ];

    #[test]
    fn every_vendor_rule_carries_a_prefilter_marker() {
        // The prefilter contract: an Aho-Corasick miss must prove that no
        // rule can match. Every case-sensitive rule's match therefore has
        // to contain a VENDOR_MARKER_LITERALS entry, every case-insensitive
        // rule's match a CUE_MARKER_LITERALS entry. Checked on one witness
        // per rule; a new rule without a witness fails the count below.
        let rules: Vec<&SecretRule> = VENDOR_RULES.iter().chain(CONTEXT_RULES.iter()).collect();
        assert_eq!(rules.len(), RULE_WITNESSES.len(), "one witness per rule");
        for (rule, witness) in rules.iter().zip(RULE_WITNESSES) {
            let m = rule
                .regex
                .find(witness)
                .expect("engine")
                .unwrap_or_else(|| panic!("{} does not match its witness", rule.vendor));
            let matched = m.as_str();
            let covered = if rule.regex.as_str().starts_with("(?i)") {
                has_cue_marker(matched)
            } else {
                has_vendor_marker(matched)
            };
            assert!(
                covered,
                "{} match {matched:?} carries no marker",
                rule.vendor
            );
        }
        // the JWT shape is gated by the "eyJ" marker
        assert!(VENDOR_MARKER_LITERALS.contains(&"eyJ"));
        assert!(JWT_SHAPE.as_str().contains("eyJ"));
    }

    #[test]
    fn shannon_is_exact() {
        // uniform hex nibbles 0-f over 16 chars -> 4.0 bits/char
        let bytes: Vec<u8> = (0..16u8)
            .map(|b| match b {
                0..=9 => b'0' + b,
                _ => b'a' + b - 10,
            })
            .collect();
        assert!((shannon(&bytes) - 4.0).abs() < 1e-5);
        // constant run -> 0.0
        assert_eq!(shannon(b"aaaaaaaa"), 0.0);
    }

    #[test]
    fn evidence_never_contains_the_secret() {
        let sigs = secrets_risk("api_key = Sup3rS3cr3tValu3!");
        for s in &sigs {
            assert!(!s.evidence.contains("Sup3rS3cr3t"));
            assert!(!s.rationale.contains("Sup3rS3cr3t"));
        }
    }

    fn sf(start: usize, end: usize, vendor: &'static str, score: f32) -> SecretFinding {
        SecretFinding {
            start,
            end,
            vendor,
            score,
        }
    }

    #[test]
    fn mask_spans_unite_raw_and_normalized_findings() {
        // the raw view sees nothing, the normalized view the key;
        // the mapped span covers the zero-width character too
        let text = "a AKIA\u{200B}IOSFODNN7EXAMPLE b";
        let spans = find_secret_mask_spans(text);
        assert_eq!(spans.len(), 1);
        assert_eq!(
            &text[spans[0].start..spans[0].end],
            "AKIA\u{200B}IOSFODNN7EXAMPLE"
        );
        // a raw-only and a normalized-only key on one line: both masked
        let both = "x AKIAIOSFODNN7EXAMPLE y \u{FF21}KIAIOSFODNN7EXAMPLE z";
        assert_eq!(
            mask_secrets(both),
            "x [SECRET:AWS_ACCESS_KEY] y [SECRET:AWS_ACCESS_KEY] z"
        );
        // ASCII text: exactly the raw scan
        let ascii = "token: aB3dE5fG7hJ9kL1mN2pQ AKIAIOSFODNN7EXAMPLE";
        assert_eq!(find_secret_mask_spans(ascii), find_secret_spans(ascii));
    }

    #[test]
    fn merge_unites_overlaps_and_labels_by_score_then_length() {
        let text = "0123456789abcdefghijklmnopqrstuvwxyz";
        let merged = merge_mask_spans(
            text,
            vec![
                sf(10, 30, "HIGH_ENTROPY", 0.4),
                sf(8, 20, "AWS_ACCESS_KEY", 0.9),
                sf(30, 34, "JWT_SHAPE", 0.6), // adjacent: a group of its own
                sf(0, 0, "SCAN_ERROR", 0.4),
                sf(0, 0, "SCAN_ERROR", 0.4),
                sf(35, 99, "OUT_OF_BOUNDS", 0.9),
            ],
        );
        assert_eq!(
            merged,
            vec![
                sf(0, 0, "SCAN_ERROR", 0.4),
                sf(8, 30, "AWS_ACCESS_KEY", 0.9),
                sf(30, 34, "JWT_SHAPE", 0.6),
            ]
        );
        // equal scores: the longer member labels the group; equal length
        // too: the earlier one
        let merged = merge_mask_spans(text, vec![sf(0, 4, "A", 0.6), sf(2, 12, "B", 0.6)]);
        assert_eq!(merged, vec![sf(0, 12, "B", 0.6)]);
        let merged = merge_mask_spans(text, vec![sf(2, 6, "B", 0.6), sf(0, 4, "A", 0.6)]);
        assert_eq!(merged, vec![sf(0, 6, "A", 0.6)]);
    }

    #[test]
    fn merged_spans_replace_exactly_the_regions_replace_spans_replaces() {
        // the merge groups like the crate's one span-replacement loop:
        // over every pair and triple of the spans below (overlapping,
        // nested, adjacent, empty, off a char boundary, out of bounds) the
        // replaced regions are identical
        let text = "ab\u{e7}def AKIA x\u{11f}y tail";
        let pool = [
            sf(0, 2, "A", 0.9),
            sf(0, 6, "B", 0.6),
            sf(4, 12, "C", 0.4),
            sf(6, 8, "D", 0.9),
            sf(8, 12, "E", 0.6),
            sf(12, 22, "F", 0.4),
            sf(3, 8, "OFF", 0.9),
            sf(5, 5, "EMPTY", 0.4),
            sf(20, 40, "OUT", 0.9),
        ];
        let region = |_: &'static str, r: &str| format!("<{}>", r.len());
        let mut checked = 0;
        for i in 0..pool.len() {
            for j in i..pool.len() {
                for k in j..pool.len() {
                    let spans = vec![pool[k].clone(), pool[i].clone(), pool[j].clone()];
                    let merged = merge_mask_spans(text, spans.clone());
                    for w in merged.windows(2) {
                        assert!(w[0].end <= w[1].start, "{merged:?}");
                    }
                    assert_eq!(
                        crate::pii::replace_spans(text, &merged, region),
                        crate::pii::replace_spans(text, &spans, region),
                        "{spans:?}"
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 165);
    }

    #[test]
    fn unaligned_lines_fail_closed_per_line() {
        use crate::guard::normalize::{align_for_scan_with, align_line};
        // the aligner seam: the key's line cannot be aligned, so that
        // whole raw line is masked and the other lines stay
        let text = "first \u{FF21}\nkey AKIA\u{200B}IOSFODNN7EXAMPLE end\nlast";
        let fail_on = |needle: &'static str| {
            move |t: &str| {
                align_for_scan_with(t, |line| {
                    if line.contains(needle) {
                        None
                    } else {
                        align_line(line)
                    }
                })
            }
        };
        let spans = secret_mask_spans_with(text, fail_on("AKIA"));
        assert_eq!(spans.len(), 1);
        assert_eq!(
            &text[spans[0].start..spans[0].end],
            "key AKIA\u{200B}IOSFODNN7EXAMPLE end"
        );
        assert_eq!(spans[0].vendor, "AWS_ACCESS_KEY");
        // another line failing does not coarsen the key's precise span
        let spans = secret_mask_spans_with(text, fail_on("first"));
        assert_eq!(
            &text[spans[0].start..spans[0].end],
            "AKIA\u{200B}IOSFODNN7EXAMPLE"
        );
        // a finding over a line break covers both lines; a span ending
        // with the break does not reach the next line
        let two = "a\nb c\nd e\nf";
        let a = fail_on(" ")(two);
        let spans = map_to_raw(two, two, &a, &[sf(4, 7, "X", 0.6), sf(6, 10, "Y", 0.6)]);
        assert_eq!((spans[0].start, spans[0].end), (2, 9));
        assert_eq!((spans[1].start, spans[1].end), (6, 9));
        // line counts that disagree: the whole text; markers pass through
        let spans = map_to_raw(
            text,
            "one line",
            &align_for_scan(text),
            &[sf(0, 4, "X", 0.9), sf(0, 0, "SCAN_ERROR", 0.4)],
        );
        assert_eq!((spans[0].start, spans[0].end), (0, text.len()));
        assert_eq!((spans[1].start, spans[1].end), (0, 0));
    }

    #[test]
    fn mask_span_starts_read_the_cluster_start() {
        // a key whose first char comes out of a multi-char NFKC expansion
        // (U+00BD -> `1`, U+2044, `2`; the Telegram rule starts at the `2`):
        // the raw span starts at the expansion, never after it
        let text = "bot \u{BD}34567890:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw end";
        let spans = find_secret_mask_spans(text);
        assert_eq!(spans.len(), 1, "{spans:?}");
        assert_eq!(spans[0].vendor, "TELEGRAM_TOKEN");
        assert_eq!(
            &text[spans[0].start..spans[0].end],
            "\u{BD}34567890:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"
        );
    }
}
