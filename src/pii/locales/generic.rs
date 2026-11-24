//! Locale-independent rules declared here: e-mail, credit card (Luhn +
//! number-range length),
//! IP address (IPv4/IPv6, public addresses only; plus the
//! whitespace-separated IPv6 helper), URL and international `+CC` phone
//! numbers. The other always-on rules live in their own modules: IBAN
//! (`iban`, 89 registry countries), VIN (`vin`), IMEI (`imei`) and
//! SWIFT/BIC (`swift`).
//! Several rules share this module, so each one carries an explicit rule
//! id (`generic::email`, ...; see `rule!`).

use crate::pii::entity::EntityType;
use crate::pii::locales::{luhn_valid, rule, ContextPolicy, Rule};

/// Returns `true` if `number` passes the Luhn checksum.
///
/// Non-digit characters are ignored (space/dash separators); at least **13**
/// digits are required. Every second digit, starting from the second one on the
/// right, is doubled; values above 9 have 9 subtracted; the sum must be a
/// multiple of 10.
///
/// # Examples
/// ```
/// use redactify::valid_luhn;
/// assert!(valid_luhn("4111111111111111"));
/// assert!(!valid_luhn("4111111111111112"));
/// ```
#[must_use]
pub fn valid_luhn(number: &str) -> bool {
    let digits: Vec<u8> = number.bytes().filter(u8::is_ascii_digit).collect();
    digits.len() >= 13 && luhn_valid(&digits)
}

/// E-mail address, including internationalized addresses. RFC 6531
/// section 3.3 extends the RFC 5321 mailbox with `sub-domain =/ U-label`
/// and `atext =/ UTF8-non-ascii`
/// (<https://www.rfc-editor.org/rfc/rfc6531>, retrieved 2026-10-31):
/// - domain labels accept letters, marks and digits of any script (a
///   U-label sits between `@` and an ASCII dot, so it is delimited on
///   both sides);
/// - the top-level domain is ASCII letters or an A-label (`xn--...`,
///   RFC 5890 section 2.3.2.1). A U-label top-level domain is not
///   matched: next to CJK or Thai text, which has no word spaces, its end
///   cannot be told apart from the following word;
/// - the local part accepts ASCII `atext` characters plus Latin-script
///   letters (`müller`, `çağrı`): before, the ASCII-only class masked
///   `ller@example.com` and left `mü` visible. Letters of other scripts
///   are left out of the local part for the same delimiting reason (a CJK
///   sentence would otherwise be swallowed into the address).
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn email_rule() -> Rule {
    rule!(
        id = "generic::email",
        EntityType::Email,
        r"[A-Za-z0-9._%+\-\p{Latin}]+@[\p{L}\p{M}\p{N}.\-]+\.(?:xn--[A-Za-z0-9\-]*[A-Za-z0-9]|[A-Za-z]{2,})",
        None,
        ContextPolicy::None,
        0.85
    )
}

/// Card number ranges whose published lengths include 15 digits:
/// `(prefix digits, first prefix, last prefix)`. A 15-digit card candidate
/// is a card only inside one of them (see [`card_length_fits_iin`]).
/// Sources, retrieved 2026-11-23:
///
/// - American Express, "Getting Started" merchant guide (UK): "Card
///   Account numbers are embossed and begin with '34' or '37' and consist
///   of 15 digits"
///   (<https://americanexpress.com/content/dam/amex/uk/staticassets/merchant/pdf/support-and-services/American_Express_Getting_Started_Guide.pdf>);
/// - Discover Global Network, "Global Payment Network - IIN Range Summary"
///   (2026): 3600 0000 - 3699 9999 (Diners Club International) is listed
///   with 14-19 digits; every other range (Discover, Diners Club, JCB
///   3528-3589, UnionPay) with 16-19
///   (<https://www.discoverglobalnetwork.com/content/dam/discover/en_us/dgn/docs/IPP-VAR-Enabler-Compliance.pdf>);
/// - Mastercard BIN Lookup support page: "Maestro account ranges:
///   639000--639099 / 670000--679999"
///   (<https://developer.mastercard.com/bin-lookup/documentation/support/>);
/// - Wikipedia "Payment card number" (secondary, **unverified** against
///   the networks' own documents), kept so that no card it lists is lost:
///   UATP `1` (15 digits), Diners Club `30`, `38`, `39` (14-19), Maestro
///   (12-19, also 5018, 5020, 5038, 5893, 6304).
const FIFTEEN_DIGIT_CARD_RANGES: &[(u8, u32, u32)] = &[
    (1, 1, 1),             // UATP (unverified)
    (2, 30, 30),           // Diners Club (unverified)
    (2, 34, 34),           // American Express
    (2, 36, 36),           // Diners Club International (Discover)
    (2, 37, 37),           // American Express
    (2, 38, 39),           // Diners Club (unverified)
    (4, 5018, 5018),       // Maestro (unverified)
    (4, 5020, 5020),       // Maestro (unverified)
    (4, 5038, 5038),       // Maestro (unverified)
    (4, 5893, 5893),       // Maestro (unverified)
    (4, 6304, 6304),       // Maestro (unverified)
    (6, 639_000, 639_099), // Maestro (Mastercard)
    (6, 670_000, 679_999), // Maestro (Mastercard), holds 6759 and 6761-6763
];

/// The first `n` digits of `digits` as a number.
fn prefix(digits: &[u8], n: usize) -> u32 {
    digits[..n]
        .iter()
        .fold(0, |acc, &d| acc * 10 + u32::from(d - b'0'))
}

/// Whether a Luhn-valid digit run fits a card number range:
///
/// - 15 digits: only inside [`FIFTEEN_DIGIT_CARD_RANGES`]. All 39 IMEIs
///   of nm-kvkk-pii-6K (15 digits, prefixes 35 and 86) pass Luhn and
///   belong to `imei`; JCB 3528-3589 has 16-19 digits and 86 is in no card
///   range. The same check drops two 15-digit IMSIs (MCC 286) and a
///   15-digit fragment of a UUID in that set;
/// - every other length (13-19): any prefix. A run of 13, 14 or
///   16-19 digits that passes Luhn without being a card is often another
///   identifier (a South African ID number, a SIRET) whose pack is not
///   enabled, and the card rule is its only mask; an unlisted national or
///   private-label network keeps its cards masked too;
/// - never a run of one repeated digit. Of those only `0...0` (every
///   length), `6...6` (13), `8...8` (16), `2...2` and `4...4` (17) pass
///   Luhn, and none is a card: no range starts with `0`, `66` or `88`, and
///   `2...2` / `4...4` would be 17-digit Mastercard / Visa numbers, a length
///   neither lists (Mastercard 16, Visa 13/16/19 in the Wikipedia table,
///   **unverified**). Seen as `0000000000000000` and `8888888888888888` in
///   third-party negative fixtures.
fn card_length_fits_iin(digits: &[u8]) -> bool {
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }
    digits.len() != 15
        || FIFTEEN_DIGIT_CARD_RANGES
            .iter()
            .any(|&(n, lo, hi)| (lo..=hi).contains(&prefix(digits, usize::from(n))))
}

/// Card validator: Luhn, except for an E.164 phone number. About one digit
/// run in ten passes Luhn by chance, so `+4915112345678` (a German mobile
/// number) would be claimed as `CREDIT_CARD` - a checksummed span
/// outranks a phone - with its `+` left in clear. A `+`-prefixed candidate
/// in a shape the `generic::intl_phone` rule matches as well (compact, or
/// `+CC NATIONAL` with a space or hyphen) that [`valid_intl_phone`]
/// accepts is that phone, and the phone rule claims the same span. Any
/// other `+`-prefixed run stays a card candidate, `+` included, so a card
/// in a URL-encoded form body (`my+card+is+4111111111111111`) is still
/// masked whole; a card candidate is never dropped for a phone shape the
/// phone rule would not claim (`+4111 1111 1111 111`).
fn valid_card_match(candidate: &str) -> bool {
    let phone = candidate.strip_prefix('+').is_some_and(|rest| {
        let mut groups = rest.split([' ', '-']);
        let first = groups.next().unwrap_or_default();
        let shaped = match (groups.next(), groups.next()) {
            (None, _) => true,
            (Some(national), None) => first.len() <= 3 && (6..=12).contains(&national.len()),
            _ => false,
        };
        shaped && valid_intl_phone(candidate)
    });
    !phone && card_number(candidate)
}

/// A card number for the `CREDIT_CARD` rule: [`valid_credit_card`] (13-19
/// digits, Luhn) plus a length that fits the number range
/// ([`card_length_fits_iin`]). The public validator keeps its plain Luhn
/// contract (it is cross-checked row by row against an independent
/// implementation in `tests/validator_crosscheck.rs`).
fn card_number(candidate: &str) -> bool {
    let digits: Vec<u8> = candidate.bytes().filter(u8::is_ascii_digit).collect();
    (13..=19).contains(&digits.len()) && luhn_valid(&digits) && card_length_fits_iin(&digits)
}

/// Credit-card rule (13-19 digits, Luhn, the length must fit the number
/// range, see [`card_number`] and [`valid_card_match`]). A `+`
/// right before the digits starts the match (leftmost match); after a
/// digit (`qty=2+4111...`) the match starts at the digits.
/// The fraction of a decimal number is no card: a float printed with 16
/// or more fraction digits (`score 0.4111111111111111`, JSON / log
/// output) passes Luhn about one time in ten, so an UNSEPARATED run after
/// `<digit>.` is skipped; a grouped run there (`item 1.4111 1111 1111
/// 1111`) is a card, since a fraction holds no separator. A decimal comma
/// is not skipped: `1,4111111111111111,John` is a CSV row as often as a
/// Turkish decimal. The check is one negative lookahead (no alternation):
/// every lookaround and branch costs backtracking steps at EVERY start
/// position, and an alternation of the two shapes exhausted the step
/// budget on a 200 000-character line (`tests/custom_rule_linear.rs`).
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn card_rule() -> Rule {
    rule!(
        id = "generic::card",
        EntityType::CreditCard,
        r"(?<!\d)(?!(?<=\d\.)\d{13,19}(?!\d))\+?(?:\d[ -]?){12,18}\d(?!\d)",
        Some(valid_card_match),
        ContextPolicy::None,
        1.0
    )
}

/// Returns `true` if `ip` is a structurally valid IPv4 or IPv6 address.
///
/// IPv4: 4 decimal octets, each 0-255 (leading zeros rejected to avoid
/// octal-notation ambiguity). IPv6: 8 hextets or `::` compressed form
/// (simplified: at most one `::`, valid hex groups).
///
/// # Examples
/// ```
/// use redactify::valid_ip_address;
/// assert!(valid_ip_address("192.168.1.1"));
/// assert!(valid_ip_address("255.255.255.0"));
/// assert!(!valid_ip_address("256.1.1.1")); // octet > 255
/// assert!(!valid_ip_address("192.168.1"));  // 3 octets
/// assert!(valid_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
/// assert!(valid_ip_address("::1"));
/// assert!(!valid_ip_address("2001:db8:::1")); // double ::
/// ```
#[must_use]
pub fn valid_ip_address(ip: &str) -> bool {
    let s = ip.trim();
    // IPv4
    if s.contains('.') && !s.contains(':') {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return false;
        }
        return parts.iter().all(|p| {
            if p.is_empty() || p.len() > 3 || !p.chars().all(|c| c.is_ascii_digit()) {
                return false;
            }
            if p.len() > 1 && p.starts_with('0') {
                return false;
            }
            p.parse::<u16>().is_ok_and(|v| v <= 255)
        });
    }
    // IPv6 (simplified: :: compression + hex groups)
    if s.contains(':') {
        if s.contains(":::") {
            return false;
        }
        let has_compression = s.contains("::");
        let groups: Vec<&str> = if has_compression {
            let (left, right) = s.split_once("::").unwrap_or((s, ""));
            // at most ONE `::` (doc contract): splitting the right-hand
            // side on single colons would silently drop an inner `::` and
            // pass `1::2::3`
            if right.contains("::") {
                return false;
            }
            let mut g: Vec<&str> = left.split(':').filter(|x| !x.is_empty()).collect();
            g.extend(right.split(':').filter(|x| !x.is_empty()));
            g
        } else {
            s.split(':').collect()
        };
        if !has_compression && groups.len() != 8 {
            return false;
        }
        if has_compression && groups.len() > 7 {
            return false;
        }
        return groups
            .iter()
            .all(|g| !g.is_empty() && g.len() <= 4 && g.chars().all(|c| c.is_ascii_hexdigit()));
    }
    false
}

/// IPv4 reserved / non-routable ranges: `0/8` (this-network), `10/8` +
/// `172.16/12` + `192.168/16` (RFC 1918 private), `127/8` (loopback),
/// `169.254/16` (link-local), `224/4`+ (multicast, reserved, broadcast).
/// These are not personal identifiers - RFC 1918 space is reused in every
/// private network, so claiming them in prose is pure false-positive surface.
fn is_reserved_ipv4(s: &str) -> bool {
    let mut octets = [0u8; 4];
    for (part, slot) in s.split('.').zip(octets.iter_mut()) {
        // caller guarantees 0-255 decimal, but stay defensive on parse
        match part.parse::<u8>() {
            Ok(v) => *slot = v,
            Err(_) => return false,
        }
    }
    let [a, b, _, _] = octets;
    matches!(a, 0 | 10 | 127)
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || a >= 224
}

/// IPv6 reserved ranges by first hextet: `fc00::/7` (ULA private),
/// `fe80::/10` (link-local), `ff00::/8` (multicast), and the `::`-leading
/// block (unspecified `::`, loopback `::1`, IPv4-mapped `::ffff:0:0/96`).
fn is_reserved_ipv6(s: &str) -> bool {
    if s.starts_with("::") {
        return true;
    }
    let first = s.split(':').next().unwrap_or("");
    let Some(v) = u16::from_str_radix(first, 16).ok() else {
        return false;
    };
    (v & 0xfe00) == 0xfc00 || (v & 0xffc0) == 0xfe80 || (v & 0xff00) == 0xff00
}

/// Returns `true` for a structurally valid **public** (non-reserved)
/// IP address - the PII-claim gate used by the IP rule.
///
/// Reserved/private ranges (RFC 1918, loopback, link-local, ULA, multicast)
/// are rejected: they identify a network slot, not a person, and the
/// PII-Bench v2 gold set contains only public addresses, so the gate costs
/// no recall there while keeping benign infrastructure prose silent.
///
/// # Examples
/// ```
/// use redactify::valid_public_ip_address;
/// assert!(valid_public_ip_address("8.8.8.8"));
/// assert!(valid_public_ip_address("2606:4700::1111"));
/// assert!(!valid_public_ip_address("10.0.0.5"));   // RFC 1918 private
/// assert!(!valid_public_ip_address("192.168.1.1")); // RFC 1918 private
/// assert!(!valid_public_ip_address("127.0.0.1"));   // loopback
/// assert!(!valid_public_ip_address("::1"));         // loopback
/// assert!(!valid_public_ip_address("fe80::1"));     // link-local
/// ```
#[must_use]
pub fn valid_public_ip_address(ip: &str) -> bool {
    let s = ip.trim();
    if !valid_ip_address(s) {
        return false;
    }
    if s.contains('.') && !s.contains(':') {
        !is_reserved_ipv4(s)
    } else {
        !is_reserved_ipv6(s)
    }
}

/// Returns `true` if `url` is a structurally valid HTTP/HTTPS/FTP URL
/// (scheme + domain with at least one dot + optional port/path/query), or a
/// scheme-less `www.` host. Sentence-final punctuation must already be
/// trimmed by the rule regex; the validator sees the final span text.
///
/// # Examples
/// ```
/// use redactify::valid_url;
/// assert!(valid_url("https://example.com"));
/// assert!(valid_url("http://sub.domain.org/path?q=1"));
/// assert!(valid_url("http://example.com:8080/path")); // port
/// assert!(valid_url("www.example.com/page"));         // scheme-less www
/// assert!(!valid_url("not-a-url"));
/// assert!(!valid_url("http://localhost"));  // no dot in domain
/// ```
#[must_use]
pub fn valid_url(url: &str) -> bool {
    let s = url.trim();
    // scheme:// or scheme-less www. host
    let rest = match s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .or_else(|| s.strip_prefix("ftp://"))
    {
        Some(r) => r,
        None if s.starts_with("www.") => s,
        None => return false,
    };
    // split domain from path
    let mut domain = rest.split(['/', '?', '#']).next().unwrap_or("");
    if domain.is_empty() {
        return false;
    }
    // bracketed IPv6 host: [addr] or [addr]:port (RFC 3986 authority)
    if let Some(inner) = domain.strip_prefix('[') {
        let Some((host, tail)) = inner.split_once(']') else {
            return false;
        };
        let port_ok = tail.is_empty()
            || tail.strip_prefix(':').is_some_and(|p| {
                !p.is_empty() && p.len() <= 5 && p.chars().all(|c| c.is_ascii_digit())
            });
        return port_ok && valid_ip_address(host);
    }
    // optional :port before label validation
    if let Some((host, port)) = domain.rsplit_once(':') {
        if !port.is_empty() && port.len() <= 5 && port.chars().all(|c| c.is_ascii_digit()) {
            domain = host;
        }
    }
    // domain must contain at least one dot and no spaces
    if !domain.contains('.') || domain.contains(' ') {
        return false;
    }
    // each label: alphanumeric + hyphen, not starting/ending with hyphen
    domain.split('.').all(|label| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// Standalone IP-address detection rule (locale-independent, always active).
///
/// Uses `valid_public_ip_address` (not the bare structural check): reserved
/// ranges are rejected so benign prose like "sunucu 10.0.0.5 uzerinden yanit
/// verdi" stays silent (canary-locked in `tests/fpr_budget_gate.rs`).
///
/// A version number is no address: "Sürüm 1.2.3.4 yayımlandı" has the
/// shape of a public IPv4 address. A match right after a version word (`sürüm`,
/// `surum`, `versiyon`, `version`, `ver.`, `v`, `v.`, any case, an optional
/// colon and one whitespace) is dropped by a lookbehind placed AFTER the
/// address. The version word must start a word (the inner `(?<!\w)`):
/// without that check "conversion 85.105.12.34", "Subversion ..." and
/// "inversion ..." would leave a public address in clear. A
/// bare "ver" is not a version word: it is the Turkish imperative "give"
/// ("IP'yi ver 85.105.12.34"). `v1.2.3.4` never matches (no word character
/// right before an address). The lookbehind sits after the address, so
/// it runs only for a matched address, never at every start position: a
/// leading optional version group makes the scan of a 200 000-character
/// line exhaust the backtrack budget (fancy-regex 0.20).
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn ip_rule() -> Rule {
    rule!(
        id = "generic::ip",
        EntityType::IpAddress,
        r"(?<![\w.])(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})(?![\w.])(?<!(?<!\w)(?i:sürüm|surum|versiyon|version|ver\.|v\.?):?\s\S{3,39})",
        Some(valid_public_ip_address),
        ContextPolicy::None,
        0.85
    )
}

/// Spaced IPv6 fragments (`0 a 12 : d3 3 e : ... : 29 af` - the PII-Bench
/// gold shape) are invisible to the contiguous [`ip_rule`] regex. This
/// helper scans a whitespace-collapsed copy of the line for the **strict
/// full 8-group form** and maps matches back to original byte offsets.
///
/// Deliberately narrow (no `::` compression, exactly 8 groups): a time like
/// `12:30:45` is 3 groups and can never match; the validator still applies
/// the public-address gate on the collapsed text.
///
/// Regex runtime errors (e.g. a backtrack limit) are added to `errors`
/// instead of vanishing silently; the engine reports them as an
/// incomplete scan of this line.
pub(crate) fn collapsed_ipv6_spans(line: &str, errors: &mut usize) -> Vec<(usize, usize)> {
    // cheap gates: needs colons, and collapsing only matters with whitespace
    if !line.contains(':') || !line.contains(char::is_whitespace) {
        return Vec::new();
    }
    static COLLAPSED_RE: std::sync::LazyLock<fancy_regex::Regex> = std::sync::LazyLock::new(|| {
        // no left lookbehind on purpose: collapsed prose merges adjacent
        // words into the run ("séance 0 a 12 :" -> "séance0a12:"), and the
        // {1,4}-hex-per-group constraint self-corrects the match start
        fancy_regex::Regex::new(r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])")
            .expect("collapsed ipv6 pattern compiles")
    });
    // collapsed text + per-collapsed-byte original index
    let mut collapsed = String::with_capacity(line.len());
    let mut orig_byte: Vec<usize> = Vec::with_capacity(line.len());
    for (b, ch) in line.char_indices() {
        if ch.is_whitespace() {
            continue;
        }
        collapsed.push(ch);
        orig_byte.resize(orig_byte.len() + ch.len_utf8(), b);
    }
    let mut spans = Vec::new();
    for m in COLLAPSED_RE.find_iter(&collapsed) {
        let Ok(m) = m else {
            *errors += 1;
            continue;
        };
        if !valid_public_ip_address(m.as_str()) {
            continue;
        }
        // collapsed match bytes map 1:1 onto orig_byte
        let start = orig_byte[m.start()];
        let end = orig_byte[m.end() - 1] + 1;
        spans.push((start, end));
    }
    spans
}

/// Standalone URL detection rule (locale-independent, always active).
/// Two recall requirements baked into the pattern (PII-Bench evidence):
/// - sentence-final punctuation must not be consumed: the match is forced to
///   end on a non-punctuation char (otherwise `...standards,` / `...2023.`
///   would be dropped whole by the validator's label check);
/// - scheme-less `www.` hosts are claimable (`www.xbrl.org`-style gold).
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn url_rule() -> Rule {
    rule!(
        id = "generic::url",
        EntityType::Url,
        r#"(?<![\w])(?:(?:https?|ftp)://|www\.)[^\s<>"']*[^\s<>"'.,;:!)]"#,
        Some(valid_url),
        ContextPolicy::None,
        0.85
    )
}

/// The ITU-T E.164 country codes in use, ascending: the keys of
/// libphonenumber's `CountryCodeToRegionCodeMap` (215 codes, geographic
/// and non-geographic such as `800` / `882`), retrieved 2026-11-21 from
/// <https://github.com/google/libphonenumber/blob/master/java/libphonenumber/src/com/google/i18n/phonenumbers/CountryCodeToRegionCodeMap.java>.
/// E.164 country codes are prefix-free (no code is the start of another),
/// so the code of a digit run is the one 1-, 2- or 3-digit prefix found
/// here.
const E164_COUNTRY_CODES: &[u16] = &[
    1, 7, 20, 27, 30, 31, 32, 33, 34, 36, 39, 40, 41, 43, 44, 45, 46, 47, 48, 49, 51, 52, 53, 54,
    55, 56, 57, 58, 60, 61, 62, 63, 64, 65, 66, 81, 82, 84, 86, 90, 91, 92, 93, 94, 95, 98, 211,
    212, 213, 216, 218, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234,
    235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253,
    254, 255, 256, 257, 258, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 290, 291, 297, 298,
    299, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 370, 371, 372, 373, 374, 375, 376, 377,
    378, 380, 381, 382, 383, 385, 386, 387, 389, 420, 421, 423, 500, 501, 502, 503, 504, 505, 506,
    507, 508, 509, 590, 591, 592, 593, 594, 595, 596, 597, 598, 599, 670, 672, 673, 674, 675, 676,
    677, 678, 679, 680, 681, 682, 683, 685, 686, 687, 688, 689, 690, 691, 692, 800, 808, 850, 852,
    853, 855, 856, 870, 878, 880, 881, 882, 883, 886, 888, 960, 961, 962, 963, 964, 965, 966, 967,
    968, 970, 971, 972, 973, 974, 975, 976, 977, 979, 992, 993, 994, 995, 996, 998,
];

/// The E.164 country code that `digits` (ASCII digits only) starts with,
/// if any ([`E164_COUNTRY_CODES`]).
fn e164_country_code(digits: &[u8]) -> Option<u16> {
    let mut code = 0u16;
    for &d in digits.iter().take(3) {
        code = code * 10 + u16::from(d - b'0');
        if E164_COUNTRY_CODES.binary_search(&code).is_ok() {
            return Some(code);
        }
    }
    None
}

/// Returns `true` for an E.164-shaped international phone number:
///
/// - **grouped**: `+CC` prefix + subscriber digits in groups separated by
///   a space, dot or dash (a first group of 1-4 digits as in
///   `+33 1 23 45 67 89`, then groups of 2-4), 10-15 digits in total;
/// - **`+CC NATIONAL`**: the code, a space or hyphen and the national
///   number in one run (`+44 7700900123`); the code must be an assigned
///   E.164 country code (`E164_COUNTRY_CODES`). A dot there is a signed
///   decimal (`+1.4142135623`), not a phone;
/// - **compact**: `+` and 10-15 digits with no separator
///   (`+447700900123`), the form phones, CRMs and `tel:` links store.
///   Without groups nothing marks where the country code ends, so the
///   run must start with an assigned E.164 country code.
///
/// No checksum exists for phone numbers, so the explicit `+` prefix IS the
/// claim signal (PII-Bench gold phones are all `+966/+7/+974`-style; the
/// deterministic canary corpus contains no `+CC` shapes by construction).
/// Country code `90` (TR) is rejected here and grouped `1` (NANP) numbers
/// too - they have dedicated, stricter rules. A compact or `+1 NATIONAL`
/// number is accepted when it is NANP-valid (area and exchange codes
/// start 2-9), because the NANP rule only takes `NPA-NXX-XXXX` with
/// separators.
///
/// # Examples
/// ```
/// use redactify::valid_intl_phone;
/// assert!(valid_intl_phone("+974 4437 9827"));
/// assert!(valid_intl_phone("+966 54 288 7391"));
/// assert!(valid_intl_phone("+7 391 248-7362"));
/// assert!(valid_intl_phone("+447700900123"));      // compact, CC 44
/// assert!(valid_intl_phone("+12125551234"));       // compact NANP
/// assert!(valid_intl_phone("+44 7700900123"));     // +CC NATIONAL
/// assert!(!valid_intl_phone("+28 7700900123"));    // 28: no such code
/// assert!(!valid_intl_phone("+1.4142135623"));     // a signed decimal
/// assert!(!valid_intl_phone("+1 212 555 1234"));   // NANP rule's job
/// assert!(!valid_intl_phone("+90 555 123 45 67")); // TR rule's job
/// assert!(!valid_intl_phone("+12 34 56"));         // too short for E.164
/// assert!(!valid_intl_phone("+2891234567"));       // 28x: no such code
/// assert!(!valid_intl_phone("+11234567890"));      // NANP area code 123
/// ```
#[must_use]
pub fn valid_intl_phone(phone: &str) -> bool {
    let Some(rest) = phone.strip_prefix('+') else {
        return false;
    };
    let digits: Vec<u8> = rest.bytes().filter(u8::is_ascii_digit).collect();
    // E.164: 10..=15 digits total (CC + subscriber)
    if !(10..=15).contains(&digits.len()) {
        return false;
    }
    let mut groups = rest.split([' ', '.', '-']);
    let first = groups.next().unwrap_or_default();
    let code = match groups.count() {
        // compact: the run must start with an assigned country code
        0 => e164_country_code(&digits),
        // `+CC NATIONAL`: the explicit code must be an assigned one
        // (a dot there reads as a signed decimal: `+1.4142135623`)
        1 if !first.starts_with('0') && !rest.contains('.') => first
            .parse::<u16>()
            .ok()
            .filter(|c| E164_COUNTRY_CODES.binary_search(c).is_ok()),
        1 => None,
        // grouped: dedicated stricter rules own these country codes
        _ => return !digits.starts_with(b"1") && !digits.starts_with(b"90"),
    };
    let Some(code) = code else {
        return false;
    };
    let code_len = match code {
        0..=9 => 1,
        10..=99 => 2,
        _ => 3,
    };
    let national = &digits[code_len..];
    match code {
        90 => false,
        // the NANP rule only takes `NPA-NXX-XXXX` with separators
        1 => national.len() == 10 && (b'2'..=b'9').contains(&national[0]) && national[3] >= b'2',
        _ => true,
    }
}

/// International `+CC` phone rule (PII-Bench gap: gold phones are
/// `+966/+7/+974`-style, which the NANP-only EN rule cannot see), grouped
/// or compact (see [`valid_intl_phone`]). Registered AFTER locale phone
/// rules so equal-priority ties keep the locale-specific span.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn intl_phone_rule() -> Rule {
    rule!(
        id = "generic::intl_phone",
        EntityType::Phone,
        r"(?<![\d+])\+(?:\d{1,3}[ .-]\d{1,4}(?:[ .-]\d{2,4}){1,4}|\d{1,3}[ -]\d{6,12}|\d{10,15})(?!\d)",
        Some(valid_intl_phone),
        ContextPolicy::None,
        0.70
    )
}

/// Standalone credit-card validator (13-19 digits, Luhn checksum,
/// space/dash separators tolerated). The `CREDIT_CARD` entity rule applies
/// it plus a number-range length check (a 15-digit number must lie in a
/// range published with 15 digits, and a run of one repeated digit is no
/// card number); exposed for symmetry with the other public `valid_*`
/// validators.
///
/// # Examples
/// ```
/// use redactify::valid_credit_card;
/// assert!(valid_credit_card("4539 1488 0343 6467"));
/// assert!(!valid_credit_card("4539 1488 0343 6468")); // Luhn fails
/// ```
#[must_use]
pub fn valid_credit_card(candidate: &str) -> bool {
    let digits: String = candidate.chars().filter(|c| c.is_ascii_digit()).collect();
    (13..=19).contains(&digits.len()) && valid_luhn(candidate)
}

#[cfg(test)]
mod tests {
    use super::{card_number, valid_luhn};

    #[test]
    fn golden_vectors() {
        assert!(valid_luhn("4111111111111111"));
        assert!(valid_luhn("4111 1111 1111 1111"));
        assert!(valid_luhn("4111-1111-1111-1111"));
        assert!(!valid_luhn("4111111111111112"));
        assert!(!valid_luhn("411111111111"));
        assert!(!valid_luhn(""));
        assert!(!valid_luhn("4111 1111 1111 111x"));
    }

    #[test]
    fn card_lengths_fit_the_number_ranges() {
        for (number, ok) in [
            // 16 digits: any range (Visa, Mastercard 2-series, TROY, JCB)
            ("4111111111111111", true),
            ("2221000000000009", true),
            ("9792000000000003", true),
            ("3528000000000007", true),
            // 15 digits: American Express, UATP, Diners 36, Maestro
            ("378282246310005", true),
            ("371449635398431", true),
            ("100000000000009", true),
            ("361234567890122", true),
            ("670000000000009", true),
            // 13 and 14 digits: any range (Visa, Diners Club, a
            // South African ID number or a SIRET without its pack)
            ("4222222222222", true),
            ("30569309025904", true),
            ("6874256985575", true),
            // 15-digit IMEIs: 35 is JCB only at 16-19 digits, 86 no range
            ("351524205681913", false),
            ("867236052295187", false),
            // 15-digit IMSI (MCC 286) and UUID fragment
            ("286014552090041", false),
            ("716568916055438", false),
            // one repeated digit
            ("0000000000000000", false),
            ("8888888888888888", false),
            ("6666666666666", false),
            ("000000000000000", false),
        ] {
            assert!(valid_luhn(number), "{number}: test vector must pass Luhn");
            assert_eq!(card_number(number), ok, "{number}");
        }
    }

    #[test]
    fn fifteen_digit_ranges_are_well_formed() {
        for &(n, lo, hi) in super::FIFTEEN_DIGIT_CARD_RANGES {
            assert!(lo <= hi);
            assert_eq!(lo.to_string().len(), usize::from(n), "{lo}");
            assert_eq!(hi.to_string().len(), usize::from(n), "{hi}");
        }
    }
}

#[cfg(test)]
mod ip_url_tests {
    use super::{valid_ip_address, valid_public_ip_address, valid_url};
    use crate::{detect, EntityType};

    #[test]
    fn ipv4_valid_and_invalid() {
        assert!(valid_ip_address("192.168.1.1"));
        assert!(valid_ip_address("0.0.0.0"));
        assert!(valid_ip_address("255.255.255.255"));
        assert!(valid_ip_address("10.0.0.1"));
        assert!(!valid_ip_address("256.1.1.1")); // octet > 255
        assert!(!valid_ip_address("192.168.1")); // 3 octets
        assert!(!valid_ip_address("192.168.1.1.1")); // 5 octets
        assert!(!valid_ip_address("192.168.01.1")); // leading zero
        assert!(!valid_ip_address("not.an.ip.address"));
        assert!(!valid_ip_address(""));
    }

    #[test]
    fn ipv6_valid_and_invalid() {
        assert!(valid_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
        assert!(valid_ip_address("::1"));
        assert!(valid_ip_address("::"));
        assert!(valid_ip_address("fe80::1"));
        assert!(!valid_ip_address("2001:db8:::1")); // double ::
        assert!(!valid_ip_address(
            "2001:db8:85a3:0000:0000:8a2e:0370:7334:extra"
        )); // too many
        assert!(!valid_ip_address("gggg::1")); // invalid hex
    }

    #[test]
    fn public_ip_gate_rejects_reserved_ranges() {
        // public (claimable)
        assert!(valid_public_ip_address("8.8.8.8"));
        assert!(valid_public_ip_address("59.140.33.161")); // from PII-Bench gold
        assert!(valid_public_ip_address("2606:4700::1111"));
        assert!(valid_public_ip_address(
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        ));
        // RFC 1918 private
        assert!(!valid_public_ip_address("10.0.0.5"));
        assert!(!valid_public_ip_address("172.16.0.1"));
        assert!(!valid_public_ip_address("172.31.255.254"));
        assert!(!valid_public_ip_address("192.168.1.1"));
        // loopback / link-local / this-net / multicast+reserved
        assert!(!valid_public_ip_address("127.0.0.1"));
        assert!(!valid_public_ip_address("169.254.1.1"));
        assert!(!valid_public_ip_address("0.1.2.3"));
        assert!(!valid_public_ip_address("224.0.0.1"));
        assert!(!valid_public_ip_address("255.255.255.255"));
        // IPv6 reserved: ::-block, ULA, link-local, multicast
        assert!(!valid_public_ip_address("::"));
        assert!(!valid_public_ip_address("::1"));
        assert!(!valid_public_ip_address("::ffff:8.8.8.8"));
        assert!(!valid_public_ip_address("fc00::1"));
        assert!(!valid_public_ip_address("fd12:3456::1"));
        assert!(!valid_public_ip_address("fe80::1"));
        assert!(!valid_public_ip_address("ff02::1"));
        // structurally invalid stays rejected too
        assert!(!valid_public_ip_address("256.1.1.1"));
    }

    #[test]
    fn url_valid_and_invalid() {
        assert!(valid_url("https://example.com"));
        assert!(valid_url("http://sub.domain.org/path?q=1"));
        assert!(valid_url("ftp://files.example.com"));
        assert!(valid_url("http://example.com:8080/path"));
        assert!(valid_url("www.example.com")); // scheme-less www
        assert!(valid_url("www.example.com:8080/path"));
        assert!(!valid_url("not-a-url"));
        assert!(!valid_url("http://localhost")); // no dot
        assert!(!valid_url("http://")); // empty domain
        assert!(!valid_url("://missing-scheme.com"));
        assert!(!valid_url("http://-bad-.com")); // hyphen start/end
        assert!(!valid_url("wwww.example.com")); // not a www. host with scheme
    }

    #[test]
    fn url_trailing_punctuation_not_consumed() {
        // trailing sentence punctuation would make the whole URL fail
        // validation (empty last label), so the regex never consumes it
        for text in [
            "see https://iea.org/energy-efficiency/standards, now",
            "report at https://charitynavigator.org/annual-reports/2023.",
            "docs (https://example.com/page) follow",
            "link www.xbrl.org.",
        ] {
            let ents = detect(text);
            assert!(
                ents.iter().any(|e| e.kind == EntityType::Url),
                "URL should survive sentence punctuation: {text} -> {ents:?}"
            );
        }
        // ...and the span itself must not include the punctuation
        let ents = detect("report at https://example.org/2023.");
        let u = ents
            .iter()
            .find(|e| e.kind == EntityType::Url)
            .expect("url claimed");
        assert!(
            !u.text.ends_with(['.', ',', ';', ':', '!', ')']),
            "{}",
            u.text
        );
    }

    #[test]
    fn url_schemeless_www_detected() {
        let ents = detect("standards are published at www.xbrl.org and www.w3.org");
        let urls: Vec<&str> = ents
            .iter()
            .filter(|e| e.kind == EntityType::Url)
            .map(|e| e.text.as_str())
            .collect();
        assert!(urls.contains(&"www.xbrl.org"), "{ents:?}");
        assert!(urls.contains(&"www.w3.org"), "{ents:?}");
        // a bare domain without scheme/www is still NOT claimed (FP guard)
        let ents = detect("visit example.com sometime");
        assert!(!ents.iter().any(|e| e.kind == EntityType::Url), "{ents:?}");
    }

    #[test]
    fn intl_phone_valid_and_invalid() {
        assert!(super::valid_intl_phone("+974 4437 9827"));
        assert!(super::valid_intl_phone("+966 54 288 7391"));
        assert!(super::valid_intl_phone("+7 391 248-7362"));
        assert!(super::valid_intl_phone("+44 20 7946 0958"));
        assert!(!super::valid_intl_phone("+1 212 555 1234")); // NANP rule's job
        assert!(!super::valid_intl_phone("+90 555 123 45 67")); // TR rule's job
        assert!(!super::valid_intl_phone("+12 34 56")); // below E.164 minimum
        assert!(!super::valid_intl_phone("974 4437 9827")); // no + prefix
    }

    #[test]
    fn intl_phone_detected() {
        // PII-Bench gold shapes
        for (text, span) in [
            ("fax number +974 4437 9827 to send", "+974 4437 9827"),
            ("call +966 54 288 7391 now", "+966 54 288 7391"),
            ("reach us at +7 391 248-7362", "+7 391 248-7362"),
        ] {
            let ents = detect(text);
            assert!(
                ents.iter()
                    .any(|e| e.kind == EntityType::Phone && e.text == span),
                "{text} -> {ents:?}"
            );
        }
        // NANP numbers still claimed by the EN rule with the EN span
        let ents = detect("call +1 212 555 1234 today");
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityType::Phone && e.text.contains("212")),
            "{ents:?}"
        );
        // TR numbers keep their TR-rule span (no INTL double-claim distortion)
        let ents = detect("ara +90 555 123 45 67");
        let phones: Vec<&str> = ents
            .iter()
            .filter(|e| e.kind == EntityType::Phone)
            .map(|e| e.text.as_str())
            .collect();
        assert_eq!(phones.len(), 1, "{ents:?}");
        assert!(phones[0].starts_with("+90"), "{phones:?}");
        // benign digit groups without + stay silent (canary shape)
        let ents = detect("order 1112223334 shipped monday");
        assert!(
            !ents.iter().any(|e| e.kind == EntityType::Phone),
            "{ents:?}"
        );
    }

    #[test]
    fn ip_detected_in_text() {
        let ents = detect("Server 59.140.33.161 is down");
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityType::IpAddress && e.text == "59.140.33.161"),
            "{ents:?}"
        );
        // invalid IP is not claimed
        let ents = detect("ref 256.300.1.1 not an ip");
        assert!(
            !ents.iter().any(|e| e.kind == EntityType::IpAddress),
            "{ents:?}"
        );
        // private IP in benign prose is not claimed (canary-locked)
        let ents = detect("sunucu 10.0.0.5 uzerinden yanit verdi");
        assert!(
            !ents.iter().any(|e| e.kind == EntityType::IpAddress),
            "{ents:?}"
        );
    }

    #[test]
    fn version_numbers_are_not_addresses() {
        for text in [
            "Sürüm 1.2.3.4 yayımlandı, hata düzeltmeleri içeriyor.",
            "SÜRÜM: 4.2.1.15 kuruldu",
            "Version 1.2.3.4 released",
            "ver. 2001:db8:85a3::7334 build",
            "VERSION 1.2.3.4",
            "version: 85.105.12.34",
            "v 85.105.12.34",
            "v1.2.3.4",
        ] {
            assert!(
                !detect(text).iter().any(|e| e.kind == EntityType::IpAddress),
                "{text}"
            );
        }
        // the address next to a version, and an address after other words
        let ents = detect("Sürüm 1.2.3.4, sunucu 8.8.8.8");
        let ips: Vec<&str> = ents
            .iter()
            .filter(|e| e.kind == EntityType::IpAddress)
            .map(|e| e.text.as_str())
            .collect();
        assert_eq!(ips, ["8.8.8.8"]);
    }

    #[test]
    fn a_version_word_must_start_a_word() {
        // "version" inside a longer word is no version
        // label, the address after it is masked
        for text in [
            "conversion 85.105.12.34",
            "IP conversion: 85.105.12.34",
            "Subversion sunucusu 85.105.12.34",
            "SVN (Subversion) 85.105.12.34",
            "inversion 85.105.12.34",
            "aversion 85.105.12.34",
            "IP'yi ver 85.105.12.34",
        ] {
            let ips: Vec<String> = detect(text)
                .into_iter()
                .filter(|e| e.kind == EntityType::IpAddress)
                .map(|e| e.text)
                .collect();
            assert_eq!(ips, ["85.105.12.34"], "{text}");
        }
    }

    #[test]
    fn ip_rule_completes_long_hostile_lines() {
        let rule = super::ip_rule();
        for unit in [
            "1.",
            "sürüm ",
            "version 1.",
            "conversion 1.",
            "v 1.",
            "a:",
            "1 ",
        ] {
            let text = unit.repeat(200_000 / unit.len());
            assert!(rule.regex.find_iter(&text).all(|m| m.is_ok()), "{unit:?}");
        }
    }

    #[test]
    fn spaced_ipv6_fragment_detected() {
        // PII-Bench gold shape: whitespace-scattered full IPv6
        let text = "Votre s\u{e9}ance 0 a 12 : d3 3 e : a 9 b 2 : db 4 a : b2 e 7 : 76 cd : 9 ea c : 29 af pr\u{e9}vue";
        let ents = detect(text);
        let ip = ents
            .iter()
            .find(|e| e.kind == EntityType::IpAddress)
            .expect("spaced ipv6 claimed");
        assert!(ip.text.starts_with("0 a 12"), "{}", ip.text);
        assert!(ip.text.ends_with("29 af"), "{}", ip.text);
        // span offsets must address the ORIGINAL text (spaced form)
        assert_eq!(&text[ip.start..ip.end], ip.text);

        // times / dates / digit soup never reach 8 colon groups
        for benign in [
            "meeting at 12 : 30 : 45 sharp",
            "dates 2024-01-15 and 022-03-15 14 ok",
            "referans 123456789012345 kullanilacak",
        ] {
            assert!(
                !detect(benign)
                    .iter()
                    .any(|e| e.kind == EntityType::IpAddress),
                "{benign:?}"
            );
        }

        // contiguous form still claimed by the normal rule (no dup, exact span)
        let ents = detect("server 2001:0db8:85a3:0000:0000:8a2e:0370:7334 up");
        assert!(
            ents.iter().any(|e| e.kind == EntityType::IpAddress
                && e.text == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            "{ents:?}"
        );
    }

    #[test]
    fn ipv6_multiple_compression_rejected() {
        // splitting the right-hand side of the first `::` on single colons
        // would silently drop an inner `::` and pass `1::2::3`
        use super::valid_ip_address;
        assert!(!valid_ip_address("1::2::3"));
        assert!(!valid_ip_address("1::2::3::4"));
        assert!(!valid_ip_address("::1::"));
        // single compression still valid in all positions
        assert!(valid_ip_address("::"));
        assert!(valid_ip_address("::1"));
        assert!(valid_ip_address("1::"));
        assert!(valid_ip_address("2001:db8::8a2e:370:7334"));
        assert!(valid_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
    }

    #[test]
    fn url_detected_in_text() {
        let ents = detect("Visit https://example.com/page for docs");
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityType::Url && e.text.contains("example.com")),
            "{ents:?}"
        );
    }

    #[test]
    fn ip_and_url_do_not_conflict() {
        let text = "API at http://10.0.0.5:8080/v1 and db 192.168.1.1";
        let ents = detect(text);
        // URL with a private-IP host is still a URL claim (scheme present);
        // the bare private IP next to it stays silent (public-IP gate)
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityType::Url && e.text.starts_with("http://10.0.0.5")),
            "{ents:?}"
        );
        assert!(
            !ents.iter().any(|e| e.kind == EntityType::IpAddress),
            "{ents:?}"
        );
    }
}

#[cfg(test)]
mod email_tests {
    use crate::{detect, EntityType};

    fn emails(text: &str) -> Vec<String> {
        detect(text)
            .into_iter()
            .filter(|e| e.kind == EntityType::Email)
            .map(|e| e.text)
            .collect()
    }

    #[test]
    fn ascii_addresses_keep_matching() {
        assert_eq!(emails("mail ayse@ornek.com.tr."), ["ayse@ornek.com.tr"]);
    }

    #[test]
    fn idn_domain_labels_belong_to_the_address() {
        // RFC 6531 section 3.3: `sub-domain =/ U-label`
        assert_eq!(emails("mail user@bücher.example"), ["user@bücher.example"]);
        assert_eq!(emails("info@örnek.com.tr adresine"), ["info@örnek.com.tr"]);
        assert_eq!(emails("test@例子.com"), ["test@例子.com"]);
        // an A-label (RFC 5890 section 2.3.2.1) top-level domain
        assert_eq!(emails("user@example.xn--p1ai"), ["user@example.xn--p1ai"]);
    }

    #[test]
    fn latin_letters_in_the_local_part_are_not_cut_off() {
        // RFC 6531 section 3.3: `atext =/ UTF8-non-ascii`; the ASCII-only
        // local part would mask `ller@example.com` and leave `mü` visible
        assert_eq!(emails("mail müller@example.com"), ["müller@example.com"]);
        assert_eq!(emails("çağrı@example.com yaz"), ["çağrı@example.com"]);
    }

    #[test]
    fn spaceless_script_neighbours_stay_outside_the_address() {
        // CJK and Thai text has no word spaces: a neighbouring letter of
        // those scripts must not be read as part of the local part or TLD
        assert_eq!(
            emails("\u{6211}\u{7684}\u{90AE}\u{7BB1}\u{662F}test@example.com\u{8C22}\u{8C22}"),
            ["test@example.com"]
        );
        assert_eq!(
            emails("\u{0E2D}\u{0E35}\u{0E40}\u{0E21}\u{0E25}test@example.com\u{0E04}\u{0E23}\u{0E31}\u{0E1A}"),
            ["test@example.com"]
        );
    }

    #[test]
    fn at_signs_without_an_address_stay_silent() {
        for t in ["@ayşe merhaba", "kullanıcı@ adı", "fiyat@iyi değil", "a@b"] {
            assert!(emails(t).is_empty(), "{t}: {:?}", emails(t));
        }
    }
}
