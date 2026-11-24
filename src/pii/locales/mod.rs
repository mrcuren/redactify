//! Locale registry: every locale contributes rules; the engine stays generic.
//!
//! Adding a locale = adding a folder (`locales/<iso>/`) with one file per
//! identifier (validator + pattern + cue policy together, no duplication) and
//! registering its rules in [`rules_for_locales`]. Engine, context windows, overlap
//! resolution and redaction are shared and never per-locale.

pub(crate) mod au;
pub(crate) mod br;
pub(crate) mod ca;
pub(crate) mod cn;
pub(crate) mod crypto;
pub(crate) mod de;
pub(crate) mod dk;
pub(crate) mod en;
pub(crate) mod es;
pub(crate) mod eu;
pub(crate) mod fi;
pub(crate) mod fr;
pub(crate) mod generic;
pub(crate) mod iban;
pub(crate) mod imei;
pub(crate) mod in_;
pub(crate) mod it;
pub(crate) mod kr;
pub(crate) mod ng;
pub(crate) mod nl;
pub(crate) mod no;
pub(crate) mod ph;
pub(crate) mod pl;
pub(crate) mod pt;
pub(crate) mod se;
pub(crate) mod sg;
pub(crate) mod swift;
pub(crate) mod th;
pub(crate) mod tr;
pub(crate) mod uk;
pub(crate) mod vin;
pub(crate) mod za;

pub(crate) use crate::pii::rule::{ContextPolicy, Rule};

use crate::pii::entity::EntityType;

/// A built-in detector that is not one regex: it scans a whole line and
/// appends `(start, end, score)` byte spans (offsets into the line) of
/// its entity kind. Line scoped like every rule, so the engine runs it
/// beside the rules of [`rules_for_locales`] and the stream guard's
/// line-completion semantics hold unchanged.
pub(crate) struct LineScanner {
    /// Stable id reported by explanations (`"tr::person"`).
    pub id: &'static str,
    /// Entity type of every span the scanner reports.
    pub kind: EntityType,
    /// Appends the spans found on one line.
    pub scan: fn(&str, &mut Vec<(usize, usize, f32)>),
}

/// The line scanners of the selected locales (see [`LineScanner`]); empty
/// for packs that have none.
pub(crate) fn line_scanners_for_locales(locales: &[&str]) -> Vec<LineScanner> {
    let mut scanners = Vec::new();
    if locales.contains(&"tr") {
        scanners.push(tr::person::scanner());
        // KVKK art. 6 special categories: one scanner per category (a
        // scanner reports one entity type); they share one analysis per
        // line through a per-thread memo (`tr::special`)
        scanners.extend(tr::special::scanners());
    }
    scanners
}

/// Gregorian leap-year rule (shared by the birth-date validators of the
/// cn, se, fi and dk packs, whose century is known).
pub(crate) const fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Number of days in `month` (1-12) of a year with the given leap flag;
/// `0` for a month outside 1-12, so `day <= days_in_month(..)` with
/// `day >= 1` is a complete calendar-date check.
pub(crate) const fn days_in_month(month: u32, leap: bool) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    }
}

/// Leap-year test for a two-digit year whose century the identifier does
/// not fix (se separator form, no): `true` when the year is a leap year in
/// at least one century, so 29 February is accepted whenever some century
/// allows it (recall-first). For `yy` in 0-99 that is `yy % 4 == 0` (`00`
/// is a leap year in 2000).
pub(crate) const fn is_leap_two_digit_year(yy: u32) -> bool {
    yy % 4 == 0
}

/// Two ASCII digits as a number (callers check `is_ascii_digit` first).
pub(crate) fn two_digits(b: &[u8]) -> u32 {
    u32::from(b[0] - b'0') * 10 + u32::from(b[1] - b'0')
}

/// Luhn (mod 10) check over ASCII digits: from the right, every second
/// digit is doubled (minus 9 when the product exceeds 9) and the sum must
/// be a multiple of 10. No length gate: each validator enforces its own
/// length (the public card check `valid_luhn` requires at least 13
/// digits). Every byte must be an ASCII digit (callers check first).
pub(crate) fn luhn_valid(digits: &[u8]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &c)| {
            let d = u32::from(c - b'0');
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 {
                    x - 9
                } else {
                    x
                }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

/// Collects the identifier characters of `s` (the bytes `keep` accepts)
/// into exactly `N` slots, skipping the separator bytes listed in `skip`.
/// `None` for any other byte (multi-byte characters included), for more
/// than `N` identifier characters, or for fewer.
pub(crate) fn code_chars<const N: usize>(
    s: &str,
    keep: fn(&u8) -> bool,
    skip: &[u8],
) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    let mut n = 0usize;
    for b in s.bytes() {
        if keep(&b) {
            *out.get_mut(n)? = b;
            n += 1;
        } else if !skip.contains(&b) {
            return None;
        }
    }
    (n == N).then_some(out)
}

/// Declares a rule together with its lazily compiled pattern.
/// Defined here so every locale submodule sees it via textual scoping.
///
/// The rule id is the invoking module's path below this registry
/// (`tr::tckn`); a module that declares several rules names each one
/// explicitly with the `id = "..."` form (`generic::email`). Every pattern
/// is compiled with the explicit backtrack budget
/// `crate::pii::rule::BACKTRACK_LIMIT` (equal to the engine default).
macro_rules! rule {
    (id = $id:expr, $kind:expr, $re:expr, $validator:expr, $context:expr, $score:expr) => {{
        static RE: ::std::sync::LazyLock<::fancy_regex::Regex> = ::std::sync::LazyLock::new(|| {
            ::fancy_regex::RegexBuilder::new($re)
                .backtrack_limit($crate::pii::rule::BACKTRACK_LIMIT)
                .build()
                .expect("embedded pattern compiles")
        });
        Rule {
            id: $id,
            kind: $kind,
            regex: &RE,
            validator: $validator,
            context: $context,
            score: $score,
        }
    }};
    ($kind:expr, $re:expr, $validator:expr, $context:expr, $score:expr) => {
        rule!(
            id = $crate::pii::rule::rule_id(module_path!()),
            $kind,
            $re,
            $validator,
            $context,
            $score
        )
    };
}
pub(crate) use rule;

/// The rest of a token around a value, for `concat!` in a rule pattern:
/// any run of characters other than whitespace and the delimiters
/// `,;:.!?()[]{}<>"'’=`. A rule that brackets its value with it claims the
/// whole token, so digits inside an e-mail address, a URL or an
/// alphanumeric identifier come with their letters and fail the
/// validator. No boundary assertion, so the pattern needs no lookaround
/// (cost note in `tr::address`).
macro_rules! token_rest {
    () => {
        r#"[^\s,;:.!?()\[\]{}<>"'’=]*"#
    };
}
pub(crate) use token_rest;

/// Every locale pack code the detector understands (lowercase, ASCII). Any
/// other code selects no pack, so callers that take codes from users should
/// check them against this list.
///
/// # Examples
/// ```
/// assert!(redactify::SUPPORTED_LOCALES.contains(&"tr"));
/// assert!(!redactify::SUPPORTED_LOCALES.contains(&"TR"));
/// ```
pub const SUPPORTED_LOCALES: &[&str] = &[
    "tr", "en", "de", "uk", "fr", "es", "it", "nl", "pl", "pt", "ca", "au", "sg", "in", "br", "cn",
    "se", "fi", "no", "dk", "eu", "kr", "ng", "ph", "za", "th",
];

/// Returns the rules of the given locale packs plus the always-on generic
/// rules, in a deterministic order: with equal priority and equal length,
/// the rule listed first wins (see `EntityType::priority`). Each rule is
/// registered once. `locales` is a slice of codes like `["tr"]` or
/// `["tr", "en"]`.
pub(crate) fn rules_for_locales(locales: &[&str]) -> Vec<Rule> {
    // generic rules are always included; the international IBAN rule first
    // (priority 0: it outranks every other candidate on overlap)
    let mut rules = vec![
        iban::rule(),
        vin::rule(),
        vin::cued_rule(),
        generic::card_rule(),
        generic::email_rule(),
        generic::ip_rule(),
        generic::url_rule(),
        swift::rule(),
        crypto::base58_rule(),
        crypto::bech32_rule(),
        crypto::eth_rule(),
    ];
    if locales.contains(&"tr") {
        rules.push(tr::tckn::rule());
        rules.push(tr::tckn::thousands_rule());
        rules.push(tr::iban::rule());
        rules.push(tr::plaka::rule());
        rules.push(tr::plaka::compact_rule());
        rules.push(tr::vkn::rule());
        rules.push(tr::phone::rule());
        rules.push(tr::phone::landline_rule());
        rules.push(tr::phone::intl_mobile_rule());
        rules.push(tr::phone::intl_landline_rule());
        rules.push(tr::phone::intl_landline_paren_rule());
        rules.push(tr::phone::paren_rule());
        rules.push(tr::phone::local_rule());
        rules.push(tr::phone::bare_rule());
        rules.push(tr::passport::rule());
        rules.push(tr::name::rule());
        tr::push_record_rules(&mut rules);
    }
    if locales.contains(&"en") {
        // ITIN before SSN: narrower rule wins on shape overlap
        rules.push(en::itin::rule());
        rules.push(en::itin::bare_rule());
        rules.push(en::ssn::rule());
        // bare SSN after the bare ITIN: an ITIN-range run keeps its label
        rules.push(en::ssn::bare_rule());
        rules.push(en::us_passport::rule());
        rules.push(en::mrn::rule());
        rules.push(en::zip::rule());
        // cue-gated, mutually disjoint shapes (9 digits / 10 digits /
        // 11 alphanumerics / XX-XXXXXXX): the order only fixes ties
        rules.push(en::aba_routing::rule());
        rules.push(en::npi::rule());
        rules.push(en::mbi::rule());
        rules.push(en::ein::rule());
        rules.push(en::phone::phone_rule());
        rules.push(en::name::rule());
    }
    // European packs (opt-in locales)
    if locales.contains(&"fr") {
        rules.push(fr::nir::rule());
        rules.push(fr::siret::rule());
        rules.push(fr::postal::rule());
        rules.push(fr::phone::rule());
    }
    if locales.contains(&"es") {
        rules.push(es::dni::rule());
        rules.push(es::nie::rule());
        rules.push(es::phone::rule());
    }
    if locales.contains(&"nl") {
        rules.push(nl::bsn::rule());
        rules.push(nl::phone::rule());
    }
    if locales.contains(&"uk") {
        rules.push(uk::nino::rule());
        rules.push(uk::nhs::rule());
        rules.push(uk::passport::rule());
        rules.push(uk::utr::rule());
        rules.push(uk::vat::rule());
        rules.push(uk::phone::rule());
        rules.push(uk::postcode::rule());
        rules.push(uk::driving_licence::rule());
        // three registration styles, mutually disjoint shapes
        rules.push(uk::vehicle_reg::rule());
        rules.push(uk::vehicle_reg::prefix_rule());
        rules.push(uk::vehicle_reg::suffix_rule());
    }
    if locales.contains(&"de") {
        rules.push(de::tax_id::rule());
        rules.push(de::tax_number::rule());
        rules.push(de::tax_number::printed_rule());
        rules.push(de::kvnr::rule());
        rules.push(de::rvnr::rule());
        // LANR (checksum) before BSNR (format only): same 9-digit shape,
        // the checksummed claim keeps an equal-priority, equal-span tie
        rules.push(de::lanr::rule());
        rules.push(de::bsnr::rule());
        rules.push(de::id_card::rule());
        rules.push(de::passport::rule());
        rules.push(de::kfz::rule());
        rules.push(de::phone::rule());
        rules.push(de::plz::rule());
    }
    if locales.contains(&"it") {
        rules.push(it::fiscal_code::rule());
        rules.push(it::numeric_fiscal_code::rule());
        rules.push(it::passport::rule());
        rules.push(it::phone::rule());
    }
    // national-ID packs (opt-in locales)
    if locales.contains(&"pl") {
        rules.push(pl::pesel::rule());
        rules.push(pl::nip::rule());
        rules.push(pl::phone::phone_rule());
    }
    if locales.contains(&"ca") {
        rules.push(ca::sin::rule());
        rules.push(ca::postal_code::rule());
        // Canada shares NANP with the US: the en phone rule covers it (once,
        // when the `en` pack has not registered it already)
        if !locales.contains(&"en") {
            rules.push(en::phone::phone_rule());
        }
    }
    if locales.contains(&"au") {
        rules.push(au::tfn::rule());
        rules.push(au::medicare::rule());
        rules.push(au::abn::rule());
        // after the TFN: same 9-digit shape, disjoint cue sets; a run
        // carrying both cues and passing both checks keeps the TFN label
        rules.push(au::acn::rule());
        rules.push(au::phone::phone_rule());
    }
    if locales.contains(&"sg") {
        rules.push(sg::nric_fin::rule());
        rules.push(sg::uen::rule());
        rules.push(sg::phone::phone_rule());
    }
    if locales.contains(&"in") {
        // PAN first: both are cue-gated with distinct shapes, the order
        // only fixes the (unreachable) same-tier tie semantics
        rules.push(in_::pan::rule());
        rules.push(in_::aadhaar::rule());
        // GSTIN: its 15-character shape overlaps no other rule
        rules.push(in_::gstin::rule());
        rules.push(in_::phone::phone_rule());
    }
    if locales.contains(&"pt") {
        rules.push(pt::nif::rule());
        rules.push(pt::phone::rule());
    }
    // further national-ID packs (opt-in locales). Within a pack the
    // formatted (narrower) rule precedes the bare (broader) one.
    if locales.contains(&"br") {
        rules.push(br::cpf::rule());
        rules.push(br::cpf::bare_rule());
        rules.push(br::cnpj::rule());
        rules.push(br::cnpj::bare_rule());
    }
    if locales.contains(&"cn") {
        rules.push(cn::resident_id::rule());
    }
    // dk BEFORE se: a cue-gated CPR number keeps its label when the same
    // span also passes the Swedish check (equal tier, equal span)
    if locales.contains(&"dk") {
        rules.push(dk::cpr::rule());
    }
    if locales.contains(&"se") {
        rules.push(se::personnummer::rule());
        rules.push(se::personnummer::bare_rule());
        rules.push(se::organisationsnummer::rule());
    }
    if locales.contains(&"fi") {
        rules.push(fi::hetu::rule());
    }
    if locales.contains(&"no") {
        rules.push(no::fodselsnummer::rule());
    }
    // kr and th BEFORE za: their cue-gated 13-digit rules share tier 0
    // and the shape with the cue-less ZA identity number, so a cued
    // Korean/Thai number keeps its label on an equal-span tie
    if locales.contains(&"kr") {
        rules.push(kr::rrn::rule());
        rules.push(kr::frn::rule());
        rules.push(kr::brn::rule());
        rules.push(kr::passport::rule());
    }
    if locales.contains(&"th") {
        rules.push(th::tnin::rule());
    }
    if locales.contains(&"ng") {
        rules.push(ng::nin::rule());
    }
    // formatted (narrower) TIN before the bare nine digits
    if locales.contains(&"ph") {
        rules.push(ph::tin::rule());
        rules.push(ph::tin::bare_rule());
    }
    if locales.contains(&"za") {
        rules.push(za::id_number::rule());
        rules.push(za::tax_reference::rule());
        rules.push(za::vat::rule());
        rules.push(za::company_registration::rule());
        rules.push(za::phone::phone_rule());
    }
    // the EU VAT format rule AFTER every national pack: a national rule
    // with a checksum keeps an equal-priority, equal-span tie
    if locales.contains(&"eu") {
        rules.push(eu::vat::rule());
    }
    // IMEI (tier 0) outranks the card rule (tier 1) by priority. It is
    // registered after the national packs: a 15-digit French NIR (tier 0)
    // can also pass the IMEI checks, and an equal-priority, equal-span tie
    // goes to the rule listed first, so the national identifier keeps it
    rules.push(imei::rule());
    rules.push(imei::cued_rule());
    // international +CC phones LAST: NANP/TR phone rules claim their formats
    // first (equal priority + equal span -> insertion order wins), this rule
    // only rescues the rest of the world
    rules.push(generic::intl_phone_rule());
    rules
}

#[cfg(test)]
mod ca_phone_tests {
    use super::{
        code_chars, days_in_month, is_leap_two_digit_year, is_leap_year, luhn_valid, two_digits,
    };
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn luhn_helper_table() {
        // (digits, Luhn-valid): card, SIN and SIRET vectors, short runs (no
        // length gate here), single digits and all-zero runs
        for (digits, ok) in [
            ("4111111111111111", true),
            ("4111111111111112", false),
            ("4539148803436467", true),
            ("123456782", true),
            ("123456783", false),
            ("12345678200002", true),
            ("12345678200001", false),
            ("6408233234", true),
            ("6408233235", false),
            ("18", true),
            ("19", false),
            ("0", true),
            ("5", false),
            ("", true),
            ("000000000000", true),
        ] {
            assert_eq!(luhn_valid(digits.as_bytes()), ok, "{digits}");
        }
    }

    #[test]
    fn code_char_collection_table() {
        let digit = u8::is_ascii_digit;
        assert_eq!(code_chars::<3>("1-2.3", digit, b".-"), Some(*b"123"));
        assert_eq!(code_chars::<3>("--123--", digit, b"-"), Some(*b"123"));
        assert_eq!(code_chars::<3>("12", digit, b"-"), None); // too few
        assert_eq!(code_chars::<3>("1234", digit, b"-"), None); // too many
        assert_eq!(code_chars::<3>("1 23", digit, b"-"), None); // unlisted separator
        assert_eq!(code_chars::<3>("12\u{0663}", digit, b"-"), None); // non-ASCII digit
        assert_eq!(code_chars::<0>("", digit, b"-"), Some([]));
        assert_eq!(code_chars::<0>("-", digit, b"-"), Some([]));
        let code = |b: &u8| b.is_ascii_digit() || b.is_ascii_uppercase();
        assert_eq!(code_chars::<4>("1A/B-2", code, b"/-"), Some(*b"1AB2"));
        assert_eq!(code_chars::<4>("1a/B-2", code, b"/-"), None); // lowercase
    }

    #[test]
    fn two_digit_leap_year_means_leap_in_some_century() {
        for yy in 0..100 {
            let some_century = [1800, 1900, 2000].iter().any(|c| is_leap_year(c + yy));
            assert_eq!(is_leap_two_digit_year(yy), some_century, "{yy:02}");
        }
    }

    #[test]
    fn ca_phone_uses_nanp() {
        // Canada shares NANP: the en phone rule detects CA numbers
        let ents = engine_detect("call (416) 555-0142", &["ca"]);
        assert!(ents.iter().any(|e| e.kind == EntityType::Phone), "{ents:?}");
    }

    #[test]
    fn every_rule_is_registered_once() {
        let rules = super::rules_for_locales(super::SUPPORTED_LOCALES);
        let mut ids: Vec<&str> = rules.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        let total = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), total, "a rule id is registered twice");
        assert_eq!(total, 132, "the README and crates-io.md state this count");
    }

    #[test]
    fn calendar_helpers() {
        assert!(is_leap_year(2000) && is_leap_year(1964) && is_leap_year(2024));
        assert!(!is_leap_year(1900) && !is_leap_year(2100) && !is_leap_year(2023));
        assert_eq!(days_in_month(2, true), 29);
        assert_eq!(days_in_month(2, false), 28);
        assert_eq!(days_in_month(4, false), 30);
        assert_eq!(days_in_month(12, false), 31);
        assert_eq!(days_in_month(0, true), 0);
        assert_eq!(days_in_month(13, true), 0);
        assert_eq!(two_digits(b"07"), 7);
        assert_eq!(two_digits(b"99"), 99);
    }

    #[test]
    fn rule_ids_name_one_pattern_each() {
        // every pack on; `ca` registers the `en` phone rule itself, so a
        // repeated id is fine only when it is the same pattern
        let mut seen = std::collections::HashMap::new();
        for rule in super::rules_for_locales(super::SUPPORTED_LOCALES) {
            let pattern = rule.regex.as_str();
            if let Some(prev) = seen.insert(rule.id, pattern) {
                assert_eq!(prev, pattern, "rule id {} names two patterns", rule.id);
            }
        }
    }

    #[test]
    fn supported_locales_match_the_registry() {
        use super::{rules_for_locales, SUPPORTED_LOCALES};
        // each listed code selects its own pack; an unknown or miscased code
        // selects nothing beyond the always-on generic rules
        let generic = rules_for_locales(&[]).len();
        for code in SUPPORTED_LOCALES {
            assert!(
                rules_for_locales(&[code]).len() > generic,
                "{code} selects no pack"
            );
        }
        assert_eq!(rules_for_locales(&["TR", "xx"]).len(), generic);
    }
}
