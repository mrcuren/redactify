//! Locale registry: every locale contributes rules; the engine stays generic.
//!
//! Adding a locale = adding a folder (`locales/<iso>/`) with one file per
//! identifier (validator + pattern + cue policy together, no duplication) and
//! registering its rules in [`rules_for_locales`]. Engine, context windows, overlap
//! resolution and redaction are shared and never per-locale.

pub(crate) mod en;
pub(crate) mod generic;
pub(crate) mod tr;

pub(crate) use crate::pii::rule::{ContextPolicy, Rule};

/// Declares a rule together with its lazily compiled pattern.
/// Defined here so every locale submodule sees it via textual scoping.
macro_rules! rule {
    ($kind:expr, $re:expr, $validator:expr, $context:expr, $score:expr) => {{
        static RE: ::std::sync::LazyLock<::fancy_regex::Regex> = ::std::sync::LazyLock::new(|| {
            ::fancy_regex::Regex::new($re).expect("embedded pattern compiles")
        });
        Rule {
            kind: $kind,
            regex: &RE,
            validator: $validator,
            context: $context,
            score: $score,
        }
    }};
}
pub(crate) use rule;

/// All active rules, in a deterministic order. Order matters: with equal
/// priority and equal length, the rule listed first wins (see `EntityType::priority`).
/// Returns rules filtered by locale. Generic rules are always included.
/// `locales` is a slice of ISO codes like `["tr"]` or `["tr", "en"]`.
pub(crate) fn rules_for_locales(locales: &[&str]) -> Vec<Rule> {
    let mut rules = Vec::new();
    // generic rules are always included
    rules.push(generic::card_rule());
    rules.push(generic::email_rule());
    if locales.contains(&"tr") {
        rules.push(tr::tckn::rule());
        rules.push(tr::iban::rule());
        rules.push(tr::plaka::rule());
        rules.push(tr::vkn::rule());
        rules.push(tr::phone::rule());
        rules.push(tr::passport::rule());
    }
    if locales.contains(&"en") {
        // ITIN before SSN: narrower rule wins on shape overlap
        rules.push(en::itin::rule());
        rules.push(en::itin::bare_rule());
        rules.push(en::ssn::rule());
        rules.push(en::us_passport::rule());
    }
    rules
}
