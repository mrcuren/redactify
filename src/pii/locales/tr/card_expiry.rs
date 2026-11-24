//! Card expiry date: `AA/YY` + mandatory card-expiry cue.
//!
//! Format only (cue required): a two-digit month and a two-digit year
//! (`MM/YY`) without a checksum. Only that form is accepted (month 01-12,
//! optional single spaces around the slash), so a best-before date
//! written with a 4-digit year or a day stays out. The rule needs a cue
//! (`Son kullanma tarihi`, `SKT`, `expiry`, `valid thru`).

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, token_rest, ContextPolicy, Rule};

/// Card-expiry cues (normalized: lowercase, `ı -> i`).
pub(super) const CUES: &[&str] = &[
    "son kullanma",
    "son kul.",
    "skt",
    "s.k.t",
    "expiry",
    "expiration",
    "exp date",
    "exp:",
    "exp.",
    "valid thru",
    "valid through",
];

/// `MM/YY` with month 01-12: two 2-digit runs around the slash.
fn valid_expiry(s: &str) -> bool {
    let Some((month, year)) = s.split_once('/') else {
        return false;
    };
    let (month, year) = (month.trim_end_matches(' '), year.trim_start_matches(' '));
    let two = |p: &str| p.len() == 2 && p.bytes().all(|b| b.is_ascii_digit());
    two(month) && two(year) && matches!(month.as_bytes(), [b'0', b'1'..=b'9'] | [b'1', b'0'..=b'2'])
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    // the whole token around the slash pair (leftmost-first + greedy), with
    // the digit groups written next to it after single spaces, shape checked
    // by the validator: `MM/YY` inside a longer number (`tel 0532 12/27 34
    // 56`), a full date (`12/27/2025`), an e-mail or a URL path comes with
    // its other digits or letters and is rejected, so it is never claimed
    // on its own. Cost: none of the 37 card expiries of the nm-kvkk test
    // split and the third-party fixtures has a digit group or a token
    // character next to it; an unlabelled dump line
    // (`4111111111111111 12/27 123`) loses its expiry. No boundary
    // assertion (cost note in `super::address`).
    rule!(
        EntityType::CardExpiry,
        concat!(
            token_rest!(),
            r"(?:[0-9]+ )*[0-9]+ ?/ ?[0-9]+(?: [0-9]+)*",
            token_rest!()
        ),
        Some(valid_expiry),
        ContextPolicy::RequiredCue(CUES),
        0.85
    )
}

#[cfg(test)]
mod tests {
    use crate::pii::entity::EntityType;

    fn expiries(text: &str) -> Vec<String> {
        crate::pii::detect::engine_detect(text, &["tr"])
            .into_iter()
            .filter(|e| e.kind == EntityType::CardExpiry)
            .map(|e| e.text)
            .collect()
    }

    #[test]
    fn expiry_needs_its_cue_and_the_short_form() {
        assert_eq!(expiries("Son Kullanma Tarihi: 06/27\n"), vec!["06/27"]);
        assert_eq!(expiries("son kullanma tarihi 12/27'dir."), vec!["12/27"]);
        assert_eq!(expiries("Exp: 01 / 30"), vec!["01 / 30"]);
        assert_eq!(expiries("SKT: 06/27, CVV: 123"), vec!["06/27"]);
        assert_eq!(expiries("expiry=06/27 ok"), vec!["06/27"]);
        for text in [
            "Son kullanma tarihi: 05/2026",
            "Son kullanma tarihi: 13/27",
            "Oran 12/27 olarak hesaplandı.",
            "Karar 2023/45 sayılı",
            // inside a longer number, a full date, an e-mail, a URL path
            "SKT: tel 0532 12/27 34 56",
            "Son kullanma: 12/27/2025",
            "SKT ali12/27@x.com",
            "SKT https://x.com/p/12/27/ozet",
        ] {
            assert!(expiries(text).is_empty(), "{text}: {:?}", expiries(text));
        }
    }
}
