//! SGK registration number (sigortalı / işyeri sicil numarası): digits +
//! mandatory SGK cue.
//!
//! Format only (cue required). The Social Security Institution (SGK) has
//! no published check-digit algorithm, and the sources on its numbers
//! disagree: the 26-digit workplace number (işyeri sicil numarası) is
//! described with different field layouts by different secondary sources
//! (for example <https://www.alomaliye.com/2017/05/31/sgk-nakil-giris-cikislar/>,
//! retrieved 2026-11-23), and an insured person's number has been the
//! TCKN for current registrations. The rule therefore accepts an 8-13
//! digit run (13 digits is the length of every SGK value in the
//! `nm-kvkk-pii-6K` train and test splits; third-party fixtures also
//! label cued 8 and 10 digit values, `SSK no 12345678`) or a 26-digit run next to an SGK cue (`SGK sicil no`, `SSK`,
//! `Bağ-Kur`, `sosyal güvenlik`). A run that is also a valid TCKN is left
//! to the TCKN rule (the validator rejects it), so it keeps the TCKN
//! label.
//!
//! Boundaries and overlap tier. SGK shares the top overlap tier with
//! MERSİS (`EntityType::priority`): a cued 13-digit value passes Luhn about
//! one time in ten, and the cue-less card rule must not relabel it. A
//! top-tier span wins every overlap, so it must never be a fragment of a
//! larger entity. Two measures keep it whole:
//!
//! - the pattern takes the whole token around the digits (letters, `@`,
//!   `/`, `-`, `_` included; whitespace, sentence punctuation and the `=`
//!   of a `key=value` pair end it)
//!   and the validator wants digits only, so a run inside an e-mail local
//!   part (`ali1234567890123@firma.com`), a URL path or an alphanumeric
//!   token is never a candidate (`SGK: ali12345678@firma.com` must not
//!   become `SGK: ali[SGK]@firma.com`);
//! - an 8-12 digit token can be the subscriber part of a written phone
//!   number (`+90 5321234567`): an SGK candidate strictly inside a phone
//!   candidate is dropped before overlap resolution
//!   (`detect::sgk_yields_to_phone`), so the whole phone is masked. A
//!   number no phone rule claims (`+90 212 12345678`, an 8-digit
//!   subscriber part) keeps its cued eight digits masked as SGK.

use crate::pii::entity::EntityType;

use super::tckn::valid_tckn;
use crate::pii::locales::{rule, token_rest, ContextPolicy, Rule};

/// SGK cues (normalized: lowercase, `ı -> i`).
pub(super) const CUES: &[&str] = &[
    "sgk",
    "ssk",
    "sosyal güvenlik",
    "sosyal guvenlik",
    "sigorta sicil",
    "bağ-kur",
    "bag-kur",
    "bağkur",
    "bagkur",
];

/// A token of 8-13 or 26 ASCII digits that is not a valid TCKN.
fn valid_sgk(s: &str) -> bool {
    matches!(s.len(), 8..=13 | 26) && s.bytes().all(|b| b.is_ascii_digit()) && !valid_tckn(s)
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Sgk,
        // the whole token around the digits (leftmost-first + greedy): a run
        // inside an e-mail, a URL or an alphanumeric token comes with its
        // letters and fails the validator, so it is never claimed on its own;
        // no boundary assertion (cost note in `super::address`)
        concat!(token_rest!(), r"[0-9]{8,}", token_rest!()),
        Some(valid_sgk),
        ContextPolicy::RequiredCue(CUES),
        0.85
    )
}

#[cfg(test)]
mod tests {
    use crate::pii::entity::EntityType;

    fn found(text: &str) -> Vec<(EntityType, String)> {
        crate::pii::detect::engine_detect(text, &["tr"])
            .into_iter()
            .map(|e| (e.kind, e.text))
            .collect()
    }

    #[test]
    fn sgk_number_needs_its_cue_and_outranks_the_card_rule() {
        // 4111111111119 is a Luhn-valid 13-digit run: cued, it is an SGK
        // number (the card rule's candidate loses the overlap)
        assert_eq!(
            found("SGK Sicil No: 4111111111119\n"),
            vec![(EntityType::Sgk, "4111111111119".to_owned())]
        );
        assert_eq!(
            found("SGK Sicil Numarası: 9572017271586"),
            vec![(EntityType::Sgk, "9572017271586".to_owned())]
        );
        assert_eq!(
            found("işyeri SGK sicil no 12345678901234567890123456"),
            vec![(EntityType::Sgk, "12345678901234567890123456".to_owned())]
        );
        assert!(found("Kayıt No: 9572017271586").is_empty());
        // cued 8-12 digit values
        for (text, value) in [
            ("SGK sicil no 1234567890", "1234567890"),
            ("SSK no 12345678", "12345678"),
            ("Bağ-Kur no 22334455", "22334455"),
        ] {
            assert_eq!(
                found(text),
                vec![(EntityType::Sgk, value.to_owned())],
                "{text}"
            );
        }
        // 7 digits and 14-25 digits are not SGK numbers
        for text in ["SSK no 1234567", "SGK no 12345678901234"] {
            assert!(
                !found(text).iter().any(|(k, _)| *k == EntityType::Sgk),
                "{text}: {:?}",
                found(text)
            );
        }
        // a valid TCKN keeps the TCKN label
        assert_eq!(
            found("SGK sicil no: 10000000146"),
            vec![(EntityType::Tckn, "10000000146".to_owned())]
        );
    }

    #[test]
    fn sgk_never_takes_digits_out_of_an_email_a_url_or_a_detected_phone() {
        for (text, kind, whole) in [
            (
                "SGK: ali1234567890123@firma.com",
                EntityType::Email,
                "ali1234567890123@firma.com",
            ),
            (
                "SGK: ali12345678@firma.com",
                EntityType::Email,
                "ali12345678@firma.com",
            ),
            (
                "SGK https://ornek.com/u/1234567890123?ad=ahmet",
                EntityType::Url,
                "https://ornek.com/u/1234567890123?ad=ahmet",
            ),
            // the cued 10-digit token is the subscriber part of the phone:
            // the phone strictly contains it and takes the whole number
            (
                "SGK birimi +90 5321234567",
                EntityType::Phone,
                "+90 5321234567",
            ),
            (
                "SGK birimi (0532) 123 45 67",
                EntityType::Phone,
                "(0532) 123 45 67",
            ),
        ] {
            assert_eq!(found(text), vec![(kind, whole.to_owned())], "{text}");
        }
        // no phone rule claims an 8-digit subscriber part: the cued digits
        // stay masked as SGK
        assert_eq!(
            found("SGK iletişim +90 212 12345678"),
            vec![(EntityType::Sgk, "12345678".to_owned())]
        );
        // digits glued to letters are not SGK numbers
        for text in ["SGK no: A9572017271586", "SGK no: 9572017271586x"] {
            assert!(
                !found(text).iter().any(|(k, _)| *k == EntityType::Sgk),
                "{text}: {:?}",
                found(text)
            );
        }
        // sentence punctuation and a `key=value` separator end the token
        assert_eq!(
            found("SGK sicil numarası 9572017271586."),
            vec![(EntityType::Sgk, "9572017271586".to_owned())]
        );
        assert_eq!(
            found("sgk_no=9572017271586 durum=aktif"),
            vec![(EntityType::Sgk, "9572017271586".to_owned())]
        );
    }
}
