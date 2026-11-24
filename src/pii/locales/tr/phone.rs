//! Turkish phone numbers: detection rules (structural patterns, no checksum).
//!
//! Supported shapes (separators: space, `-` or `.`):
//! - mobile `5xx` with a trunk `0` (`05321234567`, `0532 123 45 67`,
//!   `0(532) 123 45 67`) or a country code `+90` / `0090` / `90`
//!   (`+90 532 123 45 67`, `+905321234567`, `0090 532 123 45 67`);
//! - landline `2xx/3xx/4xx` and the non-geographic `0850` / `0800` with a
//!   trunk `0` or a country code and a mandatory separator after the code
//!   (`0212 555 44 33`, `0850 222 33 44`, `+90 212 555 44 33`,
//!   `+90 (212) 555 44 33`);
//! - the trunk `0` inside parentheses (`(0212) 555 12 34`, `(0532) 123 45 67`);
//! - a prefix-less mobile grouped `3-3-2-2` (`532 123 45 67`,
//!   `532.123.45.67`) or `(532) 123 45 67` with a `2-2` tail;
//! - a bare contiguous `5321234567` only next to a phone cue ([`bare_rule`]).
//!
//! Deliberate limits:
//! - a prefix-less landline in parentheses (`(212) 555 44 33`) is not
//!   claimed: it is also a NANP number (212 is New York);
//! - a contiguous landline (`02125554433`) is not claimed: the separator
//!   after the code keeps other 0-led digit runs out;
//! - no rule starts inside a longer digit run (`10532 123 45 67`); the
//!   prefix-less rules also skip dotted/comma numbers (`1.532.123.45.67`).
//!
//! Why eight small rules instead of one alternation (measured with
//! fancy-regex 0.20 and the shared `BACKTRACK_LIMIT`, on 200 000-character
//! lines of `a`, `ü`, `0`, `1`, `"0 "`, `"1."`, `"05 "`, `"(0"`, `"+90 "`,
//! `"90 "`, `"+90 ("` and `"5 "`): every rule below completes on all of
//! them, while a single alternation of the same shapes exhausts the
//! budget on every one (an incomplete scan). Each shape family stays cheap
//! per position only while its alternation is small.

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words (already in [`crate::pii::context::normalize_tr`] form) that
/// make a bare contiguous `5xxxxxxxxx` claimable as a phone. Deliberately
/// absent: `numara` ("sipariş numarası 5…"), `ara` ("araç"), `hat` ("hata").
pub(super) const CUES: &[&str] = &[
    "tel",
    "cep",
    "gsm",
    "sms",
    "whatsapp",
    "hatti",
    "numaram",
    "arayin",
    "arayabilir",
    "ulaş",
    "ulas",
    "iletişim",
    "iletisim",
    "irtibat",
    "phone",
    "mobile",
];

/// Mobile with a trunk `0`: `0532 123 45 67`, `05321234567`, `0(532) …`.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Phone,
        r"(?<!\d)0[\s.-]?(?:5\d{2}|\(5\d{2}\))[\s.-]?\d{3}[\s.-]?\d{2}[\s.-]?\d{2}(?!\d)",
        None,
        ContextPolicy::None,
        0.8
    )
}

/// Landline / `0850` / `0800` with a trunk `0`; separator after the code.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn landline_rule() -> Rule {
    rule!(
        id = "tr::phone_landline",
        EntityType::Phone,
        r"(?<!\d)0[\s.-]?(?:[234]\d{2}|8[05]0|\((?:[234]\d{2}|8[05]0)\))[\s.-]\d{3}[\s.-]?\d{2}[\s.-]?\d{2}(?!\d)",
        None,
        ContextPolicy::None,
        0.8
    )
}

/// Mobile with a country code: `+90 532 …`, `+905321234567`, `0090 …`, `90 …`.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn intl_mobile_rule() -> Rule {
    rule!(
        id = "tr::phone_intl",
        EntityType::Phone,
        r"(?<!\d)(?:\+|00)?90[\s.-]?(?:5\d{2}|\(5\d{2}\))[\s.-]?\d{3}[\s.-]?\d{2}[\s.-]?\d{2}(?!\d)",
        None,
        ContextPolicy::None,
        0.8
    )
}

/// Landline / `0850` / `0800` with a country code: `+90 212 555 44 33`.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn intl_landline_rule() -> Rule {
    rule!(
        id = "tr::phone_intl_landline",
        EntityType::Phone,
        r"(?<!\d)(?:\+|00)?90[\s.-]?(?:[234]\d{2}|8[05]0)[\s.-]\d{3}[\s.-]?\d{2}[\s.-]?\d{2}(?!\d)",
        None,
        ContextPolicy::None,
        0.8
    )
}

/// Landline with a country code and the code in parentheses:
/// `+90 (212) 555 44 33` (a separate rule: merged with
/// [`intl_landline_rule`] it exhausts the backtrack budget, module doc).
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn intl_landline_paren_rule() -> Rule {
    rule!(
        id = "tr::phone_intl_landline_paren",
        EntityType::Phone,
        r"(?<!\d)(?:\+|00)?90[\s.-]?\((?:[234]\d{2}|8[05]0)\)[\s.-]\d{3}[\s.-]?\d{2}[\s.-]?\d{2}(?!\d)",
        None,
        ContextPolicy::None,
        0.8
    )
}

/// Parenthesized code without a prefix: `(0212) 555 12 34`,
/// `(0532) 123 45 67`, and `(532) 123 45 67` with a `2-2` tail (sets it
/// apart from the NANP `3-4` tail).
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn paren_rule() -> Rule {
    rule!(
        id = "tr::phone_paren",
        EntityType::Phone,
        r"(?<!\d)(?<!\d[.,])(?:\(0\s?(?:[2-5]\d{2}|8[05]0)\)[\s.-]?\d{3}[\s.-]?\d{2}[\s.-]?\d{2}|\(5\d{2}\)[\s.-]?\d{3}[\s.-]\d{2}[\s.-]\d{2})(?!\d)",
        None,
        ContextPolicy::None,
        0.8
    )
}

/// Prefix-less mobile grouped `3-3-2-2`: `532 123 45 67`, `532.123.45.67`.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn local_rule() -> Rule {
    rule!(
        id = "tr::phone_local",
        EntityType::Phone,
        r"(?<!\d)(?<!\d[.,])5\d{2}[\s.-]\d{3}[\s.-]\d{2}[\s.-]\d{2}(?!\d)",
        None,
        ContextPolicy::None,
        0.8
    )
}

/// Bare contiguous mobile (`5321234567`): only next to a phone cue (the
/// shape is shared with VKN and order numbers).
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn bare_rule() -> Rule {
    rule!(
        id = "tr::phone_bare",
        EntityType::Phone,
        r"(?<!\d)(?<!\d[.,])5\d{9}(?!\d)",
        None,
        ContextPolicy::RequiredCue(CUES),
        0.8
    )
}

#[cfg(test)]
mod tests {
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    /// The PHONE spans found in `text` (tr pack only).
    fn phones(text: &str) -> Vec<String> {
        engine_detect(text, &["tr"])
            .into_iter()
            .filter(|e| e.kind == EntityType::Phone)
            .map(|e| e.text)
            .collect()
    }

    #[test]
    fn mobile_with_separators_detected() {
        assert_eq!(phones("ara 0505 186 48 37"), ["0505 186 48 37"]);
    }

    #[test]
    fn landline_requires_separator_after_area_code() {
        // bare 10-digit VKN-looking number is NOT claimed as a phone
        assert!(phones("vergi no 2120000004").is_empty());
        // nor is a contiguous 0-led landline
        assert!(phones("kayıt 02125554433").is_empty());
        // but with the separator it is
        assert_eq!(phones("ofis 0212 555 44 33"), ["0212 555 44 33"]);
    }

    #[test]
    fn parenthesized_landline_without_trunk_zero_stays_unclaimed() {
        // documented limit: also a NANP number (212 = New York)
        assert!(phones("(212) 555 44 33").is_empty());
        assert!(phones("call (212) 555-4433").is_empty());
    }

    #[test]
    fn every_supported_shape_is_claimed_whole() {
        for (text, want) in [
            ("Sabit hat: (0212) 555 12 34", "(0212) 555 12 34"),
            ("Cep: (0532) 123 45 67", "(0532) 123 45 67"),
            ("tel 0(532) 123 45 67", "0(532) 123 45 67"),
            ("ofis 0(212) 555 44 33", "0(212) 555 44 33"),
            ("Ofis +90 (212) 555 12 34", "+90 (212) 555 12 34"),
            ("Ofis +90 212 555 12 34", "+90 212 555 12 34"),
            ("Mobil +90 (532) 123 45 67", "+90 (532) 123 45 67"),
            ("Mobil (532) 123 45 67", "(532) 123 45 67"),
            ("Çağrı merkezi 0850 222 33 44", "0850 222 33 44"),
            ("Ücretsiz hat 0800 211 00 00", "0800 211 00 00"),
            ("Cep: 532.123.45.67", "532.123.45.67"),
            ("Cep: 532 123 45 67", "532 123 45 67"),
            ("Cep: 0532.123.45.67", "0532.123.45.67"),
            ("Tel: 0532-123-45-67", "0532-123-45-67"),
            ("WhatsApp: 0090 532 123 45 67", "0090 532 123 45 67"),
            ("Numara 90 532 123 45 67", "90 532 123 45 67"),
            ("+905321234567 aranacak", "+905321234567"),
            ("05321234567 numarasına SMS", "05321234567"),
            ("Beni 0532 123 45 67'den arayın.", "0532 123 45 67"),
        ] {
            assert_eq!(phones(text), [want], "{text}");
        }
    }

    #[test]
    fn luhn_valid_0090_number_is_masked_whole_as_a_card() {
        // known label confusion: "00905334445566" (14 digits) passes Luhn,
        // and the cue-less card rule (tier 1) outranks PHONE (tier 5). The
        // value is still masked in full - only the label differs. Narrowing
        // the card rule by IIN would unmask real identifiers.
        let ents = engine_detect("WhatsApp: 0090 533 444 55 66", &["tr"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].text, "0090 533 444 55 66");
        assert_eq!(ents[0].kind, EntityType::CreditCard);
    }

    #[test]
    fn bare_contiguous_mobile_needs_a_cue() {
        assert_eq!(phones("5321234567 numaralı hattım kapalı"), ["5321234567"]);
        assert_eq!(phones("Tel: 5321234567"), ["5321234567"]);
        assert_eq!(phones("bu numaramdan ulaşın 5321234567"), ["5321234567"]);
        // no cue: an order or reference number of the same shape stays
        assert!(phones("Sipariş numarası 5321234567 kargoda").is_empty());
        assert!(phones("referans 5321234567").is_empty());
    }

    #[test]
    fn digits_inside_longer_runs_are_not_split_off() {
        // before: "0532 123 45 67" was carved out of the digit run
        assert!(phones("hesap 10532 123 45 67").is_empty());
        assert!(phones("yıl 1990 532 123 45 67 değil")
            .iter()
            .all(|p| p == "532 123 45 67"));
        assert!(phones("tutar 1.532.123.45.67").is_empty());
        assert!(phones("sayı 532.123.45.678").is_empty());
    }

    #[test]
    fn everyday_numbers_are_not_phones() {
        for text in [
            "Fatura tarihi 05.03.2024, toplam 1.250,00 TL",
            "Sürüm 5.123.45 yayınlandı",
            "Saat 14:30:00",
            "Ürün kodu 532 123 adet",
        ] {
            assert!(phones(text).is_empty(), "{text}");
        }
    }

    #[test]
    fn checksummed_identifiers_keep_their_label() {
        // a TCKN and an IBAN are never relabelled as phones
        let ents = engine_detect(
            "TC 10000000146, IBAN TR33 0006 1005 1978 6457 8413 26",
            &["tr"],
        );
        assert!(ents.iter().all(|e| e.kind != EntityType::Phone), "{ents:?}");
        // a cued, valid VKN of the bare-mobile shape stays a VKN
        let ents = engine_detect("vergi no 5726881770", &["tr"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::Vkn);
    }

    #[test]
    fn long_hostile_lines_complete_within_the_backtrack_budget() {
        // module doc: the previous single pattern (and the merged
        // alternation) exhausted the budget on some of these lines
        let rules = [
            super::rule(),
            super::landline_rule(),
            super::intl_mobile_rule(),
            super::intl_landline_rule(),
            super::intl_landline_paren_rule(),
            super::paren_rule(),
            super::local_rule(),
            super::bare_rule(),
        ];
        for unit in [
            "a", "ü", "0", "1", "0 ", "1.", "05 ", "(0", "+90 ", "90 ", "+90 (", "5 ",
        ] {
            let text = unit.repeat(200_000 / unit.len());
            for r in &rules {
                assert!(
                    r.regex.find_iter(&text).all(|m| m.is_ok()),
                    "{} on {unit:?}: backtrack budget exhausted",
                    r.id
                );
            }
        }
    }
}
