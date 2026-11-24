//! Mask styles: `Char`, `Partial` (never reveals a whole value) and keyed
//! `Pseudonym` (stable across encodings, key never printed), plus the
//! scan-aware `redact_scan` line masking shared by every style.

use proptest::prelude::*;
use redactify::{
    CustomRule, Detector, Entity, EntityType, MaskStyle, MaskStyleError, PseudonymKey,
};

const KEY_A: [u8; 32] = *b"0123456789abcdef0123456789ABCDEF";
const KEY_B: [u8; 32] = *b"fedcba9876543210FEDCBA9876543210";

fn key(bytes: [u8; 32]) -> PseudonymKey {
    PseudonymKey::new(bytes).expect("32-byte key")
}

fn entity(kind: EntityType, text: &str, start: usize) -> Entity {
    Entity {
        kind,
        start,
        end: start + text.len(),
        text: text.to_owned(),
        score: 1.0,
    }
}

#[test]
fn char_style_keeps_the_character_count() {
    let d = Detector::new().with_mask_style(MaskStyle::Char('x'));
    assert_eq!(
        d.redact("TCKN 12345678950, mail a@b.com"),
        "TCKN xxxxxxxxxxx, mail xxxxxxx"
    );
    // multibyte region: one mask char per CHARACTER
    let text = "ad: \u{15f}\u{fc}k\u{fc}r";
    let e = entity(EntityType::Name, "\u{15f}\u{fc}k\u{fc}r", 4);
    assert_eq!(MaskStyle::Char('*').redact(text, &[e]), "ad: *****");
}

#[test]
fn partial_style_keeps_separators_and_the_tail() {
    let d = Detector::new().with_mask_style(MaskStyle::Partial {
        keep_last: 4,
        ch: '*',
    });
    assert_eq!(
        d.redact("IBAN TR33 0006 1005 1978 6457 8413 26"),
        "IBAN **** **** **** **** **** **13 26"
    );
    assert_eq!(d.redact("TCKN 12345678950"), "TCKN *******8950");
    // keep_last 0 masks every alphanumeric, separators stay
    let none = MaskStyle::Partial {
        keep_last: 0,
        ch: '#',
    };
    let e = entity(EntityType::Phone, "0532 123 45 67", 0);
    assert_eq!(none.redact("0532 123 45 67", &[e]), "#### ### ## ##");
}

#[test]
fn partial_style_never_reveals_a_whole_value() {
    for keep_last in [0, 1, 3, 4, 10, 11, 12, 100] {
        let style = MaskStyle::Partial { keep_last, ch: '*' };
        for value in ["12345678950", "a@b.co", "X1", "7", "-+-"] {
            let e = entity(EntityType::Tckn, value, 0);
            let masked = style.redact(value, &[e]);
            assert_ne!(masked, value, "keep_last {keep_last} revealed {value:?}");
            assert_eq!(masked.chars().count(), value.chars().count());
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// For ANY region and ANY keep_last: the partial mask keeps the char
    /// count, leaves non-alphanumerics alone, and at least one
    /// alphanumeric character is always masked (a region without any
    /// alphanumeric character is masked entirely).
    #[test]
    fn partial_mask_always_hides_at_least_one_alphanumeric(
        value in "[a-zA-Z0-9 .@\u{e7}\u{131}\u{15f}-]{1,24}",
        keep_last in 0usize..30,
    ) {
        let e = entity(EntityType::Name, &value, 0);
        let masked = MaskStyle::Partial { keep_last, ch: '\u{2022}' }.redact(&value, &[e]);
        prop_assert_eq!(masked.chars().count(), value.chars().count());
        if !value.chars().any(char::is_alphanumeric) {
            prop_assert!(masked.chars().all(|c| c == '\u{2022}'), "{value:?} -> {masked:?}");
            return Ok(());
        }
        let mut hidden = 0;
        for (m, v) in masked.chars().zip(value.chars()) {
            if v.is_alphanumeric() {
                if m == '\u{2022}' {
                    hidden += 1;
                } else {
                    prop_assert_eq!(m, v);
                }
            } else {
                prop_assert_eq!(m, v);
            }
        }
        let alnum = value.chars().filter(|c| c.is_alphanumeric()).count();
        if alnum > 0 {
            prop_assert!(hidden >= 1, "{value:?} -> {masked:?}");
            prop_assert_eq!(hidden, if keep_last >= alnum { alnum } else { alnum - keep_last });
        }
    }
}

#[test]
fn pseudonym_format_and_stability() {
    let d = Detector::new()
        .with_normalization(true)
        .with_mask_style(MaskStyle::Pseudonym(key(KEY_A)));
    let plain = d.redact("TCKN 12345678950");
    let token = plain.strip_prefix("TCKN ").unwrap();
    assert!(
        token.starts_with("[TCKN#") && token.ends_with(']'),
        "{token}"
    );
    let hex = &token["[TCKN#".len()..token.len() - 1];
    assert_eq!(hex.len(), 16);
    assert!(hex
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    // the same value in fullwidth digits / scattered with zero-width
    // spaces normalizes to the same value: same pseudonym
    let fullwidth = d.redact(
        "TCKN \u{FF11}\u{FF12}\u{FF13}\u{FF14}\u{FF15}\u{FF16}\u{FF17}\u{FF18}\u{FF19}\u{FF15}\u{FF10}",
    );
    assert_eq!(fullwidth, plain);
    assert_eq!(d.redact("TCKN 1\u{200B}2345678950"), plain);
    // a different key gives a different pseudonym
    let other = Detector::new().with_mask_style(MaskStyle::Pseudonym(key(KEY_B)));
    assert_ne!(other.redact("TCKN 12345678950"), plain);
    // a different value gives a different pseudonym
    assert_ne!(d.redact("TCKN 10000000146"), plain);
}

#[test]
fn pseudonym_binds_the_type() {
    // the type is part of the HMAC message: the same text under two
    // types gets unrelated digests
    let style = MaskStyle::Pseudonym(key(KEY_A));
    let as_name = style.redact("x", &[entity(EntityType::Name, "x", 0)]);
    let as_addr = style.redact("x", &[entity(EntityType::Address, "x", 0)]);
    assert!(as_name.starts_with("[NAME#"));
    assert!(as_addr.starts_with("[ADDRESS#"));
    assert_ne!(as_name[6..], as_addr[9..]);
}

#[test]
fn pseudonym_key_length_is_enforced() {
    for len in [0, 1, 16, 31] {
        assert_eq!(
            PseudonymKey::new(vec![0u8; len]),
            Err(MaskStyleError::KeyTooShort { len, min: 32 })
        );
    }
    assert_eq!(PseudonymKey::new(vec![0u8; 32]).unwrap().len(), 32);
    assert_eq!(PseudonymKey::new(vec![0u8; 100]).unwrap().len(), 100);
    assert_eq!(PseudonymKey::MIN_LEN, 32);
}

#[test]
fn debug_never_prints_the_key() {
    let secret = *b"SUPERSECRETSUPERSECRETSUPERSECRE";
    let k = key(secret);
    let style = MaskStyle::Pseudonym(k.clone());
    let d = Detector::new().with_mask_style(style.clone());
    for dbg in [format!("{k:?}"), format!("{style:?}"), format!("{d:?}")] {
        assert!(!dbg.contains("SUPERSECRET"), "{dbg}");
        assert!(!dbg.contains("83, 85, 80"), "{dbg}"); // the bytes as numbers
        assert!(dbg.contains("<redacted, 32 bytes>"), "{dbg}");
    }
}

#[test]
fn error_lines_render_the_same_marker_in_every_style() {
    let rule = CustomRule::new(EntityType::Itin, r"(?i)(a|b|ab)*(?>c)").unwrap();
    let rules = [&rule];
    let text = format!("kimlik 12345678950\n{} c\nend", "ab".repeat(40));
    for (style, first) in [
        (MaskStyle::Label, "kimlik [TCKN]"),
        (MaskStyle::Char('*'), "kimlik ***********"),
        (
            MaskStyle::Partial {
                keep_last: 2,
                ch: '*',
            },
            "kimlik *********50",
        ),
    ] {
        let out = Detector::new()
            .with_custom_rules(&rules)
            .with_mask_style(style)
            .redact(&text);
        assert_eq!(out, format!("{first}\n[SCAN_INCOMPLETE]\nend"));
    }
    let pseudo = Detector::new()
        .with_custom_rules(&rules)
        .with_mask_style(MaskStyle::Pseudonym(key(KEY_A)))
        .redact(&text);
    assert!(pseudo.ends_with("]\n[SCAN_INCOMPLETE]\nend"), "{pseudo}");
}
