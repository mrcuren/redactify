//! More mask strategies: a fixed replacement text, masking only the first
//! or the last N characters, and a different strategy per entity type.

use redactify::{Detector, EntityType, Guard, GuardTarget, MaskStyle, PseudonymKey};

fn redact(style: MaskStyle, text: &str) -> String {
    Detector::new().with_mask_style(style).redact(text)
}

#[test]
fn a_template_without_placeholder_is_a_fixed_replacement() {
    let t = MaskStyle::Template("[REDACTED]".into());
    assert_eq!(
        redact(t, "TCKN 12345678950 and a@b.co"),
        "TCKN [REDACTED] and [REDACTED]"
    );
}

#[test]
fn mask_first_hides_the_leading_characters_only() {
    let style = MaskStyle::MaskFirst { count: 3, ch: '*' };
    assert_eq!(redact(style, "TCKN 12345678950"), "TCKN ***45678950");
    let card = MaskStyle::MaskFirst { count: 12, ch: 'x' };
    assert_eq!(
        redact(card, "kart 4111 1111 1111 1111"),
        "kart xxxx xxxx xxxx 1111"
    );
}

#[test]
fn mask_last_hides_the_trailing_characters_only() {
    let style = MaskStyle::MaskLast { count: 4, ch: '*' };
    assert_eq!(
        redact(style, "kart 4111 1111 1111 1111"),
        "kart 4111 1111 1111 ****"
    );
    let tckn = MaskStyle::MaskLast { count: 3, ch: '#' };
    assert_eq!(redact(tckn, "TCKN 12345678950"), "TCKN 12345678###");
}

#[test]
fn a_count_at_or_over_the_length_masks_everything_and_keeps_separators() {
    for style in [
        MaskStyle::MaskFirst { count: 99, ch: '*' },
        MaskStyle::MaskLast { count: 99, ch: '*' },
    ] {
        assert_eq!(redact(style, "mail a@b.co"), "mail *@*.**");
    }
    // a count of 0 must not reveal the whole value: it masks everything
    for style in [
        MaskStyle::MaskFirst { count: 0, ch: '*' },
        MaskStyle::MaskLast { count: 0, ch: '*' },
    ] {
        assert_eq!(redact(style, "TCKN 12345678950"), "TCKN ***********");
    }
}

#[test]
fn by_type_picks_the_strategy_of_the_region_type() {
    let style = MaskStyle::by_type(
        MaskStyle::Label,
        vec![
            (EntityType::Email, MaskStyle::Char('*')),
            (
                EntityType::CreditCard,
                MaskStyle::MaskLast { count: 4, ch: '#' },
            ),
        ],
    );
    let text = "TCKN 12345678950 mail a@b.co kart 4111 1111 1111 1111";
    assert_eq!(
        redact(style, text),
        "TCKN [TCKN] mail ****** kart 4111 1111 1111 ####"
    );
}

#[test]
fn by_type_works_for_guard_and_with_a_pseudonym_override() {
    let key = PseudonymKey::new([7u8; 32]).unwrap();
    let style = MaskStyle::by_type(
        MaskStyle::Template("<{type}>".into()),
        vec![(EntityType::Tckn, MaskStyle::Pseudonym(key))],
    );
    let r = Guard::new(GuardTarget::UserPrompt)
        .with_mask_style(style)
        .sanitize("TCKN 12345678950 mail a@b.co");
    assert!(r.text.starts_with("TCKN [TCKN#"), "{}", r.text);
    assert!(r.text.ends_with("mail <EMAIL>"), "{}", r.text);
}
