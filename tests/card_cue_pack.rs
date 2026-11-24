//! `packs/pci-card-cue.toml`: the opt-in pack that masks cue-labelled card
//! numbers failing the Luhn check, which the built-in rule leaves visible
//! by design (checksum first).
#![cfg(feature = "config")]

use redactify::policy::Policy;
use redactify::{Guard, GuardTarget};

const PACK: &str = include_str!("../packs/pci-card-cue.toml");

fn masked(text: &str, with_pack: bool) -> String {
    let policy = Policy::from_toml(PACK).expect("the pack parses");
    let guard = Guard::new(GuardTarget::UserPrompt);
    let guard = if with_pack {
        guard.with_policy(&policy)
    } else {
        guard
    };
    guard.sanitize(text).text
}

#[test]
fn the_built_in_rule_leaves_a_luhn_invalid_card_visible() {
    // the measured gap: one mistyped digit keeps the whole number in clear
    assert_eq!(
        masked("card number 3520186822194848", false),
        "card number 3520186822194848"
    );
}

#[test]
fn the_pack_masks_a_cue_labelled_luhn_invalid_card() {
    for text in [
        "card number 3520186822194848",
        "Kart No: 3520 1868 2219 4848",
        "kredi karti 3520-1868-2219-4848 son kullanma 12/29",
        "my credit card is 3520186822194848 thanks",
    ] {
        let out = masked(text, true);
        assert!(out.contains("[CREDIT_CARD]"), "{text:?} -> {out:?}");
        assert!(!out.contains("3520"), "{text:?} -> {out:?}");
    }
}

#[test]
fn the_pack_leaves_numbers_without_a_cue_and_valid_cards_work_as_before() {
    assert_eq!(
        masked("order 3520186822194848 shipped", true),
        "order 3520186822194848 shipped"
    );
    assert_eq!(masked("ref 1234567890", true), "ref 1234567890");
    // a Luhn-valid card is masked with or without the pack
    assert!(masked("card number 4111 1111 1111 1111", true).contains("[CREDIT_CARD]"));
    assert!(masked("card number 4111 1111 1111 1111", false).contains("[CREDIT_CARD]"));
}
