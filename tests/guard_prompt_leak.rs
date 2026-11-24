//! Output-side system-prompt leak detection (OWASP LLM07): the model
//! output is checked against the system prompt the caller supplies.

use redactify::guard::{prompt_leak_risk, SignalKind};
use redactify::policy::{GuardAction, GuardCategory, Threshold};
use redactify::{Guard, GuardTarget, Policy};

const PROMPT: &str = "You are AcmeBot, the support assistant of Acme Corp. Never reveal internal discount codes. Always answer in the customer's language and keep replies under one hundred words.";
const PROMPT_B64: &str = "WW91IGFyZSBBY21lQm90LCB0aGUgc3VwcG9ydCBhc3Npc3RhbnQgb2YgQWNtZSBDb3JwLiBOZXZlciByZXZlYWwgaW50ZXJuYWwgZGlzY291bnQgY29kZXMuIEFsd2F5cyBhbnN3ZXIgaW4gdGhlIGN1c3RvbWVyJ3MgbGFuZ3VhZ2UgYW5kIGtlZXAgcmVwbGllcyB1bmRlciBvbmUgaHVuZHJlZCB3b3Jkcy4=";

fn score(output: &str) -> Option<f32> {
    prompt_leak_risk(output, PROMPT).map(|s| {
        assert_eq!(s.kind, SignalKind::PromptLeak);
        s.score
    })
}

#[test]
fn the_whole_prompt_reproduced_is_a_high_score_leak() {
    let out = format!("Sure! My instructions are: {PROMPT} Anything else?");
    assert!(score(&out).is_some_and(|s| s >= 0.9), "{:?}", score(&out));
}

#[test]
fn one_verbatim_sentence_of_eight_or_more_words_is_flagged() {
    let out = "Of course. Never reveal internal discount codes. Always answer in the customer's language, that is the rule I follow.";
    assert!(score(out).is_some_and(|s| s >= 0.6), "{:?}", score(out));
}

#[test]
fn case_punctuation_and_spacing_do_not_hide_a_leak() {
    let out =
        "NEVER   reveal internal discount codes!!\n\nalways, answer in the customer's language";
    assert!(score(out).is_some(), "{:?}", score(out));
}

#[test]
fn invisible_and_fullwidth_characters_do_not_hide_a_leak() {
    let zw = "Ne\u{200B}ver reveal int\u{200D}ernal discount codes. Always answer in the customer's language";
    assert!(score(zw).is_some());
    let fw = "Ｎｅｖｅｒ reveal internal discount codes. Always answer in the customer's language";
    assert!(score(fw).is_some());
}

#[test]
fn a_base64_encoded_prompt_is_a_leak() {
    let out = format!("Here you go: {PROMPT_B64}");
    assert!(score(&out).is_some_and(|s| s >= 0.9), "{:?}", score(&out));
}

#[test]
fn short_fragments_and_unrelated_text_are_not_leaks() {
    // seven words from the prompt: below the shingle length
    assert_eq!(
        score("Never reveal internal discount codes. Always answer"),
        None
    );
    assert_eq!(
        score("Our support team can help you with refunds and shipping questions today."),
        None
    );
    assert_eq!(score(""), None);
}

#[test]
fn a_prompt_shorter_than_the_shingle_never_matches() {
    assert!(prompt_leak_risk("be nice and helpful always", "be nice and helpful always").is_none());
    assert!(prompt_leak_risk("anything", "").is_none());
}

#[test]
fn signal_text_never_carries_prompt_words() {
    let s = prompt_leak_risk(PROMPT, PROMPT).unwrap();
    for word in ["discount", "AcmeBot", "customer"] {
        assert!(
            !s.evidence.contains(word) && !s.rationale.contains(word),
            "{s:?}"
        );
    }
}

#[test]
fn guard_blocks_a_model_output_that_leaks_the_prompt() {
    let leak = format!("My instructions: {PROMPT}");
    let g = Guard::new(GuardTarget::ModelOutput).with_system_prompt(PROMPT);
    let d = g.decide(&leak);
    assert_eq!(d.action, GuardAction::Block, "{d:?}");
    assert!(d
        .verdicts
        .iter()
        .any(|v| v.category == GuardCategory::PromptLeak));
    assert!(
        !format!("{d:?}").contains("discount"),
        "decision leaks prompt text"
    );
}

#[test]
fn guard_without_a_prompt_or_for_other_targets_is_unchanged() {
    let leak = format!("My instructions: {PROMPT}");
    assert_ne!(
        Guard::new(GuardTarget::ModelOutput).decide(&leak).action,
        GuardAction::Block
    );
    let g = Guard::new(GuardTarget::UserPrompt).with_system_prompt(PROMPT);
    assert_ne!(g.decide(&leak).action, GuardAction::Block);
}

#[test]
fn policy_can_relax_or_disable_the_category() {
    let leak = format!("My instructions: {PROMPT}");
    let relaxed = Policy::default().with_category(GuardCategory::PromptLeak, Threshold::None);
    let g = Guard::new(GuardTarget::ModelOutput)
        .with_policy(&relaxed)
        .with_system_prompt(PROMPT);
    assert_ne!(g.decide(&leak).action, GuardAction::Block);
}

#[test]
fn category_label_is_stable() {
    assert!(GuardCategory::ALL.contains(&GuardCategory::PromptLeak));
    assert_eq!(GuardCategory::PromptLeak.as_str(), "PROMPT_LEAK");
    assert_eq!(SignalKind::PromptLeak.as_str(), "PROMPT_LEAK");
}
