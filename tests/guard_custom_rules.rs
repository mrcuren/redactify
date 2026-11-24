//! Custom rules and the allowlist in guard decisions: before, both reached
//! only `Detector`, so `Guard::sanitize` (the REST / MCP path) and the
//! streaming guard ignored them.

use redactify::policy::StreamingGuard;
use redactify::{CustomRule, EntityType, Guard, GuardAction, GuardTarget};

fn employee_rule() -> CustomRule {
    CustomRule::new(
        EntityType::custom("STAFF_NUMBER").expect("label"),
        r"\bE\d{6}\b",
    )
    .expect("pattern")
}

#[test]
fn guard_decisions_and_masks_use_custom_rules() {
    let rule = employee_rule();
    let rules = [&rule];
    let guard = Guard::new(GuardTarget::UserPrompt).with_custom_rules(&rules);
    let r = guard.sanitize("personel E123456 izinde");
    assert_eq!(
        r.decision.action,
        GuardAction::Mask,
        "{}",
        r.decision.rationale
    );
    assert!(r.decision.mask_summary.contains(&"STAFF_NUMBER"));
    assert_eq!(r.text, "personel [STAFF_NUMBER] izinde");
    assert_eq!(guard.mask_all("E654321"), "[STAFF_NUMBER]");
    // without the rule the value stays
    let plain = Guard::new(GuardTarget::UserPrompt).sanitize("personel E123456 izinde");
    assert_eq!(plain.decision.action, GuardAction::Allow);
}

#[test]
fn guard_decisions_honor_the_allowlist() {
    let ignored = ["0532 123 45 67"];
    let guard = Guard::new(GuardTarget::UserPrompt).with_ignored(&ignored);
    let r = guard.sanitize("Destek: 0532 123 45 67, TCKN 12345678950");
    assert_eq!(r.text, "Destek: 0532 123 45 67, TCKN [TCKN]");
    // an allowlist that covers every finding leaves nothing to mask
    let all = ["0532 123 45 67"];
    let r = Guard::new(GuardTarget::UserPrompt)
        .with_ignored(&all)
        .sanitize("Destek hatti 0532 123 45 67");
    assert_eq!(
        r.decision.action,
        GuardAction::Allow,
        "{}",
        r.decision.rationale
    );
}

/// The streamed output for `text` split into two chunks at every char
/// boundary must equal the batch output of the equally configured guard.
fn assert_stream_equals_batch(text: &str, build: impl Fn() -> StreamingGuard, batch: &str) {
    let cuts: Vec<usize> = text
        .char_indices()
        .map(|(i, _)| i)
        .chain([text.len()])
        .collect();
    for cut in cuts {
        let mut sg = build();
        let mut out = String::new();
        for chunk in [&text[..cut], &text[cut..]] {
            for ev in sg.push(chunk) {
                out.push_str(ev.as_segment().expect("no Block").0);
            }
        }
        for ev in sg.finish() {
            out.push_str(ev.as_segment().expect("no Block").0);
        }
        assert_eq!(out, batch, "split at byte {cut}");
    }
}

#[test]
fn the_streaming_guard_uses_custom_rules_and_matches_batch() {
    let rule = employee_rule();
    let rules = [&rule];
    let text = "personel E123456 izinde\nikinci satir E654321 ve TCKN 12345678950\n";
    let batch = Guard::new(GuardTarget::UserPrompt)
        .with_custom_rules(&rules)
        .sanitize(text);
    assert!(batch.text.contains("[STAFF_NUMBER]"), "{}", batch.text);
    assert_stream_equals_batch(
        text,
        || StreamingGuard::new(GuardTarget::UserPrompt).with_custom_rules(vec![employee_rule()]),
        &batch.text,
    );
}

#[test]
fn a_custom_match_longer_than_the_holdback_is_never_split() {
    // a custom rule whose match spans whitespace and runs past the
    // streaming holdback: early emission must stay off so the batch mask
    // (one span) is reproduced at every split of a long open line
    let long = CustomRule::new(
        EntityType::custom("SEALED_BLOCK").expect("label"),
        r"BEGIN SEALED [a-z ]{150,300} END",
    )
    .expect("pattern");
    let rules = [&long];
    let filler = "kelime ".repeat(40);
    let text = format!(
        "{filler}BEGIN SEALED {} END ve devam eden metin {filler}",
        "abc ".repeat(50)
    );
    let batch = Guard::new(GuardTarget::UserPrompt)
        .with_custom_rules(&rules)
        .sanitize(&text);
    assert!(batch.text.contains("[SEALED_BLOCK]"), "{}", batch.text);
    let make = || {
        StreamingGuard::new(GuardTarget::UserPrompt).with_custom_rules(vec![CustomRule::new(
            EntityType::custom("SEALED_BLOCK").expect("label"),
            r"BEGIN SEALED [a-z ]{150,300} END",
        )
        .expect("pattern")])
    };
    assert_stream_equals_batch(&text, make, &batch.text);
}

#[test]
fn the_streaming_guard_honors_the_allowlist_and_matches_batch() {
    let ignored = ["0532 123 45 67"];
    let filler = "uzun bir satir ".repeat(15);
    let text = format!("{filler}Destek: 0532 123 45 67, TCKN 12345678950 {filler}");
    let batch = Guard::new(GuardTarget::UserPrompt)
        .with_ignored(&ignored)
        .sanitize(&text);
    assert!(batch.text.contains("0532 123 45 67"), "{}", batch.text);
    assert!(batch.text.contains("[TCKN]"), "{}", batch.text);
    assert_stream_equals_batch(
        &text,
        || {
            StreamingGuard::new(GuardTarget::UserPrompt)
                .with_ignored(vec!["0532 123 45 67".to_owned()])
        },
        &batch.text,
    );
}
