//! Caller-supplied context: a cue in the text the input answers (the
//! previous turn of a chat or call transcript) unlocks a cue-gated
//! identifier that stands alone in the input.
//!
//! Cues are searched on the value's own line only, so without a context
//! `BOT: Vergi numaranizi yazar misiniz?` + newline + `MUSTERI: 1234567890`
//! and the SSN prompt `Please say your Social Security number.` followed
//! by `536906292` on the next line give no finding (the same values with
//! the cue on their own line are found).

use redactify::{CustomRule, Detector, EntityType, Guard, GuardAction, GuardTarget};

const VKN_PROMPT: &str = "Vergi numaranızı yazar mısınız?";

fn kinds(entities: &[redactify::Entity]) -> Vec<EntityType> {
    entities.iter().map(|e| e.kind).collect()
}

#[test]
fn a_cue_in_the_previous_turn_unlocks_a_standalone_identifier() {
    assert!(Detector::new().detect("1234567890").is_empty());
    let context = [VKN_PROMPT];
    let found = Detector::new().with_context(&context).detect("1234567890");
    assert_eq!(kinds(&found), [EntityType::Vkn]);
    // the same score as a cue on the value's own line
    let same_line = Detector::new().detect("vergi no 1234567890");
    assert_eq!(found[0].score, same_line[0].score);
}

#[test]
fn the_ssn_prompt_of_an_ivr_transcript_unlocks_the_answer() {
    let context = ["BOT: Please enter or say your nine digit Social Security number."];
    let d = Detector::new().with_locales(&["en"]).with_context(&context);
    assert!(Detector::new()
        .with_locales(&["en"])
        .detect("536906292#")
        .is_empty());
    assert_eq!(kinds(&d.detect("536906292#")), [EntityType::Ssn]);
}

#[test]
fn context_without_a_cue_changes_nothing() {
    let context = ["Siparişiniz yola çıktı, takip numarası aşağıda."];
    assert!(Detector::new()
        .with_context(&context)
        .detect("1234567890")
        .is_empty());
}

#[test]
fn context_never_replaces_the_checksum() {
    // 1234567891 fails the VKN check digit
    let context = [VKN_PROMPT];
    assert!(Detector::new()
        .with_context(&context)
        .detect("1234567891")
        .is_empty());
}

#[test]
fn short_cues_count_only_at_a_word_start_in_context_too() {
    let rule = CustomRule::new(EntityType::Itin, r"X\d{5}")
        .expect("pattern")
        .with_cue(&["tax"]);
    let rules = [&rule];
    let trap = ["syntax error in line 4"];
    assert!(Detector::new()
        .with_custom_rules(&rules)
        .with_context(&trap)
        .detect("X12345")
        .is_empty());
    let cue = ["Your tax reference?"];
    assert_eq!(
        kinds(
            &Detector::new()
                .with_custom_rules(&rules)
                .with_context(&cue)
                .detect("X12345")
        ),
        [EntityType::Itin]
    );
}

#[test]
fn a_boost_cue_in_context_raises_the_score() {
    let rule = CustomRule::new(EntityType::Itin, r"X\d{5}")
        .expect("pattern")
        .with_score(0.5)
        .with_cue_boost(&["ticket"], 0.95);
    let rules = [&rule];
    let context = ["Which ticket do you mean?"];
    let d = Detector::new().with_custom_rules(&rules);
    assert_eq!(d.detect("X12345")[0].score, 0.5);
    assert_eq!(d.with_context(&context).detect("X12345")[0].score, 0.95);
}

/// A context is searched once per cue, not once per match: a per-match
/// search of 200 cue-gated candidates against 16 KiB of `xtax ` (a short
/// cue inside words, never at a word start) costs matches x context
/// squared (seconds). The bound below is two orders of magnitude above the
/// linear cost even in a debug build.
#[test]
fn context_cost_is_linear_in_the_context() {
    let text = "1234567890 ".repeat(100);
    let context = ["xtax ".repeat(8 * 1024 / 5)];
    let refs = [context[0].as_str()];
    let started = std::time::Instant::now();
    let found = Detector::new().with_context(&refs).detect(&text);
    let elapsed = started.elapsed();
    assert!(found.is_empty(), "no cue at a word start: {found:?}");
    assert!(elapsed.as_secs_f64() < 2.0, "took {elapsed:?}");
    // the answer per cue is the same with many contexts and repeated cues
    let refs = ["xtax", "tax", VKN_PROMPT];
    let found = Detector::new().with_context(&refs).detect(&text);
    assert_eq!(found.len(), 100);
}

#[test]
fn explain_reports_the_context_cue_literal() {
    let context = [VKN_PROMPT];
    let explained = Detector::new().with_context(&context).explain("1234567890");
    assert_eq!(explained.len(), 1);
    assert_eq!(explained[0].1.cue.as_deref(), Some("vergi"));
}

#[test]
fn the_guard_masks_with_the_context_of_the_turn() {
    let context = [VKN_PROMPT];
    let guard = Guard::new(GuardTarget::UserPrompt).with_context(&context);
    let r = guard.sanitize("1234567890");
    assert_eq!(
        r.decision.action,
        GuardAction::Mask,
        "{}",
        r.decision.rationale
    );
    assert_eq!(r.text, "[VKN]");
    // without the context the bare number is not claimable
    let plain = Guard::new(GuardTarget::UserPrompt).sanitize("1234567890");
    assert_eq!(plain.decision.action, GuardAction::Allow);
}

#[cfg(feature = "api")]
#[test]
fn rest_endpoints_take_a_context_array() {
    use redactify::api::handle_request;
    let body = format!(r#"{{"text":"1234567890","context":["{VKN_PROMPT}"]}}"#);
    for path in ["/v1/sanitize", "/v1/redact", "/v1/detect", "/v1/guard"] {
        let r = handle_request("POST", path, &body);
        assert_eq!(r.status, 200, "{path}: {}", r.body);
        assert!(r.body.contains("VKN"), "{path}: {}", r.body);
        assert!(!r.body.contains("numaran"), "context echoed by {path}");
    }
    let r = handle_request(
        "POST",
        "/v1/redact",
        r#"{"text":"x","context":"not an array"}"#,
    );
    assert_eq!(r.status, 400);
    assert!(r.body.contains("bad_context"), "{}", r.body);
}
