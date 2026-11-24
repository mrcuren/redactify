//! The engine skips a cue-gated (`RequiredCue`) rule on a line where none
//! of its cues occurs (`may_hold_cue` in `src/pii/detect.rs`). These tests
//! pin that the skip never drops a candidate the full scan would claim:
//! a cue in the caller's context, a camelCase cue and a cue after the
//! value still unlock the rule, and a line without any cue stays empty.

use redactify::{Detector, EntityType};

fn kinds(detector: &Detector<'_>, text: &str) -> Vec<EntityType> {
    detector.detect(text).into_iter().map(|e| e.kind).collect()
}

#[test]
fn a_cue_only_in_the_caller_context_still_unlocks_the_rule() {
    let tr = ["tr"];
    let bare = Detector::new().with_locales(&tr);
    assert!(!kinds(&bare, "1234567890").contains(&EntityType::Vkn));
    let context = ["Vergi numaranızı yazar mısınız?"];
    let with_context = Detector::new().with_locales(&tr).with_context(&context);
    assert!(kinds(&with_context, "1234567890").contains(&EntityType::Vkn));
}

#[test]
fn cues_on_the_line_still_unlock_the_rule() {
    let tr = ["tr"];
    let d = Detector::new().with_locales(&tr);
    // leading label, camelCase key, label after the value
    for text in [
        "VKN: 1234567890",
        "taxVkn: 1234567890",
        "1234567890 (vergi no)",
    ] {
        assert!(kinds(&d, text).contains(&EntityType::Vkn), "{text}");
    }
}

#[test]
fn many_lines_without_a_cue_stay_empty_and_one_cued_line_is_found() {
    let tr = ["tr"];
    let d = Detector::new().with_locales(&tr);
    let mut text = "sipariş 1234567890 kargoda\n".repeat(200);
    text.push_str("VKN 1234567890\n");
    let vkn: Vec<_> = d
        .detect(&text)
        .into_iter()
        .filter(|e| e.kind == EntityType::Vkn)
        .collect();
    assert_eq!(vkn.len(), 1, "{vkn:?}");
    assert_eq!(&text[vkn[0].start..vkn[0].end], "1234567890");
}
