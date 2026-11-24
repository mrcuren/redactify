//! Secrets visible only in the normalized scan view (zero-width splits,
//! fullwidth letters, lookalikes) are masked by every masking surface,
//! while the public raw-view functions keep their semantics.

use redactify::guard::{find_secret_spans, mask_secrets, mask_secrets_with, secrets_risk};
use redactify::policy::{sanitize, GuardAction, GuardTarget};
use redactify::{Guard, JsonFindingKind, JsonRedactor};
use serde_json::json;

/// Secrets the raw scan cannot see: a zero-width split, a fullwidth
/// letter, a Cyrillic lookalike inside a Latin token.
const NORMALIZED_ONLY: &[(&str, &str)] = &[
    (
        "key AKIA\u{200B}IOSFODNN7EXAMPLE end",
        "key [SECRET:AWS_ACCESS_KEY] end",
    ),
    (
        "key \u{FF21}KIAIOSFODNN7EXAMPLE end",
        "key [SECRET:AWS_ACCESS_KEY] end",
    ),
    (
        "key \u{0410}KIAIOSFODNN7EXAMPLE end",
        "key [SECRET:AWS_ACCESS_KEY] end",
    ),
    (
        "token ghp_\u{200B}AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA end",
        "token [SECRET:GITHUB_TOKEN] end",
    ),
];

#[test]
fn mask_secrets_masks_secrets_found_on_the_normalized_view() {
    for (text, expected) in NORMALIZED_ONLY {
        assert_eq!(mask_secrets(text), *expected, "{text:?}");
        assert_eq!(
            mask_secrets_with(text, Some("<{VENDOR}>")),
            expected.replace("[SECRET:", "<").replace(']', ">"),
            "{text:?}"
        );
    }
}

#[test]
fn sanitize_block_and_mask_all_carry_no_normalized_secret() {
    for (text, expected) in NORMALIZED_ONLY {
        let r = sanitize(text, &GuardTarget::UserPrompt);
        assert_eq!(r.decision.action, GuardAction::Block, "{text:?}");
        assert_eq!(r.text, *expected, "{text:?}");
        assert_eq!(
            Guard::new(GuardTarget::UserPrompt).mask_all(text),
            *expected,
            "{text:?}"
        );
    }
}

#[test]
fn json_leaves_mask_normalized_secrets() {
    let mut doc =
        json!({"k": "AKIA\u{200B}IOSFODNN7EXAMPLE", "t": "x \u{FF21}KIAIOSFODNN7EXAMPLE"});
    let report = JsonRedactor::new().redact(&mut doc);
    assert_eq!(
        doc,
        json!({"k": "[SECRET:AWS_ACCESS_KEY]", "t": "x [SECRET:AWS_ACCESS_KEY]"})
    );
    let kinds: Vec<JsonFindingKind> = report.findings.iter().map(|f| f.kind).collect();
    assert_eq!(
        kinds,
        vec![
            JsonFindingKind::Secret("AWS_ACCESS_KEY"),
            JsonFindingKind::Secret("AWS_ACCESS_KEY")
        ]
    );
}

#[test]
fn a_secret_beside_an_unalignable_mark_run_is_still_masked() {
    // beside a long combining-mark run, whether the normalized view aligns
    // to the raw text or the masking falls back to whole lines, the key
    // never survives, and the fallback never reaches past the key's line
    let zalgo = format!("x{}\u{0316}", "\u{0301}".repeat(8));
    for text in [
        format!("{zalgo} key AKIA\u{200B}IOSFODNN7EXAMPLE end"),
        format!("{zalgo}\nkey \u{FF21}KIAIOSFODNN7EXAMPLE end\nnext line"),
    ] {
        let out = mask_secrets(&text);
        assert!(!out.contains("IOSFODNN7EXAMPLE"), "{out:?}");
        assert!(out.contains("[SECRET:AWS_ACCESS_KEY]"), "{out:?}");
        if text.contains('\n') {
            assert!(out.starts_with(&format!("{zalgo}\n")), "{out:?}");
            assert!(out.ends_with("\nnext line"), "{out:?}");
        }
    }
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

    /// The masking spans address the RAW text for any mix of normalized-
    /// only secrets, expansions, mark runs and line breaks: sorted,
    /// disjoint, on char boundaries, and masking never panics.
    #[test]
    fn mask_spans_are_sorted_disjoint_raw_spans(
        parts in proptest::collection::vec(
            proptest::prop_oneof![
                3 => r"\PC{0,6}",
                1 => proptest::strategy::Just("key AKIA\u{200B}IOSFODNN7EXAMPLE".to_owned()),
                1 => proptest::strategy::Just("\u{FF21}KIAIOSFODNN7EXAMPLE".to_owned()),
                1 => proptest::strategy::Just(
                    "\u{BD}34567890:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw".to_owned()
                ),
                1 => proptest::strategy::Just("password:\n\u{FF33}3cr3tPass!2024".to_owned()),
                1 => proptest::strategy::Just("x\u{0301}\u{0301}\u{0316}".to_owned()),
                1 => proptest::strategy::Just("\u{FB01}\u{200B}".to_owned()),
                1 => proptest::strategy::Just("\n".to_owned()),
                1 => proptest::strategy::Just(" ".to_owned()),
            ],
            0..6,
        )
    ) {
        let text = parts.concat();
        let spans = redactify::guard::secrets::find_secret_mask_spans(&text);
        let mut last_end = 0usize;
        for s in spans.iter().filter(|s| s.start < s.end) {
            proptest::prop_assert!(s.start >= last_end, "overlap or bad order: {spans:?}");
            proptest::prop_assert!(s.end <= text.len(), "out of bounds: {spans:?}");
            proptest::prop_assert!(text.is_char_boundary(s.start) && text.is_char_boundary(s.end));
            last_end = s.end;
        }
        let _ = mask_secrets(&text);
    }
}

#[test]
fn decision_signals_stay_raw_view_only() {
    // the decision path scans every view itself (policy.rs); the public
    // raw-view functions keep their semantics
    let text = NORMALIZED_ONLY[0].0;
    assert!(find_secret_spans(text).is_empty());
    assert!(secrets_risk(text).is_empty());
}

#[test]
fn texts_without_a_normalized_difference_mask_their_raw_spans() {
    // ASCII and normalization-stable non-ASCII texts: the raw spans only
    for text in [
        "prefix AKIAIOSFODNN7EXAMPLE suffix",
        "password = hunter2secure42!",
        "Authorization: Bearer AbCdEf123456789012345678",
        "postgres://admin:S3cr3tPass@db.example.com/prod",
        "şifre: Gizli-Parola-2024! ve AKIAIOSFODNN7EXAMPLE",
        "the api key is 3q2+7wJalrXUtnFEMIK7MDENGbPxRfiCY",
        "nothing to see here, ğüşıöç",
    ] {
        let spans = find_secret_spans(text);
        let mut expected = String::new();
        let mut last = 0;
        for s in spans.iter().filter(|s| s.start < s.end) {
            expected.push_str(&text[last..s.start]);
            expected.push_str(&format!("[SECRET:{}]", s.vendor));
            last = s.end;
        }
        expected.push_str(&text[last..]);
        assert_eq!(mask_secrets(text), expected, "{text:?}");
    }
}
