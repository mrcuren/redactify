//! Property-based invariants (proptest): contracts that must hold for
//! ARBITRARY input, complementing the hand-written golden vectors, corpora
//! and differential suites (which only cover the inputs someone thought
//! of). Seven invariants:
//!
//! 1. detection offsets are in-bounds BYTE offsets on char boundaries,
//!    every entity's `text` is exactly its sliced span, and entities come
//!    back left-to-right without overlap;
//! 2. redaction with an EMPTY mask deletes exactly the detected spans
//!    (the skeleton - everything outside entities - survives untouched);
//! 3. the vault round-trip restores the original text byte-for-byte
//!    whenever the input contains no '[' (a pre-existing placeholder-shaped
//!    token could otherwise legitimately collide with a real placeholder);
//! 4. normalization (NFKC + invisible stripping + layered base64 views)
//!    never panics on arbitrary unicode input;
//! 5. streaming == batch at RANDOM char-boundary split points, the
//!    randomized generalization of the exhaustive single-split suite in
//!    tests/stream_differential.rs;
//! 6. the normalization-aware detector keeps invariant 1 (raw-text spans,
//!    sorted, non-overlapping) although part of its findings come from the
//!    normalized view;
//! 7. `explain` returns exactly the `detect` entities, one explanation
//!    each, with the explanation score equal to the entity score.
//!
//! The text strategy mixes pure noise (arbitrary chars, including control
//! and astral-plane code points) with PII-seeded shapes (digit runs,
//! separators, Turkish multibyte, newlines) so both the empty-result fast
//! path and real detections get exercised.

use proptest::prelude::*;
use redactify::policy::stream::{GuardEvent, StreamingGuard};
use redactify::policy::{sanitize, GuardAction, GuardTarget};
use redactify::{detect, Detector, MaskStyle, Vault};

/// Mixed-alphabet char strategy: weighted toward PII-shaped material
/// (digits, latin letters, separators) but always with a share of
/// completely arbitrary unicode.
fn arb_char() -> impl Strategy<Value = char> {
    prop_oneof![
        6 => (b'0'..=b'9').prop_map(|b| b as char),
        4 => (b'a'..=b'z').prop_map(|b| b as char),
        2 => (b'A'..=b'Z').prop_map(|b| b as char),
        2 => Just(' '),
        1 => Just('-'),
        1 => Just('.'),
        1 => Just('\n'),
        1 => Just('@'),
        1 => Just('/'),
        1 => Just(':'),
        1 => Just('ğ'),
        1 => Just('ı'),
        1 => Just('İ'),
        1 => Just('ü'),
        1 => Just('ş'),
        1 => Just('日'),
        1 => Just('𝕏'), // astral plane: 4-byte UTF-8, multi-utf16-unit
        3 => any::<char>(),
    ]
}

fn arb_text() -> impl Strategy<Value = String> {
    proptest::collection::vec(arb_char(), 0..96).prop_map(|cs| cs.into_iter().collect())
}

fn targets() -> [GuardTarget; 3] {
    [
        GuardTarget::UserPrompt,
        GuardTarget::ToolResponse,
        GuardTarget::ModelOutput,
    ]
}

fn collect_event(ev: GuardEvent, out: &mut String, blocked: &mut bool) {
    match ev {
        GuardEvent::Segment { text, .. } => out.push_str(&text),
        GuardEvent::Block { .. } => *blocked = true,
        _ => {}
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// 1) offsets slice cleanly and the span text is exact (the documented
    /// left-to-right, non-overlapping contract of `detect`).
    #[test]
    fn detect_offsets_slice_cleanly(text in arb_text()) {
        let ents = detect(&text);
        let mut last_end = 0usize;
        for e in &ents {
            prop_assert!(e.end > e.start, "zero-length span: {e:?}");
            prop_assert!(e.start >= last_end, "overlap or bad order: {ents:?}");
            prop_assert!(e.end <= text.len(), "out of bounds: {e:?} / {text:?}");
            prop_assert!(text.is_char_boundary(e.start), "not a boundary: {e:?}");
            prop_assert!(text.is_char_boundary(e.end), "not a boundary: {e:?}");
            prop_assert_eq!(&text[e.start..e.end], e.text.as_str());
            last_end = e.end;
        }
    }

    /// 2) an empty mask template deletes exactly the detected spans: the
    /// output is the input skeleton (every byte outside all entities, in
    /// order) and nothing else.
    #[test]
    fn empty_mask_redaction_deletes_exactly_the_detected_spans(text in arb_text()) {
        let ents = detect(&text);
        let mut skeleton = String::with_capacity(text.len());
        let mut last = 0usize;
        for e in &ents {
            skeleton.push_str(&text[last..e.start]);
            last = e.end;
        }
        skeleton.push_str(&text[last..]);
        let masked = Detector::new()
            .with_mask_style(MaskStyle::Template(String::new()))
            .redact(&text);
        prop_assert_eq!(masked, skeleton);
    }

    /// 3) the vault restores '['-free originals byte-for-byte; inputs that
    /// could contain a placeholder-shaped token fall back to the weaker
    /// per-entity containment check.
    #[test]
    fn vault_round_trip_restores_the_original(text in arb_text()) {
        let (anon, vault) = Vault::pseudonymize(&text);
        let restored = vault.restore(&anon);
        if !text.contains('[') {
            prop_assert_eq!(restored, text, "anon was: {:?}", anon);
        } else {
            for e in detect(&text) {
                prop_assert!(
                    restored.contains(e.text.as_str()),
                    "entity {:?} lost in round trip of {:?} via {:?}",
                    e,
                    text,
                    anon
                );
            }
        }
    }

    /// 4) the L0 normalization stack never panics on arbitrary input and
    /// its layered views stay valid UTF-8 strings by construction.
    #[test]
    fn normalization_never_panics(text in arb_text()) {
        for view in redactify::guard::normalize::layered_views(&text, 2) {
            let _scanned = redactify::guard::normalize::normalize_for_scan(&view);
        }
    }

    /// 6) normalization-aware detection: spans address the RAW text, come
    /// back sorted and never overlap. Fullwidth digits and zero-width
    /// spaces are mixed in so the normalized pass actually contributes.
    #[test]
    fn normalized_detection_offsets_slice_cleanly(
        parts in proptest::collection::vec(
            prop_oneof![
                4 => arb_text(),
                1 => Just("TCKN \u{FF11}\u{FF12}\u{FF13}\u{FF14}\u{FF15}\u{FF16}\u{FF17}\u{FF18}\u{FF19}\u{FF15}\u{FF10}".to_owned()),
                1 => Just("0532\u{200B} 123 45 67".to_owned()),
                1 => Just("\u{200B}".to_owned()),
            ],
            0..4,
        )
    ) {
        let text = parts.concat();
        let ents = Detector::new().with_normalization(true).detect(&text);
        let mut last_end = 0usize;
        for e in &ents {
            prop_assert!(e.end > e.start, "zero-length span: {e:?}");
            prop_assert!(e.start >= last_end, "overlap or bad order: {ents:?}");
            prop_assert!(e.end <= text.len(), "out of bounds: {e:?}");
            prop_assert!(text.is_char_boundary(e.start) && text.is_char_boundary(e.end));
            prop_assert_eq!(&text[e.start..e.end], e.text.as_str());
            last_end = e.end;
        }
    }

    /// 7) explaining never changes what is detected.
    #[test]
    fn explain_matches_detect(text in arb_text(), normalize in any::<bool>()) {
        let d = Detector::new().with_normalization(normalize);
        let explained = d.explain(&text);
        let ents: Vec<_> = explained.iter().map(|(e, _)| e.clone()).collect();
        prop_assert_eq!(ents, d.detect(&text));
        for (e, why) in &explained {
            prop_assert_eq!(e.score, why.score);
        }
    }

    /// 5) streaming == batch for random chunk splits at char boundaries:
    /// segments concatenate to the batch sanitize text, and a Block appears
    /// if and only if the batch decision blocks.
    #[test]
    fn streaming_equals_batch_at_random_splits(
        (text, target_idx, cuts) in arb_text().prop_flat_map(|text| {
            let bounds: Vec<usize> =
                (0..=text.len()).filter(|&i| text.is_char_boundary(i)).collect();
            // at most 4 cuts, and never more than the boundary count
            let max_cuts = bounds.len().min(4);
            (
                Just(text),
                0..3usize,
                proptest::sample::subsequence(bounds, 0..=max_cuts),
            )
        })
    ) {
        let target = targets()[target_idx];
        let batch = sanitize(&text, &target);

        let mut cuts = cuts;
        cuts.sort_unstable();
        cuts.dedup();

        let mut sg = StreamingGuard::new(target);
        let mut out = String::new();
        let mut blocked = false;
        let mut prev = 0usize;
        for &c in &cuts {
            for ev in sg.push(&text[prev..c]) {
                collect_event(ev, &mut out, &mut blocked);
            }
            prev = c;
        }
        for ev in sg.push(&text[prev..]) {
            collect_event(ev, &mut out, &mut blocked);
        }
        for ev in sg.finish() {
            collect_event(ev, &mut out, &mut blocked);
        }

        match batch.decision.action {
            GuardAction::Block => prop_assert!(blocked, "batch Block must stream Block: {:?} / {:?}", text, cuts),
            _ => {
                prop_assert!(!blocked, "unexpected stream Block: {:?} / {:?}", text, cuts);
                prop_assert_eq!(out, batch.text, "stream != batch for {:?} / {:?}", text, cuts);
            }
        }
    }
}
