//! Fuzz target: streaming == batch for the full guard, with every locale
//! pack on. The first input byte picks the target, the next bytes pick
//! chunk lengths, the rest is the text. The concatenated stream segments
//! must equal `Guard::sanitize(text).text` whenever the batch decision is
//! not `Block`, and the stream must Block exactly when the batch does
//! (`tests/stream_differential.rs` proves this on a fixed corpus; here the
//! inputs and the split points are coverage-guided).
//!
//! Build/run: `cargo +nightly fuzz run guard_stream`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use redactify::policy::StreamingGuard;
use redactify::{Guard, GuardAction, GuardTarget, SUPPORTED_LOCALES};

fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let target = match pick % 3 {
        0 => GuardTarget::UserPrompt,
        1 => GuardTarget::ToolResponse,
        _ => GuardTarget::ModelOutput,
    };
    // up to 4 chunk-length bytes, then the text
    let n = rest.len().min(4);
    let (lens, text_bytes) = rest.split_at(n);
    let text = String::from_utf8_lossy(text_bytes);

    let batch = Guard::new(target)
        .with_locales(SUPPORTED_LOCALES)
        .sanitize(&text);

    let mut sg = StreamingGuard::new(target).with_locales(SUPPORTED_LOCALES);
    let mut out = String::new();
    let mut blocked = false;
    let mut at = 0usize;
    let mut i = 0usize;
    while at < text.len() && !blocked {
        let want = usize::from(lens.get(i % lens.len().max(1)).copied().unwrap_or(7)) % 64 + 1;
        let mut end = (at + want).min(text.len());
        while !text.is_char_boundary(end) {
            end += 1;
        }
        for ev in sg.push(&text[at..end]) {
            match ev.as_segment() {
                Some((seg, _)) => out.push_str(seg),
                None => blocked = true,
            }
        }
        at = end;
        i += 1;
    }
    if !blocked {
        for ev in sg.finish() {
            match ev.as_segment() {
                Some((seg, _)) => out.push_str(seg),
                None => blocked = true,
            }
        }
    }
    if batch.decision.action == GuardAction::Block {
        assert!(blocked, "batch Blocks, stream does not: {text:?}");
    } else {
        assert!(!blocked, "stream Blocks, batch does not: {text:?}");
        assert_eq!(out, batch.text, "stream != batch for {text:?}");
    }
});
