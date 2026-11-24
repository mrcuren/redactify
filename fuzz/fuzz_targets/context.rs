//! Fuzz target: caller context never breaks the byte-offset contract, and
//! context only ever ADDS candidates: every finding without context still
//! overlaps a finding with context. (Overlap resolution blocks a candidate
//! only with an overlapping chosen one, so a context-unlocked rule may win
//! over a plain finding, but never leave its bytes without a finding.)
//! The first byte splits the input into context and text.
//!
//! Build/run: `cargo +nightly fuzz run context`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use redactify::{Detector, SUPPORTED_LOCALES};

fuzz_target!(|data: &[u8]| {
    let Some((&cut, rest)) = data.split_first() else {
        return;
    };
    let cut = usize::from(cut).min(rest.len());
    let context = String::from_utf8_lossy(&rest[..cut]);
    let text = String::from_utf8_lossy(&rest[cut..]);
    let ctx = [context.as_ref()];

    let plain = Detector::new()
        .with_locales(SUPPORTED_LOCALES)
        .detect(&text);
    let with = Detector::new()
        .with_locales(SUPPORTED_LOCALES)
        .with_context(&ctx)
        .detect(&text);
    let mut last_end = 0usize;
    for e in &with {
        assert!(e.start < e.end && e.end <= text.len(), "{e:?}");
        assert!(text.is_char_boundary(e.start) && text.is_char_boundary(e.end));
        assert_eq!(&text[e.start..e.end], e.text);
        assert!(e.start >= last_end, "overlap");
        last_end = e.end;
    }
    for p in &plain {
        assert!(
            with.iter().any(|w| w.start < p.end && p.start < w.end),
            "context left {p:?} without an overlapping finding: {with:?}"
        );
    }
});
