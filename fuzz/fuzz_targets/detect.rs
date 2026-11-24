//! Fuzz target: the deterministic detection core must never panic on
//! arbitrary bytes and its byte-offset contract must hold on every input
//! (in-bounds, on char boundaries, span text exact, sorted and
//! non-overlapping) - the same invariants as tests/property.rs, but driven
//! by libFuzzer's coverage-guided corpus so the inputs nobody thought of
//! still get explored. Both the raw-text path and the normalization-aware
//! path (spans mapped back from the normalized view) are checked, plus the
//! explain, scan-aware masking and streaming-restore consumers.
//!
//! Build/run: `cargo +nightly fuzz run detect` (see Makefile `fuzz`).

#![no_main]

use libfuzzer_sys::fuzz_target;
use redactify::{Detector, Entity, MaskStyle};

fn check_spans(text: &str, ents: &[Entity]) {
    let mut last_end = 0usize;
    for e in ents {
        assert!(e.start < e.end, "zero-length span: {e:?}");
        assert!(e.end <= text.len(), "out of bounds span: {e:?}");
        assert!(
            text.is_char_boundary(e.start) && text.is_char_boundary(e.end),
            "span not on char boundaries: {e:?}"
        );
        assert_eq!(&text[e.start..e.end], e.text.as_str(), "span text mismatch");
        assert!(e.start >= last_end, "overlap or bad order: {ents:?}");
        last_end = e.end;
    }
}

fuzz_target!(|data: &[u8]| {
    // arbitrary bytes -> valid UTF-8 via lossy conversion (the REST layer
    // rejects non-UTF-8 bodies with 400, so the library itself only ever
    // sees &str; the fuzz surface starts at the string boundary)
    let text = String::from_utf8_lossy(data);

    check_spans(&text, &redactify::detect(&text));
    for normalize in [false, true] {
        let d = Detector::new().with_normalization(normalize);
        let report = d.scan(&text);
        check_spans(&text, &report.entities);
        let explained = d.explain(&text);
        assert_eq!(explained.len(), report.entities.len());
        let _ = MaskStyle::Partial {
            keep_last: 4,
            ch: '*',
        }
        .redact_scan(&text, &report);
    }

    // the downstream consumers must survive the same arbitrary input
    let _ = redactify::redact(&text);
    let (anon, vault) = redactify::Vault::pseudonymize(&text);
    let restored = vault.restore(&anon);
    // streaming restore at an input-derived split equals the batch restore
    let mut cut = data.first().map_or(0, |&b| usize::from(b)) % (anon.len() + 1);
    while !anon.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut r = vault.restorer();
    let mut streamed = r.push(&anon[..cut]);
    streamed.push_str(&r.push(&anon[cut..]));
    streamed.push_str(&r.finish());
    assert_eq!(streamed, restored);
});
