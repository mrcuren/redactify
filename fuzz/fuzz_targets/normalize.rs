//! Fuzz target: the L0 normalization stack (NFKC, invisible-character
//! stripping, confusable folding, suspect base64 decode with layered views,
//! the percent and character-reference escape decoders) must never panic
//! on arbitrary bytes - it is the first code that touches untrusted input
//! in the guard pipeline (encoding-attack defense), so a panic here would
//! be a denial-of-service vector on every entry point.
//!
//! Beyond "no panic", the offset map of `normalize_for_scan_with_map` is
//! checked against its documented invariants (it drives raw-text masking:
//! a broken map would mask the wrong bytes), and both escape decoders are
//! checked to shrink their input (single round, never an expansion).
//!
//! Build/run: `cargo +nightly fuzz run normalize` (see Makefile `fuzz`).

#![no_main]

use libfuzzer_sys::fuzz_target;
use redactify::guard::normalize::{
    decode_html_refs, layered_views, normalize_for_scan, normalize_for_scan_with_map,
    percent_decode_once,
};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    for view in layered_views(&text, 2) {
        let _ = normalize_for_scan(&view);
    }
    let norm = normalize_for_scan(&text);

    // map invariants: same target, len + 1 entries, last entry == text
    // length, never decreasing, every entry a char boundary of the text
    if let Some((mapped, map)) = normalize_for_scan_with_map(&text) {
        assert_eq!(mapped, norm, "map target differs from normalize_for_scan");
        assert_eq!(map.len(), mapped.len() + 1, "map length");
        assert_eq!(map[mapped.len()], text.len(), "last map entry");
        for w in map.windows(2) {
            assert!(w[0] <= w[1], "map decreases");
        }
        for &i in &map {
            assert!(
                text.is_char_boundary(i),
                "map entry {i} off a char boundary"
            );
        }
    }

    // both escape decoders: one round, output strictly shorter than input
    if let Some(p) = percent_decode_once(&text) {
        assert!(p.len() < text.len(), "percent decoding expanded the text");
        let _ = normalize_for_scan(&p);
    }
    if let Some(h) = decode_html_refs(&text) {
        assert!(h.len() < text.len(), "reference decoding expanded the text");
        let _ = normalize_for_scan(&h);
    }
    let _ = percent_decode_once(&norm);
    let _ = decode_html_refs(&norm);
});
