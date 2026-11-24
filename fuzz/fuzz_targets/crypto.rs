//! Fuzz target: the cryptocurrency address validators never panic, and an
//! accepted address has the shape its specification fixes (EIP-55: `0x` +
//! 40 hex digits with both letter cases; base58check: 26-35 characters
//! starting `1` or `3`; segwit: 14-74 characters starting `bc1`, one case)
//! and is reported whole by `detect` when it stands alone.
//!
//! Build/run: `cargo +nightly fuzz run crypto`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use redactify::{detect, valid_btc_address, valid_eth_address, EntityType};

fn reported_whole(addr: &str) -> bool {
    let text = format!("wallet {addr} ok");
    detect(&text)
        .iter()
        .any(|e| e.kind == EntityType::CryptoAddress && e.text == addr)
}

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    if valid_eth_address(&s) {
        assert!(s.len() == 42 && s.starts_with("0x"), "{s:?}");
        let hex = &s[2..];
        assert!(hex.bytes().any(|b| b.is_ascii_uppercase()));
        assert!(hex.bytes().any(|b| b.is_ascii_lowercase()));
        assert!(reported_whole(&s), "{s:?}");
    }
    if valid_btc_address(&s) {
        let lower = s.to_ascii_lowercase();
        if lower.starts_with("bc1") {
            assert!((14..=74).contains(&s.len()), "{s:?}");
            assert!(
                s == lower || s == s.to_ascii_uppercase(),
                "mixed case {s:?}"
            );
            // BIP173: the other case of a valid address is valid too
            assert!(valid_btc_address(&lower) && valid_btc_address(&s.to_ascii_uppercase()));
        } else {
            assert!((26..=35).contains(&s.len()), "{s:?}");
            assert!(s.starts_with('1') || s.starts_with('3'), "{s:?}");
        }
        assert!(reported_whole(&s), "{s:?}");
    }
});
