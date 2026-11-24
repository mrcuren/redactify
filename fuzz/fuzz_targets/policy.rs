//! Fuzz target: the TOML policy parser never panics on arbitrary text, and
//! a custom rule built from an arbitrary pattern either refuses with a
//! typed error or yields spans that keep the engine's byte-offset contract
//! (the pattern runs under the shared backtracking budget, so no input
//! hangs it). The first byte splits the input into pattern and text.
//!
//! Build/run: `cargo +nightly fuzz run policy`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use redactify::policy::Policy;
use redactify::{CustomRuleSpec, Detector, Guard, GuardTarget};

fuzz_target!(|data: &[u8]| {
    let whole = String::from_utf8_lossy(data);
    let _ = Policy::from_toml(&whole);

    let Some((&cut, rest)) = data.split_first() else {
        return;
    };
    let cut = usize::from(cut).min(rest.len());
    let pattern = String::from_utf8_lossy(&rest[..cut]);
    let text = String::from_utf8_lossy(&rest[cut..]);
    let Ok(rule) = CustomRuleSpec::pattern("FUZZ_RULE", &pattern).compile() else {
        return;
    };
    let rules = [&rule];
    let report = Detector::new().with_custom_rules(&rules).scan(&text);
    let mut last_end = 0usize;
    for e in &report.entities {
        assert!(e.start < e.end && e.end <= text.len(), "{e:?}");
        assert!(text.is_char_boundary(e.start) && text.is_char_boundary(e.end));
        assert_eq!(&text[e.start..e.end], e.text);
        assert!(e.start >= last_end, "overlap");
        last_end = e.end;
    }
    let _ = Guard::new(GuardTarget::UserPrompt)
        .with_custom_rules(&rules)
        .sanitize(&text);
});
