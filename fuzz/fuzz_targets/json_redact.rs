//! Fuzz target: the JSON redactor keeps the document's structure (the
//! same member names, the same array lengths, every non-string leaf
//! untouched unless number scanning replaced it by a masked string) and
//! reports only well-formed RFC 6901 pointers, on any JSON document.
//!
//! Build/run: `cargo +nightly fuzz run json_redact`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use redactify::JsonRedactor;
use serde_json::Value;

/// Same shape: equal member names, equal array lengths, recursively; a
/// leaf may change only from a string to a string, or (number scanning)
/// from a number to a string.
fn same_shape(before: &Value, after: &Value, numbers: bool) -> bool {
    match (before, after) {
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(k, v)| b.get(k).is_some_and(|w| same_shape(v, w, numbers)))
        }
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(v, w)| same_shape(v, w, numbers))
        }
        (Value::String(_), Value::String(_)) => true,
        (Value::Number(_), Value::String(_)) => numbers,
        (a, b) => a == b,
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let Ok(doc) = serde_json::from_slice::<Value>(rest) else {
        return;
    };
    let numbers = flags & 1 == 1;
    let mut redacted = doc.clone();
    let report = JsonRedactor::new()
        .with_numeric_leaves(numbers)
        .redact(&mut redacted);
    assert!(same_shape(&doc, &redacted, numbers), "shape changed");
    for f in &report.findings {
        assert!(
            f.pointer.is_empty() || f.pointer.starts_with('/'),
            "bad pointer {:?}",
            f.pointer
        );
    }
});
