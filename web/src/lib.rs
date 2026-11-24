//! The in-browser demo of redactify (GitHub Pages): one analysis entry
//! point shared by the WebAssembly export and the native gallery generator,
//! so the live demo and the example gallery come from the same code path.
//!
//! The text never leaves the browser: the engine runs in the page, with no
//! network access of its own.

use redactify::{Guard, GuardAction, GuardTarget};
use serde_json::{json, Value};

/// Byte offset -> UTF-16 code unit offset (JavaScript string indices).
fn utf16_index(text: &str, byte: usize) -> usize {
    text[..byte].encode_utf16().count()
}

/// Analyzes `text` the way the guard API does: the decision, its
/// rationale, the emitted text and the detected entities (byte and UTF-16
/// offsets, so a page can highlight them).
///
/// `locales_csv` lists locale packs (unknown codes are ignored; empty
/// selects the default tr+en set); `target` is a guard target name
/// (`user_prompt`, `tool_response`, `model_output`; anything else is
/// `user_prompt`). On Block the library returns the raw text (the caller
/// decides); the demo shows what the REST API returns there instead, the
/// loggable re-mask (`output_is_remask: true`).
#[must_use]
pub fn analyze(text: &str, locales_csv: &str, target: &str) -> Value {
    let locales: Vec<&str> = locales_csv
        .split(',')
        .map(str::trim)
        .filter(|s| redactify::SUPPORTED_LOCALES.contains(s))
        .collect();
    let target: GuardTarget = target.parse().unwrap_or(GuardTarget::UserPrompt);
    let guard = Guard::new(target).with_locales(&locales);
    let result = guard.sanitize(text);
    let blocked = result.decision.action == GuardAction::Block;
    let output = if blocked {
        guard.mask_all(text)
    } else {
        result.text
    };
    let entities: Vec<Value> = guard
        .detector()
        .with_normalization(true)
        .detect(text)
        .iter()
        .map(|e| {
            json!({
                "kind": e.kind.to_string(),
                "score": e.score,
                "start_byte": e.start,
                "end_byte": e.end,
                "start_utf16": utf16_index(text, e.start),
                "end_utf16": utf16_index(text, e.end),
            })
        })
        .collect();
    json!({
        "decision": format!("{:?}", result.decision.action),
        "rationale": result.decision.rationale,
        "output": output,
        "output_is_remask": blocked,
        "entities": entities,
    })
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use wasm_bindgen::prelude::*;

    /// [`super::analyze`] as a JSON string (no JS-object bindings needed).
    #[wasm_bindgen]
    pub fn analyze(text: &str, locales_csv: &str, target: &str) -> String {
        super::analyze(text, locales_csv, target).to_string()
    }

    /// The locale pack codes, comma-separated.
    #[wasm_bindgen]
    pub fn supported_locales() -> String {
        redactify::SUPPORTED_LOCALES.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::analyze;

    #[test]
    fn masks_and_reports_utf16_offsets() {
        let v = analyze("Caf\u{e9} \u{2014} TCKN 12345678950", "", "user_prompt");
        assert_eq!(v["decision"], "Mask");
        assert_eq!(v["output"], "Caf\u{e9} \u{2014} TCKN [TCKN]");
        let e = &v["entities"][0];
        assert_eq!(e["kind"], "TCKN");
        // the prefix is 12 UTF-16 units but 15 bytes (e-acute 2, em dash 3)
        assert_eq!(e["start_utf16"], 12);
        assert_eq!(e["start_byte"], 15);
    }

    #[test]
    fn block_shows_the_loggable_remask() {
        let v = analyze("key AKIAIOSFODNN7EXAMPLE", "", "user_prompt");
        assert_eq!(v["decision"], "Block");
        assert_eq!(v["output_is_remask"], true);
        assert_eq!(v["output"], "key [SECRET:AWS_ACCESS_KEY]");
    }

    #[test]
    fn unknown_locales_and_targets_fall_back() {
        let v = analyze("nhs 9434765870", "uk,XX,", "nope");
        assert_eq!(v["output"], "nhs [UK_NHS]");
    }
}
