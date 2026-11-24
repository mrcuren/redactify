//! Writes the example gallery of the demo page from the REAL engine output:
//! reads fixture JSONL (one `{"id", "group", "title", "text", "locales"?,
//! "target"?}` per line) and writes a JSON document with every input and
//! its analysis. The gallery is generated in CI, never committed, so it
//! cannot drift from the engine.
//!
//! Usage: `gen-gallery <fixtures.jsonl> <gallery.json>`

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let (Some(input), Some(output)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: gen-gallery <fixtures.jsonl> <gallery.json>");
        return ExitCode::FAILURE;
    };
    let fixtures = match std::fs::read_to_string(input) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read {input}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut examples = Vec::new();
    for (n, line) in fixtures.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let fixture: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{input}:{}: {e}", n + 1);
                return ExitCode::FAILURE;
            }
        };
        let Some(text) = fixture["text"].as_str() else {
            eprintln!("{input}:{}: missing \"text\"", n + 1);
            return ExitCode::FAILURE;
        };
        let locales = fixture["locales"].as_str().unwrap_or("");
        let target = fixture["target"].as_str().unwrap_or("user_prompt");
        let mut example = redactify_web::analyze(text, locales, target);
        example["id"] = fixture["id"].clone();
        example["group"] = fixture["group"].clone();
        example["title"] = fixture["title"].clone();
        example["input"] = text.into();
        example["locales"] = locales.into();
        example["target"] = target.into();
        examples.push(example);
    }
    let doc = serde_json::json!({ "examples": examples });
    let json = match serde_json::to_string_pretty(&doc) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot serialize the gallery: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = std::fs::write(output, json) {
        eprintln!("cannot write {output}: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
