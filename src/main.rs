//! `redactify` CLI - detects Turkish PII in text, prints a masked output,
//! and optionally runs the full guard pipeline (deterministic rules + policy).
//!
//! Usage:
//! ```text
//! redactify "TCKN'm 12345678950"                  # PII detect + mask
//! redactify --guard "http://169.254.169.254/x"    # full guard decision
//! cat document.txt | redactify                     # from stdin (UTF-8)
//! ```

use std::io::Read;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // parse --target <kind> first, then the mode flag
    let mut target = redactify::policy::GuardTarget::UserPrompt;
    let mut locale_filter: Option<Vec<String>> = None;
    let mut remaining: Vec<String> = Vec::new();
    let mut skip_next = false;
    for (i, arg) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--target" || arg == "-t" {
            if let Some(kind) = args.get(i + 1) {
                target = match kind.as_str() {
                    "tool" | "tool-response" => redactify::policy::GuardTarget::ToolResponse,
                    "model" | "model-output" => redactify::policy::GuardTarget::ModelOutput,
                    _ => redactify::policy::GuardTarget::UserPrompt,
                };
                skip_next = true;
            }
        } else if arg == "--locale" || arg == "-l" {
            if let Some(kind) = args.get(i + 1) {
                locale_filter = Some(kind.split(',').map(String::from).collect());
                skip_next = true;
            }
        } else {
            remaining.push(arg.clone());
        }
    }

    // parse --format json
    let json_format = remaining.iter().any(|a| a == "--json" || a == "-j");
    remaining.retain(|a| a != "--json" && a != "-j");

    let (mode, text) = match remaining.split_first() {
        Some((flag, rest)) if flag == "--guard" || flag == "-g" => {
            (Mode::Guard, rest.first().cloned())
        }
        Some((flag, rest)) if flag == "--sanitize" || flag == "-s" => {
            (Mode::Sanitize, rest.first().cloned())
        }
        Some((flag, rest)) if flag == "--encode" || flag == "-e" => {
            (Mode::Encode, rest.first().cloned())
        }
        Some((flag, rest)) if flag == "--vault" || flag == "-v" => {
            (Mode::Vault, rest.first().cloned())
        }
        Some((first, _)) => (Mode::Detect, Some(first.clone())),
        None => (Mode::Detect, None),
    };

    let text = match text {
        Some(t) => t,
        None => {
            let mut buf = String::new();
            if std::io::stdin().read_to_string(&mut buf).is_err() {
                eprintln!("failed to read input (UTF-8 expected)");
                std::process::exit(1);
            }
            buf
        }
    };

    match mode {
        Mode::Guard => run_guard(&text, &target, json_format),
        Mode::Sanitize => run_sanitize(&text, &target),
        Mode::Encode => run_encode(&text),
        Mode::Vault => run_vault(&text),
        Mode::Detect => run_detect(&text, json_format, locale_filter.as_deref()),
    }
}

enum Mode {
    Detect,
    Guard,
    Sanitize,
    Encode,
    Vault,
}

fn run_detect(text: &str, json_format: bool, locale_filter: Option<&[String]>) {
    let ents = match locale_filter {
        Some(locales) => {
            let refs: Vec<&str> = locales.iter().map(String::as_str).collect();
            redactify::detect_with_locales(text, &refs)
        }
        None => redactify::detect(text),
    };
    if json_format {
        print_json_detect(text, &ents);
        return;
    }
    if ents.is_empty() {
        println!("No PII found.");
        return;
    }
    println!(
        "{:<13} {:>8} {:>8} {:>5}  TEXT",
        "TYPE", "BEGIN", "END", "SCORE"
    );
    for e in &ents {
        println!(
            "{:<13} {:>8} {:>8} {:>5.2}  {}",
            e.kind, e.start, e.end, e.score, e.text
        );
    }
    println!();
    println!("{}", redactify::redact(text));
}

fn run_guard(text: &str, target: &redactify::policy::GuardTarget, json_format: bool) {
    use redactify::policy;

    let d = policy::guard_targeted(text, target);
    if json_format {
        print_json_guard(&d);
        return;
    }

    println!("{:<12} {:?}", "ACTION:", d.action);
    println!("{:<12} {}", "RATIONALE:", d.rationale);

    if !d.mask_summary.is_empty() {
        println!("{:<12} {}", "PII FOUND:", d.mask_summary.join(", "));
    }

    if !d.verdicts.is_empty() {
        println!();
        println!(
            "{:<16} {:>6} {:>8}  RATIONALE",
            "CATEGORY", "SCORE", "SEVERITY"
        );
        for v in &d.verdicts {
            println!(
                "{:<16} {:>6.2} {:>8}  {}",
                v.category.as_str(),
                v.score,
                v.severity.as_str(),
                v.rationale
            );
        }
    }

    // exit code: 0 for Allow/Mask/Log, 1 for Block
    if d.action == policy::GuardAction::Block {
        std::process::exit(1);
    }
}

fn run_sanitize(text: &str, target: &redactify::policy::GuardTarget) {
    use redactify::policy;

    let r = policy::sanitize(text, target);
    println!("{:<12} {:?}", "ACTION:", r.decision.action);
    println!("{:<12} {}", "RATIONALE:", r.decision.rationale);
    if !r.decision.mask_summary.is_empty() {
        println!(
            "{:<12} {}",
            "PII FOUND:",
            r.decision.mask_summary.join(", ")
        );
    }
    println!();
    println!("{}", r.text);

    if r.decision.action == policy::GuardAction::Block {
        std::process::exit(1);
    }
}

fn run_encode(text: &str) {
    println!("{}", redactify::guard::encode_html(text));
}

fn print_json_detect(text: &str, ents: &[redactify::Entity]) {
    let entities: Vec<serde_json::Value> = ents
        .iter()
        .map(|e| {
            serde_json::json!({
                "type": e.kind.as_str(),
                "start": e.start,
                "end": e.end,
                "score": e.score,
                "text": e.text,
            })
        })
        .collect();
    let out = serde_json::json!({
        "input": text,
        "entities": entities,
    });
    println!("{out}");
}

fn print_json_guard(d: &redactify::policy::Decision) {
    let verdicts: Vec<serde_json::Value> = d
        .verdicts
        .iter()
        .map(|v| {
            serde_json::json!({
                "category": v.category.as_str(),
                "score": v.score,
                "severity": v.severity.as_str(),
                "action": format!("{:?}", v.action),
                "rationale": v.rationale,
            })
        })
        .collect();
    let out = serde_json::json!({
        "action": format!("{:?}", d.action),
        "top_signal": d.top_signal.as_ref().map(|s| serde_json::json!({
            "kind": format!("{:?}", s.kind),
            "score": s.score,
        })),
        "pii_found": d.mask_summary,
        "rationale": d.rationale,
        "verdicts": verdicts,
    });
    println!("{out}");
    if d.action == redactify::policy::GuardAction::Block {
        std::process::exit(1);
    }
}

fn run_vault(text: &str) {
    let (anon, vault) = redactify::Vault::anonymize(text);
    println!("{:<16} {}", "ANONYMIZED:", anon);
    println!("{:<16} {} unique PII entries", "VAULT:", vault.len());
    for (placeholder, original) in vault.entries_iter() {
        println!("  [{placeholder}] -> {original}");
    }

    // Demo the round-trip
    let restored = vault.deanonymize(&anon);
    println!();
    println!("{:<16} {}", "RESTORED:", restored);
    println!();
    println!("Library API:");
    println!("  let (anon, vault) = Vault::anonymize(prompt);");
    println!("  let response = llm_call(&anon);");
    println!("  let natural = vault.deanonymize(&response);");
}
