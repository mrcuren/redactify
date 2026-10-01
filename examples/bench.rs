//! Micro-benchmark: measures the full local pipeline over a JSONL input file.
//!
//! Two chains are timed separately, in-process, single-threaded:
//! 1. `detect + redact` (the PII core alone),
//! 2. `policy::guard_all` (PII + deterministic guards + decision + rationale).
//!
//! Usage: `cargo run --release --example bench -- input.jsonl [iterations]`
//! Prints total seconds, ms/text and texts/second for the best iteration.

use std::io::BufRead;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .expect("usage: bench <input.jsonl> [iterations]");
    let iterations: usize = args.next().map_or(10, |s| s.parse().expect("iterations"));

    let file = std::fs::File::open(&path).expect("input file opens");
    let texts: Vec<String> = std::io::BufReader::new(file)
        .lines()
        .map(|l| {
            let l = l.expect("line reads");
            let v: serde_json::Value = serde_json::from_str(&l).expect("valid JSON line");
            v["text"].as_str().expect("text field").to_owned()
        })
        .collect();
    println!(
        "input: {path} ({} texts, {} iterations)",
        texts.len(),
        iterations
    );

    // warm-up
    for t in texts.iter().take(5) {
        let _ = redactify::redact(t);
        let _ = redactify::policy::guard_all(t);
    }

    let mut best_redact = f64::MAX;
    let mut best_guard = f64::MAX;
    for _ in 0..iterations {
        let t0 = std::time::Instant::now();
        for t in &texts {
            let _ = redactify::redact(t);
        }
        best_redact = best_redact.min(t0.elapsed().as_secs_f64());

        let t0 = std::time::Instant::now();
        for t in &texts {
            let _ = redactify::policy::guard_all(t);
        }
        best_guard = best_guard.min(t0.elapsed().as_secs_f64());
    }

    let n = texts.len() as f64;
    for (name, secs) in [
        ("detect+redact", best_redact),
        ("guard_all (full chain)", best_guard),
    ] {
        println!(
            "{name:<26} best {secs:.4} s  |  {:.3} ms/text  |  {:.0} texts/s",
            secs * 1000.0 / n,
            n / secs
        );
    }
}
