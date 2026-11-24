//! English-only prose gate: fails when Turkish prose appears where it
//! should not.
//!
//! Turkish is FUNCTIONAL in this codebase (tr locale rules, cue words,
//! test fixtures, detection regexes) - those locations are allowlisted
//! below. Everything else must be English: the gate keeps new
//! human-language content (docs, comments, CI, config) from quietly
//! reintroducing Turkish. Run alone with `cargo test --test english_only`.
//!
//! A line fails when it holds a Turkish diacritic, or, in Markdown, one of
//! a few Turkish function words. The scan starts at the package root, so
//! it covers the repository checkout and, in a published package, the
//! packaged files only.

use std::path::{Path, PathBuf};

/// Directories never scanned (build output, local model exports, VCS).
const EXCLUDE_DIRS: &[&str] = &[".git", "target", "ml_models", "__pycache__"];

/// File extensions scanned for prose.
const SCAN_EXTENSIONS: &[&str] = &["rs", "md", "toml", "yml", "yaml", "json", "txt", "sh"];

/// File names scanned regardless of extension.
const SCAN_NAMES: &[&str] = &[
    "Makefile",
    "Dockerfile",
    "docker-compose.yml",
    "NOTICE",
    ".gitignore",
    ".dockerignore",
];

/// Path prefixes where Turkish is functional (fixtures, cue words,
/// detection patterns, sample data). New prose in these files still shows
/// up in review; the gate tolerates them on purpose.
const ALLOWED_PREFIXES: &[&str] = &[
    "src/pii/",  // tr locale rules, cue words, fixtures
    "tests/",    // test fixtures (Turkish attack/data strings)
    "examples/", // demo payloads
    "benches/",  // bench payloads
    "data/",     // eval sets + SOURCES notes (sample rows)
    "crates/",   // MCP fixtures
];

/// Single files where Turkish is functional.
const ALLOWED_FILES: &[&str] = &[
    // Turkish detection regexes + doctest payloads
    "src/guard/rules.rs",
    // doctest/test fixtures + functional character references
    "src/lib.rs",
    "src/main.rs",
    "src/policy.rs",
    "src/policy/stream.rs",
    "src/policy/relevance.rs",
    "src/guard/eval.rs",
    "src/guard/ml.rs",
    "src/guard/normalize.rs", // Turkish multibyte round-trip fixtures
    "docs/relevance.md",
    // fixture lines inside otherwise-English docs
    "ML_SETUP.md",
    "CHANGELOG.md", // one entry lists the functional letters
    "data/ner_testset_tr.SOURCES.md",
    // third-party copyright lines reproduced verbatim (authors' names as
    // written, e.g. "Kaan Öztürk", "Ubeyde Emir Özdemir")
    "NOTICE",
];

/// Turkish letters with diacritics (the dotted capital included, plain
/// ASCII `i` not).
const DIACRITICS: &[char] = &['ç', 'ğ', 'ı', 'ö', 'ş', 'ü', 'Ç', 'Ğ', 'İ', 'Ö', 'Ş', 'Ü'];

/// Turkish function words, checked in Markdown only (whole words).
const PROSE_WORDS: &[&str] = &[
    "ve",
    "ile",
    "için",
    "olarak",
    "Ancak",
    "Ayrıca",
    "Kullanım",
    "Örnek",
];

fn is_scanned(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if SCAN_NAMES.contains(&name) {
        return true;
    }
    name != "Cargo.lock"
        && path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| SCAN_EXTENSIONS.contains(&e))
}

fn allowed(rel: &str) -> bool {
    ALLOWED_PREFIXES.iter().any(|p| rel.starts_with(p)) || ALLOWED_FILES.contains(&rel)
}

/// Whole words of `line` (runs of alphanumerics and `_`).
fn words(line: &str) -> impl Iterator<Item = &str> {
    line.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
}

/// Every scanned file under `dir`, recursively, excluded directories
/// skipped.
fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if !EXCLUDE_DIRS.iter().any(|d| name == *d) {
                collect(&path, out);
            }
        } else if is_scanned(&path) {
            out.push(path);
        }
    }
}

#[test]
fn prose_outside_the_functional_allowlist_is_english() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect(root, &mut files);
    files.sort();
    let mut offenders = Vec::new();
    for path in &files {
        let rel = path
            .strip_prefix(root)
            .expect("collected under the root")
            .to_string_lossy()
            .replace('\\', "/");
        if allowed(&rel) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue; // not UTF-8: no prose to check
        };
        let markdown = path.extension().is_some_and(|e| e == "md");
        for (n, line) in text.lines().enumerate() {
            let why = if line.contains(DIACRITICS) {
                "diacritic"
            } else if markdown && words(line).any(|w| PROSE_WORDS.contains(&w)) {
                "turkish word"
            } else {
                continue;
            };
            let excerpt: String = line.trim().chars().take(100).collect();
            offenders.push(format!("{rel}:{}: {why}: {excerpt}", n + 1));
        }
    }
    assert!(
        offenders.is_empty(),
        "{} unexpected Turkish line(s):\n{}",
        offenders.len(),
        offenders.join("\n")
    );
}
