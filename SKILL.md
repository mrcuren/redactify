---
name: redactify-rules
description: >
  Project rules for developing redactify: Rust architecture, locale-based file
  layout, sustainable extension recipes (new locale / rule / guard), the exact
  mistakes already made and their permanent fixes, quality gates, and references
  to the installed rust-skills rule set. Read before writing or reviewing any
  code in this repository.
license: Apache-2.0
metadata:
  project: redactify
  rule-source: leonardomso/rust-skills (MIT), installed at ~/.zcode/skills/rust-skills
---

# redactify development rules

Read this file before writing, refactoring or reviewing code in this repo.
Every "lesson" below comes from a real mistake made in this project, together
with its permanent fix. Following these rules prevents repeating them.

## 1) Immutable surface rules (never violate)

1. **README.md is FROZEN.** Do not edit, extend or restructure it. All new
   project rules, architecture notes and decisions go into THIS file
   (`SKILL.md`) or `research/ROADMAP.md` (which is local-only, never pushed).
2. **No em dash (U+2014) or en dash (U+2013) anywhere in the repository.** Use the ASCII hyphen `-` or rephrase.
3. **All code comments, rustdoc, error messages, rationale strings and CLI
   output are in ENGLISH.** Turkish appears only as *test data* and as *cue
   words* (e.g. `"vergi"`, `"plaka"`) because those are literally the strings
   being detected.
4. **No version tags in commit messages or docs.** Version bumps happen only in
   `Cargo.toml` when the owner asks. The frozen README files keep their historical
   version references; do not edit them to comply (rule 1.1 wins).
5. **No external product/project names** (competitors, the original Python
   library) in any pushed file. Internal analysis lives in `research/`
   (gitignored). Exception: this file cites `leonardomso/rust-skills` because
   the owner explicitly asked for the attribution.
6. **No assumptions.** Any new pattern, format or claim must be backed by a
   verified source or a measured test. If evidence is missing, record it as a
   decision-to-make, do not implement.
7. **Single-commit history.** Amend the existing commit and force-push; keep
   the commit message accurate (no version tags, no em-dashes).

## 2) Repository layout (do not invent new top-level structure)

```
src/
├── lib.rs            crate docs + flat public API re-exports (API is frozen here)
├── main.rs           thin CLI entry point (no logic)
├── pii/              L1 detection core
│   ├── rule.rs       Rule { kind, regex, validator, ContextPolicy, score }
│   ├── context.rs    shared character-based cue windows (has_cue)
│   ├── detect.rs     locale-agnostic engine (line-scan, policy, overlap)
│   ├── redact.rs     mask templating
│   └── locales/
│       ├── generic.rs        e-mail + Luhn card (locale-independent)
│       ├── tr/               one file per Turkish identifier
│       └── en/               one file per US identifier
├── guard/            L0/L2/L3/L4 guards
│   ├── ml.rs         ML interface: MlClassifier trait, MlRouter, mock classifiers
│   ├── rules.rs      SQL / XSS / SSRF-URL / obfuscation / deep-PII /
│   │                 authority-impersonation / NoSQL / XXE / CRLF / XPath rules
│   ├── normalize.rs  NFKC, invisible stripping, base64 suspects, layered_views
│   └── output.rs     L4: HTML entity encoding, JSON schema validation
└── policy.rs         decision core (Allow/Log/Mask/Block + rationale)
tests/                golden vectors, detection behavior, EN rules, corpus parity
examples/             quickstart, parity (differential runner)
data/pii_corpus.jsonl synthetic labeled corpus (never commit real PII)
```

Style decisions (from rust-skills `proj-*` rules, applied here):
- feature-based modules (`pii/`, `guard/`), **mod.rs style everywhere**,
  one identifier per locale file (validator + pattern + cues together, zero
  duplication), thin `main.rs` (`proj-lib-main-split`), no `[[bin]]` section
  for a single binary (`proj-bin-dir`).

## 3) Core invariants of the detection engine

1. **Checksum before claim.** A structured identifier is only reported when its
   math validates (TCKN two check digits, IBAN mod-97, Luhn, VKN checksum).
2. **No checksum -> cue required.** Identifiers without a checksum (VKN,
  passports) are never claimed from a bare pattern match; `ContextPolicy::RequiredCue`
   is mandatory for them.
3. **Boost, never punish.** Cue-less findings for identifiers WITH structure
   keep a base score (e.g. plate 0.85) and a cue only *raises* it (0.95).
4. **Narrower rule wins.** When two rules match the same span (ITIN vs SSN
   shape), the NARROWER pattern must be evaluated first; rule order in
   `locales::all_rules()` is the tie-breaker. Keep `en::itin` before `en::ssn`.
5. **Line-scoped scanning** stays: no entity may span lines; every regex sees
   one line (ReDoS mitigation; fancy-regex has no timeout knob).
6. **`Entity::start/end` are BYTE offsets** (Rust convention, panic-free
   slicing) while label files may use character offsets; convert with
   `char_to_byte` (see `tests/corpus.rs`).
7. **Score scale**: checksum-verified = 1.0; format + mandatory cue = 0.9;
   structural with boost = 0.75/0.85 -> 0.95; strict regex = 0.85; narrow
   pattern = 0.8. New rules must document where they sit and why.

## 4) Rust lessons already paid for (do not repeat)

| Lesson | Rule |
|---|---|
| `(-x) % 10` returns a negative value in Rust | Use `i32` + `rem_euclid(10)` wherever Python-style non-negative modulo is expected (TCKN `d10`). |
| `r"...\"..."` is not an escape; the `\` is literal and the `"` closes the string | For patterns containing `"` use raw strings with a hash: `r#"..."#`. |
| `#[derive(Eq)]` fails on `f32` | Never derive `Eq` for structs containing floats (`Entity` has `score: f32`; only `PartialEq`). |
| Compiling regexes inside a function body recompiles them on EVERY call | Wrap pattern tables in function-local `static LazyLock<...>` (see `guard::rules::compile_rules` and the `rule!` macro). |
| Items after `#[cfg(test)] mod tests` is an error | The test module is ALWAYS the last item in a file. |
| `pub(super)` only reaches the parent module | For cross-branch visibility use `pub(crate)`; module tree visibility must form an unbroken chain up to the re-export. |
| `macro_rules!` needs textual scoping | Shared macros are defined in `locales/mod.rs` (after `mod` declarations) so all locale submodules see them; re-export with `pub(crate) use`. |
| Comparing formatted vs raw values | Sample/placeholder rejection must compare on NORMALIZED DIGITS (SSN `123-45-6789` is the canonical `123456789` with separators stripped), never on the raw matched string. |
| CRLF/Windows line endings | `.gitattributes` enforces LF; never "fix" files to CRLF, and strip `\r` when diffing tool output on this host. |
| Turkish `i/İ/ı` casing | Cue matching goes through `to_lowercase()` + `ı->i` normalization (`context::normalize_tr`); never compare Turkish text case-sensitively. |
| Byte vs character windows | Context windows count CHARACTERS, not bytes; always walk with `char_indices` (`context::char_window`). |
| `unwrap()` in production code | Only in `#[cfg(test)]`. In production, `expect()` exclusively for true invariants (embedded patterns that cannot fail to compile). |

Also applied from the installed rule set (`leonardomso/rust-skills`):
`lint-missing-docs` (deny), `lint-deny-correctness` via `clippy -D warnings`,
`err-expect-bugs-only`, `anti-unwrap-abuse`, `mem-with-capacity`,
`perf-iter-over-index`, `anti-string-for-str` (take `&str`, never `&String`),
`api-must-use`, `test-descriptive-names`, `doc-all-public`. When in doubt,
consult `~/.zcode/skills/rust-skills/rules/<category>-<name>.md`.

## 5) Quality gates (run before every commit)

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                      # all suites must pass
cargo run --release --example parity <parity_inputs.jsonl>   # byte-identical diff
```

- The differential parity suite (184 vectors) locks Turkish detection behavior.
  If a change intentionally diverges, it must be justified, tested and recorded;
  accidental breakage is a bug.
- The synthetic corpus test (140 gold + 15 distractors) must stay green;
  distractor lines must produce zero findings.
- New rules require: unit tests with golden vectors (valid + invalid + edge),
  false-positive counter-tests against the OTHER locale's traffic, and a cue
  policy decision documented in the rule file.

## 6) Extension recipes (follow exactly)

### Add a locale (e.g. `de`)
1. Create `src/pii/locales/de/` with one file per identifier: `mod.rs`
   (module list) plus `<identifier>.rs` containing, in this order:
   module doc, validator (`pub fn valid_x(&str) -> bool`, only if a checksum
   or structure exists), `pub(super) const CUES`, `pub(crate) fn rule()`
   (using the `rule!` macro), then the `#[cfg(test)] mod tests` LAST.
2. Add `EntityType` variants in `pii/entity.rs` (label + priority + score doc).
3. Register rules in `locales::all_rules()`; mind the ORDER rule (narrower
   before broader).
4. Re-export validators in `pii/mod.rs` and `lib.rs` (flat public API).
5. Tests: golden vectors + cross-locale FP counter-tests. No external format
   claim without a verified source (rule 1.6).

### Add a guard rule (L0/L4)
1. Add the pattern table in `guard/rules.rs` as function-local
   `static LazyLock<Vec<(Regex, &str)>>` via `compile_rules` (three severity
   levels: 0.9 / 0.6 / 0.4).
2. Deterministic scoring only; every signal carries `evidence` + human-readable
   `rationale`.
3. Never resolve DNS or guess: URL checks judge literal addresses only.
4. FP counter-tests are mandatory (benign query words, public IPs, natural
   language that resembles the pattern).

### Add an ML-facing piece (future)
Follow `research/ROADMAP.md`: router + parallel twins, thresholds calibrated
by measurement, primary metric always Student-vs-Human.

## 7) Attribution

Development rules partially derive from
[leonardomso/rust-skills](https://github.com/leonardomso/rust-skills) (MIT),
installed at `~/.zcode/skills/rust-skills` (265 rules, 26 categories). Rule
references in section 4 use that set's `category-name` identifiers.
