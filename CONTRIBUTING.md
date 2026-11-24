# Contributing to redactify

Thanks for taking the time to contribute!

The following is a set of guidelines for contributing to redactify. The project is a
small Rust workspace (the root library crate plus the optional `redactify-mcp` server).

Issues and discussions may be written in English or Turkish. Code, comments and
documentation are in English; `cargo test --test english_only` enforces it outside
the functional allowlist (locale rules, cue words, test fixtures).

## Code of Conduct

This project has adopted the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code. Please report unacceptable
behavior through a private GitHub security advisory or by contacting a maintainer
directly.

## What do I need to know before I get started?

### Design invariants

Before proposing changes, please read the [README](README.md) and keep three invariants
in mind:

1. **Checksum before claim.** An identifier with a check digit (TCKN, IBAN, VKN,
   credit card) is confirmed by its validator before it is reported; one without
   a check digit whose shape collides with everyday numbers is claimed only next
   to a context label. Precision is deliberately preferred over raw recall.
2. **Differential parity contract.** Detection behavior is locked by the
   differential and corpus suites: `tests/stream_differential.rs` (stream == batch
   at every char-boundary split, corpus + locale variants) and `tests/corpus.rs`
   (exact spans over the synthetic corpus). Any change that alters behavior on
   these suites must be avoided or explicitly justified in the PR (see "Parity-affecting changes"
   below).
3. **Zero-model core.** The library must stay dependency-light (`fancy-regex`, `aho-corasick`, `unicode-normalization`, `base64`, `serde_json`, `regex-syntax`, `thiserror`) and
   never require an NLP model, network access, or any external runtime. NER-style
   detection stays OUT of the default build (it is an optional `ml-onnx` layer
   the host opts into; the zero-model core never needs it).

### Rights of contribution

By submitting a contribution, you represent that you have the legal right to contribute
the code and that it may be distributed under the project's dual `MIT OR Apache-2.0`
license (see [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE)).
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work shall be dual licensed as such, without any additional
terms or conditions.
Furthermore, you confirm that your contribution does not knowingly contain proprietary
or confidential information or code.

### PR guidelines

- Keep commits small and messages clear (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`
  prefixes are appreciated but not required).
- All quality gates must pass locally before you push (CI will run the same):
  ```bash
  cargo fmt --check
  cargo clippy --all-targets -- -D warnings
  cargo test
  ```
- Do not edit `Cargo.lock` semantics or bump the version in a PR; maintainers handle
  releases.

## Getting started with the code

```bash
git clone <your-fork> && cd redactify
cargo build
cargo test
```

Layout (see [README §Use from Rust](README.md#use-from-rust)):

| Path | Purpose |
|---|---|
| `src/pii/locales/<locale>/<identifier>.rs` | one file per identifier: validator + pattern + cue policy together |
| `src/pii/locales/mod.rs` | `rules_for_locales()` registration (order matters: narrower rule before broader) |
| `src/pii/entity.rs` | `EntityType` variants, labels, overlap priorities |
| `src/pii/context.rs` | context-cue windows (VKN mandatory cue, plate score boost) |
| `src/pii/detect.rs` | candidate collection, scoring, overlap resolution |
| `src/pii/redact.rs` | masking; `src/pii/vault.rs` reversible pseudonymization (vault) |
| `src/guard/` | L0/L2/L3/L4 guards: rules, normalization, output guards, ML interface |
| `src/policy.rs` (+ `src/policy/stream.rs`) | decision core (severity banding, per-category thresholds, streaming) |
| `src/api/mod.rs` | optional REST server (`api` feature) |
| `tests/` | golden vectors, detection behavior, corpus parity, EU ids, streaming differential, REST, CLI-JSON |
| `data/pii_corpus.jsonl` | 155-line synthetic labeled corpus (no real PII; third-party, Apache-2.0, see `data/pii_corpus.SOURCES.md`) |
| `examples/` | `quickstart.rs` (library tour) and `api_bench.rs` (REST throughput, `api` feature) |

Every file under `data/` has a `<name>.SOURCES.md` note (origin, licence,
changes, what the set is not evidence of); a new data file needs one too.

### How to test?

`cargo test` runs unit tests, doctests and integration tests (including the
155-line corpus parity test). The evidence behind each README claim is listed in
[README §Validation](README.md#validation).

### Parity-affecting changes

If your change alters detection on any differential suite input, the PR must
state this explicitly and include the re-run diff. Behavior divergences are acceptable
when they fix a documented correctness bug, but they must be justified, tested,
and recorded, never accidental.

## Adding a new identifier detector

Adding detectors for new PII types (or new locales) is the most valuable contribution.
Please follow these steps:

1. **Add the identifier file** under `src/pii/locales/<locale>/<name>.rs`
   (validator, pattern and cues live together):
   - Pure function `pub fn valid_<name>(&str) -> bool`, no panics, no allocations beyond need.
   - If the identifier has a checksum (mod-97, Luhn, NVI-style, ...), implement it and
     **document the official source** of the algorithm in the module docs.
   - Mind Rust arithmetic pitfalls: use `rem_euclid` where non-negative modulo
     semantics are expected (negative operands), and `u128`/streamed mod arithmetic
     for very long numeric strings.
2. **Register the rule** in `rules_for_locales()` (`src/pii/locales/mod.rs`):
   - Prefer **specific** patterns; document why lookarounds (if any) are needed.
   - Note that `fancy-regex` supports lookarounds; patterns are compiled once via
     `LazyLock` (the `rule!` macro). Mind the ORDER rule: the narrower pattern
     must be evaluated first (e.g. `en::itin` before `en::ssn`).
3. **Set entity type and priority** in `src/pii/entity.rs`:
   - Add the `EntityType` variant, its `as_str()` label and `priority()`
     (lower wins overlaps). Give the rule a justified confidence score (the
      last `rule!` argument in the identifier file).
4. **Add tests** (all three layers):
   - Unit tests in the validator module (golden vectors: valid + invalid + edge cases).
   - Detection tests in `tests/detect.rs` (boundaries, overlaps, context cues).
   - If you add corpus rows, regenerate expectations consistently - never check in real
     personal data; synthetic, checksum-valid values only.
5. **Documentation**: rustdoc with doctest examples is required for every public item
   (`#![deny(missing_docs)]` is enforced).

## Fixing bugs and improving the code

Please review the open GitHub issues first. Detections that changed between releases
should come with a failing test that reproduces the bug before the fix.

## Reporting security or privacy issues

See [SECURITY.md](SECURITY.md). In short: use private GitHub vulnerability reporting,
not public issues, for anything sensitive.

## Contacting us

Open a GitHub issue or discussion on this repository.
