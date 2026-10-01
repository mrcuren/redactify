# Contributing to redactify

:tada: Thanks for taking the time to contribute! :tada:

The following is a set of guidelines for contributing to redactify. It is modeled on the practices of mature open-source privacy projects, adapted to a
small, single-crate Rust library.

**Türkçe katkı yapmak isteyenler için:** katkılar Türkçe veya İngilizce olabilir; kod
yorumları ve dokümantasyon İngilizce tercih edilir (uluslararası kütüphane).

## Code of Conduct

This project has adopted the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code. Please report unacceptable
behavior through a private GitHub security advisory or by contacting a maintainer
directly.

## What do I need to know before I get started?

### Design invariants

Before proposing changes, please read the [README](README.md) and keep three invariants
in mind:

1. **Checksum before claim.** Every structured identifier (TCKN, IBAN, VKN, credit card)
   is confirmed by a mathematical validator before it is reported. A bare number is
   never PII on its own. Precision is deliberately preferred over raw recall.
2. **Differential parity contract.** Detection behavior is locked by the internal
   differential suite (`examples/parity.rs`, 184 byte-identical vectors). Any change
   that alters behavior on this set must be avoided or explicitly justified in the PR
   (see "Parity-affecting changes" below).
3. **Zero-model core.** The library must stay dependency-light (`fancy-regex`, `unicode-normalization`, `base64`) and
   never require an NLP model, network access, or any external runtime. NER-style detection
   is out of scope for the core crate.

### Rights of contribution

By submitting a contribution, you represent that you have the legal right to contribute
the code and that it may be distributed under the project's Apache-2.0 license.
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

Layout (see [README §Architecture](README.md#architecture)):

| Path | Purpose |
|---|---|
| `src/validators/` | one module per identifier checksum/structure validator |
| `src/patterns.rs` | the pattern table (regex + validator + entity type) |
| `src/context.rs` | context-cue windows (VKN mandatory cue, plate score boost) |
| `src/detect.rs` | candidate collection, scoring, overlap resolution |
| `src/redact.rs` | masking |
| `tests/` | golden vectors, detection behavior, corpus parity |
| `data/pii_corpus.jsonl` | 155-line synthetic labeled corpus (no real PII) |
| `examples/parity.rs` | differential runner used for the parity proof |

### How to test?

`cargo test` runs unit tests, doctests and integration tests (including the
155-line corpus parity test). For the differential parity proof, see `examples/parity.rs` and [README §Validation](README.md#validation).

### Parity-affecting changes

If your change alters detection on any of the 184 differential inputs, the PR must
state this explicitly and include the re-run diff. Behavior divergences are acceptable
when they fix a documented correctness bug (e.g. the plate-alphabet alignment) -
but they must be justified, tested, and recorded, never accidental.

## Adding a new identifier detector

Adding detectors for new PII types (or new locales) is the most valuable contribution.
Please follow these steps:

1. **Add a validator** under `src/validators/<name>.rs`:
   - Pure function `fn valid_<name>(&str) -> bool`, no panics, no allocations beyond need.
   - If the identifier has a checksum (mod-97, Luhn, NVI-style, …), implement it and
     **document the official source** of the algorithm in the module docs.
   - Mind Rust arithmetic pitfalls: use `rem_euclid` where non-negative modulo
     semantics are expected (negative operands), and `u128`/streamed mod arithmetic
     for very long numeric strings.
2. **Register the pattern** in `src/patterns.rs`:
   - Prefer **specific** patterns; document why lookarounds (if any) are needed.
   - Note that `fancy-regex` supports lookarounds; patterns are compiled once via
     `LazyLock`.
3. **Set entity type and priority** in `src/entity.rs`:
   - Add the `EntityType` variant, its `as_str()` label and `priority()`
     (lower wins overlaps). Update `base_score` with a justified confidence value.
4. **Add tests** (all three layers):
   - Unit tests in the validator module (golden vectors: valid + invalid + edge cases).
   - Detection tests in `tests/detect.rs` (boundaries, overlaps, context cues).
   - If you add corpus rows, regenerate expectations consistently - never check in real
     personal data; synthetic, checksum-valid values only.
5. **Documentation**: rustdoc with doctest examples is required for every public item
   (`#![warn(missing_docs)]` is enforced).

## Fixing bugs and improving the code

Please review the open GitHub issues first. Detections that changed between releases
should come with a failing test that reproduces the bug before the fix.

## Reporting security or privacy issues

See [SECURITY.md](SECURITY.md). In short: use private GitHub vulnerability reporting,
not public issues, for anything sensitive.

## Contacting us

Open a GitHub issue or discussion on this repository.
