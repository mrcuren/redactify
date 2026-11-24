# evasion_corpus.jsonl - provenance

**Origin:** written for this project (self-authored). The rows are produced
by a deterministic Python builder, `build_evasion_corpus.py`, that is kept
outside this repository (the repository holds Rust code only). It has no
sampling and no external input: every value is a fixed literal or a fixed
transform (zero-width or soft-hyphen insertion, fullwidth forms, base64
nesting, separator scattering, homoglyph cue words) of the project's own
test identifiers (for example the TCKN test value `12345678950` that also
appears in the crate docs). Re-running the builder on 2026-11-23 produced
a file byte-identical to the committed one.

**Licence:** project data, distributed under the repository licence (MIT
OR Apache-2.0). No third-party text is included.

**Format:** one JSON object per line, `{"id", "family", "text",
"expected"}` where `expected` is `mask`, `block` or `boundary` (a
documented evasion the pipeline does not catch).

**Composition (15 rows):**

| family | rows |
|---|---|
| normalization_pii | 4 |
| layer_depth | 4 |
| encoded_rules | 3 |
| cue_homoglyph | 2 |
| separator_scatter | 2 |

Expected values: 9 `mask`, 3 `block`, 3 `boundary`.

**How `expected` was set:** each value records the policy-path behaviour
measured end to end before the file was frozen (builder docstring); it is
not an independent label. `tests/adversarial_evasion.rs`
(`evasion_corpus_expectations_hold_row_by_row`) keeps every row equal to
the current pipeline. Regenerate the file only after a pipeline change and
re-measure before editing `expected`.

**Consumers:** `tests/adversarial_evasion.rs`, `docs/evasion-v1.md` (the
depth measurement harness is kept outside the crate).

**What it is not:** an independent robustness benchmark. The project wrote
both the cases and the defences, so "12/15 caught" is a regression figure
for these 15 cases, not an evasion rate against real attackers.
