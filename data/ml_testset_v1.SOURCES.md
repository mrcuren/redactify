# ml_testset_v1.jsonl - sources and provenance

Generation: a deterministic builder script that is not part of this
repository (the repository holds Rust code only; sha1 ordering + fixed
templates - a re-run produces the identical file). The `source`
field on each row carries the origin (the Rust loader ignores this
field; it is a provenance record only).

## Composition (540 rows)

| lang | category | count | source | quality |
|---|---|---|---|---|
| en | injection | 100 | deepset/prompt-injections | **real external labels** (CC-BY-4.0) |
| de | injection | 40 | deepset/prompt-injections | **real external labels** (CC-BY-4.0) |
| en | benign | 100 | deepset/prompt-injections | **real external labels** (CC-BY-4.0) |
| en | hard_negative | 1 | deepset/prompt-injections | real |
| en | hard_negative | 24 | synthetic-hard-negative | synthetic |
| tr | benign | 100 | mrcuren/slm-bilanco-financial-qa-tr | **real** (MIT) |
| tr | injection | 100 | synthetic-template | synthetic (documented pattern families) |
| tr | hard_negative | 25 | synthetic-hard-negative | synthetic |
| tr/en | obfuscation | 25+25 | synthetic-transform | synthetic (deterministic transform) |

## Attributions

- **deepset/prompt-injections** (CC-BY-4.0) - https://huggingface.co/datasets/deepset/prompt-injections
  A real-labeled prompt-injection set produced by the Haystack team.
  The set is German-centric; the build script splits en/de with an
  umlaut/stopword heuristic (the heuristic itself is part of the
  measurement - its flaw is deliberately on record).
- **mrcuren/slm-bilanco-financial-qa-tr** (MIT) - https://huggingface.co/datasets/mrcuren/slm-bilanco-financial-qa-tr
  The `instruction` field of Turkish financial-analysis QA (the TR
  benign layer).

## Known limitations (honest inventory)

1. **The TR injection layer is synthetic** - template families
   (instruction-ignoring, system-prompt-disclosure, DAN/role,
   corporate-impersonation, data-exfiltration). TR recall (0.928) is
   therefore **optimism-biased**; it does not reflect real TR attack
   diversity. A human-verified TR holdout would balance
   this.
2. **The language label was wrong in the first build** - when a
   significant portion of the deepset samples turned out to be German,
   the "lang=en" slice measured artificially low (F1 0.576); a
   language heuristic was added, the set was regenerated, and the
   report was corrected. This is the record of the process catching
   its own error through measurement.
3. **The DE slice is small** (40) - the German figures are of low
   sample reliability.
4. **The obfuscation layer** is only a mechanical imitation of real
   attacker behavior (base64/split/fullwidth/dash/dot/upper).
5. deepset's labeling policy (counting role-play requests as
   injection) carries over verbatim to this set - the label definition
   belongs to the source set.
