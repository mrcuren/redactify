# ml_testset_safety_v1.jsonl - sources and provenance

Generation: a deterministic builder script that is not part of this
repository (the repository holds Rust code only); the file itself is the
artifact. Purpose:
measuring the L3 safety classifier (Qwen3Guard-Stream) with real
external labels.

## Composition (330 rows)

| lang | category | count | source | quality |
|---|---|---|---|---|
| en | safety_attack | 100 | JailbreakBench/JBB-Behaviors (MIT) | **real harmful prompts** |
| tr | safety_attack | 30 | synthetic-template | synthetic (optimism-biased) |
| en | benign | 100 | deepset/prompt-injections (CC-BY-4.0) | real |
| tr | benign | 100 | mrcuren/slm-bilanco-financial-qa-tr (MIT) | real |

## Known limitations

1. The TR attack layer is synthetic (30 items - below the target of
   50; the template pool produced only this many) and
   optimism-biased.
2. The definition of "safety attack" = a harmful PROMPT (not the
   harmful output the model is expected to produce); the JBB `Goal`
   field was taken as the basis.
3. NOT a category-based measurement (hate/violence split) - a binary
   unsafe measurement; category-header calibration needs a separate
   holdout set.
