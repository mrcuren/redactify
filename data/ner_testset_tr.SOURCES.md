# ner_testset_tr.jsonl - provenance

**Type:** handmade, synthetic (there is no real person's data; the
names are common Turkish first-name/surname combinations and publicly
famous artist/athlete names used as scaffolding - it contains no
reference to any real person).

**Purpose:** span-level measurement of the L1 NER layer
(OnnxNerRecognizer + the savasy/bert-base-turkish-ner-cased export):
a span-level evaluation harness (kept outside the crate) produces
precision/recall/F1 with this set and determines the measured default
threshold.

**Format:** each row is `{"text": string, "names": [string, ...]}` -
`names` holds the gold span texts (each must occur exactly once in the
text; the evaluator resolves byte offsets with `text.find(name)`).
Negative examples have `names: []`.

**Distribution (v1, 100 rows):** 72 positive (free text,
suffix-taking names (`'ın/'ı/'e`), title prefixes Dr./Av./Sayın,
foreign names, multiple names in one sentence) + 28 negative
(organization/place/product/brand/event names, sentences featuring
TCKN/IBAN/e-mail).

**Maintenance:** the set is for measurement only; production decisions
are made with the measurements that come out of this set
(`best_f1_threshold`), not with assumptions.
