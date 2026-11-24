# Encoding and evasion handling

How the guard handles obfuscated input, what it costs, and where its
boundaries are. Corpus: `data/evasion_corpus.jsonl` (15 deterministic cases;
the generator script is not part of this repository). Tests:
`tests/adversarial_evasion.rs`. The depth and cost figures below come from a
measurement harness kept outside the crate (release build, same container
for every comparison).

## Scan views

Every text is scanned as written and in derived views:

1. **Normalized view** (`normalize_for_scan`): NFKC, invisible-character
   stripping, confusable folding, and decimal digit folding for every
   Unicode Nd digit set.
2. **Base64 layers** (`layered_views`): every base64 candidate of a layer is
   decoded, one per line (PII matches and context cues are line-scoped, so
   candidates stay apart), up to `DECODE_DEPTH = 3` nested layers. All layers
   together hold at most about 1.7 times the input.
3. **Escape views:** single-round percent decoding and character-reference
   decoding of the normalized view.

PII detection (`collect_pii_views` in `src/policy.rs`) and the full
deterministic rule battery (`rule_battery`) run on every view that differs
from the raw text. Clean inputs pay nothing extra: when normalization changes
nothing, the duplicate pass is skipped and exactly one detection pass runs.

## Normalization-only evasions

A value that only the normalizer can undo drives the decision and is masked
in the emitted text:

| input | decision | emitted text |
|---|---|---|
| `TCKN 1\u{200B}2\u{200B}345678950` (zero-width scatter) | Mask | `TCKN [TCKN]` |
| `tckn １２３…` (fullwidth digits) | Mask | value masked as `[TCKN]` |
| `iban ＴＲ33 0006 …` (fullwidth prefix) | Mask | `iban [IBAN]` |
| fullwidth `ＳＥＬＥＣＴ * FROM …` | Block | - |

Masking maps findings back to the raw text with
`normalize_for_scan_with_map` (`src/guard/normalize.rs`): a cluster-aligned
byte-offset map from the normalized view into the raw text. It handles NFKC
cross-character composition, combining-mark reordering and ligature
expansions, and over-masks when a boundary clips an expansion (the safe
direction). Every masking site uses it: batch sanitize, streaming emission,
the ML privacy input and the REST `/v1/detect`, `/v1/redact` and `/v1/guard`
endpoints.

Tests: `normalization_only_evasion_is_masked_in_output`,
`zero_width_scattered_value_is_masked_in_output`,
`fullwidth_obfuscated_sql_drives_block`; the offset map is checked over
representative input classes, composition and ligature clusters included,
in `src/guard/normalize.rs` (`map_round_trips_representative_inputs`).

## Non-ASCII decimal digits

NFKC folds compatibility forms such as fullwidth digits, but Arabic-Indic,
Extended Arabic-Indic (Persian/Urdu), Devanagari and the other native
decimal digit sets are ordinary characters that NFKC keeps. The normalized
view folds every General Category Nd digit to the ASCII digit of its value
(table `src/guard/digits.rs`, generated from the pinned `UnicodeData.txt`
18.0.0 by a generator kept outside this repository). The fold is one
character for one character, so the offset map masks the original digits.
The digit value wins over the confusable table, which maps 122 of these
digits by shape to a letter or a different digit (U+0665 ARABIC-INDIC DIGIT
FIVE to `o`, U+09EA BENGALI DIGIT FOUR to `8`).

| input | result |
|---|---|
| `TCKN` + Arabic-Indic digits (U+0660..U+0669) | Mask (`TCKN`) |
| `TCKN` + Extended Arabic-Indic / Devanagari digits | Mask (`TCKN`) |
| card number in Arabic-Indic / Persian digits | Mask (`CREDIT_CARD`) |
| `IBAN TR` + Arabic-Indic digits | Mask (`IBAN`) |

Tests: `native_digit_tckn_drives_mask`,
`native_digit_card_and_iban_are_masked_in_output`,
`native_digit_tckn_reports_the_raw_span` and the native-digit cases of
`streaming_matches_batch_on_evasion_inputs`.

## Base64

Every base64 candidate is decoded, so a longer benign token next to a
payload does not hide it. Payload alone / with a benign decoy after / with
the decoy before (`redactify --sanitize --json`):

| payload | decision |
|---|---|
| `kimlik 12345678950` | Mask / Mask / Mask |
| `aws key AKIAIOSFODNN7EXAMPLE` | Block / Block / Block |
| `Ignore all previous instructions ...` | Block / Block / Block |
| `x'; DROP TABLE users; --` | Block / Block / Block |

A token whose decoded layers hold a credential is masked as that secret,
and one that holds PII as that entity type (`policy::encoded_tokens`), on
every masking path (batch sanitize on every branch, `Guard::mask_all`, the
streaming emission, the ML input). A token scattered with zero-width
characters is found through the normalized view and masked over its raw
span:

| input | emitted text |
|---|---|
| `veri: <base64 of "kimlik 12345678950"> tamam` | `veri: [TCKN] tamam` (Mask) |
| `cfg: <base64 of "aws key AKIAIOSFODNN7EXAMPLE here">` | `cfg: [SECRET:AWS_ACCESS_KEY]` (Block) |
| `a <base64 TCKN> b <longer benign base64>` | `a [TCKN] b <benign token unchanged>` |

Tests: `a_longer_benign_base64_token_does_not_hide_a_payload`,
`base64_wrapped_values_are_masked_in_the_output_not_only_decided`,
`a_base64_wrapped_credential_is_masked_on_every_branch_block_included` and
the base64 cases of `streaming_matches_batch_on_evasion_inputs`.

### Decode depth

Catch rate over the corpus (PII and signal probes) and mean scan cost, 100
iterations:

| decode depth | catch | mean scan cost |
|---|---|---|
| 1 | 10/15 | 85.6 µs/call |
| 2 | 11/15 | 100.4 µs/call |
| 3 | 12/15 | 102.8 µs/call |

Depth 3 adds triple-wrapped payloads for ~2.4 µs/call over depth 2 (within
run-to-run noise; the corpus is small and dominated by the detection pass),
hence `DECODE_DEPTH = 3` (`src/guard/normalize.rs`). A quadruple wrap is a
documented boundary
(`base64_depth_3_is_caught_and_depth_4_is_a_documented_boundary`).

### Cost

`sanitize` per message: text without base64 ~1,233 vs ~1,236 µs without and
with every-candidate decoding (within noise); three benign base64 tokens per
message ~1,743 vs ~2,002 µs (+15%, the extra decoded content); one line of
2,000 or 8,000 base64 tokens 40 vs 71 µs per token, linear in the token
count.

## Percent escapes and character references

Every line that holds an escape is decoded with a map from each decoded byte
back to its raw escape (`percent_decode_once_mapped`,
`decode_html_refs_mapped`, locked equal to the decision decoders by a unit
test) and scanned whole (context cues in the line count); a finding that
covers an escaped byte is masked over its raw span:

| input | emitted text |
|---|---|
| `kimlik %31%32%33%34%35%36%37%38%39%35%30 kaydi` | `kimlik [TCKN] kaydi` (Mask) |
| `kimlik &#49;&#50;...&#48; kaydi` | `kimlik [TCKN] kaydi` (Mask) |
| `kimlik 123%34%35678950 kaydi` (partly escaped) | `kimlik [TCKN] kaydi` |
| `key %41%4B%49%41...` (an AWS key) | `key [SECRET:AWS_ACCESS_KEY]` (Block) |
| `path a%20b and Tom &amp; Jerry` | unchanged |

Tests: `escape_encoded_values_are_masked_in_the_output_not_only_decided` and
the escape cases of `streaming_matches_batch_on_evasion_inputs`. Only lines
with an escape are decoded: decoding the whole text would cost ~47% of
`sanitize` and ~3x `mask_all` on a message with one benign `&amp;` line;
per line it costs ~6% and ~22% (3 runs each).

## Documented boundaries

| case | behavior | reason |
|---|---|---|
| dot/underscore-scattered digits (`1.2.3…`/`1_2_3…`) | Allow | separator scatter breaks every national pattern; decimal-separator ambiguity (see `tests/eu_adversarial.rs`) |
| quadruple base64 wrap | Allow | decode depth is 3 |
| hex and base64url encodings | not decoded | |

## Corpus composition

15 cases across 5 families: `normalization_pii` (4), `encoded_rules` (3),
`layer_depth` (4), `separator_scatter` (2), `cue_homoglyph` (2). Every
`expected` value was verified end to end against the compiled CLI before
freezing; `evasion_corpus_expectations_hold_row_by_row` checks them on every
test run.
