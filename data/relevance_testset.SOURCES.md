# relevance_testset.jsonl - provenance

Producer: hand-authored for the relevance (Stage 1) feature. Not derived from
any external corpus; every entity value is a synthetic sample already used by
the repo's rule tests (`0505 186 48 37` TR mobile, `12345678950` valid TCKN,
`TR33 0006 1005 1978 6457 8413 26` TR IBAN, `a@b.com` / `john@example.com`
example mailboxes). Deterministic: no sampling, no randomness.

Schema (one JSON object per line):

| field | meaning |
|---|---|
| `text` | input to `sanitize_with_policy` |
| `rule` | rule family the expectations assume (`phone_contact`: PHONE + cues "call me at"/"reach me at"/"ara beni", window 64; `email_contact`: EMAIL + cue "contact:") |
| `expect_stay` | substrings that must remain in the sanitized text |
| `expect_masked` | mask tokens that must appear (`[PHONE]`, `[TCKN]`, ...) |
| `expect_action` | expected `Decision.action` |
| `note` | optional remark (e.g. window-boundary case) |

Composition: 12 items - 8 `phone_contact` (4 positive-cue, 2 negative-cue,
1 danger-signal Block, 1 window-boundary miss), 2 `email_contact`,
2 mixed-entity. Languages: English 10, Turkish-adjacent 2 (ASCII-only
transliteration; cue "ara beni" exercises Turkish lowercase matching via the
unit tests in `src/policy/relevance.rs`).

Known limitations:

- Expectations encode CURRENT Stage-1 behavior (first-match rule wins,
  symmetric byte window, Unicode simple-lowercase substring cues) and are
  enforced row by row by `tests/relevance.rs::testset_expectations_hold_row_by_row`.
- The window-boundary item separates the cue and the span by a 70-char
  filler run; it is a coarse boundary probe, not a byte-exact one
  (byte-exact boundaries are covered by the unit test
  `cue_window_boundary_is_respected`).
- No cross-turn accumulation cases (CAMP-style) - out of Stage-1 scope.

Consumed by: `tests/relevance.rs` (behavior contract).
