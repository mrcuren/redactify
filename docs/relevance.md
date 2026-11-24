# Relevance-aware masking (opt-in)

Relevance rules are deterministic policy entries matched by a rule engine;
LLM-assisted query-relevance judgment is out of scope.

## Motivation

Blanket redaction trades utility for safety: a support chat where the user
writes "call me at 0505 186 48 37" still gets the phone number masked even
though the user just volunteered it for that exact purpose. The 2025-2026 PII
literature (PII-Bench, CAPID, CAMP) moves from "detect everything, mask
everything" toward **query-aware masking**: mask what is irrelevant or risky in
context, pass through what the conversation legitimately needs.

redactify's deterministic core is deliberately conservative (mask by default).
Relevance rules are the opt-in escape valve: they encode *"this entity type is
expected - and therefore not masked - when the surrounding context says so"*.

## Semantics

A **relevance rule** is:

```text
(entity types) + (context cue condition within ±window bytes) → downgrade
```

- `entity_types`: the `EntityType` labels the rule applies to (`PHONE`, `EMAIL`, ...).
- `cue_any`: at least one of these cues must appear in the context window.
- `cue_all`: all of these cues must appear (combine with `cue_any` for tighter
  conditions; at least one of the two must be non-empty, enforced at config
  load - fail-closed).
- `window`: symmetric byte window around the entity span, clipped to the
  span's line (it never crosses a line break, so batch and stream decide
  alike) and snapped to UTF-8 char boundaries (default 64).

When a rule fires for an entity:

1. The entity is **excluded from masking** (it stays in the text).
2. It is **still reported**: the decision rationale records how many entities
   were relevance-downgraded and of which types.
3. The downgrade **only ever loosens masking** - it never touches `Block`
   decisions from danger signals (injection, secrets, ...), never raises any
   score, and never un-masks an entity that a *danger* rule demanded masked.

The default policy is empty → behavior is byte-identical to no feature. This is
a load-bearing invariant: relevance is opt-in per deployment, not per build.

## API surface

```rust
use redactify::policy::{Policy, RelevancePolicy, RelevanceRule};
use redactify::EntityType;

let policy = Policy::default().with_relevance(RelevanceRule {
    entity_types: vec![EntityType::Phone, EntityType::Email],
    cue_any: vec!["call me at".into(), "reach me at".into(), "contact:".into()],
    cue_all: vec![],
    window: 64,
});
```

`RelevancePolicy::partition(text, &[Entity]) -> (masked, downgraded)` is the
single entry point used by the guard/sanitize pipelines (they own the text;
`decide()` itself sees pre-filtered entities and keeps its signature).

Cue matching is Unicode-simple-lowercase substring over the context window
(std `char::to_lowercase`; no new dependencies). Turkish `İ` lowercases to
`i̇` (i + combining dot), so write Turkish cues in lowercase (`"telefonum"`,
`"ara beni"`) - matching is lowercase-vs-lowercase, so a lowercase cue matches
any case of the text.

## TOML configuration (schema 0.2)

```toml
schema_version = "0.2"

block_at = 0.6
log_at   = 0.4

[[relevance.rules]]
entity_types = ["PHONE", "EMAIL"]
cue_any = ["call me at", "reach me at", "contact:"]
window = 64

[[relevance.rules]]
entity_types = ["NAME"]
cue_all = ["resume", "cv attached"]
window = 128
```

- `schema_version = "0.1"` files keep parsing (no `relevance` table → empty
  policy); `"0.2"` adds the table. Unknown `entity_types` labels, empty rules,
  or rules with no cues are **config errors** (fail-closed, `ConfigError`).
- Applies to every mode the policy reaches: batch decisions
  (`Guard::new(target).with_policy(&policy)` then `.decide` / `.sanitize`),
  streaming (`StreamingGuard` inherits the policy), and the REST API via
  `REDACTIFY_POLICY` / `--policy`.

## What relevance rules do not do

- No LLM calls, no query classification, no cross-turn accumulation (CAMP-style
  registries). Rules are deterministic and auditable, and their per-entity
  work is small (not timed separately:
  one window slice + substring scans).
- No per-user or per-session state.
- No auto-generated rules; every rule is written by a human and reviewed like
  code.

## Evaluation

`data/relevance_testset.jsonl` (+ `.SOURCES.md`) records positive/negative
context cases per rule family. Golden/parity tests assert that an empty
relevance policy reproduces stock decisions exactly.

## Security notes

- Relevance downgrades reduce masking for matching entities. A malicious
  prompt that plants the cue ("call me at") next to someone else's phone
  number would keep that number in the text. Deployments that must never
  downgrade can simply not configure rules; `Threshold::None`-style per-rule
  kill switches are not needed because rules are allowlists by construction.
- Downgraded entities still appear in the decision rationale and audit
  metadata (entity type + count, never raw values).
