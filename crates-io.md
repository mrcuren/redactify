# redactify

A deterministic data-protection and policy layer for LLM and agent
pipelines, in Rust: PII and secret detection and masking, one policy
decision per text, and agent tool-call checks. Identifiers are
checksum-verified (mod-97 IBAN, Luhn, Verhoeff, ISO 7064,
national check digits), so a digit run that fails its check is not masked
(the explicit exceptions are listed in the README).
The deterministic core has no model, no network and no async runtime, and
compiles for `wasm32-unknown-unknown`.

- **103 entity types, 26 locale packs, 132 rules** plus 11 Turkish
  lexicon scanners (person names, KVKK special categories) with every
  pack enabled;
  the default set is Turkish + English, every other pack is opt-in.
- **Decisions, not just spans:** one call returns Allow / Log / Mask / Block
  with a rationale and the masked text.
- **Guard rules** for prompt injection, secrets and API keys, SSRF, XSS, SQL
  and path traversal, also inside base64, percent and HTML encodings. The
  prompt-injection rules catch known phrasings only; for injection and
  harmful-content detection, plug in an independently validated classifier
  (`guard::ml::MlClassifier`). Measured limits are in the
  [README](https://github.com/mrcuren/redactify#prompt-injection-and-safety-detection).
- **Reversible pseudonymization vault** for LLM round trips, a **streaming guard**
  byte-identical to batch, and an agent **tool-call guard**.
- Optional REST server (`api`), ONNX classifiers and NER (`ml-onnx`),
  `serde` derives and TOML policy files (`config`).

## Install

```text
cargo add redactify                    # deterministic core
cargo add redactify --features api     # + REST server
```

## Usage

Mask identifiers; an order number that fails every checksum stays as it is:

```rust
use redactify::redact;

assert_eq!(
    redact("TCKN'm 12345678950, IBAN TR33 0006 1005 1978 6457 8413 26, mail a@b.com"),
    "TCKN'm [TCKN], IBAN [IBAN], mail [EMAIL]"
);
let order = "order 4111 1111 1111 1112 shipped"; // fails the Luhn check
assert_eq!(redact(order), order);
```

Opt-in locale packs, typed spans and mask styles:

```rust
use redactify::{Detector, EntityType, MaskStyle};

let uk = Detector::new().with_locales(&["uk"]);
assert_eq!(uk.detect("nhs 9434765870")[0].kind, EntityType::UkNhs);
assert_eq!(uk.redact("nhs 9434765870"), "nhs [UK_NHS]");

let partial = uk.with_mask_style(MaskStyle::Partial { keep_last: 4, ch: '*' });
assert_eq!(partial.redact("nhs 9434765870"), "nhs ******5870");
```

The full guard pipeline (rules + PII + policy) returns one decision:

```rust
use redactify::{Guard, GuardAction, GuardTarget};

let r = Guard::new(GuardTarget::UserPrompt).sanitize("TCKN 12345678950 and SSN 536-90-6292");
assert_eq!(r.decision.action, GuardAction::Mask);
assert_eq!(r.text, "TCKN [TCKN] and SSN [SSN]");
```

Secrets are reported without echoing the key:

```rust
use redactify::guard::{secrets_risk, SignalKind};

let sigs = secrets_risk("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
assert_eq!(sigs[0].kind, SignalKind::Secrets);
assert!(sigs[0].score >= 0.9);
assert!(!sigs[0].evidence.contains("N7EXAMPLE"));
```

Reversible pseudonymization for an LLM round trip: the model sees
placeholders, the caller keeps the mapping and restores the reply (the
text is pseudonymized, not anonymous):

```rust
use redactify::Vault;

let (prompt, vault) = Vault::pseudonymize("My TCKN is 12345678950");
assert_eq!(prompt, "My TCKN is [TCKN_1]");
let reply = "Your [TCKN_1] is valid.";
assert_eq!(vault.restore(reply), "Your 12345678950 is valid.");
```

## Crate features

| Feature | Adds | Notes |
|---|---|---|
| *(default)* | the deterministic core: detection, redaction, guard rules, secrets, policy, streaming guard, vault | no model, no network; compiles for `wasm32-unknown-unknown` |
| `api` | REST server (`redactify::api`), `tiny_http` | native only |
| `ml-onnx` | ONNX classifiers and NER (`redactify::guard::onnx`), `ort` + `tokenizers` | needs Rust 1.88+ (`ort` 2.0.0-rc.13 declares it); `ort` downloads the ONNX Runtime library at build time; models are not shipped |
| `serde` | `Serialize`/`Deserialize` on the public data types | `Vault` is deliberately not serializable |
| `config` | TOML policy files (`Policy::from_toml`, `REDACTIFY_POLICY`), `toml` | implies `serde` |

**MSRV:** Rust 1.80 for the default features and `api`, `serde`, `config`;
`ml-onnx` needs 1.88.

## Locale packs

`tr` and `en` by default; opt in to `de`, `uk`, `fr`, `es`, `it`, `nl`, `pl`,
`pt`, `ca`, `au`, `sg`, `in`, `br`, `cn`, `se`, `fi`, `no`, `dk`, `eu`, `kr`,
`ng`, `ph`, `za`, `th` with `Detector::with_locales`. Always on: IBAN (89
countries), VIN, payment cards (Luhn), e-mail, IP, URL, SWIFT/BIC,
international `+CC` phone numbers, IMEI, Bitcoin and Ethereum addresses.

## More

- API reference: <https://docs.rs/redactify>
- REST API, Docker image, MCP server, validation evidence and honest limits:
  <https://github.com/mrcuren/redactify#readme>
- MCP server crate: [`redactify-mcp`](https://crates.io/crates/redactify-mcp)

This is an identifier redactor, not a KVKK/GDPR compliance guarantee.

## License

`(MIT OR Apache-2.0) AND Unicode-3.0`: MIT or Apache-2.0 at your option; the
generated Unicode data tables are under Unicode-3.0
([NOTICE](https://github.com/mrcuren/redactify/blob/main/NOTICE)).
