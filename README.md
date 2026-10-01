# redactify

**Checksum-validated PII detection & redaction for structured identifiers.**

redactify is a **Rust-native, local-first AI safety & security runtime**: an embedded
library that runs inside your process. Scanned text never leaves your infrastructure -
no cloud calls, no external services. It is not another guardrails *framework*; it is
the engine such frameworks (or your application) can run underneath.

Ships with the **Turkish** and **English (US)** identifier sets - TCKN (national ID), TR-IBAN, VKN (tax
number), passport numbers, vehicle plates, phone numbers (mobile & landline), credit
cards and e-mail - while the underlying architecture (pattern + checksum validator +
priority + confidence score) is locale-agnostic and designed to grow to other
countries' identifiers.

> [Türkçe dokümantasyon için README.tr.md](README.tr.md)

## Why checksums?

Structured identifiers carry math: a TCKN has 11 digits and two check digits, a VKN has
its own checksum, an IBAN is mod-97, a Turkish plate encodes one of 81 provinces.
Treating a bare 11-digit number as a national ID floods you with false positives;
**validating the checksum makes redaction precise**. A random order number is never
masked as a TCKN - and a real one never slips through.

## Installation

```toml
[dependencies]
redactify = "0.3.0"
```

Minimal, auditable dependencies (`fancy-regex`, `unicode-normalization`, `base64`).
No models, no network, no external runtimes. MSRV: **1.80**.

## Quick start

```rust
use redactify::{detect, redact, detect_with_threshold, EntityType};

// Masking:
assert_eq!(
    redact("TCKN'm 12345678950, IBAN TR33 0006 1005 1978 6457 8413 26, mail a@b.com"),
    "TCKN'm [TCKN], IBAN [IBAN], mail [EMAIL]"
);

// A non-checksum order number is NOT redacted (precision):
assert_eq!(
    redact("Sipariş numaranız 12000345671 olarak kaydedildi."),
    "Sipariş numaranız 12000345671 olarak kaydedildi."
);

// Typed spans with byte offsets and confidence scores:
let ents = detect("Plakası 34-ABC-123, TCKN 12345678950");
assert_eq!(ents[0].kind, EntityType::Plaka);
assert_eq!(ents[0].score, 0.95);          // context cue ("plaka") nearby
assert_eq!(ents[1].score, 1.0);           // checksum-verified → certainty

// Confidence thresholding:
assert_eq!(detect_with_threshold("Yolda 34 ABC 123 gördüm", 0.9).len(), 0); // bare plate: 0.85

// Validators are also usable standalone:
use redactify::valid_tckn;
assert!(valid_tckn("12345678950"));
```

### Guardrails L0 seed - input normalization

v0.3 adds the first guardrails layer:
NFKC normalization (homoglyph/fullwidth evasion), invisible-character stripping
(ZWSP/ZWJ/BOM/soft-hyphen) and base64 suspect decoding with re-scan:

```rust
use redactify::normalize::normalize_for_scan;
let dirty = "kimlik ＴＣＫＮ １２３４５６７８９５０"; // fullwidth digits
assert!(redactify::detect(dirty).is_empty());
assert!(redactify::detect(&normalize_for_scan(dirty))
    .iter().any(|e| e.kind == redactify::EntityType::Tckn));
```

### Deterministic guards & policy (OWASP LLM05 defenses)

`guard` scans input/output text for known danger patterns without any model:
SQL injection signatures, XSS/HTML injection, SSRF-dangerous URLs (cloud metadata
endpoint, RFC1918 ranges, localhost, `file:`), character-splitting obfuscation and
PII hidden inside base64 payloads. `policy` turns signals plus PII findings into an
explainable decision:

```rust
use redactify::guard::{sql_risk, url_guard, SignalKind};
use redactify::policy::{guard_all, GuardAction};

let sig = sql_risk("1' OR '1'='1").unwrap();      // score 0.9
assert_eq!(sig.kind, SignalKind::SqlInjection);

assert_eq!(url_guard("http://169.254.169.254/meta").len(), 1); // cloud metadata (SSRF)
assert!(url_guard("https://example.com/page").is_empty());     // DNS is never resolved: no guessing

assert_eq!(guard_all("http://10.0.0.5/admin").action, GuardAction::Block);
assert_eq!(guard_all("TCKN 12345678950").action, GuardAction::Mask);
assert_eq!(guard_all("merhaba dunya").action, GuardAction::Allow);
```

Every decision carries a human-readable `rationale` (which rule, which score, which
threshold). URL classification never resolves DNS: only literal addresses are judged,
so there are no assumptions about hostnames.

### CLI

```text
redactify "TCKN 12345678950, vergi no 1234567890"   # from an argument
cat document.txt | redactify                         # from stdin (UTF-8)
```

```text
TYPE             BEGIN      END  SCORE  TEXT
PASSPORT            11        20   0.90  U12345678
PHONE               27        41   0.80  0212 555 44 33
VKN                 52        62   1.00  2120000004

Pasaportum [PASSPORT], ofis [PHONE], vergi no [VKN]
```

## Detection model

| Entity | Validation | Base score | Notes |
|---|---|---|---|
| `TCKN` | 11 digits, 2 check digits (NVI algorithm) | **1.0** | first digit ≠ 0 |
| `IBAN` | ISO-13616 mod-97 | **1.0** | TR + 24 digits, spacing tolerant |
| `VKN` | 10 digits, single check digit | **1.0** | **context cue required** (`vergi`/`VKN`/`tax` within ±18 chars) - a bare 10-digit number is never claimed |
| `CREDIT_CARD` | Luhn, ≥ 13 digits | **1.0** | space/dash separators tolerated |
| `PASSPORT` | `U` + 8 digits (biometric) | **0.90** | no checksum → nearby `pasaport`/`passport` cue **required** |
| `PLAKA` | province 01-81 + plate alphabet | **0.85 → 0.95** with a context cue | letters `[A-PR-VY-Z]` (Q/W/X not in the Turkish plate alphabet), serial 2-4 digits, space or hyphen separators |
| `EMAIL` | strict regex | **0.85** | |
| `PHONE` | structural pattern | **0.80** | mobile `5xx` with `0`/`+90` prefix or separators; landline with a mandatory separator after the area code (a bare 10-digit VKN is never claimed) |
| `SSN` | structural rules (no checksum exists) | **0.75 → 0.95** with a cue (`ssn`, `social`...) | separator-bearing `123-45-6789` forms; rejects 000/666 areas, zero groups, all-same digits, sample SSNs |
| `ITIN` | restricted middle group (`9xx`) | **0.75 → 0.95** with a tax cue | narrower than SSN: an input fitting both shapes is claimed as ITIN |
| `US_PASSPORT` | Next Generation `[A-Z]` + 8 digits | **0.90** | no checksum -> a nearby `passport`/`travel` cue is **required** |

**Overlap resolution:** IBAN > CREDIT_CARD > PLAKA > TCKN > EMAIL > PHONE > PASSPORT >
VKN - a 10-digit block inside an IBAN never wins over the IBAN.

**Scanning is line-scoped**: each regex sees a single line, so one pathological line
cannot stall the whole scan (ReDoS mitigation).

## Architecture

```
src/
├── lib.rs            crate docs + flat public API re-exports
├── pii/              L1 detection core (private; re-exported at the crate root)
│   ├── mod.rs        module wiring + re-exports
│   ├── entity.rs     EntityType enum (label, priority) + Entity (byte-offset span, score)
│   ├── rule.rs       the Rule model: pattern + validator + context policy + score
│   ├── context.rs    shared context-cue windows (character-based)
│   ├── detect.rs     the locale-agnostic engine (scan, policy, overlap resolution)
│   ├── redact.rs     mask templating
│   └── locales/      locale rule sets - one file per identifier (validator,
│       │             pattern and cue policy together, no duplication):
│       ├── generic.rs  e-mail + Luhn credit card (locale-independent)
│       ├── tr/         TCKN, IBAN-TR, VKN, plates, passports, phones
│       └── en/         SSN, ITIN, US passports (Next Generation)
├── guard/            L0/L4 deterministic guards
│   ├── mod.rs        module wiring + re-exports
│   ├── rules.rs      SQL/XSS/SSRF/obfuscation/deep-PII rules (patterns compiled once)
│   └── normalize.rs  NFKC, invisible stripping, base64 suspects
├── policy.rs         decision core: signals + PII -> Allow/Log/Mask/Block
└── main.rs           CLI binary (thin entry point)
tests/                golden vectors, detection behavior, corpus parity
examples/             quickstart, parity (differential runner)
data/pii_corpus.jsonl synthetic, checksum-valid, span-labeled corpus (no real PII)
```

Guardrails evolution (layered rules → PII → ML classifiers → policy engine) is
tracked in the internal roadmap (not part of the public repo).

## Validation

Everything below was actually executed in this repository:

| Gate | Result |
|---|---|
| `cargo fmt --check` / `cargo clippy --all-targets -- -D warnings` | ✅ clean |
| `cargo test` | ✅ **70 tests** (unit + corpus + golden + detection + doctests) |
| Corpus (155 lines: 140 gold + 15 distractors) | ✅ **140/140** span-exact, **0** false positives |
| Differential reference suite (`examples/parity.rs`) | ✅ **184/184** inputs produce byte-identical `redact` output |
| Throughput (185 texts, in-process) | ~**57 ms** (≈ 0.3 ms/text) |

## Honest limits

- Checksums cut false positives; they do **not** guarantee real-world recall. Messy
  formatting and OCR noise remain hard.
- The VKN/passport context rules trade recall for precision (a real identifier without
  a nearby cue is skipped, deliberately).
- The phone pattern covers separator-bearing mobile and landline formats; parenthesized
  formats like `(212) 555 44 33` are not covered.
- Names/addresses have no checksum → out of scope. This is an **identifier redactor**,
  not a full anonymizer, and not a KVKK/GDPR compliance guarantee.

## Contributing & conduct

Contributions are welcome - see [CONTRIBUTING.md](CONTRIBUTING.md) (detector-adding
guide included) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security reports:
[SECURITY.md](SECURITY.md) (private GitHub vulnerability reporting).

## License

Apache-2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE).
