//! # redactify
//!
//! **Checksum-validated** PII detection and redaction across 26 locale packs
//! and 103 entity types. Structured identifiers carry math (TCKN double check
//! digits, IBAN mod-97, VIN ISO 3779, Aadhaar Verhoeff, ...); validating
//! the checksum makes redaction precise. Deterministic guard rules
//! (injection, secrets, SSRF, XSS, tool-injection), a streaming guard, a
//! reversible vault, and optional ONNX ML (prompt-injection, safety, NER)
//! complete the pipeline.
//!
//! # Quick start
//!
//! ```
//! use redactify::{detect, redact, EntityType};
//!
//! // 1) Masking:
//! assert_eq!(
//!     redact("TCKN'm 12345678950, IBAN TR33 0006 1005 1978 6457 8413 26, mail a@b.com"),
//!     "TCKN'm [TCKN], IBAN [IBAN], mail [EMAIL]"
//! );
//!
//! // 2) A non-checksum order number stays UNCHANGED (precision):
//! let s = "Sipariş numaranız 12000345671 olarak kaydedildi.";
//! assert_eq!(redact(s), s);
//!
//! // 3) Typed spans:
//! let ents = detect("Beni 0532 123 45 67'den ara.");
//! assert_eq!(ents[0].kind, EntityType::Phone);
//! assert_eq!(&ents[0].text, "0532 123 45 67");
//! ```
//!
//! # Installation and crate features
//!
//! ```text
//! cargo add redactify                    # deterministic core
//! cargo add redactify --features api     # + REST server
//! ```
//!
//! | Feature | Adds | Notes |
//! |---|---|---|
//! | *(default)* | the deterministic core: detection, redaction, guard rules, secrets, policy, streaming guard, vault | no model, no network; compiles for `wasm32-unknown-unknown` |
//! | `api` | REST server ([`api`]), `tiny_http` | native only |
//! | `ml-onnx` | ONNX classifiers and NER (`guard::onnx`), `ort` + `tokenizers` | needs Rust 1.88+ (`ort` 2.0.0-rc.13 declares it; the crate MSRV 1.80 covers the other features); `ort` downloads the ONNX Runtime library at build time; models are not shipped |
//! | `serde` | `Serialize`/`Deserialize` on the public data types | [`Vault`] is deliberately not serializable |
//! | `config` | TOML policy files (`Policy::from_toml`, `REDACTIFY_POLICY`), `toml` | implies `serde` |
//!
//! # Honest limits
//!
//! - Checksums cut false positives but do **not** guarantee real-world recall:
//!   messy formatting and OCR noise remain hard.
//! - The VKN has a single check digit (~10% of random strings pass); therefore a
//!   bare VKN is only masked when a `vkn`, `vergi` or `tax` cue appears nearby
//!   (matched case-insensitively). This trades recall for precision
//!   deliberately.
//! - Person names carry no checksum. The `tr` pack finds Turkish names
//!   without a label through a lexicon scanner (first and last names from
//!   `mkozturk/trnames`, MIT; word evidence from Zemberek, Apache-2.0); in
//!   other languages names are claimed **only in labeled contexts** (a
//!   capitalized 2-4 word sequence next to a cue like "name:", score 0.85),
//!   and free-prose names need the contextual NER layer (optional
//!   `ml-onnx` feature: [`Detector::with_ner`], [`NerRecognizer`]). This is
//!   an **identifier redactor**, not a full anonymizer, and it offers no
//!   KVKK compliance guarantee.
//! - REST is batch plus two streaming endpoints, and **incremental
//!   guarding exists at the library level**: [`StreamingGuard`]
//!   is line-buffered and differential-proven
//!   byte-identical to batch `sanitize`. 26 locale packs ship (tr, en and
//!   24 opt-in: de uk fr es it nl pl pt ca au sg in br cn se fi no dk eu
//!   kr ng ph za th),
//!   always-on generic rules include the 89-country IBAN registry (mod-97 +
//!   exact country lengths, [`valid_iban`]); an empty locale slice selects
//!   the default tr+en set.
//!
//! # Layout
//!
//! - `pii`: the L1 detection core (private module; re-exported flat here).
//! - [`guard`]: the L0/L4 deterministic guard rules and normalization.
//! - [`policy`]: signal + PII decision making.
//!
//! # Dependency note
//!
//! Dependencies are minimal and auditable: `fancy-regex` (lookaround-capable
//! backtracking engine), `aho-corasick` (literal prefilter of the secrets
//! layer, vault restoration), `unicode-normalization` and `base64`
//! (guardrails L0), `serde_json` (guardrails L4 + evaluation harness),
//! `regex-syntax` (validating caller-supplied patterns against the
//! linear-time syntax) and `thiserror` (typed error derives). Optional
//! features add `tiny_http` (REST `api`), `serde`
//! (Serialize/Deserialize on the public data types), `toml` (TOML `config`)
//! and `ort` + `tokenizers` (ML via `ml-onnx`); the zero-model core keeps
//! none of them.
//!
//! The deterministic core (default and `serde` features) compiles for
//! `wasm32-unknown-unknown` - the same code runs at the edge/in-browser
//! (CI gate; the `api`/`ml-onnx` features are native-only by design).
//!
//! # Failure semantics (fail-mode matrix)
//!
//! What every component does when something breaks - a guard whose detector
//! errors must never silently look like clean text:
//!
//! | Component | Failure | Behavior |
//! |---|---|---|
//! | Deterministic rules (L0/L4, incl. secrets) | regex cancel on one match | other matches still reported; embedded patterns are compile-tested (panic at first use, never a silent skip) |
//! | ML classifiers (L2/L3, `ml-onnx`) | model load/warmup error | startup REFUSES: `new` returns `Err`, the CLI exits 1, the API refuses to serve |
//! | ML classifiers (L2/L3, `ml-onnx`) | inference error or >2s timeout | `FailMode::Closed` (default): maximum-severity signals -> **Block**; `FailMode::Open` is an explicit opt-in; either way an `ML_DEGRADED` **Log** signal names the failure (blockable via a `CategoryOverrides` entry) |
//! | Plug-in classifiers (`guard::guarded::Guarded`) | adapter error, unparseable or out-of-range score, answer after the deadline | the same `FailMode` rule and `ML_DEGRADED` signal; with `Guarded::isolated` a hung adapter is cut off at the timeout and its lane fails fast until a half-open probe succeeds |
//! | ONNX inference lane (`ml-onnx`) | timeout or dead worker | the lane is degraded: calls fail fast under the fail mode above and `health()` reports `Degraded` (REST `/health` shows it); after `guard::onnx::RECOVERY_COOLDOWN` (30 s) one background half-open probe rebuilds the session, and a success clears the degraded state |
//! | NER enrichment (L1, `ml-onnx`) | inference error | spans absent (fail-open by design) + a `NER_DEGRADED` **Log** signal (blockable via a `CategoryOverrides` entry) |
//! | NER ensemble (PIIRanha secondary) | member load failure | single-model fallback + `NER_DEGRADED` Log signal |
//! | L1 PII engine | regex runtime error (the 1,000,000-step backtrack budget is exhausted) | the line counts as not fully scanned ([`ScanReport::is_complete`] is `false`); the guard adds a `SCAN_INCOMPLETE` **Log** signal (blockable via a `CategoryOverrides` entry) and every masking output replaces the line with `[SCAN_INCOMPLETE]` |
//! | REST API worker | handler panic | `catch_unwind` isolation -> 500; raw request body never echoed |
//! | MCP server (`redactify-mcp`) | tool-call panic | `catch_unwind` isolation -> JSON-RPC error -32603 without the panic message (stderr gets the panic location only); the server keeps serving |
//! | REST `/v1/sanitize` and MCP `guard` on Block | n/a | the returned text is the loggable re-mask [`Guard::mask_all`]: secrets first, then normalization-aware PII with the effective locales and recognizers, `[SCAN_INCOMPLETE]` lines, HTML encoding for `ModelOutput` (the library's [`Guard::sanitize`] keeps the raw PII on Block: the caller decides) |
//! | Audit sink | write error | non-fatal by design (guarding must not depend on logging health); the chain keeps the in-memory head

// `unsafe_code = "forbid"` and `unexpected_cfgs = "deny"` come from
// [workspace.lints] in Cargo.toml (every crate and target)
#![deny(missing_docs)]
// docs.rs builds with --cfg docsrs (see [package.metadata.docs.rs]); enable
// per-feature badges on gated modules
#![cfg_attr(docsrs, feature(doc_cfg))]

/// The README's Rust examples, run as doctests (`cargo test --doc`) so the
/// README cannot drift from the API. Compiled only for doctests, so the
/// README is neither rendered on docs.rs nor part of the public API (the
/// rustdoc book's pattern for testing external Markdown).
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;

/// The crates.io page's Rust examples (`crates-io.md`, the package
/// `readme`), run as doctests for the same reason.
#[cfg(doctest)]
#[doc = include_str!("../crates-io.md")]
pub struct CratesIoReadmeDoctests;

/// REST API server (optional `api` feature): a simple JSON/HTTP interface
/// over the deterministic core.
#[cfg(feature = "api")]
#[cfg_attr(docsrs, doc(cfg(feature = "api")))]
pub mod api;
pub mod guard;
mod pii;
pub mod policy;

pub use guard::normalize;
pub use pii::lang_gate::{is_non_latin, script_candidates};
pub use pii::{
    valid_au_abn, valid_au_acn, valid_au_medicare, valid_au_phone, valid_au_tfn, valid_br_cnpj,
    valid_br_cpf, valid_bsn, valid_btc_address, valid_ca_postal_code, valid_ca_sin,
    valid_cn_resident_id, valid_credit_card, valid_de_bsnr, valid_de_id_card, valid_de_kfz,
    valid_de_kvnr, valid_de_lanr, valid_de_rvnr, valid_de_tax_id, valid_de_tax_number,
    valid_dk_cpr, valid_dni, valid_eth_address, valid_eu_vat, valid_fi_hetu, valid_fr_siret,
    valid_iban, valid_iban_tr, valid_in_aadhaar, valid_in_gstin, valid_in_pan, valid_in_phone,
    valid_intl_phone, valid_ip_address, valid_it_fiscal_code, valid_it_numeric_fiscal_code,
    valid_it_passport, valid_kr_brn, valid_kr_frn, valid_kr_passport, valid_kr_rrn, valid_luhn,
    valid_ng_nin, valid_nie, valid_nino, valid_nir, valid_no_fodselsnummer, valid_passport,
    valid_pesel, valid_ph_tin, valid_pl_nip, valid_pl_phone, valid_plaka, valid_pt_nif,
    valid_public_ip_address, valid_se_organisationsnummer, valid_se_personnummer,
    valid_sg_nric_fin, valid_sg_phone, valid_sg_uen, valid_ssn, valid_swift_bic, valid_tckn,
    valid_th_tnin, valid_uk_driving_licence, valid_uk_nhs, valid_uk_vat, valid_uk_vehicle_reg,
    valid_url, valid_us_aba_routing, valid_us_ein, valid_us_mbi, valid_us_npi, valid_us_passport,
    valid_us_phone, valid_vin, valid_vkn, valid_za_company_registration, valid_za_id_number,
    valid_za_phone, valid_za_tax_reference, valid_za_vat, CustomLabel, CustomLabelError,
    CustomRule, CustomRuleError, CustomRuleSpec, CustomRules, CustomRulesError, DetectionSource,
    DetectionView, Entity, EntityType, EntityTypeParseError, Explanation, MockNameRecognizer,
    NerHealth, NerRecognizer, RestoreOptions, StreamRestorer, Vault, VaultError,
    LINEAR_MAX_PATTERN_BYTES, LINEAR_MIN_MATCH_LEN, MAX_CUSTOM_LABELS, MAX_CUSTOM_LABEL_LEN,
    MAX_VAULT_ENTRIES, SUPPORTED_LOCALES,
};
pub use policy::{
    decide, detect, guard_all, redact, sanitize, CategoryOverrides, Decision, Detector,
    DowngradedSpan, Guard, GuardAction, GuardCategory, GuardEvent, GuardTarget, GuardVerdict,
    JsonFinding, JsonFindingKind, JsonRedactionReport, JsonRedactor, MaskStyle, MaskStyleError,
    MlStreamBudget, Policy, PseudonymKey, RelevancePolicy, RelevanceRule, SanitizeResult,
    ScanReport, Severity, StreamingGuard, Threshold, DEFAULT_WINDOW,
};
