# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-25

The first public release. Nothing was published before it, so this
section describes the whole initial feature set; later releases list
changes against it.

### Added

- **Turkish person names without a label:** a lexicon scanner (`tr::person`)
  with first and last names from `mkozturk/trnames` (MIT) and word evidence
  from Zemberek (Apache-2.0) covers inflected forms (`Ahmet'in`, `Ayşeye`,
  `AHMET'in`), titles and organisation-name exclusion; the title and the
  case suffix stay visible (`Ahmet'in` -> `[NAME]'in`). A name is masked
  whole or not at all: words joined by a tab, several spaces, `_`, a
  hyphen (`Ayşe-Nur`, `Yılmaz-Kaya`) or a table separator before a surname
  stay one span, and every item of a name list is checked; hospital, shop
  and brand words (`Hastanesi`, `Çarşısı`, `Marka:`) keep organisation
  names out. Person-name F1 is 0.984 on the independent `nm-kvkk-pii-6K`
  test split and 0.911 on the Turkish slice of `piimask-eval-tr-en`
  (thresholds tuned on the nm train split).
- **Turkish record fields** (cue-gated unless noted): rule-based Turkish
  postal address (street and door anchors checked against a province and
  district gazetteer from `ubeydeozdmr/turkiye-api`, MIT), `DATE_OF_BIRTH`,
  `PLACE_OF_BIRTH`, `CARD_CVV`, `CARD_EXPIRY`, `CUSTOMER_NUMBER`,
  `POLICY_NUMBER`, `SGK`, `MERSIS`; Turkish credential keys `şifre` /
  `parola` in the secrets layer (every spelling the pattern accepts,
  `SİFRE` / `Şıfre` included, passes the literal prefilter; checked over
  all 160 spellings). The number rules take the whole token, so digits
  inside an e-mail address, URL or identifier never split it (`sgk_no=…`
  and `imei=…` still match); a postal
  code is exactly five digits, so a phone or TCKN after an address leaves
  the address whole; a cued SGK value inside a phone number yields
  to the phone.
- **KVKK special categories (Law 6698 art. 6):** ten entity types
  (`SPECIAL_HEALTH`, `SPECIAL_GENETIC`, `SPECIAL_BIOMETRIC`,
  `SPECIAL_SEX_LIFE`, `SPECIAL_CRIMINAL`, `SPECIAL_BELIEF`,
  `SPECIAL_ETHNICITY`, `SPECIAL_POLITICAL`, `SPECIAL_ATTIRE`,
  `SPECIAL_MEMBERSHIP`) found by Turkish lexicon scanners (health terms
  from Wikidata, CC0; the other lists curated from the KVKK guide). A term
  is claimed only when it is tied to a person: a record field (`Tanı:`,
  `Kan grubu:`), a first-person suffix (`diyabetim`), or a person, name,
  identifier or e-mail address in the same sentence; all-caps text needs
  stronger evidence, so headings stay unclaimed. On the `nm-kvkk-pii-6K`
  test split, health mentions reach precision 0.940 and recall 0.709;
  benign evaluation texts get no special-category hit. One pass per line
  is shared by the ten scanners, so cost stays linear in the line length.
- **`IMEI` entity:** 15 digits, Luhn and a GSMA TS.06 reporting-body prefix
  claimed without a cue; any prefix and the 16-digit IMEISV next to an
  `imei` cue. An IMEI outranks the card rule, and digits inside an e-mail
  address or URL are not an IMEI.
- **Tolerant vault restore and Turkish suffix repair:** `Vault::restore`
  and `restorer` restore placeholders an LLM altered (other brackets,
  doubled, markdown/HTML/JSON-escaped, any letter case, inner spaces, zero
  padding, translated labels, bare `NAME_1` in prose) only when the token
  maps to an entry the vault issued; a bare token in code (inline code,
  fenced blocks, `const PHONE_1 = 5`, `obj.PHONE_1`, JSON keys) is left as
  written. They also reshape a Turkish suffix after an apostrophe
  for the restored value (`[NAME_1]'e` -> `Ayşe'ye`, `[TCKN_1]'in` ->
  `12345678950'nin`, TDK spelling rules). `RestoreOptions::STRICT` with
  `restore_with` / `restorer_with` keeps exact-token restore. The
  byte-exact round trip holds in every mode (3,213/3,213 texts).
- **LiteLLM restoration (opt-in):** `REDACTIFY_LITELLM_RESTORE=1` (requires
  `REDACTIFY_API_TOKEN`): request-side calls get numbered placeholders kept
  in a bounded server-side session (`RestoreSessions` / `RestoreLimits`)
  tied to the LiteLLM call id and API key hash; response-side and
  `incremental_diff` streaming calls get the originals back. Calls whose
  `x-litellm-call-id` the client chose are never restored (replay
  protection). A placeholder in any URL context stays masked: the URL
  forms browsers accept (`https:\\host`, `https:host`, `https:/host`,
  character references), markdown link and image destinations, HTML tags.
  Placeholder-shaped text the client wrote (`<TCKN_1>`, `TCKN_1`) is never
  filled; the answer is restored in one pass, so code context carries
  across lines and protected ranges. Sessions keep the call's vault
  (about 2 KiB for one value, 47 KiB for 256); the default table holds
  2,048 sessions (about 60 MiB worst case). Verified end to end through a
  LiteLLM v1.110.2 proxy.
- **Operations:** per-entity policy actions (`MASK` / `BLOCK` / `LOG` /
  `IGNORE`, TOML schema 0.4 `[entities]`; a decision lists type counts,
  never values); dry-run shadow mode (`dry_run = true`: decisions are
  computed and audited, nothing is enforced); Prometheus `GET /metrics`
  (behind the API token); REST audit file (`REDACTIFY_AUDIT_FILE` /
  `REDACTIFY_AUDIT_KEY`, a file that does not verify refuses startup);
  configurable body limit (`REDACTIFY_MAX_BODY` / `--max-body`, 1 KiB to
  16 MiB, default 1 MiB); `redactify selftest` (canonical probes, no
  values printed) and `--probe TEXT`.
- **Cue prefilter:** a cue-gated rule is skipped on a line where none of
  its cues occurs (in the normalized line or the caller's context), since
  it could not claim a match there. Outputs with and without the prefilter
  are identical on the 3,213 evaluation texts.
- **Egress allowlist** (`guard::egress::EgressAllowlist`, opt-in): replaces
  markdown, HTML, autolink, protocol-relative and `www.` URLs to hosts
  outside the allowlist with `[BLOCKED_URL]` (userinfo tricks including
  Unicode whitespace before `@`, IDN, IPv4 notations, percent and
  character-reference encodings, a backslash before a reference, and the
  tab, newline and leading C0 characters URL parsers strip; quoted HTML
  attribute values are judged as whole URL strings), with a streaming
  adapter equal to the batch filter; a `ToolContract` `egress_allowlist`
  denies a tool call whose arguments hold such a URL (`EGRESS_HOST`),
  judging every JSON string literal including duplicate keys. Measured (release, shared
  machine): 642 MB/s on prose without links, 210 MB/s with links.
- **Server-held tool sessions** (`guard::tools::ToolSessions`,
  `session_id` on `POST /v1/tool/check` and the MCP `tool_check` tool): the
  server keeps each session's call history, bound to the contract of its
  first call, in a bounded table (1,024 sessions, 1,024 calls each, 1 h idle
  timeout; a live session is never evicted), so a caller cannot reset
  its budget by omitting history. Every tool decision is written to
  the audit sink (`AuditRecord::tool_decision`: code, policy hash, engine
  version, session id and counts, never arguments); the MCP server reads
  `REDACTIFY_AUDIT_FILE` / `REDACTIFY_AUDIT_KEY`.
- **LiteLLM Generic Guardrail API** (`POST /beta/litellm_basic_guardrail_api`,
  contract of LiteLLM v1.110.2): a Block answers `BLOCKED` with a
  content-free reason, masked texts come back as `GUARDRAIL_INTERVENED` in
  request order, otherwise `NONE`; tool messages are checked as tool
  responses and response-side texts as model output;
  `stream_holdback_chars` lets LiteLLM's `incremental_diff` streaming
  release whole masked lines. The API token is also accepted as
  `x-api-key` on this path. Client options in
  `additional_provider_specific_params` can only add detection: `words`,
  `words_ignore_case` and `patterns` (with `pattern` and `cues` only, no
  `label` or `score`) run after the built-in masking, on its output, so
  they can never displace or split a built-in entity (LiteLLM end users
  can set these params). Tool-call arguments are checked whatever their
  JSON shape. Verified end to end through a LiteLLM proxy
  (mask before the model, block, fail closed). In LiteLLM's default
  `block_only` streaming mode masked text is dropped by LiteLLM, so streamed
  answers need `incremental_diff`.
- **Pluggable classifiers:** the `GuardClassifier` trait (masked text, role,
  optional prompt context, deadline; per-category scores, raw label,
  probability or label-only), the `Guarded<C>` policy wrapper (threshold,
  fail mode, deadline, per-model chunking, role, health, optional
  `isolated()` hard timeout and circuit breaker; still an `MlClassifier`),
  `OnnxEncoder` loaded from a per-model `model.toml`, and a shared
  inference executor for the ONNX lanes. An `ML_DEGRADED` signal (score
  0.4, blockable by policy) reports a classifier that timed out or failed:
  fail-closed blocks, fail-open logs it instead of a silent Allow;
  a failed or label-only security call never closes the safety gate (the
  safety classifier runs), and fail-closed with no declared categories
  blocks through `ML_DEGRADED` at 1.0.
  L2 and L3 run concurrently when no safety gate applies; behind the
  default gate they run in sequence.
- **In-browser demo site (`web/`, GitHub Pages):** the deterministic core
  compiled to WebAssembly runs in a Web Worker (the text never leaves the
  page); the example gallery is generated by the engine in CI and the
  WebAssembly module must reproduce it before the site deploys
  (`.github/workflows/pages.yml`). A standalone crate, not published.
- **crates.io page and feature docs:** `crates-io.md` (Rust-first summary
  whose examples run as doctests), an installation and crate-features
  section in the crate docs, a single docs.rs target, and a CI job that
  builds the docs the way docs.rs does (nightly, `--cfg docsrs`).
- **API conventions (Rust API Guidelines):** every public type implements
  `Debug` (C-DEBUG); `StreamingGuard`, the audit sinks and `NerRouter` do
  it by hand and print no stream text and no HMAC key, only sizes and
  states. The result types that only the library builds (`Decision`,
  `SanitizeResult`, `GuardVerdict`, `SecretFinding`, `StreamGuardScore`,
  `DowngradedSpan`, `ToolVerdict`, `AuditRecord`, `ApiResponse` and the
  evaluation reports) are `#[non_exhaustive]`, so a later release can add
  a field or variant without a breaking change. Input and configuration
  types (`Entity`, which `NerRecognizer` implementations build,
  `GuardSignal`, `Policy`, `RelevanceRule`, ...) stay exhaustive, so struct
  literals and `..Default::default()` keep working. `tests/api_conventions.rs`
  asserts at compile time that the public types are `Send + Sync + Debug`
  and the error types `Error + Send + Sync + 'static`. Workspace lints
  enforce the rest: `missing_debug_implementations`, `unreachable_pub`,
  `clippy::missing_errors_doc`, `clippy::missing_panics_doc`.
- **Mask strategies:** a template without `{type}` is a fixed replacement
  (`[REDACTED]`), `MaskStyle::MaskFirst` / `MaskLast` hide only the first or
  last N characters, and `MaskStyle::by_type` gives each entity type its own
  strategy; over REST they are `mask` styles `mask_first` / `mask_last` and
  the `mask_by_type` object, accepted by the stream endpoints as well as
  `words` and `patterns`.
- **REST request options:** `mask` (label, template, character, partial),
  `words` / `words_ignore_case` (a literal, bounded deny list masked as
  `CUSTOM_WORD`), `patterns` (custom regular expressions restricted to the
  linear-time syntax, `CustomRule::new_linear`) and `system_prompt` on the
  guard and sanitize endpoints;
  `GET /openapi.json` serves an OpenAPI 3.1 description whose example
  requests are exercised by the test suite.
- **Output-side prompt-leak detection:** `Guard::with_system_prompt` and
  `guard::prompt_leak_risk`; new guard category and signal `PROMPT_LEAK`
  (OWASP LLM07), matched on 8-word shingles through normalization, base64
  and escape views.
- **Executable URL schemes:** `vbscript:` joins `javascript:`; a scheme split
  by tab, line feed or carriage return, or written with character references
  (`&#106;`, `&colon;`, `&Tab;`, `&NewLine;`), is caught too
  (`guard::script_scheme_risk`).
- **`CustomRule::deny_list_ignore_case`** and the opt-in policy pack
  `packs/pci-card-cue.toml` (cue-labelled Luhn-invalid card numbers).
- **International phone numbers:** dots as separators and a one-digit first
  group (`+33 1 23 45 67 89`, `+47.20-853.2208`); the compact form
  (`+447700900123`, `+12125551234`) and `+CC NATIONAL` with a space or
  hyphen (`+44 7700900123`), where the country code must be an assigned
  E.164 code (the 215 codes of libphonenumber's country-code map) and a
  `+1` number must be NANP-valid. A signed decimal (`+1.4142135623`) is no
  phone; a signed amount or ID of 10-15 digits that starts with a country
  code (`+25000000000`) is claimed as one (the shape carries no other
  signal).
- **camelCase label cues:** a short cue also starts at a lowercase to
  uppercase change for identifier types, so `customerSsn: 536906292`,
  `employerEin: 10-1234567`, `applicantDni: 12345678Z`,
  `holderPan: AFZPK7190K` - and the same camelCase keys in JSON documents -
  unlock their value; the cue must end its segment (`sendTelemetry`,
  `getTaxonomyNode` unlock nothing). Names and addresses keep the strict
  word start (`fileName: Annual Report` is no NAME).
- **Label forms:** `FEIN:` / `FEIN#` (US EIN) and the dotted `V.K.N.` (TR
  VKN); hyphen-grouped Turkish IBANs (`TR33-0006-1005-...`). The
  international rule stays space-only: its variable-length candidate
  would take a hyphenated tail (`DE89...3000-2024.pdf`) and fail.
- **Turkish phone numbers:** the trunk `0` in parentheses (`(0212) 555 12 34`,
  `0(532) 123 45 67`), `0850` / `0800`, dots as separators, the `0090` and
  `90` country-code forms, `+90` landlines (`+90 (212) 555 12 34`), a
  prefix-less `(532) 123 45 67`, and a contiguous `5321234567` next to a
  phone cue (`tr::phone_bare`). A prefix-less `(212) 555 44 33` stays
  unclaimed (also a NANP number), and no rule starts inside a longer digit
  run (`10532 123 45 67` holds no phone). The formats are eight rules: one
  merged alternation exhausts the backtrack budget on long digit/space
  lines (measured in `tr::phone` tests).
- **Checksum-validated PII detection:** 103 entity types across 26 locale
  packs plus always-on IBAN (89 registry countries), VIN, credit card,
  e-mail, IP address, URL, SWIFT/BIC, international phone numbers and
  cryptocurrency addresses (Bitcoin mainnet base58check and segwit, EIP-55
  checksummed Ethereum).
  Identifiers with a check digit are reported only when it validates;
  identifiers without one need a nearby context cue.
- **Builders:** `Detector` (detect, redact, scan, explain, pseudonymize) and
  `Guard` (decide, sanitize, mask_all) with locale packs, a score
  threshold, an allowlist, custom rules, NER recognizers, caller context
  (`with_context`: a cue in the text the input answers unlocks cue-gated
  identifiers) and mask styles (label, template, character, partial, keyed
  HMAC pseudonym).
- **Custom rules end to end:** custom entity labels
  (`EntityType::custom("EMPLOYEE_ID")` masks as `[EMPLOYEE_ID]`), custom
  rules and the allowlist in `Guard`, `StreamingGuard` and every REST /
  MCP text endpoint, and TOML `[[custom_rules]]` (schema 0.3: a label, a
  pattern or deny-list words, optional cues and score), compiled when the
  policy loads so a bad rule refuses the file. The REST API takes rules
  with look-around or other backtracking constructs only from the server
  policy; a request may carry a bounded literal `words` list and linear-time
  `patterns`.
- **Evasion resistance:** detection also runs on a normalized view (NFKC,
  invisible-character stripping, decimal digit folding for every Unicode
  decimal digit set, mixed-script confusable folding) and on up to three
  base64 layers plus percent and HTML-escape views; findings map back to
  raw-text spans, so the obfuscated value is masked in the output.
- **Guard rules and decisions:** SQL / XSS / SSRF-URL / path traversal /
  command injection / prompt-injection vocabulary / NoSQL / XXE / CRLF /
  XPath rules, credential and API-key detection (`[SECRET:VENDOR]`), a
  policy core (Allow / Log / Mask / Block, per-category thresholds,
  per-target strictness) and a TOML policy file with GDPR, HIPAA and KVKK
  presets.
- **Streaming guard:** incremental masking whose output equals the batch
  output at every chunk split.
- **Reversible vault:** consistent placeholders and restoration, including
  a streaming restorer.
- **JSON redaction:** masks string (optionally number) leaves and reports
  findings by RFC 6901 pointer.
- **Agent tool guard:** deny-by-default tool contracts with budgets, loop
  detection and argument deny patterns.
- **Audit records** that cannot carry content, with a SHA-256-chained JSONL
  sink.
- **REST API** (`api` feature): detect, redact, JSON redact, guard,
  sanitize, batch detect / redact / sanitize, NDJSON and SSE streams, vault
  pseudonymize / restore, tool check, health; optional bearer-token
  authentication (RFC 6750, `REDACTIFY_API_TOKEN`).
- **MCP server** (`redactify-mcp`): detect, redact, guard, vault and tool
  check tools with agent / operator tier isolation. A stdio line is
  bounded (`MAX_LINE`, 8 MiB: a 1 MiB text with worst-case JSON escaping
  plus 2 MiB of envelope); a longer line is read past without being
  buffered and answered with the JSON-RPC server error -32000.
- **CLI:** detect, guard, sanitize, encode, vault, stream and a canary
  monitor. Usage errors exit 2 (an unknown flag, a second TEXT, two
  modes, a flag without its value, an argument that is not valid
  Unicode, which is never echoed); `--` ends the options; the decision's
  exit code (1 on Block) survives a closed stdout.
- **Optional ML layer** (`ml-onnx` feature): ONNX prompt-injection and
  safety classifiers and a multilingual NER router, with fail-closed
  defaults and timeouts.
- **Evaluation tooling:** provenance-tracked evaluation sets, P/R/F1/FPR
  metrics, a false-positive budget gate and a canary monitor in the CLI.
- **Linear cost:** detection, decisions and the vault scale linearly with
  the input, also with caller context, an allowlist and relevance rules
  (each context cue is searched once per pass; overlap resolution is
  O(n log n)). The streaming guard decides every line like the batch
  decision of the stream so far, over bounded windows of each scan view
  (derived per rule family in `policy::stream::decider`): 2,000 short lines
  take 0.15 s through the CLI (one batch decision over the same text
  0.20 s) and memory stays flat;
  only the backtick pairing of the command rule keeps the text from the
  first backtick, and an unclosed template or subshell opener widens the
  window until it closes. A policy set on a running stream applies to
  every line decided after it (a match that completed before the change
  and lies outside the windows is not re-decided; see "Reconfiguring a
  running stream" in the `StreamingGuard` docs). When several signals
  block at once, the Block rationale may name a different signal than the
  batch decision; the decision and the output are identical. Known
  difference: a secret-scan budget error that only appears over the whole
  text (`SCAN_ERROR`, score 0.4, logged by the default policy) is raised by
  the batch decision but not by the stream.

- **Measured precision on the `nm-kvkk-pii-6K` test split:** 2
  credit-card false positives (a 15-digit number must lie in a published
  15-digit range; a run of one repeated digit is no card), VIN F1 0.987 (a
  VIN without a valid check digit is claimed next to a `VIN` / `şasi` cue:
  the check digit is mandatory under US 49 CFR 565, not under EU Reg.
  19/2011), Turkish passport F1 0.978 (`S` prefix, cue-gated), dotted TCKN
  (`232.475.469.02`; spaced forms need a cue). A lowercase compact plate
  needs a cue (uppercase `34ABC123` does not), and a version number after
  `sürüm` / `version` / `v` is no IP address (`conversion 85.105.12.34`
  still is).
- **Cue spelling:** the Turkish label `Müşteri:` unlocks a name like its
  ASCII spelling, and a capitalized label word stays out of the name span.
- **Vault hygiene:** `Debug for Vault` prints counts only, never values;
  placeholder-shaped text already in a prompt (`[NAME_1]`, `[TCKN_1]`)
  keeps its number, issued placeholders skip it, and restore leaves it as
  written.
- **Streaming credentials:** a credential split across lines (`APP_KEY` /
  `=` / value) is masked by the streaming guard as in batch, also under a
  non-blocking secrets policy (`tests/stream_window_bounds.rs`).
- **Audit chain:** every record, nested objects included, is written as one
  parsable JSONL line.
- **PEM private keys:** the whole block is one `[SECRET:PEM_PRIVATE_KEY]`,
  encrypted-PEM headers, JSON-escaped (`\n`) and space-collapsed bodies
  included. A truncated key masks its header and the base64 lines after it
  (prose after them stays), bounded at 16 KiB; the streaming guard holds an
  open block (at most 16 KiB), so its output equals the batch masking (held
  lines are rescanned, which costs time while a block is open).
- **Code that reads a secret is no credential:** a call or subscript whose
  arguments are quoted strings (or identifiers after a qualified callee:
  `password = os.environ["DB_PASSWORD"]`, `os.getenv("X")`,
  `config.get(name)`, `load_secret()`, `ENV["X"]`) and a dotted path under a
  configuration root (`process.env.API_KEY`) are not masked;
  `Summer2024(!)`, `Tr0ub4dor(2024)` or `Pa55(word)xyz!` are. A credential
  mask never leaves half a token in clear.
- **Credential keys:** the credential word must end the key, with any
  prefix, and the key may be quoted, so the standard `.env` keys
  (`DB_PASSWORD`, `MAIL_PASSWORD`, `APP_SECRET`, `JWT_SECRET`,
  `STRIPE_SECRET_KEY`, `GITHUB_TOKEN`, `APP_KEY`) and quoted JSON keys
  (`"password": "..."`) are secrets; `PASSWORD_RESET_URL`, `TOKEN_EXPIRY`
  and `CACHE_KEY` are not.
- **Phone numbers versus cards:** about one digit run in ten passes Luhn. A
  `+`-prefixed compact or `+CC NATIONAL` run that is a valid E.164 number
  (`+4915112345678`, `+86 13812345678`) is a phone; any other `+`-prefixed
  card (`my+card+is+4111111111111111` in a URL-encoded body) is masked
  whole, `+` included. A 13-15 digit card right after `+` whose head is a
  country code is masked as PHONE.
- **Fractions are no cards:** an unseparated run right after `<digit>.`
  (`score 0.4111111111111111`) is no card candidate; a grouped one
  (`item 1.4111 1111 1111 1111`) is, since a fraction holds no separator.
  A card glued to a dotted date (`21.11.2026.4111...`) is not claimed. A
  decimal comma is not skipped (`1,4111111111111111,John` is a CSV row as
  often).
- **Plates:** a candidate whose letter group is a unit of measure (`GB`,
  `MHZ`, `KG`, `CM`, ...) and whose digits are followed by a unit is a
  specification (`Laptop 16 GB 512 GB SSD`), not a plate; one unit alone
  keeps the plate (`plaka 34 AB 123 KM`, `34 AB 1234 Mah.`). A province
  code right after a standalone 1-2 digit number and `/` or `.` is the year
  of a date, so `SKT 06/27 CVV 123` yields a card expiry and a card code;
  plates joined by a slash (`34 ABC 123/06 AB 1234`) keep their labels.
- **Encoded payloads:** every base64 candidate is decoded (`layered_views`,
  one candidate per line), so a longer benign token next to an ID, an API
  key, a prompt injection or SQL does not hide it. Every masking path
  (sanitize on every branch, `Guard::mask_all`, the streaming emission, the
  ML input) masks an encoded credential as `[SECRET:VENDOR]` and encoded
  PII as its entity type, over the raw span (cost in
  `docs/evasion-v1.md`).
- **ML timeouts are hard bounds:** the inference worker measures each
  inference and sends its duration with the answer; an answer whose
  inference took longer than the timeout is a timeout (and degrades the
  lane) however late it is read, and a zero timeout fails every call. A
  call queued behind other callers waits while the worker makes progress,
  so the verdict does not depend on load; a stuck worker fails the call and
  degrades the lane.
- **Code-friendly guard rules:** a Markdown code span counts as a command
  only when its content is a shell command, and fenced blocks are skipped;
  `time.sleep(2)`, `/* comment */`, `exec(code)` and `benchmark(f, n)` are
  no SQL injection, while `1 AND SLEEP(5)`, `admin'/*`, `; EXEC(@q)` and
  `BENCHMARK(5000000, MD5(1))` are; `AssertionError`, `ConnectionError` and
  similar raise no obfuscation signal (only a word that the letter-joining
  itself creates counts).
- **Task-hijack template in tool output:** the "important message from me
  ... to you" / "before you can solve the task that I gave you" framing is
  a tool-injection signal.
- **Safety gate:** the gate reads the raw security score
  (`MlClassifier::classify_with_raw`), and PII does not bypass it, so the
  safety model does not flag text whose PII the rules already masked. On
  the benchmark sets: 165 of 230 safety attacks and 186 of 290 injection
  attacks blocked; on the GuardBench slice 305 of 1,748 attacks and 25 of
  1,351 benign texts flagged.

[Unreleased]: https://github.com/mrcuren/redactify/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mrcuren/redactify/releases/tag/v0.1.0
