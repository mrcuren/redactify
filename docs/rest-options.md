# REST per-request options

Every text endpoint takes `ignore` (values to leave in the text); all of
them except the two stream endpoints take `context` (the text this text
answers).

Per-request options of the detect, redact, JSON, guard, sanitize, batch and
stream endpoints (the vault endpoint takes `words` and `patterns` only):

- `mask`: how a span is rendered, one of `{"style": "label"}` (default),
  `{"style": "template", "template": "[REDACTED]"}` (`{type}` becomes the type
  label; without it the text is a fixed replacement), `{"style": "char",
  "char": "*"}`, `{"style": "partial", "keep_last": 4, "char": "*"}` (all but
  the last characters), `{"style": "mask_first", "count": 3, "char": "*"}` or
  `{"style": "mask_last", "count": 4, "char": "*"}` (only that many characters
  from the start or the end). A keyed pseudonym style is not offered over HTTP
  because it needs a server-held key.
- `mask_by_type`: a strategy per entity type, e.g. `{"EMAIL": {"style":
  "char", "char": "*"}, "CREDIT_CARD": {"style": "mask_last", "count": 4,
  "char": "#"}}`. A type without an entry uses `mask`.
- `words`: a literal deny list (at most 256 words of at most 128 bytes),
  matched as whole words and masked as `CUSTOM_WORD`; `"words_ignore_case":
  true` ignores letter case.
- `patterns`: up to 16 custom regular expressions, each `{"pattern": "...",
  "label": "ITIN", "cues": ["order"], "score": 0.9}` (only `pattern` is
  required). Only the linear-time syntax is accepted: look-around,
  back-references and atomic groups are refused, so the engine never
  backtracks and a caller cannot choose the scan cost. A pattern is at most
  256 bytes and must match at least 3 characters at the shortest. Matches are
  `CUSTOM_PATTERN`, or the `label` when it names an entity type that already
  exists (a request never registers a label). Patterns that need look-around
  stay in the server policy.
- `system_prompt` (`/v1/guard`, `/v1/sanitize`, `/v1/batch/sanitize` with
  `"target": "model_output"`): a model output that reproduces a run of 8 or
  more words of this prompt gets a `PROMPT_LEAK` verdict (OWASP LLM07). It
  matches through case, punctuation, zero-width characters, fullwidth forms,
  base64 and percent or HTML-reference encodings, and its signal carries
  counts only, never prompt text.

The machine-readable description of every endpoint and option is served at
`GET /openapi.json`.
