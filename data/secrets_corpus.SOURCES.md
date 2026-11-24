# secrets_corpus.jsonl - two-source notes

Every secret rule family below is grounded in
two sources: (1) the vendor's own token-format documentation, (2) a second
vendor-owned page or, for the older families, an independent public rule
set describing the same shape. Families whose vendor documentation does
not state a length or character set say so explicitly (evidence gap, not a
claim). Rows marked "retrieved 2026-10-29" were re-verified on that date;
the other vendor links are cited from the canonical documentation locations
and must be re-verified right before the first crates.io publish (recorded
as a pending item, not a claim).

No online "is this key live" verification exists anywhere in the crate: the
core never touches the network. A 0.9 score means "vendor shape confirmed".

| Rule family | Source 1 (vendor docs) | Source 2 |
|---|---|---|
| AWS_ACCESS_KEY | AWS IAM docs, "Understanding unique identifiers" (docs.aws.amazon.com/IAM): AKIA/ASIA/AGPA/AIDA/AROA/AIPA/ANPA/ANVA/ABIA/ACCA/A3T prefixes, 20-char key ids | independent public rule set: `(?:A3T[A-Z0-9]|AKIA|...)[A-Z0-9]{16}` |
| AWS_SECRET_KEY | AWS IAM docs: secret access keys are 40-char base64-ish strings | independent public rule sets: 40-char values behind an `aws` cue |
| GITHUB_TOKEN | GitHub docs "Token formats" (docs.github.com): ghp/gho/ghu/ghs/ghr + 36; github_pat_ + 82 | independent public rule set (classic and fine-grained PAT shapes) |
| SLACK_TOKEN | Slack API docs, "Token types" (api.slack.com): xoxb/xoxp/xoxa/xoxr/xoxs classic 3-segment form | independent public rule set (same classic shape) |
| SLACK_APP_TOKEN | Slack developer docs, "Tokens" (https://docs.slack.dev/authentication/tokens, retrieved 2026-10-29): "App-level token strings begin with `xapp-`"; sections are separated by `-` and the final section is the secret. The page states no length or character set: the `xapp-1-` + `[A-Za-z0-9-]{20,}` bound is structural (evidence gap) | same page: rotating app-level tokens begin with `xoxe.xapp-` (the `xapp-` marker still occurs) |
| SLACK_WEBHOOK | Slack docs, incoming webhooks (hooks.slack.com/services/T.../B.../...) | independent public rule set (webhook URL shape) |
| STRIPE_KEY / STRIPE_TEST_KEY | Stripe docs, "API keys": sk_live_/rk_live_ secret keys (pk_ publishable deliberately NOT treated as a secret) | independent public rule set |
| OPENAI_KEY | OpenAI platform docs (platform.openai.com): sk-proj- project keys; legacy sk- prefixed keys | independent public rule set |
| ANTHROPIC_KEY | Anthropic docs (docs.anthropic.com): sk-ant- (+ api03- generation marker) | independent public rule set |
| GOOGLE_API_KEY | Google Cloud docs: API keys start AIza + 35 chars | independent public rule set |
| GOOGLE_OAUTH | Google Codelabs, "How to generate image from Vertex AI and Upload to Google Ads" (https://codelabs.developers.google.com/generate_creatives_google_ads, found 2026-10-29): a client-secret placeholder `GOCSPX-abcd1234-abcd1234-abcd1234` next to a `.apps.googleusercontent.com` client id. No Google page found states the GOCSPX length or charset: the `[A-Za-z0-9_-]{28,}` bound is structural (evidence gap) | Google Cloud console help, "Manage OAuth Clients" (https://support.google.com/cloud/answer/15549257, found 2026-10-29): client secrets are shown in full only once at creation (supports treating the value as a secret; says nothing about its shape) |
| GITLAB_TOKEN | GitLab docs, "GitLab token overview" (https://docs.gitlab.com/security/tokens/, retrieved 2026-10-29): `glpat-` prefix (personal, impersonation, project and group access tokens). The page states no length or character set | independent public rule set (`glpat-` + 20 token chars) |
| NPM_TOKEN | npm docs, granular access tokens: npm_ + 36 | independent public rule set |
| PYPI_TOKEN | PyPI docs, upload tokens: pypi- + base64("api.python.org") = pypi-AgEIcHlwaS5vcmc prefix | independent public rule set |
| SENDGRID_KEY | SendGrid docs: SG.\<segment>.\<secret\> key shape | independent public rule set |
| TELEGRAM_TOKEN | Telegram Bot API docs (core.telegram.org/bots): bot_id:AA + tail (documented example tail 32; live tokens 33-35 -> pattern 30-40, anchor is digits:AA) | independent public rule set |
| TWILIO_SID | Twilio docs, "What is a String Identifier (SID)?" (https://www.twilio.com/docs/glossary/what-is-a-sid, retrieved 2026-10-31): "Twilio identifies every resource with a 34-character String Identifier (SID). This SID consists of a two-letter prefix followed by 32 hexadecimal digits"; prefix table row `AC` = Account | Twilio REST API reference, "Key Resource v2010" (https://www.twilio.com/docs/iam/api-keys/key-resource-v2010, retrieved 2026-10-31): `accountSid` "Pattern: ^AC[0-9a-fA-F]{32}$ Min length: 34 Max length: 34". The rule matches the schema's hex set (both cases) |
| TWILIO_KEY | same SID page: prefix table row `SK` = "API Key" (the 34-character API Key SID that identifies the key; the separate key secret has no documented shape) | same Key Resource reference: `sid` of type `SID<SK>`, "Pattern: ^SK[0-9a-fA-F]{32}$ Min length: 34 Max length: 34". One rule at 0.9 (2026-10-31: the former `TWILIO_TOKEN` 0.9 rule, lowercase hex, and the `TWILIO_KEY` 0.6 rule, both cases, matched the same `SK` shape and were merged under the vendor's name) |
| DOPPLER_TOKEN | Doppler docs, "Auth Token Formats" (https://docs.doppler.com/reference/auth-token-formats, retrieved 2026-10-29): personal `/dp\.pt\.[a-zA-Z0-9]{40,44}/`, CLI `dp.ct.`, service `/dp\.st\.(?:[a-z0-9\-_]{2,35}\.)?[a-zA-Z0-9]{40,44}/`, service account `dp.sa.`, service account identity `dp.said.`, SCIM `dp.scim.`, audit `dp.audit.` (all with the 40-44 alnum body); test vectors are the vendor's published examples | Doppler docs, "Service Tokens" (https://docs.doppler.com/docs/service-tokens, retrieved 2026-10-29): usage examples `dp.st.prd.xxxx`, `dp.st.dev.fHhinxK...` (the optional environment segment) |
| AZURE_STORAGE_KEY | Azure storage docs, connection string: AccountKey=base64 (88-char standard key, min 50 enforced) | independent public rule set (connection-string assignment shape) |
| PEM_PRIVATE_KEY | RFC 7468, "Textual Encodings of PKIX...": -----BEGIN x PRIVATE KEY----- headers | independent public rule set |
| JWT | RFC 7519 (JWS compact serialization: 3 base64url segments) | structural validation in-tree: base64url-decoded header must parse as JSON containing an `alg` claim (the second gate IS code, not a second doc) |
| CREDENTIAL_ASSIGNMENT | Common configuration grammar (KEY=value / "KEY": "value" across dotenv/JSON/YAML) | independent public rule sets (assignment detection) + placeholder list from OWASP/CWE-798 documented placeholder values |
| BEARER_TOKEN | RFC 6750, "Authorization: Bearer" | independent public rule sets (Authorization header capture) |
| URL_CREDENTIALS | RFC 3986 section 3.2.1, userinfo user:pass@ | independent public rule sets (URL credential detection) |
| HIGH_ENTROPY | Shannon, "A Mathematical Theory of Communication" (1948) - exact entropy, not an approximation | independent public rule sets' entropy thresholds (hex 3.0 / base64 4.5); ours raised to 3.2/4.2 and cue-adjacency made mandatory after benign-canary calibration |

## Vendors considered and NOT added (2026-10-29)

The gate for a new vendor is: the vendor's own documentation states the
token prefix AND its length or character set, plus a second vendor-owned
page. Candidates that failed the gate:

- GitLab non-PAT tokens (`gloas-`, `gldt-`, `glrt-`, `glcbt-`, `glptt-`,
  `glft-`, `glimt-`, `glagent-`, `glwt-`, `glsoat-`, `glffct-`): the token
  overview lists the prefixes but states no length or character set.
- Hugging Face user access tokens (`hf_`): the user access token page
  shows only `hf_...`; no length or character set.
- DigitalOcean personal access tokens (`dop_v1_`): the token how-to page
  states no prefix, length or character set.
- Shopify access tokens (`shpat_`, `shppa_`): documented as opaque
  strings; no length or character set.

## Decisions recorded (measured or reasoned, not assumed)

- pk_live_ (publishable Stripe keys) excluded: publishable by design.
- Test-tier keys (sk_test_, rk_test_) score 0.6, not 0.9: still a leaked
  credential, not a production one.
- Bare high-entropy runs with no cue word NEVER fire: git commit SHAs are
  40-char hex with ~3.9 bits/char and would flood any log-scanning use.
- Placeholder values (changeme, <your_key_here>, ${VAR}, ...) never fire
  (CWE-798 documents the common placeholder set).
- Telegram tail length widened to 30-40: the documented example and common
  live tokens disagree on the exact tail length; the digits:AA anchor is
  the load-bearing part of the shape.
- Doppler tokens are matched exactly as documented (40-44 alnum body,
  lowercase environment segment); a 39- or 45-char body does not match.
