# redactify-mcp

MCP (Model Context Protocol) server for [redactify](https://github.com/mrcuren/redactify):
PII detection, redaction, guard decisions, the reversible pseudonymization vault and the agent
tool-call guard, exposed as agent tools over newline-delimited JSON-RPC 2.0 on
stdio. Everything runs locally: no network, no models in the default build.

## Install and run

From crates.io:

```sh
cargo install redactify-mcp
redactify-mcp                     # agent tier
redactify-mcp --allow-restore     # operator tier
```

From a checkout of the repository:

```sh
cargo run --release -p redactify-mcp                    # agent tier
cargo run --release -p redactify-mcp -- --allow-restore  # operator tier
```

Point your MCP client at the built binary as a stdio server. An optional TOML
policy is read from `REDACTIFY_POLICY`; a malformed file (or a value that is
not valid Unicode) refuses startup. `REDACTIFY_AUDIT_FILE` appends every
`tool_check` decision to a hash-chained audit log (`REDACTIFY_AUDIT_KEY`
adds an HMAC key); an existing file that does not verify refuses startup.

## Tools

| Tool | Returns |
|---|---|
| `detect` | entity spans only (type, offsets, score); raw values never enter the model context |
| `redact` | masked text (leaked credentials first, then PII) |
| `guard` | the guard decision; a `Block` returns the loggable re-mask |
| `vault_pseudonymize` | the pseudonymized text only (placeholders); the placeholder mapping never transits the model context |
| `vault_restore` | the restored text; operator tier only (`--allow-restore`), refused otherwise |
| `tool_check` | the tool-call verdict and its stable code, never the checked call's arguments; with `session_id` the server keeps the call history (budgets cannot be reset by omitting it) |

`detect`, `redact`, `guard` and `vault_pseudonymize` take optional `locales` (exact codes from
`redactify::SUPPORTED_LOCALES`; anything else is JSON-RPC error -32602). Argument
errors never echo the offending value, and a panic inside a tool is answered
with JSON-RPC error -32603 while the server keeps serving.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
