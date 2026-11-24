# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a vulnerability

We take security issues seriously, especially given this project's purpose - protecting
personal data. **Please do not report vulnerabilities through public GitHub issues.**

Instead, use GitHub's **private vulnerability reporting**:

1. Go to this repository on GitHub.
2. Open the **Security** tab → **Advisories** → **Report a vulnerability**.

Please include as much of the following as you can:

- The type of issue (e.g. ReDoS via crafted input, incorrect detection leading to PII
  leakage, panic on malformed input).
- Full steps or a minimal reproducer (sample input text).
- Impact assessment, especially if the bug could cause PII to be missed (false negative)
  or wrongly exposed (false positive).
- Any possible mitigation you identified.

We aim to acknowledge reports within a few days and will keep you informed about the
progress toward a fix and an announcement.

### What counts as a security issue here

Because redactify is a PII detection library, both of these classes are security-relevant:

- **Missed PII (false negatives):** a formatting variation that causes a real identifier
  not to be detected can leak personal data downstream.
- **Crashes / DoS:** panics on malformed or adversarial input, or catastrophic regex
  backtracking (the scanner is line-scoped precisely to bound this; see
  `src/pii/detect.rs`).

## Disclosure timeline

We follow coordinated disclosure: a fix is prepared, a patched release is published, and
the advisory is credited to the reporter (unless anonymity is requested).

## Advisories

Vulnerability reports go through GitHub's private vulnerability reporting
(Report a vulnerability on this repository's Security tab). Please do not
open public issues for security problems. Include reproduction input where
possible - every detection/redaction bug class in this repo (false
negatives that leak PII, panics on malformed input, regex backtracking) is
treated as a security issue per the scope above. Fixes ship with a
regression test and a CHANGELOG entry; disclosures are coordinated with
reporters. There is no PGP key or dedicated security email at this time -
the private reporting channel is the interface.

## Supply chain

- Dependencies are few and reviewed by the maintainers (no independent
  security audit has been done; `cargo deny` license +
  advisory + sources policy in CI; `Cargo.lock` committed and every CI
  build runs `--locked`, except the `fresh-config` job, which runs
  `cargo update -p toml` on purpose to catch a new `toml` release that
  breaks the `config` feature).
- ML models are NOT shipped: local, SHA-256-pinned artifacts
  (`ml_models.pins.sha256`, verified with `sha256sum -c ml_models.pins.sha256`).
- Release images build from the locked manifest in a multi-stage Docker
  build (non-root uid, read-only rootfs in compose).
- The published crate excludes dev/ops tooling and model pins (see
  `Cargo.toml` `exclude`).
