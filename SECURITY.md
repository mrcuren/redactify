# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅        |
| < 0.2   | ❌        |

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
  `src/detect.rs`).

## Disclosure timeline

We follow coordinated disclosure: a fix is prepared, a patched release is published, and
the advisory is credited to the reporter (unless anonymity is requested).
