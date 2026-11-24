//! Guided tour of the redactify surface: detect/redact, thresholds, the
//! guard pipeline, per-category policy thresholds, secrets detection, and
//! the vault.
fn main() {
    // 1) PII detection + masking (checksum-validated precision)
    let text = "TCKN 12345678950, IBAN TR33 0006 1005 1978 6457 8413 26, mail a@b.com";
    println!("redact : {}", redactify::redact(text));
    for e in redactify::detect(text) {
        println!(
            "  {:<12} [{}..{}] score {:.2}",
            e.kind, e.start, e.end, e.score
        );
    }

    // 2) The full guard pipeline: deterministic rules + PII + policy
    use redactify::policy::{guard_all, sanitize, GuardAction, GuardTarget};
    let d = guard_all("see http://169.254.169.254/meta");
    println!("guard  : {:?} - {}", d.action, d.rationale);
    let r = sanitize("TCKN 12345678950 and x < y", &GuardTarget::ModelOutput);
    println!("sanitize: {:?} -> {}", r.decision.action, r.text);

    // 3) Per-category thresholds: monitor URLs, block SQL only at HIGH
    use redactify::guard::sql_risk;
    use redactify::{decide, GuardCategory, Policy, Threshold};
    let policy = Policy::default()
        .with_category(GuardCategory::SqlInjection, Threshold::High)
        .with_category(GuardCategory::DangerousUrl, Threshold::None);
    let sigs = [sql_risk("SELECT 1; -- comment").unwrap()]; // level-1 signature, 0.6
    let d = decide(&sigs, &[], &policy);
    println!(
        "policy : 0.6 SQL with High band -> {:?} (global 0.6 would Block)",
        d.action
    );
    let _ = GuardAction::Allow;

    // 4) Secrets: leaked credentials are blocked AND masked out of every
    // sanitize branch (evidence in decisions never echoes the value)
    let d = guard_all("deploy key AKIAIOSFODNN7EXAMPLE sent");
    println!("secrets: {:?} - {}", d.action, d.rationale);

    // 5) Vault: reversible pseudonymization
    let (anon, vault) = redactify::Vault::pseudonymize(text);
    println!("vault  : {}", anon);
    println!(
        "vault  : {} entries, round-trip ok = {}",
        vault.len(),
        vault.restore(&anon) == text
    );
}
