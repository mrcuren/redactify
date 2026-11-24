//! TOML policy configuration acceptance (`config` feature): bundled packs
//! parse, malformed inputs refuse loudly, and a loaded policy actually
//! changes decisions.

#![cfg(feature = "config")]

use std::path::PathBuf;

use redactify::guard::{GuardSignal, SignalKind};
use redactify::policy::{decide, guard_all, load_policy_env, GuardAction, Policy};

fn pack_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("packs")
        .join(name)
}

#[test]
fn bundled_packs_parse() {
    for (name, want_block_at) in [
        ("kvkk.tr.toml", 0.60),
        ("gdpr.toml", 0.60),
        ("hipaa.toml", 0.50),
    ] {
        let p = Policy::load_toml_file(pack_path(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!((p.block_at - want_block_at).abs() < 1e-6, "{name}");
        assert!((p.log_at - 0.40).abs() < 1e-6 || (p.log_at - 0.30).abs() < 1e-6);
    }
}

#[test]
fn pack_pack_categories_block_their_signals() {
    // kvkk pack: NER_DEGRADED at band low must BLOCK the 0.4 health signal
    // (the documented fail-closed-enricher knob)
    let p = Policy::load_toml_file(pack_path("kvkk.tr.toml")).unwrap();
    let signals = vec![GuardSignal {
        kind: SignalKind::NerDegraded,
        score: 0.4,
        evidence: "ner".into(),
        rationale: "ner enricher degraded".into(),
    }];
    let d = decide(&signals, &[], &p);
    assert_eq!(d.action, GuardAction::Block);
}

#[test]
fn default_policy_does_not_block_ner_degraded() {
    // sanity mirror: without the pack the same signal only logs
    let signals = vec![GuardSignal {
        kind: SignalKind::NerDegraded,
        score: 0.4,
        evidence: "ner".into(),
        rationale: "ner enricher degraded".into(),
    }];
    let d = decide(&signals, &[], &Policy::default());
    assert_eq!(d.action, GuardAction::Log);
}

#[test]
fn unknown_schema_version_refused() {
    // schema 0.2 adds relevance rules, 0.3 custom rules, 0.4 entity
    // actions and dry run; the refuse-gate bites at 0.5
    let err = Policy::from_toml("schema_version = \"0.5\"\nblock_at = 0.5\n").unwrap_err();
    assert!(err.to_string().contains("schema_version"), "{err}");
    // and 0.2, 0.3 and 0.4 parse
    for v in ["0.2", "0.3", "0.4"] {
        let p = Policy::from_toml(&format!("schema_version = \"{v}\"\nblock_at = 0.5\n")).unwrap();
        assert_eq!(p.block_at, 0.5);
        assert!(p.relevance.is_empty());
        assert!(p.custom_rules.is_empty());
    }
}

#[test]
fn unknown_category_and_band_refused() {
    let e = Policy::from_toml("schema_version = \"0.1\"\n[categories]\nNOT_A_CATEGORY = \"low\"\n")
        .unwrap_err();
    assert!(e.to_string().contains("NOT_A_CATEGORY"), "{e}");
    let e = Policy::from_toml("schema_version = \"0.1\"\n[categories]\nSECRETS = \"extreme\"\n")
        .unwrap_err();
    assert!(e.to_string().contains("extreme"), "{e}");
}

#[test]
fn out_of_range_thresholds_refused() {
    let e = Policy::from_toml("schema_version = \"0.1\"\nblock_at = 1.5\n").unwrap_err();
    assert!(e.to_string().contains("range"), "{e}");
}

#[test]
fn log_line_above_the_block_line_refused() {
    let e =
        Policy::from_toml("schema_version = \"0.2\"\nblock_at = 0.5\nlog_at = 0.6\n").unwrap_err();
    assert!(
        matches!(e, redactify::policy::ConfigError::LogAboveBlock { .. }),
        "{e}"
    );
    assert!(e.to_string().contains("log_at"), "{e}");
}

#[test]
fn pack_overrides_on_tool_response_keep_only_stricter_bands() {
    use redactify::policy::{GuardCategory, GuardTarget};
    // kvkk: NER_DEGRADED / ENCODED_PII = low (0.35, stricter than the tool
    // line) survive; SECRETS = medium (0.60, looser) falls back to 0.5
    let p = Policy::load_toml_file(pack_path("kvkk.tr.toml")).unwrap();
    let tool = p.for_target(&GuardTarget::ToolResponse);
    assert_eq!(tool.block_line_for(GuardCategory::NerDegraded), 0.35);
    assert_eq!(tool.block_line_for(GuardCategory::EncodedPii), 0.35);
    assert_eq!(tool.block_line_for(GuardCategory::Secrets), 0.5);
    // the user-prompt target keeps the pack as written
    let user = p.for_target(&GuardTarget::UserPrompt);
    assert_eq!(user.block_line_for(GuardCategory::Secrets), 0.60);
}

#[test]
fn pack_default_locales_reach_guard_and_stream() {
    use redactify::policy::{GuardTarget, StreamingGuard};
    use redactify::Guard;
    // gdpr lists the uk pack: no explicit locales needed
    let gdpr = Policy::load_toml_file(pack_path("gdpr.toml")).unwrap();
    let r = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&gdpr)
        .sanitize("nhs 9434765870");
    assert_eq!(r.text, "nhs [UK_NHS]");
    let mut sg = StreamingGuard::new(GuardTarget::UserPrompt).with_policy(gdpr);
    let ev = sg.push("nhs 9434765870\n");
    assert_eq!(ev[0].as_segment().unwrap().0, "nhs [UK_NHS]\n");
}

#[test]
fn omitted_fields_take_defaults() {
    let p = Policy::from_toml("schema_version = \"0.1\"\n").unwrap();
    assert_eq!(p.block_at, Policy::default().block_at);
    assert_eq!(p.log_at, Policy::default().log_at);
}

#[test]
fn env_loader_reports_missing_variable() {
    // ensure the variable is absent for this test's environment
    std::env::remove_var(redactify::policy::POLICY_ENV_VAR);
    let err = load_policy_env().unwrap_err();
    assert!(err.to_string().contains("REDACTIFY_POLICY"), "{err}");
}

#[test]
fn hipaa_pack_tightens_the_global_line() {
    // hipaa blocks a 0.55 signal globally where the default would only log
    let signals = vec![GuardSignal {
        kind: SignalKind::Obfuscation,
        score: 0.55,
        evidence: "d r o p t a b l e".into(),
        rationale: "obfuscation".into(),
    }];
    let hipaa = Policy::load_toml_file(pack_path("hipaa.toml")).unwrap();
    assert_eq!(decide(&signals, &[], &hipaa).action, GuardAction::Block);
    assert_eq!(
        decide(&signals, &[], &Policy::default()).action,
        GuardAction::Log
    );
}

#[test]
fn packs_do_not_break_the_default_guard() {
    // regression sanity: the shipped default path is unaffected by packs
    assert_eq!(guard_all("bugun hava cok guzel").action, GuardAction::Allow);
}

// The two api_wiring tests below need BOTH features: the file gate needs
// `config` (TOML packs) and the handler surface needs `api`. Neither
// single-feature CI step compiles them, so they run in the combined
// "api config" step instead of failing `--features config` builds.
#[test]
#[cfg(all(feature = "config", feature = "api"))]
fn api_state_policy_changes_guard_decisions() {
    // the wired Docker story: a loaded pack changes what the SERVED API
    // blocks. Borderline obfuscation line (0.55): default logs, hipaa
    // (block_at 0.50) blocks.
    let body = r#"{"text": "kural: d r o p t a b l e kullanicilar"}"#;
    let default = redactify::api::handle_request("POST", "/v1/guard", body);
    let dv: serde_json::Value = serde_json::from_str(&default.body).unwrap();
    assert_eq!(dv["action"], "Log", "default policy changed: {dv}");

    let hipaa = Policy::load_toml_file(pack_path("hipaa.toml")).unwrap();
    let state = redactify::api::ApiState::default().with_policy(hipaa);
    let strict = redactify::api::handle_request_with(&state, "POST", "/v1/guard", body);
    let sv: serde_json::Value = serde_json::from_str(&strict.body).unwrap();
    assert_eq!(sv["action"], "Block", "hipaa policy not wired: {sv}");
}

#[test]
#[cfg(all(feature = "config", feature = "api"))]
fn api_state_policy_flows_into_the_stream_endpoint() {
    let body = r#"{"chunks": ["kural: d r o p t a b l e kullanicilar\n"]}"#;
    // default policy: the borderline line emits a segment
    let default = redactify::api::handle_request("POST", "/v1/stream/sanitize", body);
    assert!(
        default.body.contains("\"type\":\"segment\""),
        "{}",
        default.body
    );

    let hipaa = Policy::load_toml_file(pack_path("hipaa.toml")).unwrap();
    let state = redactify::api::ApiState::default().with_policy(hipaa);
    let strict = redactify::api::handle_request_with(&state, "POST", "/v1/stream/sanitize", body);
    assert!(
        strict.body.contains("\"type\":\"block\""),
        "stream ignored the policy: {}",
        strict.body
    );
}

#[test]
fn tool_response_keeps_builtin_strictness_under_custom_policy() {
    // for_target: even a LOOSE custom policy cannot soften ToolResponse
    // below the built-in 0.5/0.3 lines
    let loose = Policy {
        block_at: 0.9,
        log_at: 0.8,
        ..Policy::default()
    };
    let tool = loose.for_target(&redactify::policy::GuardTarget::ToolResponse);
    assert_eq!(tool.block_at, 0.5);
    assert_eq!(tool.log_at, 0.3);
    // other targets keep the custom lines untouched
    let user = loose.for_target(&redactify::policy::GuardTarget::UserPrompt);
    assert_eq!(user.block_at, 0.9);
}

#[test]
fn streaming_guard_with_policy_tightens_the_line() {
    use redactify::policy::{GuardEvent, GuardTarget, StreamingGuard};
    let mut sg = StreamingGuard::new(GuardTarget::UserPrompt).with_policy(Policy {
        block_at: 0.5,
        log_at: 0.3,
        ..Policy::default()
    });
    let events = sg.push("kural: d r o p t a b l e kullanicilar\n");
    assert!(
        events.iter().any(|e| matches!(e, GuardEvent::Block { .. })),
        "policy not applied to the stream: {events:?}"
    );
    // and without the policy the same line passes through as a segment
    let mut sg2 = StreamingGuard::new(GuardTarget::UserPrompt);
    let events2 = sg2.push("kural: d r o p t a b l e kullanicilar\n");
    assert!(events2.iter().all(|e| e.as_segment().is_some()));
}

mod config_schema {
    use redactify::policy::{ConfigError, GuardCategory, Policy, Threshold};

    /// TOOL_INJECTION is part of the TOML category list: it can be
    /// configured and disabled like every other category.
    #[test]
    fn tool_injection_is_configurable() {
        let p = Policy::from_toml(
            r#"
            schema_version = "0.2"
            [categories]
            TOOL_INJECTION = "none"
            "#,
        )
        .unwrap();
        assert_eq!(
            p.categories.get(GuardCategory::ToolInjection),
            Some(Threshold::None)
        );
        let disabled = Policy::from_toml(
            r#"
            schema_version = "0.2"
            disabled = ["TOOL_INJECTION"]
            "#,
        )
        .unwrap();
        assert!(disabled.disabled.contains(&GuardCategory::ToolInjection));
    }

    /// Fail-closed parsing: a typo'd or unknown key refuses the whole file
    /// instead of being silently ignored.
    #[test]
    fn unknown_toml_keys_refuse_parsing() {
        let e = Policy::from_toml("schema_version = \"0.2\"\nblok_at = 0.5").unwrap_err();
        assert!(matches!(e, ConfigError::Toml(_)), "{e}");
        let e = Policy::from_toml(
            "schema_version = \"0.2\"\n[[relevance.rules]]\nentty_types = [\"PHONE\"]\ncue_any = [\"x\"]",
        )
        .unwrap_err();
        assert!(matches!(e, ConfigError::Toml(_)), "{e}");
    }
}

/// The GDPR scope does not depend on nationality (Regulation (EU) 2016/679
/// Art. 3, Art. 4(1) and Recital 14), so `packs/gdpr.toml` keeps the tr+en
/// default locales next to the EU packs.
#[test]
fn gdpr_pack_keeps_the_tr_en_default() {
    use redactify::policy::GuardTarget;
    use redactify::Guard;
    let gdpr =
        Policy::load_toml_file(pack_path("gdpr.toml")).unwrap_or_else(|e| panic!("gdpr.toml: {e}"));
    for code in ["tr", "en", "de", "fr", "es", "nl", "uk", "it", "pl", "pt"] {
        assert!(gdpr.default_locales.iter().any(|c| c == code), "{code}");
    }
    let guard = Guard::new(GuardTarget::UserPrompt).with_policy(&gdpr);
    // a Turkish national's identity number (TCKN) is masked under GDPR
    assert_eq!(guard.sanitize("TCKN 12345678950").text, "TCKN [TCKN]");
    // the EU packs stay on
    assert_eq!(guard.sanitize("nhs 9434765870").text, "nhs [UK_NHS]");
}

/// `hipaa` and `kvkk.tr` list no locales and keep the built-in default.
#[test]
fn hipaa_and_kvkk_packs_keep_the_builtin_default() {
    use redactify::policy::GuardTarget;
    use redactify::Guard;
    for name in ["hipaa.toml", "kvkk.tr.toml"] {
        let p = Policy::load_toml_file(pack_path(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(p.default_locales.is_empty(), "{name}");
        let guard = Guard::new(GuardTarget::UserPrompt).with_policy(&p);
        assert_eq!(
            guard.sanitize("TCKN 12345678950").text,
            "TCKN [TCKN]",
            "{name}"
        );
    }
}
