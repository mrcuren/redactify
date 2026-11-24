//! Adversarial coverage for the opt-in locale rule packs:
//! encoding/obfuscation bypass attempts, cue boundary conditions,
//! separator-scatter probes and overlap corners, measured end-to-end
//! through the locale-aware guard runtime.
//!
//! Every case asserts the observed end-to-end behavior;
//! cases where an evasion exists at the raw detect() layer are asserted
//! to be caught by the L0 normalization pipeline (NFKC + invisible
//! stripping + base64 layering) that the policy path runs.

use redactify::guard::normalize::normalize_for_scan;
use redactify::policy::{GuardAction, GuardTarget};
use redactify::{redact, Detector, EntityType, Guard};

fn base64(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s)
}

// ------------------------------------------------------ guard reachability

#[test]
fn locale_packs_reach_the_guard_runtime() {
    // the plain policy functions run the default tr+en rule set: the
    // opt-in locale rules are invisible to them, only the locale-aware
    // variants see them
    assert_eq!(
        redactify::policy::guard_all("nhs 9434765870").action,
        GuardAction::Allow
    );
    let d = Guard::new(GuardTarget::UserPrompt)
        .with_locales(&["uk"])
        .decide("nhs 9434765870");
    assert_eq!(d.action, GuardAction::Mask);
    assert!(d.mask_summary.contains(&"UK_NHS"));

    let r = Guard::new(GuardTarget::UserPrompt)
        .with_locales(&["pl"])
        .sanitize("pesel 80010123450");
    assert_eq!(r.text, "pesel [PL_PESEL]");
    let r = Guard::new(GuardTarget::UserPrompt)
        .with_locales(&["fr"])
        .sanitize("call 06 12 34 56 78");
    assert_eq!(r.text, "call [PHONE]");
}

// ------------------------------------------------------- encoding bypasses

#[test]
fn fullwidth_digit_ids_caught_by_l0_pipeline() {
    // the raw view cannot match fullwidth digits (ASCII classes): measured
    // with the Detector's normalization explicitly switched off
    let raw = "nif: １２３４５６７８９";
    assert!(Detector::new()
        .with_locales(&["pt"])
        .with_normalization(false)
        .detect(raw)
        .is_empty());
    // the Detector normalizes by default: the default path claims the id
    let default_kinds: Vec<EntityType> = Detector::new()
        .with_locales(&["pt"])
        .detect(raw)
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert_eq!(default_kinds, vec![EntityType::PtNif]);
    // the L0 normalized view folds them and the locale rule claims the id
    let clean = normalize_for_scan(raw);
    let kinds: Vec<EntityType> = Detector::new()
        .with_locales(&["pt"])
        .detect(&clean)
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert_eq!(kinds, vec![EntityType::PtNif]);
}

#[test]
fn zero_width_scatter_caught_by_l0_pipeline() {
    let raw = "aadhaar 6\u{200B}0\u{200B}7\u{200B}3\u{200B}2\u{200B}4\u{200B}1\u{200B}3\u{200B}4\u{200B}3\u{200B}6\u{200B}0";
    // raw view (normalization off): the scattered digits are not a match
    assert!(Detector::new()
        .with_locales(&["in"])
        .with_normalization(false)
        .detect(raw)
        .is_empty());
    // the Detector normalizes by default: the default path claims the id
    assert!(Detector::new()
        .with_locales(&["in"])
        .detect(raw)
        .iter()
        .any(|e| e.kind == EntityType::InAadhaar));
    let kinds: Vec<EntityType> = Detector::new()
        .with_locales(&["in"])
        .detect(&normalize_for_scan(raw))
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert_eq!(kinds, vec![EntityType::InAadhaar]);
}

#[test]
fn base64_wrapped_fullwidth_id_drives_mask() {
    // full stack: base64(fullwidth PESEL) -> decode -> NFKC -> rule -> Mask
    let payload = format!(
        "pesel {}",
        "\u{ff18}\u{ff10}\u{ff10}\u{ff11}\u{ff10}\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff10}"
    );
    let wrapped = format!("not: {}", base64(payload.as_str()));
    let d = Guard::new(GuardTarget::UserPrompt)
        .with_locales(&["pl"])
        .decide(&wrapped);
    assert_eq!(
        d.action,
        GuardAction::Mask,
        "layered evasion must drive Mask; rationale: {}",
        d.rationale
    );
}

#[test]
fn nested_base64_eu_id_drives_mask() {
    let inner = base64("nhs 9434765870");
    let outer = format!("log: {}", base64(&format!("ctx {inner}")));
    let d = Guard::new(GuardTarget::UserPrompt)
        .with_locales(&["uk"])
        .decide(&outer);
    assert_eq!(d.action, GuardAction::Mask);
}

// ------------------------------------------------------- separator probes

#[test]
fn separator_scatter_within_allowed_set_is_caught() {
    // dashes/dots/spaces between every digit stay in-pattern (FR mobile)
    let kinds: Vec<EntityType> = Detector::new()
        .with_locales(&["fr"])
        .detect("num 06-1-2-3-4-5-6-7-8 x")
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert_eq!(kinds, vec![EntityType::Phone]);
}

#[test]
fn underscore_scatter_is_a_documented_boundary() {
    // underscores and commas between digits break every national pattern
    // (TR precedent): the raw layer stays silent and ONLY the encoding
    // attacks above are covered by L0. Measured boundary, documented.
    assert!(Detector::new()
        .with_locales(&["fr"])
        .detect("num 06_1_2_3_4_5_6_7_8 x")
        .is_empty());
    assert!(Detector::new()
        .with_locales(&["pt"])
        .detect("nif: 1,2,3,4,5,6,7,8,9")
        .is_empty());
}

// ------------------------------------------------------- cue boundaries

#[test]
fn cue_window_boundary_is_exact() {
    // cue 17 chars before the span -> inside the ±18 window (the padding
    // ends in a space: a short cue counts only where it starts a word)
    let near = format!("{} nif: 123456789", "x".repeat(12));
    let kinds: Vec<EntityType> = Detector::new()
        .with_locales(&["pt"])
        .detect(&near)
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert_eq!(kinds, vec![EntityType::PtNif]);
    // 40 chars BETWEEN cue and span -> outside the ±18 window: not
    // claimable (by design; the window looks back from the span start)
    let far = format!("nif: {}123456789", "x".repeat(40));
    assert!(Detector::new()
        .with_locales(&["pt"])
        .detect(&far)
        .is_empty());
}

#[test]
fn turkish_dotted_capital_cue_still_matches() {
    // "NİF" lowercases to "ni\u{0307}f"; the engine's Turkish cue
    // normalization strips U+0307, so the label still unlocks the rule
    let kinds: Vec<EntityType> = Detector::new()
        .with_locales(&["pt"])
        .detect("NİF: 123456789")
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert_eq!(kinds, vec![EntityType::PtNif]);
}

// ------------------------------------------------------- overlap corners

#[test]
fn swift_inside_url_masked_by_the_url_span() {
    // a BIC embedded in a URL path: both rules are tier 5, the longer
    // URL span wins and the raw BIC never leaks into the redacted text
    let text = "see https://bank.example/swift/DEUTDEFF now";
    let out = redact(text);
    assert!(out.contains("[URL]"), "{out}");
    assert!(!out.contains("DEUTDEFF"), "raw BIC leaked: {out}");
}

#[test]
fn nie_with_dni_cue_is_silent() {
    // the DNI cue list does not contain the NIE cues and the DNI pattern
    // cannot match a letter-prefixed span: measured isolation
    assert!(Detector::new()
        .with_locales(&["es"])
        .detect("dni X1234567L ref")
        .is_empty());
    assert_eq!(
        Detector::new()
            .with_locales(&["es"])
            .detect("nie X1234567L ref")
            .iter()
            .map(|e| e.kind)
            .collect::<Vec<_>>(),
        vec![EntityType::Nie]
    );
}

#[test]
fn locale_redact_and_default_redact_are_isolated() {
    assert_eq!(
        Detector::new()
            .with_locales(&["uk"])
            .redact("nhs 9434765870"),
        "nhs [UK_NHS]"
    );
    assert_eq!(redact("nhs 9434765870"), "nhs 9434765870");
}

// ------------------------------------------------------------- REST API

#[cfg(feature = "api")]
mod api_locales {
    use redactify::api::handle_request;

    fn post(path: &str, body: &str) -> serde_json::Value {
        let r = handle_request("POST", path, body);
        assert_eq!(r.status, 200, "{}", r.body);
        serde_json::from_str(&r.body).unwrap()
    }

    #[test]
    fn guard_endpoint_honors_locales() {
        let v = post(
            "/v1/guard",
            r#"{"text":"nhs 9434765870","target":"user_prompt","locales":["uk"]}"#,
        );
        assert_eq!(v["action"], "Mask");
        assert!(v["pii"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["type"] == "UK_NHS"));
    }

    #[test]
    fn sanitize_endpoint_masks_with_locales() {
        let v = post(
            "/v1/sanitize",
            r#"{"text":"pesel 80010123450","target":"user_prompt","locales":["pl"]}"#,
        );
        assert_eq!(v["action"], "Mask");
        assert_eq!(v["text"], "pesel [PL_PESEL]");
    }

    #[test]
    fn redact_endpoint_honors_locales() {
        let v = post(
            "/v1/redact",
            r#"{"text":"call 06 12 34 56 78","locales":["fr"]}"#,
        );
        assert_eq!(v["redacted"], "call [PHONE]");
        // without locales the same text is untouched (opt-in by design)
        let v = post("/v1/redact", r#"{"text":"call 06 12 34 56 78"}"#);
        assert_eq!(v["redacted"], "call 06 12 34 56 78");
    }

    #[test]
    fn detect_endpoint_redacted_field_uses_locales() {
        let v = post(
            "/v1/detect",
            r#"{"text":"codice fiscale MRTRSS85M01H501C","locales":["it"]}"#,
        );
        assert_eq!(v["count"], 1);
        assert_eq!(v["redacted"], "codice fiscale [IT_FISCAL_CODE]");
    }
}

#[cfg(feature = "api")]
mod api_stream_locales {
    use redactify::api::handle_request;

    #[test]
    fn stream_sanitize_endpoint_honors_locales() {
        let r = handle_request(
            "POST",
            "/v1/stream/sanitize",
            r#"{"chunks":["nhs 9434","765870 ok"],"target":"user_prompt","locales":["uk"]}"#,
        );
        assert_eq!(r.status, 200, "{}", r.body);
        let mut masked_all = String::new();
        for line in r.body.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            if v["type"] == "segment" {
                masked_all.push_str(v["text"].as_str().unwrap());
            }
        }
        assert!(masked_all.contains("[UK_NHS]"), "body: {}", r.body);
        assert!(
            !masked_all.contains("9434765870"),
            "raw NHS leaked: {masked_all}"
        );
    }
}

// ------------------------------------------- AU Medicare, UK/DE postcodes

#[cfg(test)]
mod postcodes_and_medicare {
    use redactify::{detect, Detector, EntityType};

    fn kind_of(text: &str, locale: &str) -> Vec<EntityType> {
        Detector::new()
            .with_locales(&[locale])
            .detect(text)
            .into_iter()
            .map(|e| e.kind)
            .collect()
    }

    #[test]
    fn au_medicare_requires_cue_and_checksum() {
        assert_eq!(
            kind_of("medicare 3189977021 claim", "au"),
            vec![EntityType::AuMedicare]
        );
        assert_eq!(
            kind_of("medicare 3189 97702 1 claim", "au"),
            vec![EntityType::AuMedicare]
        );
        // no cue -> silent; check-digit corruption -> rejected
        assert!(kind_of("health card 3189977021 claim", "au").is_empty());
        assert!(kind_of("medicare 3189977031 claim", "au").is_empty());
        assert!(kind_of("medicare 1189977021 claim", "au").is_empty());
    }

    #[test]
    fn uk_postcode_and_de_plz_cue_gated() {
        assert_eq!(
            kind_of("postcode SW1A 1AA on file", "uk"),
            vec![EntityType::UkPostcode]
        );
        assert!(kind_of("see SW1A 1AA tower", "uk").is_empty());
        assert_eq!(kind_of("PLZ: 10115 berlin", "de"), vec![EntityType::DePlz]);
        assert!(kind_of("bestellung 10115 versendet", "de").is_empty());
        assert!(kind_of("plz send 40732 refs", "de").is_empty());
        // locale isolation: default detect() sees none of these rules
        assert!(detect("postcode SW1A 1AA on file").is_empty());
        assert!(detect("medicare 3189977021 claim").is_empty());
        assert!(detect("PLZ: 10115 berlin").is_empty());
    }
}
