//! OpenAPI description of the REST API (`GET /openapi.json`). The spec is
//! checked against the live handler: every documented path exists, every
//! example request in it succeeds, and the documented limits equal the
//! enforced ones.
#![cfg(feature = "api")]

use redactify::api::handle_request;
use serde_json::Value;

fn spec() -> Value {
    let r = handle_request("GET", "/openapi.json", "");
    assert_eq!(r.status, 200, "{}", r.body);
    serde_json::from_str(&r.body).expect("spec is JSON")
}

#[test]
fn spec_is_openapi_3_1_with_crate_version() {
    let s = spec();
    assert!(
        s["openapi"].as_str().unwrap().starts_with("3.1"),
        "{}",
        s["openapi"]
    );
    assert_eq!(s["info"]["title"], "redactify");
    assert_eq!(s["info"]["version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn spec_paths_equal_the_served_endpoints() {
    let root: Value = serde_json::from_str(&handle_request("GET", "/", "").body).unwrap();
    let mut served: Vec<String> = root["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            // "POST /v1/stream/sse (socket server only)" -> "POST /v1/stream/sse"
            e.as_str().unwrap().split(" (").next().unwrap().to_owned()
        })
        .collect();
    assert!(
        served.contains(&"GET /openapi.json".to_owned()),
        "{served:?}"
    );
    let s = spec();
    let mut documented: Vec<String> = Vec::new();
    for (path, item) in s["paths"].as_object().unwrap() {
        for method in item.as_object().unwrap().keys() {
            documented.push(format!("{} {}", method.to_uppercase(), path));
        }
    }
    served.sort();
    documented.sort();
    assert_eq!(documented, served);
}

#[test]
fn every_operation_documents_its_error_responses() {
    let s = spec();
    for (path, item) in s["paths"].as_object().unwrap() {
        for (method, op) in item.as_object().unwrap() {
            assert!(
                op["summary"].as_str().is_some_and(|t| !t.is_empty()),
                "{method} {path}"
            );
            assert!(op["responses"]["200"].is_object(), "{method} {path}");
            if method == "post" {
                assert!(
                    op["requestBody"]["required"].as_bool().unwrap_or(false),
                    "{path}"
                );
                assert!(op["responses"]["400"].is_object(), "{path}");
                assert!(op["responses"]["413"].is_object(), "{path}");
                assert!(op["responses"]["401"].is_object(), "{path}");
            }
        }
    }
}

#[test]
fn every_documented_example_request_succeeds() {
    let s = spec();
    let mut posted = 0;
    for (path, item) in s["paths"].as_object().unwrap() {
        let Some(op) = item.get("post") else { continue };
        let example = &op["requestBody"]["content"]["application/json"]["example"];
        assert!(example.is_object(), "{path} has no example");
        let r = handle_request("POST", path, &example.to_string());
        if path == "/v1/stream/sse" {
            // socket-only endpoint: the pure handler says so, by contract
            assert_eq!(r.status, 400);
            assert!(r.body.contains("socket_only"));
            continue;
        }
        assert_eq!(r.status, 200, "{path}: {}", r.body);
        posted += 1;
    }
    assert!(posted >= 12, "only {posted} endpoints exercised");
}

#[test]
fn documented_limits_equal_the_enforced_ones() {
    let s = spec();
    let schemas = &s["components"]["schemas"];
    let mask = &schemas["Mask"];
    let styles: Vec<&str> = mask["properties"]["style"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        styles,
        [
            "label",
            "template",
            "char",
            "partial",
            "mask_first",
            "mask_last"
        ]
    );
    assert_eq!(schemas["MaskByType"]["maxProperties"], 32);
    for path in ["/v1/stream/sanitize", "/v1/stream/sse"] {
        let props = &s["paths"][path]["post"]["requestBody"]["content"]["application/json"]
            ["schema"]["properties"];
        for field in [
            "mask",
            "mask_by_type",
            "words",
            "words_ignore_case",
            "patterns",
        ] {
            assert!(props[field].is_object(), "{path} lacks {field}");
        }
    }
    assert_eq!(mask["properties"]["template"]["maxLength"], 64);
    assert_eq!(mask["properties"]["keep_last"]["maximum"], 64);
    let words = &schemas["Words"];
    assert_eq!(words["maxItems"], 256);
    assert_eq!(words["items"]["maxLength"], 128);
    assert_eq!(schemas["SystemPrompt"]["maxLength"], 64 * 1024);
    let patterns = &schemas["Patterns"];
    assert_eq!(patterns["maxItems"], 16);
    assert_eq!(patterns["items"]["properties"]["pattern"]["maxLength"], 256);
    assert_eq!(patterns["items"]["properties"]["cues"]["maxItems"], 16);
    assert_eq!(
        patterns["items"]["properties"]["cues"]["items"]["maxLength"],
        64
    );
    assert_eq!(patterns["items"]["additionalProperties"], false);
    for path in [
        "/v1/detect",
        "/v1/redact",
        "/v1/json/redact",
        "/v1/guard",
        "/v1/sanitize",
        "/v1/batch/detect",
        "/v1/batch/redact",
        "/v1/batch/sanitize",
        "/v1/vault/pseudonymize",
    ] {
        let props = &s["paths"][path]["post"]["requestBody"]["content"]["application/json"]
            ["schema"]["properties"];
        assert!(props["patterns"].is_object(), "{path} lacks patterns");
    }
    // an example that really carries a pattern is exercised by the example test
    let ex =
        &s["paths"]["/v1/detect"]["post"]["requestBody"]["content"]["application/json"]["example"];
    assert!(
        ex["patterns"].is_array(),
        "the detect example must show patterns"
    );
    for path in ["/v1/guard", "/v1/sanitize", "/v1/batch/sanitize"] {
        let props = &s["paths"][path]["post"]["requestBody"]["content"]["application/json"]
            ["schema"]["properties"];
        assert!(
            props["system_prompt"].is_object(),
            "{path} lacks system_prompt"
        );
    }
    for path in ["/v1/detect", "/v1/redact"] {
        let props = &s["paths"][path]["post"]["requestBody"]["content"]["application/json"]
            ["schema"]["properties"];
        assert!(
            props["system_prompt"].is_null(),
            "{path} must not document system_prompt"
        );
    }
    assert_eq!(
        schemas["RequestId"]["maxLength"],
        redactify::api::MAX_REQUEST_ID_LEN
    );
    // every enum value is accepted by the real endpoint
    for style in ["label", "char", "partial", "template"] {
        let body = match style {
            "label" => r#"{"style":"label"}"#,
            "char" => r#"{"style":"char","char":"*"}"#,
            "partial" => r#"{"style":"partial","keep_last":2,"char":"*"}"#,
            _ => r#"{"style":"template","template":"<{type}>"}"#,
        };
        let r = handle_request(
            "POST",
            "/v1/redact",
            &format!(r#"{{"text":"a","mask":{body}}}"#),
        );
        assert_eq!(r.status, 200, "{style}: {}", r.body);
    }
}

#[test]
fn spec_never_contains_request_values() {
    // the spec is static: it must not vary with, or echo, anything a
    // client sent before
    let _ = handle_request(
        "POST",
        "/v1/redact",
        r#"{"text":"zq-probe-7731","words":["zq-probe-7731"]}"#,
    );
    let r = handle_request("GET", "/openapi.json", "");
    assert!(!r.body.contains("zq-probe-7731"));
}

#[test]
fn openapi_rejects_post() {
    let r = handle_request("POST", "/openapi.json", "{}");
    assert_eq!(r.status, 405);
}

#[test]
fn litellm_example_is_masked_in_order_and_its_params_match_the_handler() {
    let s = spec();
    let path = "/beta/litellm_basic_guardrail_api";
    let op = &s["paths"][path]["post"];
    let example = &op["requestBody"]["content"]["application/json"]["example"];
    let r = handle_request("POST", path, &example.to_string());
    assert_eq!(r.status, 200, "{}", r.body);
    let v: Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["action"], "GUARDRAIL_INTERVENED");
    let sent = example["texts"].as_array().unwrap();
    let got = v["texts"].as_array().unwrap();
    assert_eq!(got.len(), sent.len());
    assert_eq!(got[0], sent[0]);
    assert_eq!(got[1], "My TCKN is [TCKN]");
    assert_eq!(got[2], sent[2]);
    // both auth schemes are documented for this operation
    assert_eq!(op["security"].as_array().unwrap().len(), 2);
    assert_eq!(
        s["components"]["securitySchemes"]["apiKeyAuth"]["name"],
        "x-api-key"
    );
    // the documented provider params are exactly the accepted ones
    let params = &op["requestBody"]["content"]["application/json"]["schema"]["properties"]
        ["additional_provider_specific_params"];
    assert_eq!(params["additionalProperties"], false);
    let documented: Vec<&String> = params["properties"].as_object().unwrap().keys().collect();
    for key in &documented {
        let value = match key.as_str() {
            "words" => serde_json::json!(["x"]),
            "patterns" => serde_json::json!([{ "pattern": r"zz\d{3}" }]),
            _ => serde_json::json!(false),
        };
        let body = serde_json::json!({
            "input_type": "request", "texts": ["a"],
            "additional_provider_specific_params": { key.as_str(): value }
        });
        let r = handle_request("POST", path, &body.to_string());
        assert_eq!(r.status, 200, "{key}: {}", r.body);
    }
    assert_eq!(documented.len(), 5, "{documented:?}");
}
