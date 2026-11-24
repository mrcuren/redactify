//! `JsonRedactor`: member names act as context cues, secrets are masked
//! before PII, arrays inherit the enclosing key, nesting depth never
//! touches the call stack, number leaves are opt-in, a long member name
//! adds only a bounded cue tail to each value scan, findings come in walk
//! order, and the report holds pointers and kinds only - never a value.

use std::time::{Duration, Instant};

use redactify::{Detector, EntityType, JsonFinding, JsonFindingKind, JsonRedactor, MaskStyle};
use serde_json::{json, Value};

fn kinds(findings: &[JsonFinding]) -> Vec<(String, JsonFindingKind, bool)> {
    findings
        .iter()
        .map(|f| (f.pointer.clone(), f.kind, f.in_key))
        .collect()
}

#[test]
fn member_name_is_a_context_cue() {
    // a bare 10-digit VKN is only claimable next to a cue: the member
    // name supplies it
    let mut doc = json!({"vergi_no": "1234567890", "siparis": "1234567890"});
    let report = JsonRedactor::new().redact(&mut doc);
    assert_eq!(doc, json!({"vergi_no": "[VKN]", "siparis": "1234567890"}));
    assert_eq!(
        kinds(&report.findings),
        vec![(
            "/vergi_no".to_owned(),
            JsonFindingKind::Pii(EntityType::Vkn),
            false
        )]
    );
}

#[test]
fn secrets_are_masked_before_pii() {
    let mut doc = json!({
        "aws": "AKIAIOSFODNN7EXAMPLE",
        "log": "key AKIAIOSFODNN7EXAMPLE for TCKN 12345678950"
    });
    let report = JsonRedactor::new().redact(&mut doc);
    assert_eq!(
        doc,
        json!({
            "aws": "[SECRET:AWS_ACCESS_KEY]",
            "log": "key [SECRET:AWS_ACCESS_KEY] for TCKN [TCKN]"
        })
    );
    assert_eq!(
        kinds(&report.findings),
        vec![
            (
                "/aws".to_owned(),
                JsonFindingKind::Secret("AWS_ACCESS_KEY"),
                false
            ),
            (
                "/log".to_owned(),
                JsonFindingKind::Secret("AWS_ACCESS_KEY"),
                false
            ),
            (
                "/log".to_owned(),
                JsonFindingKind::Pii(EntityType::Tckn),
                false
            ),
        ]
    );
}

#[test]
fn array_items_use_the_enclosing_key_as_cue() {
    let mut doc = json!({
        "vergi_numaralari": ["1234567890", ["2120000004"], {"x": "1234567890"}],
        "list": ["1234567890"]
    });
    let report = JsonRedactor::new().redact(&mut doc);
    assert_eq!(
        doc,
        json!({
            "vergi_numaralari": ["[VKN]", ["[VKN]"], {"x": "1234567890"}],
            "list": ["1234567890"]
        })
    );
    let pointers: Vec<&str> = report.findings.iter().map(|f| f.pointer.as_str()).collect();
    assert_eq!(
        pointers,
        vec!["/vergi_numaralari/0", "/vergi_numaralari/1/0"]
    );
}

#[test]
fn pii_in_member_names_is_reported_not_rewritten() {
    let mut doc = json!({"a@b.com": {"note": "x"}, "plain": "mail c@d.com"});
    let report = JsonRedactor::new().redact(&mut doc);
    // the member name stays (renaming would change the schema)...
    assert!(doc.get("a@b.com").is_some());
    assert_eq!(doc["plain"], json!("mail [EMAIL]"));
    // ...but it is reported, and its pointer segment is masked
    assert_eq!(
        kinds(&report.findings),
        vec![
            (
                "/[EMAIL]".to_owned(),
                JsonFindingKind::Pii(EntityType::Email),
                true
            ),
            (
                "/plain".to_owned(),
                JsonFindingKind::Pii(EntityType::Email),
                false
            ),
        ]
    );
}

#[test]
fn pointers_escape_and_mask_member_names() {
    let mut doc = json!({"a/b~c": {"TCKN 12345678950": "mail x@y.com"}});
    let report = JsonRedactor::new().redact(&mut doc);
    let pointers: Vec<&str> = report.findings.iter().map(|f| f.pointer.as_str()).collect();
    // the key finding (in_key) comes first, then the value inside it;
    // the descendant's pointer carries the MASKED member name too
    assert_eq!(
        pointers,
        vec!["/a~1b~0c/TCKN [TCKN]", "/a~1b~0c/TCKN [TCKN]"]
    );
    assert!(report.findings[0].in_key);
    assert!(!report.findings[1].in_key);
}

#[test]
fn report_never_contains_a_detected_value() {
    let values = [
        "12345678950",
        "a@b.com",
        "AKIAIOSFODNN7EXAMPLE",
        "0532 123 45 67",
    ];
    let mut doc = json!({
        "12345678950": [values[1], {"k": values[2]}],
        "tel": values[3],
        "nested": {"a@b.com": values[0]}
    });
    let report = JsonRedactor::new().redact(&mut doc);
    assert!(report.findings.len() >= 5, "{report:?}");
    let dbg = format!("{report:?}");
    let out = doc.to_string();
    for v in values {
        assert!(!dbg.contains(v), "{v} leaked into the report: {dbg}");
    }
    // values are masked; the two PII member NAMES stay by design
    assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"), "{out}");
    assert!(!out.contains("0532 123 45 67"), "{out}");
}

#[test]
fn numeric_leaves_are_opt_in() {
    let mut doc = json!({"tckn": 12345678950_u64, "n": 7, "f": 1.5, "b": true, "z": null});
    let off = JsonRedactor::new().redact(&mut doc);
    assert!(off.findings.is_empty());
    assert_eq!(doc["tckn"], json!(12345678950_u64));
    let on = JsonRedactor::new()
        .with_numeric_leaves(true)
        .redact(&mut doc);
    assert_eq!(
        doc,
        json!({"tckn": "[TCKN]", "n": 7, "f": 1.5, "b": true, "z": null})
    );
    assert_eq!(
        kinds(&on.findings),
        vec![(
            "/tckn".to_owned(),
            JsonFindingKind::Pii(EntityType::Tckn),
            false
        )]
    );
}

#[test]
fn detector_options_apply() {
    let d = Detector::new()
        .with_locales(&["uk"])
        .with_mask_style(MaskStyle::Template("<{type}>".into()));
    let mut doc = json!({"nhs": "9434765870", "evasion": "TCKN 1\u{200B}2345678950"});
    let _ = JsonRedactor::new().with_detector(d).redact(&mut doc);
    // the uk pack is on, tr is off for this detector
    assert_eq!(doc["nhs"], json!("<UK_NHS>"));
    assert_eq!(doc["evasion"], json!("TCKN 1\u{200B}2345678950"));
    // the default redactor runs the normalization pass: the zero-width
    // scattered TCKN is found
    let mut doc = json!({"evasion": "TCKN 1\u{200B}2345678950"});
    let _ = JsonRedactor::new().redact(&mut doc);
    assert_eq!(doc["evasion"], json!("TCKN [TCKN]"));
}

/// Builds a document nested `depth` levels deep (alternating arrays and
/// objects) around one string leaf, without recursion.
fn deep(depth: usize, leaf: &str) -> Value {
    let mut v = Value::String(leaf.to_owned());
    for i in 0..depth {
        v = if i % 2 == 0 {
            Value::Array(vec![v])
        } else {
            // (not `json!`: interpolating a Value there re-serializes it,
            // which recurses once per level)
            let mut map = serde_json::Map::new();
            map.insert("k".to_owned(), v);
            Value::Object(map)
        };
    }
    v
}

/// Takes a deep document apart without recursion (the derived `Drop` of
/// `serde_json::Value` recurses once per level).
fn dismantle(v: Value) {
    let mut stack = vec![v];
    while let Some(mut x) = stack.pop() {
        match &mut x {
            Value::Array(items) => stack.append(items),
            Value::Object(map) => {
                let map = std::mem::take(map);
                stack.extend(map.into_iter().map(|(_, v)| v));
            }
            _ => {}
        }
    }
}

#[test]
fn ten_thousand_levels_do_not_touch_the_call_stack() {
    // run on a deliberately small stack: one frame per nesting level
    // would overflow it long before 10k levels
    let worker = std::thread::Builder::new()
        .stack_size(512 * 1024)
        .spawn(|| {
            let depth = 10_000;
            let mut doc = deep(depth, "TCKN 12345678950");
            let report = JsonRedactor::new().redact(&mut doc);
            assert_eq!(report.findings.len(), 1);
            let f = &report.findings[0];
            assert_eq!(f.kind, JsonFindingKind::Pii(EntityType::Tckn));
            assert_eq!(f.pointer.matches('/').count(), depth);
            assert!(f.pointer.starts_with("/k/0/k/0"), "{}", &f.pointer[..20]);
            // walk down to the leaf iteratively
            let mut cur = &doc;
            loop {
                cur = match cur {
                    Value::Array(items) => &items[0],
                    Value::Object(map) => &map["k"],
                    _ => break,
                };
            }
            assert_eq!(cur, &json!("TCKN [TCKN]"));
            dismantle(doc);
        })
        .expect("spawn");
    worker.join().expect("no stack overflow");
}

// ------------------------------------------------------ long member names

/// One document: a member name of `key_len` chars over `items` empty
/// strings (a cost-amplification shape).
fn long_key_doc(key_len: usize, items: usize) -> serde_json::Value {
    let key = "k".repeat(key_len);
    json!({ key: vec![json!(""); items] })
}

#[test]
fn a_long_member_name_does_not_multiply_the_value_scan_cost() {
    // each item sees a bounded cue tail of the member name, not the whole
    // name (which would cost items x key length)
    let mut doc = long_key_doc(100_000, 400);
    let t0 = Instant::now();
    let report = JsonRedactor::new().redact(&mut doc);
    let took = t0.elapsed();
    assert!(report.findings.is_empty());
    assert!(
        took < Duration::from_secs(20),
        "400 leaves under a 100,000-char key took {took:?}"
    );
}

#[test]
fn the_cue_tail_keeps_the_cue_of_a_long_member_name() {
    // a cue at the END of a long member name still reaches the value
    let mut doc = json!({ format!("{}_vergi_no", "x".repeat(5_000)): "1234567890" });
    let report = JsonRedactor::new().redact(&mut doc);
    assert_eq!(doc.as_object().unwrap().values().next().unwrap(), "[VKN]");
    assert_eq!(
        report.findings[0].kind,
        JsonFindingKind::Pii(EntityType::Vkn)
    );
}

#[test]
fn the_cue_tail_covers_the_longest_bounded_secret_cue() {
    // AWS secret-key rule: `aws[^\n]{0,30}?(?:secret|sk)[^\n]{0,20}?[=:\s]`
    // reaches 3 + 30 + 6 + 19 = 58 chars back from the value into the
    // member name (the 20th char of the lazy gap is the ':' separator)
    let key = format!("aws{}secret{}", "a".repeat(30), "b".repeat(19));
    assert_eq!(key.chars().count(), 58);
    let value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    for pad in [0usize, 1, 6, 1_000] {
        let mut doc = json!({ format!("{}{key}", "z".repeat(pad)): value });
        let _ = JsonRedactor::new().redact(&mut doc);
        assert_eq!(
            doc.as_object().unwrap().values().next().unwrap(),
            "[SECRET:AWS_SECRET_KEY]",
            "pad {pad}"
        );
    }
}

// ------------------------------------------------------------ finding order

#[test]
fn json_findings_come_in_walk_order() {
    // member names AND values in the map's iteration order: each member's
    // key findings directly before the findings inside its value
    let mut doc = json!({"10000000146": "mail a@b.com", "vergi 1234567890": "plain"});
    let report = JsonRedactor::new().redact(&mut doc);
    let got: Vec<(&str, JsonFindingKind, bool)> = report
        .findings
        .iter()
        .map(|f| (f.pointer.as_str(), f.kind, f.in_key))
        .collect();
    assert_eq!(
        got,
        vec![
            ("/[TCKN]", JsonFindingKind::Pii(EntityType::Tckn), true),
            ("/[TCKN]", JsonFindingKind::Pii(EntityType::Email), false),
            ("/vergi [VKN]", JsonFindingKind::Pii(EntityType::Vkn), true),
        ]
    );
}
