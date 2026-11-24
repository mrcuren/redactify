//! `CustomRule::new_linear`: a custom pattern restricted to the
//! linear-time regex syntax, safe to accept from an untrusted caller.

use std::time::{Duration, Instant};

use redactify::{CustomRule, Detector, EntityType};

fn kind() -> EntityType {
    EntityType::Itin
}

fn redact(rule: &CustomRule, text: &str) -> String {
    let rules = [rule];
    Detector::new().with_custom_rules(&rules).redact(text)
}

#[test]
fn accepts_the_linear_syntax_and_matches_like_new() {
    let rule = CustomRule::new_linear(kind(), r"\bE\d{6}\b").unwrap();
    assert_eq!(redact(&rule, "emp E123456 ok"), "emp [ITIN] ok");
    let ci = CustomRule::new_linear(kind(), r"(?i)acme-[a-z]{4}").unwrap();
    assert_eq!(redact(&ci, "see ACME-wxyz now"), "see [ITIN] now");
}

#[test]
fn rejects_every_construct_that_needs_backtracking() {
    for pattern in [
        r"foo(?=bar)",
        r"(?<=foo)bar",
        r"(?<!foo)bar",
        r"(?!foo)barbaz",
        r"(a)\1bc",
        r"(?>abc)+",
        r"(?P<x>abc)(?P=x)",
    ] {
        assert!(
            CustomRule::new_linear(kind(), pattern).is_err(),
            "{pattern}"
        );
    }
}

#[test]
fn rejects_patterns_that_match_too_little() {
    for pattern in [r"\d", r"\w*", r"a?", r".", r"\d{2}", r"(?:ab)?"] {
        assert!(
            CustomRule::new_linear(kind(), pattern).is_err(),
            "{pattern}"
        );
    }
    assert!(CustomRule::new_linear(kind(), r"\d{3}").is_ok());
}

#[test]
fn rejects_long_deep_and_oversized_patterns() {
    assert!(CustomRule::new_linear(kind(), &"a".repeat(257)).is_err());
    assert!(CustomRule::new_linear(kind(), &"a".repeat(256)).is_ok());
    let deep = format!("{}abc{}", "(".repeat(40), ")".repeat(40));
    assert!(CustomRule::new_linear(kind(), &deep).is_err());
    // compiled program far over the size limit
    assert!(CustomRule::new_linear(kind(), r"(\w{100}){100}").is_err());
    assert!(CustomRule::new_linear(kind(), r"\p{L}{1000}").is_err());
}

#[test]
fn error_text_never_echoes_the_pattern() {
    for pattern in [
        "SECRETPAT(?=x)",
        "SECRETPAT(",
        "SECRETPAT[z-a]",
        "SECRETPAT{2,1}",
    ] {
        let err = CustomRule::new_linear(kind(), pattern)
            .unwrap_err()
            .to_string();
        assert!(!err.contains("SECRETPAT"), "{pattern}: {err}");
    }
}

#[test]
fn catastrophic_patterns_run_in_linear_time() {
    // exponential for a backtracking engine, linear here
    let rule = CustomRule::new_linear(kind(), r"(a+)+bcd").unwrap();
    let text = format!("{}!", "a".repeat(200_000));
    let rules = [&rule];
    let start = Instant::now();
    let report = Detector::new().with_custom_rules(&rules).scan(&text);
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
    assert!(report.error_spans.is_empty());
    assert!(report.entities.is_empty());
}
