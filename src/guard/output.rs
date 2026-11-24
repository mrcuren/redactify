//! L4 Output Guards: HTML entity encoding and JSON schema validation
//! (OWASP LLM05: Improper Output Handling defenses).
//!
//! LLM output is untrusted. Before it reaches a browser, a database or a
//! downstream system, it must be validated and sanitized. This module
//! provides two deterministic, model-free transforms:
//!
//! - [`encode_html`]: HTML entity encoding for XSS prevention
//! - [`validate_json_schema`]: structural JSON validation for output shaping

use std::collections::BTreeSet;

/// Known HTML entities that are NOT double-encoded by [`encode_html`].
const KNOWN_ENTITIES: &[&str] = &[
    "&amp;", "&lt;", "&gt;", "&quot;", "&#34;", "&#39;", "&apos;", "&nbsp;", "&copy;", "&reg;",
    "&trade;", "&hellip;", "&mdash;", "&ndash;",
];

/// HTML-encodes all dangerous characters for safe rendering in a browser context.
///
/// Encodes: `&` -> `&amp;`, `<` -> `&lt;`, `>` -> `&gt;`, `"` -> `&#34;`, `'` -> `&#39;`.
/// Pre-existing HTML entities (e.g. `&lt;`, `&amp;`) are NOT double-encoded:
/// `&` that is already part of a recognized entity is left as-is.
///
/// # Examples
/// ```
/// use redactify::guard::output::encode_html;
/// assert_eq!(encode_html("<script>alert(1)</script>"), "&lt;script&gt;alert(1)&lt;/script&gt;");
/// assert_eq!(encode_html("a & b"), "a &amp; b");
/// ```
#[must_use]
pub fn encode_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '&' => {
                // Check if this & starts a known entity; if so, copy it as-is
                let rest: String = chars[i..(i + 10).min(chars.len())].iter().collect();
                let matched = KNOWN_ENTITIES.iter().find(|e| rest.starts_with(*e));
                if let Some(entity) = matched {
                    out.push_str(entity);
                    i += entity.chars().count();
                } else {
                    out.push_str("&amp;");
                    i += 1;
                }
            }
            '<' => {
                out.push_str("&lt;");
                i += 1;
            }
            '>' => {
                out.push_str("&gt;");
                i += 1;
            }
            '"' => {
                out.push_str("&#34;");
                i += 1;
            }
            '\'' => {
                out.push_str("&#39;");
                i += 1;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// A minimal JSON schema for structural validation of LLM output.
///
/// This is not a full JSON Schema implementation (that would require a
/// dependency-heavy validator). It covers the OWASP LLM05 guidance:
/// validate that the output is a JSON object with required keys, allowed
/// key types and no unexpected top-level keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonSchema {
    /// Keys that must be present at the top level.
    pub required: &'static [&'static str],
    /// If non-empty, only these keys are allowed at the top level.
    pub allowed: &'static [&'static str],
}

/// Typed error for [`validate_json_schema`] (no stringly-typed errors);
/// `source()` preserves the underlying JSON error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SchemaError {
    /// The output is not valid JSON.
    #[error("output is not valid JSON: {0}")]
    InvalidJson(#[source] serde_json::Error),
    /// The top-level value is not a JSON object.
    #[error("output must be a JSON object at the top level")]
    NotAnObject,
    /// A key required by the schema is absent.
    #[error("required key '{0}' is missing from output")]
    MissingRequiredKey(String),
    /// A key outside the schema's allowed list is present.
    #[error("unexpected key '{0}' in output (not in allowed list)")]
    UnexpectedKey(String),
}

/// Validates that `text` is a JSON object carrying every required key and no
/// key outside the allowed list (an empty allowed list permits anything).
///
/// # Examples
/// ```
/// use redactify::guard::output::{validate_json_schema, JsonSchema};
///
/// let schema = JsonSchema {
///     required: &["name", "email"],
///     allowed: &["name", "email", "phone"],
/// };
///
/// assert!(validate_json_schema(r#"{"name":"Ali","email":"a@b.com"}"#, &schema).is_ok());
/// assert!(validate_json_schema(r#"{"name":"Ali"}"#, &schema).is_err()); // missing email
/// assert!(validate_json_schema(r#"{"name":"Ali","email":"a@b.com","x":1}"#, &schema).is_err());
/// assert!(validate_json_schema("not json", &schema).is_err());
/// ```
///
/// # Errors
/// Returns a typed [`SchemaError`]: invalid JSON, non-object top level,
/// a missing required key, or a key outside the allowed list.
pub fn validate_json_schema(text: &str, schema: &JsonSchema) -> Result<(), SchemaError> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(SchemaError::InvalidJson)?;

    let obj = v.as_object().ok_or(SchemaError::NotAnObject)?;

    let keys: BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();

    for req in schema.required {
        if !keys.contains(req) {
            return Err(SchemaError::MissingRequiredKey((*req).to_owned()));
        }
    }

    if !schema.allowed.is_empty() {
        for key in &keys {
            if !schema.allowed.contains(key) {
                return Err(SchemaError::UnexpectedKey((*key).to_owned()));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{encode_html, validate_json_schema, JsonSchema};

    #[test]
    fn html_encodes_all_dangerous_chars() {
        assert_eq!(encode_html("<b>"), "&lt;b&gt;");
        assert_eq!(encode_html("a&b"), "a&amp;b");
        assert_eq!(encode_html("say \"hi\""), "say &#34;hi&#34;");
        assert_eq!(encode_html("it's"), "it&#39;s");
        assert_eq!(encode_html("safe text"), "safe text");
        assert_eq!(encode_html(""), "");
    }

    #[test]
    fn html_preserves_known_entities() {
        // encoding already-encoded text preserves entities (no double-encode)
        assert_eq!(encode_html("&lt;script&gt;"), "&lt;script&gt;");
        assert_eq!(encode_html("a &amp; b"), "a &amp; b");
        assert_eq!(encode_html("5 &lt; 10"), "5 &lt; 10");
    }

    #[test]
    fn html_encodes_bare_ampersand() {
        // a bare & (not part of an entity) IS encoded
        assert_eq!(encode_html("a & b"), "a &amp; b");
        assert_eq!(encode_html("x&y"), "x&amp;y");
    }

    const SCHEMA: JsonSchema = JsonSchema {
        required: &["id", "name"],
        allowed: &["id", "name", "email", "phone"],
    };

    #[test]
    fn json_valid_output_passes() {
        assert!(validate_json_schema(r#"{"id":1,"name":"Ali"}"#, &SCHEMA).is_ok());
        assert!(validate_json_schema(
            r#"{"id":1,"name":"Ali","email":"a@b.com","phone":"05321234567"}"#,
            &SCHEMA
        )
        .is_ok());
    }

    #[test]
    fn json_missing_required_key_fails() {
        let err = validate_json_schema(r#"{"name":"Ali"}"#, &SCHEMA).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("id"), "unexpected message: {msg}");
    }

    #[test]
    fn json_unknown_key_fails() {
        let err =
            validate_json_schema(r#"{"id":1,"name":"Ali","hacked":"yes"}"#, &SCHEMA).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("hacked"), "unexpected message: {msg}");
    }

    #[test]
    fn json_non_object_fails() {
        assert!(validate_json_schema("[1,2,3]", &SCHEMA).is_err());
        assert!(validate_json_schema("\"just a string\"", &SCHEMA).is_err());
        assert!(validate_json_schema("not json at all", &SCHEMA).is_err());
    }

    #[test]
    fn json_empty_schema_accepts_any_object() {
        let permissive = JsonSchema {
            required: &[],
            allowed: &[],
        };
        assert!(validate_json_schema("{}", &permissive).is_ok());
        assert!(validate_json_schema(r#"{"anything":1}"#, &permissive).is_ok());
    }
}
