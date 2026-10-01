//! Redaction - the mask template contract.

use crate::pii::detect::detect;

/// Replaces detected PII with a `[{TYPE}]` style mask.
///
/// # Examples
/// ```
/// use redactify::redact;
///
/// assert_eq!(
///     redact("TCKN'm 12345678950, mail a@b.com"),
///     "TCKN'm [TCKN], mail [EMAIL]"
/// );
/// // an order number without a valid checksum stays UNCHANGED:
/// assert_eq!(
///     redact("Sipariş numaranız 12000345671 olarak kaydedildi."),
///     "Sipariş numaranız 12000345671 olarak kaydedildi."
/// );
/// ```
#[must_use]
pub fn redact(text: &str) -> String {
    redact_with_mask(text, "[{type}]")
}

/// Redacts with a custom mask template; the `{type}` placeholder is replaced by the type label.
///
/// # Examples
/// ```
/// use redactify::redact_with_mask;
///
/// assert_eq!(
///     redact_with_mask("TCKN 12345678950", "<<{type}>>"),
///     "TCKN <<TCKN>>"
/// );
/// ```
#[must_use]
pub fn redact_with_mask(text: &str, mask: &str) -> String {
    let ents = detect(text);
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for e in &ents {
        out.push_str(&text[last..e.start]);
        out.push_str(&mask.replace("{type}", e.kind.as_str()));
        last = e.end;
    }
    out.push_str(&text[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::{redact, redact_with_mask};

    #[test]
    fn quickstart_sentence() {
        assert_eq!(
            redact("TCKN'm 12345678950, IBAN TR33 0006 1005 1978 6457 8413 26, mail a@b.com"),
            "TCKN'm [TCKN], IBAN [IBAN], mail [EMAIL]"
        );
    }

    #[test]
    fn order_number_untouched() {
        let s = "Sipariş numaranız 12000345671 olarak kaydedildi.";
        assert_eq!(redact(s), s);
    }

    #[test]
    fn custom_mask() {
        assert_eq!(redact_with_mask("mail a@b.com", "«{type}»"), "mail «EMAIL»");
    }
}
