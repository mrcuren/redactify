//! Reversible anonymization (vault pattern): mask PII before an LLM call,
//! restore it in the LLM response. The model never sees real identifiers.
//!
//! This fills the gap left by the archived open-source guardrail tool that
//! pioneered the pattern. The flow:
//!
//! ```text
//! User prompt (with PII)
//!     |
//!     v
//! Vault::anonymize()  -->  "[TCKN_1]" placeholder + vault
//!     |
//!     v
//! LLM call (placeholder text only; the model cannot leak what it never saw)
//!     |
//!     v
//! LLM response (may reference "[TCKN_1]")
//!     |
//!     v
//! vault.deanonymize()  -->  real value restored; user sees natural text
//! ```
//!
//! # Examples
//! ```
//! use redactify::Vault;
//!
//! let prompt = "My TCKN is 12345678950 and email is a@b.com";
//! let (anon, vault) = Vault::anonymize(prompt);
//! assert!(!anon.contains("12345678950"));
//! assert!(!anon.contains("a@b.com"));
//! assert!(anon.contains("[TCKN_1]"));
//! assert!(anon.contains("[EMAIL_1]"));
//!
//! // Simulated LLM response referencing the placeholders
//! let llm_response = "I see your TCKN is [TCKN_1] and email is [EMAIL_1].";
//! let restored = vault.deanonymize(llm_response);
//! assert!(restored.contains("12345678950"));
//! assert!(restored.contains("a@b.com"));
//! assert!(!restored.contains("[TCKN_1]"));
//! ```

use std::collections::BTreeMap;

/// A vault that stores the mapping between placeholders and original PII values.
///
/// Created by [`Vault::anonymize`], consumed by [`Vault::deanonymize`].
/// The vault is deliberately not `Serialize` (avoid accidental persistence of
/// real PII); it lives only for the duration of one LLM round-trip.
#[derive(Debug, Clone, PartialEq)]
pub struct Vault {
    /// Maps placeholder (e.g. `"TCKN_1"`) -> original value (e.g. `"12345678950"`).
    entries: BTreeMap<String, String>,
}

impl Vault {
    /// Anonymizes `text`: every detected PII entity is replaced with a typed,
    /// sequentially numbered placeholder. Returns the anonymized text and the
    /// vault needed to restore the originals later.
    ///
    /// Placeholders follow the format `[{TYPE}_{N}]` where `TYPE` is the entity
    /// label (TCKN, IBAN, EMAIL, ...) and `N` is a per-type counter starting at 1.
    /// The same original value always gets the same placeholder within one vault.
    ///
    /// # Examples
    /// ```
    /// use redactify::Vault;
    ///
    /// let (anon, _) = Vault::anonymize("TCKN 12345678950 and TCKN 12345678950");
    /// // Both occurrences map to the same placeholder
    /// assert_eq!(anon.matches("[TCKN_1]").count(), 2);
    /// ```
    #[must_use]
    pub fn anonymize(text: &str) -> (String, Self) {
        let entities = crate::detect(text);
        let mut vault = Self {
            entries: BTreeMap::new(),
        };
        let mut type_counters: BTreeMap<&str, usize> = BTreeMap::new();
        let mut out = String::with_capacity(text.len());
        let mut last = 0;

        for e in &entities {
            // Skip zero-length or invalid spans
            if e.start >= e.end || e.start < last {
                continue;
            }

            let label = e.kind.as_str();

            // Same original value -> same placeholder (deduplication)
            let placeholder = if let Some(existing) = vault
                .entries
                .iter()
                .find(|(_, v)| *v == &e.text)
                .map(|(k, _)| k.clone())
            {
                existing
            } else {
                let n = type_counters.entry(label).or_insert(0);
                *n += 1;
                format!("{label}_{n}")
            };

            vault.entries.insert(placeholder.clone(), e.text.clone());

            out.push_str(&text[last..e.start]);
            out.push('[');
            out.push_str(&placeholder);
            out.push(']');
            last = e.end;
        }

        out.push_str(&text[last..]);
        (out, vault)
    }

    /// Restores original PII values in an LLM response by replacing every
    /// known placeholder with its original value from the vault.
    ///
    /// Placeholders that the vault does not know (e.g. the LLM hallucinated
    /// `[TCKN_99]`) are left as-is - the vault never guesses.
    ///
    /// # Examples
    /// ```
    /// use redactify::Vault;
    ///
    /// let (_, vault) = Vault::anonymize("TCKN 12345678950");
    /// let restored = vault.deanonymize("Your [TCKN_1] is valid. [TCKN_99] unknown.");
    /// assert!(restored.contains("12345678950"));
    /// assert!(restored.contains("[TCKN_99]")); // unknown -> left as-is
    /// ```
    #[must_use]
    pub fn deanonymize(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for (placeholder, original) in &self.entries {
            let token = format!("[{placeholder}]");
            out = out.replace(&token, original);
        }
        out
    }

    /// Returns the number of unique PII entries stored in the vault.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the vault holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns an iterator over `(placeholder, original)` pairs.
    pub fn entries_iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.entries.iter()
    }

    /// Returns the placeholder for a given original value, if stored.
    #[must_use]
    pub fn placeholder_for(&self, original: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(_, v)| v == &original)
            .map(|(k, _)| k.as_str())
    }

    /// Returns the original value for a given placeholder, if stored.
    #[must_use]
    pub fn original_for(&self, placeholder: &str) -> Option<&str> {
        self.entries.get(placeholder).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::Vault;

    #[test]
    fn round_trip_single_pii() {
        let (anon, vault) = Vault::anonymize("TCKN 12345678950");
        assert!(anon.contains("[TCKN_1]"));
        assert!(!anon.contains("12345678950"));
        assert_eq!(vault.len(), 1);

        let restored = vault.deanonymize(&anon);
        assert_eq!(restored, "TCKN 12345678950");
    }

    #[test]
    fn round_trip_multiple_types() {
        let text = "TCKN 12345678950, IBAN TR33 0006 1005 1978 6457 8413 26, mail a@b.com";
        let (anon, vault) = Vault::anonymize(text);
        assert!(anon.contains("[TCKN_1]"));
        assert!(anon.contains("[IBAN_1]"));
        assert!(anon.contains("[EMAIL_1]"));
        assert_eq!(vault.len(), 3);

        let restored = vault.deanonymize(&anon);
        assert_eq!(restored, text);
    }

    #[test]
    fn same_value_same_placeholder() {
        let (anon, _) = Vault::anonymize("TCKN 12345678950 ve tekrar 12345678950");
        assert_eq!(anon.matches("[TCKN_1]").count(), 2);
    }

    #[test]
    fn different_values_different_placeholders() {
        let text = "TCKN 12345678950 ve TCKN 10000000146";
        let (anon, vault) = Vault::anonymize(text);
        assert!(anon.contains("[TCKN_1]"));
        assert!(anon.contains("[TCKN_2]"));
        assert_eq!(vault.len(), 2);
    }

    #[test]
    fn llm_response_deanonymization() {
        let (_, vault) = Vault::anonymize("SSN 536-90-6292 ve TCKN 12345678950");

        // Simulated LLM response that references the placeholders
        let response = "I found your SSN [SSN_1] and TCKN [TCKN_1]. Is this correct?";
        let restored = vault.deanonymize(response);
        assert!(restored.contains("536-90-6292"));
        assert!(restored.contains("12345678950"));
        assert!(!restored.contains("[SSN_1]"));
        assert!(!restored.contains("[TCKN_1]"));
    }

    #[test]
    fn unknown_placeholder_left_as_is() {
        let (_, vault) = Vault::anonymize("TCKN 12345678950");
        let result = vault.deanonymize("ref [TCKN_1] and [TCKN_99]");
        assert!(result.contains("12345678950"));
        assert!(result.contains("[TCKN_99]")); // not in vault -> untouched
    }

    #[test]
    fn no_pii_returns_unchanged() {
        let (anon, vault) = Vault::anonymize("hello world no PII");
        assert_eq!(anon, "hello world no PII");
        assert!(vault.is_empty());
    }

    #[test]
    fn cross_locale_vault() {
        let text = "SSN 536-90-6292 ve TCKN 12345678950";
        let (anon, vault) = Vault::anonymize(text);
        assert_eq!(vault.len(), 2);
        let restored = vault.deanonymize(&anon);
        assert_eq!(restored, text);
    }

    #[test]
    fn lookup_helpers() {
        let (_, vault) = Vault::anonymize("TCKN 12345678950");
        assert_eq!(vault.placeholder_for("12345678950"), Some("TCKN_1"));
        assert_eq!(vault.original_for("TCKN_1"), Some("12345678950"));
        assert_eq!(vault.original_for("TCKN_99"), None);
    }

    #[test]
    fn vkn_with_cue_is_vaulted() {
        let (anon, vault) = Vault::anonymize("vergi no 1234567890");
        assert!(anon.contains("[VKN_1]"));
        assert_eq!(vault.len(), 1);
    }

    #[test]
    fn empty_text() {
        let (anon, vault) = Vault::anonymize("");
        assert_eq!(anon, "");
        assert!(vault.is_empty());
    }
}
