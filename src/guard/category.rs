//! Guard category taxonomy.
//!
//! Lives in the `guard` layer (detection vocabulary) so that the ML
//! interface (`guard::ml`) has zero upward imports - breaking the old
//! `guard::ml <-> policy` module cycle.
//! `policy` re-exports it unchanged for API stability.

/// Guard category taxonomy.
///
/// Who produces what: the deterministic rules (L0/L4) produce SQL_INJECTION
/// through SECRETS; the PII pipeline produces the two health categories
/// (NER_DEGRADED, SCAN_INCOMPLETE) and the ML layer the third
/// (ML_DEGRADED); the ML classifiers ([`crate::guard::ml`],
/// ONNX models behind the `ml-onnx` feature) produce PROMPT_INJECTION and
/// JAILBREAK (L2 security) and HATE through SELF_HARM (L3 safety). Labels
/// ([`GuardCategory::as_str`]) are the stable interface contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "SCREAMING_SNAKE_CASE"))]
#[non_exhaustive]
pub enum GuardCategory {
    /// SQL injection pattern (deterministic, L0/L4).
    SqlInjection,
    /// XSS / HTML injection pattern (deterministic, L0/L4).
    Xss,
    /// SSRF-dangerous URL (deterministic, L0/L4).
    DangerousUrl,
    /// Character-splitting or encoded-payload obfuscation (deterministic, L0).
    Obfuscation,
    /// PII found inside an encoded payload (deterministic, L0).
    EncodedPii,
    /// Path traversal attempt (deterministic, L0/L4).
    PathTraversal,
    /// OS command injection (deterministic, L0/L4).
    CommandInjection,
    /// Server-side template injection / SSTI (deterministic, L0/L4).
    TemplateInjection,
    /// NoSQL injection: MongoDB `$where`, Redis `FLUSHALL` (deterministic, L0/L4).
    /// serde label pinned to the canonical `as_str()` spelling
    /// "NOSQL_INJECTION" (SCREAMING_SNAKE_CASE alone would produce
    /// "NO_SQL_INJECTION").
    #[cfg_attr(feature = "serde", serde(rename = "NOSQL_INJECTION"))]
    NoSqlInjection,
    /// XML External Entity injection: `<!DOCTYPE...><!ENTITY...SYSTEM...>` (deterministic, L0/L4).
    Xxe,
    /// CRLF / HTTP header injection: response splitting, `Set-Cookie` forging (deterministic, L0/L4).
    CrlfInjection,
    /// XPath injection: tautology, axis traversal (deterministic, L0/L4).
    XpathInjection,
    /// Authority impersonation / social engineering (deterministic, L0).
    AuthorityImpersonation,
    /// Indirect / tool-call prompt injection (deterministic, L0; OWASP LLM01).
    ToolInjection,
    /// Leaked credential: API key, token, private key material (deterministic, L0/L4).
    Secrets,
    /// NER enrichment degraded (health signal, L1; default Log-level).
    NerDegraded,
    /// The PII engine could not finish scanning part of the input (a regex
    /// runtime error such as an exhausted backtrack budget), so that line
    /// was not fully checked (health signal, L1; label `SCAN_INCOMPLETE`).
    /// Scored 0.4: Log under the default policy, blockable via a category
    /// override; output transformations mask the affected line as
    /// `[SCAN_INCOMPLETE]`.
    ScanIncomplete,
    /// Prompt injection (ML L2 security classifier).
    PromptInjection,
    /// Jailbreak attempt (ML L2 security classifier).
    Jailbreak,
    /// Hate speech (ML L3 safety classifier).
    Hate,
    /// Insulting content (ML L3 safety classifier).
    Insult,
    /// Sexual content (ML L3 safety classifier).
    Sexual,
    /// Violent content (ML L3 safety classifier).
    Violence,
    /// Misconduct / unethical acts (ML L3 safety classifier).
    Misconduct,
    /// Self-harm related content (ML L3 safety classifier).
    SelfHarm,
    /// System-prompt leakage: a model output that reproduces the system
    /// prompt (deterministic, output side, needs the prompt from the
    /// caller; OWASP LLM07).
    PromptLeak,
    /// An ML classifier produced no verdict for the text (timeout,
    /// unavailable or degraded backend, inference or parse error): health
    /// signal, L2/L3; scored 0.4, so Log under the default policy and
    /// blockable via a category override. The classifier's fail mode
    /// decides the content verdict separately (fail-closed blocks).
    MlDegraded,
}

impl GuardCategory {
    /// Every category, in declaration order (the label space accepted by
    /// policy configuration). A test pins it against an exhaustive match,
    /// so a new variant cannot be forgotten here.
    ///
    /// # Examples
    /// ```
    /// use redactify::GuardCategory;
    ///
    /// assert!(GuardCategory::ALL.contains(&GuardCategory::Secrets));
    /// let labels: Vec<&str> = GuardCategory::ALL.iter().map(|c| c.as_str()).collect();
    /// assert!(labels.contains(&"SCAN_INCOMPLETE"));
    /// ```
    pub const ALL: &'static [GuardCategory] = &[
        Self::SqlInjection,
        Self::Xss,
        Self::DangerousUrl,
        Self::Obfuscation,
        Self::EncodedPii,
        Self::PathTraversal,
        Self::CommandInjection,
        Self::TemplateInjection,
        Self::NoSqlInjection,
        Self::Xxe,
        Self::CrlfInjection,
        Self::XpathInjection,
        Self::AuthorityImpersonation,
        Self::ToolInjection,
        Self::Secrets,
        Self::NerDegraded,
        Self::ScanIncomplete,
        Self::PromptInjection,
        Self::Jailbreak,
        Self::Hate,
        Self::Insult,
        Self::Sexual,
        Self::Violence,
        Self::Misconduct,
        Self::SelfHarm,
        Self::PromptLeak,
        Self::MlDegraded,
    ];

    /// Returns the canonical label (the serde spelling, the policy
    /// configuration key and the audit `guard` field).
    ///
    /// # Examples
    /// ```
    /// use redactify::GuardCategory;
    ///
    /// assert_eq!(GuardCategory::ScanIncomplete.as_str(), "SCAN_INCOMPLETE");
    /// assert_eq!(GuardCategory::NoSqlInjection.as_str(), "NOSQL_INJECTION");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SqlInjection => "SQL_INJECTION",
            Self::Xss => "XSS",
            Self::DangerousUrl => "DANGEROUS_URL",
            Self::Obfuscation => "OBFUSCATION",
            Self::EncodedPii => "ENCODED_PII",
            Self::PathTraversal => "PATH_TRAVERSAL",
            Self::CommandInjection => "COMMAND_INJECTION",
            Self::TemplateInjection => "TEMPLATE_INJECTION",
            Self::NoSqlInjection => "NOSQL_INJECTION",
            Self::Xxe => "XXE",
            Self::CrlfInjection => "CRLF_INJECTION",
            Self::XpathInjection => "XPATH_INJECTION",
            Self::AuthorityImpersonation => "AUTHORITY_IMPERSONATION",
            Self::ToolInjection => "TOOL_INJECTION",
            Self::Secrets => "SECRETS",
            Self::NerDegraded => "NER_DEGRADED",
            Self::ScanIncomplete => "SCAN_INCOMPLETE",
            Self::PromptInjection => "PROMPT_INJECTION",
            Self::Jailbreak => "JAILBREAK",
            Self::Hate => "HATE",
            Self::Insult => "INSULT",
            Self::Sexual => "SEXUAL",
            Self::Violence => "VIOLENCE",
            Self::Misconduct => "MISCONDUCT",
            Self::SelfHarm => "SELF_HARM",
            Self::PromptLeak => "PROMPT_LEAK",
            Self::MlDegraded => "ML_DEGRADED",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::GuardCategory;

    /// Number of variants; keep in sync with [`ordinal`] (the exhaustive
    /// match below fails to compile when a variant is added, pointing here).
    const VARIANT_COUNT: usize = 27;

    /// Declaration-order index of every variant. EXHAUSTIVE on purpose: a
    /// new variant is a compile error until it is numbered here.
    const fn ordinal(c: GuardCategory) -> usize {
        match c {
            GuardCategory::SqlInjection => 0,
            GuardCategory::Xss => 1,
            GuardCategory::DangerousUrl => 2,
            GuardCategory::Obfuscation => 3,
            GuardCategory::EncodedPii => 4,
            GuardCategory::PathTraversal => 5,
            GuardCategory::CommandInjection => 6,
            GuardCategory::TemplateInjection => 7,
            GuardCategory::NoSqlInjection => 8,
            GuardCategory::Xxe => 9,
            GuardCategory::CrlfInjection => 10,
            GuardCategory::XpathInjection => 11,
            GuardCategory::AuthorityImpersonation => 12,
            GuardCategory::ToolInjection => 13,
            GuardCategory::Secrets => 14,
            GuardCategory::NerDegraded => 15,
            GuardCategory::ScanIncomplete => 16,
            GuardCategory::PromptInjection => 17,
            GuardCategory::Jailbreak => 18,
            GuardCategory::Hate => 19,
            GuardCategory::Insult => 20,
            GuardCategory::Sexual => 21,
            GuardCategory::Violence => 22,
            GuardCategory::Misconduct => 23,
            GuardCategory::SelfHarm => 24,
            GuardCategory::PromptLeak => 25,
            GuardCategory::MlDegraded => 26,
        }
    }

    #[test]
    fn all_lists_every_variant_exactly_once_in_order() {
        assert_eq!(GuardCategory::ALL.len(), VARIANT_COUNT);
        for (i, c) in GuardCategory::ALL.iter().enumerate() {
            assert_eq!(ordinal(*c), i, "{c:?} out of place in ALL");
        }
    }

    #[test]
    fn labels_are_unique() {
        let mut labels: Vec<&str> = GuardCategory::ALL.iter().map(|c| c.as_str()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), VARIANT_COUNT);
    }

    #[test]
    fn scan_incomplete_label() {
        assert_eq!(GuardCategory::ScanIncomplete.as_str(), "SCAN_INCOMPLETE");
        // the signal kind and the category share the label
        assert_eq!(
            crate::guard::SignalKind::ScanIncomplete.as_str(),
            GuardCategory::ScanIncomplete.as_str()
        );
    }

    #[test]
    fn ml_degraded_label() {
        assert_eq!(GuardCategory::MlDegraded.as_str(), "ML_DEGRADED");
        assert_eq!(
            crate::guard::SignalKind::MlDegraded.as_str(),
            GuardCategory::MlDegraded.as_str()
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_labels_match_as_str() {
        for c in GuardCategory::ALL {
            let json = serde_json::to_string(c).unwrap();
            assert_eq!(json, format!("\"{}\"", c.as_str()), "{c:?}");
        }
    }
}
