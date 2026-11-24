//! TOML policy configuration (`config` feature).
//!
//! Docker-first deployments configure the policy from a file instead of
//! builder code: `Policy::from_toml` parses
//!
//! ```toml
//! schema_version = "0.4"
//! block_at = 0.6
//! log_at = 0.4
//! # shadow mode (schema 0.4): decide and audit, enforce nothing
//! dry_run = false
//!
//! [categories]
//! # threshold band per guard category label: none | low | medium | high
//! SECRETS = "medium"
//! NER_DEGRADED = "low"
//! PROMPT_INJECTION = "low"   # ML categories use the same label space:
//!                            # PROMPT_INJECTION, JAILBREAK, HATE, ...
//!
//! # opt-in relevance rules (schema 0.2): entities whose type + context
//! # cue match are downgraded from masking (see docs/relevance.md)
//! [[relevance.rules]]
//! entity_types = ["PHONE", "EMAIL"]
//! cue_any = ["call me at", "reach me at", "contact:"]
//! window = 64
//!
//! # custom detection rules (schema 0.3), compiled when the file is
//! # parsed: a label (built-in or custom), a pattern OR deny-list words,
//! # optional required cues and an optional score
//! [[custom_rules]]
//! label = "EMPLOYEE_ID"
//! pattern = '\bE\d{6}\b'
//!
//! [[custom_rules]]
//! label = "PROJECT_CODENAME"
//! words = ["Falcon", "Nightjar"]
//!
//! [[custom_rules]]
//! label = "TICKET_ID"
//! pattern = '\bT-\d{4}\b'
//! cues = ["ticket", "bilet"]
//! score = 0.9
//!
//! # per-entity actions (schema 0.4): mask (the default for every type),
//! # block, log (reported, not masked) or ignore (never detected); keys
//! # are canonical labels, built-in or registered by a custom rule above
//! [entities]
//! TCKN = "block"
//! EMAIL = "log"
//! URL = "ignore"
//! EMPLOYEE_ID = "block"
//! ```
//!
//! and `load_policy_env()` resolves the path from the `REDACTIFY_POLICY`
//! environment variable (the single-knob Docker story). Bundled presets
//! live in `packs/` (kvkk.tr.toml, gdpr.toml, hipaa.toml,
//! pci-card-cue.toml): mapping INPUT
//! for compliance workflows, not a certification.
//!
//! The `schema_version` prefix gate follows the same rule as every
//! forward-compatible config format: a file declaring an unknown major or
//! minor version is rejected, not guessed at. Schema 0.1 files (no
//! `relevance` table) keep parsing unchanged; `[[custom_rules]]` needs 0.3
//! or later, `[entities]` and `dry_run` need 0.4.

use std::path::Path;

use super::{
    CategoryOverrides, EntityAction, EntityActions, GuardCategory, Policy, RelevancePolicy,
    RelevanceRule, Threshold, DEFAULT_WINDOW,
};

/// Errors from parsing a policy file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The TOML text itself is malformed.
    #[error("invalid TOML: {0}")]
    Toml(#[from] toml::de::Error),
    /// `schema_version` is missing or not a supported `"0.1"`, `"0.2"`,
    /// `"0.3"` or `"0.4"` prefix.
    #[error(
        "unsupported schema_version {0:?}: expected a \"0.1\", \"0.2\", \"0.3\" or \"0.4\" prefix"
    )]
    SchemaVersion(String),
    /// A `[[custom_rules]]` table appears in a file whose schema is older
    /// than 0.3 (the version that introduced it).
    #[error("[[custom_rules]] needs schema_version \"0.3\"")]
    CustomRulesNeedSchema03,
    /// An `[entities]` table or a `dry_run` key appears in a file whose
    /// schema is older than 0.4 (the version that introduced them).
    #[error("{0} needs schema_version \"0.4\"")]
    NeedsSchema04(&'static str),
    /// An `[entities]` value is not one of mask, block, log, ignore.
    #[error("[entities] {label}: unknown action, expected mask | block | log | ignore")]
    UnknownEntityAction {
        /// The entity label whose action is invalid.
        label: String,
    },
    /// A `[[custom_rules]]` entry does not compile (the file is refused).
    #[error("{0}")]
    CustomRule(#[from] crate::pii::CustomRulesError),
    /// A category key does not name a known guard category.
    #[error("unknown guard category: {0}")]
    UnknownCategory(String),
    /// A band value is not one of none/low/medium/high.
    #[error("unknown threshold band {0:?}: expected none|low|medium|high")]
    UnknownBand(String),
    /// Threshold values must stay in 0.0..=1.0.
    #[error("threshold out of range: {0}")]
    OutOfRange(f32),
    /// The log line sits above the block line (`log_at > block_at`): every
    /// signal that would log already blocks, so the log band is empty.
    /// When only `block_at` is set below the default log line, set
    /// `log_at` explicitly too.
    #[error(
        "log_at {log_at} is above block_at {block_at}: the log line must not exceed the block line"
    )]
    LogAboveBlock {
        /// The effective log line (file value or default).
        log_at: f32,
        /// The effective block line (file value or default).
        block_at: f32,
    },
    /// An `entity_types` entry is not a canonical entity-type label.
    #[error("unknown entity type {0:?}: expected a canonical label (PHONE, IBAN, TCKN, ...)")]
    UnknownEntityType(String),
    /// A relevance rule listed no entity types (it could never fire).
    #[error("relevance rule has an empty entity_types list")]
    EmptyEntityTypes,
    /// A relevance rule has no cues (it would fire on every entity of its
    /// types, unmasking them wholesale).
    #[error("relevance rule for {0:?} has no cues: at least one of cue_any / cue_all is required")]
    RelevanceRuleWithoutCues(Vec<String>),
    /// A `locales` entry is not one of [`crate::SUPPORTED_LOCALES`]
    /// (compared exactly: no trimming, no case folding). An unknown code
    /// would select no pack and silently switch detection off.
    #[error(
        "unknown locale code {0:?}: expected one of {supported} (lowercase, no surrounding spaces)",
        supported = crate::SUPPORTED_LOCALES.join(", ")
    )]
    UnknownLocale(String),
    /// [`POLICY_ENV_VAR`] is set but its value is not valid Unicode (it is
    /// never treated as unset: that would silently drop the policy).
    #[error("{var} is set but its value is not valid Unicode")]
    NonUnicodeEnv {
        /// The environment variable.
        var: &'static str,
    },
    /// The file could not be read.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Supported schema prefixes (forward gate: 0.1 parses without the
/// relevance table, 0.2 adds it, 0.3 adds `[[custom_rules]]`, 0.4 adds
/// `[entities]` and `dry_run`; an unknown major or minor refuses).
fn supported_schema(v: &str) -> bool {
    ["0.1", "0.2", "0.3", "0.4"]
        .iter()
        .any(|p| v == *p || v.strip_prefix(p).is_some_and(|rest| rest.starts_with('.')))
}

/// Whether `v` is the schema `minor` or a patch of it (`"0.3"`, `"0.3.1"`).
fn schema_is(v: &str, minor: &str) -> bool {
    v.strip_prefix(minor)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
}

/// Whether the schema is 0.3 or later (the `[[custom_rules]]` table).
fn schema_has_custom_rules(v: &str) -> bool {
    schema_is(v, "0.3") || schema_has_entities(v)
}

/// Whether the schema is 0.4 or later (`[entities]` and `dry_run`).
fn schema_has_entities(v: &str) -> bool {
    schema_is(v, "0.4")
}

/// Environment variable `load_policy_env` reads the path from.
pub const POLICY_ENV_VAR: &str = "REDACTIFY_POLICY";

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyToml {
    schema_version: String,
    block_at: Option<f32>,
    log_at: Option<f32>,
    categories: Option<std::collections::BTreeMap<String, String>>,
    /// Categories whose signals are completely suppressed (never collected).
    disabled: Option<Vec<String>>,
    /// Server-wide default locale codes (e.g. ["tr","en","uk"]).
    locales: Option<Vec<String>>,
    /// Opt-in relevance rules (schema 0.2).
    relevance: Option<RelevanceToml>,
    /// Custom detection rules (schema 0.3).
    custom_rules: Option<Vec<crate::pii::CustomRuleSpec>>,
    /// Per-entity actions (schema 0.4): label -> mask | block | log | ignore.
    entities: Option<std::collections::BTreeMap<String, String>>,
    /// Shadow mode (schema 0.4).
    dry_run: Option<bool>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RelevanceToml {
    rules: Vec<RelevanceRuleToml>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RelevanceRuleToml {
    entity_types: Vec<String>,
    #[serde(default)]
    cue_any: Vec<String>,
    #[serde(default)]
    cue_all: Vec<String>,
    #[serde(default = "default_window")]
    window: usize,
}

fn default_window() -> usize {
    DEFAULT_WINDOW
}

fn parse_band(v: &str) -> Result<Threshold, ConfigError> {
    match v.to_ascii_lowercase().as_str() {
        "none" => Ok(Threshold::None),
        "low" => Ok(Threshold::Low),
        "medium" => Ok(Threshold::Medium),
        "high" => Ok(Threshold::High),
        other => Err(ConfigError::UnknownBand(other.to_owned())),
    }
}

/// Converts the optional `[[relevance.rules]]` tables into a
/// [`RelevancePolicy`], fail-closed on structural problems: unknown entity
/// labels, empty `entity_types`, and cue-less rules are all config errors
/// (a cue-less rule would unmask every entity of its types wholesale).
fn parse_relevance(raw: Option<RelevanceToml>) -> Result<RelevancePolicy, ConfigError> {
    let Some(raw) = raw else {
        return Ok(RelevancePolicy::default());
    };
    let mut rules = Vec::with_capacity(raw.rules.len());
    for rt in raw.rules {
        if rt.entity_types.is_empty() {
            return Err(ConfigError::EmptyEntityTypes);
        }
        let mut entity_types = Vec::with_capacity(rt.entity_types.len());
        for label in &rt.entity_types {
            let kind: crate::EntityType = label
                .parse()
                .map_err(|_| ConfigError::UnknownEntityType(label.clone()))?;
            entity_types.push(kind);
        }
        if rt.cue_any.is_empty() && rt.cue_all.is_empty() {
            return Err(ConfigError::RelevanceRuleWithoutCues(rt.entity_types));
        }
        rules.push(RelevanceRule {
            entity_types,
            cue_any: rt.cue_any,
            cue_all: rt.cue_all,
            window: rt.window,
        });
    }
    Ok(RelevancePolicy { rules })
}

/// Converts the optional `[entities]` table into [`EntityActions`]:
/// every key must be a canonical entity label (built-in, or a custom label
/// a `[[custom_rules]]` entry registered), every value one of mask, block,
/// log, ignore (ASCII-case-insensitive).
fn parse_entities(
    raw: Option<std::collections::BTreeMap<String, String>>,
) -> Result<EntityActions, ConfigError> {
    let mut actions = EntityActions::default();
    for (label, action) in raw.into_iter().flatten() {
        let kind: crate::EntityType = label
            .parse()
            .map_err(|_| ConfigError::UnknownEntityType(label.clone()))?;
        let action: EntityAction = action
            .parse()
            .map_err(|_| ConfigError::UnknownEntityAction { label })?;
        actions.set(kind, action);
    }
    Ok(actions)
}

/// Resolves a category label, ASCII-case-insensitively, against the
/// canonical `as_str` spelling of every [`GuardCategory::ALL`] entry.
fn parse_category(label: &str) -> Result<GuardCategory, ConfigError> {
    GuardCategory::ALL
        .iter()
        .find(|c| c.as_str().eq_ignore_ascii_case(label))
        .copied()
        .ok_or_else(|| ConfigError::UnknownCategory(label.to_owned()))
}

impl Policy {
    /// Builds a policy from TOML text (see the module docs for the schema).
    ///
    /// # Errors
    /// See [`ConfigError`]; `schema_version` must start with `"0.1"`,
    /// `"0.2"`, `"0.3"` or `"0.4"` (`[[custom_rules]]` needs 0.3, and every
    /// custom rule must compile; `[entities]` and `dry_run` need 0.4, every
    /// `[entities]` key must be a canonical entity label and every value one
    /// of mask, block, log, ignore), both lines must lie in `0.0..=1.0`, `log_at` must not
    /// exceed `block_at` (defaults included: a file that only lowers
    /// `block_at` below the default log line 0.4 must set `log_at` too),
    /// and every `locales` code must be one of [`crate::SUPPORTED_LOCALES`]
    /// exactly ([`ConfigError::UnknownLocale`]).
    ///
    /// # Examples
    /// ```
    /// use redactify::policy::Policy;
    ///
    /// let p = Policy::from_toml(r#"
    ///     schema_version = "0.1"
    ///     block_at = 0.5
    ///     [categories]
    ///     SECRETS = "low"
    /// "#).unwrap();
    /// assert_eq!(p.block_at, 0.5);
    ///
    /// // schema 0.4: per-entity actions and shadow mode
    /// use redactify::policy::EntityAction;
    /// use redactify::EntityType;
    /// let p = Policy::from_toml(r#"
    ///     schema_version = "0.4"
    ///     dry_run = true
    ///     [entities]
    ///     TCKN = "block"
    ///     EMAIL = "Log"
    /// "#).unwrap();
    /// assert!(p.dry_run);
    /// assert_eq!(p.entity_actions.action_for(EntityType::Tckn), EntityAction::Block);
    /// assert_eq!(p.entity_actions.action_for(EntityType::Email), EntityAction::Log);
    /// ```
    #[cfg(feature = "config")]
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let raw: PolicyToml = toml::from_str(text)?;
        if !supported_schema(&raw.schema_version) {
            return Err(ConfigError::SchemaVersion(raw.schema_version));
        }
        let block_at = raw.block_at.unwrap_or(Policy::default().block_at);
        let log_at = raw.log_at.unwrap_or(Policy::default().log_at);
        if !(0.0..=1.0).contains(&block_at) {
            return Err(ConfigError::OutOfRange(block_at));
        }
        if !(0.0..=1.0).contains(&log_at) {
            return Err(ConfigError::OutOfRange(log_at));
        }
        if log_at > block_at {
            return Err(ConfigError::LogAboveBlock { log_at, block_at });
        }
        let mut categories = CategoryOverrides::default();
        if let Some(cats) = raw.categories {
            for (label, band) in cats {
                let category = parse_category(&label)?;
                let threshold = parse_band(&band)?;
                categories.set(category, threshold);
            }
        }
        let mut disabled = Vec::new();
        if let Some(dis) = raw.disabled {
            for label in dis {
                disabled.push(parse_category(&label)?);
            }
        }
        let default_locales = raw.locales.unwrap_or_default();
        if let Some(code) = default_locales
            .iter()
            .find(|code| !crate::SUPPORTED_LOCALES.contains(&code.as_str()))
        {
            return Err(ConfigError::UnknownLocale(code.clone()));
        }
        let relevance = parse_relevance(raw.relevance)?;
        let custom_rules = match raw.custom_rules {
            None => crate::pii::CustomRules::default(),
            Some(_) if !schema_has_custom_rules(&raw.schema_version) => {
                return Err(ConfigError::CustomRulesNeedSchema03)
            }
            Some(specs) => crate::pii::CustomRules::new(specs)?,
        };
        if !schema_has_entities(&raw.schema_version) {
            if raw.entities.is_some() {
                return Err(ConfigError::NeedsSchema04("[entities]"));
            }
            if raw.dry_run.is_some() {
                return Err(ConfigError::NeedsSchema04("dry_run"));
            }
        }
        // after the custom rules: they register the custom labels an
        // action may name
        let entity_actions = parse_entities(raw.entities)?;
        Ok(Policy {
            block_at,
            log_at,
            categories,
            disabled,
            default_locales,
            relevance,
            custom_rules,
            entity_actions,
            dry_run: raw.dry_run.unwrap_or(false),
        })
    }

    /// [`Policy::from_toml`] over a file.
    ///
    /// # Errors
    /// IO plus the parse errors of [`Policy::from_toml`].
    #[cfg(feature = "config")]
    pub fn load_toml_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)?;
        Self::from_toml(&text)
    }
}

/// Loads the policy from the path in [`POLICY_ENV_VAR`].
///
/// # Errors
/// The variable missing ([`ConfigError::Io`] with a NotFound kind), set but
/// not valid Unicode ([`ConfigError::NonUnicodeEnv`]), plus the IO and
/// parse errors of [`Policy::load_toml_file`].
#[cfg(feature = "config")]
pub fn load_policy_env() -> Result<Policy, ConfigError> {
    load_policy_env_if_set()?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{POLICY_ENV_VAR} is not set"),
        )
        .into()
    })
}

/// Loads the policy from the path in [`POLICY_ENV_VAR`] when the variable
/// is set; `Ok(None)` only when it is absent. The single env rule of the
/// CLI, the REST server and the MCP server: a variable that is set but
/// unreadable is an error, never "no policy" (fail-closed).
///
/// # Errors
/// [`ConfigError::NonUnicodeEnv`] when the value is not valid Unicode,
/// plus the IO and parse errors of [`Policy::load_toml_file`].
///
/// # Examples
/// ```
/// use redactify::policy::{config::load_policy_env_if_set, POLICY_ENV_VAR};
///
/// if std::env::var_os(POLICY_ENV_VAR).is_none() {
///     assert!(load_policy_env_if_set().unwrap().is_none());
/// }
/// ```
#[cfg(feature = "config")]
pub fn load_policy_env_if_set() -> Result<Option<Policy>, ConfigError> {
    match std::env::var(POLICY_ENV_VAR) {
        Ok(path) => Policy::load_toml_file(path).map(Some),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(ConfigError::NonUnicodeEnv {
            var: POLICY_ENV_VAR,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_category, ConfigError, GuardCategory};

    #[test]
    fn every_category_label_parses_case_insensitively() {
        for c in GuardCategory::ALL {
            assert_eq!(parse_category(c.as_str()).ok(), Some(*c));
            assert_eq!(
                parse_category(&c.as_str().to_ascii_lowercase()).ok(),
                Some(*c)
            );
        }
        assert!(matches!(
            parse_category("NOT_A_CATEGORY"),
            Err(ConfigError::UnknownCategory(_))
        ));
    }

    #[test]
    fn log_line_above_the_block_line_is_refused() {
        use crate::policy::Policy;
        let err = Policy::from_toml("schema_version = \"0.2\"\nblock_at = 0.5\nlog_at = 0.7\n")
            .unwrap_err();
        assert!(
            matches!(err, ConfigError::LogAboveBlock { log_at, block_at } if log_at == 0.7 && block_at == 0.5),
            "{err}"
        );
        // the default log line (0.4) counts: lowering only block_at refuses
        let err = Policy::from_toml("schema_version = \"0.2\"\nblock_at = 0.3\n").unwrap_err();
        assert!(matches!(err, ConfigError::LogAboveBlock { .. }), "{err}");
        // equal lines are fine
        let p =
            Policy::from_toml("schema_version = \"0.2\"\nblock_at = 0.5\nlog_at = 0.5\n").unwrap();
        assert_eq!((p.block_at, p.log_at), (0.5, 0.5));
    }

    #[test]
    fn locale_codes_are_matched_exactly() {
        use crate::policy::Policy;
        let with = |codes: &str| format!("schema_version = \"0.2\"\nlocales = [{codes}]\n");
        for bad in ["TR", "tr ", " en", "xx", "", "tr,en"] {
            let err = Policy::from_toml(&with(&format!("\"tr\", \"{bad}\""))).unwrap_err();
            assert!(
                matches!(&err, ConfigError::UnknownLocale(code) if code == bad),
                "{bad:?}: {err}"
            );
            assert!(err.to_string().contains("tr, en, de"), "{err}");
        }
        for code in crate::SUPPORTED_LOCALES {
            let p = Policy::from_toml(&with(&format!("\"{code}\""))).unwrap();
            assert_eq!(p.default_locales, [*code]);
        }
        // an absent or empty list keeps the built-in default (tr+en)
        let p = Policy::from_toml(&with("")).unwrap();
        assert!(p.default_locales.is_empty());
    }
}
