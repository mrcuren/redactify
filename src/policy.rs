//! Policy core: turns guard signals + PII findings into a decision, with
//! severity banding and per-category thresholds.
//!
//! The decision model follows "block at or above the threshold" semantics (the
//! same logic as per-category thresholds in cloud guardrail services):
//!
//! - `score >= block_at` -> [`GuardAction::Block`]
//! - `score >= log_at`   -> [`GuardAction::Log`]
//! - with PII findings    -> a masking suggestion is attached to the rationale
//!   (applicable via [`crate::redact`])
//!
//! Every decision is justified through [`Decision::rationale`]: which signal,
//! which score, which threshold. Deterministic and ML signals share this
//! interface.

use crate::guard::normalize::{ScanViews, ViewKind};
use crate::guard::{GuardSignal, SecretFinding};

pub use crate::guard::GuardAction;
pub use crate::guard::GuardCategory;
use crate::pii::{Entity, NerRecognizer};

pub mod stream;

pub mod relevance;

pub mod actions;

#[cfg(feature = "config")]
pub mod config;

pub mod detector;

pub mod mask;

pub mod pipeline;

pub mod json;

#[cfg(feature = "config")]
pub use config::{load_policy_env, load_policy_env_if_set, ConfigError, POLICY_ENV_VAR};

pub use actions::{EntityAction, EntityActionParseError, EntityActions, EntityCount};
pub use relevance::{DowngradedSpan, RelevancePolicy, RelevanceRule, DEFAULT_WINDOW};
pub use stream::{GuardEvent, MlStreamBudget, StreamingGuard};

pub use detector::{detect, redact, Detector, ScanReport};
pub use json::{JsonFinding, JsonFindingKind, JsonRedactionReport, JsonRedactor};
pub use mask::{MaskStyle, MaskStyleError, PseudonymKey};
pub use pipeline::Guard;

/// Severity band for a signal or finding (policy banding layer).
///
/// Maps a raw confidence score to a human-readable band. The thresholds are
/// a starting point, not an assumption; calibration happens by measurement
/// (ROC / holdout, with the ML layer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "SCREAMING_SNAKE_CASE"))]
#[non_exhaustive]
pub enum Severity {
    /// No risk detected: p < 0.35.
    Safe,
    /// Low risk: 0.35 <= p < 0.60.
    Low,
    /// Medium risk: 0.60 <= p < 0.85.
    Medium,
    /// High risk: p >= 0.85.
    High,
}

impl Severity {
    /// Maps a raw score to a severity band using the default thresholds.
    ///
    /// Not `const`: float comparisons in a `const fn` require Rust 1.82,
    /// above the crate MSRV (1.80).
    #[must_use]
    pub fn from_score(score: f32) -> Self {
        if score >= 0.85 {
            Self::High
        } else if score >= 0.60 {
            Self::Medium
        } else if score >= 0.35 {
            Self::Low
        } else {
            Self::Safe
        }
    }

    /// Returns the canonical label (`"SAFE"`, `"LOW"`, `"MEDIUM"`, `"HIGH"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Safe => "SAFE",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
        }
    }
}

/// Per-category blocking threshold - the same semantics cloud
/// guardrail services expose: pick a severity band per category, and scores
/// at or above that band's lower edge block.
///
/// Band edges mirror [`Severity::from_score`]: LOW from 0.35,
/// MEDIUM from 0.60, HIGH from 0.85.
///
/// # Examples
/// ```
/// use redactify::policy::Threshold;
///
/// assert_eq!(Threshold::Low.block_score(), 0.35);
/// assert_eq!(Threshold::Medium.block_score(), 0.60);
/// assert_eq!(Threshold::High.block_score(), 0.85);
/// // None never blocks (monitor-only category)
/// assert!(Threshold::None.block_score() > 1.0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "SCREAMING_SNAKE_CASE"))]
#[non_exhaustive]
pub enum Threshold {
    /// Never block this category (log/allow only) - monitoring mode.
    /// Not honored on [`GuardTarget::ToolResponse`] (see
    /// [`Policy::for_target`]).
    None,
    /// Block from the LOW band (score >= 0.35).
    Low,
    /// Block from the MEDIUM band (score >= 0.60).
    Medium,
    /// Block from the HIGH band (score >= 0.85).
    High,
}

impl Threshold {
    /// The score at or above which this threshold blocks.
    ///
    /// Not `const`: `f32::INFINITY` in a `const fn` requires Rust 1.82,
    /// above the crate MSRV (1.80).
    #[must_use]
    pub fn block_score(self) -> f32 {
        match self {
            Self::None => f32::INFINITY,
            Self::Low => 0.35,
            Self::Medium => 0.60,
            Self::High => 0.85,
        }
    }

    /// The nearest threshold band for a global numeric cutoff (calibration
    /// helper: e.g. a measured best-F1 cutoff maps onto the band grid).
    ///
    /// # Examples
    /// ```
    /// use redactify::policy::Threshold;
    /// assert_eq!(Threshold::from_cutoff(0.706), Threshold::Medium);
    /// assert_eq!(Threshold::from_cutoff(0.815), Threshold::Medium); // 0.815 < 0.85
    /// assert_eq!(Threshold::from_cutoff(0.90), Threshold::High);
    /// assert_eq!(Threshold::from_cutoff(0.30), Threshold::Low);
    /// ```
    #[must_use]
    pub fn from_cutoff(cutoff: f32) -> Self {
        if cutoff >= 0.85 {
            Self::High
        } else if cutoff >= 0.60 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

/// Per-category threshold overrides.
///
/// Empty by default: every category then follows the policy's global
/// [`Policy::block_at`] line. Categories present here block at their band
/// edge instead - "blocks at the chosen band and above" semantics.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CategoryOverrides {
    entries: Vec<(GuardCategory, Threshold)>,
}

// Order-insensitive equality: a derived PartialEq would compare the Vec
// entry-by-entry, so the SAME override set built in a different insertion
// order would compare unequal.
impl PartialEq for CategoryOverrides {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len()
            && self
                .entries
                .iter()
                .all(|(c, t)| other.entries.iter().any(|(c2, t2)| c == c2 && t == t2))
    }
}
impl Eq for CategoryOverrides {}

impl CategoryOverrides {
    /// Iterates the stored overrides (category, threshold).
    fn iter(&self) -> impl Iterator<Item = (GuardCategory, Threshold)> + '_ {
        self.entries.iter().copied()
    }

    /// The overrides a `ToolResponse` decision honors: only those whose
    /// block line sits at or below the built-in tool block line
    /// ([`TOOL_BLOCK_AT`], i.e. `Threshold::Low`). Looser overrides
    /// (`Medium`, `High`, `None`) are DROPPED, so their category falls back
    /// to the clamped global line. Used by [`Policy::for_target`].
    fn tool_response_lines(&self) -> Self {
        let mut out = Self::default();
        for (cat, threshold) in self.iter() {
            if threshold.block_score() <= TOOL_BLOCK_AT {
                out.set(cat, threshold);
            }
        }
        out
    }

    /// Sets (or replaces) the threshold for one category.
    pub fn set(&mut self, category: GuardCategory, threshold: Threshold) {
        if let Some(slot) = self.entries.iter_mut().find(|(c, _)| *c == category) {
            slot.1 = threshold;
        } else {
            self.entries.push((category, threshold));
        }
    }

    /// The override for a category, if any.
    #[must_use]
    pub fn get(&self, category: GuardCategory) -> Option<Threshold> {
        self.entries
            .iter()
            .find(|(c, _)| *c == category)
            .map(|(_, t)| *t)
    }

    /// Number of overrides set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no overrides are set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A single guard verdict with category, score, severity band, action and rationale.
///
/// This is a fixed Rust contract. The ML layer will
/// produce these; the deterministic layer produces them today.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct GuardVerdict {
    /// Guard category.
    pub category: GuardCategory,
    /// Raw confidence score (0.0-1.0).
    pub score: f32,
    /// Severity band derived from the score.
    pub severity: Severity,
    /// The action decided for this category.
    pub action: GuardAction,
    /// Human-readable rationale (which rule, which score, which threshold).
    pub rationale: String,
}

/// Rule-based policy settings.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Policy {
    /// At this score and above: block (global line; per-category overrides
    /// below take precedence for their category).
    pub block_at: f32,
    /// At this score and above: log (below the block line).
    pub log_at: f32,
    /// Per-category band overrides; empty = global line everywhere.
    pub categories: CategoryOverrides,
    /// Categories whose signals are COMPLETELY suppressed (never collected;
    /// stronger than `Threshold::None` which only blocks but still
    /// collects + masks). Set from TOML `[disabled]`. Not honored on
    /// [`GuardTarget::ToolResponse`] (see [`Policy::for_target`]).
    #[cfg_attr(feature = "serde", serde(default))]
    pub disabled: Vec<GuardCategory>,
    /// Default locale packs (empty = the built-in tr+en default). Every
    /// guard built with this policy ([`Guard`], [`StreamingGuard`], the REST
    /// API) detects with these locales unless the caller passes an explicit
    /// locale list, which takes precedence.
    #[cfg_attr(feature = "serde", serde(default))]
    pub default_locales: Vec<String>,
    /// Opt-in relevance rules: entities whose type + surrounding
    /// context match a rule are downgraded from masking - they stay in the
    /// text while still being reported on the decision. Empty (the default)
    /// masks everything detected. See docs/relevance.md and [`relevance`].
    #[cfg_attr(feature = "serde", serde(default))]
    pub relevance: RelevancePolicy,
    /// Custom rules (TOML `[[custom_rules]]`, schema 0.3), compiled when
    /// the policy is built. Every [`Guard`] and [`StreamingGuard`] carrying
    /// this policy detects with them (on top of any rules passed to the
    /// guard directly), on every target. Empty (the default) changes
    /// nothing.
    #[cfg_attr(feature = "serde", serde(default))]
    pub custom_rules: crate::pii::CustomRules,
    /// Per-entity-type actions (TOML `[entities]`, schema 0.4): mask
    /// (the default for every type), block, log or ignore. Empty (the
    /// default) masks every detected type.
    /// See [`actions`] for how the actions compose with relevance rules
    /// and guard signals.
    #[cfg_attr(feature = "serde", serde(default))]
    pub entity_actions: EntityActions,
    /// Shadow mode (TOML `dry_run = true`, schema 0.4; off by default):
    /// every [`Guard`] decision is computed as usual, but nothing is
    /// enforced. The decision's `action` is `Allow`, the action the policy
    /// decided is kept in [`Decision::dry_run_action`] and named in the
    /// rationale (`dry run (not enforced): would Block ...`), and
    /// [`Guard::sanitize`] returns the text unchanged (secrets and PII
    /// included). Audit records carry the decided action (guard
    /// `DRY_RUN`, see [`audit_from_decision`]). The [`StreamingGuard`]
    /// still enforces: the REST and CLI stream surfaces shadow it
    /// themselves, echoing the input.
    #[cfg_attr(feature = "serde", serde(default))]
    pub dry_run: bool,
}

impl Default for Policy {
    /// Defaults: block 0.6, log 0.4. These numbers are a starting point, not an
    /// assumption; calibration happens by measurement (ROC / holdout, with the ML layer).
    fn default() -> Self {
        Self {
            block_at: 0.6,
            log_at: 0.4,
            categories: CategoryOverrides::default(),
            disabled: Vec::new(),
            default_locales: Vec::new(),
            relevance: RelevancePolicy::default(),
            custom_rules: crate::pii::CustomRules::default(),
            entity_actions: EntityActions::default(),
            dry_run: false,
        }
    }
}

impl Policy {
    /// Sets the action for one entity type (builder style; see
    /// [`actions`]).
    ///
    /// # Examples
    /// ```
    /// use redactify::policy::{EntityAction, Policy};
    /// use redactify::{EntityType, Guard, GuardAction, GuardTarget};
    ///
    /// let p = Policy::default()
    ///     .with_entity_action(EntityType::Tckn, EntityAction::Block)
    ///     .with_entity_action(EntityType::Email, EntityAction::Log);
    /// let guard = Guard::new(GuardTarget::UserPrompt).with_policy(&p);
    ///
    /// let d = guard.decide("TCKN 12345678950");
    /// assert_eq!(d.action, GuardAction::Block);
    /// assert!(!d.rationale.contains("12345678950")); // labels, never values
    ///
    /// let r = guard.sanitize("mail a@b.com, SSN 536-90-6292");
    /// assert_eq!(r.decision.action, GuardAction::Log);
    /// assert_eq!(r.text, "mail a@b.com, SSN [SSN]"); // LOG: counted, not masked
    /// ```
    #[must_use]
    pub fn with_entity_action(mut self, kind: crate::EntityType, action: EntityAction) -> Self {
        self.entity_actions.set(kind, action);
        self
    }

    /// Sets a per-category band override (builder style).
    ///
    /// # Examples
    /// ```
    /// use redactify::policy::{GuardCategory, Policy, Threshold};
    /// let p = Policy::default()
    ///     .with_category(GuardCategory::SqlInjection, Threshold::High)
    ///     .with_category(GuardCategory::DangerousUrl, Threshold::None);
    /// assert_eq!(p.categories.get(GuardCategory::SqlInjection), Some(Threshold::High));
    /// ```
    #[must_use]
    pub fn with_category(mut self, category: GuardCategory, threshold: Threshold) -> Self {
        self.categories.set(category, threshold);
        self
    }

    /// Appends a relevance rule (builder style). Entities matching the rule
    /// are downgraded from masking (see [`relevance`]); the empty default
    /// policy is a no-op, so relevance is strictly opt-in per rule added.
    ///
    /// # Examples
    /// ```
    /// use redactify::policy::{Policy, RelevanceRule};
    /// use redactify::EntityType;
    ///
    /// let p = Policy::default().with_relevance(RelevanceRule {
    ///     entity_types: vec![EntityType::Phone],
    ///     cue_any: vec!["call me at".into()],
    ///     cue_all: vec![],
    ///     window: 64,
    /// });
    /// assert_eq!(p.relevance.rules.len(), 1);
    /// ```
    #[must_use]
    pub fn with_relevance(mut self, rule: RelevanceRule) -> Self {
        self.relevance.rules.push(rule);
        self
    }

    /// The effective block line for one category (override or global).
    #[must_use]
    pub fn block_line_for(&self, category: GuardCategory) -> f32 {
        self.categories
            .get(category)
            .map_or(self.block_at, Threshold::block_score)
    }

    /// Whether signals of `category` are collected at all (`false` for a
    /// category listed in [`Policy::disabled`]).
    fn is_enabled(&self, category: GuardCategory) -> bool {
        !self.disabled.contains(&category)
    }

    /// [`Policy::default_locales`] as borrowed locale codes.
    fn default_locale_refs(&self) -> Vec<&str> {
        self.default_locales.iter().map(String::as_str).collect()
    }
}

/// The built-in `ToolResponse` block line: tool output is the indirect
/// prompt-injection vector, so no policy decides it more loosely.
const TOOL_BLOCK_AT: f32 = 0.5;

/// The built-in `ToolResponse` log line.
const TOOL_LOG_AT: f32 = 0.3;

/// The effective locale list of a guard: an explicit (non-empty) list
/// wins, else the policy's [`Policy::default_locales`], else empty (the
/// engine's default tr+en set).
fn effective_locales<'a>(explicit: &[&'a str], policy: Option<&'a Policy>) -> Vec<&'a str> {
    if explicit.is_empty() {
        policy.map(Policy::default_locale_refs).unwrap_or_default()
    } else {
        explicit.to_vec()
    }
}

/// Where the guarded text comes from. Different targets may warrant different
/// rule sets or thresholds (a tool response from a web scraper is more likely
/// to carry injected content than a direct user prompt).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum GuardTarget {
    /// Direct user input (prompt).
    UserPrompt,
    /// Response from an external tool (web scraper, API call, database query).
    /// This is the attack vector for indirect prompt injection.
    ToolResponse,
    /// Model-generated output (LLM response before it reaches the consumer).
    ModelOutput,
}

/// Parse error for `GuardTarget::from_str`: the input was not one of the
/// recognized target names.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
#[error("unknown target `{0}` (user_prompt | tool_response | model_output)")]
pub struct GuardTargetParseError(String);

impl std::str::FromStr for GuardTarget {
    type Err = GuardTargetParseError;

    /// Parses a target name (same spellings as the CLI `--target` flag:
    /// `user_prompt`/`user`/`prompt`, `tool_response`/`tool`,
    /// `model_output`/`model`).
    ///
    /// # Examples
    /// ```
    /// use redactify::policy::GuardTarget;
    /// use std::str::FromStr;
    /// assert_eq!(GuardTarget::from_str("tool").unwrap(), GuardTarget::ToolResponse);
    /// assert!(GuardTarget::from_str("nope").is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user_prompt" | "user" | "prompt" => Ok(Self::UserPrompt),
            "tool_response" | "tool" | "tool-response" => Ok(Self::ToolResponse),
            "model_output" | "model" | "model-output" => Ok(Self::ModelOutput),
            other => Err(GuardTargetParseError(other.to_owned())),
        }
    }
}

/// A policy decision with its rationale.
///
/// serde: `Serialize` only - `mask_summary` holds `&'static str` labels that
/// `Deserialize` cannot produce (no `'static` data from borrowed input).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct Decision {
    /// The chosen action.
    pub action: GuardAction,
    /// ALL guard signals that were evaluated (both deterministic and ML).
    pub signals: Vec<GuardSignal>,
    /// The highest-scoring signal that drove the decision, if any.
    pub top_signal: Option<GuardSignal>,
    /// Masking suggestion: labels of entity types found, if any.
    pub mask_summary: Vec<&'static str>,
    /// Human-readable rationale.
    pub rationale: String,
    /// Individual verdicts per guard signal (severity-banded).
    pub verdicts: Vec<GuardVerdict>,
    /// The relevance rules that produced this decision's downgrades (policy
    /// echo for the sanitize transformation, which re-applies them to the
    /// entities of the raw text it masks, before secrets and PII are masked
    /// in one pass). Never serialized: decisions carry data, not
    /// configuration.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub relevance: RelevancePolicy,
    /// Entities relevance-downgraded (type + span, NO raw values - decisions
    /// never echo PII). Empty unless rules were configured AND matched.
    pub relevance_downgraded: Vec<DowngradedSpan>,
    /// The entity types found, each with the action the policy applied and
    /// a count (first-seen order; no values; see [`EntityCount`]). Empty
    /// when no PII was found.
    pub entity_counts: Vec<EntityCount>,
    /// Shadow mode ([`Policy::dry_run`]): the action the policy decided,
    /// which this decision does not enforce (`action` is then `Allow`).
    /// `None` outside dry-run mode.
    pub dry_run_action: Option<GuardAction>,
}

impl Decision {
    /// The action the policy decided: [`Decision::dry_run_action`] in
    /// dry-run mode, else [`Decision::action`] (what metrics and audit
    /// records count).
    ///
    /// # Examples
    /// ```
    /// use redactify::policy::{GuardAction, Policy};
    /// use redactify::{Guard, GuardTarget};
    ///
    /// let p = Policy { dry_run: true, ..Policy::default() };
    /// let d = Guard::new(GuardTarget::UserPrompt).with_policy(&p).decide("TCKN 12345678950");
    /// assert_eq!(d.action, GuardAction::Allow); // nothing enforced
    /// assert_eq!(d.decided_action(), GuardAction::Mask);
    /// assert!(d.rationale.starts_with("dry run (not enforced): would Mask"));
    /// ```
    #[must_use]
    pub fn decided_action(&self) -> GuardAction {
        self.dry_run_action.unwrap_or(self.action)
    }

    /// Turns this decision into its dry-run form: the decided action moves
    /// to [`Decision::dry_run_action`], `action` becomes `Allow`, and the
    /// rationale names the decided action and the entity counts. A no-op
    /// on a decision already in that form.
    pub(crate) fn into_dry_run(mut self) -> Self {
        if self.dry_run_action.is_some() {
            return self;
        }
        let counts: Vec<String> = self
            .entity_counts
            .iter()
            .map(|c| format!("{}={} x{}", c.kind.as_str(), c.action, c.count))
            .collect();
        let entities = if counts.is_empty() {
            String::new()
        } else {
            format!(" [entities: {}]", counts.join(", "))
        };
        self.rationale = format!(
            "dry run (not enforced): would {}{entities}; {}",
            self.action, self.rationale
        );
        self.dry_run_action = Some(self.action);
        self.action = GuardAction::Allow;
        self
    }
}

/// Turns signals and PII findings into a policy decision.
///
/// # Examples
/// ```
/// use redactify::guard::sql_risk;
/// use redactify::policy::{decide, GuardAction, Policy};
///
/// let sig = vec![sql_risk("1' OR '1'='1").unwrap()];
/// let d = decide(&sig, &[], &Policy::default());
/// assert_eq!(d.action, GuardAction::Block);
///
/// let d = decide(&[], &[], &Policy::default());
/// assert_eq!(d.action, GuardAction::Allow);
/// ```
///
/// Entity actions ([`Policy::entity_actions`]) apply to `pii`: a `Block`
/// type blocks, a `Log` type makes the decision at least `Log` and stays
/// out of `mask_summary`, an `Ignore` type is dropped.
#[must_use]
pub fn decide(signals: &[GuardSignal], pii: &[Entity], policy: &Policy) -> Decision {
    let counts = actions::tally(
        pii,
        std::iter::empty(),
        std::iter::empty(),
        &policy.entity_actions,
    );
    decide_counted(signals, counts, policy)
}

/// The labels of the `counts` whose action is `action`, in order.
fn labels_with(counts: &[EntityCount], action: EntityAction) -> Vec<&'static str> {
    counts
        .iter()
        .filter(|c| c.action == action)
        .map(|c| c.kind.as_str())
        .collect()
}

/// [`decide`] over already-tallied entities (see [`EntityCount`]).
fn decide_counted(signals: &[GuardSignal], counts: Vec<EntityCount>, policy: &Policy) -> Decision {
    let top = signals.iter().max_by(|a, b| a.score.total_cmp(&b.score));

    let mask_summary = labels_with(&counts, EntityAction::Mask);
    let blocked = labels_with(&counts, EntityAction::Block);
    let logged = labels_with(&counts, EntityAction::Log);

    // Build per-signal verdicts with severity banding. Each category blocks
    // at ITS line: a band override if set, else the global block_at.
    let verdicts: Vec<GuardVerdict> = signals
        .iter()
        .map(|s| {
            let severity = Severity::from_score(s.score);
            let category = signal_kind_to_category(s.kind);
            let block_line = policy.block_line_for(category);
            let action = if s.score >= block_line {
                GuardAction::Block
            } else if s.score >= policy.log_at {
                GuardAction::Log
            } else {
                GuardAction::Allow
            };
            GuardVerdict {
                category,
                score: s.score,
                severity,
                action,
                rationale: s.rationale.clone(),
            }
        })
        .collect();

    // ANY blocking verdict blocks, not only the top-scoring signal's: a
    // strict per-category override (`SECRETS = "low"`) must hold even when
    // a higher-scoring signal from a laxer category tops the list.
    // entity actions: a BLOCK type blocks after a blocking signal; a LOG
    // type logs after a log-level signal (the rationale names type labels
    // only, never values)
    let blocked_why = || format!("entity type(s) configured BLOCK: {}", blocked.join(", "));
    let logged_why = || {
        format!(
            "entity type(s) configured LOG (reported, not masked): {}",
            logged.join(", ")
        )
    };
    let (action, mut why) = if let Some(v) =
        verdicts.iter().find(|v| v.action == GuardAction::Block)
    {
        (
                GuardAction::Block,
                format!(
                "signal category {} score {:.2} >= its block line ({}); top signal {:?} score {:.2}",
                v.category.as_str(),
                v.score,
                policy.block_line_for(v.category),
                top.map(|s| s.kind).map(|k| format!("{k:?}")).unwrap_or_else(|| "none".into()),
                top.map(|s| s.score).unwrap_or(0.0),
            ),
            )
    } else if !blocked.is_empty() {
        (GuardAction::Block, blocked_why())
    } else {
        match top {
            Some(s) if s.score >= policy.log_at => (
                GuardAction::Log,
                format!(
                    "top signal {:?} score {:.2} >= log threshold {:.2}",
                    s.kind, s.score, policy.log_at
                ),
            ),
            _ if !logged.is_empty() => (GuardAction::Log, logged_why()),
            _ if !mask_summary.is_empty() => (
                GuardAction::Mask,
                "no danger signals; PII should be masked".to_owned(),
            ),
            _ => (GuardAction::Allow, "no signals and no PII".to_owned()),
        }
    };
    // the entity actions the primary reason above does not name
    if action == GuardAction::Block && !blocked.is_empty() && !why.starts_with("entity") {
        why.push_str("; ");
        why.push_str(&blocked_why());
    }
    if !logged.is_empty() && !why.starts_with("entity type(s) configured LOG") {
        why.push_str("; ");
        why.push_str(&logged_why());
    }

    Decision {
        action,
        signals: signals.to_vec(),
        top_signal: top.cloned(),
        mask_summary,
        rationale: why,
        verdicts,
        relevance: RelevancePolicy::default(),
        relevance_downgraded: Vec::new(),
        entity_counts: counts,
        dry_run_action: None,
    }
}

/// Runs every deterministic guard rule in one call and produces the policy decision.
///
/// Ordering is cost-aware: cheap rules first, PII scanning stays a caller concern;
/// this function simply combines them all.
///
/// # Examples
/// ```
/// use redactify::policy::{guard_all, GuardAction};
/// let d = guard_all("bkz: http://169.254.169.254/meta");
/// assert_eq!(d.action, GuardAction::Block);
/// let d = guard_all("merhaba dunya");
/// assert_eq!(d.action, GuardAction::Allow);
/// ```
#[must_use]
pub fn guard_all(text: &str) -> Decision {
    Guard::new(GuardTarget::UserPrompt).decide(text)
}

/// The distinct type labels of `entities`, in first-seen order (the
/// `mask_summary` form).
fn unique_labels<'e>(entities: impl IntoIterator<Item = &'e Entity>) -> Vec<&'static str> {
    let mut labels: Vec<&'static str> = Vec::new();
    for e in entities {
        let label = e.kind.as_str();
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    labels
}

/// PII findings grouped by coordinate system: `raw` offsets index `text`
/// (the only group relevance rules and masking operate on), `normalized`
/// offsets index the normalized view (NFKC/invisible-stripped - the same
/// visible text, so relevance rules apply there too), `decoded` holds the
/// findings of every decoded view (base64 layers and escape-decoded
/// views) with the view they came from (their offsets do not map back
/// into the text, and opaque payloads are never relevance-downgraded; the
/// masking pass masks the base64 tokens themselves, see [`encoded_tokens`]).
///
/// `engine_errors` sums the scan errors of every scan (regex runtime
/// errors, and lines whose normalized view could not be aligned back to the
/// raw text); the first line that was not fully scanned is kept for the leak-safe evidence
/// preview of the `SCAN_INCOMPLETE` signal.
pub(crate) struct PiiViews {
    raw: Vec<Entity>,
    normalized: Vec<Entity>,
    decoded: Vec<(ViewKind, Vec<Entity>)>,
    engine_errors: usize,
    first_incomplete_line: Option<String>,
}

impl PiiViews {
    /// Whether ANY scan found PII (raw, normalized or decoded; before
    /// relevance, which only loosens the masking suggestion).
    fn has_pii(&self) -> bool {
        !self.raw.is_empty()
            || !self.normalized.is_empty()
            || self.decoded.iter().any(|(_, ents)| !ents.is_empty())
    }

    /// Adds one scan's entity-independent health facts.
    fn record_health(&mut self, scanned: &str, report: &ScanReport) {
        self.engine_errors += report.engine_errors;
        if self.first_incomplete_line.is_none() {
            self.first_incomplete_line = report
                .error_spans
                .first()
                .and_then(|&(s, e)| scanned.get(s..e))
                .map(str::to_owned);
        }
    }
}

/// Collects PII findings for the DECISION from the raw text, the
/// normalized view, and every decoded view, all with the same raw-text
/// `detector` (no normalization pass of its own: the normalized view is
/// scanned here explicitly). Normalized-view and decoded-view findings
/// drive the decision even though their offsets do not map back into the
/// original text (masking always re-detects on the raw text). The
/// normalized view's participation is load-bearing: an encoding evasion
/// that only the normalizer can undo (fullwidth digits, zero-width
/// scatter, dotted-İ casings) must still flip the decision to Mask even
/// when the raw-text scan misses it (see tests/adversarial_evasion.rs).
fn collect_pii_views(text: &str, views: &ScanViews, detector: &Detector<'_>) -> PiiViews {
    let mut pii = PiiViews {
        raw: Vec::new(),
        normalized: Vec::new(),
        decoded: Vec::new(),
        engine_errors: 0,
        first_incomplete_line: None,
    };
    let report = detector.scan(text);
    pii.record_health(text, &report);
    pii.raw = report.entities;
    // normalized == text means normalization changed nothing: its
    // detections would duplicate `raw` verbatim, so skip the duplicate pass
    // (clean inputs pay nothing for the normalized-view pass).
    if views.normalized() != text {
        let report = detector.scan(views.normalized());
        pii.record_health(views.normalized(), &report);
        pii.normalized = report.entities;
    }
    for (kind, view) in views.decoded() {
        let report = detector.scan(view);
        pii.record_health(view, &report);
        pii.decoded.push((kind, report.entities));
    }
    pii
}

/// The secret spans every masking path of the policy layer replaces with
/// `[SECRET:VENDOR]`: batch sanitize, the ML input and every stream
/// segment take them from here, so the paths never disagree on what a
/// credential is. These are the MASKING spans (raw view united with the
/// normalized view, mapped back to raw offsets, sorted and disjoint; see
/// [`crate::guard::secrets::find_secret_mask_spans`]); decision signals
/// keep scanning every view on its own.
fn secret_mask_spans(text: &str) -> Vec<SecretFinding> {
    secret_mask_spans_with(text, &encoded_tokens(text))
}

/// [`secret_mask_spans`] over already-decoded tokens (a masking pass that
/// also needs [`encoded_pii_entities`] decodes the tokens once).
pub(crate) fn secret_mask_spans_with(text: &str, tokens: &EncodedTokens) -> Vec<SecretFinding> {
    let mut spans = crate::guard::secrets::find_secret_mask_spans(text);
    let encoded = tokens.secret_spans();
    if !encoded.is_empty() {
        spans.extend(encoded);
        spans.sort_by(|a, b| a.start.cmp(&b.start).then(a.end.cmp(&b.end)));
        // disjoint for the renderer: an overlap merges into the earlier span
        let mut merged: Vec<SecretFinding> = Vec::with_capacity(spans.len());
        for s in spans {
            match merged.last_mut() {
                Some(last) if s.start < last.end => last.end = last.end.max(s.end),
                _ => merged.push(s),
            }
        }
        spans = merged;
    }
    spans
}

// Encoded payloads in the OUTPUT. The decoded scan views drive the
// decision; these helpers are their masking counterpart, so what a decision
// saw inside an encoding is also masked in the emitted text. Every base64
// candidate token is decoded `DECODE_DEPTH` layers deep (every nested
// candidate too, the views' rule): a token whose decoded layers hold a
// credential is masked whole as that secret (`secret_mask_spans`, so every
// masking path and the Block branch mask it), otherwise a token that holds
// PII is masked whole as that entity type (`encoded_pii_entities`, with the
// masking pass's own detector). Every line with percent escapes or
// character references is decoded with a byte map back to the raw text; a
// credential or PII found there that covers an escaped byte is masked over
// its raw span the same two ways.

/// One decoded base64 token: raw span, its decoded layers
/// 1..=`DECODE_DEPTH`, and the first credential in them (the zero-length
/// scan-error marker is not a credential).
struct EncodedToken {
    start: usize,
    end: usize,
    layers: Vec<String>,
    secret: Option<SecretFinding>,
}

/// One escape-decoded view of the raw text (percent escapes or character
/// references, decoded once): its normalized form, which is scanned, and the
/// maps from a normalized boundary to a decoded one and from a decoded byte
/// to its raw byte range.
struct EscapedView {
    norm: String,
    /// normalized boundary -> decoded boundary (`norm.len() + 1` entries)
    nmap: Vec<usize>,
    /// decoded byte -> raw byte range
    raw: Vec<(usize, usize)>,
}

impl EscapedView {
    /// The view of one line decoded as `(decoded, raw)`; `offset` is the
    /// line's byte offset in the text (added to every raw range).
    fn new((decoded, raw): (String, Vec<(usize, usize)>), offset: usize) -> Self {
        let raw = raw
            .into_iter()
            .map(|(a, b)| (a + offset, b + offset))
            .collect();
        // an unalignable line (defensive, see `normalize_for_scan_with_map`)
        // falls back to scanning the decoded text itself
        let (norm, nmap) = crate::guard::normalize::normalize_for_scan_with_map(&decoded)
            .unwrap_or_else(|| {
                let n = decoded.len();
                (decoded.clone(), (0..=n).collect())
            });
        Self { norm, nmap, raw }
    }

    /// The raw span of the normalized span `[s, e)`, when that span covers
    /// at least one escaped byte (a finding of plain text is the raw scan's).
    fn raw_span(&self, s: usize, e: usize) -> Option<(usize, usize)> {
        let (ds, de) = (*self.nmap.get(s)?, *self.nmap.get(e)?);
        let bytes = self.raw.get(ds..de)?;
        let (first, last) = (bytes.first()?, bytes.last()?);
        bytes
            .iter()
            .any(|(a, b)| b - a > 1)
            .then_some((first.0, last.1))
    }
}

/// The encoded parts of a text, each decoded and checked for a credential
/// ONCE per masking pass ([`encoded_tokens`]): the base64 candidate tokens
/// and the percent / character-reference decoded views.
pub(crate) struct EncodedTokens {
    tokens: Vec<EncodedToken>,
    escaped: Vec<EscapedView>,
}

/// Decodes every base64 candidate token of `text` (raw spans; see
/// [`encoded_token_spans`]) and checks its layers for a credential, and
/// decodes the percent escapes and character references of every line that
/// holds one (with maps back to the raw text). Plain text with neither
/// costs only the scans that find nothing to decode.
pub(crate) fn encoded_tokens(text: &str) -> EncodedTokens {
    use crate::guard::normalize::{
        decode_html_refs_mapped, layered_views, percent_decode_once_mapped, DECODE_DEPTH,
    };
    let tokens = encoded_token_spans(text)
        .into_iter()
        .map(|(start, end, decoded)| {
            // `decoded` is layer 1; peel the remaining layers below it
            let layers = layered_views(&decoded, DECODE_DEPTH.saturating_sub(1));
            let secret = layers.iter().find_map(|layer| {
                crate::guard::secrets::find_secret_spans(layer)
                    .into_iter()
                    .find(|s| s.start < s.end)
            });
            EncodedToken {
                start,
                end,
                layers,
                secret,
            }
        })
        .collect();
    // escape views per LINE, and only for lines that hold an escape: PII
    // matches and context cues are line-scoped, so a line's own view is the
    // whole context, and a text whose escapes all sit in one line re-scans
    // that line only (decoding the whole text cost ~47% of `sanitize` and
    // ~3x `mask_all` on text with a benign `&amp;` / `%20`)
    let mut escaped = Vec::new();
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        if body.contains(['%', '&']) {
            for view in [
                percent_decode_once_mapped(body),
                decode_html_refs_mapped(body),
            ]
            .into_iter()
            .flatten()
            {
                escaped.push(EscapedView::new(view, offset));
            }
        }
        offset += line.len();
    }
    EncodedTokens { tokens, escaped }
}

impl EncodedTokens {
    /// Raw spans of the encoded credentials: the base64 tokens that hide one
    /// (vendor and score of the first) and the escape-encoded credentials
    /// (their raw span).
    fn secret_spans(&self) -> Vec<SecretFinding> {
        let tokens = self.tokens.iter().filter_map(|t| {
            t.secret.as_ref().map(|s| SecretFinding {
                start: t.start,
                end: t.end,
                vendor: s.vendor,
                score: s.score,
            })
        });
        let escaped = self.escaped.iter().flat_map(|v| {
            crate::guard::secrets::find_secret_spans(&v.norm)
                .into_iter()
                .filter(|s| s.start < s.end)
                .filter_map(move |s| {
                    v.raw_span(s.start, s.end)
                        .map(|(start, end)| SecretFinding {
                            start,
                            end,
                            vendor: s.vendor,
                            score: s.score,
                        })
                })
        });
        tokens.chain(escaped).collect()
    }
}

/// The tokens of `tokens` (decoded from `text`) that hold PII and no
/// credential (those are [`secret_mask_spans`]'s), as entities of the first
/// entity's type and score spanning the whole raw token. `detector` is the
/// masking pass's own detector, so a token is masked under the same
/// locales, custom rules and recognizers as the plain text.
pub(crate) fn encoded_pii_entities(
    text: &str,
    tokens: &EncodedTokens,
    detector: &Detector<'_>,
) -> Vec<Entity> {
    let base64 = tokens
        .tokens
        .iter()
        .filter(|t| t.secret.is_none()) // masked as that secret
        .filter_map(|t| {
            t.layers
                .iter()
                .find_map(|layer| detector.scan(layer).entities.into_iter().next())
                .map(|e| Entity {
                    kind: e.kind,
                    start: t.start,
                    end: t.end,
                    text: text[t.start..t.end].to_owned(),
                    score: e.score,
                })
        });
    // escape-encoded PII: the line's decoded view is scanned whole (context
    // cues in neighboring words count, as in the decision view)
    let escaped = tokens.escaped.iter().flat_map(|v| {
        detector
            .scan(&v.norm)
            .entities
            .into_iter()
            .filter_map(move |e| {
                v.raw_span(e.start, e.end).map(|(start, end)| Entity {
                    kind: e.kind,
                    start,
                    end,
                    text: text[start..end].to_owned(),
                    score: e.score,
                })
            })
    });
    let mut out: Vec<Entity> = base64.chain(escaped).collect();
    // disjoint for the renderer: an escaped span inside a base64 token's
    // span (or two overlapping escape views) keeps the earlier, longer one
    out.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut kept: Vec<Entity> = Vec::with_capacity(out.len());
    for e in out {
        if kept.last().map_or(true, |last| e.start >= last.end) {
            kept.push(e);
        }
    }
    kept
}

/// The base64 candidate tokens of `text` (raw spans, decoded layer 1): those
/// of the raw text plus, for a non-ASCII text, those of its normalized view
/// mapped back through the line alignment (a token scattered with
/// zero-width characters is contiguous only there). Sorted, disjoint.
fn encoded_token_spans(text: &str) -> Vec<(usize, usize, String)> {
    use crate::guard::normalize::{align_for_scan, base64_candidate_spans, normalize_for_scan};
    let mut spans = base64_candidate_spans(text);
    // the line alignment is costly and rarely needed: compute it only when
    // the normalized view holds a candidate at all (measured: aligning every
    // non-ASCII text cost ~6% of `sanitize` on text without any base64)
    if !text.is_ascii() && !base64_candidate_spans(&normalize_for_scan(text)).is_empty() {
        let a = align_for_scan(text);
        for (s, e, decoded) in base64_candidate_spans(&a.normalized) {
            let (rs, re) = (a.start[s], a.end[e]);
            if rs < re {
                spans.push((rs, re, decoded));
            }
        }
        // sweep: keep the earliest (then longest) of overlapping tokens
        spans.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
        let mut kept: Vec<(usize, usize, String)> = Vec::with_capacity(spans.len());
        for span in spans {
            // `map_or`, not `is_none_or` (Rust 1.82, above the 1.80 MSRV)
            if kept.last().map_or(true, |last| span.0 >= last.1) {
                kept.push(span);
            }
        }
        spans = kept;
    }
    spans
}

/// Adds encoded-PII token entities ([`encoded_pii_entities`]) to `entities`:
/// a token replaces every entity it overlaps; the result stays sorted by
/// start.
pub(crate) fn add_encoded_entities(entities: &mut Vec<Entity>, encoded: Vec<Entity>) {
    if encoded.is_empty() {
        return;
    }
    entities.retain(|e| !encoded.iter().any(|t| e.start < t.end && t.start < e.end));
    entities.extend(encoded);
    entities.sort_by_key(|e| e.start);
}

/// The one masking pass behind every guard output (batch sanitize, the
/// stream segments, the ML input), on RAW coordinates: the `secrets` spans
/// become `[SECRET:VENDOR]` and win over every overlapping entity (a key is
/// never split by a PII span), then the remaining entities of `report` and
/// its incompletely scanned lines are masked with `style`. Relevance
/// partitions therefore always run on the raw text, before this pass.
fn render_masked(
    text: &str,
    secrets: &[SecretFinding],
    mut report: ScanReport,
    style: &MaskStyle,
) -> String {
    report
        .entities
        .retain(|e| !secrets.iter().any(|s| e.start < s.end && s.start < e.end));
    let spans: Vec<(usize, usize, &str)> =
        secrets.iter().map(|s| (s.start, s.end, s.vendor)).collect();
    let masked = mask_secret_spans(text, &spans, &mut report);
    style.redact_scan(&masked, &report)
}

/// The text the ML classifiers see, built the same way in batch and in
/// stream: the `secrets` spans FIRST (a credential never reaches a model),
/// then the PII `entities` with the label mask (a stable vocabulary for the
/// models, whatever the output mask style). Incompletely scanned lines are
/// NOT blanked here: that would let a line crafted to exhaust the regex
/// budget hide its content from the classifiers.
fn ml_input(text: &str, secrets: &[SecretFinding], entities: Vec<Entity>) -> String {
    let report = ScanReport {
        entities,
        engine_errors: 0,
        error_spans: Vec::new(),
    };
    render_masked(text, secrets, report, &MaskStyle::Label)
}

/// Replaces the given secret spans of `text` (sorted, non-overlapping,
/// `(start, end, vendor)` in `text` coordinates; empty or malformed spans
/// are skipped) with `[SECRET:VENDOR]` and moves the spans of `report`
/// into the rewritten text's coordinates (a span edge inside a secret
/// moves to that placeholder's edge).
fn mask_secret_spans(
    text: &str,
    spans: &[(usize, usize, &str)],
    report: &mut ScanReport,
) -> String {
    let mut out = String::with_capacity(text.len());
    // (raw start, raw end, new start, new end) of every applied span
    let mut applied: Vec<(usize, usize, usize, usize)> = Vec::new();
    let mut cursor = 0usize;
    for &(start, end, vendor) in spans {
        if start < cursor
            || start >= end
            || end > text.len()
            || !text.is_char_boundary(start)
            || !text.is_char_boundary(end)
        {
            continue;
        }
        out.push_str(&text[cursor..start]);
        let new_start = out.len();
        out.push_str("[SECRET:");
        out.push_str(vendor);
        out.push(']');
        applied.push((start, end, new_start, out.len()));
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    if applied.is_empty() {
        return out;
    }
    let map = |x: usize, is_end: bool| -> usize {
        let (mut raw_base, mut new_base) = (0usize, 0usize);
        for &(start, end, new_start, new_end) in &applied {
            if x >= end {
                raw_base = end;
                new_base = new_end;
                continue;
            }
            if x > start {
                return if is_end { new_end } else { new_start };
            }
            break;
        }
        x - raw_base + new_base
    };
    for e in &mut report.entities {
        e.start = map(e.start, false);
        e.end = map(e.end, true);
    }
    for span in &mut report.error_spans {
        *span = (map(span.0, false), map(span.1, true));
    }
    out
}

/// The `SCAN_INCOMPLETE` signal when any PII scan could not check a line
/// completely (a regex runtime error such as an exhausted backtrack budget,
/// or a normalized view that could not be aligned back to the raw text):
/// that line may hide PII the engine could not check. Score 0.4 puts it at LOG level under the
/// default policy; a `SCAN_INCOMPLETE = "low"` override blocks it. The
/// output transformations mask every such line as `[SCAN_INCOMPLETE]`.
fn scan_incomplete_signal(pii: &PiiViews) -> Option<GuardSignal> {
    (pii.engine_errors > 0).then(|| GuardSignal {
        kind: crate::guard::SignalKind::ScanIncomplete,
        score: 0.4,
        evidence: crate::guard::rules::evidence_preview(
            pii.first_incomplete_line.as_deref().unwrap_or(""),
        ),
        rationale: format!(
            "pii scan incomplete: {} scan error(s); the affected line(s) are masked as [SCAN_INCOMPLETE]",
            pii.engine_errors
        ),
    })
}

/// [`decide`] plus the relevance pass: raw-text entities matching a
/// relevance rule are excluded from the masking suggestion and reported via
/// `relevance_downgraded` (type + span, no values). Normalized-view
/// entities are partitioned against the SAME rules on the normalized text
/// (it is the same visible text; downgraded copies are dropped silently -
/// the report comes from the raw partition). Decoded-view entities are
/// passed through untouched: a cue inside an opaque encoded payload is not
/// context, it is smuggling. Never affects signal verdicts: relevance
/// only loosens the PII-driven branches (a downgraded entity is neither
/// masked nor subject to its entity action, see [`actions`]).
fn decide_with_relevance(
    text: &str,
    views: &ScanViews,
    signals: &[GuardSignal],
    pii: &PiiViews,
    policy: &Policy,
) -> Decision {
    let (masked, downgraded) = policy.relevance.partition(text, &pii.raw);
    let (keep, _) = policy
        .relevance
        .partition(views.normalized(), &pii.normalized);
    let counts = actions::tally(
        masked,
        keep,
        pii.decoded.iter().flat_map(|(_, ents)| ents),
        &policy.entity_actions,
    );
    let mut d = decide_counted(signals, counts, policy);
    d.relevance = policy.relevance.clone();
    if !downgraded.is_empty() {
        let types = unique_labels(downgraded.iter().copied());
        d.relevance_downgraded = downgraded
            .iter()
            .map(|e| DowngradedSpan {
                kind: e.kind,
                start: e.start,
                end: e.end,
            })
            .collect();
        d.rationale.push_str(&format!(
            "; relevance downgraded {} entity(ies) (contextually expected, not masked: {})",
            downgraded.len(),
            types.join(", ")
        ));
    }
    d
}

/// The deterministic guard signal set shared by every guard entry point
/// (rules are locale-independent; only L1 detection is locale-gated).
/// `views` is shared with [`collect_pii_views`] (one layered-views
/// computation per guard call); `encoded` are the precomputed
/// `ENCODED_PII` signals (see `guard::rules::encoded_pii_signals`), placed in the raw
/// text's battery.
///
/// Layer re-scanning: the FULL rule battery runs on every view that
/// differs from the raw text - the normalized view (fullwidth/zero-width
/// obfuscation must not slip the rules) and every decoded view (a
/// base64-wrapped injection attempt is the same attack as a plain one).
/// Markup-sensitive rules skip the views whose kind says so (escaped
/// markup is inert). When normalization changed nothing (normalized view
/// == text) the duplicate pass is skipped, so clean-input cost is
/// unchanged.
fn collect_guard_signals(
    text: &str,
    views: &ScanViews,
    encoded: Vec<GuardSignal>,
) -> Vec<GuardSignal> {
    let mut signals = rule_battery(text, true, encoded);
    for (kind, view) in views.all() {
        if view != text {
            let markup = kind.runs_markup_rules();
            signals.extend(rule_battery(view, markup, Vec::new()));
            // a view that skips the tag rules (escaped markup is inert)
            // still runs the script schemes: `&#106;avascript:` is live
            if !markup {
                signals.extend(crate::guard::script_scheme_risk(view));
            }
        }
    }
    // the same rule can legitimately fire on BOTH the raw text and a view
    // (e.g. SQL plus one zero-width char: the normalized view differs but
    // still contains the SQL). Duplicates add no information and would
    // double the verdict list - drop them, first occurrence wins. The
    // comparison key normalizes evidence harder than the scan pipeline
    // (invisibles stripped AND whitespace runs collapsed): the raw-view
    // copy can carry the very invisible characters that made it a separate
    // view, leaving doubled spaces after stripping.
    let mut deduped: Vec<GuardSignal> = Vec::with_capacity(signals.len());
    let mut seen: Vec<(crate::guard::SignalKind, u32, String, String)> = Vec::new();
    for s in signals.drain(..) {
        let key = (
            s.kind,
            s.score.to_bits(),
            evidence_key(&s.evidence),
            s.rationale.clone(),
        );
        if !seen.contains(&key) {
            seen.push(key);
            deduped.push(s);
        }
    }
    deduped
}

/// Comparison key for evidence deduplication: invisibles stripped,
/// whitespace runs collapsed to single spaces.
fn evidence_key(e: &str) -> String {
    crate::guard::normalize::normalize_for_scan(e)
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

/// Every deterministic rule over one text (sql, xss, url, obfuscation,
/// traversal, command/template/nosql/xxe/crlf/xpath/authority/tool
/// injection, secrets). `markup` gates the markup-sensitive rules (XSS,
/// XXE): a view whose kind does not run them skips them. `encoded`
/// (precomputed `ENCODED_PII` signals) is placed before the secrets.
fn rule_battery(text: &str, markup: bool, encoded: Vec<GuardSignal>) -> Vec<GuardSignal> {
    rule_battery_with(text, markup, encoded, Battery::FULL)
}

/// Which parts of [`rule_battery`] run. The batch decision runs all of
/// them; the streaming guard runs the window-local regex rules over a
/// bounded window and decides the three whole-text parts on its own
/// (`policy::stream` documents why each is exact).
#[derive(Debug, Clone, Copy)]
struct Battery {
    /// The character-splitting rule (`obfuscation_risk`).
    obfuscation: bool,
    /// The backtick-execution part of `command_injection_risk`.
    backtick: bool,
    /// The secret rules (`secrets_risk`).
    secrets: bool,
}

impl Battery {
    /// Every rule: the batch battery.
    const FULL: Self = Self {
        obfuscation: true,
        backtick: true,
        secrets: true,
    };

    /// The window-local rules only: the streaming guard's per-window
    /// battery.
    const WINDOW: Self = Self {
        obfuscation: false,
        backtick: false,
        secrets: false,
    };
}

/// [`rule_battery`] restricted to the `parts` that are switched on (the
/// other rules always run, in the same order).
fn rule_battery_with(
    text: &str,
    markup: bool,
    encoded: Vec<GuardSignal>,
    parts: Battery,
) -> Vec<GuardSignal> {
    type Rule = fn(&str) -> Option<GuardSignal>;
    let mut signals: Vec<GuardSignal> = Vec::new();
    let xss = if markup {
        crate::guard::xss_risk(text)
    } else {
        None
    };
    signals.extend([crate::guard::sql_risk(text), xss].into_iter().flatten());
    signals.extend(crate::guard::url_guard(text));
    if parts.obfuscation {
        if let Some(s) = crate::guard::obfuscation_risk(text) {
            signals.push(s);
        }
    }
    let command: Rule = if parts.backtick {
        crate::guard::command_injection_risk
    } else {
        crate::guard::rules::command_injection_patterns
    };
    // (rule, is a markup rule)
    let rules: [(Rule, bool); 9] = [
        (crate::guard::path_traversal_risk, false),
        (command, false),
        (crate::guard::template_injection_risk, false),
        (crate::guard::nosql_injection_risk, false),
        (crate::guard::xxe_risk, true),
        (crate::guard::crlf_injection_risk, false),
        (crate::guard::xpath_injection_risk, false),
        (crate::guard::authority_impersonation_risk, false),
        (crate::guard::tool_injection_risk, false),
    ];
    for (risk, is_markup) in rules {
        if is_markup && !markup {
            continue;
        }
        if let Some(s) = risk(text) {
            signals.push(s);
        }
    }
    signals.extend(encoded);
    // Secrets: a base64-wrapped API key is the same leak as a plain one.
    if parts.secrets {
        signals.extend(crate::guard::secrets_risk(text));
    }
    signals
}

/// The policy a guard call decides under: the caller's policy, or the
/// built-in default, adapted to the target (tool responses get the
/// stricter built-in lines: indirect injection risk is higher).
fn effective_policy(policy: Option<&Policy>, target: GuardTarget) -> Policy {
    policy.map_or_else(
        || Policy::default().for_target(&target),
        |p| p.for_target(&target),
    )
}

/// Drops the signals of `policy.disabled` categories (they are never
/// collected at all - stronger than `Threshold::None`, which only
/// suppresses the block decision).
fn retain_enabled(signals: &mut Vec<GuardSignal>, policy: &Policy) {
    if !policy.disabled.is_empty() {
        signals.retain(|sig| policy.is_enabled(signal_kind_to_category(sig.kind)));
    }
}

impl Policy {
    /// Adapts this policy to a target. `UserPrompt` and `ModelOutput` use
    /// the policy unchanged. `ToolResponse` (the indirect prompt-injection
    /// vector) is never decided more loosely than the built-in tool lines:
    ///
    /// - the global lines clamp down to block 0.5 / log 0.3;
    /// - a category override survives only when its block line is at or
    ///   below 0.5 (`Threshold::Low`); `Medium`, `High` and `None`
    ///   overrides are dropped and their category follows the clamped
    ///   global line;
    /// - [`Policy::disabled`] is not honored (every category is collected).
    ///
    /// Locales, relevance rules, custom rules, entity actions and the dry
    /// run flag carry over unchanged.
    ///
    /// # Examples
    /// ```
    /// use redactify::policy::{GuardCategory, GuardTarget, Policy, Threshold};
    ///
    /// let p = Policy::default()
    ///     .with_category(GuardCategory::DangerousUrl, Threshold::None)
    ///     .with_category(GuardCategory::Secrets, Threshold::Low);
    /// let tool = p.for_target(&GuardTarget::ToolResponse);
    /// assert_eq!(tool.block_line_for(GuardCategory::DangerousUrl), 0.5); // None dropped
    /// assert_eq!(tool.block_line_for(GuardCategory::Secrets), 0.35); // Low kept
    /// assert_eq!(p.for_target(&GuardTarget::UserPrompt), p);
    /// ```
    #[must_use]
    pub fn for_target(&self, target: &GuardTarget) -> Policy {
        match target {
            GuardTarget::ToolResponse => Policy {
                block_at: self.block_at.min(TOOL_BLOCK_AT),
                log_at: self.log_at.min(TOOL_LOG_AT),
                categories: self.categories.tool_response_lines(),
                disabled: Vec::new(),
                default_locales: self.default_locales.clone(),
                relevance: self.relevance.clone(),
                custom_rules: self.custom_rules.clone(),
                entity_actions: self.entity_actions.clone(),
                dry_run: self.dry_run,
            },
            _ => self.clone(),
        }
    }
}

/// Builds the `NER_DEGRADED` signal when any attached recognizer reports
/// [`crate::pii::NerHealth::Degraded`].
///
/// Score 0.4 puts it at LOG level under the default policy (observable in
/// every decision and audit record without blocking); deployments that
/// want a fail-closed enricher set a category override
/// (`CategoryOverrides::set(GuardCategory::NerDegraded, Threshold::Low)`
/// blocks from 0.35).
fn ner_degradation_signal(ner: &[&dyn NerRecognizer]) -> Option<GuardSignal> {
    ner.iter().find_map(|r| match r.health() {
        crate::pii::NerHealth::Degraded(reason) => Some(GuardSignal {
            kind: crate::guard::SignalKind::NerDegraded,
            score: 0.4,
            evidence: r.name().to_owned(),
            rationale: format!("ner enricher degraded: {reason}"),
        }),
        crate::pii::NerHealth::Ok => None,
    })
}

/// The result of a `sanitize` call: the decision plus the transformed text.
///
/// When the decision is `Mask`, the `text` field contains the PII-masked version.
/// When the target is `ModelOutput`, the text is additionally HTML-entity encoded
/// (OWASP LLM05 output handling). On `Block` the text keeps its PII raw
/// (only secrets are masked): the caller owns the decision and already
/// holds the original.
///
/// serde (feature `serde`): `Serialize` only (the decision is
/// Serialize-only) and log-safe: on `Block` the `text` field serializes as
/// `null`, because that text still carries raw PII. Use
/// [`Guard::mask_all`] for a loggable rendering of a blocked text.
///
/// # Examples
/// ```
/// use redactify::policy::{sanitize, GuardAction, GuardTarget, SanitizeResult};
///
/// // PII is masked
/// let r = sanitize("TCKN 12345678950 and SSN 536-90-6292", &GuardTarget::UserPrompt);
/// assert_eq!(r.decision.action, GuardAction::Mask);
/// assert!(r.text.contains("[TCKN]"));
/// assert!(!r.text.contains("12345678950"));
///
/// // clean text passes through unchanged
/// let r = sanitize("hello world", &GuardTarget::UserPrompt);
/// assert_eq!(r.text, "hello world");
///
/// // ModelOutput also HTML-encodes dangerous characters
/// let r = sanitize("math: 5 < 10 and 20 > 3", &GuardTarget::ModelOutput);
/// assert!(r.text.contains("5 &lt; 10"));
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct SanitizeResult {
    /// The policy decision (action, verdicts, rationale).
    pub decision: Decision,
    /// The transformed text: masked (PII), HTML-encoded (ModelOutput), or the original.
    pub text: String,
}

#[cfg(feature = "serde")]
impl serde::Serialize for SanitizeResult {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        // log-safe: a blocked text keeps raw PII, so it is withheld
        let text = (self.decision.action != GuardAction::Block).then_some(self.text.as_str());
        let mut s = serializer.serialize_struct("SanitizeResult", 2)?;
        s.serialize_field("decision", &self.decision)?;
        s.serialize_field("text", &text)?;
        s.end()
    }
}

/// Builds the metadata-only [`AuditRecord`](crate::guard::audit::AuditRecord)
/// for one verdict (policy-side adapter: the audit module stays free of
/// upward imports).
#[must_use]
pub fn audit_from_verdict(
    request_id: impl Into<String>,
    layer: &'static str,
    verdict: &GuardVerdict,
) -> crate::guard::audit::AuditRecord {
    crate::guard::audit::AuditRecord::from_parts(
        request_id,
        layer,
        verdict.category,
        verdict.score,
        verdict.action,
        verdict.rationale.clone(),
    )
}

/// Builds the DECISION-summary [`AuditRecord`](crate::guard::audit::AuditRecord).
///
/// A dry-run decision ([`Policy::dry_run`]) is recorded with the action
/// the policy decided ([`Decision::decided_action`]) under the guard name
/// `DRY_RUN` instead of `DECISION`, so shadow-mode records are filtered
/// apart from enforced ones; its rationale names the entity counts.
///
/// # Examples
/// ```
/// use redactify::policy::{audit_from_decision, GuardAction, Policy};
/// use redactify::{Guard, GuardTarget};
///
/// let p = Policy { dry_run: true, ..Policy::default() };
/// let d = Guard::new(GuardTarget::UserPrompt).with_policy(&p).decide("TCKN 12345678950");
/// let rec = audit_from_decision("req-1", "L0+L1", &d);
/// assert_eq!((rec.guard.as_str(), rec.action), ("DRY_RUN", GuardAction::Mask));
/// assert!(rec.rationale.contains("TCKN=MASK x1"));
/// assert!(!rec.to_json().contains("12345678950"));
/// ```
#[must_use]
pub fn audit_from_decision(
    request_id: impl Into<String>,
    layer: &'static str,
    d: &Decision,
) -> crate::guard::audit::AuditRecord {
    let mut record = crate::guard::audit::AuditRecord::decision(
        request_id,
        layer,
        d.top_signal.as_ref().map_or(0.0, |s| s.score),
        d.decided_action(),
        d.rationale.clone(),
    );
    if d.dry_run_action.is_some() {
        "DRY_RUN".clone_into(&mut record.guard);
    }
    record
}

/// Runs the full guard pipeline and returns a decision plus sanitized text.
///
/// This is the "one-call" API for LLM pipelines:
/// - `UserPrompt`: PII mask if needed; dangerous content is blocked (the text is
///   still returned with its PII raw - the caller owns the decision and must
///   check `decision.action == Block`; [`Guard::mask_all`] renders a loggable
///   copy).
/// - `ToolResponse`: same as UserPrompt but with stricter thresholds.
/// - `ModelOutput`: PII mask + HTML entity encoding (OWASP LLM05).
///
/// Detected secrets are masked on every branch (including Block): a leaked
/// credential must never survive a sanitize round trip into the caller's
/// logs.
///
/// # Examples
/// ```
/// use redactify::policy::{sanitize, GuardAction, GuardTarget};
///
/// let r = sanitize("SSN 536-90-6292", &GuardTarget::UserPrompt);
/// assert_eq!(r.decision.action, GuardAction::Mask);
/// assert_eq!(r.text, "SSN [SSN]");
///
/// // a leaked AWS key blocks AND is masked out of the returned text
/// let r = sanitize("AKIAIOSFODNN7EXAMPLE gonderiliyor", &GuardTarget::UserPrompt);
/// assert_eq!(r.decision.action, GuardAction::Block);
/// assert!(!r.text.contains("N7EXAMPLE"));
/// assert!(r.text.contains("[SECRET:AWS_ACCESS_KEY]"));
/// ```
#[must_use]
pub fn sanitize(text: &str, target: &GuardTarget) -> SanitizeResult {
    Guard::new(*target).sanitize(text)
}

/// Maps a deterministic `SignalKind` to its `GuardCategory` counterpart.
fn signal_kind_to_category(kind: crate::guard::SignalKind) -> GuardCategory {
    use crate::guard::SignalKind as SK;
    match kind {
        SK::SqlInjection => GuardCategory::SqlInjection,
        SK::Xss => GuardCategory::Xss,
        SK::DangerousUrl => GuardCategory::DangerousUrl,
        SK::Obfuscation => GuardCategory::Obfuscation,
        SK::EncodedPii => GuardCategory::EncodedPii,
        SK::PathTraversal => GuardCategory::PathTraversal,
        SK::CommandInjection => GuardCategory::CommandInjection,
        SK::TemplateInjection => GuardCategory::TemplateInjection,
        SK::NoSqlInjection => GuardCategory::NoSqlInjection,
        SK::Xxe => GuardCategory::Xxe,
        SK::CrlfInjection => GuardCategory::CrlfInjection,
        SK::XpathInjection => GuardCategory::XpathInjection,
        SK::AuthorityImpersonation => GuardCategory::AuthorityImpersonation,
        SK::ToolInjection => GuardCategory::ToolInjection,
        SK::Secrets => GuardCategory::Secrets,
        SK::NerDegraded => GuardCategory::NerDegraded,
        SK::ScanIncomplete => GuardCategory::ScanIncomplete,
        SK::MlPromptInjection => GuardCategory::PromptInjection,
        SK::MlJailbreak => GuardCategory::Jailbreak,
        SK::MlHate => GuardCategory::Hate,
        SK::MlInsult => GuardCategory::Insult,
        SK::MlSexual => GuardCategory::Sexual,
        SK::MlViolence => GuardCategory::Violence,
        SK::MlMisconduct => GuardCategory::Misconduct,
        SK::MlSelfHarm => GuardCategory::SelfHarm,
        SK::PromptLeak => GuardCategory::PromptLeak,
        SK::MlDegraded => GuardCategory::MlDegraded,
    }
}

/// The routing facts of an already-computed decision: `blocked` when the
/// action is `Block`, `has_pii` when the decision carries a masking
/// suggestion.
///
/// # Examples
/// ```
/// use redactify::guard::ml::RouteInputs;
/// use redactify::policy::guard_all;
///
/// let d = guard_all("TCKN 12345678950");
/// let inputs = RouteInputs::from(&d);
/// assert!(!inputs.blocked);
/// assert!(inputs.has_pii);
/// ```
impl From<&Decision> for crate::guard::ml::RouteInputs {
    fn from(d: &Decision) -> Self {
        Self {
            blocked: d.action == GuardAction::Block,
            has_pii: !d.mask_summary.is_empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decide, guard_all, Guard, GuardAction, GuardCategory, GuardTarget, Policy, Severity,
        Threshold,
    };
    use crate::guard::{sql_risk, GuardSignal, SignalKind};
    use crate::pii::NerRecognizer;

    #[test]
    fn block_on_high_risk() {
        let sigs = vec![sql_risk("1' OR '1'='1").unwrap()];
        let d = decide(&sigs, &[], &Policy::default());
        assert_eq!(d.action, GuardAction::Block);
        assert!(d.rationale.contains("0.90"));
    }

    #[test]
    fn strict_category_override_blocks_even_below_the_top_signal() {
        // the SECRETS=Low override must block even when a higher-scoring
        // laxer-category signal tops the list
        let secrets_sig = GuardSignal {
            kind: SignalKind::Secrets,
            score: 0.4,
            evidence: "x".into(),
            rationale: "entropy secret".into(),
        };
        let obf = GuardSignal {
            kind: SignalKind::Obfuscation,
            score: 0.5,
            evidence: "y".into(),
            rationale: "spacing trick".into(),
        };
        let strict = Policy::default().with_category(GuardCategory::Secrets, Threshold::Low);
        let d = decide(&[obf.clone(), secrets_sig.clone()], &[], &strict);
        assert_eq!(d.action, GuardAction::Block, "rationale: {}", d.rationale);
        // without the override: top (0.5) only logs, secrets 0.4 stays quiet
        let d = decide(&[obf, secrets_sig], &[], &Policy::default());
        assert_eq!(d.action, GuardAction::Log);
    }

    #[test]
    fn log_on_low_risk() {
        let sigs = vec![sql_risk("a' or 'b").unwrap()];
        let d = decide(&sigs, &[], &Policy::default());
        assert_eq!(d.action, GuardAction::Log);
    }

    #[test]
    fn block_on_medium_with_strict_policy() {
        let sigs = vec![sql_risk("SELECT 1; -- comment").unwrap()]; // 0.6
        let strict = Policy {
            block_at: 0.5,
            log_at: 0.3,
            ..Policy::default()
        };
        assert_eq!(decide(&sigs, &[], &strict).action, GuardAction::Block);
    }

    #[test]
    fn allow_when_clean() {
        let d = decide(&[], &[], &Policy::default());
        assert_eq!(d.action, GuardAction::Allow);
        assert_eq!(d.rationale, "no signals and no PII");
    }

    #[test]
    fn mask_when_only_pii() {
        let pii = crate::detect("TCKN 12345678950");
        let d = decide(&[], &pii, &Policy::default());
        assert_eq!(d.action, GuardAction::Mask);
        assert_eq!(d.mask_summary, vec!["TCKN"]);
    }

    #[test]
    fn category_override_high_raises_the_bar() {
        // SQL signature at 0.7: globally blocks (>= 0.6), with High band it
        // only logs (0.7 < 0.85) - "selected band and above blocks"
        let sigs = vec![GuardSignal {
            kind: SignalKind::SqlInjection,
            score: 0.7,
            evidence: "x".into(),
            rationale: "test".into(),
        }];
        let p = Policy::default().with_category(GuardCategory::SqlInjection, Threshold::High);
        let d = decide(&sigs, &[], &p);
        assert_eq!(d.action, GuardAction::Log);
        assert_eq!(d.verdicts[0].action, GuardAction::Log);
        // same signal at 0.9 crosses the High band -> Block
        let strong = vec![GuardSignal {
            score: 0.9,
            ..sigs[0].clone()
        }];
        assert_eq!(decide(&strong, &[], &p).action, GuardAction::Block);
    }

    #[test]
    fn category_override_none_never_blocks() {
        let sigs = vec![GuardSignal {
            kind: SignalKind::DangerousUrl,
            score: 0.95,
            evidence: "u".into(),
            rationale: "test".into(),
        }];
        let p = Policy::default().with_category(GuardCategory::DangerousUrl, Threshold::None);
        let d = decide(&sigs, &[], &p);
        assert_ne!(d.action, GuardAction::Block, "None must never block");
        assert_eq!(d.verdicts[0].action, GuardAction::Log); // 0.95 >= log_at
    }

    #[test]
    fn category_override_low_blocks_below_global_line() {
        // EncodedPii at 0.4: below global block 0.6 (-> Log), but the Low band
        // (>= 0.35) blocks it once the override is set
        let sigs = vec![GuardSignal {
            kind: SignalKind::EncodedPii,
            score: 0.4,
            evidence: "b64".into(),
            rationale: "test".into(),
        }];
        let d = decide(&sigs, &[], &Policy::default());
        assert_eq!(d.action, GuardAction::Log);
        let p = Policy::default().with_category(GuardCategory::EncodedPii, Threshold::Low);
        assert_eq!(decide(&sigs, &[], &p).action, GuardAction::Block);
    }

    #[test]
    fn overrides_are_isolated_per_category() {
        let p = Policy::default()
            .with_category(GuardCategory::SqlInjection, Threshold::High)
            .with_category(GuardCategory::Xss, Threshold::Low);
        assert_eq!(p.block_line_for(GuardCategory::SqlInjection), 0.85);
        assert_eq!(p.block_line_for(GuardCategory::Xss), 0.35);
        assert_eq!(p.block_line_for(GuardCategory::Xxe), 0.6); // untouched -> global
                                                               // replacing an override updates, not appends
        let p = p.with_category(GuardCategory::Xss, Threshold::High);
        assert_eq!(p.categories.len(), 2);
    }

    #[test]
    fn from_cutoff_maps_all_bands() {
        assert_eq!(super::Threshold::from_cutoff(0.10), super::Threshold::Low);
        assert_eq!(super::Threshold::from_cutoff(0.35), super::Threshold::Low);
        assert_eq!(
            super::Threshold::from_cutoff(0.599),
            super::Threshold::Low // Medium starts AT 0.60
        );
        assert_eq!(
            super::Threshold::from_cutoff(0.60),
            super::Threshold::Medium
        );
        assert_eq!(
            super::Threshold::from_cutoff(0.849),
            super::Threshold::Medium
        );
        assert_eq!(super::Threshold::from_cutoff(0.85), super::Threshold::High);
        assert_eq!(super::Threshold::from_cutoff(0.99), super::Threshold::High);
    }

    #[test]
    fn category_overrides_empty_and_len() {
        let o = super::CategoryOverrides::default();
        assert!(o.is_empty());
        assert_eq!(o.len(), 0);
        let mut o = super::CategoryOverrides::default();
        o.set(GuardCategory::Xss, super::Threshold::High);
        assert!(!o.is_empty());
        assert_eq!(o.len(), 1);
    }

    #[test]
    fn threshold_bands_agree_with_severity() {
        // The block edge of each band equals that severity band's lower
        // edge (a score inside the band blocks when that band is selected)
        assert_eq!(Threshold::Low.block_score(), 0.35);
        assert_eq!(Threshold::Medium.block_score(), 0.60);
        assert_eq!(Threshold::High.block_score(), 0.85);
        assert_eq!(Severity::from_score(0.35), Severity::Low);
        assert_eq!(Severity::from_score(0.60), Severity::Medium);
        assert_eq!(Severity::from_score(0.85), Severity::High);
    }

    #[test]
    fn custom_thresholds() {
        let sigs = vec![GuardSignal {
            kind: SignalKind::Xss,
            score: 0.5,
            evidence: "x".into(),
            rationale: "test".into(),
        }];
        let strict = Policy {
            block_at: 0.4,
            log_at: 0.2,
            ..Policy::default()
        };
        assert_eq!(decide(&sigs, &[], &strict).action, GuardAction::Block);
        let loose = Policy {
            block_at: 0.9,
            log_at: 0.45,
            ..Policy::default()
        };
        assert_eq!(decide(&sigs, &[], &loose).action, GuardAction::Log);
    }

    #[test]
    fn guard_all_end_to_end() {
        assert_eq!(
            guard_all("http://169.254.169.254/meta").action,
            GuardAction::Block
        );
        assert_eq!(guard_all("merhaba dunya").action, GuardAction::Allow);
        assert_eq!(guard_all("TCKN 12345678950").action, GuardAction::Mask);
        let d = guard_all("govde: a2ltbGlrIDEyMzQ1Njc4OTUw");
        assert_eq!(d.action, GuardAction::Mask);
        assert!(d.mask_summary.contains(&"TCKN"));
    }

    // ------------------------------------------------ severity banding

    #[test]
    fn severity_bands_are_correct() {
        assert_eq!(Severity::from_score(0.0), Severity::Safe);
        assert_eq!(Severity::from_score(0.34), Severity::Safe);
        assert_eq!(Severity::from_score(0.35), Severity::Low);
        assert_eq!(Severity::from_score(0.59), Severity::Low);
        assert_eq!(Severity::from_score(0.60), Severity::Medium);
        assert_eq!(Severity::from_score(0.84), Severity::Medium);
        assert_eq!(Severity::from_score(0.85), Severity::High);
        assert_eq!(Severity::from_score(1.0), Severity::High);
    }

    #[test]
    fn severity_labels() {
        assert_eq!(Severity::Safe.as_str(), "SAFE");
        assert_eq!(Severity::Low.as_str(), "LOW");
        assert_eq!(Severity::Medium.as_str(), "MEDIUM");
        assert_eq!(Severity::High.as_str(), "HIGH");
    }

    #[test]
    fn verdicts_have_category_and_severity() {
        let sigs = vec![sql_risk("1' OR '1'='1").unwrap()];
        let d = decide(&sigs, &[], &Policy::default());
        assert_eq!(d.verdicts.len(), 1);
        assert_eq!(d.verdicts[0].category, GuardCategory::SqlInjection);
        assert_eq!(d.verdicts[0].severity, Severity::High);
        assert_eq!(d.verdicts[0].action, GuardAction::Block);
    }

    // ------------------------------------------------ target-specific

    #[test]
    fn tool_response_is_stricter() {
        // a mid-level signal that passes at default but blocks for tool responses
        let text = "SELECT a; -- comment"; // SQL comment marker: 0.6
        let user = Guard::new(GuardTarget::UserPrompt).decide(text);
        let tool = Guard::new(GuardTarget::ToolResponse).decide(text);
        // default: block_at 0.6, tool: block_at 0.5
        assert_eq!(user.action, GuardAction::Block); // 0.6 >= 0.6
        assert_eq!(tool.action, GuardAction::Block); // 0.6 >= 0.5 (also blocks, stricter threshold)
    }

    #[test]
    fn tool_response_blocks_lower_score() {
        // construct a signal at 0.55: passes default log_at (0.4) but is below
        // default block_at (0.6); tool policy blocks at 0.5 so it blocks there
        let sigs = vec![GuardSignal {
            kind: SignalKind::Xss,
            score: 0.55,
            evidence: "test".into(),
            rationale: "synthetic".into(),
        }];
        let default_d = decide(&sigs, &[], &Policy::default());
        assert_eq!(default_d.action, GuardAction::Log); // 0.55 >= 0.4, < 0.6
        let tool_d = decide(
            &sigs,
            &[],
            &Policy {
                block_at: 0.5,
                log_at: 0.3,
                ..Policy::default()
            },
        );
        assert_eq!(tool_d.action, GuardAction::Block); // 0.55 >= 0.5
    }

    // ------------------------------------------------ sanitize API

    #[test]
    fn sanitize_masks_pii_in_user_prompt() {
        let r = super::sanitize("TCKN 12345678950", &GuardTarget::UserPrompt);
        assert_eq!(r.decision.action, GuardAction::Mask);
        assert!(r.text.contains("[TCKN]"));
        assert!(!r.text.contains("12345678950"));
    }

    #[test]
    fn sanitize_passes_clean_text_through() {
        let r = super::sanitize("hello world", &GuardTarget::UserPrompt);
        assert_eq!(r.decision.action, GuardAction::Allow);
        assert_eq!(r.text, "hello world");
    }

    #[test]
    fn sanitize_html_encodes_model_output() {
        // use text with HTML-sensitive chars that does NOT trigger the XSS
        // signature rules (no script/iframe/event-handler tags)
        let r = super::sanitize("compare: a < b and c > d", &GuardTarget::ModelOutput);
        assert!(r.text.contains("a &lt; b"), "encoded: {}", r.text);
        assert!(r.text.contains("c &gt; d"), "encoded: {}", r.text);
    }

    #[test]
    fn sanitize_masks_and_encodes_model_output() {
        let r = super::sanitize("TCKN 12345678950 <b>bold</b>", &GuardTarget::ModelOutput);
        assert!(r.text.contains("[TCKN]"), "PII masked: {}", r.text);
        assert!(r.text.contains("&lt;b&gt;"), "HTML encoded: {}", r.text);
    }

    #[test]
    fn sanitize_block_returns_original_text() {
        let r = super::sanitize("http://169.254.169.254/meta", &GuardTarget::UserPrompt);
        assert_eq!(r.decision.action, GuardAction::Block);
        // text is still returned (caller decides what to do); it is NOT encoded
        assert_eq!(r.text, "http://169.254.169.254/meta");
    }

    #[test]
    fn sanitize_cross_locale() {
        let r = super::sanitize(
            "SSN 536-90-6292 ve TCKN 12345678950",
            &GuardTarget::UserPrompt,
        );
        assert!(r.text.contains("[SSN]"));
        assert!(r.text.contains("[TCKN]"));
    }

    // ------------------------------------------------ guard with ML classifiers

    #[test]
    fn disabled_categories_silence_ml_signals_too() {
        // the disabled filter applies to the ML re-decide too, not only
        // to the deterministic set
        use crate::guard::ml::{MlRouter, MockSecurityClassifier};
        let sec = MockSecurityClassifier::new();
        let router = MlRouter::default();
        let policy = Policy {
            disabled: vec![GuardCategory::PromptInjection],
            ..Policy::default()
        };
        let d = Guard::new(GuardTarget::UserPrompt)
            .with_policy(&policy)
            .with_ml(router, Some(&sec), None)
            .decide("explain how jailbreak attacks work");
        assert!(
            !d.signals
                .iter()
                .any(|s| s.kind == crate::guard::SignalKind::MlPromptInjection),
            "disabled ML category must not survive the re-decide: {:?}",
            d.signals
        );
    }

    const THRESHOLDS: [Threshold; 4] = [
        Threshold::None,
        Threshold::Low,
        Threshold::Medium,
        Threshold::High,
    ];

    #[test]
    fn tool_response_never_decides_a_category_above_the_tool_line() {
        // invariant over every band x every category x global lines from
        // strict to loose: on ToolResponse no category blocks above 0.5
        for block_at in [0.2, 0.5, 0.6, 0.9, 1.0] {
            for cat in GuardCategory::ALL {
                for threshold in THRESHOLDS {
                    let p = Policy {
                        block_at,
                        log_at: 0.1,
                        ..Policy::default()
                    }
                    .with_category(*cat, threshold);
                    let line = p
                        .for_target(&GuardTarget::ToolResponse)
                        .block_line_for(*cat);
                    assert!(
                        line <= 0.5,
                        "{cat:?} {threshold:?} block_at {block_at}: tool line {line}"
                    );
                    // a stricter (Low) override is kept as is; looser ones
                    // fall back to the clamped global line
                    let expected = if threshold == Threshold::Low {
                        0.35
                    } else {
                        block_at.min(0.5)
                    };
                    assert_eq!(line, expected, "{cat:?} {threshold:?} {block_at}");
                }
            }
        }
    }

    #[test]
    fn tool_response_ignores_disabled_categories() {
        let p = Policy {
            disabled: GuardCategory::ALL.to_vec(),
            ..Policy::default()
        };
        assert!(p.for_target(&GuardTarget::ToolResponse).disabled.is_empty());
        // the other targets keep the list
        assert_eq!(p.for_target(&GuardTarget::UserPrompt).disabled, p.disabled);
        assert_eq!(p.for_target(&GuardTarget::ModelOutput).disabled, p.disabled);
    }

    #[test]
    fn tool_response_blocks_a_private_url_despite_loosening_config() {
        let text = "http://10.0.0.5/x";
        let none = Policy::default().with_category(GuardCategory::DangerousUrl, Threshold::None);
        let disabled = Policy {
            disabled: vec![GuardCategory::DangerousUrl],
            ..Policy::default()
        };
        for policy in [&none, &disabled] {
            let tool = Guard::new(GuardTarget::ToolResponse)
                .with_policy(policy)
                .decide(text);
            assert_eq!(tool.action, GuardAction::Block, "{}", tool.rationale);
            // the same configuration does loosen the user-prompt target
            let user = Guard::new(GuardTarget::UserPrompt)
                .with_policy(policy)
                .decide(text);
            assert_ne!(user.action, GuardAction::Block, "{}", user.rationale);
        }
    }

    #[test]
    fn ml_guard_clean_text_same_as_without() {
        use crate::guard::ml::{MlRouter, MockSafetyClassifier, MockSecurityClassifier};
        let sec = MockSecurityClassifier::new();
        let saf = MockSafetyClassifier::new();
        let router = MlRouter::default();
        let d = Guard::new(GuardTarget::UserPrompt)
            .with_ml(router, Some(&sec), Some(&saf))
            .decide("hello world");
        assert_eq!(d.action, GuardAction::Allow);
    }

    #[test]
    fn ml_guard_injection_fires() {
        use crate::guard::ml::{MlRouter, MockSecurityClassifier};
        let sec = MockSecurityClassifier::new();
        let router = MlRouter::default();
        // "jailbreak" fires the MOCK but not the deterministic L0 layer
        // (L0's tool-injection rule matches the imperative override forms;
        // those would short-circuit ML via the router's Block skip)
        let d = Guard::new(GuardTarget::UserPrompt)
            .with_ml(router, Some(&sec), None)
            .decide("explain how jailbreak attacks work");
        assert!(!d.verdicts.is_empty(), "ML should produce verdicts: {d:?}");
        assert!(
            d.verdicts.iter().any(|v| v.score >= 0.88),
            "high score expected: {d:?}"
        );
    }

    #[test]
    fn ml_guard_l0_block_skips_ml() {
        use crate::guard::ml::{MlRouter, MockSecurityClassifier};
        let sec = MockSecurityClassifier::new();
        let router = MlRouter::default();
        // L0 blocks this URL; ML should be skipped
        let d = Guard::new(GuardTarget::UserPrompt)
            .with_ml(router, Some(&sec), None)
            .decide("http://169.254.169.254/meta");
        assert_eq!(d.action, GuardAction::Block);
        // no ML verdicts should be present (ML was skipped)
        assert!(
            d.verdicts
                .iter()
                .all(|v| !v.rationale.contains("mock-security")),
            "ML should be skipped on L0 Block: {d:?}"
        );
    }

    #[test]
    fn ml_guard_without_classifiers_behaves_like_the_deterministic_guard() {
        use crate::guard::ml::MlRouter;
        let router = MlRouter::default();
        let d = Guard::new(GuardTarget::UserPrompt)
            .with_ml(router, None, None)
            .decide("hello");
        assert_eq!(d.action, GuardAction::Allow);
    }

    /// Records every text it is asked to classify (pipeline-privacy probe).
    struct SpyClassifier {
        seen: std::sync::Mutex<Vec<String>>,
    }

    impl crate::guard::ml::MlClassifier for SpyClassifier {
        fn classify(&self, text: &str) -> Vec<(GuardCategory, f32)> {
            self.seen.lock().unwrap().push(text.to_owned());
            Vec::new()
        }
        fn name(&self) -> &'static str {
            "spy"
        }
    }

    #[test]
    fn ml_guard_never_shows_raw_pii_to_classifiers() {
        use crate::guard::ml::MlRouter;
        let router = MlRouter::default();
        let spy = SpyClassifier {
            seen: std::sync::Mutex::new(Vec::new()),
        };
        // "jailbreak" vocabulary fires neither the deterministic L0 layer
        // nor any rule - the Spy runs and its masking is what we assert
        let text = "TCKN 12345678950 ile jailbreak analizi";
        let d = Guard::new(GuardTarget::UserPrompt)
            .with_ml(router, Some(&spy), Some(&spy))
            .decide(text);
        // L1 found PII -> decision carries a mask suggestion
        assert!(!d.mask_summary.is_empty());
        // the classifier ran (L0 allowed) and saw MASKED text only
        let seen = spy.seen.lock().unwrap().clone();
        assert!(!seen.is_empty(), "classifier should have been invoked");
        for t in &seen {
            assert!(!t.contains("12345678950"), "raw TCKN leaked to ML: {t}");
            assert!(t.contains("[TCKN]"), "masked text expected, got: {t}");
            // the non-rule vocabulary survives masking (detection unaffected)
            assert!(t.contains("jailbreak"));
        }
    }

    #[test]
    fn ml_guard_shows_raw_text_when_no_pii() {
        use crate::guard::ml::MlRouter;
        let router = MlRouter::default();
        let spy = SpyClassifier {
            seen: std::sync::Mutex::new(Vec::new()),
        };
        let d = Guard::new(GuardTarget::UserPrompt)
            .with_ml(router, Some(&spy), None)
            .decide("just a normal sentence");
        assert_eq!(d.action, GuardAction::Allow);
        let seen = spy.seen.lock().unwrap().clone();
        assert_eq!(seen, vec!["just a normal sentence".to_owned()]);
    }

    #[test]
    fn ml_guard_with_ner_never_shows_raw_name_to_classifiers() {
        use crate::guard::ml::MlRouter;
        use crate::MockNameRecognizer;
        let router = MlRouter::default();
        let spy = SpyClassifier {
            seen: std::sync::Mutex::new(Vec::new()),
        };
        let ner = MockNameRecognizer::new();
        let rec = [&ner as &dyn NerRecognizer];
        // free prose: only the NER layer finds the name; "jailbreak"
        // vocabulary stays silent in L0 so the Spy actually runs
        let text = "Bugün toplantıda Ahmet Yılmaz konuştu ve jailbreak analizi";
        let d = Guard::new(GuardTarget::UserPrompt)
            .with_ner(&rec)
            .with_ml(router, Some(&spy), Some(&spy))
            .decide(text);
        assert_eq!(d.action, GuardAction::Mask);
        assert_eq!(d.mask_summary, vec!["NAME"]);
        let seen = spy.seen.lock().unwrap().clone();
        assert!(!seen.is_empty(), "classifier should have been invoked");
        for t in &seen {
            assert!(!t.contains("Ahmet Yılmaz"), "raw name leaked to ML: {t}");
            assert!(t.contains("[NAME]"), "masked text expected, got: {t}");
            // the non-rule vocabulary survives masking (detection unaffected)
            assert!(t.contains("jailbreak"));
        }
    }

    #[test]
    fn ner_sanitize_masks_free_prose_name() {
        use crate::MockNameRecognizer;
        let ner = MockNameRecognizer::new();
        let rec = [&ner as &dyn NerRecognizer];
        let r = Guard::new(GuardTarget::UserPrompt)
            .with_ner(&rec)
            .sanitize("Bugün toplantıda Ahmet Yılmaz konuştu.");
        assert_eq!(r.decision.action, GuardAction::Mask);
        assert_eq!(r.text, "Bugün toplantıda [NAME] konuştu.");
    }

    #[test]
    fn ner_sanitize_respects_precomputed_decision() {
        use crate::MockNameRecognizer;
        let ner = MockNameRecognizer::new();
        let rec = [&ner as &dyn NerRecognizer];
        let guard = Guard::new(GuardTarget::UserPrompt).with_ner(&rec);
        let d = guard.decide("Ahmet Yılmaz arayacak.");
        let r = guard.sanitize_with_decision("Ahmet Yılmaz arayacak.", d);
        assert_eq!(r.text, "[NAME] arayacak.");
    }

    #[test]
    fn every_category_maps_to_a_signal_and_back() {
        use crate::guard::ml::ml_signal;
        // the two directions are separate exhaustive matches; this keeps
        // them inverse to each other
        for &category in GuardCategory::ALL {
            let kind = ml_signal("x", category, 0.5).kind;
            assert_eq!(super::signal_kind_to_category(kind), category, "{kind:?}");
        }
    }

    #[test]
    fn scan_incomplete_maps_both_ways() {
        use crate::guard::ml::ml_signal;
        assert_eq!(
            super::signal_kind_to_category(SignalKind::ScanIncomplete),
            GuardCategory::ScanIncomplete
        );
        assert_eq!(
            ml_signal("x", GuardCategory::ScanIncomplete, 0.4).kind,
            SignalKind::ScanIncomplete
        );
        assert_eq!(SignalKind::ScanIncomplete.as_str(), "SCAN_INCOMPLETE");
    }

    #[test]
    fn builtin_effective_policy_matches_the_historical_target_defaults() {
        // the former per-target default: ToolResponse 0.5/0.3, else default
        let tool = Policy {
            block_at: 0.5,
            log_at: 0.3,
            ..Policy::default()
        };
        assert_eq!(
            super::effective_policy(None, GuardTarget::ToolResponse),
            tool
        );
        assert_eq!(
            super::effective_policy(None, GuardTarget::UserPrompt),
            Policy::default()
        );
        assert_eq!(
            super::effective_policy(None, GuardTarget::ModelOutput),
            Policy::default()
        );
        let strict = Policy::default().with_category(GuardCategory::Xss, Threshold::Low);
        assert_eq!(
            super::effective_policy(Some(&strict), GuardTarget::ToolResponse),
            strict.for_target(&GuardTarget::ToolResponse)
        );
    }

    #[test]
    fn route_inputs_carry_the_block_and_pii_facts_of_a_decision() {
        use crate::guard::ml::RouteInputs;
        for (text, blocked, has_pii) in [
            ("hello", false, false),
            ("TCKN 12345678950", false, true),
            // the link-local address is also an IP_ADDRESS finding
            ("http://169.254.169.254/meta", true, true),
        ] {
            let d = guard_all(text);
            let inputs = RouteInputs::from(&d);
            assert_eq!(inputs.blocked, d.action == GuardAction::Block, "{text}");
            assert_eq!(inputs.has_pii, !d.mask_summary.is_empty(), "{text}");
            assert_eq!(inputs, RouteInputs { blocked, has_pii }, "{text}");
        }
    }

    #[test]
    fn ner_name_loses_overlap_against_structural_entity() {
        use crate::MockNameRecognizer;
        // the mock claims "Ahmet Yılmaz" (free prose) while the rules claim
        // the e-mail; both coexist because they do not overlap. A TCKN
        // inside a name span would win by priority - covered in
        // pii::detect tests; here we verify the guard path stays consistent.
        let ner = MockNameRecognizer::new();
        let rec = [&ner as &dyn NerRecognizer];
        let d = Guard::new(GuardTarget::UserPrompt)
            .with_ner(&rec)
            .decide("Ahmet Yılmaz'in mail a@b.com ve TCKN 12345678950");
        assert_eq!(d.action, GuardAction::Mask);
        assert!(d.mask_summary.contains(&"NAME"), "{:?}", d.mask_summary);
        assert!(d.mask_summary.contains(&"EMAIL"), "{:?}", d.mask_summary);
        assert!(d.mask_summary.contains(&"TCKN"), "{:?}", d.mask_summary);
    }
}
