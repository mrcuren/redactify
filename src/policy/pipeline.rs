//! The guard builder: ONE configurable entry point for the full decision
//! pipeline (deterministic rules, PII detection, optional ML classifiers,
//! policy) and the output transformation.
//!
//! [`Guard`] collects every guard option (target, policy, locales, NER
//! recognizers, ML classifiers, mask style) in one builder.

use std::fmt;

use super::detector::Detector;
use super::mask::MaskStyle;
use super::{
    add_encoded_entities, collect_guard_signals, collect_pii_views, decide_with_relevance,
    effective_locales, effective_policy, encoded_pii_entities, encoded_tokens, ml_input,
    ner_degradation_signal, render_masked, retain_enabled, scan_incomplete_signal,
    secret_mask_spans_with, Decision, EntityAction, GuardAction, GuardTarget, PiiViews, Policy,
    SanitizeResult, ScanReport,
};
use crate::guard::classifier::Role;
use crate::guard::leak::PromptIndex;
use crate::guard::ml::{MlCall, MlClassifier, MlRouter, RouteInputs};
use crate::guard::normalize::{ScanViews, DECODE_DEPTH};
use crate::guard::GuardSignal;
use crate::pii::{CustomRule, NerRecognizer};

/// Configurable guard pipeline (builder).
///
/// Every setter consumes and returns the builder; a terminal method
/// ([`decide`](Self::decide), [`sanitize`](Self::sanitize),
/// [`sanitize_with_decision`](Self::sanitize_with_decision),
/// [`mask_all`](Self::mask_all)) runs the pipeline. A `Guard` borrows its
/// inputs and is cheap to clone.
///
/// Without ML classifiers the pipeline is the deterministic core:
/// L0 rules on the raw text and every scan view, L1 PII detection
/// (locale packs + NER), relevance, one policy decision. With classifiers
/// attached ([`with_ml`](Self::with_ml)) the router may add L2/L3 signals;
/// the classifiers only ever see PII-masked text.
///
/// `Debug` prints the recognizer and classifier NAMES, not the objects.
///
/// # Examples
/// ```
/// use redactify::{Guard, GuardAction, GuardTarget};
///
/// let guard = Guard::new(GuardTarget::UserPrompt);
/// assert_eq!(guard.decide("bkz: http://169.254.169.254/meta").action, GuardAction::Block);
///
/// let r = guard.sanitize("TCKN 12345678950 and SSN 536-90-6292");
/// assert_eq!(r.decision.action, GuardAction::Mask);
/// assert_eq!(r.text, "TCKN [TCKN] and SSN [SSN]");
/// ```
#[derive(Clone)]
#[must_use = "a Guard does nothing until decide/sanitize runs"]
pub struct Guard<'a> {
    /// Where the text comes from (selects target-specific strictness).
    target: GuardTarget,
    /// Caller policy (`None` = the built-in default for the target).
    policy: Option<&'a Policy>,
    /// Explicit locale codes (empty = the policy's default locales, else
    /// the default tr+en set).
    locales: &'a [&'a str],
    /// The effective locale list (`policy::effective_locales` of the
    /// explicit list and the policy), recomputed whenever either changes.
    resolved_locales: Vec<&'a str>,
    /// The policy's `Ignore` entity types (recomputed with the policy),
    /// dropped by every detector of this guard.
    ignored_types: Vec<crate::EntityType>,
    /// NER recognizers (L1 enrichment).
    ner: &'a [&'a dyn NerRecognizer],
    /// Caller-supplied context texts (see [`Guard::with_context`]).
    context: &'a [&'a str],
    /// Custom rules (see [`Guard::with_custom_rules`]).
    custom: &'a [&'a CustomRule],
    /// Allowlisted values (see [`Guard::with_ignored`]).
    ignored: &'a [&'a str],
    /// Which ML classifiers run (only consulted when one is attached).
    router: MlRouter,
    /// L2 security classifier.
    security: Option<&'a dyn MlClassifier>,
    /// L3 safety classifier.
    safety: Option<&'a dyn MlClassifier>,
    /// How masked output renders PII spans.
    mask: MaskStyle,
    /// The indexed system prompt of the output-side leak check (see
    /// [`Guard::with_system_prompt`]).
    leak: Option<PromptIndex>,
}

impl<'a> Guard<'a> {
    /// A guard for `target` with the defaults: the built-in policy for the
    /// target, the tr+en locale set, no recognizers, no ML classifiers,
    /// [`MaskStyle::Label`].
    ///
    /// # Examples
    /// ```
    /// use redactify::{Guard, GuardAction, GuardTarget};
    ///
    /// let d = Guard::new(GuardTarget::ToolResponse).decide("http://169.254.169.254/meta");
    /// assert_eq!(d.action, GuardAction::Block);
    /// ```
    pub fn new(target: GuardTarget) -> Self {
        Self {
            target,
            policy: None,
            locales: &[],
            resolved_locales: Vec::new(),
            ignored_types: Vec::new(),
            ner: &[],
            context: &[],
            custom: &[],
            ignored: &[],
            router: MlRouter::default(),
            security: None,
            safety: None,
            mask: MaskStyle::Label,
            leak: None,
        }
    }

    /// Decides under a caller-supplied policy (`None` restores the
    /// built-in default). `ToolResponse` never gets looser than the
    /// built-in tool strictness (see [`Policy::for_target`]). The policy's
    /// [`default_locales`](Policy::default_locales) apply whenever no
    /// explicit locales are set (see [`with_locales`](Self::with_locales)).
    ///
    /// # Examples
    /// ```
    /// use redactify::{Guard, GuardAction, GuardTarget, Policy};
    ///
    /// // a 0.55 obfuscation signal only logs under the default policy...
    /// let text = "kural: d r o p t a b l e kullanicilar";
    /// let guard = Guard::new(GuardTarget::UserPrompt);
    /// assert_ne!(guard.decide(text).action, GuardAction::Block);
    /// // ...but blocks under a tightened one
    /// let strict = Policy { block_at: 0.5, log_at: 0.3, ..Policy::default() };
    /// assert_eq!(guard.with_policy(&strict).decide(text).action, GuardAction::Block);
    /// ```
    pub fn with_policy(mut self, policy: impl Into<Option<&'a Policy>>) -> Self {
        self.policy = policy.into();
        self.resolved_locales = effective_locales(self.locales, self.policy);
        self.ignored_types = self
            .policy
            .map(|p| p.entity_actions.ignored_types())
            .unwrap_or_default();
        self
    }

    /// Runs the rules of these locale packs in L1 detection and masking.
    /// Effective locales: this explicit list when non-empty, else the
    /// policy's [`default_locales`](Policy::default_locales), else the
    /// default tr+en set.
    ///
    /// # Examples
    /// ```
    /// use redactify::{Guard, GuardAction, GuardTarget, Policy};
    ///
    /// let guard = Guard::new(GuardTarget::UserPrompt);
    /// assert_eq!(guard.decide("nhs 9434765870").action, GuardAction::Allow);
    /// let uk = guard.clone().with_locales(&["uk"]);
    /// assert_eq!(uk.decide("nhs 9434765870").action, GuardAction::Mask);
    /// assert_eq!(uk.sanitize("nhs 9434765870").text, "nhs [UK_NHS]");
    ///
    /// // the same pack selected through the policy's default locales
    /// let policy = Policy { default_locales: vec!["uk".into()], ..Policy::default() };
    /// let r = guard.with_policy(&policy).sanitize("nhs 9434765870");
    /// assert_eq!(r.text, "nhs [UK_NHS]");
    /// ```
    pub fn with_locales(mut self, locales: &'a [&'a str]) -> Self {
        self.locales = locales;
        self.resolved_locales = effective_locales(self.locales, self.policy);
        self
    }

    /// Adds NER recognizers to L1 detection: free-prose names join the
    /// PII findings, drive the Mask action and are masked in the output.
    /// A recognizer reporting degraded health adds a `NER_DEGRADED` signal.
    ///
    /// # Examples
    /// ```
    /// use redactify::{Guard, GuardAction, GuardTarget, MockNameRecognizer, NerRecognizer};
    ///
    /// let ner = MockNameRecognizer::new();
    /// let rec = [&ner as &dyn NerRecognizer];
    /// let r = Guard::new(GuardTarget::UserPrompt)
    ///     .with_ner(&rec)
    ///     .sanitize("we met Ahmet Yilmaz yesterday.");
    /// assert_eq!(r.decision.action, GuardAction::Mask);
    /// assert_eq!(r.text, "we met [NAME] yesterday.");
    /// ```
    pub fn with_ner(mut self, ner: &'a [&'a dyn NerRecognizer]) -> Self {
        self.ner = ner;
        self
    }

    /// Context texts the guarded text answers (the previous turn of a
    /// conversation): their cues unlock cue-gated identifiers in every
    /// PII pass of this guard, as [`Detector::with_context`] describes.
    ///
    /// # Examples
    /// ```
    /// use redactify::{Guard, GuardAction, GuardTarget};
    ///
    /// let turn = ["Vergi numaranizi yazar misiniz?"];
    /// let r = Guard::new(GuardTarget::UserPrompt).with_context(&turn).sanitize("1234567890");
    /// assert_eq!(r.decision.action, GuardAction::Mask);
    /// assert_eq!(r.text, "[VKN]");
    /// ```
    pub fn with_context(mut self, texts: &'a [&'a str]) -> Self {
        self.context = texts;
        self
    }

    /// Custom rules joining every PII pass of this guard: the decision,
    /// the PII it reports and the masks it applies (see
    /// [`Detector::with_custom_rules`]).
    ///
    /// # Examples
    /// ```
    /// use redactify::{CustomRule, EntityType, Guard, GuardAction, GuardTarget};
    ///
    /// let staff = EntityType::custom("STAFF_ID").unwrap();
    /// let rule = CustomRule::new(staff, r"\bE\d{6}\b").unwrap();
    /// let rules = [&rule];
    /// let r = Guard::new(GuardTarget::UserPrompt).with_custom_rules(&rules).sanitize("E123456");
    /// assert_eq!(r.decision.action, GuardAction::Mask);
    /// assert_eq!(r.text, "[STAFF_ID]");
    /// ```
    pub fn with_custom_rules(mut self, rules: &'a [&'a CustomRule]) -> Self {
        self.custom = rules;
        self
    }

    /// Allowlisted values for every PII pass of this guard (see
    /// [`Detector::with_ignored`]): an allowlisted value is neither
    /// reported nor masked, and does not drive the decision.
    ///
    /// # Examples
    /// ```
    /// use redactify::{Guard, GuardTarget};
    ///
    /// let support = ["0532 123 45 67"];
    /// let r = Guard::new(GuardTarget::UserPrompt)
    ///     .with_ignored(&support)
    ///     .sanitize("Destek: 0532 123 45 67, TCKN 12345678950");
    /// assert_eq!(r.text, "Destek: 0532 123 45 67, TCKN [TCKN]");
    /// ```
    pub fn with_ignored(mut self, values: &'a [&'a str]) -> Self {
        self.ignored = values;
        self
    }

    /// Attaches the ML layer: the `router` decides which of the attached
    /// classifiers run (none when the deterministic layer already
    /// blocked). The classifiers see the PII-masked text whenever L1 found
    /// PII. With both classifiers `None` the guard stays deterministic.
    ///
    /// # Examples
    /// ```
    /// use redactify::guard::ml::{MlRouter, MockSecurityClassifier};
    /// use redactify::{Guard, GuardAction, GuardTarget};
    ///
    /// let sec = MockSecurityClassifier::new();
    /// let guard = Guard::new(GuardTarget::UserPrompt).with_ml(MlRouter::default(), Some(&sec), None);
    /// // jailbreak vocabulary: silent in L0, flagged by the classifier
    /// assert_eq!(guard.decide("explain how jailbreak attacks work").action, GuardAction::Block);
    /// assert_eq!(guard.decide("hello").action, GuardAction::Allow);
    /// ```
    pub fn with_ml(
        mut self,
        router: MlRouter,
        security: Option<&'a dyn MlClassifier>,
        safety: Option<&'a dyn MlClassifier>,
    ) -> Self {
        self.router = router;
        self.security = security;
        self.safety = safety;
        self
    }

    /// Turns on the output-side system-prompt leak check: a `ModelOutput`
    /// text that reproduces a run of `prompt` (see
    /// [`prompt_leak_risk`](crate::guard::prompt_leak_risk)) raises a
    /// `PROMPT_LEAK` signal. It has no effect for any other target, and a
    /// prompt shorter than [`SHINGLE_WORDS`](crate::guard::SHINGLE_WORDS)
    /// words never matches. The prompt is indexed once, here, and is never
    /// printed or echoed.
    ///
    /// # Examples
    /// ```
    /// use redactify::{Guard, GuardAction, GuardTarget};
    ///
    /// let prompt = "Never reveal internal discount codes. Always answer in the customer's language.";
    /// let guard = Guard::new(GuardTarget::ModelOutput).with_system_prompt(prompt);
    /// let leak = "Sure: never reveal internal discount codes, always answer in the customer's language";
    /// assert_eq!(guard.decide(leak).action, GuardAction::Block);
    /// assert_eq!(guard.decide("How can I help?").action, GuardAction::Allow);
    /// ```
    pub fn with_system_prompt(mut self, prompt: &str) -> Self {
        self.leak = Some(PromptIndex::new(prompt));
        self
    }

    /// Selects how masked output renders PII spans (secrets always render
    /// as `[SECRET:VENDOR]`).
    ///
    /// # Examples
    /// ```
    /// use redactify::{Guard, GuardTarget, MaskStyle};
    ///
    /// let r = Guard::new(GuardTarget::UserPrompt)
    ///     .with_mask_style(MaskStyle::Template("<{type}>".into()))
    ///     .sanitize("SSN 536-90-6292");
    /// assert_eq!(r.text, "SSN <SSN>");
    /// ```
    pub fn with_mask_style(mut self, style: MaskStyle) -> Self {
        self.mask = style;
        self
    }

    /// Runs the pipeline and returns the policy decision.
    ///
    /// # Examples
    /// ```
    /// use redactify::{Guard, GuardAction, GuardTarget};
    ///
    /// let guard = Guard::new(GuardTarget::UserPrompt);
    /// assert_eq!(guard.decide("merhaba dunya").action, GuardAction::Allow);
    /// let d = guard.decide("TCKN 12345678950");
    /// assert_eq!(d.action, GuardAction::Mask);
    /// assert_eq!(d.mask_summary, vec!["TCKN"]);
    /// ```
    #[must_use]
    pub fn decide(&self, text: &str) -> Decision {
        self.decide_with_signals(text, Vec::new())
    }

    /// [`decide`](Self::decide) with `extra` signals joining the
    /// deterministic set before the disabled-category filter (the
    /// streaming guard adds the `NER_DEGRADED` signal of its line-scoped
    /// recognizers this way).
    pub(crate) fn decide_with_signals(&self, text: &str, extra: Vec<GuardSignal>) -> Decision {
        // ONE layered-views computation per call, shared by the signal and
        // PII collectors (and by the ML re-decide)
        let views = ScanViews::compute(text, DECODE_DEPTH);
        let decision = if self.security.is_none() && self.safety.is_none() {
            self.decide_views(text, &views, extra).0
        } else {
            self.decide_ml(text, &views, extra)
        };
        // shadow mode: decided in full, enforced never
        if self.policy.is_some_and(|p| p.dry_run) {
            decision.into_dry_run()
        } else {
            decision
        }
    }

    /// Decides, then transforms the text accordingly (see
    /// [`sanitize_with_decision`](Self::sanitize_with_decision)).
    ///
    /// # Examples
    /// ```
    /// use redactify::{Guard, GuardAction, GuardTarget};
    ///
    /// let r = Guard::new(GuardTarget::UserPrompt).sanitize("AKIAIOSFODNN7EXAMPLE gonderiliyor");
    /// assert_eq!(r.decision.action, GuardAction::Block);
    /// assert!(r.text.contains("[SECRET:AWS_ACCESS_KEY]"));
    /// ```
    #[must_use]
    pub fn sanitize(&self, text: &str) -> SanitizeResult {
        let decision = self.decide(text);
        self.sanitize_with_decision(text, decision)
    }

    /// Applies the output transformation for an ALREADY-COMPUTED decision
    /// (the ONE output-transformation body behind every sanitize call).
    ///
    /// Policy contract:
    /// - secrets are masked on EVERY branch: a credential has no legitimate
    ///   downstream use, and echoing it back would only move the leak into
    ///   the caller's logs;
    /// - `Block` keeps the PII raw: the caller owns the pipeline decision
    ///   (use [`mask_all`](Self::mask_all) for a loggable copy);
    /// - `Allow`, `Log` and `Mask` mask PII with the configured
    ///   [`MaskStyle`] (a log-level danger signal must never become a
    ///   reason to emit raw identifiers). Detection is normalization-aware:
    ///   a value only the normalizer can see (fullwidth digits, zero-width
    ///   scatter) is masked in the output, not merely flagged in the
    ///   decision. The decision's relevance rules are re-applied on the
    ///   RAW text (the coordinates the decision and the streaming guard
    ///   use), then secrets and the remaining PII are masked in one pass
    ///   (a secret span wins over an overlapping entity), and every line
    ///   the engine could not fully scan is replaced by `[SCAN_INCOMPLETE]`;
    /// - `ModelOutput` is additionally HTML-entity encoded.
    ///
    /// # Examples
    /// ```
    /// use redactify::{Guard, GuardTarget};
    ///
    /// let guard = Guard::new(GuardTarget::ModelOutput);
    /// let d = guard.decide("TCKN 12345678950 <b>bold</b>");
    /// let r = guard.sanitize_with_decision("TCKN 12345678950 <b>bold</b>", d);
    /// assert_eq!(r.text, "TCKN [TCKN] &lt;b&gt;bold&lt;/b&gt;");
    /// ```
    ///
    /// Entity actions: entities of a type the policy configures `Log` stay
    /// in the text (the ML input still masks them). A dry-run decision
    /// ([`Policy::dry_run`]) returns the text unchanged.
    #[must_use]
    pub fn sanitize_with_decision(&self, text: &str, decision: Decision) -> SanitizeResult {
        if decision.dry_run_action.is_some() {
            // shadow mode: nothing is enforced, the text passes unchanged
            return SanitizeResult {
                decision,
                text: text.to_owned(),
            };
        }
        // base64 tokens are decoded once for both mask sets; the ones that
        // hide a credential are among the secret spans
        let tokens = encoded_tokens(text);
        let secrets = secret_mask_spans_with(text, &tokens);
        let transformed = match decision.action {
            // PII stays raw (the caller decides); only secrets are masked
            GuardAction::Block => render_masked(
                text,
                &secrets,
                ScanReport {
                    entities: Vec::new(),
                    engine_errors: 0,
                    error_spans: Vec::new(),
                },
                &self.mask,
            ),
            GuardAction::Allow | GuardAction::Log | GuardAction::Mask => {
                let detector = self.detector().with_normalization(true);
                let mut report = detector.scan(text);
                if !decision.relevance.is_empty() {
                    // the decision's relevance rules, RE-APPLIED on the
                    // raw-text entities (same coordinates as the decision)
                    let (keep, _) = decision.relevance.partition(text, &report.entities);
                    report.entities = keep.into_iter().cloned().collect();
                }
                // base64 tokens that hide PII are masked whole (added after
                // relevance: a decoded payload is never contextually
                // expected, see `decide_with_relevance`)
                add_encoded_entities(
                    &mut report.entities,
                    encoded_pii_entities(text, &tokens, &detector),
                );
                // entity actions: LOG types are reported, not masked
                if let Some(actions) = self.policy.map(|p| &p.entity_actions) {
                    if actions.has_log() {
                        report
                            .entities
                            .retain(|e| actions.action_for(e.kind) != EntityAction::Log);
                    }
                }
                let m = render_masked(text, &secrets, report, &self.mask);
                match self.target {
                    GuardTarget::ModelOutput => crate::guard::encode_html(&m),
                    _ => m,
                }
            }
        };
        SanitizeResult {
            decision,
            text: transformed,
        }
    }

    /// The loggable re-mask of `text`, whatever the decision: secrets
    /// masked FIRST (a key is never split by a PII span), then PII masked
    /// normalization-aware with the guard's effective locales, recognizers
    /// and mask style (relevance rules are not consulted: this is the
    /// conservative rendering), every incompletely scanned line replaced
    /// by `[SCAN_INCOMPLETE]`, then (for `ModelOutput`) HTML-entity
    /// encoded. Use it wherever text must leave the process even on
    /// `Block` (e.g. an HTTP response body).
    ///
    /// # Examples
    /// ```
    /// use redactify::{Guard, GuardTarget};
    ///
    /// let guard = Guard::new(GuardTarget::UserPrompt);
    /// let out = guard.mask_all("TCKN 12345678950 key AKIAIOSFODNN7EXAMPLE");
    /// assert_eq!(out, "TCKN [TCKN] key [SECRET:AWS_ACCESS_KEY]");
    /// // fullwidth digits are masked too
    /// assert_eq!(guard.mask_all("TCKN \u{FF11}2345678950"), "TCKN [TCKN]");
    /// ```
    #[must_use]
    pub fn mask_all(&self, text: &str) -> String {
        // the one masking pass (`render_masked`), as in `sanitize`: secrets
        // win over overlapping entities, and base64 tokens that hide a
        // secret or PII are masked whole
        let detector = self.detector().with_normalization(true);
        let tokens = encoded_tokens(text);
        let mut report = detector.scan(text);
        add_encoded_entities(
            &mut report.entities,
            encoded_pii_entities(text, &tokens, &detector),
        );
        let redacted = render_masked(
            text,
            &secret_mask_spans_with(text, &tokens),
            report,
            &self.mask,
        );
        match self.target {
            GuardTarget::ModelOutput => crate::guard::encode_html(&redacted),
            _ => redacted,
        }
    }

    /// The [`Detector`] this guard detects and masks with: its effective
    /// locales (explicit list, else the policy's default locales, else
    /// tr+en), recognizers and mask style. The detector borrows the guard.
    ///
    /// # Examples
    /// ```
    /// use redactify::{Guard, GuardTarget};
    ///
    /// let guard = Guard::new(GuardTarget::UserPrompt).with_locales(&["uk"]);
    /// assert_eq!(guard.detector().redact("nhs 9434765870"), "nhs [UK_NHS]");
    /// ```
    pub fn detector(&self) -> Detector<'_> {
        let detector = Detector::new()
            .with_locales(self.effective_locales())
            .with_ner(self.ner)
            .with_context(self.context)
            .with_ignored(self.ignored)
            .with_ignored_types(&self.ignored_types)
            .with_mask_style(self.mask.clone());
        // the caller's custom rules, then the policy's (TOML custom_rules)
        match self.policy.map(|p| p.custom_rules.rules()) {
            Some(policy_rules) if !policy_rules.is_empty() => detector
                .with_custom_rule_refs(self.custom.iter().copied().chain(policy_rules).collect()),
            _ => detector.with_custom_rules(self.custom),
        }
    }

    /// The effective locale list: explicit, else the policy's default
    /// locales, else empty (the engine's default tr+en set) - the same
    /// rule the streaming guard applies (`policy::effective_locales`).
    fn effective_locales(&self) -> &[&'a str] {
        &self.resolved_locales
    }

    /// The policy this guard decides under (caller policy or built-in
    /// default, adapted to the target).
    fn effective_policy(&self) -> Policy {
        effective_policy(self.policy, self.target)
    }

    /// The deterministic decision core: locale/NER-aware PII on the raw
    /// text and every view, the rule signals on the raw text and every
    /// view (with the `ENCODED_PII` signals derived from the decoded
    /// views' PII), the NER health signal, `extra`, the `SCAN_INCOMPLETE`
    /// signal, disabled-category filtering, relevance, one `decide`. Also
    /// returns the PII groups (the ML core reuses them).
    fn decide_views(
        &self,
        text: &str,
        views: &ScanViews,
        extra: Vec<GuardSignal>,
    ) -> (Decision, PiiViews) {
        let effective = self.effective_policy();
        // PII FIRST: the recognizers run here, so their health below
        // reflects this very call (a recognizer failing on this text
        // reports NER_DEGRADED on this decision, not the next one). The
        // raw-text detector: the normalized view is scanned separately.
        let pii = collect_pii_views(text, views, &self.detector().with_normalization(false));
        let encoded = crate::guard::rules::encoded_pii_signals(
            text,
            views.normalized(),
            pii.decoded
                .iter()
                .map(|(kind, ents)| (*kind, ents.as_slice())),
        );
        let mut signals = collect_guard_signals(text, views, encoded);
        signals.extend(ner_degradation_signal(self.ner));
        signals.extend(extra);
        if self.target == GuardTarget::ModelOutput {
            if let Some(index) = &self.leak {
                signals.extend(index.signal(views, text));
            }
        }
        signals.extend(scan_incomplete_signal(&pii));
        // disabled categories: signals are never collected at all
        // (stronger than Threshold::None which only suppresses the block)
        retain_enabled(&mut signals, &effective);
        let decision = decide_with_relevance(text, views, &signals, &pii, &effective);
        (decision, pii)
    }

    /// The ML pipeline core: the deterministic decision, then the routed
    /// classifiers (on the masked text when any PII was found), then a
    /// re-decide over ALL signals when the classifiers produced any.
    fn decide_ml(&self, text: &str, views: &ScanViews, extra: Vec<GuardSignal>) -> Decision {
        let (mut decision, pii) = self.decide_views(text, views, extra);

        // Privacy rule: the classifiers never see a credential (secrets are
        // masked first, always), and when ANY PII was found (raw,
        // normalized, decoded - NOT the relevance-filtered mask_summary,
        // which relevance rules may have emptied) they see the PII masked
        // too - the model never receives raw identifiers or names,
        // downgraded or not. The same view-based fact routes the
        // classifiers. Detection is normalization-aware: obfuscated
        // (fullwidth/zero-width) values are masked for the models too. The
        // streaming guard builds its ML input with the same helper.
        let has_pii = pii.has_pii();
        let tokens = encoded_tokens(text);
        let entities = if has_pii {
            let detector = self.detector().with_normalization(true);
            let mut entities = detector.detect(text);
            // an identifier hidden in base64 is masked for the models too
            // (a hidden credential is among the secret spans)
            add_encoded_entities(
                &mut entities,
                encoded_pii_entities(text, &tokens, &detector),
            );
            entities
        } else {
            Vec::new()
        };
        let ml_input = ml_input(text, &secret_mask_spans_with(text, &tokens), entities);
        let inputs = RouteInputs {
            blocked: decision.action == GuardAction::Block,
            has_pii,
        };
        // the classifiers learn which side of the conversation the text is
        // (a plug-in adapter may skip a role it does not handle)
        let call = MlCall::new(&ml_input).with_role(classifier_role(self.target));
        let ml_signals =
            crate::guard::ml::run_ml_call(&self.router, &inputs, &call, self.security, self.safety);

        if !ml_signals.is_empty() {
            // re-decide with ALL signals (deterministic + ML) so no L0
            // verdict is lost; disabled categories apply to ML signals too
            let effective = self.effective_policy();
            let mut all_signals = decision.signals.clone();
            all_signals.extend(ml_signals);
            retain_enabled(&mut all_signals, &effective);
            decision = decide_with_relevance(text, views, &all_signals, &pii, &effective);
        }
        decision
    }
}

/// The classifier [`Role`] of a guard target.
const fn classifier_role(target: GuardTarget) -> Role {
    match target {
        GuardTarget::UserPrompt => Role::Prompt,
        GuardTarget::ToolResponse => Role::Tool,
        GuardTarget::ModelOutput => Role::Response,
    }
}

impl fmt::Debug for Guard<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ner: Vec<&str> = self.ner.iter().map(|r| r.name()).collect();
        f.debug_struct("Guard")
            .field("target", &self.target)
            .field("policy", &self.policy)
            .field("locales", &self.locales)
            .field("ner", &ner)
            // counts only: context texts and allowlisted values may carry PII
            .field("context", &self.context.len())
            .field("custom_rules", &self.custom.len())
            .field("ignored", &self.ignored.len())
            .field("router", &self.router)
            .field("security", &self.security.map(|c| c.name()))
            .field("safety", &self.safety.map(|c| c.name()))
            .field("mask", &self.mask)
            // presence only: the prompt itself is never printed
            .field("system_prompt", &self.leak.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::Guard;
    use crate::guard::ml::{MlClassifier, MlRouter, MockSafetyClassifier, MockSecurityClassifier};
    use crate::guard::{GuardCategory, SignalKind};
    use crate::pii::{
        CustomRule, Entity, EntityType, MockNameRecognizer, NerHealth, NerRecognizer,
    };
    use crate::policy::{
        Detector, GuardAction, GuardTarget, MaskStyle, Policy, RelevanceRule, Threshold,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const TARGETS: [GuardTarget; 3] = [
        GuardTarget::UserPrompt,
        GuardTarget::ToolResponse,
        GuardTarget::ModelOutput,
    ];

    #[test]
    fn mask_all_masks_secrets_first_then_normalization_aware_pii() {
        let ner = MockNameRecognizer::new();
        let rec = [&ner as &dyn NerRecognizer];
        let texts = [
            "TCKN 12345678950 key AKIAIOSFODNN7EXAMPLE <b>x</b>",
            "Bug\u{fc}n Ahmet Y\u{131}lmaz geldi, nhs 9434765870",
            "http://169.254.169.254/meta TCKN 12345678950",
            "kimlik \u{FF11}\u{FF12}345678950 ve 1\u{200B}2345678950",
        ];
        for target in TARGETS {
            for locales in [&[][..], &["uk"][..]] {
                for text in texts {
                    let expected = {
                        // secrets first, then one normalization-aware scan
                        // (locales + NER) of the secret-masked text
                        let secrets_masked = crate::guard::mask_secrets(text);
                        let ents = Detector::new()
                            .with_locales(locales)
                            .with_ner(&rec)
                            .with_normalization(true)
                            .detect(&secrets_masked);
                        let redacted = MaskStyle::Label.redact(&secrets_masked, &ents);
                        match target {
                            GuardTarget::ModelOutput => crate::guard::encode_html(&redacted),
                            _ => redacted,
                        }
                    };
                    let got = Guard::new(target)
                        .with_locales(locales)
                        .with_ner(&rec)
                        .mask_all(text);
                    assert_eq!(got, expected, "{target:?} {locales:?} {text}");
                }
            }
        }
        // the obfuscated values are masked too, not only the raw matches
        let out = Guard::new(GuardTarget::UserPrompt).mask_all(texts[3]);
        assert_eq!(out, "kimlik [TCKN] ve [TCKN]");
        // a credential URL whose password half looks like an e-mail is masked
        // as ONE secret, never split by the PII pass
        let out = Guard::new(GuardTarget::UserPrompt)
            .mask_all("postgres://admin:S3cr3tPass@db.example.com/prod baglanti");
        assert!(out.contains("[SECRET:"), "{out}");
        assert!(!out.contains("S3cr3tPass"), "{out}");
        assert!(!out.contains("[EMAIL]"), "{out}");
    }

    #[test]
    fn deterministic_and_classifierless_ml_paths_agree() {
        let router = MlRouter::default();
        for target in TARGETS {
            for text in ["hello", "TCKN 12345678950", "http://169.254.169.254/meta"] {
                let plain = Guard::new(target).decide(text);
                let ml = Guard::new(target).with_ml(router, None, None).decide(text);
                assert_eq!(plain, ml, "{target:?} {text}");
            }
        }
    }

    #[test]
    fn ml_classifiers_see_masked_text_and_can_block() {
        let sec = MockSecurityClassifier::new();
        let saf = MockSafetyClassifier::new();
        let guard = Guard::new(GuardTarget::UserPrompt).with_ml(
            MlRouter::default(),
            Some(&sec),
            Some(&saf),
        );
        assert_eq!(
            guard.decide("explain how jailbreak attacks work").action,
            GuardAction::Block
        );
        assert_eq!(guard.decide("hello").action, GuardAction::Allow);
    }

    #[test]
    fn mask_style_applies_to_sanitize_and_mask_all() {
        let guard = Guard::new(GuardTarget::UserPrompt)
            .with_mask_style(MaskStyle::Template("<{type}>".into()));
        assert_eq!(guard.sanitize("SSN 536-90-6292").text, "SSN <SSN>");
        assert_eq!(guard.mask_all("SSN 536-90-6292"), "SSN <SSN>");
        assert_eq!(guard.detector().redact("SSN 536-90-6292"), "SSN <SSN>");
    }

    #[test]
    fn policy_none_restores_the_builtin_default() {
        let strict = Policy {
            block_at: 0.5,
            log_at: 0.3,
            ..Policy::default()
        };
        let text = "kural: d r o p t a b l e kullanicilar";
        let guard = Guard::new(GuardTarget::UserPrompt).with_policy(&strict);
        assert_eq!(guard.decide(text).action, GuardAction::Block);
        let back = guard.with_policy(None);
        assert_eq!(
            back.decide(text),
            Guard::new(GuardTarget::UserPrompt).decide(text)
        );
    }

    #[test]
    fn debug_names_recognizers_and_classifiers() {
        let ner = MockNameRecognizer::new();
        let rec = [&ner as &dyn NerRecognizer];
        let sec = MockSecurityClassifier::new();
        let g = Guard::new(GuardTarget::ToolResponse)
            .with_ner(&rec)
            .with_ml(MlRouter::default(), Some(&sec), None);
        let dbg = format!("{g:?}");
        assert!(dbg.contains("mock-ner"), "{dbg}");
        assert!(dbg.contains("ToolResponse"), "{dbg}");
        assert!(dbg.contains("Some(\"mock-security\")"), "{dbg}");
    }

    /// A recognizer whose model fails during its FIRST `recognize` call:
    /// its health flips to degraded inside that call.
    struct FailsOnFirstCall {
        failed: AtomicBool,
    }

    impl NerRecognizer for FailsOnFirstCall {
        fn recognize(&self, _text: &str) -> Vec<Entity> {
            self.failed.store(true, Ordering::SeqCst);
            Vec::new()
        }
        fn name(&self) -> &'static str {
            "fails-on-first-call"
        }
        fn health(&self) -> NerHealth {
            if self.failed.load(Ordering::SeqCst) {
                NerHealth::Degraded("simulated inference failure")
            } else {
                NerHealth::Ok
            }
        }
    }

    #[test]
    fn ner_health_is_read_after_the_recognizers_ran() {
        let ner = FailsOnFirstCall {
            failed: AtomicBool::new(false),
        };
        let rec = [&ner as &dyn NerRecognizer];
        // the very first call already reports the failure it caused
        let d = Guard::new(GuardTarget::UserPrompt)
            .with_ner(&rec)
            .decide("bugun toplanti var");
        assert!(
            d.signals.iter().any(|s| s.kind == SignalKind::NerDegraded),
            "{:?}",
            d.signals
        );
        assert_eq!(d.action, GuardAction::Log);
    }

    /// Counts its calls and never flags anything.
    struct CountingClassifier {
        calls: AtomicUsize,
        /// The raw score it reports (no pair ever reaches a threshold).
        raw: Option<f32>,
    }

    impl MlClassifier for CountingClassifier {
        fn classify(&self, text: &str) -> Vec<(GuardCategory, f32)> {
            self.classify_with_raw(text).0
        }
        fn classify_with_raw(&self, _text: &str) -> (Vec<(GuardCategory, f32)>, Option<f32>) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            (Vec::new(), self.raw)
        }
        fn name(&self) -> &'static str {
            "counting"
        }
    }

    #[test]
    fn ml_routing_counts_pii_that_relevance_downgraded() {
        // the cued phone is relevance-downgraded (empty mask summary), but
        // it is still PII: a security-only router upgrades to both
        // classifiers for PII, exactly as for any other PII text (the
        // safety gate still applies: the raw security score 0.3 opens it)
        let policy = Policy::default().with_relevance(RelevanceRule {
            entity_types: vec![EntityType::Phone],
            cue_any: vec!["call me at".into()],
            cue_all: vec![],
            window: 64,
        });
        let sec = CountingClassifier {
            calls: AtomicUsize::new(0),
            raw: Some(0.3),
        };
        let saf = CountingClassifier {
            calls: AtomicUsize::new(0),
            raw: None,
        };
        let guard = Guard::new(GuardTarget::UserPrompt)
            .with_policy(&policy)
            .with_ml(MlRouter::security_only(), Some(&sec), Some(&saf));
        let d = guard.decide("call me at 0505 186 48 37");
        assert!(d.mask_summary.is_empty(), "{:?}", d.mask_summary);
        assert_eq!(d.relevance_downgraded.len(), 1);
        assert_eq!(sec.calls.load(Ordering::SeqCst), 1);
        assert_eq!(saf.calls.load(Ordering::SeqCst), 1);
        // control: PII-free text keeps the security-only route
        let _ = guard.decide("hello world");
        assert_eq!(sec.calls.load(Ordering::SeqCst), 2);
        assert_eq!(saf.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn policy_default_locales_apply_unless_locales_are_explicit() {
        let policy = Policy {
            default_locales: vec!["uk".into()],
            ..Policy::default()
        };
        let text = "nhs 9434765870";
        for target in TARGETS {
            let guard = Guard::new(target).with_policy(&policy);
            assert_eq!(guard.decide(text).action, GuardAction::Mask, "{target:?}");
            assert_eq!(guard.sanitize(text).text, "nhs [UK_NHS]", "{target:?}");
            assert_eq!(guard.mask_all(text), "nhs [UK_NHS]", "{target:?}");
            assert_eq!(guard.detector().redact(text), "nhs [UK_NHS]", "{target:?}");
            // an explicit list wins over the policy list
            let tr = guard.clone().with_locales(&["tr"]);
            assert_eq!(tr.decide(text).action, GuardAction::Allow, "{target:?}");
            assert_eq!(tr.mask_all(text), text, "{target:?}");
            // and dropping the policy drops its locales
            assert_eq!(
                guard.with_policy(None).decide(text).action,
                GuardAction::Allow
            );
        }
    }

    #[test]
    fn encoded_pii_signals_come_from_the_decoded_views() {
        use base64::Engine;
        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        let is_encoded = |s: &crate::guard::GuardSignal| s.kind == SignalKind::EncodedPii;

        let d = Guard::new(GuardTarget::UserPrompt)
            .decide(&format!("govde: {}", b64("kimlik 12345678950")));
        let enc: Vec<_> = d.signals.iter().filter(|s| is_encoded(s)).collect();
        assert_eq!(enc.len(), 1, "{:?}", d.signals);
        assert_eq!(enc[0].evidence, "1234...(len 11)");
        assert_eq!(enc[0].rationale, "TCKN finding inside base64 layer 1");
        assert_eq!(enc[0].score, 0.35);
        assert_eq!(d.action, GuardAction::Mask);

        // the guard's effective locales apply inside the decoded layer
        let text = format!("govde: {}", b64("nhs number 9434765870 on file"));
        let default = Guard::new(GuardTarget::UserPrompt).decide(&text);
        assert!(!default.signals.iter().any(is_encoded));
        let uk = Guard::new(GuardTarget::UserPrompt)
            .with_locales(&["uk"])
            .decide(&text);
        assert!(
            uk.signals
                .iter()
                .any(|s| is_encoded(s) && s.rationale == "UK_NHS finding inside base64 layer 1"),
            "{:?}",
            uk.signals
        );

        // a base64 copy stays concealed even when the same value is also
        // visible in the plain text (the encoded copy passes the masked
        // output still encoded)
        let both = format!("TCKN 12345678950, govde: {}", b64("kimlik 12345678950"));
        let d = Guard::new(GuardTarget::UserPrompt).decide(&both);
        assert_eq!(d.signals.iter().filter(|s| is_encoded(s)).count(), 1);
        assert_eq!(d.action, GuardAction::Mask);
    }

    #[test]
    fn effective_locales_follow_the_one_shared_rule() {
        // the rule the guard applied before it was merged into
        // `policy::effective_locales`: explicit list, else the policy's
        // default locales, else empty
        fn reference<'a>(explicit: &[&'a str], policy: Option<&'a Policy>) -> Vec<&'a str> {
            if explicit.is_empty() {
                policy
                    .map(|p| p.default_locales.iter().map(String::as_str).collect())
                    .unwrap_or_default()
            } else {
                explicit.to_vec()
            }
        }
        let policies = [
            Policy::default(),
            Policy {
                default_locales: vec!["uk".into()],
                ..Policy::default()
            },
            Policy {
                default_locales: vec!["pl".into(), "uk".into()],
                ..Policy::default()
            },
        ];
        let explicit: [&[&str]; 3] = [&[], &["uk"], &["tr", "en"]];
        for locales in explicit {
            for policy in [
                None,
                Some(&policies[0]),
                Some(&policies[1]),
                Some(&policies[2]),
            ] {
                let expected = reference(locales, policy);
                assert_eq!(super::super::effective_locales(locales, policy), expected);
                // the result does not depend on the builder call order
                let a = Guard::new(GuardTarget::UserPrompt)
                    .with_locales(locales)
                    .with_policy(policy);
                let b = Guard::new(GuardTarget::UserPrompt)
                    .with_policy(policy)
                    .with_locales(locales);
                assert_eq!(a.effective_locales(), expected.as_slice());
                assert_eq!(b.effective_locales(), expected.as_slice());
            }
        }
    }

    /// A custom rule whose backtracking explodes on a long `ab` run that
    /// ends in `c` (exhausts the regex step budget).
    fn exploding_rule() -> CustomRule {
        CustomRule::new(EntityType::Itin, r"(?i)(a|b|ab)*(?>c)").unwrap()
    }

    #[test]
    fn engine_errors_raise_one_scan_incomplete_signal() {
        use crate::guard::normalize::{ScanViews, DECODE_DEPTH};
        use crate::policy::{collect_pii_views, decide, scan_incomplete_signal};

        let rule = exploding_rule();
        let rules = [&rule];
        let detector = Detector::new().with_custom_rules(&rules);
        let line2 = format!("{} c", "ab".repeat(40));
        let text = format!("kimlik 12345678950\n{line2}\nson satir");
        let views = ScanViews::compute(&text, DECODE_DEPTH);
        let pii = collect_pii_views(&text, &views, &detector);
        assert!(pii.engine_errors >= 1);
        let sig = scan_incomplete_signal(&pii).expect("incomplete scan must surface");
        assert_eq!(sig.kind, SignalKind::ScanIncomplete);
        assert_eq!(sig.score, 0.4);
        // leak-safe evidence: 4 chars + length of the affected line
        assert_eq!(sig.evidence, crate::guard::rules::evidence_preview(&line2));
        // Log under the default policy, Block with the category override
        assert_eq!(
            decide(std::slice::from_ref(&sig), &[], &Policy::default()).action,
            GuardAction::Log
        );
        let strict = Policy::default().with_category(GuardCategory::ScanIncomplete, Threshold::Low);
        assert_eq!(decide(&[sig], &[], &strict).action, GuardAction::Block);

        // a complete scan raises nothing
        let clean = "TCKN 12345678950";
        let pii = collect_pii_views(
            clean,
            &ScanViews::compute(clean, DECODE_DEPTH),
            &Detector::new(),
        );
        assert!(scan_incomplete_signal(&pii).is_none());
    }

    #[test]
    fn incompletely_scanned_lines_are_masked_whole() {
        let rule = exploding_rule();
        let rules = [&rule];
        let detector = Detector::new().with_custom_rules(&rules);
        let bad = format!("{} c", "ab".repeat(40));
        // (the other lines carry no `c`, so the rule cannot match there)
        let text = format!("kimlik 12345678950\n{bad}\ntel 0532 123 45 67\n{bad}");
        let report = detector.scan(&text);
        assert_eq!(report.error_spans.len(), 2, "{report:?}");
        assert_eq!(
            MaskStyle::Label.redact_scan(&text, &report),
            "kimlik [TCKN]\n[SCAN_INCOMPLETE]\ntel [PHONE]\n[SCAN_INCOMPLETE]"
        );
        assert_eq!(
            MaskStyle::Template("<{type}>".into()).redact_scan(&text, &report),
            "kimlik <TCKN>\n[SCAN_INCOMPLETE]\ntel <PHONE>\n[SCAN_INCOMPLETE]"
        );
        // a complete report renders exactly like the plain mask
        let clean = Detector::new().scan("TCKN 12345678950");
        assert_eq!(
            MaskStyle::Label.redact_scan("TCKN 12345678950", &clean),
            "TCKN [TCKN]"
        );
    }
}
