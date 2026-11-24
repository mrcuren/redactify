//! [`Guarded`]: the policy wrapper that turns any
//! [`GuardClassifier`] adapter into an [`MlClassifier`] the pipeline can
//! use.
//!
//! The adapter only calls its model and returns a typed result; everything
//! that is policy lives here, in one place:
//!
//! - **threshold**: the minimum score a category must reach to be emitted
//!   (default 0.5; per-category overrides);
//! - **fail mode**: what a failed call emits ([`FailMode::Closed`], the
//!   default: every category of the adapter's [`Capabilities`] at 1.0, or
//!   `ML_DEGRADED` at 1.0 when it declares none - a Block either way;
//!   [`FailMode::Open`]: nothing). Either way the failure is reported, so
//!   the pipeline adds an `ML_DEGRADED` signal, and a failed security call
//!   never closes the safety gate;
//! - **deadline**: each call gets `now + timeout` (default 2 s); an answer
//!   that arrives after it counts as a timeout. With [`Guarded::isolated`]
//!   the adapter runs on the crate's bounded-inference executor instead: a
//!   hard timeout on a worker thread, a circuit breaker that fails fast
//!   after a timeout or a dead worker, and a half-open probe after the
//!   cooldown (the machinery the ONNX classifiers use);
//! - **chunking**: texts over the adapter's own
//!   [`Capabilities::max_chars`] are classified in overlapping windows
//!   (per category, the maximum score wins), instead of the global
//!   1,800-character budget;
//! - **role**: a text whose [`Role`] the adapter does not handle is not
//!   sent to it;
//! - **health**: the adapter's own health, the isolated lane's state, and
//!   any failed call within the cooldown.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::guard::category::GuardCategory;
use crate::guard::classifier::{
    intern, Capabilities, CategoryScore, ClassifierError, ClassifyRequest, GuardClassifier, Role,
    Verdict,
};
use crate::guard::executor::{
    lock, Engine, EngineFactory, JobResult, Lane, LaneError, LaneNames, DEFAULT_COOLDOWN,
};
use crate::guard::ml::{chunked_outcome, FailMode, MlCall, MlClassifier, MlHealth, MlOutcome};

/// Default per-call timeout of a [`Guarded`] classifier (the ONNX default).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// Default emission threshold of a [`Guarded`] classifier (the ONNX
/// default).
pub const DEFAULT_THRESHOLD: f32 = 0.5;

/// Raw label of the scores a fail-closed failure emits (it shows in the
/// decision rationale instead of a model label).
pub const FAIL_CLOSED_LABEL: &str = "fail-closed";

/// Upper bound of a deadline offset: `Instant + Duration` panics on
/// overflow, and no classification needs a day.
const MAX_DEADLINE_OFFSET: Duration = Duration::from_secs(86_400);

/// Thread names of an isolated lane.
const GUARDED_LANE_NAMES: LaneNames = LaneNames {
    worker: "redactify-guarded-infer",
    probe: "redactify-guarded-recover",
};

/// `now + timeout`, without overflow.
fn deadline_after(timeout: Duration) -> Instant {
    Instant::now() + timeout.min(MAX_DEADLINE_OFFSET)
}

/// A request the isolated worker owns (the caller's borrow cannot cross
/// threads). The deadline is computed when the worker STARTS the call, so
/// queueing behind other callers never counts against it (the executor's
/// load-independence rule).
#[derive(Clone)]
struct OwnedRequest {
    text: String,
    role: Role,
    prompt_context: Option<String>,
    timeout: Duration,
}

/// What the isolated worker answers: the adapter's own result, typed.
type IsolatedAnswer = Result<Verdict, ClassifierError>;

/// The engine of an isolated lane: a shared handle to the adapter. A
/// rebuild (half-open probe) spawns a fresh worker over the same adapter;
/// an abandoned worker stuck in a call keeps its handle until the call
/// returns.
struct IsolatedEngine<C>(Arc<C>);

impl<C: GuardClassifier + 'static> Engine<OwnedRequest, IsolatedAnswer> for IsolatedEngine<C> {
    fn run(&mut self, req: OwnedRequest) -> JobResult<IsolatedAnswer> {
        let mut r = ClassifyRequest::new(&req.text, req.role, deadline_after(req.timeout));
        r.prompt_context = req.prompt_context.as_deref();
        // the adapter's error is an answer, not a lane failure: the lane
        // breaker reacts to hangs and dead workers only
        Ok(self.0.classify(&r))
    }
}

/// Policy wrapper around a [`GuardClassifier`] (see the module docs).
///
/// It implements [`MlClassifier`], so it plugs into
/// [`Guard::with_ml`](crate::Guard::with_ml), the streaming guard and the
/// REST state wherever an L2/L3 classifier goes.
///
/// # Examples
/// ```
/// use std::time::Duration;
/// use redactify::guard::classifier::{
///     Capabilities, CategoryScore, ClassifierError, ClassifyRequest, GuardClassifier, Verdict,
/// };
/// use redactify::guard::guarded::Guarded;
/// use redactify::guard::ml::{FailMode, MlCall, MlClassifier};
/// use redactify::GuardCategory;
///
/// struct Down(Capabilities);
/// impl GuardClassifier for Down {
///     fn id(&self) -> &str { "down" }
///     fn capabilities(&self) -> &Capabilities { &self.0 }
///     fn classify(&self, _: &ClassifyRequest<'_>) -> Result<Verdict, ClassifierError> {
///         Err(ClassifierError::Unavailable("connection refused".to_owned()))
///     }
/// }
///
/// let caps = Capabilities::new(vec![GuardCategory::Hate, GuardCategory::Violence]);
/// // fail-closed (default): every category at 1.0, and the failure is reported
/// let closed = Guarded::new(Down(caps.clone())).with_timeout(Duration::from_millis(500));
/// let out = closed.classify_call(&MlCall::new("some text"));
/// assert_eq!(out.pairs(), vec![(GuardCategory::Hate, 1.0), (GuardCategory::Violence, 1.0)]);
/// assert_eq!(out.failure.unwrap().kind(), "unavailable");
/// // fail-open: no scores, the failure is still reported
/// let open = Guarded::new(Down(caps)).with_fail_mode(FailMode::Open);
/// let out = open.classify_call(&MlCall::new("some text"));
/// assert!(out.scores.is_empty() && out.failure.is_some());
/// ```
pub struct Guarded<C> {
    inner: Arc<C>,
    name: &'static str,
    threshold: f32,
    category_thresholds: Vec<(GuardCategory, f32)>,
    fail_mode: FailMode,
    timeout: Duration,
    role: Role,
    max_chars: usize,
    overlap: usize,
    /// The fail-closed set: the adapter's categories, read once, or
    /// `[ML_DEGRADED]` when it declares none (see [`Guarded::new`]).
    fail_categories: Vec<GuardCategory>,
    /// Last failed call and when, reported by `health()` for `cooldown`.
    last_failure: Mutex<Option<(Instant, String)>>,
    /// The bounded-inference lane when isolated.
    lane: Option<Arc<Lane<OwnedRequest, IsolatedAnswer>>>,
    cooldown: Duration,
}

impl<C: GuardClassifier> Guarded<C> {
    /// Wraps `inner` with the defaults: threshold [`DEFAULT_THRESHOLD`],
    /// [`FailMode::Closed`], timeout [`DEFAULT_TIMEOUT`], role
    /// [`Role::Prompt`] for calls that carry none, the adapter's own
    /// chunking, a 30 s health cooldown, not isolated. The name reported to
    /// the pipeline is the adapter's [`GuardClassifier::id`].
    ///
    /// Fail-closed emits every category of the adapter's [`Capabilities`]
    /// at 1.0. An adapter that declares NO category still blocks: its
    /// fail-closed signal is `ML_DEGRADED` at 1.0 (raw label
    /// [`FAIL_CLOSED_LABEL`]), so a failure never degrades to the Log-level
    /// health signal alone. Only a policy that explicitly sets
    /// `ML_DEGRADED` to `Threshold::None` (or disables it) lets such a
    /// failure through.
    pub fn new(inner: C) -> Self {
        let caps = inner.capabilities();
        let fail_categories = if caps.categories.is_empty() {
            vec![GuardCategory::MlDegraded]
        } else {
            caps.categories.clone()
        };
        let (max_chars, overlap) = (caps.max_chars.max(1), caps.chunk_overlap_chars);
        let name = intern(inner.id());
        Self {
            inner: Arc::new(inner),
            name,
            threshold: DEFAULT_THRESHOLD,
            category_thresholds: Vec::new(),
            fail_mode: FailMode::Closed,
            timeout: DEFAULT_TIMEOUT,
            role: Role::Prompt,
            max_chars,
            overlap: overlap.min(max_chars - 1),
            fail_categories,
            last_failure: Mutex::new(None),
            lane: None,
            cooldown: DEFAULT_COOLDOWN,
        }
    }

    /// Overrides the name reported to the pipeline (evidence `ml:<name>`).
    #[must_use]
    pub const fn with_name(mut self, name: &'static str) -> Self {
        self.name = name;
        self
    }

    /// Sets the emission threshold for every category without an override.
    #[must_use]
    pub const fn with_threshold(mut self, threshold: f32) -> Self {
        self.threshold = threshold;
        self
    }

    /// Sets the emission threshold of one category.
    #[must_use]
    pub fn with_category_threshold(mut self, category: GuardCategory, threshold: f32) -> Self {
        match self
            .category_thresholds
            .iter_mut()
            .find(|(c, _)| *c == category)
        {
            Some(entry) => entry.1 = threshold,
            None => self.category_thresholds.push((category, threshold)),
        }
        self
    }

    /// Sets the error policy ([`FailMode::Closed`] by default).
    #[must_use]
    pub const fn with_fail_mode(mut self, mode: FailMode) -> Self {
        self.fail_mode = mode;
        self
    }

    /// Sets the per-call timeout (default [`DEFAULT_TIMEOUT`]); each window
    /// of a chunked text gets its own. `Duration::ZERO` fails every call.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the role used when a call carries none (legacy entry points
    /// such as [`MlClassifier::classify`]); default [`Role::Prompt`].
    #[must_use]
    pub const fn with_role(mut self, role: Role) -> Self {
        self.role = role;
        self
    }

    /// Overrides the adapter's chunking: windows of `max_chars` characters
    /// (at least 1) overlapping by `overlap` (clamped below `max_chars`).
    #[must_use]
    pub fn with_chunking(mut self, max_chars: usize, overlap: usize) -> Self {
        self.max_chars = max_chars.max(1);
        self.overlap = overlap.min(self.max_chars - 1);
        self
    }

    /// Sets how long a failed call keeps [`MlClassifier::health`] degraded
    /// and, for an isolated classifier, the recovery cooldown of its lane
    /// (default 30 s). Call it BEFORE [`Guarded::isolated`].
    #[must_use]
    pub const fn with_cooldown(mut self, cooldown: Duration) -> Self {
        self.cooldown = cooldown;
        self
    }

    /// The adapter.
    #[must_use]
    pub fn inner(&self) -> &C {
        &self.inner
    }

    /// The default emission threshold.
    #[must_use]
    pub const fn threshold(&self) -> f32 {
        self.threshold
    }

    /// The emission threshold that applies to `category`.
    #[must_use]
    pub fn threshold_for(&self, category: GuardCategory) -> f32 {
        self.category_thresholds
            .iter()
            .find(|(c, _)| *c == category)
            .map_or(self.threshold, |(_, t)| *t)
    }

    /// The error policy.
    #[must_use]
    pub const fn fail_mode(&self) -> FailMode {
        self.fail_mode
    }

    /// The per-call timeout.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The window size and overlap, in characters.
    #[must_use]
    pub const fn chunking(&self) -> (usize, usize) {
        (self.max_chars, self.overlap)
    }

    /// Whether calls run on an isolated lane ([`Guarded::isolated`]).
    #[must_use]
    pub const fn is_isolated(&self) -> bool {
        self.lane.is_some()
    }

    /// Classifies a whole text: role filter, chunking, per-window calls,
    /// thresholds, and the fail mode on failure.
    fn outcome(&self, call: &MlCall<'_>) -> MlOutcome {
        let role = call.role.unwrap_or(self.role);
        let caps = self.inner.capabilities();
        if !caps.supports_role(role) {
            return MlOutcome::default();
        }
        let context = if caps.supports_prompt_context {
            call.prompt_context
        } else {
            None
        };
        // fail-closed blocks whatever the remaining windows say: stop at
        // the first failure instead of spending their calls
        let stop = self.fail_mode == FailMode::Closed;
        let mut out = chunked_outcome(call.text, self.max_chars, self.overlap, stop, |w| {
            self.window(w, role, context)
        });
        if let Some(e) = &out.failure {
            *lock(&self.last_failure) = Some((Instant::now(), e.to_string()));
            if self.fail_mode == FailMode::Closed {
                out.scores = self
                    .fail_categories
                    .iter()
                    .map(|&c| CategoryScore::new(c, 1.0, FAIL_CLOSED_LABEL))
                    .collect();
                out.raw = None;
            }
            // fail-open keeps what the windows that did answer reported
        }
        out
    }

    /// One window: the adapter's verdict, validated and thresholded.
    fn window(&self, text: &str, role: Role, context: Option<&str>) -> MlOutcome {
        match self.call_adapter(text, role, context).and_then(validate) {
            Ok(verdict) => {
                let raw = verdict.max_score();
                let kind = verdict.kind;
                let mut scores: Vec<CategoryScore> = verdict
                    .scores
                    .into_iter()
                    .filter(|s| s.score >= self.threshold_for(s.category))
                    .collect();
                scores.sort_by(|a, b| b.score.total_cmp(&a.score));
                MlOutcome {
                    scores,
                    raw,
                    kind,
                    failure: None,
                }
            }
            Err(e) => MlOutcome {
                failure: Some(e),
                ..MlOutcome::default()
            },
        }
    }

    /// Calls the adapter once, on the isolated lane or on this thread.
    fn call_adapter(
        &self,
        text: &str,
        role: Role,
        context: Option<&str>,
    ) -> Result<Verdict, ClassifierError> {
        if let Some(lane) = &self.lane {
            let req = OwnedRequest {
                text: text.to_owned(),
                role,
                prompt_context: context.map(str::to_owned),
                timeout: self.timeout,
            };
            return lane
                .call(req, self.timeout)
                .map_err(|e| match e {
                    LaneError::TimedOut(m) => ClassifierError::Timeout(m),
                    LaneError::Unavailable(m) => ClassifierError::Unavailable(m),
                    LaneError::Call(m) => ClassifierError::Inference(m),
                })
                .and_then(|answer| answer);
        }
        let deadline = deadline_after(self.timeout);
        let mut req = ClassifyRequest::new(text, role, deadline);
        req.prompt_context = context;
        let result = self.inner.classify(&req);
        // an answer past the deadline is a timeout however good it is (and
        // a zero timeout admits none), like the executor's rule
        if self.timeout.is_zero() || Instant::now() > deadline {
            return Err(ClassifierError::Timeout(format!(
                "the classifier answered after the {:?} deadline",
                self.timeout
            )));
        }
        result
    }
}

impl<C: GuardClassifier + 'static> Guarded<C> {
    /// Runs the adapter on the crate's bounded-inference executor: a
    /// dedicated worker thread with a hard per-call timeout (the caller
    /// stops waiting even when the adapter hangs), a circuit breaker
    /// (after a timeout or a dead worker every call fails fast and follows
    /// the fail mode) and ONE background half-open probe per cooldown,
    /// which must answer a `"warmup"` request within the timeout before the
    /// lane closes again. Calls queue on the worker; queueing behind other
    /// callers never counts against a call's timeout.
    ///
    /// The cost is one text copy and one thread hand-off per call; adapters
    /// that already bound their own calls (the ONNX encoder runs on such a
    /// lane internally) do not need it.
    ///
    /// # Errors
    /// The worker thread cannot be spawned.
    pub fn isolated(mut self) -> std::io::Result<Self> {
        let engine = IsolatedEngine(Arc::clone(&self.inner));
        let shared = Arc::clone(&self.inner);
        let factory: Box<EngineFactory<OwnedRequest, IsolatedAnswer>> = Box::new(move || {
            Ok(Box::new(IsolatedEngine(Arc::clone(&shared)))
                as Box<dyn Engine<OwnedRequest, IsolatedAnswer>>)
        });
        let probe = OwnedRequest {
            text: "warmup".to_owned(),
            role: self.role,
            prompt_context: None,
            timeout: self.timeout,
        };
        self.lane = Some(Lane::new(
            Box::new(engine),
            factory,
            probe,
            self.cooldown,
            GUARDED_LANE_NAMES,
        )?);
        Ok(self)
    }
}

/// Rejects a verdict whose scores are not numbers in `[0, 1]`: a NaN would
/// never reach a threshold and silently read as clean.
fn validate(verdict: Verdict) -> Result<Verdict, ClassifierError> {
    if verdict
        .scores
        .iter()
        .all(|s| s.score.is_finite() && (0.0..=1.0).contains(&s.score))
    {
        Ok(verdict)
    } else {
        Err(ClassifierError::Parse)
    }
}

impl<C: GuardClassifier> MlClassifier for Guarded<C> {
    /// The emitted pairs for `text` (role: the configured default).
    fn classify(&self, text: &str) -> Vec<(GuardCategory, f32)> {
        self.outcome(&MlCall::new(text)).pairs()
    }

    /// The emitted pairs and the highest raw score (`None` when the call
    /// failed or the verdict was empty).
    fn classify_with_raw(&self, text: &str) -> (Vec<(GuardCategory, f32)>, Option<f32>) {
        let out = self.outcome(&MlCall::new(text));
        (out.pairs(), out.raw)
    }

    fn name(&self) -> &'static str {
        self.name
    }

    /// `Degraded` when the adapter reports it, while the isolated lane is
    /// degraded, or when a call failed within the cooldown; `Ok`
    /// otherwise.
    fn health(&self) -> MlHealth {
        if let MlHealth::Degraded(reason) = self.inner.health() {
            return MlHealth::Degraded(reason);
        }
        if let Some(reason) = self.lane.as_ref().and_then(|l| l.degraded_reason()) {
            return MlHealth::Degraded(format!("inference lane degraded: {reason}"));
        }
        match lock(&self.last_failure).as_ref() {
            Some((at, msg)) if at.elapsed() < self.cooldown => MlHealth::Degraded(format!(
                "a classification failed within the last {}s: {msg}",
                self.cooldown.as_secs()
            )),
            _ => MlHealth::Ok,
        }
    }

    /// Exact per-call outcome: typed failure, the adapter's chunking, the
    /// call's role and prompt context.
    fn classify_call(&self, call: &MlCall<'_>) -> MlOutcome {
        self.outcome(call)
    }
}

impl<C> fmt::Debug for Guarded<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Guarded")
            .field("name", &self.name)
            .field("threshold", &self.threshold)
            .field("category_thresholds", &self.category_thresholds)
            .field("fail_mode", &self.fail_mode)
            .field("timeout", &self.timeout)
            .field("role", &self.role)
            .field("chunking", &(self.max_chars, self.overlap))
            .field("isolated", &self.lane.is_some())
            .finish_non_exhaustive()
    }
}

impl<T: GuardClassifier + ?Sized> GuardClassifier for Box<T> {
    fn id(&self) -> &str {
        (**self).id()
    }
    fn capabilities(&self) -> &Capabilities {
        (**self).capabilities()
    }
    fn classify(&self, req: &ClassifyRequest<'_>) -> Result<Verdict, ClassifierError> {
        (**self).classify(req)
    }
    fn health(&self) -> MlHealth {
        (**self).health()
    }
}

impl<T: GuardClassifier + ?Sized> GuardClassifier for Arc<T> {
    fn id(&self) -> &str {
        (**self).id()
    }
    fn capabilities(&self) -> &Capabilities {
        (**self).capabilities()
    }
    fn classify(&self, req: &ClassifyRequest<'_>) -> Result<Verdict, ClassifierError> {
        (**self).classify(req)
    }
    fn health(&self) -> MlHealth {
        (**self).health()
    }
}

#[cfg(test)]
mod tests {
    use super::{Guarded, FAIL_CLOSED_LABEL};
    use crate::guard::category::GuardCategory;
    use crate::guard::classifier::{
        Capabilities, CategoryScore, ClassifierError, ClassifyRequest, GuardClassifier, Role,
        Verdict,
    };
    use crate::guard::ml::{FailMode, MlCall, MlClassifier, MlHealth};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// Scores by marker words; counts calls and records the longest text.
    struct Scripted {
        caps: Capabilities,
        calls: AtomicUsize,
        longest: AtomicUsize,
    }

    impl Scripted {
        fn new(caps: Capabilities) -> Self {
            Self {
                caps,
                calls: AtomicUsize::new(0),
                longest: AtomicUsize::new(0),
            }
        }
    }

    impl GuardClassifier for Scripted {
        fn id(&self) -> &str {
            "scripted"
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        fn classify(&self, req: &ClassifyRequest<'_>) -> Result<Verdict, ClassifierError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.longest
                .fetch_max(req.text.chars().count(), Ordering::SeqCst);
            if req.text.contains("FAIL") {
                return Err(ClassifierError::Unavailable("scripted outage".to_owned()));
            }
            if req.text.contains("NAN") {
                return Ok(Verdict::probability(vec![CategoryScore::new(
                    GuardCategory::Hate,
                    f32::NAN,
                    "x",
                )]));
            }
            let hate = if req.text.contains("HATE") { 0.9 } else { 0.1 };
            let violence = if req.text.contains("VIOLENT") {
                0.6
            } else {
                0.05
            };
            Ok(Verdict::probability(vec![
                CategoryScore::new(GuardCategory::Hate, hate, "S10"),
                CategoryScore::new(GuardCategory::Violence, violence, "S1"),
            ]))
        }
    }

    fn caps() -> Capabilities {
        Capabilities::new(vec![GuardCategory::Hate, GuardCategory::Violence])
    }

    #[test]
    fn thresholds_filter_emission_but_not_the_raw_score() {
        let g = Guarded::new(Scripted::new(caps())).with_threshold(0.5);
        let (pairs, raw) = g.classify_with_raw("HATE");
        assert_eq!(pairs, vec![(GuardCategory::Hate, 0.9)]);
        assert_eq!(raw, Some(0.9));
        let (pairs, raw) = g.classify_with_raw("calm");
        assert!(pairs.is_empty());
        assert_eq!(raw, Some(0.1));
        // a per-category override
        let g = g.with_category_threshold(GuardCategory::Violence, 0.55);
        let pairs = g.classify("HATE VIOLENT");
        assert_eq!(
            pairs,
            vec![(GuardCategory::Hate, 0.9), (GuardCategory::Violence, 0.6)]
        );
        assert_eq!(g.threshold_for(GuardCategory::Violence), 0.55);
        assert_eq!(g.threshold_for(GuardCategory::Hate), 0.5);
    }

    #[test]
    fn raw_labels_survive_into_the_outcome() {
        let g = Guarded::new(Scripted::new(caps()));
        let out = g.classify_call(&MlCall::new("HATE"));
        assert_eq!(out.scores[0].raw_label, "S10");
        assert!(out.failure.is_none());
    }

    #[test]
    fn chunking_follows_the_adapter_budget_not_the_global_one() {
        // 5,000 chars: the global budget would make 3 windows of 1,800;
        // an 8,000-char adapter gets ONE call with the whole text
        let text = "a ".repeat(2_500);
        let big = Guarded::new(Scripted::new(caps().with_chunking(8_000, 100)));
        let _ = big.classify(&text);
        assert_eq!(big.inner().calls.load(Ordering::SeqCst), 1);
        // a 1,000-char adapter: several windows, none longer than 1,000
        let small = Guarded::new(Scripted::new(caps().with_chunking(1_000, 100)));
        let _ = small.classify(&format!("{text}HATE"));
        assert!(small.inner().calls.load(Ordering::SeqCst) >= 5);
        assert!(small.inner().longest.load(Ordering::SeqCst) <= 1_000);
        // and the far-end marker is still found
        assert_eq!(
            small.classify(&format!("{text}HATE"))[0],
            (GuardCategory::Hate, 0.9)
        );
    }

    #[test]
    fn fail_closed_reports_every_category_and_the_failure() {
        let g = Guarded::new(Scripted::new(caps()));
        let out = g.classify_call(&MlCall::new("FAIL"));
        assert_eq!(
            out.pairs(),
            vec![(GuardCategory::Hate, 1.0), (GuardCategory::Violence, 1.0)]
        );
        assert!(out.scores.iter().all(|s| s.raw_label == FAIL_CLOSED_LABEL));
        assert_eq!(out.raw, None);
        assert_eq!(
            out.failure.as_ref().map(ClassifierError::kind),
            Some("unavailable")
        );
        assert!(matches!(g.health(), MlHealth::Degraded(r) if r.contains("scripted outage")));
    }

    #[test]
    fn fail_closed_without_declared_categories_still_blocks_via_ml_degraded() {
        let g = Guarded::new(Scripted::new(Capabilities::new(vec![])));
        let out = g.classify_call(&MlCall::new("FAIL"));
        assert_eq!(out.pairs(), vec![(GuardCategory::MlDegraded, 1.0)]);
        assert!(out.failure.is_some());
        // a healthy call of such an adapter emits only what it scored
        let out = g.classify_call(&MlCall::new("HATE"));
        assert_eq!(out.pairs(), vec![(GuardCategory::Hate, 0.9)]);
    }

    #[test]
    fn fail_closed_stops_at_the_first_failed_window_fail_open_continues() {
        let long = format!("FAIL{}HATE", " x".repeat(2_000));
        let closed = Guarded::new(Scripted::new(caps()));
        let _ = closed.classify(&long);
        assert_eq!(closed.inner().calls.load(Ordering::SeqCst), 1);
        let open = Guarded::new(Scripted::new(caps())).with_fail_mode(FailMode::Open);
        let out = open.classify_call(&MlCall::new(&long));
        assert!(open.inner().calls.load(Ordering::SeqCst) >= 2);
        // the windows that answered still count, and the failure is kept
        assert_eq!(out.pairs(), vec![(GuardCategory::Hate, 0.9)]);
        assert!(out.failure.is_some());
    }

    #[test]
    fn non_numeric_scores_are_a_parse_failure() {
        let g = Guarded::new(Scripted::new(caps())).with_fail_mode(FailMode::Open);
        let out = g.classify_call(&MlCall::new("NAN"));
        assert_eq!(out.failure, Some(ClassifierError::Parse));
    }

    #[test]
    fn unsupported_roles_are_skipped_without_a_failure() {
        let g = Guarded::new(Scripted::new(caps().with_roles(vec![Role::Prompt])));
        let out = g.classify_call(&MlCall::new("HATE").with_role(Role::Response));
        assert!(out.scores.is_empty() && out.failure.is_none());
        assert_eq!(g.inner().calls.load(Ordering::SeqCst), 0);
        // the configured default role applies to legacy calls
        let g = g.with_role(Role::Tool);
        assert!(g.classify("HATE").is_empty());
    }

    #[test]
    fn a_zero_timeout_fails_every_direct_call() {
        let g = Guarded::new(Scripted::new(caps())).with_timeout(Duration::ZERO);
        let out = g.classify_call(&MlCall::new("calm"));
        assert_eq!(
            out.failure.as_ref().map(ClassifierError::kind),
            Some("timeout")
        );
        assert_eq!(out.pairs().len(), 2, "fail-closed");
    }

    #[test]
    fn the_name_is_the_adapter_id_unless_overridden() {
        let g = Guarded::new(Scripted::new(caps()));
        assert_eq!(g.name(), "scripted");
        assert_eq!(g.with_name("custom").name(), "custom");
    }
}
