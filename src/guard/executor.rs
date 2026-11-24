//! Shared bounded-inference executor: one worker thread that owns an
//! inference engine, a hard per-call timeout, and the circuit breaker with
//! its half-open recovery probe.
//!
//! This is the machinery every ONNX model wrapper used privately
//! (`guard::onnx`), made generic over the engine's input and output types
//! so that any backend that cannot be interrupted mid-call (an ONNX
//! Runtime session, a blocking client, a plug-in classifier behind
//! [`Guarded::isolated`](crate::guard::guarded::Guarded::isolated)) gets the
//! same semantics:
//!
//! - Concurrent calls queue behind one another on the worker. A call waits
//!   for its job to START as long as the worker keeps making progress (an
//!   inference started or finished within the timeout), then at most its
//!   timeout for its own inference. A queued call therefore never fails
//!   because of load, so a verdict never depends on how busy the lane is.
//! - An inference that exceeds the timeout, a worker that made no progress
//!   within the timeout while a job was queued, or a dead worker DEGRADES
//!   the lane: every later call fails fast instead of queueing behind a
//!   stuck worker.
//! - Once the cooldown has elapsed, the next call starts ONE background
//!   half-open probe: a fresh engine and worker must answer the probe input
//!   within the timeout. Success swaps the new worker in and clears the
//!   degradation; failure restarts the cooldown. At most
//!   [`MAX_LANE_WORKERS`] worker threads (the current one plus one
//!   abandoned predecessor) are alive per lane.
//!
//! Module-private to the crate: the public surface is the classifiers that
//! use it.

use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// Default cooldown before a degraded lane is rebuilt (the public
/// `guard::onnx::RECOVERY_COOLDOWN` and the [`Guarded`] default).
///
/// [`Guarded`]: crate::guard::guarded::Guarded
pub(crate) const DEFAULT_COOLDOWN: Duration = Duration::from_secs(30);

/// Upper bound on live worker threads per lane: the current worker plus at
/// most one abandoned (possibly stuck) predecessor.
pub(crate) const MAX_LANE_WORKERS: usize = 2;

/// Locks `m`, recovering the data of a poisoned mutex. Shared by the ML
/// runtime modules: every critical section there leaves its data
/// consistent, and a guard must not turn one panicked thread into a
/// permanent failure.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a worker answers for one job.
pub(crate) type JobResult<O> = Result<O, String>;

/// A worker's answer plus how long the inference itself took, measured on
/// the worker. The caller judges the timeout on this duration, not on when
/// it happens to read the answer: a caller that wakes up late (a loaded
/// host) must not accept an inference that exceeded the bound.
type JobAnswer<O> = (JobResult<O>, Duration);

/// The inference backend a lane worker owns.
pub(crate) trait Engine<I, O>: Send {
    /// Runs one inference; the input is moved in (no copy on the hot
    /// path).
    fn run(&mut self, input: I) -> JobResult<O>;
}

/// Builds a fresh engine; called by every half-open recovery probe. The
/// error is a human-readable message (never input text).
pub(crate) type EngineFactory<I, O> =
    dyn Fn() -> Result<Box<dyn Engine<I, O>>, String> + Send + Sync;

/// Where a job stands; shared by its caller and the worker (state changes
/// happen under the mutex, so caller and worker never disagree).
#[derive(Clone, Copy)]
enum JobState {
    /// Waiting in the worker's queue.
    Queued,
    /// The worker started its inference at this instant.
    Started(Instant),
    /// Dropped unstarted: its caller stopped waiting for it to start.
    Abandoned,
}

/// One inference job, answered over `resp`.
struct Job<I, O> {
    input: I,
    state: Arc<Mutex<JobState>>,
    resp: Sender<JobAnswer<O>>,
}

/// One worker thread as its lane sees it: the job queue and the worker's
/// progress clock (when it last started or finished an inference; its
/// spawn time before the first job).
pub(crate) struct Worker<I, O> {
    tx: Sender<Job<I, O>>,
    progress: Arc<Mutex<Instant>>,
}

/// Decrements the lane's live-worker count when a worker thread ends
/// (normal exit or unwinding panic), after its engine has been dropped.
struct LiveWorker(Arc<AtomicUsize>);

impl Drop for LiveWorker {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Worker loop: serves jobs until every sender is gone (the lane was
/// rebuilt or its owner dropped).
///
/// A dropped response receiver (the caller timed out) is NOT a reason to
/// stop: stopping there would kill the lane for good. A job that was
/// abandoned (its caller stopped waiting) is skipped instead of inferred.
/// `progress` is stamped when an inference starts and finishes; the answer
/// carries the inference's own duration ([`JobAnswer`]).
fn serve<I, O>(
    mut engine: Box<dyn Engine<I, O>>,
    rx: Receiver<Job<I, O>>,
    progress: &Mutex<Instant>,
) {
    for Job { input, state, resp } in rx {
        let started = {
            let mut state = lock(&state);
            if matches!(*state, JobState::Abandoned) {
                continue; // nobody waits for it; dropping `job` closes its channel
            }
            let now = Instant::now();
            *state = JobState::Started(now);
            *lock(progress) = now;
            now
        };
        let out = engine.run(input);
        let finished = Instant::now();
        *lock(progress) = finished;
        // receiver gone = caller timed out; keep serving
        let _ = resp.send((out, finished.saturating_duration_since(started)));
    }
}

/// Spawns a dedicated worker thread named `name` that owns `engine`.
/// `live` counts the lane's live worker threads.
pub(crate) fn spawn_worker<I: Send + 'static, O: Send + 'static>(
    engine: Box<dyn Engine<I, O>>,
    live: &Arc<AtomicUsize>,
    name: &'static str,
) -> std::io::Result<Worker<I, O>> {
    let (tx, rx) = mpsc::channel();
    let progress = Arc::new(Mutex::new(Instant::now()));
    let worker_progress = Arc::clone(&progress);
    live.fetch_add(1, Ordering::AcqRel);
    // moved into the thread; also dropped (decrementing) if spawning fails
    let guard = LiveWorker(Arc::clone(live));
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let _live = guard;
            serve(engine, rx, &worker_progress);
        })?;
    Ok(Worker { tx, progress })
}

/// A sent job awaiting its answer.
pub(crate) struct Pending<O> {
    rx: Receiver<JobAnswer<O>>,
    state: Arc<Mutex<JobState>>,
    /// The progress clock of the worker the job was sent to.
    progress: Arc<Mutex<Instant>>,
}

/// Outcome of one job round-trip.
pub(crate) enum RoundTrip<O> {
    /// The worker answered (with outputs or an inference error).
    Answered(JobResult<O>),
    /// The job's own inference exceeded the timeout.
    TimedOut,
    /// The job was still queued and the worker made no progress within the
    /// timeout: the worker is stuck or starved.
    Stalled,
    /// The worker is gone (its thread exited or panicked).
    WorkerGone,
}

/// Sends one job; `None` when the worker no longer receives.
pub(crate) fn dispatch<I, O>(worker: &Worker<I, O>, input: I) -> Option<Pending<O>> {
    let (resp, rx) = mpsc::channel();
    let state = Arc::new(Mutex::new(JobState::Queued));
    worker
        .tx
        .send(Job {
            input,
            state: Arc::clone(&state),
            resp,
        })
        .ok()?;
    Some(Pending {
        rx,
        state,
        progress: Arc::clone(&worker.progress),
    })
}

impl<O> Pending<O> {
    /// Waits for the job to start as long as the worker keeps making
    /// progress (an inference started or finished within `timeout`), then
    /// until `timeout` after its start for the answer: the queue wait
    /// behind other callers never counts against the inference itself, and
    /// a call never fails merely because the lane is busy.
    ///
    /// Every answer is judged on the inference duration the worker measured
    /// ([`judge`]), so the bound holds even when this thread reads the
    /// answer late.
    pub(crate) fn wait(&self, timeout: Duration) -> RoundTrip<O> {
        let started = loop {
            match self.rx.recv_timeout(timeout) {
                Ok(answer) => return judge(answer, timeout),
                // dropped unanswered: the worker died (mid-job, or with
                // this job still in its queue)
                Err(RecvTimeoutError::Disconnected) => return RoundTrip::WorkerGone,
                Err(RecvTimeoutError::Timeout) => {
                    // lock order state -> progress, as in `serve`
                    let mut state = lock(&self.state);
                    match *state {
                        JobState::Started(at) => break at,
                        JobState::Queued if lock(&self.progress).elapsed() < timeout => {}
                        JobState::Queued | JobState::Abandoned => {
                            *state = JobState::Abandoned; // the worker skips it
                            return RoundTrip::Stalled;
                        }
                    }
                }
            }
        };
        let left = started
            .checked_add(timeout)
            .map_or(timeout, |end| end.saturating_duration_since(Instant::now()));
        match self.rx.recv_timeout(left) {
            Ok(answer) => judge(answer, timeout),
            Err(RecvTimeoutError::Timeout) => RoundTrip::TimedOut,
            Err(RecvTimeoutError::Disconnected) => RoundTrip::WorkerGone,
        }
    }
}

/// An answer counts only when its inference fit the bound: an inference
/// that took longer than `timeout` is a timeout however soon the caller
/// reads it, and a zero bound admits no inference at all.
fn judge<O>((result, took): JobAnswer<O>, timeout: Duration) -> RoundTrip<O> {
    if timeout.is_zero() || took > timeout {
        RoundTrip::TimedOut
    } else {
        RoundTrip::Answered(result)
    }
}

impl<O> Drop for Pending<O> {
    /// A caller that stops waiting (any exit, a panic included) abandons
    /// its job if it has not started, so the worker never infers it.
    fn drop(&mut self) {
        let mut state = lock(&self.state);
        if matches!(*state, JobState::Queued) {
            *state = JobState::Abandoned;
        }
    }
}

/// Degradation record of a lane.
struct Degradation {
    since: Instant,
    reason: String,
}

/// Mutable lane state.
#[derive(Default)]
pub(crate) struct LaneState {
    /// `Some` while the lane is degraded (calls fail fast).
    degraded: Option<Degradation>,
    /// A half-open recovery probe is running in the background.
    pub(crate) probing: bool,
    /// Successful recoveries so far.
    pub(crate) recoveries: u64,
}

/// Why a lane call failed. The lane-level variants are already recorded in
/// the lane state; every message is human-readable and never carries input.
pub(crate) enum LaneError {
    /// The inference exceeded the timeout, or the worker made no progress
    /// within it (the lane is now degraded).
    TimedOut(String),
    /// The worker is gone, or the lane is degraded and failing fast.
    Unavailable(String),
    /// The worker answered with an inference error; the lane is healthy.
    Call(String),
}

/// Thread names of a lane: the worker and the recovery probe.
#[derive(Clone, Copy)]
pub(crate) struct LaneNames {
    pub(crate) worker: &'static str,
    pub(crate) probe: &'static str,
}

/// The inference lane: one worker thread owning the engine, the request
/// channel, and the degradation / recovery state machine described in the
/// module docs.
///
/// Lock order: `state` before `current`; `current` alone is held only for a
/// non-blocking send.
pub(crate) struct Lane<I, O> {
    /// `(generation, worker)` of the current worker. The generation grows
    /// with every successful rebuild, so a late timeout of a job sent to a
    /// replaced worker never degrades its successor.
    current: Mutex<(u64, Worker<I, O>)>,
    pub(crate) state: Mutex<LaneState>,
    /// Builds a fresh engine for the half-open probe.
    factory: Box<EngineFactory<I, O>>,
    /// Probe input (the construction warmup input).
    probe: I,
    /// Live worker threads (current + abandoned), kept by the workers.
    pub(crate) live_workers: Arc<AtomicUsize>,
    /// [`DEFAULT_COOLDOWN`] in production; shortened by the unit tests.
    cooldown: Duration,
    /// Thread names.
    names: LaneNames,
}

impl<I, O> Lane<I, O>
where
    I: Clone + Send + Sync + 'static,
    O: Send + 'static,
{
    /// Starts a lane whose first worker owns `engine`.
    ///
    /// # Errors
    /// The worker thread cannot be spawned.
    pub(crate) fn new(
        engine: Box<dyn Engine<I, O>>,
        factory: Box<EngineFactory<I, O>>,
        probe: I,
        cooldown: Duration,
        names: LaneNames,
    ) -> std::io::Result<Arc<Self>> {
        let live_workers = Arc::new(AtomicUsize::new(0));
        let worker = spawn_worker(engine, &live_workers, names.worker)?;
        Ok(Arc::new(Self {
            current: Mutex::new((0, worker)),
            state: Mutex::new(LaneState::default()),
            factory,
            probe,
            live_workers,
            cooldown,
            names,
        }))
    }

    /// Runs one inference: waiting for it to start while the worker makes
    /// progress and at most `timeout` for the inference itself (see
    /// [`Pending::wait`]).
    pub(crate) fn call(self: &Arc<Self>, input: I, timeout: Duration) -> Result<O, LaneError> {
        self.admit(timeout).map_err(LaneError::Unavailable)?;
        let (generation, pending) = {
            let current = lock(&self.current);
            (current.0, dispatch(&current.1, input))
        };
        let outcome = match pending {
            Some(p) => p.wait(timeout),
            None => RoundTrip::WorkerGone,
        };
        match outcome {
            RoundTrip::Answered(Ok(out)) => Ok(out),
            RoundTrip::Answered(Err(e)) => Err(LaneError::Call(e)),
            RoundTrip::TimedOut => Err(LaneError::TimedOut(self.degrade(
                generation,
                format!("inference exceeded the {timeout:?} timeout"),
            ))),
            RoundTrip::Stalled => Err(LaneError::TimedOut(self.degrade(
                generation,
                format!("inference worker made no progress within the {timeout:?} timeout"),
            ))),
            RoundTrip::WorkerGone => Err(LaneError::Unavailable(
                self.degrade(generation, "inference worker died".to_owned()),
            )),
        }
    }

    /// Lets a call through on a healthy lane. While degraded, fails fast;
    /// once the cooldown has elapsed (and no abandoned worker is still
    /// alive) it starts the ONE background half-open probe first.
    fn admit(self: &Arc<Self>, timeout: Duration) -> Result<(), String> {
        let mut st = lock(&self.state);
        let Some(deg) = st.degraded.as_ref() else {
            return Ok(());
        };
        let reason = deg.reason.clone();
        if st.probing {
            return Err(format!(
                "inference lane degraded ({reason}); recovery probe running"
            ));
        }
        if deg.since.elapsed() < self.cooldown {
            return Err(format!(
                "inference lane degraded ({reason}); failing fast until the {:?} recovery cooldown elapses",
                self.cooldown
            ));
        }
        if self.live_workers.load(Ordering::Acquire) >= MAX_LANE_WORKERS {
            return Err(format!(
                "inference lane degraded ({reason}); recovery deferred while an abandoned worker is still running"
            ));
        }
        st.probing = true;
        drop(st);
        let lane = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name(self.names.probe.into())
            .spawn(move || lane.probe(timeout));
        if spawned.is_err() {
            // no probe thread: stay degraded and try again after a cooldown
            let mut st = lock(&self.state);
            st.probing = false;
            if let Some(d) = st.degraded.as_mut() {
                d.since = Instant::now();
            }
        }
        Err(format!(
            "inference lane degraded ({reason}); recovery probe started"
        ))
    }

    /// Half-open probe (background thread): build a fresh engine + worker
    /// and require one probe answer within `timeout`. Success swaps the new
    /// worker in (the old sender is dropped, so the old worker exits once
    /// its current inference returns) and clears the degradation; failure
    /// restarts the cooldown and abandons the new worker instead.
    fn probe(&self, timeout: Duration) {
        // a panic while rebuilding (engine factory, worker spawn) fails the
        // probe like any other error: left uncaught it would end this thread
        // with `probing` still set, wedging the lane in "recovery probe
        // running" for good
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| self.build_and_check(timeout)))
            .unwrap_or_else(|_| Err("the rebuild panicked".to_owned()));
        let mut st = lock(&self.state);
        st.probing = false;
        match outcome {
            Ok(worker) => {
                {
                    let mut current = lock(&self.current);
                    current.0 = current.0.wrapping_add(1);
                    current.1 = worker;
                }
                st.degraded = None;
                st.recoveries += 1;
            }
            Err(reason) => {
                st.degraded = Some(Degradation {
                    since: Instant::now(),
                    reason: format!("recovery probe failed: {reason}"),
                });
            }
        }
    }

    fn build_and_check(&self, timeout: Duration) -> Result<Worker<I, O>, String> {
        let engine = (self.factory)().map_err(|e| format!("rebuild failed: {e}"))?;
        let worker = spawn_worker(engine, &self.live_workers, self.names.worker)
            .map_err(|_| "cannot spawn the inference worker thread".to_owned())?;
        let outcome = match dispatch(&worker, self.probe.clone()) {
            Some(p) => p.wait(timeout),
            None => RoundTrip::WorkerGone,
        };
        // on any error `worker` is dropped here: the new worker exits as
        // soon as its current inference (if any) returns
        match outcome {
            RoundTrip::Answered(Ok(_)) => Ok(worker),
            RoundTrip::Answered(Err(e)) => Err(format!("warmup inference failed: {e}")),
            RoundTrip::TimedOut => {
                Err(format!("warmup inference exceeded the {timeout:?} timeout"))
            }
            // the fresh worker's only job: it never started within the timeout
            RoundTrip::Stalled => Err(format!(
                "warmup inference not started within the {timeout:?} timeout"
            )),
            RoundTrip::WorkerGone => Err("the new inference worker died".to_owned()),
        }
    }

    /// Marks the lane degraded (the first failure wins; a failure of a job
    /// sent to an already replaced worker is ignored) and returns the
    /// caller-facing message.
    pub(crate) fn degrade(&self, generation: u64, reason: String) -> String {
        let mut st = lock(&self.state);
        if st.degraded.is_none() && lock(&self.current).0 == generation {
            st.degraded = Some(Degradation {
                since: Instant::now(),
                reason: reason.clone(),
            });
        }
        if st.degraded.is_some() {
            format!(
                "{reason} (inference lane degraded: later calls fail fast; recovery probe after the {:?} cooldown)",
                self.cooldown
            )
        } else {
            reason
        }
    }

    /// The degradation reason (with the recovery status), or `None` when the
    /// lane is healthy.
    pub(crate) fn degraded_reason(&self) -> Option<String> {
        let st = lock(&self.state);
        st.degraded.as_ref().map(|d| {
            if st.probing {
                format!("{}; recovery probe running", d.reason)
            } else if d.since.elapsed() >= self.cooldown
                && self.live_workers.load(Ordering::Acquire) >= MAX_LANE_WORKERS
            {
                format!(
                    "{}; recovery deferred while an abandoned worker is still running",
                    d.reason
                )
            } else {
                d.reason.clone()
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        dispatch, lock, spawn_worker, Engine, EngineFactory, JobResult, Lane, LaneError, LaneNames,
        RoundTrip, MAX_LANE_WORKERS,
    };
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const TIMEOUT: Duration = Duration::from_millis(40);
    const COOLDOWN: Duration = Duration::from_millis(150);
    const PATIENCE: Duration = Duration::from_secs(5);
    const NAMES: LaneNames = LaneNames {
        worker: "redactify-test-infer",
        probe: "redactify-test-recover",
    };

    /// The ONNX lane's shapes: token ids + mask in, named outputs out.
    type Input = (Vec<i64>, Vec<i64>);
    type Outputs = Vec<(String, Vec<i64>, Vec<f32>)>;
    type TestLane = Lane<Input, Outputs>;

    /// Knobs shared by every scripted engine of one lane: the
    /// slow-worker hook (no model files needed).
    #[derive(Default)]
    struct Script {
        delay_ms: AtomicU64,
        panic_next: AtomicBool,
        fail_build: AtomicBool,
        panic_build: AtomicBool,
        builds: AtomicUsize,
        started: AtomicUsize,
        finished: AtomicUsize,
    }

    struct Scripted(Arc<Script>);

    impl Engine<Input, Outputs> for Scripted {
        fn run(&mut self, (ids, _mask): Input) -> JobResult<Outputs> {
            self.0.started.fetch_add(1, Ordering::SeqCst);
            if self.0.panic_next.swap(false, Ordering::SeqCst) {
                panic!("scripted inference worker crash");
            }
            let ms = self.0.delay_ms.load(Ordering::SeqCst);
            if ms > 0 {
                std::thread::sleep(Duration::from_millis(ms));
            }
            self.0.finished.fetch_add(1, Ordering::SeqCst);
            Ok(vec![(
                "logits".to_owned(),
                vec![1, 2],
                vec![0.0, ids.len() as f32],
            )])
        }
    }

    fn lane(script: &Arc<Script>) -> Arc<TestLane> {
        let s = Arc::clone(script);
        let factory: Box<EngineFactory<Input, Outputs>> = Box::new(move || {
            s.builds.fetch_add(1, Ordering::SeqCst);
            assert!(
                !s.panic_build.load(Ordering::SeqCst),
                "scripted engine factory crash"
            );
            if s.fail_build.load(Ordering::SeqCst) {
                return Err("scripted build failure".to_owned());
            }
            Ok(Box::new(Scripted(Arc::clone(&s))) as Box<dyn Engine<Input, Outputs>>)
        });
        Lane::new(
            Box::new(Scripted(Arc::clone(script))),
            factory,
            (vec![1], vec![1]),
            COOLDOWN,
            NAMES,
        )
        .expect("lane starts")
    }

    fn call(l: &Arc<TestLane>) -> Result<f32, String> {
        call_with(l, TIMEOUT)
    }

    fn call_with(l: &Arc<TestLane>, timeout: Duration) -> Result<f32, String> {
        l.call((vec![7, 8, 9], vec![1, 1, 1]), timeout)
            .map(|outs| outs[0].2[1])
            .map_err(|e| match e {
                LaneError::TimedOut(m) | LaneError::Unavailable(m) | LaneError::Call(m) => m,
            })
    }

    /// Polls `cond` until it holds or [`PATIENCE`] runs out.
    fn eventually(mut cond: impl FnMut() -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < PATIENCE {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        cond()
    }

    fn live(l: &TestLane) -> usize {
        l.live_workers.load(Ordering::SeqCst)
    }

    /// Times out one call on a worker that sleeps `ms`.
    fn degrade_with_slow_job(s: &Script, l: &Arc<TestLane>, ms: u64) {
        s.delay_ms.store(ms, Ordering::SeqCst);
        let err = call(l).expect_err("the slow job must time out");
        assert!(err.contains("timeout"), "{err}");
        assert!(l.degraded_reason().is_some());
    }

    /// A worker that has already answered, waited on by a caller that
    /// arrives `late_ms` after the answer (scheduler delay on a loaded
    /// host): the answer may count only if the inference itself fit the
    /// timeout, whenever the caller looks.
    fn late_wait(delay_ms: u64, late_ms: u64, timeout: Duration) -> RoundTrip<Outputs> {
        let s = Arc::new(Script::default());
        s.delay_ms.store(delay_ms, Ordering::SeqCst);
        let live = Arc::new(AtomicUsize::new(0));
        let worker = spawn_worker(
            Box::new(Scripted(Arc::clone(&s))) as Box<dyn Engine<Input, Outputs>>,
            &live,
            NAMES.worker,
        )
        .expect("worker");
        let pending = dispatch(&worker, (vec![1], vec![1])).expect("dispatched");
        assert!(eventually(|| s.finished.load(Ordering::SeqCst) == 1));
        std::thread::sleep(Duration::from_millis(late_ms));
        pending.wait(timeout)
    }

    #[test]
    fn a_late_caller_rejects_an_inference_that_exceeded_the_timeout() {
        // a 60 ms inference against the 40 ms bound: the answer is
        // already in the channel when the caller looks
        assert!(matches!(late_wait(60, 20, TIMEOUT), RoundTrip::TimedOut));
    }

    #[test]
    fn a_late_caller_keeps_an_inference_that_fit_the_timeout() {
        assert!(matches!(
            late_wait(0, 20, TIMEOUT),
            RoundTrip::Answered(Ok(_))
        ));
    }

    #[test]
    fn a_zero_timeout_fails_even_an_answer_that_is_already_there() {
        assert!(matches!(
            late_wait(0, 20, Duration::ZERO),
            RoundTrip::TimedOut
        ));
    }

    #[test]
    fn healthy_lane_answers_within_the_timeout() {
        let s = Arc::new(Script::default());
        let l = lane(&s);
        assert_eq!(call(&l), Ok(3.0));
        assert!(l.degraded_reason().is_none());
        assert_eq!(live(&l), 1);
    }

    #[test]
    fn worker_survives_a_caller_that_timed_out() {
        // the worker must not `break` when the timed-out caller has
        // dropped its receiver: that would kill the lane for good
        let s = Arc::new(Script::default());
        let l = lane(&s);
        degrade_with_slow_job(&s, &l, 300);
        assert!(eventually(|| s.finished.load(Ordering::SeqCst) == 1));
        std::thread::sleep(Duration::from_millis(50)); // room for a wrong exit
        assert_eq!(live(&l), 1, "the worker exited after an unanswerable job");
    }

    #[test]
    fn degraded_lane_fails_fast_then_recovers_after_the_cooldown() {
        let s = Arc::new(Script::default());
        let l = lane(&s);
        degrade_with_slow_job(&s, &l, 300);
        s.delay_ms.store(0, Ordering::SeqCst);

        // within the cooldown: fail fast, no rebuild
        let t0 = Instant::now();
        let err = call(&l).unwrap_err();
        assert!(t0.elapsed() < TIMEOUT, "degraded calls must not wait");
        assert!(err.contains("failing fast"), "{err}");
        assert_eq!(s.builds.load(Ordering::SeqCst), 0);

        // after the cooldown: ONE background half-open probe; the
        // triggering call itself still fails fast
        std::thread::sleep(COOLDOWN);
        let err = call(&l).unwrap_err();
        assert!(err.contains("recovery probe started"), "{err}");
        assert!(eventually(|| l.degraded_reason().is_none()), "no recovery");
        assert_eq!(s.builds.load(Ordering::SeqCst), 1);
        assert_eq!(lock(&l.state).recoveries, 1);
        assert_eq!(call(&l), Ok(3.0));

        // the replaced worker exits once its stuck job has returned
        assert!(
            eventually(|| live(&l) == 1),
            "abandoned worker never exited"
        );

        // a late failure of a job sent to the replaced generation is
        // ignored instead of degrading the fresh lane
        let _ = l.degrade(0, "late timeout of a replaced worker".to_owned());
        assert!(l.degraded_reason().is_none());
    }

    #[test]
    fn failed_probe_restarts_the_cooldown() {
        let s = Arc::new(Script::default());
        let l = lane(&s);
        degrade_with_slow_job(&s, &l, 200);
        s.delay_ms.store(0, Ordering::SeqCst);
        s.fail_build.store(true, Ordering::SeqCst);

        std::thread::sleep(COOLDOWN);
        assert!(call(&l).unwrap_err().contains("recovery probe started"));
        assert!(eventually(|| l
            .degraded_reason()
            .is_some_and(|r| r.contains("recovery probe failed"))));
        assert_eq!(s.builds.load(Ordering::SeqCst), 1);

        // the cooldown restarted: no second probe right away
        let err = call(&l).unwrap_err();
        assert!(err.contains("failing fast"), "{err}");
        assert_eq!(s.builds.load(Ordering::SeqCst), 1);

        s.fail_build.store(false, Ordering::SeqCst);
        std::thread::sleep(COOLDOWN);
        let _ = call(&l);
        assert!(eventually(|| l.degraded_reason().is_none()));
        assert_eq!(s.builds.load(Ordering::SeqCst), 2);
        assert_eq!(call(&l), Ok(3.0));
    }

    #[test]
    fn rebuild_is_deferred_while_an_abandoned_worker_is_alive() {
        let s = Arc::new(Script::default());
        let l = lane(&s);
        // W1 stuck for 800 ms
        degrade_with_slow_job(&s, &l, 800);

        // the probe's fresh worker W2 is just as slow: its warmup times
        // out, the probe fails and W2 is abandoned (still running)
        std::thread::sleep(COOLDOWN);
        assert!(call(&l).unwrap_err().contains("recovery probe started"));
        assert!(eventually(|| l
            .degraded_reason()
            .is_some_and(|r| r.contains("recovery probe failed"))));
        assert_eq!(live(&l), MAX_LANE_WORKERS);

        // next cooldown: two live workers, so no third session is built
        std::thread::sleep(COOLDOWN);
        let err = call(&l).unwrap_err();
        assert!(err.contains("recovery deferred"), "{err}");
        assert!(l
            .degraded_reason()
            .is_some_and(|r| r.contains("recovery deferred")));
        assert_eq!(s.builds.load(Ordering::SeqCst), 1);
        assert!(live(&l) <= MAX_LANE_WORKERS);

        // once the abandoned worker has exited, recovery proceeds
        s.delay_ms.store(0, Ordering::SeqCst);
        assert!(eventually(|| {
            let _ = call(&l);
            l.degraded_reason().is_none()
        }));
        assert_eq!(s.builds.load(Ordering::SeqCst), 2);
        assert_eq!(call(&l), Ok(3.0));
        assert!(eventually(|| live(&l) == 1));
    }

    #[test]
    fn dead_worker_degrades_the_lane_and_is_rebuilt() {
        let s = Arc::new(Script::default());
        let l = lane(&s);
        s.panic_next.store(true, Ordering::SeqCst);
        // a generous budget for the panicking call: under a loaded test run
        // the unwind can take longer than TIMEOUT, and the call then reports
        // a timeout instead of the dead worker this test is about
        let err = call_with(&l, Duration::from_millis(500)).unwrap_err();
        assert!(err.contains("worker died"), "{err}");
        assert!(l.degraded_reason().is_some());
        assert!(eventually(|| live(&l) == 0));

        std::thread::sleep(COOLDOWN);
        let _ = call(&l);
        assert!(eventually(|| l.degraded_reason().is_none()));
        assert_eq!(call(&l), Ok(3.0));
    }

    #[test]
    fn stale_jobs_behind_a_stuck_one_are_skipped() {
        let s = Arc::new(Script::default());
        let l = lane(&s);
        s.delay_ms.store(300, Ordering::SeqCst);
        let callers: Vec<_> = (0..3)
            .map(|_| {
                let l = Arc::clone(&l);
                std::thread::spawn(move || {
                    let t = Instant::now();
                    (call(&l), t.elapsed())
                })
            })
            .collect();
        for c in callers {
            let (result, waited) = c.join().expect("caller thread");
            assert!(result.is_err());
            // a queued caller does not wait for a stuck worker
            assert!(waited < Duration::from_millis(250), "{waited:?}");
        }
        assert!(eventually(|| s.finished.load(Ordering::SeqCst) == 1));
        std::thread::sleep(Duration::from_millis(50));
        // queued jobs whose callers gave up are never inferred
        assert_eq!(s.started.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn input_level_errors_do_not_degrade_the_lane() {
        struct Failing;
        impl Engine<Input, Outputs> for Failing {
            fn run(&mut self, _input: Input) -> JobResult<Outputs> {
                Err("onnxruntime: scripted input error".to_owned())
            }
        }
        let factory: Box<EngineFactory<Input, Outputs>> =
            Box::new(|| Ok(Box::new(Failing) as Box<dyn Engine<Input, Outputs>>));
        let l = Lane::new(
            Box::new(Failing),
            factory,
            (vec![1], vec![1]),
            COOLDOWN,
            NAMES,
        )
        .expect("lane starts");
        for _ in 0..3 {
            match l.call((vec![1], vec![1]), TIMEOUT) {
                Err(LaneError::Call(m)) => assert!(m.contains("scripted input error")),
                _ => panic!("expected an input-level error"),
            }
        }
        assert!(
            l.degraded_reason().is_none(),
            "a bad input must not block everyone"
        );
    }

    #[test]
    fn queued_callers_wait_for_a_lane_that_is_making_progress() {
        // a burst of legitimate concurrent calls, each inference well
        // inside the timeout, must neither degrade the lane nor fail the
        // queue tail as "lane busy" (the fail mode would turn that into a
        // load-dependent verdict): callers wait while the worker makes
        // progress
        const BURST_TIMEOUT: Duration = Duration::from_millis(500);
        let s = Arc::new(Script::default());
        let l = lane(&s);
        s.delay_ms.store(40, Ordering::SeqCst); // 16 x 40 ms > 500 ms
        let callers: Vec<_> = (0..16)
            .map(|_| {
                let l = Arc::clone(&l);
                std::thread::spawn(move || call_with(&l, BURST_TIMEOUT))
            })
            .collect();
        let results: Vec<Result<f32, String>> = callers
            .into_iter()
            .map(|c| c.join().expect("caller thread"))
            .collect();
        assert!(
            l.degraded_reason().is_none(),
            "no inference exceeded the timeout, yet the lane degraded: {:?}",
            l.degraded_reason()
        );
        assert!(
            results.iter().all(|r| *r == Ok(3.0)),
            "a healthy lane failed queued calls: {results:?}"
        );
        assert_eq!(s.finished.load(Ordering::SeqCst), 16);
        // the lane keeps serving at full speed
        s.delay_ms.store(0, Ordering::SeqCst);
        assert_eq!(call(&l), Ok(3.0));
    }

    #[test]
    fn a_panicking_rebuild_fails_the_probe_instead_of_wedging_it() {
        // an engine factory that panics inside the probe thread must not
        // leave `probing` set forever (degraded for good, health stuck at
        // "recovery probe running")
        let s = Arc::new(Script::default());
        let l = lane(&s);
        degrade_with_slow_job(&s, &l, 200);
        s.delay_ms.store(0, Ordering::SeqCst);
        s.panic_build.store(true, Ordering::SeqCst);

        std::thread::sleep(COOLDOWN);
        assert!(call(&l).unwrap_err().contains("recovery probe started"));
        assert!(
            eventually(|| l
                .degraded_reason()
                .is_some_and(|r| r.contains("recovery probe failed"))),
            "{:?}",
            l.degraded_reason()
        );
        assert!(!lock(&l.state).probing);
        assert_eq!(s.builds.load(Ordering::SeqCst), 1);

        // the next cooldown rebuilds normally
        s.panic_build.store(false, Ordering::SeqCst);
        std::thread::sleep(COOLDOWN);
        let _ = call(&l);
        assert!(eventually(|| l.degraded_reason().is_none()));
        assert_eq!(s.builds.load(Ordering::SeqCst), 2);
        assert_eq!(call(&l), Ok(3.0));
    }

    #[test]
    fn lane_errors_carry_their_kind() {
        // the typed variants let callers map a timeout and an unavailable
        // lane to distinct classifier errors (ML_DEGRADED rationale)
        let s = Arc::new(Script::default());
        let l = lane(&s);
        s.delay_ms.store(200, Ordering::SeqCst);
        assert!(matches!(
            l.call((vec![1], vec![1]), TIMEOUT),
            Err(LaneError::TimedOut(_))
        ));
        assert!(matches!(
            l.call((vec![1], vec![1]), TIMEOUT),
            Err(LaneError::Unavailable(m)) if m.contains("failing fast")
        ));
    }
}
