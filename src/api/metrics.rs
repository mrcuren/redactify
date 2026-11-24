//! Prometheus metrics of the REST server (`GET /metrics`), written by hand
//! in the text exposition format 0.0.4
//! (<https://prometheus.io/docs/instrumenting/exposition_formats/>,
//! retrieved 2026-11-24): one `# HELP` and one `# TYPE` line per metric
//! family, every sample of a family grouped after them, histogram buckets
//! cumulative in increasing `le` order ending with `le="+Inf"` (equal to
//! `_count`), and a line feed after the last line.
//!
//! Labels are value-free by construction: an endpoint is one of the
//! server's fixed paths (anything else is `other`), a status is an HTTP
//! status code, an action is a decision or entity action label, and an
//! entity type is a canonical label (built-in, or a custom label the
//! server policy registered: a request can never register one). No label
//! ever carries request text.
//!
//! Cost: the request path records into fixed arrays of atomic counters
//! (no lock, no allocation); only a decision that found entities takes a
//! short-lived lock to add its per-type counts.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use crate::policy::{Decision, GuardAction};

/// The router's endpoint lists, GET first: an endpoint's position is its
/// counter slot, and slot [`OTHER_SLOT`] collects unknown paths.
const ROUTES: [&[&str]; 2] = [super::GET_ENDPOINTS, super::POST_ENDPOINTS];

/// The slot of unknown paths (after every routed endpoint).
const OTHER_SLOT: usize = super::GET_ENDPOINTS.len() + super::POST_ENDPOINTS.len();

/// The number of endpoint slots (every routed endpoint plus `other`).
const ENDPOINT_SLOTS: usize = OTHER_SLOT + 1;

/// Every endpoint label in slot order, `other` last.
fn endpoint_labels() -> impl Iterator<Item = &'static str> {
    ROUTES
        .into_iter()
        .flatten()
        .copied()
        .chain(std::iter::once("other"))
}

/// The status codes counted on their own; any other code counts as
/// `other`.
const STATUSES: &[u16] = &[200, 400, 401, 404, 405, 413, 500];

/// The decision action labels (index = slot).
const ACTIONS: &[GuardAction] = &[
    GuardAction::Allow,
    GuardAction::Log,
    GuardAction::Mask,
    GuardAction::Block,
];

/// Upper bounds of the latency histogram, in seconds (the label text and
/// the bound in nanoseconds).
const BUCKETS: &[(&str, u64)] = &[
    ("0.0005", 500_000),
    ("0.001", 1_000_000),
    ("0.0025", 2_500_000),
    ("0.005", 5_000_000),
    ("0.01", 10_000_000),
    ("0.025", 25_000_000),
    ("0.05", 50_000_000),
    ("0.1", 100_000_000),
    ("0.25", 250_000_000),
    ("0.5", 500_000_000),
    ("1", 1_000_000_000),
    ("2.5", 2_500_000_000),
    ("5", 5_000_000_000),
];

/// The slot of an endpoint path (`other` for an unknown one).
fn endpoint_slot(path: &str) -> usize {
    ROUTES
        .into_iter()
        .flatten()
        .position(|p| *p == path)
        .unwrap_or(OTHER_SLOT)
}

/// The slot of a status code (`STATUSES.len()` = other).
fn status_slot(status: u16) -> usize {
    STATUSES
        .iter()
        .position(|s| *s == status)
        .unwrap_or(STATUSES.len())
}

/// The slot of a decision action (`None` for an action this server does
/// not know: the enum is non-exhaustive).
fn action_slot(action: GuardAction) -> Option<usize> {
    ACTIONS.iter().position(|a| *a == action)
}

/// A fixed-size array of zeroed atomic counters.
fn counters(n: usize) -> Box<[AtomicU64]> {
    (0..n).map(|_| AtomicU64::new(0)).collect()
}

/// The server's metric registry (shared by every worker through
/// [`ApiState::metrics`](super::ApiState::metrics)). Opaque: it is
/// recorded by the server and read through [`Metrics::render`].
///
/// # Examples
/// ```
/// # #[cfg(feature = "api")]
/// # {
/// use redactify::api::{handle_request_with, ApiState};
///
/// let state = ApiState::default();
/// let _ = handle_request_with(&state, "POST", "/v1/sanitize", r#"{"text":"TCKN 12345678950"}"#);
/// let text = state.metrics.render();
/// assert!(text.contains(r#"redactify_requests_total{endpoint="/v1/sanitize",status="200"} 1"#));
/// assert!(text.contains(
///     r#"redactify_entities_total{endpoint="/v1/sanitize",entity_type="TCKN",action="MASK"} 1"#
/// ));
/// assert!(!text.contains("12345678950")); // labels never carry request text
/// # }
/// ```
pub struct Metrics {
    /// endpoint x (status slots + other)
    requests: Box<[AtomicU64]>,
    /// endpoint x bucket (non-cumulative; summed when rendered)
    latency_buckets: Box<[AtomicU64]>,
    /// endpoint: observations above the last bound (the `+Inf`-only part)
    latency_overflow: Box<[AtomicU64]>,
    /// endpoint: total observed nanoseconds
    latency_sum_ns: Box<[AtomicU64]>,
    /// endpoint x action x mode (enforced, dry run)
    decisions: Box<[AtomicU64]>,
    /// (endpoint slot, entity type label, entity action) -> count
    entities: Mutex<BTreeMap<(usize, &'static str, &'static str), u64>>,
}

impl Default for Metrics {
    fn default() -> Self {
        let e = ENDPOINT_SLOTS;
        Self {
            requests: counters(e * (STATUSES.len() + 1)),
            latency_buckets: counters(e * BUCKETS.len()),
            latency_overflow: counters(e),
            latency_sum_ns: counters(e),
            decisions: counters(e * ACTIONS.len() * 2),
            entities: Mutex::new(BTreeMap::new()),
        }
    }
}

impl std::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total: u64 = self
            .requests
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum();
        f.debug_struct("Metrics").field("requests", &total).finish()
    }
}

impl Metrics {
    /// Records one answered request: its endpoint, status and latency.
    pub(crate) fn observe_request(&self, path: &str, status: u16, elapsed: Duration) {
        let e = endpoint_slot(path);
        self.requests[e * (STATUSES.len() + 1) + status_slot(status)]
            .fetch_add(1, Ordering::Relaxed);
        let ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        match BUCKETS.iter().position(|&(_, bound)| ns <= bound) {
            Some(b) => self.latency_buckets[e * BUCKETS.len() + b].fetch_add(1, Ordering::Relaxed),
            None => self.latency_overflow[e].fetch_add(1, Ordering::Relaxed),
        };
        self.latency_sum_ns[e].fetch_add(ns, Ordering::Relaxed);
    }

    /// Records one decision: its decided action (dry-run decisions under
    /// `mode="dry_run"`) and its per-type entity counts.
    pub(crate) fn observe_decision(&self, path: &str, d: &Decision) {
        let e = endpoint_slot(path);
        if let Some(a) = action_slot(d.decided_action()) {
            let mode = usize::from(d.dry_run_action.is_some());
            self.decisions[(e * ACTIONS.len() + a) * 2 + mode].fetch_add(1, Ordering::Relaxed);
        }
        if !d.entity_counts.is_empty() {
            let mut map = self.entities.lock().unwrap_or_else(PoisonError::into_inner);
            for c in &d.entity_counts {
                *map.entry((e, c.kind.as_str(), c.action.as_str()))
                    .or_insert(0) += c.count as u64;
            }
        }
    }

    /// Records the would-be Block of a dry-run stream (the stream emits no
    /// other decision).
    pub(crate) fn observe_stream_block(&self, path: &str, dry_run: bool) {
        let e = endpoint_slot(path);
        let a = action_slot(GuardAction::Block).unwrap_or(ACTIONS.len() - 1);
        self.decisions[(e * ACTIONS.len() + a) * 2 + usize::from(dry_run)]
            .fetch_add(1, Ordering::Relaxed);
    }

    /// The metrics in the Prometheus text exposition format 0.0.4 (served
    /// as `text/plain; version=0.0.4; charset=utf-8`). Series that were
    /// never recorded are omitted, except `redactify_build_info`.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(4096);
        let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
        // writing to a String cannot fail
        let _ = writeln!(
            out,
            "# HELP redactify_build_info The redactify version serving.\n\
             # TYPE redactify_build_info gauge\n\
             redactify_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        );

        out.push_str(
            "# HELP redactify_requests_total Requests answered, by endpoint and HTTP status.\n\
             # TYPE redactify_requests_total counter\n",
        );
        for (e, endpoint) in endpoint_labels().enumerate() {
            for s in 0..=STATUSES.len() {
                let n = load(&self.requests[e * (STATUSES.len() + 1) + s]);
                if n > 0 {
                    let status = STATUSES.get(s).map_or("other".to_owned(), u16::to_string);
                    let _ = writeln!(
                        out,
                        "redactify_requests_total{{endpoint=\"{endpoint}\",status=\"{status}\"}} {n}"
                    );
                }
            }
        }

        out.push_str(
            "# HELP redactify_request_duration_seconds Request handling time, by endpoint.\n\
             # TYPE redactify_request_duration_seconds histogram\n",
        );
        for (e, endpoint) in endpoint_labels().enumerate() {
            let per_bucket: Vec<u64> = (0..BUCKETS.len())
                .map(|b| load(&self.latency_buckets[e * BUCKETS.len() + b]))
                .collect();
            let count = per_bucket.iter().sum::<u64>() + load(&self.latency_overflow[e]);
            if count == 0 {
                continue;
            }
            let mut cumulative = 0u64;
            for (&(le, _), n) in BUCKETS.iter().zip(&per_bucket) {
                cumulative += n;
                let _ = writeln!(
                    out,
                    "redactify_request_duration_seconds_bucket{{endpoint=\"{endpoint}\",le=\"{le}\"}} {cumulative}"
                );
            }
            let sum = load(&self.latency_sum_ns[e]) as f64 / 1e9;
            let _ = writeln!(
                out,
                "redactify_request_duration_seconds_bucket{{endpoint=\"{endpoint}\",le=\"+Inf\"}} {count}\n\
                 redactify_request_duration_seconds_sum{{endpoint=\"{endpoint}\"}} {sum}\n\
                 redactify_request_duration_seconds_count{{endpoint=\"{endpoint}\"}} {count}"
            );
        }

        out.push_str(
            "# HELP redactify_decisions_total Guard decisions, by endpoint, decided action and mode (enforce or dry_run).\n\
             # TYPE redactify_decisions_total counter\n",
        );
        for (e, endpoint) in endpoint_labels().enumerate() {
            for (a, action) in ACTIONS.iter().enumerate() {
                for (m, mode) in ["enforce", "dry_run"].iter().enumerate() {
                    let n = load(&self.decisions[(e * ACTIONS.len() + a) * 2 + m]);
                    if n > 0 {
                        let _ = writeln!(
                            out,
                            "redactify_decisions_total{{endpoint=\"{endpoint}\",action=\"{}\",mode=\"{mode}\"}} {n}",
                            action_label(*action)
                        );
                    }
                }
            }
        }

        out.push_str(
            "# HELP redactify_entities_total Entities found by guard decisions, by endpoint, entity type and entity action.\n\
             # TYPE redactify_entities_total counter\n",
        );
        let map = self.entities.lock().unwrap_or_else(PoisonError::into_inner);
        for (&(e, kind, action), n) in map.iter() {
            let _ = writeln!(
                out,
                "redactify_entities_total{{endpoint=\"{}\",entity_type=\"{}\",action=\"{action}\"}} {n}",
                endpoint_labels().nth(e).unwrap_or("other"),
                escape_label(kind)
            );
        }
        out
    }
}

/// The lowercase label of a decision action.
fn action_label(a: GuardAction) -> &'static str {
    match a {
        GuardAction::Allow => "allow",
        GuardAction::Log => "log",
        GuardAction::Mask => "mask",
        GuardAction::Block => "block",
    }
}

/// A label value escaped per the exposition format (backslash, double
/// quote, line feed). Entity labels are `[A-Z0-9_]` by construction, so
/// this only guards the format.
fn escape_label(v: &str) -> std::borrow::Cow<'_, str> {
    if v.contains(['\\', '"', '\n']) {
        std::borrow::Cow::Owned(
            v.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n"),
        )
    } else {
        std::borrow::Cow::Borrowed(v)
    }
}

#[cfg(test)]
mod tests {
    use super::{escape_label, Metrics, BUCKETS};
    use std::time::Duration;

    #[test]
    fn histogram_is_cumulative_and_ends_with_inf_equal_to_count() {
        let m = Metrics::default();
        m.observe_request("/v1/guard", 200, Duration::from_micros(300));
        m.observe_request("/v1/guard", 200, Duration::from_millis(3));
        m.observe_request("/v1/guard", 400, Duration::from_secs(9));
        let text = m.render();
        let buckets: Vec<u64> = text
            .lines()
            .filter(|l| {
                l.starts_with("redactify_request_duration_seconds_bucket{endpoint=\"/v1/guard\"")
            })
            .map(|l| l.rsplit(' ').next().unwrap().parse().unwrap())
            .collect();
        assert_eq!(buckets.len(), BUCKETS.len() + 1);
        assert!(buckets.windows(2).all(|w| w[0] <= w[1]), "{buckets:?}");
        assert_eq!(buckets[0], 1); // 0.3 ms <= 0.5 ms
        assert_eq!(*buckets.last().unwrap(), 3);
        assert!(text.contains("redactify_request_duration_seconds_count{endpoint=\"/v1/guard\"} 3"));
        assert!(text.contains("redactify_requests_total{endpoint=\"/v1/guard\",status=\"400\"} 1"));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn unknown_paths_and_statuses_collapse_into_other() {
        let m = Metrics::default();
        m.observe_request("/wp-admin/../secret?x=1", 418, Duration::ZERO);
        let text = m.render();
        assert!(text.contains("redactify_requests_total{endpoint=\"other\",status=\"other\"} 1"));
        assert!(!text.contains("wp-admin"));
    }

    #[test]
    fn every_family_has_one_help_and_one_type_line() {
        let text = Metrics::default().render();
        for family in [
            "redactify_build_info",
            "redactify_requests_total",
            "redactify_request_duration_seconds",
            "redactify_decisions_total",
            "redactify_entities_total",
        ] {
            assert_eq!(text.matches(&format!("# HELP {family} ")).count(), 1);
            assert_eq!(text.matches(&format!("# TYPE {family} ")).count(), 1);
        }
    }

    #[test]
    fn label_escaping_follows_the_format() {
        assert_eq!(escape_label("TCKN"), "TCKN");
        assert_eq!(escape_label("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
