//! Binary classification metrics for guardrail evaluation (F1, FPR,
//! ROC-AUC).
//!
//! Pure, dependency-free functions over parallel label/prediction (or score)
//! slices. Conventions are explicit and tested:
//!
//! - Labels and predictions are `0`/`1` (`u8`).
//! - A metric whose denominator is zero is reported as `0.0` (a classifier
//!   that predicts nothing positive has zero precision - not `NaN`).
//! - [`roc_auc`] uses the rank statistic (Mann-Whitney U / probability that a
//!   random positive outscores a random negative, ties counted as half) so no
//!   threshold is involved; it returns `None` when the labels contain a
//!   single class (AUC is undefined there).
//!
//! # Examples
//! ```
//! use redactify::guard::metrics::{confusion, roc_auc};
//!
//! // 3 positives, 2 negatives; the classifier catches 2 of 3, one false alarm
//! let labels = [1, 1, 1, 0, 0];
//! let preds = [1, 1, 0, 1, 0];
//! let c = confusion(&labels, &preds);
//! assert_eq!((c.tp, c.fp, c.fn_count, c.tn), (2, 1, 1, 1));
//!
//! // perfectly separated scores -> AUC 1.0
//! assert!((roc_auc(&[0.9, 0.8, 0.2, 0.1, 0.05], &labels).unwrap() - 1.0).abs() < 1e-9);
//! ```

/// Confusion matrix counts for binary classification.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConfusionCounts {
    /// True positives (label 1, predicted 1).
    pub tp: usize,
    /// False positives (label 0, predicted 1).
    pub fp: usize,
    /// False negatives (label 1, predicted 0).
    pub fn_count: usize,
    /// True negatives (label 0, predicted 0).
    pub tn: usize,
}

impl ConfusionCounts {
    /// Total number of evaluated items.
    #[must_use]
    pub const fn total(self) -> usize {
        self.tp + self.fp + self.fn_count + self.tn
    }
}

/// Computes confusion counts from parallel label/prediction slices.
///
/// # Panics
/// Panics if the slices have different lengths (caller bug, not data issue).
#[must_use]
pub fn confusion(labels: &[u8], preds: &[u8]) -> ConfusionCounts {
    assert_eq!(
        labels.len(),
        preds.len(),
        "labels and predictions must be parallel"
    );
    let mut c = ConfusionCounts::default();
    for (&l, &p) in labels.iter().zip(preds) {
        match (l, p) {
            (1, 1) => c.tp += 1,
            (0, 1) => c.fp += 1,
            (1, 0) => c.fn_count += 1,
            (0, 0) => c.tn += 1,
            // lenient (never a panic), consistent with `mcc`/`roc_auc`:
            // anything but an explicit 1 counts as the negative class
            _ => {
                if p == 1 {
                    c.fp += 1;
                } else {
                    c.tn += 1;
                }
            }
        }
    }
    c
}

/// Computes confusion counts by thresholding scores (`pred = score >= t`).
///
/// # Panics
/// When `scores` and `labels` differ in length (they must be parallel).
#[must_use]
pub fn confusion_at_threshold(scores: &[f32], labels: &[u8], threshold: f32) -> ConfusionCounts {
    assert_eq!(
        scores.len(),
        labels.len(),
        "scores and labels must be parallel"
    );
    let preds: Vec<u8> = scores.iter().map(|&s| u8::from(s >= threshold)).collect();
    confusion(labels, &preds)
}

/// Derived binary metrics from confusion counts.
///
/// Zero-denominator metrics are `0.0` by convention (see module docs).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[non_exhaustive]
pub struct BinaryMetrics {
    /// Raw confusion counts.
    pub counts: ConfusionCounts,
    /// TP / (TP + FP).
    pub precision: f64,
    /// TP / (TP + FN) - a.k.a. detection rate / TPR.
    pub recall: f64,
    /// Harmonic mean of precision and recall (0.0 when both are 0).
    pub f1: f64,
    /// FP / (FP + TN) - false positive rate (fall-out).
    pub fpr: f64,
    /// (TP + TN) / total.
    pub accuracy: f64,
}

impl BinaryMetrics {
    /// Computes all metrics from confusion counts.
    #[must_use]
    pub fn from_counts(counts: ConfusionCounts) -> Self {
        let tp = counts.tp as f64;
        let fp = counts.fp as f64;
        let fn_ = counts.fn_count as f64;
        let tn = counts.tn as f64;
        let total = counts.total() as f64;
        let precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
        let recall = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
        let f1 = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };
        let fpr = if fp + tn > 0.0 { fp / (fp + tn) } else { 0.0 };
        let accuracy = if total > 0.0 { (tp + tn) / total } else { 0.0 };
        Self {
            counts,
            precision,
            recall,
            f1,
            fpr,
            accuracy,
        }
    }

    /// Computes metrics by thresholding scores (`pred = score >= t`).
    #[must_use]
    pub fn at_threshold(scores: &[f32], labels: &[u8], threshold: f32) -> Self {
        Self::from_counts(confusion_at_threshold(scores, labels, threshold))
    }

    /// Computes metrics from parallel label/prediction slices.
    #[must_use]
    pub fn from_predictions(labels: &[u8], preds: &[u8]) -> Self {
        Self::from_counts(confusion(labels, preds))
    }
}

/// Matthews Correlation Coefficient from confusion counts - the balanced
/// measure that stays informative under class imbalance. Returns `None` for mismatched/empty slices.
#[must_use]
pub fn mcc(labels: &[u8], preds: &[u8]) -> Option<f64> {
    if labels.len() != preds.len() || labels.is_empty() {
        return None;
    }
    let c = confusion(labels, preds);
    let (tp, fp, fn_, tn) = (c.tp as f64, c.fp as f64, c.fn_count as f64, c.tn as f64);
    let denom = ((tp + fp) * (tp + fn_) * (tn + fp) * (tn + fn_)).sqrt();
    if denom == 0.0 {
        // a degenerate confusion matrix has no correlation to report
        return None;
    }
    Some(((tp * tn) - (fp * fn_)) / denom)
}

/// Matthews Correlation Coefficient at a score threshold.
#[must_use]
pub fn mcc_at_threshold(scores: &[f32], labels: &[u8], threshold: f32) -> Option<f64> {
    let preds: Vec<u8> = scores.iter().map(|&s| u8::from(s >= threshold)).collect();
    mcc(labels, &preds)
}

/// Area under the Precision-Recall curve (average-precision style, step
/// interpolation after sorting by score descending). `None` when undefined:
/// empty input, mismatched lengths, or no positive labels.
#[must_use]
pub fn auprc(scores: &[f32], labels: &[u8]) -> Option<f64> {
    if scores.len() != labels.len() || labels.is_empty() || !labels.contains(&1) {
        return None;
    }
    let mut order: Vec<usize> = (0..scores.len()).collect();
    order.sort_by(|&a, &b| scores[b].total_cmp(&scores[a]));
    let total_pos = labels.iter().filter(|&&l| l == 1).count() as f64;
    let mut tp = 0.0_f64;
    let mut fp = 0.0_f64;
    let mut ap = 0.0_f64;
    let mut prev_recall = 0.0_f64;
    for &i in &order {
        if labels[i] == 1 {
            tp += 1.0;
        } else {
            fp += 1.0;
        }
        let precision = tp / (tp + fp);
        let recall = tp / total_pos;
        // step interpolation: area accumulates only when recall increases
        ap += precision * (recall - prev_recall);
        prev_recall = recall;
    }
    Some(ap)
}

/// Threshold-independent area under the ROC curve (rank statistic with ties
/// counted as half a win). Returns `None` when AUC is undefined: empty input,
/// mismatched slice lengths, or labels with a single class.
#[must_use]
pub fn roc_auc(scores: &[f32], labels: &[u8]) -> Option<f64> {
    if scores.len() != labels.len() || scores.is_empty() {
        return None;
    }
    let n_pos = labels.iter().filter(|&&l| l == 1).count();
    let n_neg = labels.len() - n_pos;
    if n_pos == 0 || n_neg == 0 {
        return None;
    }

    // average ranks (1-based) over ascending scores; ties share a rank
    let mut indexed: Vec<(f32, usize)> = scores.iter().enumerate().map(|(i, &s)| (s, i)).collect();
    indexed.sort_by(|a, b| a.0.total_cmp(&b.0));

    let n = indexed.len();
    let mut ranks = vec![0.0_f64; n];
    let mut i = 0;
    while i < n {
        let mut j = i;
        while j + 1 < n && indexed[j + 1].0 == indexed[i].0 {
            j += 1;
        }
        let avg_rank = (i + 1 + j + 1) as f64 / 2.0; // ranks i+1 ..= j+1
        for entry in &indexed[i..=j] {
            ranks[entry.1] = avg_rank;
        }
        i = j + 1;
    }

    let rank_sum_pos: f64 = labels
        .iter()
        .enumerate()
        .filter(|(_, &l)| l == 1)
        .map(|(idx, _)| ranks[idx])
        .sum();
    let u_pos = rank_sum_pos - (n_pos * (n_pos + 1)) as f64 / 2.0;
    Some(u_pos / (n_pos * n_neg) as f64)
}

/// A swept threshold with its F1 (and the metrics it produced).
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct ThresholdPoint {
    /// The threshold (`pred = score >= threshold`).
    pub threshold: f32,
    /// Metrics at this threshold.
    pub metrics: BinaryMetrics,
}

/// Sweeps all informative thresholds and returns the best-F1 operating point.
///
/// Candidates: every unique score, plus one value above the maximum (the
/// predict-nothing point). Ties on F1 resolve to the **highest** threshold
/// (fewest alerts at equal F1 - the conservative choice). Returns `None` for
/// empty input, mismatched slices, or single-class labels (F1 meaningless).
#[must_use]
pub fn best_f1_threshold(scores: &[f32], labels: &[u8]) -> Option<ThresholdPoint> {
    if scores.len() != labels.len() || scores.is_empty() {
        return None;
    }
    let n_pos = labels.iter().filter(|&&l| l == 1).count();
    let n_neg = labels.len() - n_pos;
    if n_pos == 0 || n_neg == 0 {
        return None;
    }

    let mut candidates: Vec<f32> = scores.to_vec();
    candidates.sort_by(|a, b| a.total_cmp(b));
    candidates.dedup();
    let above_all = candidates[candidates.len() - 1] + f32::EPSILON.max(1e-6); // predict-none point
    candidates.push(above_all);

    let mut best: Option<ThresholdPoint> = None;
    for &t in &candidates {
        let metrics = BinaryMetrics::at_threshold(scores, labels, t);
        let better = match best {
            None => true,
            Some(b) => metrics.f1 > b.metrics.f1 || (metrics.f1 == b.metrics.f1 && t > b.threshold),
        };
        if better {
            best = Some(ThresholdPoint {
                threshold: t,
                metrics,
            });
        }
    }
    best
}

/// Attack Success Rate at a threshold: the fraction of ATTACK items
/// (label=1) that slip through (`score < threshold`). Equivalent to 1 −
/// recall on the attack slice; reported under its security name. `None`
/// when there are no attack items.
#[must_use]
pub fn asr(scores: &[f32], labels: &[u8], threshold: f32) -> Option<f64> {
    if scores.len() != labels.len() {
        return None;
    }
    let (mut attacks, mut bypassed) = (0u32, 0u32);
    for (&s, &l) in scores.iter().zip(labels) {
        if l == 1 {
            attacks += 1;
            if s < threshold {
                bypassed += 1;
            }
        }
    }
    (attacks > 0).then(|| f64::from(bypassed) / f64::from(attacks))
}

/// Wilson score interval (95% when `z = 1.96`) for a binomial proportion -
/// a confidence interval without a bootstrap machinery. Returns `(low, high)` in `[0, 1]`.
#[must_use]
pub fn wilson_interval(successes: usize, n: usize, z: f64) -> (f64, f64) {
    if n == 0 {
        return (0.0, 0.0);
    }
    let p = successes as f64 / n as f64;
    let z2 = z * z;
    let denom = 1.0 + z2 / n as f64;
    let centre = p + z2 / (2.0 * n as f64);
    let margin = z * (p * (1.0 - p) / n as f64 + z2 / (4.0 * n as f64 * n as f64)).sqrt();
    (
        ((centre - margin) / denom).max(0.0),
        ((centre + margin) / denom).min(1.0),
    )
}

#[cfg(test)]
mod tests {
    use super::{best_f1_threshold, confusion, confusion_at_threshold, roc_auc, BinaryMetrics};

    #[test]
    fn confusion_counts_match_hand_computation() {
        let labels = [1, 1, 1, 0, 0];
        let preds = [1, 1, 0, 1, 0];
        let c = confusion(&labels, &preds);
        assert_eq!((c.tp, c.fp, c.fn_count, c.tn), (2, 1, 1, 1));
        assert_eq!(c.total(), 5);
    }

    #[test]
    fn confusion_all_correct() {
        let c = confusion(&[1, 0, 1], &[1, 0, 1]);
        assert_eq!((c.tp, c.fp, c.fn_count, c.tn), (2, 0, 0, 1));
    }

    #[test]
    fn confusion_thresholding_includes_boundary() {
        let scores = [0.9_f32, 0.6, 0.5, 0.2];
        let labels = [1_u8, 1, 0, 0];
        // threshold at exactly a score includes it (>= semantics): the 0.5
        // score belongs to a NEGATIVE item, so including it is a false alarm
        let c = confusion_at_threshold(&scores, &labels, 0.5);
        assert_eq!((c.tp, c.fp, c.fn_count, c.tn), (2, 1, 0, 1));
        let c = confusion_at_threshold(&scores, &labels, 0.50001);
        assert_eq!((c.tp, c.fp, c.fn_count, c.tn), (2, 0, 0, 2));
        let c = confusion_at_threshold(&scores, &labels, 0.7);
        assert_eq!((c.tp, c.fp, c.fn_count, c.tn), (1, 0, 1, 2));
    }

    #[test]
    fn metrics_hand_computed() {
        // tp=2 fp=1 fn=1 tn=1 -> P=2/3, R=2/3, F1=2/3, FPR=1/2, acc=3/5
        let m = BinaryMetrics::from_counts(confusion(&[1, 1, 1, 0, 0], &[1, 1, 0, 1, 0]));
        assert!((m.precision - 2.0 / 3.0).abs() < 1e-9);
        assert!((m.recall - 2.0 / 3.0).abs() < 1e-9);
        assert!((m.f1 - 2.0 / 3.0).abs() < 1e-9);
        assert!((m.fpr - 0.5).abs() < 1e-9);
        assert!((m.accuracy - 0.6).abs() < 1e-9);
    }

    #[test]
    fn metrics_zero_denominators_are_zero_not_nan() {
        // predict-nothing: precision denominator 0; no negatives: fpr denom 0
        let m = BinaryMetrics::from_counts(confusion(&[1, 1], &[0, 0]));
        assert_eq!(m.precision, 0.0);
        assert_eq!(m.f1, 0.0);
        assert_eq!(m.fpr, 0.0);
        assert!(!m.precision.is_nan() && !m.f1.is_nan());
        let m = BinaryMetrics::from_counts(confusion(&[1, 1], &[1, 0]));
        assert_eq!(m.fpr, 0.0); // no negatives at all
    }

    #[test]
    fn auc_perfect_separation() {
        let auc = roc_auc(&[0.9, 0.8, 0.2, 0.1, 0.05], &[1, 1, 0, 0, 0]).unwrap();
        assert!((auc - 1.0).abs() < 1e-9);
    }

    #[test]
    fn auc_worst_separation() {
        let auc = roc_auc(&[0.05, 0.1, 0.8, 0.9], &[0, 0, 1, 1]).unwrap();
        assert_eq!(auc, 1.0, "AUC is direction-free: pos above neg is 1.0");
        // reversed: positives BELOW negatives
        let auc = roc_auc(&[0.9, 0.8, 0.2, 0.1], &[0, 0, 1, 1]).unwrap();
        assert!(auc.abs() < 1e-9);
    }

    #[test]
    fn auc_ties_count_half() {
        // all scores identical -> every pair is a tie -> 0.5
        let auc = roc_auc(&[0.5, 0.5, 0.5, 0.5], &[1, 1, 0, 0]).unwrap();
        assert!((auc - 0.5).abs() < 1e-9);
        // partial tie: pairs (0.5 pos vs 0.5 neg) are ties
        let auc = roc_auc(&[0.9, 0.5, 0.5, 0.1], &[1, 1, 0, 0]).unwrap();
        // pos-neg pairs: (0.9,0.5)=1, (0.9,0.1)=1, (0.5,0.5)=0.5, (0.5,0.1)=1 => 3.5/4
        assert!((auc - 0.875).abs() < 1e-9);
    }

    #[test]
    fn auc_undefined_for_single_class_or_bad_input() {
        assert!(roc_auc(&[0.1, 0.2], &[1, 1]).is_none());
        assert!(roc_auc(&[], &[]).is_none());
    }

    #[test]
    fn auc_matches_hand_computed_mid_case() {
        // labels: P P N N; scores: 0.8 0.4 0.6 0.2
        // pairs: (0.8,0.6) win, (0.8,0.2) win, (0.4,0.6) loss, (0.4,0.2) win => 3/4
        let auc = roc_auc(&[0.8, 0.4, 0.6, 0.2], &[1, 1, 0, 0]).unwrap();
        assert!((auc - 0.75).abs() < 1e-9);
    }

    #[test]
    fn best_threshold_perfect_point_exists() {
        let scores = [0.9_f32, 0.8, 0.3, 0.2];
        let labels = [1_u8, 1, 0, 0];
        let best = best_f1_threshold(&scores, &labels).unwrap();
        assert!(best.metrics.f1 > 0.99);
        assert!(best.threshold > 0.3 && best.threshold <= 0.8);
        assert_eq!(best.metrics.counts.fp, 0);
        assert_eq!(best.metrics.counts.fn_count, 0);
    }

    #[test]
    fn best_threshold_single_class_is_none() {
        assert!(best_f1_threshold(&[0.5, 0.6], &[1, 1]).is_none());
        assert!(best_f1_threshold(&[], &[]).is_none());
    }

    #[test]
    fn best_threshold_tradeoff_case() {
        // one positive scored below one negative: perfect recall costs an FP
        let scores = [0.9_f32, 0.2, 0.5];
        let labels = [1_u8, 1, 0];
        let best = best_f1_threshold(&scores, &labels).unwrap();
        // t=0.5: P=1/2 R=1/2 F1=0.5; t=0.2: P=2/3 R=1 F1=0.8; t=0.9: P=1 R=0.5 F1=0.667
        assert!((best.metrics.f1 - 0.8).abs() < 1e-9);
        assert!(best.threshold <= 0.2 + f32::EPSILON);
    }

    #[test]
    fn f1_tie_prefers_higher_threshold() {
        // t=0.5 and t=0.7 both give F1=1.0 -> take the higher (fewer alerts)
        let scores = [0.9_f32, 0.7, 0.5, 0.1];
        let labels = [1_u8, 1, 0, 0];
        let best = best_f1_threshold(&scores, &labels).unwrap();
        assert!((best.threshold - 0.7).abs() < 1e-6);
    }

    mod mcc_auprc {
        use super::super::{asr, auprc, mcc, wilson_interval};

        #[test]
        fn mcc_perfect_and_random() {
            let labels = [1u8, 1, 0, 0, 1, 0];
            let perfect = [1u8, 1, 0, 0, 1, 0];
            assert!((mcc(&labels, &perfect).unwrap() - 1.0).abs() < 1e-9);
            let inverted = [0u8, 0, 1, 1, 0, 1];
            assert!((mcc(&labels, &inverted).unwrap() + 1.0).abs() < 1e-9);
            // degenerate: all-positive predictions on mixed labels
            let all_pos = [1u8; 6];
            assert!(mcc(&labels, &all_pos).is_none());
            assert!(mcc(&[], &[]).is_none());
        }

        #[test]
        fn mcc_matches_manual_value() {
            // TP=3 FP=1 FN=1 TN=2 -> MCC = (6-1)/sqrt(4*4*3*3) = 5/ (2*2*3) = 0.4166..
            let labels = [1u8, 1, 1, 0, 0, 1, 0];
            let preds = [1u8, 1, 0, 0, 0, 1, 1];
            let v = mcc(&labels, &preds).unwrap();
            assert!((v - 5.0 / 12.0).abs() < 1e-9, "{v}");
        }

        #[test]
        fn auprc_perfect_ranking_is_one() {
            let scores = [0.9f32, 0.8, 0.7, 0.2, 0.1];
            let labels = [1u8, 1, 1, 0, 0];
            assert!((auprc(&scores, &labels).unwrap() - 1.0).abs() < 1e-9);
        }

        #[test]
        fn auprc_worst_ranking_is_positive_rate_fraction() {
            // all positives ranked last: AP = sum(1/N * k/total_pos)? -> equals
            // (1/total_pos) * sum_{k=1..3} k/(k+2) computed manually below
            let scores = [0.1f32, 0.2, 0.3, 0.9, 0.8];
            let labels = [1u8, 1, 1, 0, 0];
            let expected = (1.0 / 3.0) * (1.0 / 3.0 + 2.0 / 4.0 + 3.0 / 5.0);
            let v = auprc(&scores, &labels).unwrap();
            assert!((v - expected).abs() < 1e-9, "{v} vs {expected}");
        }

        #[test]
        fn asr_is_one_minus_recall_on_attacks() {
            let scores = [0.9f32, 0.2, 0.8, 0.1];
            let labels = [1u8, 1, 0, 0];
            // attacks: 2, bypassed (<0.5): 1 -> ASR 0.5
            assert!((asr(&scores, &labels, 0.5).unwrap() - 0.5).abs() < 1e-9);
            assert!(asr(&scores, &[0u8; 4], 0.5).is_none()); // no attacks
            assert!(asr(&scores, &[1u8], 0.5).is_none()); // length mismatch
        }

        #[test]
        fn wilson_brackets_the_proportion() {
            // 1 success in 20 at z=1.96: point 0.05, interval must contain it
            let (lo, hi) = wilson_interval(1, 20, 1.96);
            assert!(lo < 0.05 && hi > 0.05, "{lo}..{hi}");
            assert!(lo >= 0.0 && hi <= 1.0);
            // zero successes / zero n degenerate safely
            assert_eq!(wilson_interval(0, 0, 1.96), (0.0, 0.0));
            let (lo, hi) = wilson_interval(0, 40, 1.96);
            assert_eq!(lo, 0.0);
            assert!(hi < 0.12, "upper bound sane: {hi}");
        }

        #[test]
        fn auprc_undefined_cases() {
            assert!(auprc(&[], &[]).is_none());
            assert!(auprc(&[0.5], &[0u8]).is_none()); // no positives
            assert!(auprc(&[0.5, 0.4], &[1u8]).is_none()); // length mismatch
        }
    }
}
