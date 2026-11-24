//! Redaction: the one span-replacement loop every masking site shares
//! (the public masking entry points - `redactify::redact`,
//! `Detector::redact`, `MaskStyle` - all render through it).

use crate::pii::entity::{Entity, EntityType};

/// A byte span that [`replace_spans`] can replace: [`Entity`] implements
/// it, and other span carriers (e.g. secret findings) can too.
pub(crate) trait ReplaceSpan {
    /// The label handed to the replacement closure for a merged group.
    type Label: Copy;
    /// The byte range `[start, end)` of the span.
    fn byte_range(&self) -> (usize, usize);
    /// This span's label.
    fn label(&self) -> Self::Label;
    /// Tie-break rank between equal-length spans of one merged group:
    /// the LOWER rank wins (for entities: the more specific type).
    fn rank(&self) -> u8;
}

impl ReplaceSpan for Entity {
    type Label = EntityType;

    fn byte_range(&self) -> (usize, usize) {
        (self.start, self.end)
    }

    fn label(&self) -> EntityType {
        self.kind
    }

    fn rank(&self) -> u8 {
        self.kind.priority()
    }
}

/// THE one span-replacement loop: every masking site that rewrites spans
/// of a text funnels through here.
///
/// Spans are validated and sorted internally: empty, out-of-bounds and
/// non-char-boundary spans are skipped defensively (never a panic), and
/// callers may pass them unsorted. Overlapping spans merge into ONE
/// replaced region covering their union, so no tail of a longer span can
/// leak; the region's label comes from the group's longest span (the outer
/// span covers the region - "address containing a name" is an ADDRESS
/// region), ties broken by the lower [`ReplaceSpan::rank`].
///
/// `replacement` receives the group label and the ORIGINAL text of the
/// merged region and returns what is written in its place.
pub(crate) fn replace_spans<S, F>(text: &str, spans: &[S], mut replacement: F) -> String
where
    S: ReplaceSpan,
    F: FnMut(S::Label, &str) -> String,
{
    // validate + sort by start (stable: equal starts keep input order)
    let mut valid: Vec<(usize, usize, &S)> = spans
        .iter()
        .filter_map(|s| {
            let (start, end) = s.byte_range();
            (start < end
                && end <= text.len()
                && text.is_char_boundary(start)
                && text.is_char_boundary(end))
            .then_some((start, end, s))
        })
        .collect();
    valid.sort_by_key(|&(start, _, _)| start);

    let mut out = String::with_capacity(text.len());
    let mut last = 0usize;
    let mut i = 0usize;
    while i < valid.len() {
        let (group_start, first_end, first) = valid[i];
        let mut group_end = first_end;
        let mut group_label = first.label();
        let mut group_rank = first.rank();
        let mut group_label_len = first_end - group_start;
        let mut j = i;
        while j < valid.len() && valid[j].0 < group_end {
            let (start, end, span) = valid[j];
            let len = end - start;
            if len > group_label_len || (len == group_label_len && span.rank() < group_rank) {
                group_label = span.label();
                group_rank = span.rank();
                group_label_len = len;
            }
            group_end = group_end.max(end);
            j += 1;
        }
        out.push_str(&text[last..group_start]);
        out.push_str(&replacement(group_label, &text[group_start..group_end]));
        last = group_end;
        i = j;
    }
    out.push_str(&text[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::replace_spans;
    use crate::pii::detect::detect;
    use crate::pii::entity::EntityType;
    use crate::pii::Entity;

    /// The default `[TYPE]` mask of one replaced region.
    fn label_mask(kind: EntityType, _region: &str) -> String {
        format!("[{}]", kind.as_str())
    }

    /// Raw-view detection masked with `[TYPE]` labels.
    fn redact(text: &str) -> String {
        replace_spans(text, &detect(text), label_mask)
    }

    /// The `[TYPE]` label mask over already-detected entities.
    fn label(text: &str, ents: &[Entity]) -> String {
        replace_spans(text, ents, label_mask)
    }

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
        // a `{type}` template rendered through the one replacement loop
        let text = "mail a@b.com";
        let out = replace_spans(text, &detect(text), |kind, _| {
            "«{type}»".replace("{type}", kind.as_str())
        });
        assert_eq!(out, "mail «EMAIL»");
    }

    #[test]
    fn ner_entities_mask_free_prose_names() {
        use crate::pii::ner::{MockNameRecognizer, NerRecognizer};
        use crate::pii::{run, EngineOpts};
        let ner = MockNameRecognizer::new();
        let text = "Bugün toplantıda Ahmet Yılmaz konuştu.";
        let ents = run(
            text,
            &EngineOpts {
                ner: &[&ner as &dyn NerRecognizer],
                ..EngineOpts::default()
            },
        )
        .entities;
        assert_eq!(label(text, &ents), "Bugün toplantıda [NAME] konuştu.");
    }

    #[test]
    fn redact_entities_skips_bad_spans() {
        use crate::pii::entity::EntityType;
        use crate::pii::Entity;
        // out-of-order + out-of-bounds spans are skipped, not panics
        let bad = vec![
            Entity {
                kind: EntityType::Name,
                start: 100,
                end: 200,
                text: String::new(),
                score: 0.9,
            },
            Entity {
                kind: EntityType::Name,
                start: 0,
                end: 0,
                text: String::new(),
                score: 0.9,
            },
        ];
        assert_eq!(label("merhaba", &bad), "merhaba");
    }

    #[test]
    fn overlapping_spans_masked_as_union_without_tail_leak() {
        use crate::pii::entity::EntityType;
        use crate::pii::Entity;

        // PII-Bench v4 shape: Address [0,28) contains Name [0,18).
        // A cursor that skips the second span would leak the
        // " Institute" tail unmasked.
        let text = "Johannes R. Becher Institute heute";
        let ents = vec![
            Entity {
                kind: EntityType::Name,
                start: 0,
                end: 18,
                text: "Johannes R. Becher".into(),
                score: 0.9,
            },
            Entity {
                kind: EntityType::Address,
                start: 0,
                end: 28,
                text: "Johannes R. Becher Institute".into(),
                score: 0.9,
            },
        ];
        assert_eq!(label(text, &ents), "[ADDRESS] heute");
    }

    #[test]
    fn unsorted_and_partial_overlap_inputs_are_handled() {
        use crate::pii::entity::EntityType;
        use crate::pii::Entity;

        // reversed order + partial overlap: sorted internally, union masked
        let text = "abcdefgh";
        let ents = vec![
            Entity {
                kind: EntityType::Address,
                start: 3,
                end: 8,
                text: "defgh".into(),
                score: 0.9,
            },
            Entity {
                kind: EntityType::Name,
                start: 0,
                end: 5,
                text: "abcde".into(),
                score: 0.9,
            },
        ];
        assert_eq!(label(text, &ents), "[NAME]");
    }

    #[test]
    fn replace_spans_hands_the_merged_region_to_the_closure() {
        use crate::pii::entity::EntityType;
        use crate::pii::Entity;

        let text = "x abcdefgh y";
        let ents = vec![
            Entity {
                kind: EntityType::Name,
                start: 2,
                end: 7,
                text: "abcde".into(),
                score: 0.9,
            },
            Entity {
                kind: EntityType::Address,
                start: 5,
                end: 10,
                text: "defgh".into(),
                score: 0.9,
            },
        ];
        let mut seen = Vec::new();
        let out = replace_spans(text, &ents, |kind, region| {
            seen.push((kind, region.to_owned()));
            format!("<{}>", region.len())
        });
        assert_eq!(out, "x <8> y");
        // one call for the union region; equal lengths and equal rank keep
        // the first span's label (input order after the stable sort)
        assert_eq!(seen, vec![(EntityType::Name, "abcdefgh".to_owned())]);
    }
}
