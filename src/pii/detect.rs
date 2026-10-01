//! Detection engine: candidate collection, context policies, scoring and
//! overlap resolution. Locale-agnostic: every rule comes from `locales`.

use crate::pii::context;
use crate::pii::entity::Entity;
use crate::pii::locales::{self, ContextPolicy};

/// Context window (characters) applied to every cue policy.
const CUE_WINDOW: usize = 18;

/// Returns the validated, non-overlapping PII entities in the text, left to right.
///
/// Flow: for each rule (from [`locales::rules_for_locales`]) collect candidates per line
/// -> run the rule's validator -> apply the rule's context policy (required cue
/// or confidence boost) -> resolve overlaps (higher priority = lower
/// [`EntityType::priority`] first, then longer spans) -> sort by start.
///
/// Scanning is **line-scoped**: each regex sees a single line. Since no
/// supported entity can span lines, results are identical to whole-text
/// scanning, yet one pathological line can no longer stall the whole scan
/// (a simple but effective ReDoS mitigation, as fancy-regex has no timeout).
///
/// # Examples
/// ```
/// use redactify::{detect, EntityType};
///
/// let ents = detect("TCKN 12345678950, mail a@b.com");
/// let kinds: Vec<_> = ents.iter().map(|e| e.kind).collect();
/// assert!(kinds.contains(&EntityType::Tckn));
/// assert!(kinds.contains(&EntityType::Email));
/// assert!(detect("").is_empty());
/// ```
#[must_use]
pub fn detect(text: &str) -> Vec<Entity> {
    detect_inner(text, 0.0)
}

/// Like [`detect`], but drops detections whose score is below `threshold`
/// (a confidence cutoff filter).
///
/// # Examples
/// ```
/// use redactify::detect_with_threshold;
///
/// // a "plaka" cue nearby -> 0.95; no cue -> 0.85.
/// let with_cue = detect_with_threshold("Plakası 34 ABC 123 olan araç", 0.9);
/// let bare = detect_with_threshold("Yolda 34 ABC 123 gördüm", 0.9);
/// assert_eq!(with_cue.len(), 1);
/// assert_eq!(bare.len(), 0);
/// ```
#[must_use]
pub fn detect_with_threshold(text: &str, threshold: f32) -> Vec<Entity> {
    detect_inner(text, threshold)
}

/// Like [`detect`], but only runs rules for the specified locales.
/// Generic rules (e-mail, credit card) are always included.
///
/// This is a performance optimization: a Turkish-only application skips all
/// English pattern scanning, and vice versa. It also eliminates cross-locale
/// false positives by design.
///
/// # Examples
/// ```
/// use redactify::{detect_with_locales, EntityType};
///
/// // Turkish-only scan: finds TCKN, skips SSN patterns
/// let ents = detect_with_locales("TCKN 12345678950 and SSN 536-90-6292", &["tr"]);
/// assert!(ents.iter().any(|e| e.kind == EntityType::Tckn));
/// assert!(!ents.iter().any(|e| e.kind == EntityType::Ssn));
///
/// // English-only scan: finds SSN, skips TCKN patterns
/// let ents = detect_with_locales("TCKN 12345678950 and SSN 536-90-6292", &["en"]);
/// assert!(!ents.iter().any(|e| e.kind == EntityType::Tckn));
/// assert!(ents.iter().any(|e| e.kind == EntityType::Ssn));
/// ```
#[must_use]
pub fn detect_with_locales(text: &str, locales: &[&str]) -> Vec<Entity> {
    detect_inner_with_rules(text, 0.0, locales)
}

fn detect_inner(text: &str, threshold: f32) -> Vec<Entity> {
    detect_inner_with_rules(text, threshold, &["tr", "en"])
}

fn detect_inner_with_rules(text: &str, threshold: f32, locales: &[&str]) -> Vec<Entity> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut cands: Vec<Entity> = Vec::new();
    // Line-scoped scanning: each line is scanned with its own offset.
    let mut offset = 0;
    for line in text.split('\n') {
        collect_line_with_rules(line, offset, &mut cands, locales);
        offset += line.len() + 1; // +1: the '\n' itself
    }
    resolve_overlaps(cands, threshold)
}

fn collect_line_with_rules(
    line: &str,
    offset: usize,
    cands: &mut Vec<Entity>,
    locale_tags: &[&str],
) {
    if line.is_empty() {
        return;
    }
    for rule in locales::rules_for_locales(locale_tags) {
        for m in rule.regex.find_iter(line) {
            let Ok(m) = m else { continue };
            let val = m.as_str();
            if let Some(validate) = rule.validator {
                if !validate(val) {
                    continue;
                }
            }
            let mut score = rule.score;
            match rule.context {
                ContextPolicy::RequiredCue(cues) => {
                    if !context::has_cue(line, m.start(), m.end(), cues, CUE_WINDOW) {
                        continue; // checksum-less identifier: not claimable without a cue
                    }
                }
                ContextPolicy::Boost(cues, boosted) => {
                    if context::has_cue(line, m.start(), m.end(), cues, CUE_WINDOW) {
                        score = boosted;
                    }
                }
                ContextPolicy::None => {}
            }
            cands.push(Entity {
                kind: rule.kind,
                start: offset + m.start(),
                end: offset + m.end(),
                text: val.to_owned(),
                score,
            });
        }
    }
}

/// Resolves overlapping candidates: walk in (priority asc, length desc) order and
/// greedily accept the non-overlapping ones.
fn resolve_overlaps(mut cands: Vec<Entity>, threshold: f32) -> Vec<Entity> {
    cands.sort_by(|a, b| {
        a.kind
            .priority()
            .cmp(&b.kind.priority())
            .then(b.len().cmp(&a.len()))
    });
    let mut occupied: Vec<(usize, usize)> = Vec::new();
    let mut chosen: Vec<Entity> = Vec::new();
    for e in cands {
        if e.score < threshold {
            continue;
        }
        let overlaps = occupied
            .iter()
            .any(|&(s, en)| !(e.end <= s || e.start >= en));
        if !overlaps {
            occupied.push((e.start, e.end));
            chosen.push(e);
        }
    }
    chosen.sort_by_key(|e| e.start);
    chosen
}

#[cfg(test)]
mod tests {
    use super::detect;
    use crate::pii::entity::EntityType;

    fn kinds(text: &str) -> Vec<(EntityType, String)> {
        detect(text).into_iter().map(|e| (e.kind, e.text)).collect()
    }

    #[test]
    fn iban_wins_over_embedded_vkn_spans() {
        let t = "IBAN TR33 0006 1005 1978 6457 8413 26";
        let found = kinds(t);
        assert_eq!(found.len(), 1, "expected only the IBAN: {found:?}");
        assert_eq!(found[0].0, EntityType::Iban);
        assert_eq!(found[0].1, "TR33 0006 1005 1978 6457 8413 26");
    }

    #[test]
    fn adjacent_tckns_both_found() {
        let found = kinds("12345678950 ve 10000000146");
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|(k, _)| *k == EntityType::Tckn));
    }

    #[test]
    fn tckn_inside_longer_digit_run_is_rejected() {
        assert!(kinds("ref 123456789501 X").is_empty());
    }

    #[test]
    fn empty_input() {
        assert!(detect("").is_empty());
    }

    // ------------------------------------------------ plate alignment (0.2)

    #[test]
    fn hyphenated_plate_is_detected() {
        let found = kinds("plaka 34-ABC-123 geçti");
        assert_eq!(found, vec![(EntityType::Plaka, "34-ABC-123".into())]);
    }

    #[test]
    fn qwx_letters_rejected() {
        assert!(!kinds("plaka 34 QWX 123")
            .iter()
            .any(|(k, _)| *k == EntityType::Plaka));
    }

    #[test]
    fn five_digit_serial_rejected() {
        assert!(!kinds("plaka 34 ABC 12345")
            .iter()
            .any(|(k, _)| *k == EntityType::Plaka));
    }

    // ------------------------------------------------ score + threshold (0.2)

    #[test]
    fn scores_follow_structural_certainty() {
        let ents = detect("TCKN 12345678950");
        assert_eq!(ents[0].score, 1.0); // checksum verified -> certainty

        let ents = detect("Plaka 34 ABC 123"); // "plaka" cue nearby
        assert_eq!(
            ents.iter()
                .find(|e| e.kind == EntityType::Plaka)
                .map(|e| e.score),
            Some(0.95)
        );

        let ents = detect("Yolda 34 ABC 123 gördüm"); // no cue
        assert_eq!(
            ents.iter()
                .find(|e| e.kind == EntityType::Plaka)
                .map(|e| e.score),
            Some(0.85)
        );

        let ents = detect("mail a@b.com");
        assert_eq!(ents[0].score, 0.85);

        let ents = detect("Cep: 532 123 45 67");
        assert_eq!(ents[0].score, 0.8);
    }

    #[test]
    fn threshold_filters_weak_detections() {
        use super::detect_with_threshold;
        // a cue-less plate (0.85) is dropped at threshold 0.9; a cued one (0.95) stays
        assert_eq!(
            detect_with_threshold("Yolda 34 ABC 123 gördüm", 0.9).len(),
            0
        );
        assert_eq!(
            detect_with_threshold("Plakası 34 ABC 123 olan araç", 0.9).len(),
            1
        );
        // checksum-backed types survive any reasonable threshold
        assert_eq!(detect_with_threshold("TCKN 12345678950", 0.99).len(), 1);
    }

    // ------------------------------------------------ line-scoped scanning (0.2)

    #[test]
    fn multiline_offsets_are_global() {
        let text = "birinci satır\nTCKN 12345678950\nson satır";
        let ents = detect(text);
        assert_eq!(ents.len(), 1);
        assert_eq!(&text[ents[0].start..ents[0].end], "12345678950");
        // the TCKN is on line 2: the first line is 15 bytes ('ı' is 2 bytes)
        // plus the 5 bytes of "TCKN "
        assert_eq!(ents[0].start, 15 + 5);
    }

    #[test]
    fn crlf_line_endings_keep_offsets_correct() {
        let text = "satir1\r\nplaka 34 ABC 123\r\n";
        let ents = detect(text);
        assert_eq!(ents.len(), 1);
        assert_eq!(&text[ents[0].start..ents[0].end], "34 ABC 123");
    }

    // ------------------------------------------------ passport + landline (0.3)

    #[test]
    fn passport_requires_cue() {
        let found = kinds("Pasaport numaram U12345678.");
        assert_eq!(found, vec![(EntityType::Passport, "U12345678".into())]);
        // lowercase u with a cue is also accepted
        let found = kinds("pasaport: u12345678");
        assert_eq!(found, vec![(EntityType::Passport, "u12345678".into())]);
        // no cue -> a checksum-less candidate cannot be claimed
        assert!(!kinds("kayit u12345678 tamam")
            .iter()
            .any(|(k, _)| *k == EntityType::Passport));
    }

    #[test]
    fn passport_score_is_structural() {
        let ents = detect("Pasaport: U12345678");
        assert_eq!(ents[0].kind, EntityType::Passport);
        assert_eq!(ents[0].score, 0.9); // format + mandatory cue; no checksum -> not 1.0
    }

    #[test]
    fn landline_detected_with_separator_after_area_code() {
        assert_eq!(
            kinds("ofis 0 212 555 44 33."),
            vec![(EntityType::Phone, "0 212 555 44 33".into())]
        );
        assert_eq!(
            kinds("ofis 0212 555 44 33."),
            vec![(EntityType::Phone, "0212 555 44 33".into())]
        );
    }

    #[test]
    fn bare_ten_digit_vkn_is_not_confused_with_landline() {
        // a REAL (checksum-valid) VKN starting with 212, without separators:
        let found = kinds("vergi no 2120000004");
        assert!(found
            .iter()
            .any(|(k, t)| *k == EntityType::Vkn && t == "2120000004"));
        assert!(!found.iter().any(|(k, _)| *k == EntityType::Phone));
        // with no cue, nothing is claimed
        assert!(kinds("kod 2120000004 x").is_empty());
    }
}
