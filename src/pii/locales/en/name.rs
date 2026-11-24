//! English (US) person names in **labeled contexts** (cue + capitalized
//! sequence). Same design as the Turkish rule: no checksum exists, so a bare
//! capitalized sequence is never claimed without a nearby label cue. See
//! [`super::super::tr::name`] for the shared rationale and limits.

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue phrases that make a capitalized sequence claimable as a person name.
/// The bare word "name" is deliberately not a cue: it appears inside
/// "filename"/"surname"/"renamed" and would fire on unrelated text.
pub(super) const CUES: &[&str] = &[
    "full name",
    "name:",
    "name is",
    "customer name",
    "passenger name",
];

/// Label words: a candidate made up **entirely** of these is the label phrase
/// itself ("Full Name"), not a name. Titles ("Dr John Smith") keep the name.
const LABEL_WORDS: &[&str] = &[
    "name",
    "full",
    "customer",
    "passenger",
    "account",
    "holder",
    "mr",
    "mrs",
    "ms",
    "dr",
];

/// Rejects candidates consisting only of label words.
fn not_label_phrase(candidate: &str) -> bool {
    !candidate
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .all(|w| LABEL_WORDS.contains(&w))
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Name,
        r"\b\p{Lu}\p{Ll}+(?:-\p{Lu}?\p{Ll}+)*(?:\s+\p{Lu}\p{Ll}+(?:-\p{Lu}?\p{Ll}+)*){1,3}\b",
        Some(not_label_phrase),
        ContextPolicy::RequiredCue(CUES),
        0.85
    )
}

#[cfg(test)]
mod tests {
    use crate::pii::entity::EntityType;

    fn names(text: &str) -> Vec<(EntityType, String)> {
        crate::pii::detect::engine_detect(text, &["en"])
            .into_iter()
            .map(|e| (e.kind, e.text))
            .collect()
    }

    #[test]
    fn labeled_full_name_detected() {
        let found = names("Full name: John Smith, email john@example.com.");
        assert!(
            found.contains(&(EntityType::Name, "John Smith".into())),
            "{found:?}"
        );
    }

    #[test]
    fn name_is_phrase_detected() {
        let found = names("My name is John Smith and I approve this message.");
        assert!(
            found.contains(&(EntityType::Name, "John Smith".into())),
            "{found:?}"
        );
    }

    #[test]
    fn no_cue_no_claim() {
        assert!(names("Yesterday John Smith gave a great talk.").is_empty());
    }

    #[test]
    fn label_phrase_itself_is_rejected() {
        let found = names("Passenger Name: Mary-Jane Watson");
        let texts: Vec<&str> = found.iter().map(|(_, t)| t.as_str()).collect();
        assert!(texts.contains(&"Mary-Jane Watson"), "{found:?}");
        assert!(
            !texts
                .iter()
                .any(|t| t.contains("Passenger") || *t == "Name"),
            "{found:?}"
        );
    }
}
