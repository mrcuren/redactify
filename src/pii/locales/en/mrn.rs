//! US Medical Record Number: cue-gated heuristic rule.
//!
//! Evidence (two independent sources, retrieved 2026-10-12):
//! 1. HL7 FHIR R4 Patient resource + v2 Table 0203 identifier type
//!    "MR": MRNs are local identifiers assigned by each facility;
//!    length and alphabet vary by EHR/MPI (no national standard).
//! 2. ONC/ASTP (healthit.gov): the US has no national patient
//!    identifier - cross-facility matching is a known problem.
//!
//! Because NO standard shape exists, this rule is a CUE-GATED
//! HEURISTIC (not a format validation): 6-10 alphanumeric chars
//! immediately following "MRN" / "Medical Record" / "Patient ID".

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::UsMrn,
        r"(?i)(?:mrn|medical record(?: number)?|patient id)[\s:#]*[A-Z]{0,2}\d{4,10}[A-Z]{0,2}\b",
        None,
        ContextPolicy::None, // cue embedded in the pattern itself
        0.9
    )
}

#[cfg(test)]
mod mrn_tests {
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn mrn_detected_with_embedded_cue() {
        let ents = engine_detect("MRN: 12345678", &["en"]);
        assert!(ents.iter().any(|e| e.kind == EntityType::UsMrn), "{ents:?}");
        let ents = engine_detect("Medical Record 123456", &["en"]);
        assert!(ents.iter().any(|e| e.kind == EntityType::UsMrn), "{ents:?}");
        // bare number without cue: not claimed
        let ents = engine_detect("ref 12345678", &["en"]);
        assert!(
            !ents.iter().any(|e| e.kind == EntityType::UsMrn),
            "{ents:?}"
        );
    }
}
