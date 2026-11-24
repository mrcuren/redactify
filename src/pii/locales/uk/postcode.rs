//! UK postcode: detection rule (structural,
//! no checksum exists). Evidence (two independent sources, retrieved
//! 2026-10-08):
//!
//! An independent public rule set: the canonical Ofcom-format
//! pattern (GIR 0AA special case plus the four outward-code classes
//! with restricted third-position letters) with context "postcode",
//! "post code", "postal code" (and broader words deliberately not
//! reused here).
//!
//! Wikipedia "Postcodes in the United Kingdom" documents the outward
//! code (area + district, optional sub-district letter) plus inward
//! code (sector digit + unit letters, excluding C I K M O V) and the
//! canonical public examples SW1A 1AA, EC1A 1BB, M1 1AE, B33 8TH and
//! GIR 0AA.
//!
//! Official source for the letter of the ANA outward form (corrected
//! 2026-10-31): Royal Mail "PAF Programmers' Guide", Edition 7 Version
//! 6.2, "Structure of a PAF address, Breakdown of a Postcode" and Table 16
//! "Valid Postcode formats"
//! (<https://www.poweredbypaf.com/wp-content/uploads/2024/11/Latest-Programmers_guide_Edition-7-Version-6-2.pdf>,
//! retrieved 2026-10-30): "The only letters to appear in the third alpha
//! position are A, B, C, D, E, F, G, H, J, K, P, R\*, S, T, U, V, W and X.
//! \* = R in the third position is only used in one Postcode, namely GIR
//! 0AA"; Table 16 gives the ANA example `W1P 1BB`, so P, V and X are
//! included. The ANA third character therefore takes
//! exactly that list (R only in `GIR 0AA`, handled by its own branch).
//!
//! The remaining letter positions follow the same passage:
//! "The letters Q, V and X are not used in the first alpha
//! position" (the area letter of every form: `[A-PR-UWYZ]`);
//! "The letters I and Z are not used in the second alpha position" (the
//! second letter of the AAN, AANN and AANA forms: `[A-HJ-Y]`, which
//! admits J); "The letters C I K M O V are not used in the second part of
//! the Postcode" (the two inward letters). The guide states no
//! class for the fourth character of the AANA form, so it takes any
//! letter: a narrower class would have no official source.
//! "Third alpha position" is read, as for the ANA form above, as the
//! third character when it is a letter (the ANA form). The other reading
//! (the third letter of an AANA code) would restrict the AANA fourth
//! letter to the same list and drop M, N, R and Y there; it is not
//! applied.
//!
//! FP policy (NINO precedent): no checksum exists, so a cue is
//! REQUIRED and the score stays at 0.9. The broad rule-set context
//! words ("address", "delivery", "shipping", "zip") are deliberately
//! NOT reused: they are common prose words that would unlock the shape
//! from ordinary text (documented deviation; the label forms cover the
//! realistic usages). Uppercase canonical form only.

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words that make a postcode candidate claimable.
pub(super) const CUES: &[&str] = &["postcode", "post code", "postal code"];

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::UkPostcode,
        r"(?<![A-Z0-9])(?:GIR ?0AA|[A-PR-UWYZ][0-9][ABCDEFGHJKPSTUVWX]?\s?[0-9][ABD-HJLNP-UW-Z]{2}|[A-PR-UWYZ][0-9]{2}\s?[0-9][ABD-HJLNP-UW-Z]{2}|[A-PR-UWYZ][A-HJ-Y][0-9][A-Z]?\s?[0-9][ABD-HJLNP-UW-Z]{2}|[A-PR-UWYZ][A-HJ-Y][0-9]{2}\s?[0-9][ABD-HJLNP-UW-Z]{2})(?![A-Z0-9])",
        None,
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    fn kinds(text: &str) -> Vec<EntityType> {
        engine_detect(text, &["uk"])
            .into_iter()
            .map(|e| e.kind)
            .collect()
    }

    #[test]
    fn canonical_postcodes_with_cue_detected() {
        // canonical public examples (Wikipedia/Ofcom)
        for pc in ["SW1A 1AA", "EC1A 1BB", "M1 1AE", "B33 8TH", "GIR 0AA"] {
            assert_eq!(
                kinds(&format!("postcode {pc} on file")),
                vec![EntityType::UkPostcode],
                "{pc}"
            );
        }
        // no-space variants
        assert_eq!(
            kinds("postal code SW1A1AA please"),
            vec![EntityType::UkPostcode]
        );
    }

    #[test]
    fn royal_mail_table_16_examples_detected() {
        // PAF Programmers' Guide Table 16 (every format) plus GIR 0AA;
        // W1P 1BB was missed before the ANA correction
        for pc in [
            "M1 1AA", "M60 1NW", "CR2 6XH", "DN55 1PT", "W1P 1BB", "EC1A 1BB", "PO1 1AF", "GIR 0AA",
        ] {
            assert_eq!(
                kinds(&format!("postcode {pc} on file")),
                vec![EntityType::UkPostcode],
                "{pc}"
            );
        }
        // the other Royal Mail ANA letters (V, X) and the excluded R
        assert_eq!(kinds("postcode W1V 1AA"), vec![EntityType::UkPostcode]);
        assert_eq!(kinds("postcode W1X 1AA"), vec![EntityType::UkPostcode]);
        assert!(kinds("postcode W1R 1AA").is_empty());
    }

    #[test]
    fn royal_mail_second_and_fourth_positions() {
        // derived vectors: J is allowed in the second alpha position (only
        // I and Z are excluded), and the AANA fourth letter is unrestricted
        for pc in [
            "AJ1 1AA", "AJ12 1AA", "AJ1A 1AA", "EC1M 1BB", "EC1C 1BB", "SW1D 1AA", "SW1Z 1AA",
        ] {
            assert_eq!(
                kinds(&format!("postcode {pc} on file")),
                vec![EntityType::UkPostcode],
                "{pc}"
            );
        }
        // derived invalid vectors: I and Z in the second alpha position, Q,
        // V and X in the first, and an inward letter from C I K M O V
        for pc in [
            "AI1 1AA", "AZ12 1AA", "QA1 1AA", "VA1 1AA", "XA1A 1AA", "EC1A 1AK",
        ] {
            assert!(kinds(&format!("postcode {pc} on file")).is_empty(), "{pc}");
        }
    }

    #[test]
    fn no_cue_or_bad_shape_stays_silent() {
        // no cue: ordinary prose with a postcode-shaped token
        assert!(kinds("see SW1A 1AA somewhere").is_empty());
        // lowercase is not the canonical form
        assert!(kinds("postcode sw1a 1aa here").is_empty());
        // invalid inward letters (C, I, K, M, O, V excluded by format)
        assert!(kinds("postcode SW1A 1CC here").is_empty());
        assert!(kinds("postcode Q1 1AA").is_empty()); // Q excluded from area letters
                                                      // the omitted broad cue words must NOT unlock the shape
        assert!(kinds("shipping SW1A 1AA today").is_empty());
        assert!(kinds("delivery EC1A 1BB monday").is_empty());
    }
}
