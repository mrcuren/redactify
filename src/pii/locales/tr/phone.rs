//! Turkish phone numbers: detection rule (structural pattern, no checksum).
// Mobile `5xx` with 0/+90 prefix or separators; landline with a mandatory
// separator after the area code (a bare 10-digit VKN is never claimed).

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::Phone,
        r"(?:(?:\+90|0)[\s-]?5\d{2}[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}|5\d{2}[\s-]\d{3}[\s-]\d{2}[\s-]\d{2}|0[\s-]?[234]\d{2}[\s-]\d{3}[\s-]?\d{2}[\s-]?\d{2})(?!\d)",
        None,
        ContextPolicy::None,
        0.8
    )
}
