//! South African national phone number rule (geographic and mobile
//! numbers written with the national prefix `0`).
//!
//! Official sources (Independent Communications Authority of South
//! Africa, retrieved 2026-10-31):
//!
//! 1. Numbering Plan Regulations, GN 370, Government Gazette No. 39861,
//!    24 March 2016, <https://www.icasa.org.za/uploads/files/NumberingPlanReg.pdf>:
//!    13(3) "The national prefix is `0'."; 15(3) "A geographic number must
//!    have a length of ten (10) digits."; 16(2) "A non-geographic number
//!    other than a short code and machine related number must have a
//!    length of ten (10) digits."
//! 2. Amendment of the Numbering Plan Regulations, 2016 ("Numbering Plan
//!    Second Amendment Regulations, 2023"), GN 1719, Government Gazette
//!    No. 48328, 29 March 2023,
//!    <https://www.icasa.org.za/uploads/files/Amendment-of-the-Numbering-Plan-Regulations-2016.pdf>,
//!    regulations 12.2 and 13.2, which substitute Table 3 "Area code of
//!    geographic numbers" and Table 4 "Non-geographic ranges and
//!    services". Table 3 marks as "Released" the area codes 010-018,
//!    021-023, 027, 028, 031-036, 039-049, 051, 053, 054 and 056-058 (the
//!    rest are "Protected"). Table 4 assigns "Mobile services" to 050,
//!    052, 055, 059, 060-079 and 081-085; 080 is "Toll free services",
//!    086 "Inbound services", 087 VoIP, 088 and 089 "Future
//!    non-geographic services", 090-092 premium rate, 093-095 and 099
//!    "Protected", 096-098 "Machine related services". The Significance
//!    column merges cells across rows, and the text layer does not keep
//!    the merged blocks apart, so the block boundaries above were read
//!    from the cell borders drawn on the gazette pages (the same check on
//!    the 2016 table gives 060-074, 076-079 and 081-084 as its mobile
//!    blocks, superseded by the 2023 table).
//! 3. Numbering Plan Fourth Amendment Regulations, 2026, Notice 3997,
//!    Government Gazette No. 54930, 1 July 2026,
//!    <https://www.gov.za/sites/default/files/gcis_document/202607/54930gon3997.pdf>:
//!    it amends only regulations 1 and 6A and defines the regulations as
//!    GN 370 "as amended by Government Notices No. 245 ... of 15 April
//!    2020 and No. 1719 ... of 29 March 2023", so the 2023 tables are the
//!    ones in force.
//!
//! The validator accepts 10 digits whose first three are a released
//! geographic area code or a mobile block. Toll free, inbound, premium
//! rate and similar service numbers are not personal data and are not
//! claimed; VoIP (087) numbers are left out as well.
//!
//! Cue policy: none, score 0.80 (structural pattern; the other national
//! phone rules' precedent). A separator between the groups is required
//! (`082 123 4567`, `011-114-5678`) so a bare 10-digit run stays with the
//! identifier rules of other packs. Priority: the shared PHONE tier.

use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Released geographic area codes (Table 3 as substituted in 2023),
/// without the national prefix: the second and third digits.
const GEOGRAPHIC: &[u8] = &[
    10, 11, 12, 13, 14, 15, 16, 17, 18, 21, 22, 23, 27, 28, 31, 32, 33, 34, 35, 36, 39, 40, 41, 42,
    43, 44, 45, 46, 47, 48, 49, 51, 53, 54, 56, 57, 58,
];

/// Whether the second and third digits `nn` of a number name a released
/// geographic area code or a mobile block (Tables 3 and 4 as substituted
/// in 2023).
fn assigned_to_subscribers(nn: u8) -> bool {
    let mobile = matches!(nn, 50 | 52 | 55 | 59 | 60..=79 | 81..=85);
    mobile || GEOGRAPHIC.contains(&nn)
}

/// Returns `true` if `phone` is a South African national geographic or
/// mobile number: 10 digits after removing spaces and `-`, starting with
/// the national prefix `0`, whose first three digits are a released area
/// code or a mobile block of the ICASA numbering plan (2023 tables).
///
/// # Examples
/// ```
/// use redactify::valid_za_phone;
/// assert!(valid_za_phone("011 114 5678")); // Johannesburg, test range
/// assert!(valid_za_phone("082 123 4567")); // mobile block
/// assert!(!valid_za_phone("080 123 4567")); // toll free
/// assert!(!valid_za_phone("019 123 4567")); // protected area code
/// ```
#[must_use]
pub fn valid_za_phone(phone: &str) -> bool {
    let mut d = [0u8; 10];
    let mut n = 0;
    for b in phone.bytes() {
        match b {
            b'0'..=b'9' => {
                if n == d.len() {
                    return false;
                }
                d[n] = b - b'0';
                n += 1;
            }
            b' ' | b'-' => {}
            _ => return false,
        }
    }
    n == d.len() && d[0] == 0 && assigned_to_subscribers(d[1] * 10 + d[2])
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn phone_rule() -> Rule {
    rule!(
        EntityType::Phone,
        r"(?<!\d)0[1-8]\d[ -]\d{3}[ -]\d{4}(?!\d)",
        Some(valid_za_phone),
        ContextPolicy::None,
        0.80
    )
}

#[cfg(test)]
mod tests {
    use super::valid_za_phone;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn released_and_mobile_blocks() {
        for v in [
            "010 114 0000", // geographic test ranges 0XX 114-117 (15(4))
            "021 115 1234",
            "058 117 9999",
            "050 123 4567", // 2023: 050/052/055/059 moved to mobile
            "059 123 4567",
            "060 123 4567",
            "075 123 4567", // 2023: released for mobile services
            "079 123 4567",
            "081 123 4567",
            "085 123 4567", // 2023: released for mobile services
            "082-123-4567",
        ] {
            assert!(valid_za_phone(v), "{v}");
        }
        for v in [
            "019 123 4567",  // protected area code
            "024 123 4567",  // protected area code
            "080 123 4567",  // toll free
            "086 123 4567",  // inbound services
            "087 123 4567",  // VoIP
            "089 123 4567",  // future non-geographic
            "090 123 4567",  // premium rate
            "097 123 4567",  // machine related
            "082 123 456",   // 9 digits
            "082 123 45678", // 11 digits
            "82 123 4567",   // no national prefix
            "082.123.4567",  // foreign separator
        ] {
            assert!(!valid_za_phone(v), "{v}");
        }
    }

    #[test]
    fn separator_required_and_cue_less() {
        let ents = engine_detect("call 082 123 4567 today", &["za"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::Phone);
        assert!((ents[0].score - 0.80).abs() < 1e-6);
        assert!(engine_detect("call 0821234567 today", &["za"]).is_empty());
        assert!(engine_detect("free 080 123 4567 line", &["za"]).is_empty());
    }
}
