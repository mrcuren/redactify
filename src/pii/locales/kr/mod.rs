//! South Korean identifier rules: resident registration number (RRN),
//! foreigner registration number (FRN), business registration number
//! (BRN) and passport number.

pub(crate) mod brn;
pub(crate) mod frn;
pub(crate) mod passport;
pub(crate) mod rrn;

use crate::pii::locales::{days_in_month, is_leap_year, two_digits};

/// The 13 digits of a registration number written `YYMMDD-GNNNNNN` or
/// `YYMMDDGNNNNNN` (the National Tax Service's `XXXXXX-XXXXXXX` form and
/// its unseparated spelling); `None` for any other shape.
fn registration_digits(s: &str) -> Option<[u8; 13]> {
    let b = s.as_bytes();
    let mut out = [0u8; 13];
    match b.len() {
        13 => out.copy_from_slice(b),
        14 if b[6] == b'-' => {
            out[..6].copy_from_slice(&b[..6]);
            out[6..].copy_from_slice(&b[7..]);
        }
        _ => return None,
    }
    out.iter().all(u8::is_ascii_digit).then_some(out)
}

/// Shared check of the RRN and FRN: the shape of [`registration_digits`],
/// the seventh digit (`G`) mapped to a birth century by `century`, and a
/// real calendar date `YYMMDD` in that century.
fn valid_registration(s: &str, century: fn(u8) -> Option<u32>) -> bool {
    let Some(d) = registration_digits(s) else {
        return false;
    };
    let Some(base) = century(d[6]) else {
        return false;
    };
    let year = base + two_digits(&d[0..2]);
    let month = two_digits(&d[2..4]);
    let day = two_digits(&d[4..6]);
    day >= 1 && day <= days_in_month(month, is_leap_year(year))
}

#[cfg(test)]
mod tests {
    use super::{registration_digits, valid_registration};

    #[test]
    fn registration_shape_and_date() {
        assert_eq!(
            registration_digits("850102-1234567"),
            Some(*b"8501021234567")
        );
        assert_eq!(
            registration_digits("8501021234567"),
            Some(*b"8501021234567")
        );
        assert_eq!(registration_digits("85010-21234567"), None);
        assert_eq!(registration_digits("850102 1234567"), None);
        assert_eq!(registration_digits("850102-123456"), None);
        let any = |g: u8| (g == b'1').then_some(1900);
        assert!(!valid_registration("000229-1234567", any)); // 1900 is not leap
        assert!(valid_registration("040229-1234567", any)); // 1904 leap
        assert!(!valid_registration("040229-2234567", any)); // G unmapped
    }
}
