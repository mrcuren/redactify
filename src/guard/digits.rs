//! Unicode decimal digit blocks (GENERATED - do not edit by hand).
//!
//! Source: Unicode Character Database, data file `UnicodeData.txt`,
//! version 18.0.0.
//! URL: <https://www.unicode.org/Public/18.0.0/ucd/UnicodeData.txt>
//! SHA-256: 0736451de439ae7baf1425136617da495e09ee5afbe6e394374db7009ea08950
//! Data copyright (C) 1991-2026 Unicode, Inc.; distributed under the
//! Unicode License v3 (copyright and permission notice in NOTICE).
//!
//! Selection: Numeric_Type=Decimal (fields 6, 7 and 8 non-empty, UAX #44
//! Revision 38 section 5.4), checked equal to General_Category Nd; every block is
//! verified to be ten contiguous code points valued 0..9 (Unicode
//! Character Encoding Stability Policies). The ASCII block is omitted.
//! Generated from `UnicodeData.txt` by a generator kept outside this
//! repository (the repository holds Rust code only).

/// The DIGIT ZERO of every non-ASCII decimal block, sorted (76 blocks);
/// a character `c` is the digit `c - zero` when it lies within ten code
/// points of the greatest `zero <= c`. Binary-searched by the decimal
/// digit fold of
/// [`normalize_for_scan`](crate::guard::normalize::normalize_for_scan).
pub(crate) static DECIMAL_ZEROS: &[char] = &[
    '\u{0660}',
    '\u{06F0}',
    '\u{07C0}',
    '\u{0966}',
    '\u{09E6}',
    '\u{0A66}',
    '\u{0AE6}',
    '\u{0B66}',
    '\u{0BE6}',
    '\u{0C66}',
    '\u{0CE6}',
    '\u{0D66}',
    '\u{0DE6}',
    '\u{0E50}',
    '\u{0ED0}',
    '\u{0F20}',
    '\u{1040}',
    '\u{1090}',
    '\u{17E0}',
    '\u{1810}',
    '\u{1946}',
    '\u{19D0}',
    '\u{1A80}',
    '\u{1A90}',
    '\u{1B50}',
    '\u{1BB0}',
    '\u{1C40}',
    '\u{1C50}',
    '\u{A620}',
    '\u{A8D0}',
    '\u{A900}',
    '\u{A9D0}',
    '\u{A9F0}',
    '\u{AA50}',
    '\u{ABF0}',
    '\u{FF10}',
    '\u{104A0}',
    '\u{10D30}',
    '\u{10D40}',
    '\u{11066}',
    '\u{110F0}',
    '\u{11136}',
    '\u{111D0}',
    '\u{112F0}',
    '\u{11450}',
    '\u{114D0}',
    '\u{11650}',
    '\u{116C0}',
    '\u{116D0}',
    '\u{116DA}',
    '\u{11730}',
    '\u{118E0}',
    '\u{11950}',
    '\u{11BF0}',
    '\u{11C50}',
    '\u{11D50}',
    '\u{11DA0}',
    '\u{11DE0}',
    '\u{11F50}',
    '\u{16130}',
    '\u{16A60}',
    '\u{16AC0}',
    '\u{16B50}',
    '\u{16D70}',
    '\u{1CCF0}',
    '\u{1D7CE}',
    '\u{1D7D8}',
    '\u{1D7E2}',
    '\u{1D7EC}',
    '\u{1D7F6}',
    '\u{1E140}',
    '\u{1E2F0}',
    '\u{1E4F0}',
    '\u{1E5F1}',
    '\u{1E950}',
    '\u{1FBF0}',
];
