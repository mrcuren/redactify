//! EU VAT identification numbers (27 Member States + Northern Ireland
//! `XI`): format validator + rule. FORMAT ONLY - no checksum.
//!
//! Official source (retrieved 2026-10-29): European Commission, DG TAXUD,
//! VIES (VAT Information Exchange System) FAQ, question 11, served by the
//! VIES web application <https://ec.europa.eu/taxation_customs/vies/#/faq>
//! from its translation resource
//! <https://ec.europa.eu/taxation_customs/vies/rest-api/translations?lang=en>.
//!
//! - Q11 "Is it possible to know the algorithms used by Member States /
//!   Northern Ireland in the construction of their VAT identification
//!   numbers?" - "The European Commission cannot divulge these algorithms.
//!   However, the structure of VAT identification numbers is given in the
//!   table below."
//! - Table "VAT identification number structure" (Format column): AT
//!   `ATU99999999` (note 1: "The 1st position following the prefix is
//!   always 'U'"), BE `BE0999999999` / `BE1999999999`, BG `BG999999999` or
//!   `BG9999999999`, CY `CY99999999L`, CZ `CZ99999999` or `CZ999999999` or
//!   `CZ9999999999`, DE `DE999999999`, DK `DK99 99 99 99`, EE
//!   `EE999999999`, EL `EL999999999`, ES `ESX9999999X` (note 4: "The first
//!   and last characters may be alpha or numeric; but they may not both be
//!   numeric."), FI `FI99999999`, FR `FRXX 999999999`, HR
//!   `HR99999999999`, HU `HU99999999`, IE `IE9S99999L` / `IE9999999LL`, IT
//!   `IT99999999999`, LT `LT999999999` or `LT999999999999`, LU
//!   `LU99999999`, LV `LV99999999999`, MT `MT99999999`, NL
//!   `NLSSSSSSSSSSSS`, PL `PL9999999999`, PT `PT999999999`, RO "1 block of
//!   minimum 2 digits and maximum 10 digits", SE `SE999999999999`, SI
//!   `SI99999999`, SK `SK9999999999`, XI `XI999 9999 99` or
//!   `XI999 9999 99 999` (note 5: branch traders) or `XIGD999` (note 6:
//!   Government Departments) or `XIHA999` (note 7: Health Authorities).
//! - Remarks: "9: A digit", "X: A letter or a digit", "S: A letter; a
//!   digit; '+' or '*'", "L: A letter". Note 8: "All letters are case
//!   sensitive. Please follow the exact syntax of the VAT number shown."
//!
//! Sweden: the national structure is narrower than the VIES row. Swedish
//! Tax Agency, "Momsregistreringsnummer (VAT-nummer) i EU-länderna"
//! (retrieved 2026-10-31),
//! <https://www.skatteverket.se/foretag/moms/saljavarorochtjanster/forsaljningtillandraeulander/kontrolleramomsregistreringsnummervatnummer/momsregistreringsnummer.4.18e1b10334ebe8bc80002649.html>:
//! "Sverige SE 999999999999 12 siffror" with note l) "De två sista
//! siffrorna är alltid 01." (also stated by the Bundeszentralamt für
//! Steuern, "Aufbau der Umsatzsteuer-Identifikationsnummer (USt-IdNr.) in
//! den EU-Mitgliedstaaten", retrieved 2026-10-30,
//! <https://www.bzst.de/SharedDocs/Downloads/DE/Merkblaetter/ust_idnr_aufbau.pdf?__blob=publicationFile&v=8>:
//! "Schweden ... MomsNr. SE zwölf, nur Ziffern, die beiden letzten Stellen
//! bestehen immer aus der Ziffernkombination "01""). SE numbers must
//! therefore end in `01`.
//!
//! The table's `GB` rows are out of scope (not a Member State; UK VAT has
//! its own checksummed rule in the `uk` pack). The detection pattern
//! accepts spaces only where the table shows them (DK, FR, XI); the
//! public validator ignores ASCII spaces. National check-digit
//! algorithms are NOT implemented: the Commission does not publish them
//! and no official national algorithm source has been retrieved,
//! so every country uses the format alone.
//!
//! Cue policy: a cue is REQUIRED (score 0.9: format + mandatory cue, no
//! checksum). Cues are the names of the identifier in the VIES table title
//! of each official language version (`faq_label_vatidentification`, e.g.
//! en "VAT identification number structure", de "Struktur der
//! MwSt-Identifizierungsnummern", fr "Structure des numéros
//! d'identification TVA", es/it "IVA", nl "btw-nummer", da "Momsnumres",
//! sv "Momsregistreringsnumrens", fi "Alv-tunnisteen", et
//! "Käibemaksukohustuslasena", el "ΦΠΑ", bg "ДДС", cs "daňového
//! identifikačního čísla", hr "PDV", sl "DDV", sk "IČ DPH", lt "PVM", lv
//! "PVN", hu "adószámok").
//!
//! Delimited short cues: cues match as lowercase substrings, and the
//! three-letter names `vat`, `tva` and `iva` occur inside ordinary words
//! ("private", "elevator", "derivative"; Lithuanian "tvarkymo", Slovenian
//! "varstva"; Italian "direttiva", Finnish "voivat"), so they are listed
//! only with a delimiter next to them (plus the labels the bare names
//! would catch: "VATIN", "VAT_ID", "PIVA", "TVA intracommunautaire").
//! Measured on the official text of Regulation (EU) 2016/679 in all 24
//! languages (Publications Office of the EU,
//! <http://publications.europa.eu/resource/celex/32016R0679>, retrieved
//! 2026-10-31; the regulation never names a VAT number, so every hit is
//! a false cue). With plain substring matching the bare names hit 7,385
//! times (`vat` 3,166, `tva` 1,547, `iva` 2,672) and the delimited forms
//! 859 times, 854 of them `vat ` after a word ending in "vat" (Estonian
//! "käesolevat", Finnish "ovat", Swedish "adekvat"). With the word-start
//! rule of `pii::context` (a cue of at most five characters that starts
//! with an ASCII letter counts only at a word start) the bare names still
//! hit 1,029 times (`tva` starting Lithuanian "tvarkymas") and the
//! delimited forms 0 times. `vat ` stays because it is the only form
//! that sees a label at the start of a line ("VAT DE123456789"). `tva`,
//! `iva` and
//! `piva` get no form whose only delimiter is a space after the name
//! (`tva `, `iva ` and `piva ` hit 236, 786 and 1 times, the last in
//! Finnish "yhteensopiva"), and `tva` none with only a space before it
//! (` tva` hits 1,029 times in Lithuanian "tvarkymas"), so a line-initial
//! "TVA FR..." / "IVA IT..." / "PIVA IT..." with only a space after the
//! name, and a line-final "FR... TVA", are not cued. `moms` (9
//! hits, inside Lithuanian datives) stays bare: it mostly begins a
//! compound ("momsregistreringsnummer").

use crate::pii::entity::EntityType;

use crate::pii::locales::{rule, ContextPolicy, Rule};

/// Cue words: the VAT number's name in the VIES table title of each
/// official language (lowercased fragments of the source wording). The
/// names `vat`, `tva` and `iva` occur inside other words, so they are
/// listed only with a delimiter next to them (module doc).
pub(super) const CUES: &[&str] = &[
    // "VAT DE...", "VAT: DE...", "VAT-ID", "VAT/Tax ID", "VAT#", "(VAT)",
    // "VAT_ID", "VATIN"
    "vat ",
    "vat:",
    "vat-",
    "vat/",
    "vat#",
    "vat)",
    "vat_",
    " vat",
    "(vat",
    "/vat",
    "-vat",
    "vatin ",
    "vatin:",
    "mwst",
    // "N° TVA FR...", "TVA : FR...", "(TVA)", "Id.TVA", "TVA
    // intracommunautaire"; never a bare leading " tva" (Lithuanian
    // "tvarkymas") or trailing "tva " (Slovenian "varstva")
    " tva ",
    " tva:",
    " tva-",
    " tva.",
    " tva)",
    " tva,",
    "(tva",
    "/tva",
    "-tva",
    ".tva",
    "°tva",
    "tva:",
    "tva :",
    "tva intra",
    // "partita IVA", "P.IVA", "PIVA", "NIF-IVA", "IVA:"; never a trailing
    // "iva " (Italian "direttiva", Spanish "relativa") or "piva " (Finnish
    // "sopiva")
    " iva",
    ".iva",
    "-iva",
    "(iva",
    "/iva",
    "iva:",
    " piva",
    "piva:",
    // line-start labels ("TVA FR...", "IVA IT...", "PIVA IT..."): short
    // cues count only at a word start (see `pii::context`), and the
    // trailing space keeps "tvarkymas" / "sopiva"-style words out
    "tva ",
    "iva ",
    "piva ",
    "btw",
    "moms",
    "alv-tunniste",
    "käibemaks",
    "φπα",
    "ддс",
    "identifikační",
    "pdv",
    "ddv",
    "dph",
    "pvm",
    "pvn",
    "adószám",
];

fn digits(s: &[u8]) -> bool {
    s.iter().all(u8::is_ascii_digit)
}

fn upper(c: u8) -> bool {
    c.is_ascii_uppercase()
}

/// VIES "X": a letter or a digit (letters are uppercase, note 8).
fn x_char(c: u8) -> bool {
    c.is_ascii_digit() || upper(c)
}

/// VIES "S": a letter, a digit, '+' or '*'.
fn s_char(c: u8) -> bool {
    x_char(c) || c == b'+' || c == b'*'
}

/// Returns `true` if `vat` matches the VIES published structure of an EU
/// VAT identification number: a Member State prefix (`AT` ... `SK`, Greece
/// `EL`) or Northern Ireland `XI` followed by that country's format.
/// ASCII spaces are ignored. Letters are case sensitive (uppercase). This
/// is a FORMAT check: no national check digit is verified.
///
/// # Examples
/// ```
/// use redactify::valid_eu_vat;
/// assert!(valid_eu_vat("ATU12345678"));
/// assert!(valid_eu_vat("DE123456789"));
/// assert!(valid_eu_vat("DK12 34 56 78"));
/// assert!(valid_eu_vat("ESX1234567B"));
/// assert!(valid_eu_vat("SE999999999901"));
/// assert!(!valid_eu_vat("SE999999999999")); // SE always ends in 01
/// assert!(!valid_eu_vat("ES123456789")); // ES: first and last both numeric
/// assert!(!valid_eu_vat("GB123456789")); // not an EU Member State
/// assert!(!valid_eu_vat("de123456789")); // case sensitive
/// ```
#[must_use]
pub fn valid_eu_vat(vat: &str) -> bool {
    let compact: Vec<u8> = vat.bytes().filter(|&c| c != b' ').collect();
    if compact.len() < 4 {
        return false;
    }
    let (cc, r) = compact.split_at(2);
    let n = r.len();
    match cc {
        b"AT" => n == 9 && r[0] == b'U' && digits(&r[1..]),
        b"BE" => n == 10 && (r[0] == b'0' || r[0] == b'1') && digits(r),
        b"BG" => (n == 9 || n == 10) && digits(r),
        b"CY" => n == 9 && digits(&r[..8]) && upper(r[8]),
        b"CZ" => (8..=10).contains(&n) && digits(r),
        b"DE" | b"EE" | b"EL" | b"PT" => n == 9 && digits(r),
        b"DK" | b"FI" | b"HU" | b"LU" | b"MT" | b"SI" => n == 8 && digits(r),
        b"ES" => {
            n == 9
                && x_char(r[0])
                && digits(&r[1..8])
                && x_char(r[8])
                && !(r[0].is_ascii_digit() && r[8].is_ascii_digit())
        }
        b"FR" => n == 11 && x_char(r[0]) && x_char(r[1]) && digits(&r[2..]),
        b"HR" | b"IT" | b"LV" => n == 11 && digits(r),
        b"IE" => {
            (n == 8 && r[0].is_ascii_digit() && s_char(r[1]) && digits(&r[2..7]) && upper(r[7]))
                || (n == 9 && digits(&r[..7]) && upper(r[7]) && upper(r[8]))
        }
        b"LT" => (n == 9 || n == 12) && digits(r),
        b"NL" => n == 12 && r.iter().all(|&c| s_char(c)),
        b"PL" | b"SK" => n == 10 && digits(r),
        b"RO" => (2..=10).contains(&n) && digits(r),
        // Skatteverket: "De två sista siffrorna är alltid 01."
        b"SE" => n == 12 && digits(r) && r.ends_with(b"01"),
        b"XI" => {
            ((n == 9 || n == 12) && digits(r))
                || (n == 5 && (r.starts_with(b"GD") || r.starts_with(b"HA")) && digits(&r[2..]))
        }
        _ => false,
    }
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::EuVat,
        concat!(
            r"(?<![0-9A-Za-z])(?:",
            r"ATU\d{8}|BE[01]\d{9}|BG\d{9,10}|CY\d{8}[A-Z]|CZ\d{8,10}|DE\d{9}",
            r"|DK\d{2} ?\d{2} ?\d{2} ?\d{2}|EE\d{9}|EL\d{9}|ES[0-9A-Z]\d{7}[0-9A-Z]",
            r"|FI\d{8}|FR[0-9A-Z]{2} ?\d{9}|HR\d{11}|HU\d{8}",
            r"|IE\d[0-9A-Z+*]\d{5}[A-Z]|IE\d{7}[A-Z]{2}|IT\d{11}|LT(?:\d{12}|\d{9})",
            r"|LU\d{8}|LV\d{11}|MT\d{8}|NL[0-9A-Z+*]{12}|PL\d{10}|PT\d{9}",
            r"|RO\d{2,10}|SE\d{10}01|SI\d{8}|SK\d{10}",
            r"|XI(?:\d{3} ?\d{4} ?\d{2}(?: ?\d{3})?|GD\d{3}|HA\d{3})",
            r")(?![0-9A-Za-z])"
        ),
        Some(valid_eu_vat),
        ContextPolicy::RequiredCue(CUES),
        0.9
    )
}

#[cfg(test)]
mod tests {
    use super::valid_eu_vat;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    /// One VIES-format example per prefix (digits arbitrary: format only).
    const VALID: &[&str] = &[
        "ATU12345678",
        "BE0123456789",
        "BE1123456789",
        "BG123456789",
        "BG1234567890",
        "CY12345678L",
        "CZ12345678",
        "CZ123456789",
        "CZ1234567890",
        "DE123456789",
        "DK12 34 56 78",
        "DK12345678",
        "EE123456789",
        "EL123456789",
        "ESX1234567B",
        "ESA12345678",
        "ES12345678Z",
        "FI12345678",
        "FRXX 123456789",
        "FR12123456789",
        "HR12345678901",
        "HU12345678",
        "IE1A23456B",
        "IE1+23456B",
        "IE1234567AB",
        "IT12345678901",
        "LT123456789",
        "LT123456789012",
        "LU12345678",
        "LV12345678901",
        "MT12345678",
        "NL123456789B01",
        "PL1234567890",
        "PT123456789",
        "RO12",
        "RO1234567890",
        "SE123456789001",
        "SI12345678",
        "SK1234567890",
        "XI123 4567 89",
        "XI123 4567 89 012",
        "XIGD123",
        "XIHA123",
    ];

    #[test]
    fn every_vies_format_is_accepted() {
        for v in VALID {
            assert!(valid_eu_vat(v), "{v}");
        }
    }

    #[test]
    fn off_format_values_are_rejected() {
        for v in [
            "AT12345678",     // AT needs the U
            "BE2123456789",   // BE starts with 0 or 1
            "CY123456789",    // CY ends with a letter
            "CZ1234567",      // 7 digits
            "DE12345678",     // 8 digits
            "ES123456789",    // both ends numeric
            "FR1234567890",   // 10 characters after FR
            "IE12345678",     // neither IE form
            "LT1234567890",   // 10 digits
            "NL123456789B0",  // 11 characters
            "RO1",            // fewer than 2 digits
            "RO12345678901",  // more than 10 digits
            "SE123456789012", // SE must end in 01 (Skatteverket)
            "XIGB123",        // only GD/HA
            "GB123456789",    // not a Member State
            "EU123456789",    // no such prefix
            "de123456789",    // case sensitive
            "ATu12345678",    // case sensitive
            "DE",             // prefix only
        ] {
            assert!(!valid_eu_vat(v), "{v}");
        }
    }

    #[test]
    fn rule_requires_a_cue_and_matches_every_format() {
        for v in VALID {
            let text = format!("VAT {v} ok");
            let ents = engine_detect(&text, &["eu"]);
            assert_eq!(ents.len(), 1, "{v}: {ents:?}");
            assert_eq!(ents[0].kind, EntityType::EuVat, "{v}");
            assert_eq!(ents[0].text, *v);
            assert!((ents[0].score - 0.9).abs() < 1e-6);
        }
        assert!(engine_detect("ref DE123456789 ok", &["eu"]).is_empty());
        // national-language cues from the VIES table titles
        for t in [
            "USt / MwSt-Nr. DE123456789",
            "numéro TVA FRXX 123456789",
            "partita IVA IT12345678901",
            "btw-nummer NL123456789B01",
            "ΑΦΜ / ΦΠΑ EL123456789",
        ] {
            let ents = engine_detect(t, &["eu"]);
            assert_eq!(ents.len(), 1, "{t}: {ents:?}");
        }
        // an IBAN is not a VAT number (followed by more digits)
        assert!(engine_detect("VAT DE89370400440532013000", &["eu"])
            .iter()
            .all(|e| e.kind != EntityType::EuVat));
    }

    #[test]
    fn short_names_inside_words_are_no_cue() {
        // one trap per delimited name: the name occurs inside a word
        for t in [
            "private DE123456789 room",        // vat in "private"
            "elevator ATU12345678 stuck",      // vat in "elevator"
            "derivative IT12345678901 priced", // vat and iva in "derivative"
            "duomenu tvarkymo LT123456789 ok", // tva in Lithuanian "tvarkymo"
            "varstva SI12345678 podatkov",     // tva at the end of "varstva"
            "la direttiva IT12345678901 vale", // iva at the end of "direttiva"
        ] {
            assert!(
                engine_detect(t, &["eu"])
                    .iter()
                    .all(|e| e.kind != EntityType::EuVat),
                "{t}"
            );
        }
    }

    #[test]
    fn delimited_names_keep_their_labels() {
        for t in [
            "VAT DE123456789",
            "VAT: DE123456789",
            "VAT-ID DE123456789",
            "Our VAT number is DE123456789",
            "DE123456789 (VAT)",
            "USt-IdNr./VAT DE123456789",
            "N° TVA FRXX 123456789",
            "TVA : FRXX 123456789",
            "TVA: FRXX 123456789",
            "partita IVA IT12345678901",
            "P.IVA IT12345678901",
            "IVA: IT12345678901",
            "NIF-IVA ESX1234567B",
            "IT12345678901 IVA",
            "VATIN DE123456789",
            "VAT_ID DE123456789",
            "C.F. / PIVA IT12345678901",
            "TVA intracom. FRXX 123456789",
        ] {
            let ents = engine_detect(t, &["eu"]);
            assert_eq!(ents.len(), 1, "{t}: {ents:?}");
            assert_eq!(ents[0].kind, EntityType::EuVat, "{t}");
        }
    }
}
