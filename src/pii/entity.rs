//! Entity types and span representation for detected PII.
//!
//! [`Entity::start`] / [`Entity::end`] are **byte offsets**; they come from regex
//! match boundaries and therefore always sit on UTF-8 character boundaries
//! (slicing never panics).

use std::fmt;

/// Detectable PII entity types.
///
/// The entity with the lower `priority()` wins among overlapping candidates
/// (e.g. digit groups inside an IBAN can never be claimed as a VKN).
///
/// serde (feature `serde`): a value is its canonical [`as_str`](Self::as_str)
/// label (`"TCKN"`, `"PL_PESEL"`, a custom label); deserializing parses it
/// with [`FromStr`](std::str::FromStr), which accepts a custom label only
/// once it has been registered with [`EntityType::custom`] (input never
/// registers a new label).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum EntityType {
    /// IBAN (ISO 13616): the always-on international rule validates the
    /// exact registry length of 89 countries plus mod-97; the `tr` pack
    /// adds a Turkish-specific rule (TR + 24 digits, lowercase-tolerant).
    Iban,
    /// Credit/bank card (Luhn validated).
    CreditCard,
    /// Vehicle plate (81-province aware).
    Plaka,
    /// Turkish national ID (11 digits, two check digits).
    Tckn,
    /// E-mail address.
    Email,
    /// Phone number (prefixed or separator-bearing mobile; landline with separators).
    Phone,
    /// Turkish passport number (`U` or `S` + 8 digits; context cue required).
    Passport,
    /// US Social Security Number (separator-bearing format + structural rules).
    Ssn,
    /// US Individual Taxpayer Identification Number (`9xx` + restricted middle).
    Itin,
    /// US passport number (Next Generation: one letter + 8 digits; cue required).
    UsPassport,
    /// Turkish tax number (10 digits, single check digit + context rule).
    Vkn,
    /// French NIR (numéro de sécurité sociale): 13 digits + mod-97 key
    /// (15 digits total; Corsica 2A/2B departments supported).
    Nir,
    /// Spanish DNI: 8 digits + mod-23 control letter (cue required - a
    /// single check letter admits ~4% of random shapes).
    Dni,
    /// Dutch BSN: 9 digits, elfproef (weighted sum, last digit weighted -1,
    /// mod 11; cue required - ~9% of random 9-digit runs pass).
    Bsn,
    /// UK NINO: structural (2 prefix letters + 6 digits + optional A-D
    /// suffix; no checksum exists -> cue required).
    Nino,
    /// German Steuer-IdNr (steuerliche Identifikationsnummer): 11 digits,
    /// first digit non-zero, ISO/IEC 7064 MOD 11,10 check digit (cue
    /// required - a single check digit admits ~10% of random shapes).
    DeTaxId,
    /// UK NHS number: 10 digits, weighted digit sum (weights 10..1) ≡ 0
    /// mod 11 (cue required - a single check digit admits ~9% of random
    /// 10-digit shapes).
    UkNhs,
    /// Spanish NIE (número de identidad de extranjero): `X`/`Y`/`Z` + 7
    /// digits + mod-23 control letter; the letter prefix maps to 0/1/2
    /// before the mod (same table as the DNI; cue required).
    Nie,
    /// German identity card document number: 9 uppercase letters or digits
    /// (4-character authority code + 5-character serial), or the
    /// provisional letter + 7 digits form. Its ICAO check digit stands
    /// outside the 9 characters (in the machine-readable zone), so this is
    /// a format rule (cue required).
    DeIdCard,
    /// Italian codice fiscale: 16 characters (surname/name letters, birth
    /// date encoding, comune code) with a mod-26 control character (cue
    /// required - a single control character admits ~4% of random shapes).
    ItFiscalCode,
    /// SWIFT BIC (ISO 9362): 8 or 11 characters - 4-letter institution
    /// code + ISO 3166-1 alpha-2 country + 2-character location + optional
    /// 3-character branch (no checksum exists -> cue required).
    SwiftBic,
    /// Polish PESEL: 11 digits encoding a birth date (century via the
    /// month tens digit) with a weighted (1,3,7,9,...) mod-10 check digit
    /// (cue required - a single check digit admits ~10% of shapes).
    /// Its serde label is the canonical `as_str()` spelling "PL_PESEL"
    /// (a derived SCREAMING_SNAKE_CASE name would be the locale-less
    /// "PESEL").
    Pesel,

    /// Canadian SIN: 9 digits, separator-bearing form, Luhn check, first
    /// digit never 0 or 8 (unissued prefixes; cue required).
    CaSin,
    /// Australian TFN (tax file number): 9 digits, weighted sum
    /// (1,4,3,7,5,8,6,9,10) divisible by 11 (cue required).
    AuTfn,
    /// Singapore NRIC/FIN: `S`/`T`/`F`/`G`/`M` + 7 digits + a letter.
    /// The checksum algorithm is not officially published, so this is a
    /// structural rule only (cue required).
    SgNricFin,
    /// Indian PAN: 3 letters + a holder-type letter (`A`/`B`/`C`/`F`/`G`/
    /// `H`/`J`/`L`/`P`/`T`) + letter + 4 digits + letter; no public
    /// checksum validation (cue required).
    InPan,
    /// Indian Aadhaar: 12 digits, first digit 2-9, Verhoeff check digit
    /// (cue required).
    InAadhaar,
    /// Australian Medicare card number: 10 digits (first 2-6), 9th a
    /// check digit (weights 1,3,7,9,1,3,7,9, sum mod 10), 10th the issue
    /// number (cue required).
    AuMedicare,
    /// Vehicle Identification Number (ISO 3779): 17 chars, position 9
    /// check digit (transliteration table, weights 8-2, mod 11, remainder
    /// 10 = 'X'). International, always on.
    Vin,
    /// Australian Business Number: 11 digits, mod-89 check (subtract 1
    /// from first digit, weights 10,1,3,5,7,9,11,13,15,17,19; sum % 89
    /// == 0). Cue required.
    AuAbn,
    /// UK VAT registration: 9 digits, weighted mod-97 check (last two
    /// digits = 97 - sum%97, with alternative series 42/55). Cue
    /// required.
    UkVat,
    /// French SIRET: 14 digits (SIREN + NIC), Luhn mod-10 over all 14.
    /// Cue required.
    FrSiret,
    /// Polish NIP: 10 digits, weighted mod-11 check digit (weights
    /// 6,5,7,2,3,4,5,6,7; remainder 10 never issued). Cue required.
    PlNip,
    /// UK UTR (Unique Taxpayer Reference): 10 digits. The check digit
    /// algorithm is not publicly documented (HMRC FOI refused); format
    /// + cue only (NINO precedent).
    UkUtr,
    /// UK passport number: 9 digits, all numeric. No checksum exists;
    /// cue required (PASSPORT precedent).
    UkPassport,
    /// German passport number (Reisepass 2010+): 9 chars, position 1 in
    /// {C,F,G,H,J,K}, remaining 8 in the ICAO subset (no I,O,Q,0 in
    /// Wikipedia-strict form). No checksum on the printed number; cue
    /// required.
    DePassport,
    /// US Medical Record Number: NO national standard exists (HL7 MR
    /// type, facility-specific). Cue-gated heuristic (6-10 digits
    /// adjacent to "MRN"/"medical record"/"patient ID").
    UsMrn,
    /// UK postcode: Ofcom outward+inward format (GIR 0AA special case);
    /// no checksum exists (cue required).
    UkPostcode,
    /// German PLZ: 5 digits in the assigned range 01001-99998 (the exact
    /// bookends 01000 and 99999 are unassigned; no checksum - cue
    /// required).
    DePlz,
    /// US ZIP code: 5 digits (00001-99950 assigned range; leading 00000
    /// unassigned). No checksum; cue required (PLZ precedent).
    UsZip,
    /// French postal code (code postal): 5 digits (01000-99999 metro +
    /// overseas 97xxx-98xxx). No checksum; cue required (PLZ precedent).
    FrPostal,
    /// Portuguese NIF: 9 digits, first digit non-zero, weighted mod-11
    /// check digit (cue required). Priority tier 3: its spaced 3-3-3
    /// shape collides with the cue-less pt phone rule, so the
    /// checksummed claim outranks the structural one (checksum beats
    /// structural - UK_NHS precedent).
    PtNif,
    /// Brazilian CPF (Cadastro de Pessoas Físicas): 11 digits, two mod-11
    /// check digits (Receita Federal routine). The `ddd.ddd.ddd-dd` mask
    /// is claimed cue-less; a bare 11-digit run requires a "cpf" cue.
    BrCpf,
    /// Brazilian CNPJ, numeric or alphanumeric (IN RFB 2.229/2024, from
    /// July 2026): 12 characters `[0-9A-Z]` + 2 numeric mod-11 check
    /// digits over `ASCII - 48` values. The `XX.XXX.XXX/XXXX-DV` mask is
    /// claimed cue-less; a bare 14-character run requires a "cnpj" cue.
    BrCnpj,
    /// Chinese citizen identification number (GB 11643-1999): 17 digits +
    /// ISO 7064 MOD 11-2 check character (`0`-`9` or `X`) with an
    /// embedded `YYYYMMDD` birth date. Claimed cue-less.
    CnResidentId,
    /// Swedish personnummer / samordningsnummer (Skatteverket SKV 704):
    /// `YYMMDD-NNNC` (`+` from age 100) or the 12-digit stored form; Luhn
    /// (modulus 10, weights 2/1) check digit, samordningsnummer day + 60.
    SePersonnummer,
    /// Finnish henkilötunnus (decree 128/2010 as amended by 690/2022):
    /// `DDMMYY`, a century sign (`+`, `-`/`Y X W V U`, `A`-`F`), 3 digits
    /// and a mod-31 check character. Claimed cue-less.
    FiHetu,
    /// Norwegian fødselsnummer / d-nummer (Folkeregisteret): 11 digits,
    /// `DDMMYY` (d-nummer day + 40) + individual digits + two mod-11
    /// control digits, the first under the 2032 rule (remainder 0-3).
    /// Cue required.
    NoFodselsnummer,
    /// Danish CPR personnummer: `DDMMYY-SSSS`; birth date validated with
    /// the century table, NO modulus 11 check (the CPR office issues
    /// numbers without a control digit). Cue required.
    DkCpr,
    /// EU VAT identification number (27 Member States + `XI`): country
    /// prefix + the VIES published structure. The Commission does not
    /// publish the national algorithms, so this is a format rule only
    /// (cue required).
    EuVat,
    /// US ABA routing transit number: 9 digits, first two 01-12 or 21-32,
    /// 3-7-1 weighted check digit (IRS Pub 1346; cue required).
    UsAbaRouting,
    /// US Medicare Beneficiary Identifier: 11 characters in the CMS
    /// position table (no S, L, O, I, B, Z); format only, cue required.
    UsMbi,
    /// US National Provider Identifier: 10 digits, first 1 or 2, Luhn
    /// check digit over the `80840`-prefixed number (CMS; cue required).
    UsNpi,
    /// US Employer Identification Number: `XX-XXXXXXX` with an IRS
    /// campus prefix; format only, cue required.
    UsEin,
    /// Canadian postal code: `ANA NAN`, first letter one of the 18 Canada
    /// Post major areas; format only, cue required.
    CaPostalCode,
    /// UK (GB) driving licence driver number: 16 characters (DVLA INS57P:
    /// surname, encoded birth date, initials, check characters); format
    /// only, cue required.
    UkDrivingLicence,
    /// UK (GB) vehicle registration number: current (`AA68 ABC`, DVLA
    /// INF104 memory tag + age identifier), prefix and suffix styles;
    /// format only, cue required.
    UkVehicleRegistration,
    /// Australian Company Number: 9 digits, ASIC modified modulus 10
    /// check digit (weights 8 to 1; cue required).
    AuAcn,
    /// German Steuernummer of the Länder tax offices (ELSTER
    /// "Prüfung der Steuer- und Steueridentifikationsnummer"): the 13-digit
    /// ELSTER form or a printed Bescheid layout, Land-specific check digit
    /// (cue required).
    DeTaxNumber,
    /// German health insurance number, unchangeable part (Versicherten-ID,
    /// KBV KVDT field 3119): a letter + 8 digits + a mod-10 check digit
    /// (cue required).
    DeKvnr,
    /// German pension insurance number (§ 147 SGB VI, § 2 Abs. 6 VKVV):
    /// 8 digits + a letter + 2 digits + a check digit (cue required).
    DeRvnr,
    /// German lifelong physician number (LANR, KBV guideline § 2 + ANRV
    /// § 4): 9 digits, the 7th a check digit (cue required).
    DeLanr,
    /// German practice site number (BSNR, KBV guideline § 6): 9 digits
    /// starting with a KV key; no check digit (cue required).
    DeBsnr,
    /// German vehicle registration plate (FZV § 9, Anlage 1 and 4); no
    /// check character (cue required).
    DeKfz,
    /// Italian passport number (MAE decree, GU 19-05-2010): 2 letters + 7
    /// digits; no check character (cue required).
    ItPassport,
    /// Swedish organisationsnummer (Lag 1974:174, SKV 709): 10 digits,
    /// third digit at least 2; the check digit's algorithm is not
    /// published (cue required).
    SeOrganisationsnummer,
    /// Singapore Unique Entity Number (UEN formats A, B and C); the check
    /// letter's algorithm is not published (cue required).
    SgUen,
    /// Indian GSTIN (CGST Rules 2017, Rule 10): 2-digit State code, PAN,
    /// entity code and checksum character (15 characters). The checksum
    /// algorithm is not officially published: format + cue only.
    InGstin,
    /// South Korean business registration number (NTS): 10 digits
    /// `XXX-XX-XXXXX`; no published check digit (cue required).
    KrBrn,
    /// South Korean foreigner registration number (NTS): `YYMMDD-GNNNNNN`
    /// with gender digit 5-8 and a real birth date; no published check
    /// digit (cue required).
    KrFrn,
    /// South Korean passport number: letter + 8 digits or letter + 3
    /// digits + letter + 4 digits (MOFA/MCST); format only (cue
    /// required).
    KrPassport,
    /// South Korean resident registration number (NTS): `YYMMDD-GNNNNNN`
    /// with gender digit 1-4 and a real birth date; no check digit
    /// (random since 2020; cue required).
    KrRrn,
    /// Nigerian National Identity Number (NIMC): 11 digits; no published
    /// check digit (cue required).
    NgNin,
    /// Philippine Taxpayer Identification Number (BIR RMO 23-91): 9
    /// digits; format only (cue required).
    PhTin,
    /// South African identity number (Identification Regulations reg 3):
    /// 13 digits, `YYMMDD` birth date, citizenship digit 0-2, Luhn control
    /// figure (SARS). Claimed cue-less.
    ZaIdNumber,
    /// South African income tax reference number (SARS): 10 digits, first
    /// digit 0-3 or 9, modulus 10 (Luhn) check digit (cue required).
    ZaTaxReference,
    /// South African VAT registration number (SARS): 10 digits; format
    /// only (cue required).
    ZaVat,
    /// South African company registration number (Notice 1762 of 1999):
    /// `YYYY/NNNNNN/NN` with a SARS enterprise-type suffix; format only
    /// (cue required).
    ZaCompanyRegistration,
    /// Thai national identification number (DOPA): 13 digits, person type
    /// 1-8; the check-digit algorithm is not officially published (cue
    /// required).
    ThTnin,
    /// Cryptocurrency address (always on, no cue): a Bitcoin mainnet
    /// base58check address (BIP13 double-SHA-256 checksum, version 0 or 5),
    /// a Bitcoin mainnet segwit address (BIP173 Bech32 / BIP350 Bech32m),
    /// or an EIP-55 mixed-case checksummed Ethereum address.
    CryptoAddress,
    /// Mobile equipment identity (GSMA TS.06): a 15-digit IMEI with a
    /// reporting-body prefix and a Luhn check digit (claimed cue-less), or
    /// a 16-digit IMEISV next to an "imeisv" cue.
    Imei,
    /// IPv4 or IPv6 address (structural validation: 4 octets 0-255 / 8 hextets).
    IpAddress,
    /// HTTP/HTTPS/FTP URL (structural: scheme://domain.tld/path).
    Url,
    /// Date of birth (`tr` pack): a calendar-valid date next to a birth
    /// cue ("Doğum tarihi:"); format only.
    DateOfBirth,
    /// Place of birth (`tr` pack): a Turkish province or district next to
    /// a birth-place cue ("Doğum yeri:", "... doğumlu").
    PlaceOfBirth,
    /// Payment-card security code (CVV2/CVC2/CID, 3-4 digits) next to a
    /// card-code cue (`tr` pack); format only.
    CardCvv,
    /// Payment-card expiry date (`MM/YY`) next to an expiry cue (`tr`
    /// pack); format only.
    CardExpiry,
    /// Customer number (6-12 digits) next to a customer-number cue (`tr`
    /// pack); format only.
    CustomerNumber,
    /// Insurance policy number next to a policy-number cue (`tr` pack);
    /// format only.
    PolicyNumber,
    /// Turkish social security (SGK) registration number next to an SGK
    /// cue; format only.
    Sgk,
    /// Turkish MERSİS (central trade registry) number: 16 digits next to a
    /// MERSİS cue; format only.
    Mersis,
    /// KVKK art. 6 special category (`tr` pack): health data, including
    /// disability, blood group, medication and treatment, claimed only as a
    /// record-field value ("Tanı: ...", "Kan grubu: ...") or a term tied to
    /// a person in its sentence ("diyabetim", "hastanın ... hipertansiyon").
    SpecialHealth,
    /// KVKK art. 6 special category (`tr` pack): genetic data, person-linked.
    SpecialGenetic,
    /// KVKK art. 6 special category (`tr` pack): biometric data,
    /// person-linked.
    SpecialBiometric,
    /// KVKK art. 6 special category (`tr` pack): sexual life (sexual
    /// orientation, relations), person-linked.
    SpecialSexLife,
    /// KVKK art. 6 special category (`tr` pack): criminal convictions and
    /// security measures, person-linked.
    SpecialCriminal,
    /// KVKK art. 6 special category (`tr` pack): philosophical belief,
    /// religion, sect or other beliefs, person-linked.
    SpecialBelief,
    /// KVKK art. 6 special category (`tr` pack): race and ethnic origin
    /// (not nationality), person-linked.
    SpecialEthnicity,
    /// KVKK art. 6 special category (`tr` pack): political opinion and
    /// party membership, person-linked.
    SpecialPolitical,
    /// KVKK art. 6 special category (`tr` pack): appearance and dress
    /// ("kılık ve kıyafet"), person-linked.
    SpecialAttire,
    /// KVKK art. 6 special category (`tr` pack): association, foundation or
    /// trade-union membership, person-linked.
    SpecialMembership,
    /// Address / location: model-detected (NER `LOC` tag) or the
    /// rule-based Turkish postal address (`tr` pack: neighbourhood/street
    /// units + door number + gazetteer). No checksum -> lowest priority tier.
    Address,
    /// Person name in a **labeled context** (2-4 capitalized words next to a
    /// label cue such as "Ad Soyad:" / "name:"). No checksum exists, so a bare
    /// capitalized sequence is never claimed.
    Name,
    /// A caller-defined type with its own label, created with
    /// [`EntityType::custom`] and used by custom rules
    /// ([`crate::CustomRule`]). Overlap tier 7: every built-in identifier
    /// with a checksum or a structural rule outranks it on the same span.
    Custom(CustomLabel),
}

/// The label of an [`EntityType::Custom`] type (see [`EntityType::custom`]).
///
/// Registered labels live for the rest of the process (an entity type is
/// `Copy` and its label is `&'static str`), so their number is bounded by
/// [`MAX_CUSTOM_LABELS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CustomLabel(&'static str);

impl CustomLabel {
    /// The label text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// Longest custom label, in characters (the longest built-in label,
/// `UK_VEHICLE_REGISTRATION`, has 23).
pub const MAX_CUSTOM_LABEL_LEN: usize = 64;

/// Most distinct custom labels one process can register: every label is
/// kept for the life of the process, so the registry is bounded.
pub const MAX_CUSTOM_LABELS: usize = 1024;

/// Why [`EntityType::custom`] refused a label.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CustomLabelError {
    /// Not 1 to [`MAX_CUSTOM_LABEL_LEN`] uppercase ASCII letters, digits
    /// or `_`, starting with a letter (the shape of every built-in label).
    #[error(
        "a custom label must be 1 to {MAX_CUSTOM_LABEL_LEN} uppercase ASCII letters, digits or `_`, starting with a letter"
    )]
    InvalidLabel,
    /// The label is a built-in label (`TCKN`, `EMAIL`, ...).
    #[error("the label is a built-in entity type label")]
    BuiltIn,
    /// [`MAX_CUSTOM_LABELS`] distinct labels are already registered.
    #[error("{MAX_CUSTOM_LABELS} custom labels are already registered")]
    TooManyLabels,
}

/// The registered custom labels, sorted (binary search).
static CUSTOM_LABELS: std::sync::Mutex<Vec<&'static str>> = std::sync::Mutex::new(Vec::new());

/// Registers `label` (once) in `registry` holding at most `cap` labels.
fn register_label(
    registry: &std::sync::Mutex<Vec<&'static str>>,
    label: &str,
    cap: usize,
) -> Result<&'static str, CustomLabelError> {
    let shape = label.len() <= MAX_CUSTOM_LABEL_LEN
        && label.starts_with(|c: char| c.is_ascii_uppercase())
        && label
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if !shape {
        return Err(CustomLabelError::InvalidLabel);
    }
    if EntityType::builtin_from_str(label).is_some() {
        return Err(CustomLabelError::BuiltIn);
    }
    // a poisoned lock only means another thread panicked elsewhere; the
    // vector is updated by one insert, so it is always sorted and whole
    let mut labels = registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match labels.binary_search(&label) {
        Ok(i) => Ok(labels[i]),
        Err(_) if labels.len() >= cap => Err(CustomLabelError::TooManyLabels),
        Err(i) => {
            let kept: &'static str = Box::leak(label.to_owned().into_boxed_str());
            labels.insert(i, kept);
            Ok(kept)
        }
    }
}

/// The registered label equal to `label`, without registering it.
fn registered_label(label: &str) -> Option<&'static str> {
    let labels = CUSTOM_LABELS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    labels.binary_search(&label).ok().map(|i| labels[i])
}

impl EntityType {
    /// A custom type with its own `label` (registered once per process;
    /// the same label always gives the same type). The label has the shape
    /// of the built-in labels: 1 to [`MAX_CUSTOM_LABEL_LEN`] uppercase ASCII
    /// letters, digits or `_`, starting with a letter.
    ///
    /// # Errors
    /// [`CustomLabelError::InvalidLabel`] for another shape,
    /// [`CustomLabelError::BuiltIn`] for a built-in label and
    /// [`CustomLabelError::TooManyLabels`] once [`MAX_CUSTOM_LABELS`]
    /// labels exist.
    ///
    /// # Examples
    /// ```
    /// use redactify::{CustomRule, Detector, EntityType};
    ///
    /// let employee = EntityType::custom("EMPLOYEE_ID").unwrap();
    /// let rule = CustomRule::new(employee, r"\bE\d{6}\b").unwrap();
    /// let rules = [&rule];
    /// let d = Detector::new().with_custom_rules(&rules);
    /// assert_eq!(d.redact("personel E123456"), "personel [EMPLOYEE_ID]");
    /// assert!(EntityType::custom("TCKN").is_err()); // built-in label
    /// ```
    pub fn custom(label: &str) -> Result<Self, CustomLabelError> {
        register_label(&CUSTOM_LABELS, label, MAX_CUSTOM_LABELS)
            .map(|kept| Self::Custom(CustomLabel(kept)))
    }

    /// Priority in overlap resolution: the lower value wins.
    ///
    /// IBAN(0) = NIR(0) < CREDIT_CARD(1) < PLAKA(2) < TCKN(3) = UK_NHS(3)
    /// = PT_NIF(3) < EMAIL(4) < PHONE(5) = SWIFT_BIC(5) < PASSPORT(6) < VKN(7) =
    /// DNI/BSN/NINO/DE_TAX_ID/NIE/DE_ID_CARD/IT_FISCAL_CODE + the
    /// national IDs PESEL/CA_SIN/AU_TFN/SG_NRIC_FIN/IN_PAN/IN_AADHAAR
    /// (all 7) < NAME(8).
    /// NIR shares IBAN's top tier: a 15-digit Luhn-passing NIR must be masked
    /// as NIR (specificity wins; their shapes never overlap), DNI/BSN/NINO
    /// share VKN's tier (distinct shapes, no cross-country span overlap);
    /// the other national identifiers join the same tier (distinct shapes), while
    /// SWIFT_BIC joins the PHONE/IP/URL contact tier (shapes never overlap
    /// with an IBAN). UK_NHS is the one exception: its 3-3-4 digit shape is
    /// exactly the NANP phone shape, so an NHS-checksummed run near an "nhs"
    /// cue must outrank the cue-less structural Phone rule (checksum beats
    /// structural - NIR precedent); it shares TCKN's tier instead, as does
    /// PT_NIF for the analogous pt phone-rule collision.
    ///
    /// CN_RESIDENT_ID and BR_CNPJ join the top tier
    /// (NIR precedent: about 10% of valid 18-character resident IDs and of
    /// bare 14-character CNPJs also pass Luhn, so the cue-less card rule
    /// must not relabel them); BR_CPF, SE_PERSONNUMMER and FI_HETU share
    /// TCKN's tier (checksummed national IDs claimed in their formatted
    /// shape without a cue - checksum beats structural), and so does the
    /// cue-gated DK_CPR: its `DDMMYY-SSSS` shape is also a Swedish
    /// `YYMMDD-NNNC` shape (the CPR office's own example `070761-4285`
    /// passes the Swedish samordningsnummer date and Luhn check), so with
    /// both packs enabled a "cpr"-cued number must keep its Danish label
    /// (equal tier, equal span: the dk pack is registered before se). The
    /// cue-gated NO_FODSELSNUMMER and EU_VAT join the national-ID tier 7.
    ///
    /// The 13-digit national IDs (KR_RRN, KR_FRN,
    /// TH_TNIN, ZA_ID_NUMBER) and DE_TAX_NUMBER join the top tier for the
    /// same reason as CN_RESIDENT_ID (a share of valid values passes Luhn,
    /// and the cue-less card rule must not relabel them); the checksummed
    /// ZA_TAX_REFERENCE shares TCKN's tier (it outranks the format-only
    /// UK_UTR on the shared "tax reference" cue); passports (KR_PASSPORT,
    /// IT_PASSPORT) join the passport tier; every other identifier is
    /// cue-gated in tier 7. Each arm below carries its own justification.
    ///
    /// FR_SIRET is in the top tier (its
    /// check digit is a Luhn check over the whole 14-digit value, so the
    /// cue-less card rule would claim every valid SIRET before the cue-gated
    /// SIRET rule could win).
    #[must_use]
    pub const fn priority(self) -> u8 {
        match self {
            Self::Iban | Self::Nir => 0,
            Self::Vin | Self::CnResidentId | Self::BrCnpj => 0,
            Self::CreditCard => 1,
            Self::Plaka => 2,
            Self::Tckn
            | Self::UkNhs
            | Self::PtNif
            | Self::BrCpf
            | Self::SePersonnummer
            | Self::FiHetu
            | Self::DkCpr => 3,
            Self::Email => 4,
            Self::Phone | Self::IpAddress | Self::Url | Self::SwiftBic => 5,
            Self::Passport
            | Self::Ssn
            | Self::Itin
            | Self::UsPassport
            | Self::UkPassport
            | Self::DePassport => 6,
            Self::Vkn
            | Self::Dni
            | Self::Bsn
            | Self::Nino
            | Self::DeTaxId
            | Self::Nie
            | Self::DeIdCard
            | Self::ItFiscalCode
            | Self::Pesel
            | Self::CaSin
            | Self::AuTfn
            | Self::SgNricFin
            | Self::InPan
            | Self::InAadhaar
            | Self::AuMedicare
            | Self::AuAbn
            | Self::UkVat
            | Self::PlNip
            | Self::UkUtr
            | Self::UsMrn
            | Self::UkPostcode
            | Self::DePlz
            | Self::UsZip
            | Self::FrPostal
            | Self::NoFodselsnummer
            | Self::EuVat => 7,
            // Cue-gated national-ID tier 7. No cue-less rule claims these
            // shapes, so nothing structural has to be outranked: the card
            // rule needs 13-19 digits (ABA 9, NPI 10, ACN 9 never reach
            // it), the phone rules need separators or a trunk/+CC prefix
            // (none matches a bare 9/10-digit run, the 4-4-1 ABA grouping,
            // the 3-3-3 ACN grouping or `XX-XXXXXXX`), and the letter
            // shapes (MBI, postal code, driver number, registration) match
            // no cue-less rule. Same-span ties with other tier-7 rules
            // (au::tfn vs ACN, nine-digit ids of other packs) need both cue
            // sets and fall to registration order; the bare SSN (tier 6)
            // outranks a same-span routing number only when an SSN cue is
            // present too.
            Self::UsAbaRouting
            | Self::UsMbi
            | Self::UsNpi
            | Self::UsEin
            | Self::CaPostalCode
            | Self::UkDrivingLicence
            | Self::UkVehicleRegistration
            | Self::AuAcn => 7,
            // DE_TAX_NUMBER: top tier (NIR / BR_CNPJ precedent). Its 13-digit
            // ELSTER form is also a 13-digit card shape and about 10% of
            // valid values pass Luhn, so the cue-less card rule (tier 1)
            // must not relabel a cued, checksum-valid tax number.
            Self::DeTaxNumber => 0,
            // FR_SIRET: top tier (NIR / DE_TAX_NUMBER precedent). The SIRET
            // check digit is the Luhn check over all 14 digits, so every
            // valid SIRET is also a Luhn-valid 14-digit card shape, which
            // the cue-less card rule (tier 1) would claim every time
            // (tier 7 could never win). The rule is cue-gated, so only a
            // cued value is relabelled; an uncued run stays CREDIT_CARD.
            Self::FrSiret => 0,
            // IT_PASSPORT: the passport tier, like DE/UK/US passports
            // (format + mandatory cue, no checksum).
            Self::ItPassport => 6,
            // Cue-gated national identifiers (checksummed: KVNR, RVNR,
            // LANR; structural: BSNR, KFZ, organisationsnummer, UEN): the
            // national-ID tier. Their shapes do not overlap a cue-less
            // structural rule of any pack (measured in tests/locale_ids_de_it_se_sg.rs
            // with every locale enabled), so no higher tier is needed.
            Self::DeKvnr
            | Self::DeRvnr
            | Self::DeLanr
            | Self::DeBsnr
            | Self::DeKfz
            | Self::SeOrganisationsnummer
            | Self::SgUen => 7,
            // tier 0: 13-digit national IDs. About 10% of 13-digit values
            // pass Luhn, so the cue-less card rule (tier 1) would relabel
            // them (CN_RESIDENT_ID precedent). ZA_ID_NUMBER is cue-less
            // and Luhn-checked; the cue-gated KR/TH rules share its shape,
            // so the kr and th packs are registered before za (equal tier,
            // equal span: insertion order).
            Self::ZaIdNumber | Self::KrRrn | Self::KrFrn | Self::ThTnin => 0,
            // tier 0: a checksummed address is one token (base58, Bech32,
            // `0x` + hex) that can hold a 13-19 digit run passing Luhn (an
            // Ethereum address can), so the
            // cue-less card rule (tier 1) must not claim a fragment of it
            // (CN_RESIDENT_ID precedent)
            Self::CryptoAddress => 0,
            // tier 0: every valid IMEI is a Luhn-valid 15-digit run (and an
            // IMEISV a 16-digit one), so it must outrank the cue-less card
            // rule (tier 1) on the same span (CN_RESIDENT_ID precedent)
            Self::Imei => 0,
            // tier 3: checksummed and cue-gated, but its bare 10-digit
            // shape and its "tax reference" cue are shared with the
            // format-only UK_UTR rule (tier 7): checksum beats structural
            // (UK_NHS / DK_CPR precedent)
            Self::ZaTaxReference => 3,
            // tier 6: passport tier (equal-span ties with US_PASSPORT go
            // to the en pack, registered first)
            Self::KrPassport => 6,
            // tier 7: cue-gated national IDs whose shapes overlap no
            // higher-tier claim
            Self::InGstin
            | Self::KrBrn
            | Self::NgNin
            | Self::PhTin
            | Self::ZaVat
            | Self::ZaCompanyRegistration => 7,
            // tr record fields, cue-gated and format only. SGK (8-13 or 26
            // digits) and MERSİS (16 digits) share shapes with the cue-less
            // Luhn card rule (tier 1), and about 10% of such runs pass Luhn:
            // top tier, as CN_RESIDENT_ID (only a cued value is relabelled).
            // A top-tier span wins every overlap, so both rules claim only a
            // whole digit-only token of their lengths (8-13/26, 16): never
            // the digits of an e-mail, URL or alphanumeric token, and an SGK
            // token strictly inside a phone candidate is dropped before the
            // overlap walk (`detect::sgk_yields_to_phone`, see
            // `tr::sgk`).
            Self::Sgk | Self::Mersis => 0,
            // The other fields overlap no cue-less structural rule (dates,
            // `MM/YY`, 3-4 and 6-12 digit runs, a gazetteer word), so they
            // share the cue-gated tier 7; a valid TCKN in a customer-number
            // context keeps the TCKN label (tier 3).
            Self::DateOfBirth
            | Self::PlaceOfBirth
            | Self::CardCvv
            | Self::CardExpiry
            | Self::CustomerNumber
            | Self::PolicyNumber => 7,
            Self::Name | Self::Address => 8,
            // KVKK art. 6 special categories: word evidence without a
            // checksum, like NAME, so the coexisting tier 8. Every
            // identifier inside a field value (a TCKN, a phone) outranks
            // them; a name or address overlapping one coexists and the
            // union is masked (`resolve_overlaps`).
            Self::SpecialHealth
            | Self::SpecialGenetic
            | Self::SpecialBiometric
            | Self::SpecialSexLife
            | Self::SpecialCriminal
            | Self::SpecialBelief
            | Self::SpecialEthnicity
            | Self::SpecialPolitical
            | Self::SpecialAttire
            | Self::SpecialMembership => 8,
            // caller-defined patterns: below every built-in identifier tier
            // (tier 8 is the coexisting name/address tier, see
            // `resolve_overlaps`)
            Self::Custom(_) => 7,
        }
    }

    /// Canonical short label (`"TCKN"`, `"IBAN"`, ...).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tckn => "TCKN",
            Self::Iban => "IBAN",
            Self::CreditCard => "CREDIT_CARD",
            Self::Plaka => "PLAKA",
            Self::Vkn => "VKN",
            Self::Phone => "PHONE",
            Self::Email => "EMAIL",
            Self::Passport => "PASSPORT",
            Self::Ssn => "SSN",
            Self::Itin => "ITIN",
            Self::UsPassport => "US_PASSPORT",
            Self::Nir => "NIR",
            Self::Dni => "DNI",
            Self::Bsn => "BSN",
            Self::Nino => "NINO",
            Self::DeTaxId => "DE_TAX_ID",
            Self::UkNhs => "UK_NHS",
            Self::Nie => "NIE",
            Self::DeIdCard => "DE_ID_CARD",
            Self::ItFiscalCode => "IT_FISCAL_CODE",
            Self::Pesel => "PL_PESEL",
            Self::CaSin => "CA_SIN",
            Self::AuTfn => "AU_TFN",
            Self::SgNricFin => "SG_NRIC_FIN",
            Self::InPan => "IN_PAN",
            Self::InAadhaar => "IN_AADHAAR",
            Self::PtNif => "PT_NIF",
            Self::Vin => "VIN",
            Self::AuAbn => "AU_ABN",
            Self::UkVat => "UK_VAT",
            Self::FrSiret => "FR_SIRET",
            Self::PlNip => "PL_NIP",
            Self::UkUtr => "UK_UTR",
            Self::UkPassport => "UK_PASSPORT",
            Self::DePassport => "DE_PASSPORT",
            Self::UsMrn => "US_MRN",
            Self::UsZip => "US_ZIP",
            Self::FrPostal => "FR_POSTAL",
            Self::AuMedicare => "AU_MEDICARE",
            Self::UkPostcode => "UK_POSTCODE",
            Self::DePlz => "DE_PLZ",
            Self::BrCpf => "BR_CPF",
            Self::BrCnpj => "BR_CNPJ",
            Self::CnResidentId => "CN_RESIDENT_ID",
            Self::SePersonnummer => "SE_PERSONNUMMER",
            Self::FiHetu => "FI_HETU",
            Self::NoFodselsnummer => "NO_FODSELSNUMMER",
            Self::DkCpr => "DK_CPR",
            Self::EuVat => "EU_VAT",
            Self::UsAbaRouting => "US_ABA_ROUTING",
            Self::UsMbi => "US_MBI",
            Self::UsNpi => "US_NPI",
            Self::UsEin => "US_EIN",
            Self::CaPostalCode => "CA_POSTAL_CODE",
            Self::UkDrivingLicence => "UK_DRIVING_LICENCE",
            Self::UkVehicleRegistration => "UK_VEHICLE_REGISTRATION",
            Self::AuAcn => "AU_ACN",
            Self::DeTaxNumber => "DE_TAX_NUMBER",
            Self::DeKvnr => "DE_KVNR",
            Self::DeRvnr => "DE_RVNR",
            Self::DeLanr => "DE_LANR",
            Self::DeBsnr => "DE_BSNR",
            Self::DeKfz => "DE_KFZ",
            Self::ItPassport => "IT_PASSPORT",
            Self::SeOrganisationsnummer => "SE_ORGANISATIONSNUMMER",
            Self::SgUen => "SG_UEN",
            Self::InGstin => "IN_GSTIN",
            Self::KrBrn => "KR_BRN",
            Self::KrFrn => "KR_FRN",
            Self::KrPassport => "KR_PASSPORT",
            Self::KrRrn => "KR_RRN",
            Self::NgNin => "NG_NIN",
            Self::PhTin => "PH_TIN",
            Self::ZaIdNumber => "ZA_ID_NUMBER",
            Self::ZaTaxReference => "ZA_TAX_REFERENCE",
            Self::ZaVat => "ZA_VAT",
            Self::ZaCompanyRegistration => "ZA_COMPANY_REGISTRATION",
            Self::ThTnin => "TH_TNIN",
            Self::CryptoAddress => "CRYPTO_ADDRESS",
            Self::Imei => "IMEI",
            Self::SwiftBic => "SWIFT_BIC",
            Self::IpAddress => "IP_ADDRESS",
            Self::Url => "URL",
            Self::DateOfBirth => "DATE_OF_BIRTH",
            Self::PlaceOfBirth => "PLACE_OF_BIRTH",
            Self::CardCvv => "CARD_CVV",
            Self::CardExpiry => "CARD_EXPIRY",
            Self::CustomerNumber => "CUSTOMER_NUMBER",
            Self::PolicyNumber => "POLICY_NUMBER",
            Self::Sgk => "SGK",
            Self::Mersis => "MERSIS",
            Self::SpecialHealth => "SPECIAL_HEALTH",
            Self::SpecialGenetic => "SPECIAL_GENETIC",
            Self::SpecialBiometric => "SPECIAL_BIOMETRIC",
            Self::SpecialSexLife => "SPECIAL_SEX_LIFE",
            Self::SpecialCriminal => "SPECIAL_CRIMINAL",
            Self::SpecialBelief => "SPECIAL_BELIEF",
            Self::SpecialEthnicity => "SPECIAL_ETHNICITY",
            Self::SpecialPolitical => "SPECIAL_POLITICAL",
            Self::SpecialAttire => "SPECIAL_ATTIRE",
            Self::SpecialMembership => "SPECIAL_MEMBERSHIP",
            Self::Address => "ADDRESS",
            Self::Name => "NAME",
            Self::Custom(label) => label.0,
        }
    }
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parse error of [`EntityType`]'s [`FromStr`](std::str::FromStr)
/// implementation: the input was not a canonical entity-type label.
///
/// The rejected input is kept for the `Display` message only; the type is
/// `#[non_exhaustive]` so fields can be added without a breaking change.
///
/// # Examples
/// ```
/// use redactify::{EntityType, EntityTypeParseError};
/// use std::str::FromStr;
/// let err: EntityTypeParseError = EntityType::from_str("tckn").unwrap_err();
/// assert!(err.to_string().contains("`tckn`"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown entity type `{0}` (canonical labels: TCKN, IBAN, PHONE, ...)")]
#[non_exhaustive]
pub struct EntityTypeParseError(String);

impl std::str::FromStr for EntityType {
    type Err = EntityTypeParseError;

    /// Parses a canonical label (the exact [`EntityType::as_str`] spelling,
    /// case-sensitive) back into the variant. Used by the TOML policy
    /// config layer (relevance rules name entity types by label).
    ///
    /// # Examples
    /// ```
    /// use redactify::EntityType;
    /// use std::str::FromStr;
    /// assert_eq!(EntityType::from_str("PHONE").unwrap(), EntityType::Phone);
    /// assert_eq!(EntityType::from_str("UK_NHS").unwrap(), EntityType::UkNhs);
    /// assert!(EntityType::from_str("phone").is_err()); // case-sensitive
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::builtin_from_str(s)
            .or_else(|| registered_label(s).map(|kept| Self::Custom(CustomLabel(kept))))
            .ok_or_else(|| EntityTypeParseError(s.to_owned()))
    }
}

impl EntityType {
    /// The built-in type whose label is exactly `s`.
    fn builtin_from_str(s: &str) -> Option<Self> {
        Some(match s {
            "TCKN" => Self::Tckn,
            "IBAN" => Self::Iban,
            "CREDIT_CARD" => Self::CreditCard,
            "PLAKA" => Self::Plaka,
            "VKN" => Self::Vkn,
            "PHONE" => Self::Phone,
            "EMAIL" => Self::Email,
            "PASSPORT" => Self::Passport,
            "SSN" => Self::Ssn,
            "ITIN" => Self::Itin,
            "US_PASSPORT" => Self::UsPassport,
            "NIR" => Self::Nir,
            "DNI" => Self::Dni,
            "BSN" => Self::Bsn,
            "NINO" => Self::Nino,
            "DE_TAX_ID" => Self::DeTaxId,
            "UK_NHS" => Self::UkNhs,
            "NIE" => Self::Nie,
            "DE_ID_CARD" => Self::DeIdCard,
            "IT_FISCAL_CODE" => Self::ItFiscalCode,
            "PL_PESEL" => Self::Pesel,
            "CA_SIN" => Self::CaSin,
            "AU_TFN" => Self::AuTfn,
            "SG_NRIC_FIN" => Self::SgNricFin,
            "IN_PAN" => Self::InPan,
            "IN_AADHAAR" => Self::InAadhaar,
            "PT_NIF" => Self::PtNif,
            "VIN" => Self::Vin,
            "AU_ABN" => Self::AuAbn,
            "UK_VAT" => Self::UkVat,
            "FR_SIRET" => Self::FrSiret,
            "PL_NIP" => Self::PlNip,
            "UK_UTR" => Self::UkUtr,
            "UK_PASSPORT" => Self::UkPassport,
            "DE_PASSPORT" => Self::DePassport,
            "US_MRN" => Self::UsMrn,
            "US_ZIP" => Self::UsZip,
            "FR_POSTAL" => Self::FrPostal,
            "AU_MEDICARE" => Self::AuMedicare,
            "UK_POSTCODE" => Self::UkPostcode,
            "DE_PLZ" => Self::DePlz,
            "BR_CPF" => Self::BrCpf,
            "BR_CNPJ" => Self::BrCnpj,
            "CN_RESIDENT_ID" => Self::CnResidentId,
            "SE_PERSONNUMMER" => Self::SePersonnummer,
            "FI_HETU" => Self::FiHetu,
            "NO_FODSELSNUMMER" => Self::NoFodselsnummer,
            "DK_CPR" => Self::DkCpr,
            "EU_VAT" => Self::EuVat,
            "US_ABA_ROUTING" => Self::UsAbaRouting,
            "US_MBI" => Self::UsMbi,
            "US_NPI" => Self::UsNpi,
            "US_EIN" => Self::UsEin,
            "CA_POSTAL_CODE" => Self::CaPostalCode,
            "UK_DRIVING_LICENCE" => Self::UkDrivingLicence,
            "UK_VEHICLE_REGISTRATION" => Self::UkVehicleRegistration,
            "AU_ACN" => Self::AuAcn,
            "DE_TAX_NUMBER" => Self::DeTaxNumber,
            "DE_KVNR" => Self::DeKvnr,
            "DE_RVNR" => Self::DeRvnr,
            "DE_LANR" => Self::DeLanr,
            "DE_BSNR" => Self::DeBsnr,
            "DE_KFZ" => Self::DeKfz,
            "IT_PASSPORT" => Self::ItPassport,
            "SE_ORGANISATIONSNUMMER" => Self::SeOrganisationsnummer,
            "SG_UEN" => Self::SgUen,
            "IN_GSTIN" => Self::InGstin,
            "KR_BRN" => Self::KrBrn,
            "KR_FRN" => Self::KrFrn,
            "KR_PASSPORT" => Self::KrPassport,
            "KR_RRN" => Self::KrRrn,
            "NG_NIN" => Self::NgNin,
            "PH_TIN" => Self::PhTin,
            "ZA_ID_NUMBER" => Self::ZaIdNumber,
            "ZA_TAX_REFERENCE" => Self::ZaTaxReference,
            "ZA_VAT" => Self::ZaVat,
            "ZA_COMPANY_REGISTRATION" => Self::ZaCompanyRegistration,
            "TH_TNIN" => Self::ThTnin,
            "CRYPTO_ADDRESS" => Self::CryptoAddress,
            "IMEI" => Self::Imei,
            "SWIFT_BIC" => Self::SwiftBic,
            "IP_ADDRESS" => Self::IpAddress,
            "URL" => Self::Url,
            "DATE_OF_BIRTH" => Self::DateOfBirth,
            "PLACE_OF_BIRTH" => Self::PlaceOfBirth,
            "CARD_CVV" => Self::CardCvv,
            "CARD_EXPIRY" => Self::CardExpiry,
            "CUSTOMER_NUMBER" => Self::CustomerNumber,
            "POLICY_NUMBER" => Self::PolicyNumber,
            "SGK" => Self::Sgk,
            "MERSIS" => Self::Mersis,
            "SPECIAL_HEALTH" => Self::SpecialHealth,
            "SPECIAL_GENETIC" => Self::SpecialGenetic,
            "SPECIAL_BIOMETRIC" => Self::SpecialBiometric,
            "SPECIAL_SEX_LIFE" => Self::SpecialSexLife,
            "SPECIAL_CRIMINAL" => Self::SpecialCriminal,
            "SPECIAL_BELIEF" => Self::SpecialBelief,
            "SPECIAL_ETHNICITY" => Self::SpecialEthnicity,
            "SPECIAL_POLITICAL" => Self::SpecialPolitical,
            "SPECIAL_ATTIRE" => Self::SpecialAttire,
            "SPECIAL_MEMBERSHIP" => Self::SpecialMembership,
            "ADDRESS" => Self::Address,
            "NAME" => Self::Name,
            _ => return None,
        })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for EntityType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for EntityType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let label = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        label.parse().map_err(serde::de::Error::custom)
    }
}

/// A validated, non-overlapping PII span.
///
/// Note: `Eq` is not derived because of `score: f32` (f32 has no total equality).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Entity {
    /// Entity type.
    pub kind: EntityType,
    /// Span start (byte offset, inclusive).
    pub start: usize,
    /// Span end (byte offset, exclusive).
    pub end: usize,
    /// The raw matched text.
    pub text: String,
    /// Confidence score (0.0-1.0):
    /// - **1.0** - checksum verified (TCKN/IBAN/card/VKN; mathematical certainty),
    /// - **0.95** - plate + a nearby context cue ("plaka", "araç plakasi", ...),
    /// - **0.9** - passport (format + mandatory context cue; no checksum),
    /// - **0.85** - plate (format+province), e-mail (strict regex), or a
    ///   labeled-context person name (capitalized sequence + label cue),
    /// - **0.80** - phone (structural pattern; no model-based validation).
    ///
    /// Detections below a score cutoff can be dropped with
    /// [`crate::Detector::with_threshold`].
    pub score: f32,
}

impl Entity {
    /// Byte length of the span.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the span is empty (spans are never empty in this API; kept for completeness).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.end == self.start
    }
}

#[cfg(test)]
mod tests {
    use super::EntityType;

    #[test]
    fn the_label_registry_is_bounded() {
        use super::{register_label, CustomLabelError};
        let registry = std::sync::Mutex::new(Vec::new());
        assert!(register_label(&registry, "CAP_A", 2).is_ok());
        assert!(register_label(&registry, "CAP_B", 2).is_ok());
        // a registered label still resolves when the registry is full
        assert!(register_label(&registry, "CAP_A", 2).is_ok());
        assert_eq!(
            register_label(&registry, "CAP_C", 2),
            Err(CustomLabelError::TooManyLabels)
        );
        // the same text always gives the same &'static str
        let a = register_label(&registry, "CAP_B", 2).expect("registered");
        let b = register_label(&registry, "CAP_B", 2).expect("registered");
        assert!(std::ptr::eq(a, b));
    }

    #[test]
    fn priorities_match_overlap_resolution_order() {
        // lower number = wins the overlap; README: IBAN > CREDIT_CARD >
        // PLAKA > TCKN > EMAIL > PHONE > PASSPORT > VKN > NAME
        assert!(EntityType::Iban.priority() < EntityType::CreditCard.priority());
        assert!(EntityType::CreditCard.priority() < EntityType::Plaka.priority());
        assert!(EntityType::Plaka.priority() < EntityType::Tckn.priority());
        assert!(EntityType::Tckn.priority() < EntityType::Email.priority());
        assert!(EntityType::Email.priority() < EntityType::Phone.priority());
        assert!(EntityType::Phone.priority() < EntityType::Passport.priority());
        assert!(EntityType::Passport.priority() <= EntityType::Vkn.priority());
        // NAME loses to every checksum/structural identifier
        assert!(EntityType::Vkn.priority() < EntityType::Name.priority());
        // EN identifiers share the passport tier (6); ITIN-vs-SSN shape ties
        // are resolved by rule order (ITIN first), not by priority
        assert_eq!(EntityType::Ssn.priority(), 6);
        assert_eq!(EntityType::Itin.priority(), 6);
        assert_eq!(EntityType::UsPassport.priority(), 6);
        assert_eq!(EntityType::UkPassport.priority(), 6);
        assert_eq!(EntityType::DePassport.priority(), 6);
        // VIN shares tier 0 with IBAN (both checksummed, always-on)
        assert_eq!(EntityType::Vin.priority(), 0);
        assert_eq!(EntityType::Vin.priority(), EntityType::Iban.priority());
        // IMEI outranks the card rule (every IMEI is Luhn-valid)
        assert!(EntityType::Imei.priority() < EntityType::CreditCard.priority());
        // new tier-7 members (checksummed or cue-gated structural)
        // FR_SIRET: top tier, the card rule claims every valid SIRET shape
        assert_eq!(EntityType::FrSiret.priority(), 0);
        assert!(EntityType::FrSiret.priority() < EntityType::CreditCard.priority());
        for t in [
            EntityType::AuAbn,
            EntityType::UkVat,
            EntityType::PlNip,
            EntityType::UkUtr,
            EntityType::UsMrn,
            EntityType::UsZip,
            EntityType::FrPostal,
        ] {
            assert_eq!(t.priority(), 7, "{:?}", t.as_str());
        }
        // specificity tier 0 (beats the cue-less Luhn card claim),
        // TCKN tier 3 (cue-less checksummed national IDs), tier 7 (cue-gated)
        assert_eq!(EntityType::CnResidentId.priority(), 0);
        assert_eq!(EntityType::BrCnpj.priority(), 0);
        assert!(EntityType::CnResidentId.priority() < EntityType::CreditCard.priority());
        for t in [
            EntityType::BrCpf,
            EntityType::SePersonnummer,
            EntityType::FiHetu,
            EntityType::DkCpr,
        ] {
            assert_eq!(t.priority(), EntityType::Tckn.priority(), "{}", t.as_str());
        }
        for t in [EntityType::NoFodselsnummer, EntityType::EuVat] {
            assert_eq!(t.priority(), 7, "{}", t.as_str());
        }
    }

    #[test]
    fn labels_are_stable_and_unique() {
        let all = [
            EntityType::Tckn,
            EntityType::Iban,
            EntityType::Vkn,
            EntityType::Plaka,
            EntityType::Passport,
            EntityType::Phone,
            EntityType::Email,
            EntityType::CreditCard,
            EntityType::Ssn,
            EntityType::Itin,
            EntityType::UsPassport,
            EntityType::Nir,
            EntityType::Dni,
            EntityType::Bsn,
            EntityType::Nino,
            EntityType::DeTaxId,
            EntityType::UkNhs,
            EntityType::Nie,
            EntityType::DeIdCard,
            EntityType::ItFiscalCode,
            EntityType::SwiftBic,
            EntityType::Pesel,
            EntityType::CaSin,
            EntityType::AuTfn,
            EntityType::SgNricFin,
            EntityType::InPan,
            EntityType::InAadhaar,
            EntityType::PtNif,
            EntityType::AuMedicare,
            EntityType::Vin,
            EntityType::AuAbn,
            EntityType::UkVat,
            EntityType::FrSiret,
            EntityType::PlNip,
            EntityType::UkUtr,
            EntityType::UkPassport,
            EntityType::DePassport,
            EntityType::UsMrn,
            EntityType::UkPostcode,
            EntityType::DePlz,
            EntityType::UsZip,
            EntityType::FrPostal,
            EntityType::BrCpf,
            EntityType::BrCnpj,
            EntityType::CnResidentId,
            EntityType::SePersonnummer,
            EntityType::FiHetu,
            EntityType::NoFodselsnummer,
            EntityType::DkCpr,
            EntityType::EuVat,
            EntityType::IpAddress,
            EntityType::Url,
            EntityType::Address,
            EntityType::Name,
            EntityType::UsAbaRouting,
            EntityType::UsMbi,
            EntityType::UsNpi,
            EntityType::UsEin,
            EntityType::CaPostalCode,
            EntityType::UkDrivingLicence,
            EntityType::UkVehicleRegistration,
            EntityType::AuAcn,
            EntityType::DeTaxNumber,
            EntityType::DeKvnr,
            EntityType::DeRvnr,
            EntityType::DeLanr,
            EntityType::DeBsnr,
            EntityType::DeKfz,
            EntityType::ItPassport,
            EntityType::SeOrganisationsnummer,
            EntityType::SgUen,
            EntityType::InGstin,
            EntityType::KrBrn,
            EntityType::KrFrn,
            EntityType::KrPassport,
            EntityType::KrRrn,
            EntityType::NgNin,
            EntityType::PhTin,
            EntityType::ZaIdNumber,
            EntityType::ZaTaxReference,
            EntityType::ZaVat,
            EntityType::ZaCompanyRegistration,
            EntityType::ThTnin,
            EntityType::CryptoAddress,
            EntityType::DateOfBirth,
            EntityType::PlaceOfBirth,
            EntityType::CardCvv,
            EntityType::CardExpiry,
            EntityType::CustomerNumber,
            EntityType::PolicyNumber,
            EntityType::Sgk,
            EntityType::Mersis,
            EntityType::Imei,
            EntityType::SpecialHealth,
            EntityType::SpecialGenetic,
            EntityType::SpecialBiometric,
            EntityType::SpecialSexLife,
            EntityType::SpecialCriminal,
            EntityType::SpecialBelief,
            EntityType::SpecialEthnicity,
            EntityType::SpecialPolitical,
            EntityType::SpecialAttire,
            EntityType::SpecialMembership,
        ];
        let mut seen = std::collections::HashSet::new();
        for e in all {
            assert!(seen.insert(e.as_str()), "duplicate label {}", e.as_str());
            // FromStr is the exact inverse of as_str for every variant
            assert_eq!(e.as_str().parse::<EntityType>(), Ok(e), "{}", e.as_str());
        }
        assert_eq!(seen.len(), 103, "variant count changed: update this list");
        assert_eq!(EntityType::Tckn.as_str(), "TCKN");
        assert_eq!(EntityType::UsPassport.as_str(), "US_PASSPORT");
        assert_eq!(EntityType::Nir.as_str(), "NIR");
        assert_eq!(EntityType::UkNhs.as_str(), "UK_NHS");
        assert_eq!(EntityType::ItFiscalCode.as_str(), "IT_FISCAL_CODE");
        assert_eq!(EntityType::SwiftBic.as_str(), "SWIFT_BIC");
        assert_eq!(EntityType::Address.as_str(), "ADDRESS");
        assert_eq!(EntityType::Name.as_str(), "NAME");
        assert_eq!(EntityType::BrCpf.as_str(), "BR_CPF");
        assert_eq!(EntityType::BrCnpj.as_str(), "BR_CNPJ");
        assert_eq!(EntityType::CnResidentId.as_str(), "CN_RESIDENT_ID");
        assert_eq!(EntityType::SePersonnummer.as_str(), "SE_PERSONNUMMER");
        assert_eq!(EntityType::FiHetu.as_str(), "FI_HETU");
        assert_eq!(EntityType::NoFodselsnummer.as_str(), "NO_FODSELSNUMMER");
        assert_eq!(EntityType::DkCpr.as_str(), "DK_CPR");
        assert_eq!(EntityType::EuVat.as_str(), "EU_VAT");
    }
}
