//! The public validators that share the Luhn, code-character collection
//! and two-digit leap-year helpers, compared against independent reference
//! implementations (the `reference` module below) over edge-case tables
//! and deterministic pseudo-random inputs: every verdict must agree.

/// Self-contained reference implementations of the validators, written
/// without the shared helpers (only the names differ from the public API).
mod reference {
    fn two_digits(b: &[u8]) -> u32 {
        u32::from(b[0] - b'0') * 10 + u32::from(b[1] - b'0')
    }

    const fn is_leap_year(year: u32) -> bool {
        (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
    }

    const fn days_in_month(month: u32, leap: bool) -> u32 {
        match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => 0,
        }
    }

    pub(super) fn valid_luhn(number: &str) -> bool {
        let digits: Vec<u32> = number
            .bytes()
            .filter(u8::is_ascii_digit)
            .map(|b| u32::from(b - b'0'))
            .collect();
        if digits.len() < 13 {
            return false;
        }
        let parity = digits.len() % 2;
        let checksum: u32 = digits
            .iter()
            .enumerate()
            .map(|(i, &d)| {
                let mut x = d;
                if i % 2 == parity {
                    x *= 2;
                    if x > 9 {
                        x -= 9;
                    }
                }
                x
            })
            .sum();
        checksum % 10 == 0
    }

    pub(super) fn valid_credit_card(candidate: &str) -> bool {
        let digits: String = candidate.chars().filter(|c| c.is_ascii_digit()).collect();
        (13..=19).contains(&digits.len()) && valid_luhn(candidate)
    }

    pub(super) fn valid_ca_sin(sin: &str) -> bool {
        let s: String = sin
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        let b = s.as_bytes();
        if b.len() != 9 || !b.iter().all(u8::is_ascii_digit) {
            return false;
        }
        if b[0] == b'0' || b[0] == b'8' {
            return false;
        }
        let digits: Vec<u32> = b.iter().map(|&c| u32::from(c - b'0')).collect();
        let parity = digits.len() % 2;
        let total: u32 = digits
            .iter()
            .enumerate()
            .map(|(i, &d)| {
                let mut x = d;
                if i % 2 == parity {
                    x *= 2;
                    if x > 9 {
                        x -= 9;
                    }
                }
                x
            })
            .sum();
        total % 10 == 0
    }

    pub(super) fn valid_fr_siret(siret: &str) -> bool {
        let digits: String = siret.chars().filter(|c| c.is_ascii_digit()).collect();
        let b = digits.as_bytes();
        if b.len() != 14 {
            return false;
        }
        let sum: u32 = b
            .iter()
            .rev()
            .enumerate()
            .map(|(i, &c)| {
                let mut d = u32::from(c - b'0');
                if i % 2 == 1 {
                    d *= 2;
                    if d > 9 {
                        d -= 9;
                    }
                }
                d
            })
            .sum();
        sum % 10 == 0
    }

    pub(super) fn valid_se_personnummer(pnr: &str) -> bool {
        let b = pnr.as_bytes();
        let mut d = [0u8; 10];
        let century = match b.len() {
            10 => {
                d.copy_from_slice(b);
                None
            }
            11 if matches!(b[6], b'-' | b'+') => {
                d[..6].copy_from_slice(&b[..6]);
                d[6..].copy_from_slice(&b[7..]);
                None
            }
            12 => {
                d.copy_from_slice(&b[2..]);
                if !b[..2].iter().all(u8::is_ascii_digit) {
                    return false;
                }
                let c = two_digits(&b[..2]);
                if !(18..=20).contains(&c) {
                    return false;
                }
                Some(c)
            }
            _ => return false,
        };
        if !d.iter().all(u8::is_ascii_digit) {
            return false;
        }
        let yy = two_digits(&d[0..2]);
        let month = two_digits(&d[2..4]);
        let raw_day = two_digits(&d[4..6]);
        let day = if raw_day > 60 { raw_day - 60 } else { raw_day };
        let leap = match century {
            Some(c) => is_leap_year(c * 100 + yy),
            None => yy % 4 == 0,
        };
        if day == 0 || day > days_in_month(month, leap) || &d[6..9] == b"000" {
            return false;
        }
        let sum: u32 = d[..9]
            .iter()
            .enumerate()
            .map(|(i, &c)| {
                let p = u32::from(c - b'0') * if i % 2 == 0 { 2 } else { 1 };
                p / 10 + p % 10
            })
            .sum();
        (10 - sum % 10) % 10 == u32::from(d[9] - b'0')
    }

    const K1: [u32; 9] = [3, 7, 6, 1, 8, 9, 4, 5, 2];
    const K2: [u32; 10] = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];

    pub(super) fn valid_no_fodselsnummer(fnr: &str) -> bool {
        let b = fnr.as_bytes();
        if b.len() != 11 || !b.iter().all(u8::is_ascii_digit) {
            return false;
        }
        let mut d = [0u32; 11];
        for (x, &c) in d.iter_mut().zip(b) {
            *x = u32::from(c - b'0');
        }
        let day = if d[0] >= 4 {
            (d[0] - 4) * 10 + d[1]
        } else {
            two_digits(&b[0..2])
        };
        let month = two_digits(&b[2..4]);
        let leap = two_digits(&b[4..6]) % 4 == 0;
        if day == 0 || day > days_in_month(month, leap) {
            return false;
        }
        let s1: u32 = d.iter().zip(K1).map(|(&x, w)| x * w).sum::<u32>() + d[9];
        let s2: u32 = d.iter().zip(K2).map(|(&x, w)| x * w).sum::<u32>() + d[10];
        s1 % 11 <= 3 && s2 % 11 == 0
    }

    pub(super) fn valid_br_cpf(cpf: &str) -> bool {
        let mut d = [0u32; 11];
        let mut n = 0usize;
        for b in cpf.bytes() {
            match b {
                b'0'..=b'9' => {
                    if n == d.len() {
                        return false;
                    }
                    d[n] = u32::from(b - b'0');
                    n += 1;
                }
                b'.' | b'-' => {}
                _ => return false,
            }
        }
        if n != d.len() || d.iter().all(|&x| x == 0) {
            return false;
        }
        let check = |len: usize| -> u32 {
            let soma: u32 = d
                .iter()
                .take(len)
                .zip((2..=len as u32 + 1).rev())
                .map(|(&x, w)| x * w)
                .sum();
            let resto = soma * 10 % 11;
            if resto == 10 {
                0
            } else {
                resto
            }
        };
        check(9) == d[9] && check(10) == d[10]
    }

    pub(super) fn valid_br_cnpj(cnpj: &str) -> bool {
        let mut v = [0u32; 14];
        let mut n = 0usize;
        for b in cnpj.bytes() {
            match b {
                b'.' | b'/' | b'-' => {}
                b'0'..=b'9' | b'A'..=b'Z' => {
                    if n == v.len() {
                        return false;
                    }
                    v[n] = u32::from(b) - 48;
                    n += 1;
                }
                _ => return false,
            }
        }
        if n != v.len() || v[12] > 9 || v[13] > 9 {
            return false;
        }
        let dv = |len: usize| -> u32 {
            let sum: u32 = v
                .iter()
                .take(len)
                .enumerate()
                .map(|(i, &x)| x * (2 + ((len - 1 - i) % 8) as u32))
                .sum();
            match sum % 11 {
                0 | 1 => 0,
                r => 11 - r,
            }
        };
        dv(12) == v[12] && dv(13) == v[13]
    }

    pub(super) fn valid_dk_cpr(cpr: &str) -> bool {
        let mut d = [0u8; 10];
        let mut n = 0usize;
        for b in cpr.bytes() {
            match b {
                b'0'..=b'9' => {
                    if n == d.len() {
                        return false;
                    }
                    d[n] = b;
                    n += 1;
                }
                b' ' | b'-' => {}
                _ => return false,
            }
        }
        if n != d.len() || &d[6..] == b"0000" {
            return false;
        }
        let day = two_digits(&d[0..2]);
        let month = two_digits(&d[2..4]);
        let yy = two_digits(&d[4..6]);
        let century = match (d[6] - b'0', yy) {
            (0..=3, _) | (4 | 9, 37..=99) => 1900,
            (4 | 9, _) | (5..=8, 0..=57) => 2000,
            _ => 1800,
        };
        day >= 1 && day <= days_in_month(month, is_leap_year(century + yy))
    }
}

/// Deterministic xorshift64* generator (no external crates, same inputs
/// on every run).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    /// A string of `len` characters drawn from `alphabet`.
    fn string(&mut self, alphabet: &[char], len: usize) -> String {
        (0..len)
            .map(|_| alphabet[self.below(alphabet.len())])
            .collect()
    }

    fn digits(&mut self, len: usize) -> String {
        self.string(&DIGITS, len)
    }
}

const DIGITS: [char; 10] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];

/// Separator- and junk-bearing alphabet: every separator any validator
/// skips, characters each one rejects, uppercase letters (CNPJ code
/// characters), lowercase, non-ASCII digits and multi-byte characters.
const MIXED: [char; 22] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ' ', '-', '.', '/', '+', '*', 'A', 'Z', 'a',
    '\u{0660}', '\u{FF11}', '\t',
];

/// Hand-picked edge inputs shared by every validator.
fn edge_inputs() -> Vec<String> {
    let mut v: Vec<String> = [
        "",
        " ",
        "-",
        ".",
        "0",
        "00000000000",
        "000.000.000-00",
        "529.982.247-25",
        "52998224725",
        "529.982.247-26",
        "529..982..247--25",
        "529.982.247-255",
        "5299822472",
        "52998224725 ",
        "52998224725/",
        "12.ABC.345/01DE-35",
        "12ABC34501DE35",
        "12.ABC.345/01DE-36",
        "12.abc.345/01de-35",
        "12.345.678/0001-95",
        "11222363000198",
        "12ABC34501DE3A",
        "12ABC34501DE355",
        "070761-4285",
        "070761-4286",
        "07 07 61-4285",
        "0707614285",
        "310261-4285",
        "070761-0000",
        "290200-1234",
        "290200-4234",
        "290258-5234",
        "070761-42850",
        "070761_4285",
        "4111111111111111",
        "4111 1111 1111 1111",
        "4111-1111-1111-1111",
        "4111111111111112",
        "411111111111",
        "4111 1111 1111 111x",
        "4539 1488 0343 6467",
        "4539 1488 0343 6468",
        "1234567890123456789",
        "12345678901234567890",
        "123-456-782",
        "123 456 782",
        "123456782",
        "123456783",
        "023456786",
        "823456787",
        "12345678200002",
        "12345678200001",
        "123 456 782 00002",
        "640823-3234",
        "6408233234",
        "196408233234",
        "640823+3234",
        "640883-3231",
        "640823-3235",
        "640823-0008",
        "000229-0003",
        "040229-0007",
        "190000229-0003",
        "200002290003",
        "190002290003",
        "02013299997",
        "30108299939",
        "02013299998",
        "0201329999",
        "29020012345",
        "69020012345",
        "\u{0661}23456782",
        "\u{FF11}23456782",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    // every two-digit year on 29 February in each date-first / year-first
    // layout (the leap-year helpers)
    for yy in 0..100 {
        v.push(format!("{yy:02}0229-3234"));
        v.push(format!("{yy:02}0229{:04}", yy * 37 % 10_000));
        v.push(format!("2902{yy:02}-4285"));
        v.push(format!("2902{yy:02}{:05}", yy * 911 % 100_000));
        v.push(format!("6902{yy:02}{:05}", yy * 577 % 100_000));
        for c in ["18", "19", "20"] {
            v.push(format!("{c}{yy:02}0229{:04}", yy * 13 % 10_000));
        }
    }
    v
}

/// Generated inputs: edge table + random mixed strings + random digit
/// strings + shaped values with real calendar dates (so the checksum and
/// leap-year branches are reached, not just the shape rejections).
fn generated_inputs() -> Vec<String> {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut v = edge_inputs();
    for _ in 0..60_000 {
        let len = rng.below(22);
        v.push(rng.string(&MIXED, len));
    }
    for _ in 0..60_000 {
        let len = 8 + rng.below(13);
        v.push(rng.digits(len));
    }
    for _ in 0..40_000 {
        let yy = rng.below(100);
        let mm = 1 + rng.below(12);
        let dd = 1 + rng.below(31);
        let serial = rng.digits(4);
        let plus = if rng.below(4) == 0 { 60 } else { 0 };
        let sep = ["", "-", "+", " "][rng.below(4)];
        // se layout YYMMDD[-+]NNNC (+60 coordination day)
        v.push(format!("{yy:02}{mm:02}{:02}{sep}{serial}", dd + plus));
        // dk layout DDMMYY[-]SSSS
        v.push(format!("{dd:02}{mm:02}{yy:02}{sep}{serial}"));
        // no layout DDMMYY + 5 digits (+40 d-nummer day)
        let dn = if rng.below(4) == 0 { 40 } else { 0 };
        v.push(format!("{:02}{mm:02}{yy:02}{}", dd + dn, rng.digits(5)));
        // se 12-digit form CCYYMMDDNNNC
        let cc = ["18", "19", "20", "21"][rng.below(4)];
        v.push(format!("{cc}{yy:02}{mm:02}{dd:02}{serial}"));
    }
    for _ in 0..20_000 {
        // cpf / cnpj masks with random code characters
        v.push(format!(
            "{}.{}.{}-{}",
            rng.digits(3),
            rng.digits(3),
            rng.digits(3),
            rng.digits(2)
        ));
        let code: String = rng.string(&['0', '1', '7', '9', 'A', 'B', 'Z'], 12);
        v.push(format!(
            "{}.{}.{}/{}-{}",
            &code[..2],
            &code[2..5],
            &code[5..8],
            &code[8..12],
            rng.digits(2)
        ));
    }
    v
}

/// A public validator signature.
type Validator = fn(&str) -> bool;

/// Asserts `new` and `old` agree on every input and that both verdicts
/// occur (a table where everything fails proves nothing).
fn assert_equivalent(name: &str, inputs: &[String], new: Validator, old: Validator) {
    let mut accepted = 0usize;
    for s in inputs {
        let (n, o) = (new(s), old(s));
        assert_eq!(n, o, "{name} diverges on {s:?}: public {n}, reference {o}");
        accepted += usize::from(n);
    }
    assert!(
        accepted > 0 && accepted < inputs.len(),
        "{name}: degenerate table ({accepted} of {} accepted)",
        inputs.len()
    );
}

#[test]
fn validators_agree_with_their_reference_implementations() {
    let inputs = generated_inputs();
    let cases: [(&str, Validator, Validator); 9] = [
        ("valid_luhn", redactify::valid_luhn, reference::valid_luhn),
        (
            "valid_credit_card",
            redactify::valid_credit_card,
            reference::valid_credit_card,
        ),
        (
            "valid_ca_sin",
            redactify::valid_ca_sin,
            reference::valid_ca_sin,
        ),
        (
            "valid_fr_siret",
            redactify::valid_fr_siret,
            reference::valid_fr_siret,
        ),
        (
            "valid_se_personnummer",
            redactify::valid_se_personnummer,
            reference::valid_se_personnummer,
        ),
        (
            "valid_no_fodselsnummer",
            redactify::valid_no_fodselsnummer,
            reference::valid_no_fodselsnummer,
        ),
        (
            "valid_br_cpf",
            redactify::valid_br_cpf,
            reference::valid_br_cpf,
        ),
        (
            "valid_br_cnpj",
            redactify::valid_br_cnpj,
            reference::valid_br_cnpj,
        ),
        (
            "valid_dk_cpr",
            redactify::valid_dk_cpr,
            reference::valid_dk_cpr,
        ),
    ];
    for (name, new, old) in cases {
        assert_equivalent(name, &inputs, new, old);
    }
}

#[test]
fn card_luhn_keeps_its_thirteen_digit_gate() {
    // the shared helper has no length gate; the public card Luhn keeps it
    // (a 12-digit Luhn-valid run is not a card)
    assert!(redactify::valid_ca_sin("123456782")); // 9-digit Luhn-valid
    assert!(!redactify::valid_luhn("123456782"));
    assert!(!redactify::valid_luhn("000000000000")); // 12 digits, sum 0
    assert!(redactify::valid_luhn("0000000000000")); // 13 digits, sum 0
}
