//! Brazilian CPF (Cadastro de Pessoas Físicas): validator + rules.
//!
//! Official source (retrieved 2026-10-29; re-retrieved 2026-10-31,
//! byte-identical): Receita Federal do Brasil, the public CPF
//! status-lookup service, client routine `funcoes03.js`,
//! <https://servicos.receita.fazenda.gov.br/Servicos/CPF/ConsultaSituacao/funcoes03.js>
//! (loaded by `ConsultaPublica.asp` of the same service), functions
//! `TestaCPF` (check digits) and `FG_FormatarCPF` (display mask). The
//! Receita Federal issues the CPF, so this routine is the issuing
//! authority's own published validation code (a first-party source): it
//! is the official source of the check-digit rule below, on the same
//! footing as an issuer's written specification. (No prose specification
//! of the CPF check digits was retrievable from a government page.)
//! Quoted rule (`TestaCPF`):
//!
//! ```text
//! if (strCPF == "00000000000")
//!     return false;
//! for (i=1; i<=9; i++)
//!     Soma = Soma + parseInt(strCPF.substring(i-1, i)) * (11 - i);
//! Resto = (Soma * 10) % 11;
//! if ((Resto == 10) || (Resto == 11))
//!     Resto = 0;
//! if (Resto != parseInt(strCPF.substring(9, 10)) )
//!     return false;
//! Soma = 0;
//! for (i = 1; i <= 10; i++)
//!    Soma = Soma + parseInt(strCPF.substring(i-1, i)) * (12 - i);
//! Resto = (Soma * 10) % 11;
//! if ((Resto == 10) || (Resto == 11))
//!     Resto = 0;
//! if (Resto != parseInt(strCPF.substring(10, 11) ) )
//!     return false;
//! return true;
//! ```
//!
//! Display mask (`FG_FormatarCPF`): `substr(0, 3) + '.' + substr(3, 3) +
//! '.' + substr(6, 3) + '-' + substr(9, 2)`, i.e. `XXX.XXX.XXX-XX`.
//!
//! The routine rejects only the all-zero value; other repeated-digit values
//! that pass the arithmetic (`111.111.111-11`) are accepted exactly as the
//! official routine accepts them (masking a dummy is harmless for a
//! redactor - TCKN precedent).
//!
//! Cue policy: the dotted mask carries two check digits (1 in 100 random
//! shapes pass) and is specific on its own -> claimed cue-less at 1.0
//! (TCKN tier). A bare 11-digit run collides with TCKN, PESEL, Steuer-IdNr
//! and phone shapes -> a "cpf" cue is REQUIRED (score 1.0: checksum
//! verified). The cue is the identifier's own name as used by the source.

use crate::pii::entity::EntityType;

use crate::pii::locales::{code_chars, rule, ContextPolicy, Rule};

/// Cue words that make a bare 11-digit CPF candidate claimable.
pub(super) const CUES: &[&str] = &["cpf"];

/// Returns `true` if `cpf` is a valid Brazilian CPF: 11 digits (the
/// `.`/`-` of the `XXX.XXX.XXX-XX` mask are ignored, any other character
/// rejects) whose two check digits match the Receita Federal routine; the
/// all-zero value is rejected as the routine does.
///
/// # Examples
/// ```
/// use redactify::valid_br_cpf;
/// assert!(valid_br_cpf("529.982.247-25"));
/// assert!(valid_br_cpf("52998224725"));
/// assert!(!valid_br_cpf("529.982.247-26")); // second check digit off
/// assert!(!valid_br_cpf("000.000.000-00")); // rejected by the routine
/// assert!(!valid_br_cpf("5299822472"));     // 10 digits
/// ```
#[must_use]
pub fn valid_br_cpf(cpf: &str) -> bool {
    let Some(raw) = code_chars::<11>(cpf, u8::is_ascii_digit, b".-") else {
        return false;
    };
    let d = raw.map(|b| u32::from(b - b'0'));
    if d.iter().all(|&x| x == 0) {
        return false;
    }
    // TestaCPF: weights (len + 1) down to 2, Resto = (Soma * 10) % 11,
    // a remainder of 10 counts as 0
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

/// Formatted CPF (`XXX.XXX.XXX-XX`): claimed without a cue.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::BrCpf,
        r"(?<![\d.])\d{3}\.\d{3}\.\d{3}-\d{2}(?![\d-])",
        Some(valid_br_cpf),
        ContextPolicy::None,
        1.0
    )
}

/// Bare 11-digit CPF: a "cpf" cue is required (shape collisions).
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn bare_rule() -> Rule {
    rule!(
        id = "br::cpf_bare",
        EntityType::BrCpf,
        r"(?<![\d.])\d{11}(?![\d-])",
        Some(valid_br_cpf),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_br_cpf;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn check_digit_math() {
        // check digits computed by hand with the TestaCPF arithmetic:
        // 529982247: soma = 5*10+2*9+9*8+9*7+8*6+2*5+2*4+4*3+7*2 = 295,
        // 2950 % 11 = 2 -> d10 = 2; second pass with d10 -> d11 = 5
        let soma = 5 * 10 + 2 * 9 + 9 * 8 + 9 * 7 + 8 * 6 + 2 * 5 + 2 * 4 + 4 * 3 + 7 * 2;
        assert_eq!(soma, 295);
        assert_eq!(soma * 10 % 11, 2);
        for v in [
            "529.982.247-25",
            "111.444.777-35",
            "123.456.789-09",
            "93541134780",
        ] {
            assert!(valid_br_cpf(v), "{v}");
        }
        // remainder 10 -> 0 on the first pass (100000001: soma 10+2 = 12,
        // 120 % 11 = 10) and on the second pass (100000028 -> d10 = 1,
        // second remainder 10)
        assert!(valid_br_cpf("100.000.001-08"));
        assert!(valid_br_cpf("100.000.028-10"));
        assert!(!valid_br_cpf("100.000.001-18")); // 10 written as "1" + d11
        assert!(valid_br_cpf("000.000.001-91"));
        // corrupted check digits / wrong lengths / foreign characters
        for v in [
            "529.982.247-24",
            "111.444.777-53",
            "1234567890",
            "123456789091",
            "52998224X25",
        ] {
            assert!(!valid_br_cpf(v), "{v}");
        }
        // the routine's only explicit rejection
        assert!(!valid_br_cpf("00000000000"));
        // repeated digits pass the arithmetic and the routine accepts them
        assert!(valid_br_cpf("111.111.111-11"));
    }

    #[test]
    fn formatted_is_cue_less_bare_needs_cue() {
        let ents = engine_detect("cliente 529.982.247-25 cadastrado", &["br"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::BrCpf);
        assert_eq!(ents[0].text, "529.982.247-25");
        assert!((ents[0].score - 1.0).abs() < f32::EPSILON);

        let bare = engine_detect("pedido 52998224725 enviado", &["br"]);
        assert!(bare.is_empty(), "{bare:?}");
        let cued = engine_detect("CPF 52998224725 do titular", &["br"]);
        assert_eq!(cued.len(), 1, "{cued:?}");
        assert_eq!(cued[0].kind, EntityType::BrCpf);
    }

    #[test]
    fn bad_check_digits_are_never_claimed() {
        assert!(engine_detect("CPF 529.982.247-24", &["br"]).is_empty());
        assert!(engine_detect("CPF 52998224724", &["br"]).is_empty());
    }
}
