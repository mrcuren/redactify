//! Brazilian CNPJ (Cadastro Nacional da Pessoa Jurídica), numeric and
//! alphanumeric: validator + rules.
//!
//! Official sources (retrieved 2026-10-29), Receita Federal do Brasil:
//!
//! 1. "Manual de Cálculo do DV do CNPJ" (document title "Cálculo dos
//!    dígitos verificadores de CNPJ alfanumérico", prepared by Serpro,
//!    listed under Documentos Técnicos > CNPJ, published 05/11/2024),
//!    <https://www.gov.br/receitafederal/pt-br/centrais-de-conteudo/publicacoes/documentos-tecnicos/cnpj/manual-dv-cnpj.pdf>.
//!    Section 1: "O CNPJ alfanumérico é composto por doze caracteres
//!    alfanuméricos e dois dígitos verificadores numéricos. Os dígitos
//!    verificadores (DV) são calculados a partir dos doze primeiros
//!    caracteres em duas etapas, utilizando o módulo de divisão 11 e pesos
//!    distribuídos de 2 a 9." Section 1.1: "Para cada um dos caracteres do
//!    CNPJ, atribuir o valor da coluna 'Valor para cálculo do DV' ... (ou
//!    subtrair 48 do 'Valor ASCII')"; "Distribuir os pesos de 2 a 9 da
//!    direita para a esquerda (recomeçando depois do oitavo caracter)";
//!    "Se o resto da divisão for igual a 1 ou 0, o primeiro dígito será
//!    igual a 0 (zero). Senão, o primeiro dígito será igual ao resultado de
//!    11 - resto." Section 1.2: "Para o cálculo do segundo dígito é
//!    necessário acrescentar o primeiro DV ao final do CNPJ, formando assim
//!    treze caracteres, e repetir os passos realizados para o primeiro
//!    dígito." Worked example: "Resultado final: 12.ABC.345/01DE-35".
//! 2. "CNPJ Alfanumérico - Perguntas & Respostas",
//!    <https://www.gov.br/receitafederal/pt-br/centrais-de-conteudo/publicacoes/perguntas-e-respostas/cnpj/cnpj-alfanumerico.pdf>.
//!    Q2: "AA.AAA.AAA/AAAA-DV onde: A - Alfanumérico. Poderá ser numerais de
//!    0 a 9 e letras maiúsculas de A até Z. DV - Dígito Verificador
//!    utilizando o cálculo pelo módulo 11". Q4: "A data para início de
//!    entrada em produção dos primeiros CNPJ alfanuméricos será a partir de
//!    Julho de 2026." Q7: both the numeric and the alphanumeric format stay
//!    valid. Q26: the schedule follows "Instrução Normativa 2.119/2022, com
//!    as alterações introduzidas pela Instrução Normativa RFB 2.229/2024".
//!    Q17 numeric example `12.345.678/0001-95`; Q23 examples
//!    `AA345678/000A-29` and `12.345.678/000A-08` (both check out) and
//!    `AA345678/0003-29` (a format illustration whose DVs do NOT check out:
//!    the computed DVs are `86`).
//!
//! Numeric CNPJs are the special case where every character is a digit
//! (`'0'..'9'` map to 0-9 under `ASCII - 48`), so one validator covers
//! both generations.
//!
//! Cue policy: the slash-bearing mask (`XX.XXX.XXX/XXXX-DV`, dots and the
//! dash optional as in the Q23 examples) is specific and carries two check
//! digits -> claimed cue-less at 1.0. A bare 14-character run collides with
//! SIRET/card shapes and product codes -> a "cnpj" cue is REQUIRED (1.0).
//! Priority tier 0 (see `EntityType::priority`): 9.97% of valid numeric
//! CNPJs also pass Luhn (measured on 200,000 generated values), and the
//! cue-gated checksummed claim must not be relabelled as a card.

use crate::pii::entity::EntityType;

use crate::pii::locales::{code_chars, rule, ContextPolicy, Rule};

/// Cue words that make a bare 14-character CNPJ candidate claimable.
pub(super) const CUES: &[&str] = &["cnpj"];

/// Returns `true` if `cnpj` is a valid Brazilian CNPJ: 12 characters from
/// `0-9`/`A-Z` plus 2 numeric check digits (the `.`, `/` and `-` of the
/// `XX.XXX.XXX/XXXX-DV` mask are ignored; lowercase letters and any other
/// character reject). Character value = ASCII code - 48; weights 2-9 from
/// the right, restarting after the eighth character; remainder 0 or 1
/// gives 0, otherwise 11 - remainder.
///
/// # Examples
/// ```
/// use redactify::valid_br_cnpj;
/// assert!(valid_br_cnpj("12.ABC.345/01DE-35")); // Receita worked example
/// assert!(valid_br_cnpj("12.345.678/0001-95")); // numeric (FAQ Q17)
/// assert!(valid_br_cnpj("12ABC34501DE35"));
/// assert!(!valid_br_cnpj("12.ABC.345/01DE-36")); // second DV off
/// assert!(!valid_br_cnpj("12.abc.345/01de-35")); // letters are uppercase
/// ```
#[must_use]
pub fn valid_br_cnpj(cnpj: &str) -> bool {
    let code = |b: &u8| b.is_ascii_digit() || b.is_ascii_uppercase();
    let Some(raw) = code_chars::<14>(cnpj, code, b"./-") else {
        return false;
    };
    let v = raw.map(|b| u32::from(b) - 48);
    // the two DVs are numeric
    if v[12] > 9 || v[13] > 9 {
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

/// Slash-bearing CNPJ mask: claimed without a cue.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn rule() -> Rule {
    rule!(
        EntityType::BrCnpj,
        r"(?<![0-9A-Za-z.])[0-9A-Z]{2}\.?[0-9A-Z]{3}\.?[0-9A-Z]{3}/[0-9A-Z]{4}-?\d{2}(?![0-9A-Za-z])",
        Some(valid_br_cnpj),
        ContextPolicy::None,
        1.0
    )
}

/// Bare 14-character CNPJ: a "cnpj" cue is required.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn bare_rule() -> Rule {
    rule!(
        id = "br::cnpj_bare",
        EntityType::BrCnpj,
        r"(?<![0-9A-Za-z.])[0-9A-Z]{12}\d{2}(?![0-9A-Za-z])",
        Some(valid_br_cnpj),
        ContextPolicy::RequiredCue(CUES),
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::valid_br_cnpj;
    use crate::pii::detect::engine_detect;
    use crate::EntityType;

    #[test]
    fn worked_example_arithmetic() {
        // manual section 1.1: values 1 2 17 18 19 3 4 5 0 1 20 21, weights
        // 5 4 3 2 9 8 7 6 5 4 3 2 -> 459, 459 % 11 = 8 -> DV1 = 3
        let vals = [1, 2, 17, 18, 19, 3, 4, 5, 0, 1, 20, 21];
        let w = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        let s: u32 = vals.iter().zip(w).map(|(a, b)| a * b).sum();
        assert_eq!(s, 459);
        assert_eq!(11 - s % 11, 3);
        // section 1.2: with DV1 appended, weights 6..2 -> 424, 424 % 11 = 6
        let vals2 = [1, 2, 17, 18, 19, 3, 4, 5, 0, 1, 20, 21, 3];
        let w2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        let s2: u32 = vals2.iter().zip(w2).map(|(a, b)| a * b).sum();
        assert_eq!(s2, 424);
        assert_eq!(11 - s2 % 11, 5);
    }

    #[test]
    fn official_examples() {
        for v in [
            "12.ABC.345/01DE-35",
            "12.345.678/0001-95",
            "AA345678/000A-29",
            "12.345.678/000A-08",
            "11.222.333/0001-81",
        ] {
            assert!(valid_br_cnpj(v), "{v}");
        }
        // FAQ Q23 Ex1 is a format illustration: its DVs do not check out
        assert!(!valid_br_cnpj("AA345678/0003-29"));
        assert!(valid_br_cnpj("AA345678/0003-86"));
        // letters in the DV positions, lowercase, wrong length
        assert!(!valid_br_cnpj("12ABC34501DE3A"));
        assert!(!valid_br_cnpj("12abc34501de35"));
        assert!(!valid_br_cnpj("12ABC34501DE3"));
        assert!(!valid_br_cnpj("12ABC34501DE355"));
    }

    #[test]
    fn mask_is_cue_less_bare_needs_cue() {
        let ents = engine_detect("empresa 12.ABC.345/01DE-35 ativa", &["br"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::BrCnpj);
        assert_eq!(ents[0].text, "12.ABC.345/01DE-35");

        assert!(engine_detect("lote 12ABC34501DE35 enviado", &["br"]).is_empty());
        let cued = engine_detect("CNPJ 12ABC34501DE35 da empresa", &["br"]);
        assert_eq!(cued.len(), 1, "{cued:?}");
        assert_eq!(cued[0].kind, EntityType::BrCnpj);
    }

    #[test]
    fn luhn_passing_cnpj_is_not_relabelled_as_a_card() {
        // 11222363000198 passes Luhn as well; tier 0 keeps the CNPJ label
        assert!(valid_br_cnpj("11222363000198"));
        assert!(crate::valid_luhn("11222363000198"));
        let ents = engine_detect("CNPJ 11222363000198", &["br"]);
        assert_eq!(ents.len(), 1, "{ents:?}");
        assert_eq!(ents[0].kind, EntityType::BrCnpj);
    }
}
