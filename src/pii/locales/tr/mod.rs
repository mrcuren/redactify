//! Turkish identifier rules: TCKN, IBAN-TR, VKN, plates, passports, phones,
//! labeled-context and label-free person names (the lexicon scanner), the
//! record fields of Turkish documents: postal address, date and place of
//! birth, card security code and expiry, customer, policy, SGK and MERSİS
//! numbers, and the KVKK art. 6 special categories of personal data when
//! tied to a person (`special`).

pub(crate) mod address;
pub(crate) mod birth_date;
pub(crate) mod birth_place;
pub(crate) mod card_cvv;
pub(crate) mod card_expiry;
pub(crate) mod customer_number;
mod gazetteer;
pub(crate) mod iban;
pub(crate) mod mersis;
pub(crate) mod name;
pub(crate) mod passport;
pub(crate) mod person;
mod person_lexicon;
pub(crate) mod phone;
mod places;
pub(crate) mod plaka;
pub(crate) mod policy_number;
pub(crate) mod sgk;
pub(crate) mod special;
pub(crate) mod tckn;
pub(crate) mod vkn;

use crate::pii::locales::Rule;

/// Appends the Turkish record-field rules (address, birth date/place,
/// card code/expiry, customer/policy/SGK/MERSİS numbers). Every one but
/// the address is cue-gated; their shapes and cue sets are disjoint
/// except customer vs policy numbers, where an equal-span tie (a run with
/// both cues on its line) goes to the policy number (registered first).
pub(crate) fn push_record_rules(rules: &mut Vec<Rule>) {
    rules.extend([
        address::rule(),
        birth_date::rule(),
        birth_place::rule(),
        card_cvv::rule(),
        card_expiry::rule(),
        policy_number::rule(),
        customer_number::rule(),
        sgk::rule(),
        mersis::rule(),
    ]);
}

#[cfg(test)]
mod tests {
    #[test]
    fn record_rules_finish_long_hostile_lines_within_the_backtrack_budget() {
        let mut rules = Vec::new();
        super::push_record_rules(&mut rules);
        for unit in [
            "a", "ü", "0", "1 ", "Ab ", "Ab Mah. ", "No:1 ", "1/2 ", "12.03.", "POL-1-", "İzmir ",
            "12/", "1-",
        ] {
            let text = unit.repeat(200_000 / unit.len());
            for r in &rules {
                assert!(
                    r.regex.find_iter(&text).all(|m| m.is_ok()),
                    "{} on {unit:?}: backtrack budget exhausted",
                    r.id
                );
            }
        }
    }
}
