//! International `+CC` phone numbers written with the separators real
//! text uses: dots as well as spaces and dashes, a one-digit first group
//! (`+33 1 23 45 67 89`, `+61 2 9876 5432`).

use redactify::{detect, EntityType};

fn phones(text: &str) -> Vec<String> {
    detect(text)
        .into_iter()
        .filter(|e| e.kind == EntityType::Phone)
        .map(|e| e.text)
        .collect()
}

#[test]
fn mixed_separators_and_short_first_groups_are_phones() {
    for number in [
        "+47.20-853.2208",
        "+603 05 824.9734",
        "+973-088.246 2405",
        "+65-05 348.4271",
        "+33 1 23 45 67 89",
        "+61 2 9876 5432",
        "+971 4 555 1234",
        "+53-42.392 6850",
        "+974 4437 9827",
    ] {
        assert_eq!(
            phones(&format!("call {number} now")),
            vec![number.to_owned()],
            "{number}"
        );
        assert_eq!(
            phones(&format!("tel: {number}.")),
            vec![number.to_owned()],
            "{number}"
        );
    }
}

#[test]
fn versions_dates_scores_and_short_runs_are_not_phones() {
    for text in [
        "version +1.2.3.4567 released",
        "since +2024.10.31 only",
        "pi is +3.14159",
        "score +10.5 and +20.5",
        "offset +100 200",
        "range +12 34 56",
        "ratio 1.5 +2 -3",
    ] {
        assert!(phones(text).is_empty(), "{text}: {:?}", phones(text));
    }
}

#[test]
fn nanp_and_turkish_numbers_keep_their_own_rules() {
    assert_eq!(
        phones("call +90 532 123 45 67 now"),
        vec!["+90 532 123 45 67".to_owned()]
    );
    assert_eq!(phones("call +1 415 555 2671 now").len(), 1);
}
