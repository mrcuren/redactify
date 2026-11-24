//! Corpus parity - exact span matching over a 155-line synthetic corpus:
//! 140 gold entities + 15 distractor lines (nothing should be detected there).
//!
//! **Offset note:** the reference labels use CHARACTER offsets while this API
//! returns BYTE offsets (the Rust convention). Turkish templates contain
//! multi-byte letters ("Maaş hesabı"...), so conversion is mandatory: labels are
//! mapped to byte offsets via `char_to_byte`. This proves both systems see the
//! *same spans*; only the offset unit differs.

use std::collections::BTreeSet;
use std::path::PathBuf;

use redactify::{detect, EntityType};

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data/pii_corpus.jsonl")
}

/// Maps character indices of `text` to byte indices (len = char_count + 1).
fn char_to_byte(text: &str) -> Vec<usize> {
    let mut map: Vec<usize> = text.char_indices().map(|(b, _)| b).collect();
    map.push(text.len());
    map
}

/// The entity types the corpus labels (the image of [`parse_kind`]).
const LABELED: [EntityType; 7] = [
    EntityType::Tckn,
    EntityType::Iban,
    EntityType::Vkn,
    EntityType::Plaka,
    EntityType::Phone,
    EntityType::Email,
    EntityType::CreditCard,
];

fn parse_kind(s: &str) -> EntityType {
    match s {
        "TCKN" => EntityType::Tckn,
        "IBAN" => EntityType::Iban,
        "VKN" => EntityType::Vkn,
        "PLAKA" => EntityType::Plaka,
        "PHONE" => EntityType::Phone,
        "EMAIL" => EntityType::Email,
        "CREDIT_CARD" => EntityType::CreditCard,
        other => panic!("unknown type: {other}"),
    }
}

struct Row {
    text: String,
    /// (type, start_byte, end_byte) - labels converted from character offsets.
    gold: Vec<(EntityType, usize, usize)>,
}

fn load() -> Vec<Row> {
    let raw = std::fs::read_to_string(corpus_path()).expect("corpus file reads");
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).expect("valid JSON line");
            let text = v["text"].as_str().expect("text field").to_owned();
            let map = char_to_byte(&text);
            let gold = v["entities"]
                .as_array()
                .expect("entities dizisi")
                .iter()
                .map(|e| {
                    let cs = e["start"].as_u64().expect("start") as usize;
                    let ce = e["end"].as_u64().expect("end") as usize;
                    (
                        parse_kind(e["type"].as_str().expect("type")),
                        map[cs],
                        map[ce],
                    )
                })
                .collect();
            Row { text, gold }
        })
        .collect()
}

#[test]
fn corpus_has_expected_shape() {
    let rows = load();
    assert_eq!(rows.len(), 155, "155 lines expected");
    assert_eq!(
        rows.iter().map(|r| r.gold.len()).sum::<usize>(),
        140,
        "140 gold entity"
    );
    assert_eq!(
        rows.iter().filter(|r| r.gold.is_empty()).count(),
        15,
        "15 distractor"
    );
}

#[test]
fn full_span_parity_with_reference_labels() {
    let rows = load();
    let mut total_gold = 0;
    let mut total_hit = 0;
    for (i, row) in rows.iter().enumerate() {
        let found: BTreeSet<(EntityType, usize, usize)> = detect(&row.text)
            .into_iter()
            .map(|e| (e.kind, e.start, e.end))
            .collect();
        let gold: BTreeSet<(EntityType, usize, usize)> = row.gold.iter().copied().collect();

        if row.gold.is_empty() {
            assert!(
                found.is_empty(),
                "false positive on distractor line {i}: {:?}",
                found
            );
            continue;
        }
        // exact span matching (not mere overlap - full parity) over the
        // corpus label set: the corpus labels seven types, so a detection of
        // a type it never labels (the card expiry `12/28` after "son
        // kullanma" in the card lines) is outside its reference, not a miss
        let found: BTreeSet<_> = found
            .into_iter()
            .filter(|(kind, _, _)| LABELED.contains(kind))
            .collect();
        assert_eq!(
            found, gold,
            "line {i}: text={:?} gold={:?} found={:?}",
            row.text, gold, found
        );
        total_gold += gold.len();
        total_hit += found.len();
    }
    assert_eq!(total_gold, 140);
    assert_eq!(total_hit, 140);
    println!("corpus parity: 140/140 exact spans, 15/15 distractors clean");
}
