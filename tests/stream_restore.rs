//! Streaming vault restore: for every chunking of a response, the
//! concatenated `push` outputs plus `finish` equal `restore` of the
//! whole response (strict and tolerant); and the automaton-based strict
//! restore equals the previous one-scan-per-entry algorithm (kept here as
//! the reference).

use proptest::prelude::*;
use redactify::{Detector, RestoreOptions, Vault};

/// The previous `restore`: at every step, the earliest occurrence of
/// any token wins (ties: the first entry in key order); restored text is
/// never re-scanned.
fn reference_restore(vault: &Vault, text: &str) -> String {
    let tokens: Vec<(String, String)> = vault
        .entries_iter()
        .map(|(k, v)| (format!("[{k}]"), v.clone()))
        .collect();
    let mut out = String::new();
    let mut rest = text;
    loop {
        let mut best: Option<(usize, usize)> = None;
        for (i, (token, _)) in tokens.iter().enumerate() {
            if let Some(pos) = rest.find(token.as_str()) {
                if best.map_or(true, |(b, _)| pos < b) {
                    best = Some((pos, i));
                }
            }
        }
        let Some((pos, i)) = best else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..pos]);
        out.push_str(&tokens[i].1);
        rest = &rest[pos + tokens[i].0.len()..];
    }
}

/// Restores `text` through the restorer, cut at `cuts` (sorted, deduped
/// char boundaries).
fn streamed(vault: &Vault, text: &str, cuts: &[usize]) -> String {
    streamed_with(vault, text, cuts, RestoreOptions::default())
}

/// [`streamed`] with explicit options.
fn streamed_with(vault: &Vault, text: &str, cuts: &[usize], opts: RestoreOptions) -> String {
    let mut r = vault.restorer_with(opts);
    let mut out = String::new();
    let mut prev = 0;
    for &c in cuts {
        out.push_str(&r.push(&text[prev..c]));
        prev = c;
    }
    out.push_str(&r.push(&text[prev..]));
    out.push_str(&r.finish());
    out
}

fn boundaries(text: &str) -> Vec<usize> {
    (0..=text.len())
        .filter(|&i| text.is_char_boundary(i))
        .collect()
}

#[test]
fn every_split_of_an_llm_response_restores_like_batch() {
    let prompt = "Ad Soyad: Ay\u{15f}e Kaya, TCKN 12345678950, mail ayse@ornek.com.tr, \
                  IBAN TR33 0006 1005 1978 6457 8413 26, tel 0532 123 45 67";
    let (anon, vault) = Detector::new().pseudonymize(prompt);
    assert!(vault.len() >= 4, "{anon}");
    let responses = [
        anon.clone(),
        "Merhaba [NAME_1]! [TCKN_1] ve [EMAIL_1] kayitli; [IBAN_1]/[PHONE_1].".to_owned(),
        "unknown [TCKN_9] and [TCKN_1][TCKN_1] and [ and [TCKN_ and ]".to_owned(),
        "tail cut inside a token [EMAIL_".to_owned(),
        "\u{fc}\u{131}[TCKN_1]\u{15f}\u{1D54F}[PHONE_1]".to_owned(),
    ];
    for response in &responses {
        let full = vault.restore(response);
        assert_eq!(full, reference_restore(&vault, response));
        let bounds = boundaries(response);
        // every single split point
        for &c in &bounds {
            assert_eq!(streamed(&vault, response, &[c]), full, "split at {c}");
        }
        // every pair of split points
        for (i, &a) in bounds.iter().enumerate() {
            for &b in &bounds[i..] {
                assert_eq!(streamed(&vault, response, &[a, b]), full, "splits {a},{b}");
            }
        }
        // one character per chunk
        let chars: Vec<usize> = response.char_indices().map(|(i, _)| i).skip(1).collect();
        assert_eq!(streamed(&vault, response, &chars), full, "char-wise");
    }
}

#[test]
fn restorer_emits_text_as_soon_as_it_is_final() {
    let (_, vault) = Vault::pseudonymize("TCKN 12345678950 mail a@b.com");
    let mut r = vault.restorer_with(RestoreOptions::STRICT);
    // nothing token-like: everything is final at once
    assert_eq!(r.push("Hello there, "), "Hello there, ");
    // a possible token start is held back...
    assert_eq!(r.push("your [TCKN"), "your ");
    // ...and released as soon as it completes
    assert_eq!(r.push("_1] and [EMAIL_1]"), "12345678950 and a@b.com");
    // a bracket that cannot start any token is not held back
    assert_eq!(r.push(" [x] "), " [x] ");
    assert_eq!(r.finish(), "");

    // tolerant: a complete token waits for one more character (a suffix
    // may follow); a lower-case word is never held
    let mut r = vault.restorer();
    assert_eq!(r.push("Hello there, "), "Hello there, ");
    assert_eq!(r.push("your [TCKN"), "your ");
    assert_eq!(r.push("_1] and [EMAIL_1]"), "12345678950 and ");
    assert_eq!(r.push(" [x] "), "a@b.com [x] ");
    assert_eq!(r.finish(), "");
}

/// Small alphabets so that random keys collide, nest and prefix each
/// other often.
fn arb_key() -> impl Strategy<Value = String> {
    "[AB_1\\[\\]]{0,4}"
}

fn arb_text() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            4 => "[AB_1\\[\\] ]{1,3}",
            1 => Just("\u{fc}".to_owned()),
            1 => Just("\u{1D54F}".to_owned()),
        ],
        0..24,
    )
    .prop_map(|parts| parts.concat())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// The automaton restore equals the reference algorithm on random
    /// tables whose tokens overlap and prefix each other.
    #[test]
    fn automaton_restore_equals_the_reference(
        entries in proptest::collection::vec((arb_key(), "[a-z\\[\\]]{0,3}"), 0..6),
        text in arb_text(),
    ) {
        let vault = Vault::from_entries(entries);
        prop_assert_eq!(
            vault.restore_with(&text, RestoreOptions::STRICT),
            reference_restore(&vault, &text)
        );
    }

    /// Streaming at random char-boundary cuts equals the batch restore.
    #[test]
    fn streaming_restore_equals_batch_at_random_cuts(
        (entries, text, cuts) in (
            proptest::collection::vec((arb_key(), "[a-z]{0,3}"), 0..6),
            arb_text(),
        ).prop_flat_map(|(entries, text)| {
            let bounds = boundaries(&text);
            let max = bounds.len().min(6);
            (Just(entries), Just(text), proptest::sample::subsequence(bounds, 0..=max))
        })
    ) {
        let vault = Vault::from_entries(entries);
        let mut cuts = cuts;
        cuts.sort_unstable();
        cuts.dedup();
        for opts in [RestoreOptions::STRICT, RestoreOptions::TOLERANT] {
            prop_assert_eq!(
                streamed_with(&vault, &text, &cuts, opts),
                vault.restore_with(&text, opts)
            );
        }
    }
}
