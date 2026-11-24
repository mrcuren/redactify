//! Tolerant vault restore: LLM-altered placeholder forms and Turkish
//! suffixes, the negatives that must stay untouched, placeholder-shaped
//! prompt text, and the round-trip and streaming invariants in every
//! restore mode.

use proptest::prelude::*;
use redactify::{RestoreOptions, Vault};

const ALL_OPTS: [RestoreOptions; 4] = [
    RestoreOptions::STRICT,
    RestoreOptions::TOLERANT,
    RestoreOptions::TOLERANT.with_suffix_repair(false),
    RestoreOptions::TOLERANT.with_altered_forms(false),
];

/// One suite base: prompt, value, label, translated label, and the correct
/// suffix (TDK) for the dative, genitive, locative and accusative an LLM
/// wrote as `'e`, `'in`, `'de`, `'i`.
struct Base {
    prompt: &'static str,
    value: &'static str,
    label: &'static str,
    translated: Option<&'static str>,
    suffixes: Option<[&'static str; 4]>,
}

const BASES: [Base; 6] = [
    Base {
        prompt: "Ad Soyad: Ayşe Kaya",
        value: "Ayşe Kaya",
        label: "NAME",
        translated: Some("ISIM"),
        suffixes: Some(["ya", "nın", "da", "yı"]),
    },
    Base {
        prompt: "Ad Soyad: Mehmet Öztürk",
        value: "Mehmet Öztürk",
        label: "NAME",
        translated: Some("ISIM"),
        suffixes: Some(["e", "ün", "te", "ü"]),
    },
    Base {
        prompt: "TC kimlik no: 10000000146",
        value: "10000000146",
        label: "TCKN",
        translated: None,
        suffixes: Some(["ya", "nın", "da", "yı"]),
    },
    Base {
        prompt: "Telefon: 0532 234 56 78",
        value: "0532 234 56 78",
        label: "PHONE",
        translated: Some("TELEFON"),
        suffixes: Some(["e", "in", "de", "i"]),
    },
    Base {
        prompt: "IBAN: TR85 1870 6695 8688 2745 6305 22",
        value: "TR85 1870 6695 8688 2745 6305 22",
        label: "IBAN",
        translated: None,
        suffixes: Some(["ye", "nin", "de", "yi"]),
    },
    Base {
        prompt: "E-posta: ayse.kaya@example.com",
        value: "ayse.kaya@example.com",
        label: "EMAIL",
        translated: Some("EPOSTA"),
        suffixes: None,
    },
];

/// The suite's placeholder renderings for `label` (`None`: not applicable),
/// plus the HTML / JSON escaped forms the suite applied to the other tool.
fn forms(label: &str, translated: Option<&str>) -> Vec<(&'static str, Option<String>)> {
    let lower = label.to_lowercase();
    vec![
        ("exact", Some(format!("[{label}_1]"))),
        ("bracket_swap", Some(format!("<{label}_1>"))),
        ("double_bracket", Some(format!("[[{label}_1]]"))),
        ("curly", Some(format!("{{{label}_1}}"))),
        ("markdown_escaped", Some(format!("\\[{label}\\_1\\]"))),
        ("lowercase", Some(format!("[{lower}_1]"))),
        ("inner_spaces", Some(format!("[ {label}_1 ]"))),
        ("zero_padded", Some(format!("[{label}_01]"))),
        ("translated_label", translated.map(|t| format!("[{t}_1]"))),
        ("html_escaped", Some(format!("&lt;{label}_1&gt;"))),
        (
            "json_unicode_escaped",
            Some(format!("\\u003c{label}_1\\u003e")),
        ),
        ("bare_no_brackets", Some(format!("{label}_1"))),
        ("unnumbered", Some(format!("[{label}]"))),
    ]
}

fn vault_for(base: &Base) -> Vault {
    let (anon, vault) = Vault::pseudonymize(base.prompt);
    // precondition of the suite: the value got the `_1` placeholder
    assert_eq!(
        vault.original_for(&format!("{}_1", base.label)),
        Some(base.value),
        "{anon}"
    );
    vault
}

#[test]
fn altered_forms_restore_only_when_numbered() {
    let mut restored = std::collections::BTreeMap::<&str, (usize, usize)>::new();
    for base in &BASES {
        let vault = vault_for(base);
        for (name, form) in forms(base.label, base.translated) {
            let Some(form) = form else { continue };
            let response = format!("Kayıt: {form} doğrulandı.");
            let got = vault.restore(&response);
            let expected = if name == "unnumbered" {
                response.clone() // never a guess
            } else {
                format!("Kayıt: {} doğrulandı.", base.value)
            };
            assert_eq!(got, expected, "{name}: {response}");
            let e = restored.entry(name).or_default();
            e.0 += usize::from(got.contains(base.value));
            e.1 += 1;
            // strict mode restores the exact token only
            let strict = vault.restore_with(&response, RestoreOptions::STRICT);
            assert_eq!(
                strict == expected,
                name == "exact" || name == "unnumbered",
                "{name}"
            );
        }
    }
    // 12 of the 13 forms restore every value; `unnumbered` none
    let full: Vec<&str> = restored
        .iter()
        .filter(|(_, (ok, n))| ok == n)
        .map(|(k, _)| *k)
        .collect();
    assert_eq!(full.len(), 12, "{restored:?}");
    assert_eq!(restored["unnumbered"].0, 0);
}

#[test]
fn apostrophe_suffixes_follow_the_restored_value() {
    let mut exact = 0;
    let mut total = 0;
    for base in &BASES {
        let Some(correct) = base.suffixes else {
            continue;
        };
        let vault = vault_for(base);
        let ph = format!("[{}_1]", base.label);
        for (written, correct) in ["e", "in", "de", "i"].iter().zip(correct) {
            let got = vault.restore(&format!("Not: {ph}'{written} ulaşıldı."));
            assert_eq!(got, format!("Not: {}'{correct} ulaşıldı.", base.value));
            exact += 1;
            total += 1;
            // a suffix written directly after the placeholder is untouched
            let attached = vault.restore(&format!("Not: {ph}{written} ulaşıldı."));
            assert_eq!(attached, format!("Not: {}{written} ulaşıldı.", base.value));
            // strict mode keeps the suffix as written
            let strict = vault.restore_with(
                &format!("Not: {ph}'{written} ulaşıldı."),
                RestoreOptions::STRICT,
            );
            assert_eq!(strict, format!("Not: {}'{written} ulaşıldı.", base.value));
        }
        // typographic apostrophe, kept as written
        let got = vault.restore(&format!("Not: {ph}’e ulaşıldı."));
        assert_eq!(got, format!("Not: {}’{} ulaşıldı.", base.value, correct[0]));
        // a suffix after an altered form is repaired too
        let got = vault.restore(&format!("Not: <{}_1>'e ulaşıldı.", base.label));
        assert_eq!(got, format!("Not: {}'{} ulaşıldı.", base.value, correct[0]));
    }
    assert_eq!((exact, total), (20, 20));
}

#[test]
fn task_examples() {
    let (_, v) = Vault::pseudonymize("Ad Soyad: Ayşe Yılmaz, TCKN 12345678950");
    let name = v.placeholder_for("Ayşe Yılmaz").expect("name vaulted");
    let tckn = v.placeholder_for("12345678950").expect("tckn vaulted");
    assert_eq!(
        v.restore(&format!("[{tckn}]'in kaydı")),
        "12345678950'nin kaydı"
    );
    assert_eq!(v.restore(&format!("[{name}]'e")), "Ayşe Yılmaz'a");
    let ayse = Vault::from_entries([("NAME_1".to_owned(), "Ayşe".to_owned())]);
    let kemal = Vault::from_entries([("NAME_1".to_owned(), "Kemal".to_owned())]);
    let cases = [
        ("e", "ye", "e"),
        ("a", "ye", "e"),
        ("de", "de", "de"),
        ("ta", "de", "de"),
        ("in", "nin", "in"),
        ("nın", "nin", "in"),
        ("un", "nin", "in"),
        ("i", "yi", "i"),
        ("yı", "yi", "i"),
        ("den", "den", "den"),
        ("ten", "den", "den"),
        ("le", "yle", "le"),
        ("yla", "yle", "le"),
    ];
    for (written, for_ayse, for_kemal) in cases {
        let response = format!("[NAME_1]'{written}");
        assert_eq!(ayse.restore(&response), format!("Ayşe'{for_ayse}"));
        assert_eq!(kemal.restore(&response), format!("Kemal'{for_kemal}"));
    }
}

#[test]
fn negatives_stay_untouched() {
    let (_, v) = Vault::pseudonymize("Ad Soyad: Ayşe Kaya, TCKN 12345678950");
    assert_eq!(v.original_for("NAME_1"), Some("Ayşe Kaya"));
    // another vault's tokens: this vault has no EMAIL or PHONE entry
    let (other, _) = Vault::pseudonymize("mail a@b.com, tel 0532 234 56 78");
    assert!(other.contains("[EMAIL_1]"), "{other}");
    let untouched = [
        "[NAME]",
        "[1]",
        "[NAME_2]",
        "[NAME_0]",
        "[NAME_]",
        "[_1]",
        "[NAME_1_]",
        "[N AME_1]",
        "[NAME 1]",
        "[NAME-1]",
        "[   name_1]",
        "[name_1>",
        "name_1",
        "Name_1",
        "xNAME_1",
        "NAME_1x",
        "NAME_10",
        "_NAME_1",
        "[EMAIL_1]",
        "<PHONE_1>",
        "[PERSONA_1]",
        "\\u003cNAME_1>",
        other.as_str(),
    ];
    for text in untouched {
        assert_eq!(v.restore(text), text, "{text}");
        assert_eq!(v.restore(&format!("a {text} b")), format!("a {text} b"));
    }
    // a bare token needs word boundaries but accepts punctuation around it
    assert_eq!(v.restore("(NAME_1)."), "(Ayşe Kaya).");
    // mismatched delimiters are not consumed: only the bare token inside
    for (text, want) in [
        ("[NAME_1>", "[Ayşe Kaya>"),
        ("{NAME_1]", "{Ayşe Kaya]"),
        ("[   NAME_1]", "[   Ayşe Kaya]"),
        ("&lt;NAME_1>", "&lt;Ayşe Kaya>"),
    ] {
        assert_eq!(v.restore(text), want, "{text}");
    }
    // English clitic after a placeholder: not a Turkish suffix
    assert_eq!(v.restore("[NAME_1]'s file"), "Ayşe Kaya's file");
}

#[test]
fn placeholder_shaped_prompt_text_is_never_rewritten() {
    let cases = [
        (
            "Kullanıcı [NAME_1] yazdı; Ad Soyad: Ahmet Yılmaz.",
            "Ahmet Yılmaz",
            "NAME_2",
        ),
        (
            "Şablon: [TCKN_1] alanı. TC kimlik no: 10000000146",
            "10000000146",
            "TCKN_2",
        ),
        // altered and translated shapes reserve the number too
        (
            "Şablon <NAME_1>; Ad Soyad: Ahmet Yılmaz",
            "Ahmet Yılmaz",
            "NAME_2",
        ),
        (
            "şablon name_1; Ad Soyad: Ahmet Yılmaz",
            "Ahmet Yılmaz",
            "NAME_2",
        ),
        (
            "Şablon [İSİM_1]; Ad Soyad: Ahmet Yılmaz",
            "Ahmet Yılmaz",
            "NAME_2",
        ),
        (
            "Şablon \\[NAME\\_01\\]; Ad Soyad: Ahmet Yılmaz",
            "Ahmet Yılmaz",
            "NAME_2",
        ),
        (
            "Şablon [NAME_1] ve NAME_2; Ad Soyad: Ahmet Yılmaz",
            "Ahmet Yılmaz",
            "NAME_3",
        ),
    ];
    for (prompt, value, placeholder) in cases {
        let (anon, vault) = Vault::pseudonymize(prompt);
        assert_eq!(vault.placeholder_for(value), Some(placeholder), "{anon}");
        for opts in ALL_OPTS {
            assert_eq!(vault.restore_with(&anon, opts), prompt, "{opts:?}");
        }
        // an LLM echoing the prompt's own token leaves it alone
        let response = format!("{anon} / [NAME_1] [TCKN_1] <NAME_1>");
        let restored = vault.restore(&response);
        assert!(
            restored.ends_with(" / [NAME_1] [TCKN_1] <NAME_1>"),
            "{restored}"
        );
        every_split_equals_batch(&vault, &response);
    }
}

#[test]
fn prompt_renderings_restore_verbatim_and_suffix_typos_survive() {
    // the prompt's brackets around a value become `[[TCKN_1]]`: restored
    // as written, not collapsed
    let prompt = "Kimlik [12345678950] ve TCKN 12345678950'i";
    let (anon, vault) = Vault::pseudonymize(prompt);
    assert!(anon.contains("[[TCKN_1]]"), "{anon}");
    assert!(anon.contains("[TCKN_1]'i"), "{anon}");
    for opts in ALL_OPTS {
        assert_eq!(vault.restore_with(&anon, opts), prompt, "{opts:?}");
    }
    // the LLM echoing those renderings gets the prompt's spelling back,
    // other suffixes are still repaired
    assert_eq!(vault.restore("[[TCKN_1]]"), "[12345678950]");
    assert_eq!(vault.restore("[TCKN_1]'i"), "12345678950'i");
    assert_eq!(vault.restore("[TCKN_1]'in"), "12345678950'nin");
    assert_eq!(vault.restore("<TCKN_1>"), "12345678950");
    // a vault rebuilt from its entries has no exemptions
    let rebuilt = Vault::from_entries(vault.entries_iter().map(|(k, v)| (k.clone(), v.clone())));
    assert_ne!(rebuilt, vault);
    assert_eq!(rebuilt.restore("[TCKN_1]'i"), "12345678950'yi");
    assert_eq!(rebuilt.restore_with(&anon, RestoreOptions::STRICT), prompt);
}

#[test]
fn non_canonical_vaults_restore_strictly() {
    let v = Vault::from_entries([
        ("NAME_1".to_owned(), "Ayşe".to_owned()),
        ("custom key".to_owned(), "x".to_owned()),
    ]);
    assert_eq!(v.restore("<NAME_1> [NAME_1]'a"), "<NAME_1> Ayşe'a");
}

/// Every split point and char-wise chunking equal the batch restore, in
/// every mode.
fn every_split_equals_batch(vault: &Vault, text: &str) {
    for opts in ALL_OPTS {
        let full = vault.restore_with(text, opts);
        let mut cuts: Vec<Vec<usize>> = (0..=text.len())
            .filter(|&i| text.is_char_boundary(i))
            .map(|c| vec![c])
            .collect();
        cuts.push(text.char_indices().map(|(i, _)| i).skip(1).collect());
        for cut in cuts {
            assert_eq!(streamed(vault, text, &cut, opts), full, "{opts:?} {cut:?}");
        }
    }
}

fn streamed(vault: &Vault, text: &str, cuts: &[usize], opts: RestoreOptions) -> String {
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

#[test]
fn suite_responses_stream_like_batch() {
    for base in &BASES {
        let vault = vault_for(base);
        for (_, form) in forms(base.label, base.translated) {
            let Some(form) = form else { continue };
            every_split_equals_batch(&vault, &format!("Kayıt: {form}'e doğrulandı {form}"));
        }
    }
}

/// Fragments of prompts and LLM responses: PII the default detector finds,
/// placeholder renderings, suffixes, delimiters and Turkish letters.
fn fragment() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => Just(" ".to_owned()),
        1 => Just("Ad Soyad: Ayşe Kaya".to_owned()),
        1 => Just("TCKN 12345678950".to_owned()),
        1 => Just("TC kimlik no: 10000000146".to_owned()),
        1 => Just("mail ayse@ornek.com".to_owned()),
        1 => Just("tel 0532 234 56 78".to_owned()),
        2 => prop::sample::select(vec![
            "[NAME_1]", "[NAME_2]", "[TCKN_1]", "[TCKN_2]", "[EMAIL_1]", "[PHONE_1]",
            "<NAME_1>", "[[TCKN_1]]", "{EMAIL_1}", "\\[NAME\\_1\\]", "[name_1]", "[ TCKN_1 ]",
            "[NAME_01]", "[ISIM_1]", "[İSİM_1]", "&lt;TCKN_1&gt;", "\\u003cPHONE_1\\u003e",
            "NAME_1", "TCKN_1", "[NAME]", "[1]", "NAME_", "[NAME_1", "TCKN_1]",
        ]).prop_map(str::to_owned),
        2 => prop::sample::select(vec![
            "'e", "'in", "'de", "'yı", "’e", "'lerden", "'s", "'", "e", "[", "]", "[[", "]]",
            "<", ">", "{", "}", "\\", "&", "&lt;", "_", "1", "01", "ş", "İ", "Ü", "x", ".", ",",
        ]).prop_map(str::to_owned),
        // code and identifier contexts of the bare form
        2 => prop::sample::select(vec![
            "`", "``", "```", "````", "\n", "\n```\n", " = ", "=", ":", "(", ")", "obj.", "$",
            "\"", "-", "->", "::", "_MAX", " ", "\t",
        ]).prop_map(str::to_owned),
    ]
}

/// Bare-form probes, with whether the bare placeholder is filled.
/// Identifier and code contexts are not; prose is.
const BARE_PROBES: &[(&str, bool)] = &[
    // identifier and code contexts
    ("const PHONE_1 = 5;", false),
    ("PHONE_1_MAX", false),
    ("env PHONE_1=foo", false),
    ("export PHONE_1=\"x\"", false),
    ("if PHONE_1 == 2 {", false),
    ("`PHONE_1`", false),
    ("use `PHONE_1 + 1` here", false),
    ("``PHONE_1``", false),
    ("```\nPHONE_1\n```", false),
    ("```rust\nlet x = f(PHONE_1);\nprint(PHONE_1)\n```", false),
    ("  ```\n  call PHONE_1\n  ```", false),
    ("obj.PHONE_1", false),
    ("self.PHONE_1;", false),
    ("Foo::PHONE_1", false),
    ("a->PHONE_1", false),
    ("$PHONE_1", false),
    ("${PHONE_1}", true), // `{PHONE_1}` is the curly form, `$` stays
    ("--PHONE_1", false),
    ("/etc/PHONE_1", false),
    ("@PHONE_1", false),
    ("#PHONE_1", false),
    ("{\"PHONE_1\": 5}", false),
    ("'PHONE_1'", false),
    ("PHONE_1: 5", false),
    ("PHONE_1(x)", false),
    ("PHONE_1[0]", false),
    ("PHONE_1.len()", false),
    ("PHONE_1-MAX", false),
    ("PHONE_1->next", false),
    ("x_PHONE_1", false),
    // prose: a dropped bracket
    ("Kayıt: PHONE_1 doğrulandı.", true),
    ("Telefon PHONE_1.", true),
    ("(PHONE_1), PHONE_1; PHONE_1!", true),
    ("**PHONE_1** arandı", true),
    ("- PHONE_1\n- PHONE_1", true),
    ("> PHONE_1", true),
    ("PHONE_1'e ulaşıldı", true),
    ("\"PHONE_1 numarası\"", true),
    ("Numara = PHONE_1", true),
    ("```\ncode\n```\nPHONE_1 sonra", true),
    ("tek ` tik sonra\nPHONE_1", true),
];

#[test]
fn bare_tokens_are_filled_in_prose_only() {
    let (_, v) = Vault::pseudonymize("tel 0532 234 56 78");
    assert_eq!(v.original_for("PHONE_1"), Some("0532 234 56 78"));
    let (mut filled, mut left) = (0, 0);
    for &(text, fill) in BARE_PROBES {
        let got = v.restore(text);
        let did = got.contains("0532 234 56 78");
        assert_eq!(did, fill, "{text:?} -> {got:?}");
        if fill {
            // every bare token of a prose probe is filled
            assert!(!got.contains("PHONE_1"), "{text:?} -> {got:?}");
            filled += 1;
        } else {
            assert_eq!(got, text);
            left += 1;
        }
        // strict mode never fills a bare token
        assert_eq!(v.restore_with(text, RestoreOptions::STRICT), text);
        every_split_equals_batch(&v, text);
    }
    assert_eq!((filled, left), (12, 29));
    // bracketed forms keep working inside code
    for (text, want) in [
        ("`[PHONE_1]`", "`0532 234 56 78`"),
        ("```\nx = <PHONE_1>\n```", "```\nx = 0532 234 56 78\n```"),
        ("const P = [PHONE_1];", "const P = 0532 234 56 78;"),
    ] {
        assert_eq!(v.restore(text), want, "{text:?}");
    }
}

fn text() -> impl Strategy<Value = String> {
    proptest::collection::vec(fragment(), 0..14).prop_map(|p| p.concat())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(384))]

    /// `restore(pseudonymize(x)) == x` in every restore mode, also when
    /// the prompt holds placeholder renderings and suffixes.
    #[test]
    fn round_trip_is_byte_exact_in_every_mode(prompt in text()) {
        let (anon, vault) = Vault::pseudonymize(&prompt);
        for opts in ALL_OPTS {
            prop_assert_eq!(&vault.restore_with(&anon, opts), &prompt);
        }
    }

    /// Streaming a response at random cuts equals the batch restore in
    /// every mode.
    #[test]
    fn streaming_equals_batch_at_random_cuts(
        (prompt, response, cuts) in (text(), text()).prop_flat_map(|(p, r)| {
            let bounds: Vec<usize> = (0..=r.len()).filter(|&i| r.is_char_boundary(i)).collect();
            let max = bounds.len().min(8);
            (Just(p), Just(r), proptest::sample::subsequence(bounds, 0..=max))
        })
    ) {
        let (_, vault) = Vault::pseudonymize(&prompt);
        for opts in ALL_OPTS {
            prop_assert_eq!(
                streamed(&vault, &response, &cuts, opts),
                vault.restore_with(&response, opts)
            );
        }
    }
}

#[test]
fn stream_hold_back_stays_bounded() {
    let (_, vault) = Vault::pseudonymize("Ad Soyad: Ayşe Kaya");
    // worst cases for the hold-back: an endless label run, an open
    // delimiter with spaces, a placeholder followed by an endless suffix
    for (prefix, unit) in [
        ("", "A"),
        ("", "["),
        ("", r"<  NAME"),
        ("[NAME_1]'", "e"),
        ("NAME_1’", "ş"),
    ] {
        let mut r = vault.restorer();
        let mut fed = prefix.to_owned();
        let mut out = r.push(prefix);
        for _ in 0..400 {
            out.push_str(&r.push(unit));
            fed.push_str(unit);
            let dbg = format!("{r:?}");
            let pending: usize = dbg
                .split("pending_bytes: ")
                .nth(1)
                .and_then(|s| s.trim_end_matches([' ', '}']).parse().ok())
                .expect("pending in Debug");
            assert!(pending < 250, "{unit}: {pending}");
        }
        out.push_str(&r.finish());
        assert_eq!(out, vault.restore(&fed), "{unit}");
    }
}
