//! Tier-1 language gate: std-only Unicode script classification.
//!
//! Maps text to candidate language codes by Unicode script analysis -
//! no dependencies, ~100 lines, compiles in the zero-dependency core.
//! Tier-0 is the caller-supplied locale hint (`Detector::with_locales`);
//! Tier-1 (this module) narrows by script when no hint is available;
//! Tier-2 (whatlang trigram, behind `ml-onnx`) disambiguates Latin-script
//! languages; the multilingual fallback model catches everything else.
//!
//! # Examples
//! ```
//! use redactify::script_candidates;
//!
//! // CJK scripts are deterministic
//! assert!(script_candidates("こんにちは世界").contains(&"ja"));
//! assert!(script_candidates("你好世界").contains(&"zh"));
//! assert!(script_candidates("안녕하세요").contains(&"ko"));
//! // Cyrillic
//! assert!(script_candidates("Привет мир").contains(&"ru"));
//! // Latin-script: multiple candidates (tr/en/de/fr/es/...)
//! assert!(script_candidates("merhaba dunya").contains(&"tr"));
//! ```

/// Candidate language codes for a text, derived from Unicode script analysis.
/// Returns an empty set when the script is not mapped (Greek, Hebrew, etc. -
/// route those to the multilingual fallback).
#[must_use]
pub fn script_candidates(text: &str) -> Vec<&'static str> {
    let mut has_latin = false;
    let mut has_cyrillic = false;
    let mut has_hangul = false;
    let mut has_hiragana = false;
    let mut has_katakana = false;
    let mut has_han = false;
    let mut has_arabic = false;

    for ch in text.chars() {
        let cp = ch as u32;
        // Latin letters only: the 0xC0..=0x24F supplement range excludes
        // the MULTIPLICATION SIGN and DIVISION SIGN symbols (U+00D7/U+00F7),
        // which are not letters
        if matches!(cp, 0x41..=0x5A | 0x61..=0x7A)
            || (0xC0..=0x24F).contains(&cp) && cp != 0xD7 && cp != 0xF7
        {
            has_latin = true;
        } else if (0x400..=0x4FF).contains(&cp) {
            has_cyrillic = true;
        } else if (0xAC00..=0xD7AF).contains(&cp) || (0x1100..=0x11FF).contains(&cp) {
            has_hangul = true;
        } else if (0x3040..=0x309F).contains(&cp) {
            has_hiragana = true;
        } else if (0x30A0..=0x30FF).contains(&cp) {
            has_katakana = true;
        } else if (0x4E00..=0x9FFF).contains(&cp) || (0x3400..=0x4DBF).contains(&cp) {
            has_han = true;
        } else if (0x600..=0x6FF).contains(&cp) || (0x750..=0x77F).contains(&cp) {
            has_arabic = true;
        }
    }

    let mut out = Vec::new();

    // Japanese: kana present (hiragana or katakana) is decisive
    if has_hiragana || has_katakana {
        out.push("ja");
    }

    // Korean: Hangul is unique
    if has_hangul {
        out.push("ko");
    }

    // Chinese: Han without kana
    if has_han && !has_hiragana && !has_katakana {
        out.push("zh");
    }

    // Russian / Cyrillic
    if has_cyrillic {
        out.push("ru");
    }

    // Arabic
    if has_arabic {
        out.push("ar");
    }

    // Latin script: multiple candidates. Turkish carries distinctive
    // letters (ğ/Ğ/ş/Ş/ı/İ): 92% of the TR NER test set has at least one,
    // 0% of the EN PII-Bench set does. With them, "tr" leads so the
    // TR-specialized slot serves Turkish; without them "en" leads so the
    // multilingual slot serves plain Latin (routing English to the TR-only
    // model costs recall: ensemble 223/261 where the components support
    // 234-236).
    if has_latin && out.is_empty() {
        let turkish_letters = text
            .chars()
            .any(|c| matches!(c, 'ğ' | 'Ğ' | 'ş' | 'Ş' | 'ı' | 'İ'));
        if turkish_letters {
            out.extend_from_slice(&["tr", "en", "de", "fr", "es", "it", "pt", "nl"]);
        } else {
            out.extend_from_slice(&["en", "tr", "de", "fr", "es", "it", "pt", "nl"]);
        }
    }

    out
}

/// Whether the text is predominantly a non-Latin script (routing hint:
/// these route deterministically; Latin needs trigram detection).
///
/// # Examples
/// ```
/// use redactify::is_non_latin;
///
/// assert!(is_non_latin("こんにちは世界"));
/// assert!(is_non_latin("Привет мир"));
/// assert!(!is_non_latin("merhaba dünya"));
/// assert!(!is_non_latin("hello world"));
/// ```
#[must_use]
pub fn is_non_latin(text: &str) -> bool {
    // require at least TWO script-candidate letters before deciding, so
    // one stray CJK char in Latin prose does not flip the router
    let letters: usize = text.chars().filter(|c| c.is_alphabetic()).count();
    if letters < 2 {
        return false;
    }
    let candidates = script_candidates(text);
    candidates.len() == 1
        && !matches!(
            candidates[0],
            "tr" | "en" | "de" | "fr" | "es" | "it" | "pt" | "nl"
        )
}

#[cfg(test)]
mod tests {
    use super::{is_non_latin, script_candidates};

    #[test]
    fn cjk_scripts_deterministic() {
        assert_eq!(script_candidates("こんにちは世界"), vec!["ja"]);
        assert_eq!(script_candidates("カタカナ"), vec!["ja"]);
        assert_eq!(script_candidates("안녕하세요"), vec!["ko"]);
        // Han without kana → Chinese
        assert_eq!(script_candidates("你好世界"), vec!["zh"]);
        // Han WITH kana → Japanese (kana wins)
        let ja_mixed = script_candidates("これはtestです");
        assert!(ja_mixed.contains(&"ja"));
        assert!(!ja_mixed.contains(&"zh"));
    }

    #[test]
    fn cyrillic_and_arabic() {
        assert_eq!(script_candidates("Привет мир"), vec!["ru"]);
        assert_eq!(script_candidates("مرحبا بالعالم"), vec!["ar"]);
    }

    #[test]
    fn latin_returns_multiple_candidates() {
        let cands = script_candidates("merhaba dunya bugun");
        assert!(cands.contains(&"tr"));
        assert!(cands.contains(&"en"));
        assert!(cands.len() > 1, "Latin must have multiple candidates");
    }

    #[test]
    fn latin_order_uses_turkish_letters() {
        // 92% of the TR NER test set carries ğ/ş/ı/İ,
        // 0% of the EN benchmark set does. The FIRST candidate decides the
        // router's slot: plain Latin must lead with "en" (multilingual
        // slot), Turkish-marked Latin must lead with "tr" (savasy slot).
        let plain = script_candidates("The quick brown fox jumps");
        assert_eq!(plain.first(), Some(&"en"), "{plain:?}");
        let turkish = script_candidates("merhaba dünya yağmur yağıyor");
        assert_eq!(turkish.first(), Some(&"tr"), "{turkish:?}");
        // dotless ı and İ alone also decide Turkish
        assert_eq!(script_candidates("ışık ve İrene").first(), Some(&"tr"));
    }

    #[test]
    fn latin_with_turkish_diacritics_still_latin() {
        let cands = script_candidates("ğüşöçı İstanbul");
        assert!(cands.contains(&"tr"));
    }

    #[test]
    fn mixed_script_returns_all() {
        // Japanese text with some Latin
        let cands = script_candidates("Hello こんにちは");
        assert!(cands.contains(&"ja"));
    }

    #[test]
    fn empty_text_returns_empty() {
        assert!(script_candidates("").is_empty());
    }

    #[test]
    fn non_latin_detection() {
        assert!(is_non_latin("こんにちは"));
        assert!(is_non_latin("Привет"));
        assert!(is_non_latin("مرحبا"));
        assert!(!is_non_latin("merhaba"));
        assert!(!is_non_latin("hello world"));
    }

    #[test]
    fn greek_hebrew_unmapped() {
        // Greek and Hebrew are not in our language set → empty → fallback
        assert!(script_candidates("Γεια σου κόσμε").is_empty());
        assert!(script_candidates("שלום עולם").is_empty());
    }
}
