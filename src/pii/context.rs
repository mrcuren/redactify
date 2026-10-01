//! Context-cue mechanism shared by every locale rule.
//!
//! Rules declare cue lists (`ContextPolicy::RequiredCue` / `Boost`); this
//! module answers the single question: "is any cue present within N characters
//! of this match?" Windows are **character** based (not bytes); `char_indices`
//! walks correctly across multi-byte Turkish letters.

/// Is any cue from `cues` present within `window` characters of the match?
/// Lowercasing plus an `ı->i` normalization, then substring search - this is how
/// the Turkish dotted/dotless-i problem is avoided.
pub(crate) fn has_cue(text: &str, start: usize, end: usize, cues: &[&str], window: usize) -> bool {
    let (left, right) = char_window(text, start, end, window);
    let mut ctx = String::with_capacity(start - left + right - end);
    ctx.push_str(&text[left..start]);
    ctx.push_str(&text[end..right]);
    let norm = normalize_tr(&ctx);
    cues.iter().any(|c| norm.contains(c))
}

/// Byte-offset pair for `window` characters back and `window` characters forward.
/// The returned offsets sit on character boundaries (slicing is panic-free).
fn char_window(text: &str, start: usize, end: usize, window: usize) -> (usize, usize) {
    let left = {
        let mut b = start;
        for (i, _) in text[..start].char_indices().rev().take(window) {
            b = i;
        }
        b
    };
    let right = {
        let mut b = end;
        for (i, c) in text[end..].char_indices().take(window) {
            b = end + i + c.len_utf8();
        }
        b
    };
    (left, right)
}

/// Lowercase plus `ı`->`i` (normalize the dot problem to the ASCII side).
fn normalize_tr(s: &str) -> String {
    s.to_lowercase().replace('ı', "i")
}

#[cfg(test)]
mod tests {
    use super::has_cue;

    const CUES: &[&str] = &["vergi", "tax"];

    fn pos(text: &str, needle: &str) -> (usize, usize) {
        let s = text.find(needle).expect("needle present");
        (s, s + needle.len())
    }

    #[test]
    fn cue_present_and_absent() {
        let with = "Firmanın vergi numarası 1234567890.";
        let (s, e) = pos(with, "1234567890");
        assert!(has_cue(with, s, e, CUES, 18));

        let without = "Sipariş 1234567890 hazır.";
        let (s, e) = pos(without, "1234567890");
        assert!(!has_cue(without, s, e, CUES, 18));
    }

    #[test]
    fn cue_beyond_window_is_ignored() {
        let t = "vergi çok uzakta........................ 1234567890.";
        let (s, e) = pos(t, "1234567890");
        assert!(!has_cue(t, s, e, CUES, 18));
    }

    #[test]
    fn multibyte_turkish_counts_characters_not_bytes() {
        // 'ı' is 2 bytes. "vergi no ıııııııı " is 18 CHARACTERS but 26 BYTES.
        // The window opens CHARACTER based -> "vergi" stays inside it. A byte-based
        // walk would only see "o ıııııııı" and the cue would escape - this test
        // locks in character-based semantics.
        let t = "vergi no ıııııııı 1234567890";
        let s = t.find("1234567890").expect("vkn present");
        assert!(has_cue(t, s, s + 10, CUES, 18));
    }

    #[test]
    fn cue_matches_uppercase_despite_turkish_i() {
        // "VERGİ NUMARASI" - Unicode lowercasing maps 'I'->'i'; it must match the
        // cue "vergi" (i-normalized).
        let t = "VERGİ NUMARASI: 1234567890";
        let (s, e) = pos(t, "1234567890");
        assert!(has_cue(t, s, e, CUES, 18));
    }
}
