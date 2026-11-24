//! PEM private-key blocks are masked whole (header, body, END line), in
//! batch and in the stream at every chunk split; assignment values that are
//! code reading a secret from elsewhere (`os.environ["X"]`,
//! `System.getenv("X")`, `process.env.X`) are not credentials, and no
//! credential mask ever leaves half a token in clear.

use redactify::guard::{find_secret_spans, mask_secrets, SignalKind};
use redactify::policy::{GuardCategory, GuardEvent, Policy, StreamingGuard, Threshold};
use redactify::{Guard, GuardAction, GuardTarget};

const TARGETS: [GuardTarget; 3] = [
    GuardTarget::UserPrompt,
    GuardTarget::ToolResponse,
    GuardTarget::ModelOutput,
];

/// Deterministic base64 line of `n` chars (seeded by `i`).
fn b64(i: usize, n: usize) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    (0..n).map(|k| A[(i * 7 + k * 13) % 64] as char).collect()
}

/// `lines` 64-char body lines, each ending in `nl`, the last one short.
fn body(lines: usize, nl: &str) -> String {
    let mut s: String = (0..lines).map(|i| b64(i, 64) + nl).collect();
    s.push_str(&b64(99, 22));
    s.push_str("==");
    s.push_str(nl);
    s
}

const MASK: &str = "[SECRET:PEM_PRIVATE_KEY]";

fn secrets_monitor_only() -> Policy {
    Policy::default().with_category(GuardCategory::Secrets, Threshold::None)
}

// ------------------------------------------------------------------ batch

#[test]
fn pem_block_is_masked_from_begin_through_end() {
    let text = format!(
        "before\n-----BEGIN RSA PRIVATE KEY-----\n{}-----END RSA PRIVATE KEY-----\nafter\n",
        body(4, "\n")
    );
    assert_eq!(mask_secrets(&text), format!("before\n{MASK}\nafter\n"));
    let spans = find_secret_spans(&text);
    assert_eq!(spans.len(), 1, "{spans:?}");
    assert!(spans[0].score >= 0.9);
    // CRLF line endings and every header variant
    for kind in ["", "RSA ", "EC ", "DSA ", "OPENSSH ", "ENCRYPTED "] {
        let text = format!(
            "-----BEGIN {kind}PRIVATE KEY-----\r\n{}-----END {kind}PRIVATE KEY-----\r\nok",
            body(3, "\r\n")
        );
        assert_eq!(mask_secrets(&text), format!("{MASK}\r\nok"), "{kind:?}");
    }
}

#[test]
fn encrypted_pem_headers_are_inside_the_block() {
    let text = format!(
        "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\
         DEK-Info: AES-128-CBC,3F17F5316E2BAC89BC0B2C4A3D8B5E8A\n\n{}\
         -----END RSA PRIVATE KEY-----\nafter",
        body(3, "\n")
    );
    assert_eq!(mask_secrets(&text), format!("{MASK}\nafter"));
}

#[test]
fn truncated_pem_masks_header_and_base64_lines_only() {
    // no END line: the header and every base64 line after it are masked,
    // the prose line that follows is not (and its line break stays)
    let text = format!(
        "key:\n-----BEGIN PRIVATE KEY-----\n{}what is wrong with it?\n",
        body(4, "\n")
    );
    assert_eq!(
        mask_secrets(&text),
        format!("key:\n{MASK}\nwhat is wrong with it?\n")
    );
    // blank lines after a truncated body are not swallowed
    let text = format!("-----BEGIN PRIVATE KEY-----\n{}\n\n\nnext", body(2, "\n"));
    assert_eq!(mask_secrets(&text), format!("{MASK}\n\n\n\nnext"));
    // a bare header in prose masks the header only
    let text =
        "a key file starts with -----BEGIN RSA PRIVATE KEY----- and then base64 lines follow.";
    assert_eq!(
        mask_secrets(text),
        format!("a key file starts with {MASK} and then base64 lines follow.")
    );
}

#[test]
fn json_escaped_and_collapsed_pem_are_masked_whole() {
    let json = format!(
        "{{\"private_key\": \"-----BEGIN PRIVATE KEY-----\\n{}\\n{}\\n-----END PRIVATE KEY-----\\n\", \"x\": 1}}",
        b64(1, 64),
        b64(2, 20)
    );
    assert_eq!(
        mask_secrets(&json),
        format!("{{\"private_key\": \"{MASK}\\n\", \"x\": 1}}")
    );
    // truncated inside the string: masked up to the closing quote
    let json = format!(
        "{{\"k\": \"-----BEGIN PRIVATE KEY-----\\n{}\\n{}\"}}",
        b64(1, 64),
        b64(2, 20)
    );
    assert_eq!(mask_secrets(&json), format!("{{\"k\": \"{MASK}\"}}"));
    // line breaks collapsed to spaces (an unquoted shell echo)
    let collapsed = format!(
        "KEY=-----BEGIN OPENSSH PRIVATE KEY----- {} {} AB== -----END OPENSSH PRIVATE KEY----- done",
        b64(3, 70),
        b64(4, 70)
    );
    assert_eq!(mask_secrets(&collapsed), format!("KEY={MASK} done"));
    // no separator at all
    let glued = format!(
        "-----BEGIN PRIVATE KEY-----{}-----END PRIVATE KEY-----.",
        b64(5, 300)
    );
    assert_eq!(mask_secrets(&glued), format!("{MASK}."));
}

#[test]
fn pem_block_scan_is_bounded() {
    // a header followed by 1 MiB of base64 lines and no END: the block
    // stops at the 16 KiB bound, on a token boundary
    let text = format!("-----BEGIN RSA PRIVATE KEY-----\n{}", body(16_384, "\n"));
    let spans = find_secret_spans(&text);
    assert_eq!(spans[0].start, 0);
    let end = spans[0].end;
    assert!(end <= 16 * 1024, "{end}");
    assert!(end > 16 * 1024 - 66, "{end}");
    assert_eq!(&text[end..end + 1], "\n");
    // a 1 MiB single token after the header is not key material: header only
    let text = format!("-----BEGIN PRIVATE KEY-----\n{}", b64(0, 1 << 20));
    let spans = find_secret_spans(&text);
    assert_eq!((spans[0].start, spans[0].end), (0, 27));
}

// ----------------------------------------------------------------- stream

fn stream_chunks(target: GuardTarget, policy: &Policy, chunks: &[&str]) -> Option<String> {
    let mut sg = StreamingGuard::new(target).with_policy(policy.clone());
    let mut events = Vec::new();
    for chunk in chunks {
        events.extend(sg.push(chunk));
    }
    events.extend(sg.finish());
    let mut out = String::new();
    for ev in events {
        match ev {
            GuardEvent::Segment { text, .. } => out.push_str(&text),
            _ => return None,
        }
    }
    Some(out)
}

/// Two-chunk splits at every `step`-th char boundary, the per-char run
/// (when `per_char`) and 7-byte chunks: the stream output equals the batch
/// output (both `None` on a batch Block).
fn assert_stream_equals_batch(policy: &Policy, text: &str, step: usize, per_char: bool) {
    for target in TARGETS {
        let batch = Guard::new(target).with_policy(policy).sanitize(text);
        let expected = (batch.decision.action != GuardAction::Block).then_some(batch.text.as_str());
        let splits = (0..=text.len()).filter(|&i| text.is_char_boundary(i));
        for at in splits.step_by(step) {
            let got = stream_chunks(target, policy, &[&text[..at], &text[at..]]);
            assert_eq!(
                got.as_deref(),
                expected,
                "{target:?} split {at} of {text:?}"
            );
        }
        if per_char {
            let chars: Vec<&str> = text
                .char_indices()
                .map(|(i, c)| &text[i..i + c.len_utf8()])
                .collect();
            assert_eq!(
                stream_chunks(target, policy, &chars).as_deref(),
                expected,
                "{target:?} per-char of {text:?}"
            );
        }
        let mut sevens = Vec::new();
        let mut at = 0;
        while at < text.len() {
            let mut end = (at + 7).min(text.len());
            while !text.is_char_boundary(end) {
                end += 1;
            }
            sevens.push(&text[at..end]);
            at = end;
        }
        assert_eq!(
            stream_chunks(target, policy, &sevens).as_deref(),
            expected,
            "{target:?} 7-byte chunks of {text:?}"
        );
    }
}

#[test]
fn pem_block_streams_like_batch() {
    let pad = "uzun bir aciklama satiri burada devam ediyor ve konu kapanmiyor ";
    let texts = [
        // with END, text after it
        format!(
            "ilk satir TCKN 12345678950\n-----BEGIN RSA PRIVATE KEY-----\n{}-----END RSA PRIVATE KEY-----\nson satir a@b.com\n",
            body(3, "\n")
        ),
        // without END: closed by a prose line
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}what is wrong with it?\nTCKN 12345678950\n",
            body(3, "\n")
        ),
        // without END: the stream ends inside the block
        format!("anahtar:\n-----BEGIN PRIVATE KEY-----\n{}", body(2, "\n")),
        // without END, closed by three blank lines
        format!("-----BEGIN PRIVATE KEY-----\n{}\n\n\nTCKN 12345678950", body(1, "\n")),
        // encrypted PEM, CRLF
        format!(
            "-----BEGIN RSA PRIVATE KEY-----\r\nProc-Type: 4,ENCRYPTED\r\n\
             DEK-Info: AES-128-CBC,3F17F5316E2BAC89BC0B2C4A3D8B5E8A\r\n\r\n{}\
             -----END RSA PRIVATE KEY-----\r\nok\r\n",
            body(2, "\r\n")
        ),
        // newline-free lines longer than the intra-line threshold: a JSON
        // string with escaped line breaks, and a body collapsed to spaces
        format!(
            "{pad}{pad}{{\"private_key\": \"-----BEGIN PRIVATE KEY-----\\n{}\\n{}\\n-----END PRIVATE KEY-----\\n\"}} {pad}",
            b64(1, 64),
            b64(2, 20)
        ),
        format!(
            "{pad}{pad}KEY=-----BEGIN OPENSSH PRIVATE KEY----- {} {} AB== -----END OPENSSH PRIVATE KEY----- {pad}",
            b64(3, 70),
            b64(4, 70)
        ),
        format!(
            "{pad}{pad}-----BEGIN PRIVATE KEY----- {} {} short words follow here {pad}",
            b64(3, 70),
            b64(4, 70)
        ),
        // two blocks, the second truncated
        format!(
            "-----BEGIN EC PRIVATE KEY-----\n{}-----END EC PRIVATE KEY-----\n-----BEGIN PRIVATE KEY-----\n{}",
            body(1, "\n"),
            body(1, "\n")
        ),
    ];
    let monitor = secrets_monitor_only();
    for text in &texts {
        let batch = Guard::new(GuardTarget::UserPrompt)
            .with_policy(&monitor)
            .sanitize(text);
        assert_ne!(batch.decision.action, GuardAction::Block, "{text:?}");
        assert!(batch.text.contains(MASK), "{text:?}: {}", batch.text);
        // no body line survives the mask
        assert!(!batch.text.contains(&b64(1, 64)[..32]), "{}", batch.text);
        // every 3rd two-chunk split (3 is coprime with the 64-char body
        // lines and the 7-byte chunks, so the splits walk every column);
        // the per-char run ends a chunk at EVERY boundary
        assert_stream_equals_batch(&monitor, text, 3, true);
        // the default policy blocks a private key, in batch and stream
        assert_stream_equals_batch(&Policy::default(), text, 11, false);
    }
}

// ------------------------------------------------------- code expressions

#[test]
fn code_reading_a_secret_is_not_a_credential() {
    for text in [
        "password = os.environ[\"DB_PASSWORD\"]",
        "password = os.getenv(\"DB_PASSWORD\")",
        "db_password = os.environ.get('DB_PASSWORD', '')",
        "const apiKey = process.env.STRIPE_API",
        "api_key = ENV[\"STRIPE_API\"]",
        "api_key = ENV.fetch(\"STRIPE_API\")",
        "String password = System.getenv(\"DB_PASSWORD\");",
        "client_secret = config.get(\"oauth.client\")",
        "password = load_db_credential()",
        "var apiKey = Environment.GetEnvironmentVariable(\"API_KEY\");",
        "\"password\": vault.read(path)[\"data\"],",
        "secret_key = settings.DJANGO_SIGNING",
    ] {
        let spans = find_secret_spans(text);
        assert!(spans.is_empty(), "{text:?}: {spans:?}");
        assert_eq!(mask_secrets(text), text);
        let d = Guard::new(GuardTarget::UserPrompt).decide(text);
        assert!(
            d.signals.iter().all(|s| s.kind != SignalKind::Secrets),
            "{text:?}: {:?}",
            d.signals
        );
    }
}

#[test]
fn real_credentials_are_still_masked_whole() {
    for (text, masked) in [
        (
            "DB_PASSWORD=Sup3rS3cret!x",
            "DB_PASSWORD=[SECRET:CREDENTIAL_ASSIGNMENT]",
        ),
        (
            "password = \"Sup3rS3cret!x\"",
            "password = \"[SECRET:CREDENTIAL_ASSIGNMENT]\"",
        ),
        (
            "password: hunter2hunter2!",
            "password: [SECRET:CREDENTIAL_ASSIGNMENT]",
        ),
        // an unquoted password that only looks like a call is a value
        (
            "password = Pa55(word)xyz!",
            "password = [SECRET:CREDENTIAL_ASSIGNMENT]",
        ),
        // ...and so is one ending in a call-like group whose arguments are
        // no quoted string (or, after a bare callee, an identifier)
        (
            "password=Summer2024(!)",
            "password=[SECRET:CREDENTIAL_ASSIGNMENT]",
        ),
        (
            "password=Tr0ub4dor(2024)",
            "password=[SECRET:CREDENTIAL_ASSIGNMENT]",
        ),
        (
            "password=Hunter2(x)",
            "password=[SECRET:CREDENTIAL_ASSIGNMENT]",
        ),
        // a quoted value is a literal, whatever it looks like
        (
            "password = \"os.getenv(1)x!\"",
            "password = \"[SECRET:CREDENTIAL_ASSIGNMENT]\"",
        ),
        // a quote inside the token: the whole token is masked
        (
            "password=abc12345\"def\"ghi rest",
            "password=[SECRET:CREDENTIAL_ASSIGNMENT] rest",
        ),
        // a quote closing the value keeps the punctuation after it
        (
            "<x data-password=Sup3rS3cret1\">",
            "<x data-password=[SECRET:CREDENTIAL_ASSIGNMENT]\">",
        ),
    ] {
        assert_eq!(mask_secrets(text), masked, "{text:?}");
    }
}

#[test]
fn no_credential_mask_leaves_half_a_token() {
    // after every placeholder, the text continues with whitespace, the end,
    // or punctuation that is not followed by a word character
    for text in [
        "password = os.environ[\"DB_PASSWORD\"] and token = x",
        "password=abc12345\"def\"ghi",
        "password = Pa55(word)xyz! ok",
        "password = config_lookup[\"a\"]b end",
    ] {
        let masked = mask_secrets(text);
        for (i, _) in masked.match_indices("]") {
            let rest = &masked[i + 1..];
            if !masked[..i].ends_with("CREDENTIAL_ASSIGNMENT") {
                continue;
            }
            let mut it = rest.chars();
            let next = it.next();
            let after = it.next();
            let half = match next {
                Some(c) if c.is_alphanumeric() || c == '_' => true,
                Some('"' | '\'') => after.is_some_and(|c| c.is_alphanumeric() || c == '_'),
                _ => false,
            };
            assert!(!half, "{text:?} -> {masked:?}");
        }
    }
}
