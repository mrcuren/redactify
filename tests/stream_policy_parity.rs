//! Streaming guard parity under policies: long raw spans, encoded PII,
//! cross-line and normalized-view credentials, relevance rules, the
//! longest AWS secret span and the ML classifier input.
//!
//! The central invariant: for every text and EVERY chunk split, the
//! concatenated stream segments equal the batch `sanitize` output whenever
//! the batch decision is not `Block` (and a batch `Block` streams a
//! `Block`).

use std::sync::{Arc, Mutex};

use redactify::guard::ml::{MlClassifier, MlRouter};
use redactify::guard::SignalKind;
use redactify::policy::{
    GuardCategory, GuardEvent, GuardTarget, MlStreamBudget, Policy, RelevanceRule, StreamingGuard,
    Threshold,
};
use redactify::{EntityType, Guard, GuardAction};

const TARGETS: [GuardTarget; 3] = [
    GuardTarget::UserPrompt,
    GuardTarget::ToolResponse,
    GuardTarget::ModelOutput,
];

/// Streams `chunks` and returns the concatenated segments (`None` when the
/// stream emitted a `Block`).
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

/// The split points (char boundaries) at which the stream output differs
/// from the batch output (two chunks per run), plus the per-char run.
fn bad_splits(target: GuardTarget, policy: &Policy, text: &str) -> Vec<usize> {
    let batch = Guard::new(target).with_policy(policy).sanitize(text);
    let expected = (batch.decision.action != GuardAction::Block).then_some(batch.text.as_str());
    let mut bad = Vec::new();
    for at in (0..=text.len()).filter(|&i| text.is_char_boundary(i)) {
        let got = stream_chunks(target, policy, &[&text[..at], &text[at..]]);
        if got.as_deref() != expected {
            bad.push(at);
        }
    }
    let per_char: Vec<&str> = text
        .char_indices()
        .map(|(i, c)| &text[i..i + c.len_utf8()])
        .collect();
    if stream_chunks(target, policy, &per_char).as_deref() != expected {
        bad.push(usize::MAX);
    }
    bad
}

fn assert_stream_equals_batch(policy: &Policy, text: &str) {
    for target in TARGETS {
        let bad = bad_splits(target, policy, text);
        assert!(
            bad.is_empty(),
            "{target:?}: stream != batch at {} split(s), first {:?}, text {text:?}",
            bad.len(),
            bad.first()
        );
    }
}

fn secrets_monitor_only() -> Policy {
    Policy::default().with_category(GuardCategory::Secrets, Threshold::None)
}

// ------------------------------------------------------ long raw spans

/// A whitespace-collapsed IPv6 address whose raw span is far longer than the
/// holdback (unbounded whitespace between the groups).
fn spaced_ipv6_line() -> String {
    let pad = "musteri kaydi icin aciklama satiri burada yer aliyor ve devam ediyor sonraki alana gecmeden ";
    let groups = [
        "2001", "4860", "4860", "0000", "0000", "0000", "0000", "8888",
    ];
    let sep = format!("{}:{}", " ".repeat(10), " ".repeat(10));
    format!("{pad}{pad}adres {} son", groups.join(&sep))
}

#[test]
fn spaced_ipv6_is_masked_at_every_split() {
    let text = spaced_ipv6_line();
    assert!(text.len() > 192 && !text.contains('\n'));
    let batch = Guard::new(GuardTarget::UserPrompt).sanitize(&text);
    assert!(batch.text.contains("[IP_ADDRESS]"), "{}", batch.text);
    assert_stream_equals_batch(&Policy::default(), &text);
}

#[test]
fn mrn_behind_a_long_gap_is_masked_at_every_split() {
    let text = format!(
        "hasta dosyasi guncellendi, aciklama metni burada devam ediyor, kayit mrn:{}12345678 son",
        " ".repeat(120)
    );
    assert!(text.len() > 192 && !text.contains('\n'));
    let batch = Guard::new(GuardTarget::UserPrompt).sanitize(&text);
    assert!(batch.text.contains("[US_MRN]"), "{}", batch.text);
    assert_stream_equals_batch(&Policy::default(), &text);
    // the gap may also be a run of colons and hashes
    let text = format!(
        "hasta dosyasi guncellendi, aciklama metni burada devam ediyor, kayit mrn{}12345678 son",
        ":#".repeat(80)
    );
    let batch = Guard::new(GuardTarget::UserPrompt).sanitize(&text);
    assert!(batch.text.contains("[US_MRN]"), "{}", batch.text);
    assert_stream_equals_batch(&Policy::default(), &text);
}

// ------------------------------------------------------- encoded PII

/// Standard base64 (RFC 4648 section 4) of `data`.
fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(char::from(T[(n >> 18) as usize & 63]));
        out.push(char::from(T[(n >> 12) as usize & 63]));
        out.push(if c.len() > 1 {
            char::from(T[(n >> 6) as usize & 63])
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            char::from(T[n as usize & 63])
        } else {
            '='
        });
    }
    out
}

#[test]
fn base64_copy_of_a_visible_value_still_raises_encoded_pii() {
    let policy = Policy::default().with_category(GuardCategory::EncodedPii, Threshold::Low);
    let blob = b64(b"kimlik 12345678950");
    for text in [
        format!("govde: {blob}"),
        format!("TCKN 12345678950 govde: {blob}"),
    ] {
        let d = Guard::new(GuardTarget::UserPrompt)
            .with_policy(&policy)
            .decide(&text);
        let encoded = d
            .signals
            .iter()
            .filter(|s| s.kind == SignalKind::EncodedPii)
            .count();
        assert_eq!(encoded, 1, "{text:?}: {:?}", d.signals);
        assert_eq!(d.action, GuardAction::Block, "{text:?}");
    }
}

#[test]
fn escape_views_keep_the_visible_value_skip() {
    // a percent / HTML escape view carries the WHOLE text: the plainly
    // visible TCKN is not concealed there, so it raises nothing
    let policy = Policy::default().with_category(GuardCategory::EncodedPii, Threshold::Low);
    for text in [
        "TCKN 12345678950 url %41%42 son",
        "TCKN 12345678950 &amp; &lt;b&gt; son",
    ] {
        let d = Guard::new(GuardTarget::UserPrompt)
            .with_policy(&policy)
            .decide(text);
        assert!(
            !d.signals.iter().any(|s| s.kind == SignalKind::EncodedPii),
            "{text:?}: {:?}",
            d.signals
        );
        assert_eq!(d.action, GuardAction::Mask, "{text:?}");
    }
    // while an identifier that is ONLY visible through the escape view does
    let text = "kimlik %31%32345678950 son";
    let d = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&policy)
        .decide(text);
    assert!(
        d.signals.iter().any(|s| s.kind == SignalKind::EncodedPii),
        "{:?}",
        d.signals
    );
}

// ---------------------------------------------- cross-line credentials

#[test]
fn cross_line_credentials_stream_like_batch() {
    let policy = secrets_monitor_only();
    for text in [
        "config dump\npassword:\nS3cr3tPass!2024\nend\n",
        "Authorization: Bearer\nabcdefghijklmnop1234567890XYZ\n",
        "config\npassword\n=\n\n   \nS3cr3tPass!2024 son\nend",
        "Authorization:\n  Bearer\n  abcdefghijklmnop1234567890XYZ\n",
        "aws_secret_access_key =\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nend\n",
        "TCKN 12345678950 aws secret\n\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\" ok\n",
    ] {
        let batch = Guard::new(GuardTarget::UserPrompt)
            .with_policy(&policy)
            .sanitize(text);
        assert_ne!(batch.decision.action, GuardAction::Block, "{text:?}");
        assert!(batch.text.contains("[SECRET:"), "{text:?}: {}", batch.text);
        assert_stream_equals_batch(&policy, text);
    }
}

#[test]
fn held_aws_head_without_a_key_is_released_unchanged() {
    // a line ending like the head of a cross-line AWS secret is held only
    // until the next line shows there is no key; nothing is lost
    let policy = secrets_monitor_only();
    for text in [
        "aws secret\nnot a key here\n",
        "aws secret",
        "aws secret\n",
        "aws secret\nTCKN 12345678950\naws sk\n",
    ] {
        assert_stream_equals_batch(&policy, text);
        assert_stream_equals_batch(&Policy::default(), text);
    }
}

#[test]
fn normalized_view_secrets_stream_like_batch() {
    // secrets visible only in the normalized view (zero-width split,
    // fullwidth or lookalike letters) are masked by batch sanitize; the
    // stream masks the same spans at every split, cross-line included
    let pad = "uzun bir aciklama satiri burada devam ediyor ve konu kapanmiyor ";
    let key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let texts = [
        "key AKIA\u{200B}IOSFODNN7EXAMPLE end".to_owned(),
        "key \u{FF21}KIAIOSFODNN7EXAMPLE end".to_owned(),
        format!("token ghp_\u{200B}{} end", "A1b2C3d4".repeat(4) + "E5f6"),
        format!("\u{FF41}ws secret\n{key}\nend\n"),
        format!("aws secr\u{200B}et\n{key}\nend\n"),
        format!("{pad}{pad}{pad}key AKIA\u{200B}IOSFODNN7EXAMPLE {pad}{pad}"),
    ];
    for text in &texts {
        for policy in [Policy::default(), secrets_monitor_only()] {
            let batch = Guard::new(GuardTarget::UserPrompt)
                .with_policy(&policy)
                .sanitize(text);
            if batch.decision.action != GuardAction::Block {
                assert!(batch.text.contains("[SECRET:"), "{text:?}: {}", batch.text);
            }
            assert_stream_equals_batch(&policy, text);
        }
    }
}

// --------------------------------------------------------- relevance

fn phone_email_rule() -> RelevanceRule {
    RelevanceRule {
        entity_types: vec![EntityType::Phone, EntityType::Email],
        cue_any: vec!["call me at".into()],
        cue_all: vec![],
        window: 40,
    }
}

#[test]
fn sanitize_applies_relevance_on_raw_coordinates() {
    let policy = Policy::default().with_relevance(phone_email_rule());
    let text = "call me at   token aB3dE5fG7hJ9kL1mN2pQ 0505 186 48 37";
    let r = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&policy)
        .sanitize(text);
    assert_eq!(r.decision.relevance_downgraded.len(), 1);
    assert_eq!(r.decision.relevance_downgraded[0].kind, EntityType::Phone);
    assert_eq!(
        r.text,
        "call me at   token [SECRET:HIGH_ENTROPY] 0505 186 48 37"
    );
    assert_stream_equals_batch(&policy, text);
}

// ------------------------------------------------ longest AWS secret

/// The longest AWS secret-key span the rule accepts: `aws`, a 30-char gap,
/// `secret`, a 20-char gap, `=`, a quote and the 40-char key (101 chars).
/// The gaps carry spaces, so no whitespace-free run hides the span.
fn longest_aws_secret(gap30: &str, gap20: &str) -> String {
    let pad = "uzun bir aciklama satiri burada devam ediyor ve konu kapanmiyor ";
    format!(
        "{pad}{pad}aws{gap30}secret{gap20}=\"{}\" done",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    )
}

#[test]
fn longest_aws_secret_span_streams_like_batch() {
    let policy = secrets_monitor_only();
    let gap30 = " ab".repeat(10);
    let gap20 = format!("{}xy", " cd".repeat(6));
    assert_eq!((gap30.chars().count(), gap20.chars().count()), (30, 20));
    let text = longest_aws_secret(&gap30, &gap20);
    assert!(text.len() > 192 && !text.contains('\n'));
    let batch = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&policy)
        .sanitize(&text);
    let tail = "[SECRET:AWS_SECRET_KEY]\" done";
    assert!(batch.text.ends_with(tail), "{}", batch.text);
    // the masked span is the whole 101-char match
    assert_eq!(
        text.len() - batch.text.len(),
        101 - "[SECRET:AWS_SECRET_KEY]".len()
    );
    assert_stream_equals_batch(&policy, &text);
}

#[test]
fn aws_secret_with_expanding_gap_chars_streams_like_batch() {
    // the gaps of the AWS secret rule accept any char: a compatibility
    // character that NFKC expands (U+FDFA, 18 chars) makes the normalized
    // form of the span far longer than its raw form
    let policy = secrets_monitor_only();
    let gap30 = "\u{FDFA} ".repeat(15);
    let gap20 = "\u{FDFA} ".repeat(10);
    let text = longest_aws_secret(&gap30, &gap20);
    let batch = Guard::new(GuardTarget::UserPrompt)
        .with_policy(&policy)
        .sanitize(&text);
    assert!(
        batch.text.contains("[SECRET:AWS_SECRET_KEY]"),
        "{}",
        batch.text
    );
    assert_stream_equals_batch(&policy, &text);
}

// ------------------------------------------------------ ML classifier input

/// Records every text it is asked to classify; never flags anything.
struct Recorder(Mutex<Vec<String>>);

impl MlClassifier for Recorder {
    fn classify(&self, text: &str) -> Vec<(GuardCategory, f32)> {
        self.0.lock().expect("recorder lock").push(text.to_owned());
        Vec::new()
    }
    fn name(&self) -> &'static str {
        "recorder"
    }
}

fn batch_ml_input(text: &str) -> Vec<String> {
    let rec = Recorder(Mutex::new(Vec::new()));
    let _ = Guard::new(GuardTarget::UserPrompt)
        .with_ml(MlRouter::default(), Some(&rec), None)
        .decide(text);
    let seen = rec.0.lock().expect("recorder lock").clone();
    seen
}

fn stream_ml_input(text: &str) -> Vec<String> {
    let rec = Arc::new(Recorder(Mutex::new(Vec::new())));
    let mut sg = StreamingGuard::new(GuardTarget::UserPrompt)
        .with_ml(rec.clone(), MlStreamBudget::default());
    let _ = sg.push(text);
    let _ = sg.finish();
    let seen = rec.0.lock().expect("recorder lock").clone();
    seen
}

#[test]
fn classifiers_never_see_raw_credentials() {
    let text = "deploy token aB3dE5fG7hJ9kL1mN2pQ ve TCKN 12345678950";
    for seen in [batch_ml_input(text), stream_ml_input(text)] {
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert!(!seen[0].contains("aB3dE5fG7hJ9kL1mN2pQ"), "{seen:?}");
        assert!(!seen[0].contains("12345678950"), "{seen:?}");
        assert_eq!(seen[0], "deploy token [SECRET:HIGH_ENTROPY] ve TCKN [TCKN]");
    }
}

#[test]
fn batch_and_stream_build_the_same_ml_input() {
    for text in [
        "deploy token aB3dE5fG7hJ9kL1mN2pQ ve TCKN 12345678950",
        "TCKN 12345678950 ile jailbreak analizi",
        "postgres://admin:S3cr3tPass@db.example.com/prod baglanti TCKN 12345678950",
        "token: 05321234567abcdefXYZ0123456789 ve mail a@b.com",
        "kimlik \u{FF11}2345678950 ve password=hunter2secure42! tamam",
        "just a normal sentence",
    ] {
        let batch = batch_ml_input(text);
        let stream = stream_ml_input(text);
        assert_eq!(batch, stream, "{text:?}");
    }
}
