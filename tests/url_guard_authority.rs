//! URL guard authority parsing and evidence.
//!
//! - A backslash ends the authority of a special-scheme URL (WHATWG URL
//!   Standard, section 4.4 "URL parsing", authority / host / port / path
//!   states), and a special scheme followed by any run of `/` and `\`
//!   (special authority slashes / special authority ignore slashes states)
//!   is scanned like `scheme://`; `http:` and `https:` are also scanned
//!   with no slash at all.
//! - Evidence names the scheme and host only: it never echoes a userinfo
//!   or a backslash path, and `file:` evidence carries no host or path.

use redactify::guard::url_guard;
use redactify::policy::{guard_all, GuardAction};

// ---------------------------------------------------------------- evidence

#[test]
fn file_url_evidence_echoes_no_host_or_path() {
    for (text, url) in [
        (
            r"open file://C:\Users\alice.yilmaz\maas-2026.xlsx now",
            r"file://C:\Users\alice.yilmaz\maas-2026.xlsx",
        ),
        (
            r"see file://fileserver\hr\alice.yilmaz\salary.xlsx",
            r"file://fileserver\hr\alice.yilmaz\salary.xlsx",
        ),
        (
            "see file://fileserver/hr/alice.yilmaz/salary.xlsx",
            "file://fileserver/hr/alice.yilmaz/salary.xlsx",
        ),
    ] {
        let sigs = url_guard(text);
        assert_eq!(sigs.len(), 1, "{text}: {sigs:?}");
        let ev = &sigs[0].evidence;
        assert_eq!(
            ev,
            &format!("file:// (len {})", url.chars().count()),
            "{text}"
        );
        for secret in ["Users", "alice", "yilmaz", "maas", "salary", "fileserver"] {
            assert!(!ev.contains(secret), "{text}: {ev}");
        }
    }
}

#[test]
fn backslash_path_is_never_echoed_in_url_evidence() {
    let url = r"http://169.254.169.254\latest\meta-data\iam?token=abc#frag";
    let sigs = url_guard(&format!("fetch {url} now"));
    assert_eq!(sigs.len(), 1, "{sigs:?}");
    assert_eq!(
        sigs[0].evidence,
        format!("http://169.254.169.254 (len {})", url.chars().count())
    );
    // userinfo before a backslash path is stripped too
    let url = r"http://admin:hunter2@10.0.0.5:8080\private\report.pdf";
    let sigs = url_guard(url);
    assert_eq!(sigs.len(), 1, "{sigs:?}");
    assert_eq!(
        sigs[0].evidence,
        format!("http://10.0.0.5:8080 (len {})", url.chars().count())
    );
    for secret in ["admin", "hunter2", "private", "report"] {
        assert!(!sigs[0].evidence.contains(secret), "{}", sigs[0].evidence);
    }
}

#[test]
fn slash_run_evidence_names_scheme_and_host_only() {
    let url = r"http:\\admin:hunter2@10.0.0.5:8080\private\report.pdf";
    let s = url_guard(url);
    assert_eq!(s.len(), 1, "{s:?}");
    assert_eq!(
        s[0].evidence,
        format!("http://10.0.0.5:8080 (len {})", url.chars().count())
    );
    let url = r"file:\\fileserver\hr\salary.xlsx";
    let s = url_guard(url);
    assert_eq!(s.len(), 1, "{s:?}");
    assert_eq!(
        s[0].evidence,
        format!("file:// (len {})", url.chars().count())
    );
}

// ------------------------------------------------------ backslash authority

#[test]
fn backslash_ends_the_authority_of_a_special_url() {
    for u in [
        r"http://169.254.169.254\latest\meta-data",
        r"https://169.254.169.254\latest",
        r"http://metadata.google.internal\computeMetadata\v1",
        r"http://10.0.0.5\admin",
        r"http://192.168.1.10:8080\x",
        r"https://localhost\dev",
        r"http://user@169.254.169.254\latest",
        r"http://127.1\x",
        r"http://[::1]\panel",
        r"ftp://192.168.1.10\pub",
    ] {
        let s = url_guard(u);
        assert!(!s.is_empty() && s[0].score >= 0.9, "{u}: {s:?}");
    }
    // the guard decision blocks the metadata endpoint written with `\`
    let d = guard_all(r"fetch http://169.254.169.254\latest\meta-data now");
    assert_eq!(d.action, GuardAction::Block, "{}", d.rationale);
    // public targets written with `\` stay clean
    for u in [r"https://example.com\path\to\file", r"http://8.8.8.8\dns"] {
        assert!(url_guard(u).is_empty(), "{u}");
    }
}

#[test]
fn backslash_before_userinfo_flags_either_reading() {
    // WHATWG reads `evil.example` as the host here (the `\` ends the
    // authority); a parser that does not treat `\` as a delimiter reads
    // `169.254.169.254`. The guard flags the URL when EITHER reading
    // reaches an internal target and, the host being ambiguous, echoes
    // neither candidate.
    let url = r"http://evil.example\@169.254.169.254/latest";
    let s = url_guard(url);
    assert!(!s.is_empty() && s[0].score >= 0.9, "{s:?}");
    assert_eq!(
        s[0].evidence,
        format!("http:// (len {})", url.chars().count())
    );
}

// --------------------------------------------------------------- slash runs

#[test]
fn backslash_scheme_prefixes_reach_the_authority() {
    for u in [
        r"http:\\10.0.0.5",
        r"http:/\10.0.0.5",
        r"http:\/10.0.0.5\admin",
        r"https:\\169.254.169.254\latest\meta-data",
        r"http:\\\localhost:8080",
        r"ftp:\\192.168.1.10\pub",
        "http:/10.0.0.5/admin",
        "http:///10.0.0.5/admin",
        r"http:\\user@169.254.169.254\latest",
    ] {
        let s = url_guard(u);
        assert!(!s.is_empty() && s[0].score >= 0.9, "{u}: {s:?}");
    }
    let d = guard_all(r"fetch http:\\169.254.169.254\latest\meta-data now");
    assert_eq!(d.action, GuardAction::Block, "{}", d.rationale);
    // public targets stay clean in every prefix form
    for u in [
        r"http:\\example.com\x",
        r"https:/\8.8.8.8\dns",
        "http:///example.com/",
    ] {
        assert!(url_guard(u).is_empty(), "{u}");
    }
}

// ---------------------------------------------------------- slashless http

#[test]
fn slashless_http_authority_is_scanned() {
    for u in [
        "http:10.0.0.5",
        "https:169.254.169.254/latest/meta-data",
        "HTTP:localhost:8080",
        "fetch http:user@10.0.0.5 now",
    ] {
        let s = url_guard(u);
        assert!(!s.is_empty() && s[0].score >= 0.9, "{u}: {s:?}");
    }
    assert_eq!(
        url_guard("http:10.0.0.5")[0].evidence,
        "http://10.0.0.5 (len 13)"
    );
    // ftp and file need a slash run; a public slashless host stays clean
    for t in [
        "ftp:10.0.0.5",
        "file:12",
        "file:etc",
        "https:example.com",
        "http: 10.0.0.5",
    ] {
        assert!(url_guard(t).is_empty(), "{t}");
    }
}

#[test]
fn slashless_port_like_authority_is_not_flagged() {
    // a bare decimal 1..=65535 right after `http:` / `https:` has the shape
    // of a port; as a WHATWG IPv4 host it lies in 0.0.0.0/8, which is not a
    // valid destination (RFC 6890, Table 1)
    for t in [
        "http:80",
        "https:443",
        "http:8080",
        "https:65535",
        "ports: http:80 https:443",
        "listen http:8080 and https:8443",
    ] {
        assert!(url_guard(t).is_empty(), "{t}: {:?}", url_guard(t));
        assert_eq!(guard_all(t).action, GuardAction::Allow, "{t}");
    }
    // still flagged: 0.0.0.0, integers above 65535, any other host, a
    // port-like value behind userinfo or with a port, and every form with
    // a slash run
    for u in [
        "http:0",
        "http:65536",
        "http:2130706433",
        "http:10.0.0.5",
        "upstream http:127.0.0.1:9000",
        "http:user@80",
        "http:80:8080",
        "http://80/",
        r"http:\\80",
        r"http:\80",
        "http:/80",
    ] {
        let s = url_guard(u);
        assert!(!s.is_empty() && s[0].score >= 0.9, "{u}: {s:?}");
    }
}
