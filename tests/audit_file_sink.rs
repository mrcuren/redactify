//! The chained audit sinks never glue a record onto a torn line: a file
//! whose last record lost its newline is terminated before the next
//! append, a failed write stops the sink, and opening an existing file
//! verifies it line by line exactly like `verify_chain`.

use redactify::guard::audit::{verify_chain, AuditRecord, ChainedAuditSink, FileAuditSink};
use redactify::policy::GuardAction;

/// A fresh, empty per-test directory under the system temp dir.
fn temp_audit_file(tag: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("redactify-audit-sink-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("audit.jsonl");
    let _ = std::fs::remove_file(&path);
    path
}

fn rec(id: &str) -> AuditRecord {
    AuditRecord::decision(id, "L0", 0.0, GuardAction::Allow, "t".to_owned())
}

#[test]
fn a_record_missing_its_newline_is_terminated_before_the_next_append() {
    let path = temp_audit_file("torn-newline");
    {
        let mut sink = FileAuditSink::open(&path, None).unwrap();
        sink.append(&rec("r1")).unwrap();
    }
    // a crash right before the line's final newline reached the disk
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.trim_end_matches('\n')).unwrap();
    {
        let mut sink = FileAuditSink::open(&path, None).expect("verified chain resumes");
        assert_eq!(sink.entries(), 1);
        sink.append(&rec("r2")).unwrap();
    }
    let after = std::fs::read_to_string(&path).unwrap();
    assert_eq!(after.lines().count(), 2, "{after}");
    assert!(after.ends_with('\n'));
    assert_eq!(verify_chain(after.lines(), None), Ok(2));
    assert_eq!(FileAuditSink::open(&path, None).unwrap().entries(), 2);
    let _ = std::fs::remove_file(&path);
}

/// A writer that accepts `budget` more bytes, then fails every write.
struct FlakyWriter {
    state: std::rc::Rc<std::cell::RefCell<(Vec<u8>, usize)>>,
}

impl std::io::Write for FlakyWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut st = self.state.borrow_mut();
        if st.1 == 0 {
            return Err(std::io::Error::other("disk full"));
        }
        let n = buf.len().min(st.1);
        st.0.extend_from_slice(&buf[..n]);
        st.1 -= n;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_failed_write_never_lets_a_later_record_glue_onto_a_torn_line() {
    let state = std::rc::Rc::new(std::cell::RefCell::new((Vec::new(), usize::MAX)));
    let mut sink = ChainedAuditSink::new(FlakyWriter {
        state: std::rc::Rc::clone(&state),
    });
    sink.append(&rec("r1")).unwrap();
    // the next record is torn after 40 bytes
    state.borrow_mut().1 = 40;
    assert!(sink.append(&rec("r2")).is_err());
    // the disk recovers; the sink must not write behind the torn line
    state.borrow_mut().1 = usize::MAX;
    let third = sink.append(&rec("r3"));
    let log = String::from_utf8(state.borrow().0.clone()).unwrap();
    assert!(third.is_err(), "append after a torn write succeeded: {log}");
    assert_eq!(sink.entries(), 1);
    // everything up to the torn tail still verifies
    let complete: Vec<&str> = log
        .split_inclusive('\n')
        .filter(|l| l.ends_with('\n'))
        .collect();
    assert_eq!(verify_chain(complete, None), Ok(1));
}

#[test]
fn open_verifies_the_same_way_as_verify_chain() {
    // the line-by-line verification at open agrees with verify_chain on
    // valid, CRLF, blank-line, tampered, torn and non-UTF-8 content
    let path = temp_audit_file("equiv");
    let base = {
        let mut sink = ChainedAuditSink::new(Vec::<u8>::new());
        for id in ["r1", "r2", "r3"] {
            sink.append(&rec(id)).unwrap();
        }
        sink.into_log()
    };
    let text = String::from_utf8(base.clone()).unwrap();
    let mut cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        base.clone(),
        text.replace('\n', "\r\n").into_bytes(),
        text.replacen('\n', "\n\n", 1).into_bytes(),
        format!("\n{text}").into_bytes(),
        text.replace("\"r2\"", "\"r9\"").into_bytes(),
        format!("{text}{{\"chain_prev\":\"00").into_bytes(),
        b"not json\n".to_vec(),
    ];
    let mut invalid_utf8 = base.clone();
    let at = invalid_utf8.iter().position(|&b| b == b'r').unwrap();
    invalid_utf8[at] = 0xFF;
    cases.push(invalid_utf8);
    for content in cases {
        std::fs::write(&path, &content).unwrap();
        let lossy = String::from_utf8_lossy(&content).into_owned();
        let expected = verify_chain(lossy.lines(), None);
        let got = FileAuditSink::open(&path, None).map(|s| s.entries());
        match (&expected, &got) {
            (Ok(n), Ok(m)) => assert_eq!(n, m, "{lossy:?}"),
            (Err(e), Err(redactify::guard::audit::AuditSinkError::Chain(g))) => {
                assert_eq!(e, g, "{lossy:?}");
            }
            _ => panic!("{lossy:?}: verify_chain {expected:?} vs open {got:?}"),
        }
    }
    let _ = std::fs::remove_file(&path);
}
