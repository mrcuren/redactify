//! HTTP throughput/latency benchmark for the REST API server (api feature).
//!
//! Spins the real server (tiny_http, 4 workers, deterministic state) on an
//! ephemeral local port and measures, with fresh TCP connections per request
//! (connection setup included - a conservative floor):
//!
//! - sequential: p50/p95/avg latency + requests/sec
//! - 4 concurrent clients: aggregate requests/sec
//!
//! ```text
//! cargo run --release --features api --example api_bench
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Instant;

use redactify::api::{serve_with, ApiState};

fn one_request(port: u16, body: &str) -> f32 {
    let t0 = Instant::now();
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let req = format!(
        "POST /v1/guard HTTP/1.1\r\nHost: b\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    s.write_all(req.as_bytes()).expect("write");
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).expect("read");
    assert!(
        buf.starts_with(b"HTTP/1.1 200"),
        "status not 200: {}",
        String::from_utf8_lossy(&buf[..40])
    );
    t0.elapsed().as_secs_f32() * 1000.0
}

fn main() {
    // server on an ephemeral port
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener); // free the port for tiny_http (tiny race, retry below if any)
    std::thread::spawn(move || {
        if serve_with(&format!("127.0.0.1:{port}"), ApiState::default()).is_err() {
            eprintln!("bench server bind failed");
        }
    });
    // wait for the listener
    let mut warm = None;
    for _ in 0..100 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            warm = Some(s);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    drop(warm.expect("bench server did not start"));

    let pii_body = r#"{"text":"TCKN 12345678950 and see http://169.254.169.254/meta"}"#;
    let clean_body = r#"{"text":"merhaba dunya, hava nasil today"}"#;

    // ---- sequential ----
    const SEQ_N: usize = 300;
    let mut lat: Vec<f32> = Vec::with_capacity(SEQ_N);
    let t0 = Instant::now();
    for i in 0..SEQ_N {
        lat.push(one_request(
            port,
            if i % 2 == 0 { pii_body } else { clean_body },
        ));
    }
    let seq_elapsed = t0.elapsed().as_secs_f32();
    lat.sort_by(|a, b| a.total_cmp(b));
    let p50 = lat[SEQ_N / 2];
    let p95 = lat[(SEQ_N as f32 * 0.95) as usize];
    let avg: f32 = lat.iter().sum::<f32>() / SEQ_N as f32;
    println!("sequential ({SEQ_N} req, fresh conn each):");
    println!(
        "  avg {avg:.2} ms | p50 {p50:.2} ms | p95 {p95:.2} ms | {:.0} req/s",
        SEQ_N as f32 / seq_elapsed
    );

    // ---- 4 concurrent clients ----
    const PER_THREAD: usize = 100;
    let t0 = Instant::now();
    let handles: Vec<_> = (0..4)
        .map(|t| {
            std::thread::spawn(move || {
                for i in 0..PER_THREAD {
                    let _ = one_request(
                        port,
                        if (i + t) % 2 == 0 {
                            pii_body
                        } else {
                            clean_body
                        },
                    );
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("client thread");
    }
    let conc_elapsed = t0.elapsed().as_secs_f32();
    let total = 4 * PER_THREAD;
    println!("concurrent (4 clients x {PER_THREAD}):");
    println!(
        "  {total} req in {conc_elapsed:.2}s -> {:.0} req/s",
        total as f32 / conc_elapsed
    );
}
