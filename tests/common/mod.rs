//! Helpers shared by the socket test binaries: a free localhost port, a
//! server started on it, and one raw HTTP exchange.
// each test binary compiles this module and uses a subset of it
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use redactify::api::{serve_with, ApiState};

/// A localhost port the OS reports free (bound to port 0, then released),
/// so parallel tests and concurrently running test binaries do not pick
/// the same port.
pub(crate) fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .and_then(|l| l.local_addr())
        .expect("a free localhost port")
        .port()
}

/// Serves `state` on a free port and returns the port once the listener
/// accepts connections.
pub(crate) fn start(state: ApiState) -> u16 {
    let port = free_port();
    std::thread::spawn(move || {
        let _ = serve_with(&format!("127.0.0.1:{port}"), state);
    });
    drop(connect(port));
    port
}

/// A connection to the server on `port`, retried for up to 5 s while its
/// listener comes up.
pub(crate) fn connect(port: u16) -> TcpStream {
    for _ in 0..50 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            return s;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("server did not come up");
}

/// Sends one raw request on a new connection and returns the whole
/// response (the request should ask the server to close the connection).
pub(crate) fn send(port: u16, request: &str) -> String {
    let mut s = connect(port);
    s.write_all(request.as_bytes()).expect("write");
    let mut response = String::new();
    s.read_to_string(&mut response).expect("read");
    response
}
