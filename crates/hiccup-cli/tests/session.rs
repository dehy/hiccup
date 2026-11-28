// SPDX-License-Identifier: AGPL-3.0-or-later

//! A full proxy session, scripted with the CLI only: start, intercept, edit,
//! forward, inspect history, export (the acceptance test of the CLI work).

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::{Env, wait_exit};
use serde_json::Value;

/// An origin that sends each request head it receives on the channel and
/// answers 200 "origin".
fn origin() -> (SocketAddr, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { return };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            let _ = tx.send(buf);
            let _ = s.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\norigin",
            );
        }
    });
    (addr, rx)
}

/// Polls `args` (JSON) until `ready` accepts the result.
fn until(env: &Env, args: &[&str], ready: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let value = env.json(args);
        if ready(&value) {
            return value;
        }
        assert!(Instant::now() < deadline, "{args:?}: still {value}");
        std::thread::sleep(Duration::from_millis(30));
    }
}

/// Kills the instance if the test fails before stopping it.
struct Serving(std::process::Child);

impl Drop for Serving {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_full_proxy_session() {
    let env = Env::new();
    let project = env.path("session.hiccup");
    let (serve, _stderr) = env.spawn(
        &["--project", project.to_str().unwrap(), "serve"],
        "is running",
    );
    let mut serve = Serving(serve);

    // Start the proxy, and hold requests.
    let started = env.json(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    let proxy = started["proxy"]["listen"][0].as_str().unwrap().to_owned();
    env.json(&["intercept", "on", "--path", "^/login"]);

    // A client sends a login; it is held.
    let (origin, received) = origin();
    let client = std::thread::spawn(move || {
        let mut s = TcpStream::connect(proxy).unwrap();
        let request =
            format!("GET http://{origin}/login?user=alice HTTP/1.1\r\nConnection: close\r\n\r\n");
        s.write_all(request.as_bytes()).unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).unwrap();
        out
    });
    let held = until(&env, &["intercept", "list"], |v| {
        !v.as_array().unwrap().is_empty()
    });
    let id = held[0]["id"].as_u64().unwrap().to_string();

    // Edit it, and forward the edit.
    let edited = b"GET /login?user=admin HTTP/1.1\r\nConnection: close\r\n\r\n";
    let file = env.path("edited.http");
    std::fs::write(&file, edited).unwrap();
    let out = env.run(&["intercept", "edit", &id, "--file", file.to_str().unwrap()]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        received.recv_timeout(Duration::from_secs(10)).unwrap(),
        edited
    );
    assert!(client.join().unwrap().ends_with(b"origin"));

    // Inspect history: the exchange, recorded as edited.
    let page = until(&env, &["history", "list"], |v| {
        !v["items"].as_array().unwrap().is_empty()
    });
    let exchange = &page["items"][0];
    assert_eq!(exchange["status"], 200);
    assert_eq!(exchange["request_edited"], true);
    let shown = env.json(&["history", "show", &exchange["id"].to_string()]);
    let forwarded = data_encoding::BASE64
        .decode(shown["forwarded"].as_str().unwrap().as_bytes())
        .unwrap();
    assert_eq!(forwarded, edited, "history keeps what was really sent");

    // Export it.
    let out = env.run(&["history", "export"]);
    assert!(out.status.success(), "{out:?}");
    let exported: Value =
        serde_json::from_slice(out.stdout.split(|&b| b == b'\n').next().unwrap()).unwrap();
    assert_eq!(exported["id"], exchange["id"]);

    // Done: stop everything.
    env.json(&["intercept", "off"]);
    env.json(&["proxy", "stop"]);
    assert!(env.run(&["instance", "stop"]).status.success());
    assert!(wait_exit(&mut serve.0).success());
}
