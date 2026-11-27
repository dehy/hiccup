// SPDX-License-Identifier: AGPL-3.0-or-later

//! `hiccup intercept` against a running instance: hold, show, edit, drop.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::Stdio;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use common::{Env, wait_exit};
use serde_json::Value;

/// An origin that sends what it receives (one request per connection) on
/// `received`, and answers 200 "origin".
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
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\norigin");
        }
    });
    (addr, rx)
}

/// Sends one request through the proxy in a thread; returns the response.
fn send(proxy: &str, origin: SocketAddr, path: &str) -> JoinHandle<Vec<u8>> {
    let proxy = proxy.to_owned();
    let path = path.to_owned();
    std::thread::spawn(move || {
        let mut s = TcpStream::connect(proxy).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let request = format!(
            "GET http://{origin}{path} HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
        );
        s.write_all(request.as_bytes()).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        out
    })
}

/// Runs a command that must succeed; returns its standard output.
fn stdout(env: &Env, args: &[&str]) -> String {
    let out = env.run(args);
    assert!(out.status.success(), "{args:?}: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

/// Waits until one message is held and returns its summary.
fn held(env: &Env) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let list = env.json(&["intercept", "list"]);
        if let Some(item) = list.as_array().unwrap().first() {
            return item.clone();
        }
        assert!(Instant::now() < deadline, "nothing was held");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_scripted_intercept_session() {
    let env = Env::new();
    let (mut serve, _stderr) = env.spawn(&["serve"], "is running");
    let started = env.json(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    let proxy = started["proxy"]["listen"][0].as_str().unwrap().to_owned();
    let (origin, received) = origin();

    // Settings belong to the instance.
    let status = env.json(&["intercept", "on", "--method", "get", "--path", "^/held"]);
    assert_eq!(status["requests"]["methods"], serde_json::json!(["GET"]));
    assert_eq!(status["responses"], Value::Null);

    // Not matching: not held.
    let response = send(&proxy, origin, "/free").join().unwrap();
    assert!(response.ends_with(b"origin"));
    assert!(received.recv().unwrap().starts_with(b"GET /free "));

    // Held, shown, then edited from a file: sent exactly as edited.
    let client = send(&proxy, origin, "/held/1");
    let item = held(&env);
    let id = item["id"].as_u64().unwrap().to_string();
    assert_eq!(item["target"], "/held/1");
    let raw = env.run(&["intercept", "show", &id, "--raw"]).stdout;
    assert!(raw.starts_with(b"GET /held/1 HTTP/1.1\r\n"), "{raw:?}");

    // The same, for humans.
    let text = stdout(&env, &["intercept", "status"]);
    assert!(
        text.contains("Requests:  on (methods GET; path /^/held/)"),
        "{text}"
    );
    assert!(
        text.contains("Responses: off") && text.contains("Held:      1"),
        "{text}"
    );
    let text = stdout(&env, &["intercept", "list"]);
    assert!(text.contains("  request   GET  "), "{text}");
    assert!(text.contains(&format!("http://{origin}/held/1")), "{text}");
    let text = stdout(&env, &["intercept", "show", &id]);
    assert!(
        text.starts_with(&format!("# {id} request GET {origin}/held/1 (")),
        "{text}"
    );

    let edited =
        b"GET /edited  HTTP/1.1\r\nhost: changed\r\nX-Edit: yes\r\nConnection: close\r\n\r\n";
    let file = env.path("edited.http");
    std::fs::write(&file, edited).unwrap();
    let out = env.run(&["intercept", "edit", &id, "--file", file.to_str().unwrap()]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        received.recv_timeout(Duration::from_secs(5)).unwrap(),
        edited
    );
    assert!(client.join().unwrap().ends_with(b"origin"));

    // Edited from standard input.
    let client = send(&proxy, origin, "/held/2");
    let id = held(&env)["id"].as_u64().unwrap().to_string();
    let piped = b"GET /piped HTTP/1.1\r\nConnection: close\r\n\r\n";
    let mut child = env
        .command()
        .args(["intercept", "edit", &id])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(piped).unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(
        received.recv_timeout(Duration::from_secs(5)).unwrap(),
        piped
    );
    assert!(client.join().unwrap().ends_with(b"origin"));

    // Dropped: the origin sees nothing, the client gets Hiccup's 502.
    let client = send(&proxy, origin, "/held/3");
    let id = held(&env)["id"].as_u64().unwrap().to_string();
    assert!(env.run(&["intercept", "drop", &id]).status.success());
    assert!(client.join().unwrap().starts_with(b"HTTP/1.1 502 "));
    assert!(received.try_recv().is_err());

    // An unknown ID is an error.
    let out = env.run(&["intercept", "forward", "999"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no held item 999"));

    // Forwarding everything.
    let client = send(&proxy, origin, "/held/5");
    held(&env);
    let text = stdout(&env, &["intercept", "forward", "--all"]);
    assert_eq!(text, "Forwarded 1 message(s).\n");
    assert!(client.join().unwrap().ends_with(b"origin"));
    assert!(received.recv().unwrap().starts_with(b"GET /held/5 "));
    assert_eq!(stdout(&env, &["intercept", "list"]), "No held message.\n");

    // Turning interception off forwards what is held.
    let client = send(&proxy, origin, "/held/4");
    held(&env);
    let text = stdout(&env, &["intercept", "off"]);
    assert!(text.contains("Requests:  off"), "{text}");
    assert!(client.join().unwrap().ends_with(b"origin"));
    assert!(received.recv().unwrap().starts_with(b"GET /held/4 "));

    assert!(env.run(&["instance", "stop"]).status.success());
    assert!(wait_exit(&mut serve).success());
}

#[test]
fn responses_can_be_held_with_a_timeout() {
    let env = Env::new();
    let (mut serve, _stderr) = env.spawn(&["serve"], "is running");
    let started = env.json(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    let proxy = started["proxy"]["listen"][0].as_str().unwrap().to_owned();
    let (origin, _received) = origin();

    let status = env.json(&[
        "intercept",
        "on",
        "--responses",
        "--timeout",
        "0.3",
        "--on-timeout",
        "drop",
    ]);
    assert_eq!(status["requests"], Value::Null);
    assert_eq!(status["timeout_ms"], 300);
    let text = stdout(&env, &["intercept", "status"]);
    assert!(text.contains("Timeout:   0.3s, then drop"), "{text}");
    let out = env.run(&["intercept", "on", "--timeout", "-1"]);
    assert_eq!(out.status.code(), Some(2));

    // Nobody acts: the held response is dropped after the timeout.
    let response = send(&proxy, origin, "/").join().unwrap();
    assert!(response.starts_with(b"HTTP/1.1 502 "), "{response:?}");

    assert!(env.run(&["instance", "stop"]).status.success());
    assert!(wait_exit(&mut serve).success());
}
