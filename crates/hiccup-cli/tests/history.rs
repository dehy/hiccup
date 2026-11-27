// SPDX-License-Identifier: AGPL-3.0-or-later

//! An instance with a project records history; `hiccup history` reads it,
//! across restarts.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use common::{Env, wait_exit};
use serde_json::Value;

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\norigin";

/// An origin answering every connection with `RESPONSE`.
fn origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { return };
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = s.write_all(RESPONSE);
        }
    });
    addr
}

fn send(proxy: &str, request: &str) {
    let mut s = TcpStream::connect(proxy).unwrap();
    s.write_all(request.as_bytes()).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    assert!(out.ends_with(b"origin"));
}

/// Kills the instance if the test fails before stopping it: a stray one
/// would keep the test's output pipes open.
struct Serving(std::process::Child);

impl Drop for Serving {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `history list --json`, once it has `n` items (they are written by a
/// background thread).
fn list(env: &Env, n: usize, args: &[&str]) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let page = env.json(&[&["history", "list"][..], args].concat());
        let items = page["items"].as_array().unwrap().clone();
        if items.len() >= n || Instant::now() > deadline {
            return items;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn recorded_listed_shown_exported_and_kept() {
    let env = Env::new();
    let project = env.path("work.hiccup");
    let project = project.to_str().unwrap();
    let (serve, _stderr) = env.spawn(&["--project", project, "serve"], "is running");
    let mut serve = Serving(serve);
    assert_eq!(env.json(&["instance", "list"])[0]["name"], "default");

    let started = env.json(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    let proxy = started["proxy"]["listen"][0].as_str().unwrap().to_owned();
    let origin = origin();
    let first = format!("GET http://{origin}/first HTTP/1.1\r\nHost: {origin}\r\n\r\n");
    send(&proxy, &first);
    send(
        &proxy,
        &format!("POST http://{origin}/second HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi"),
    );

    let items = list(&env, 2, &[]);
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["method"], "POST", "newest first");
    assert_eq!(items[1]["target"], format!("http://{origin}/first"));
    assert_eq!(items[1]["status"], 200);

    // Filters.
    assert_eq!(list(&env, 1, &["--method", "POST"]).len(), 1);
    assert_eq!(list(&env, 1, &["--search", "/first"])[0]["method"], "GET");
    assert!(list(&env, 0, &["--status", "404"]).is_empty());

    // The exact bytes, from JSON and from `show --request/--response`.
    let id = items[1]["id"].as_u64().unwrap().to_string();
    let shown = env.json(&["history", "show", &id]);
    let decode = |v: &Value| {
        data_encoding::BASE64
            .decode(v.as_str().unwrap().as_bytes())
            .unwrap()
    };
    assert_eq!(decode(&shown["received"]), first.as_bytes());
    let out = env.run(&["history", "show", &id, "--response"]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout, RESPONSE, "redirected: exact bytes");

    // Export: one full exchange per line.
    let out = env.run(&["history", "export"]);
    assert!(out.status.success(), "{out:?}");
    let lines: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(decode(&lines[1]["response"]), RESPONSE);

    // As text: a table, the exchange, one message exactly.
    let text = |args: &[&str]| {
        let out = env.run(args);
        assert!(out.status.success(), "{args:?}: {out:?}");
        (
            String::from_utf8(out.stdout).unwrap(),
            String::from_utf8(out.stderr).unwrap(),
        )
    };
    let (table, _) = text(&["history", "list"]);
    assert!(table.starts_with("    ID  METHOD"), "{table}");
    // The response size counts its head and body.
    let row = table.lines().find(|l| l.contains("/first")).unwrap();
    let columns: Vec<_> = row.split_whitespace().collect();
    assert_eq!(
        &columns[1..5],
        ["GET", "200", &RESPONSE.len().to_string(), "B"],
        "{row}"
    );
    let (_, hint) = text(&["history", "list", "--limit", "1"]);
    assert!(
        hint.contains("--before"),
        "a full page says how to get the next"
    );
    let (shown, _) = text(&["history", "show", &id]);
    assert!(
        shown.starts_with(&format!("# {id} GET http://{origin}/first\n")),
        "{shown}"
    );
    assert!(shown.ends_with("origin"), "{shown}");
    assert_eq!(text(&["history", "show", &id, "--request"]).0, first);

    // A failed exchange: recorded with its error, and no response.
    let mut s = TcpStream::connect(&proxy).unwrap();
    s.write_all(b"GET http://127.0.0.1:0/down HTTP/1.1\r\n\r\n")
        .unwrap();
    s.read_to_end(&mut Vec::new()).unwrap();
    let failed = list(&env, 3, &[]);
    assert!(
        failed[0]["error"]
            .as_str()
            .unwrap()
            .contains("cannot connect")
    );
    let failed_id = failed[0]["id"].as_u64().unwrap().to_string();
    assert!(text(&["history", "list"]).0.contains(" error "));
    assert!(
        text(&["history", "show", &failed_id])
            .0
            .contains("(failed: ")
    );
    let refused = |args: &[&str], expected: &str| {
        let out = env.run(args);
        assert!(!out.status.success(), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(expected), "{args:?}: {stderr}");
    };
    refused(
        &["history", "show", &failed_id, "--response"],
        "has no response",
    );
    refused(&["history", "show", "999"], "no recorded exchange 999");
    refused(&["history", "list", "--limit", "2000"], "above 1000");

    // History survives a restart of the instance.
    assert!(env.run(&["instance", "stop"]).status.success());
    assert!(wait_exit(&mut serve.0).success());
    let (again, _stderr) = env.spawn(&["--project", project, "serve"], "is running");
    let mut serve = Serving(again);
    assert_eq!(list(&env, 3, &[]).len(), 3);
    assert!(env.run(&["instance", "stop"]).status.success());
    assert!(wait_exit(&mut serve.0).success());
}

#[test]
fn without_a_project_history_is_not_recorded() {
    let env = Env::new();
    let (serve, _stderr) = env.spawn(&["serve"], "is running");
    let mut serve = Serving(serve);
    let out = env.run(&["history", "list"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no project is open"), "{stderr}");
    assert!(env.run(&["instance", "stop"]).status.success());
    assert!(wait_exit(&mut serve.0).success());
}
