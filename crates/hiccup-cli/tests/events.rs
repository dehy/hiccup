// SPDX-License-Identifier: AGPL-3.0-or-later

//! `hiccup events --json` shows traffic live while a client uses the proxy.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use common::{Env, wait_exit};
use serde_json::Value;

/// `hiccup events --json` with `args`, once it streams; its events arrive
/// on the channel.
fn events(env: &Env, args: &[&str]) -> (Child, mpsc::Receiver<Value>) {
    let mut child = env
        .command()
        .args(["--json", "events"])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    while !line.contains("Streaming events") {
        line.clear();
        assert!(stderr.read_line(&mut line).unwrap() > 0, "events exited");
    }
    let stdout = BufReader::new(child.stdout.take().unwrap());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in stdout.lines() {
            let Ok(line) = line else { return };
            let _ = tx.send(serde_json::from_str(&line).expect("one JSON object per line"));
        }
    });
    (child, rx)
}

fn next(rx: &mpsc::Receiver<Value>) -> Value {
    rx.recv_timeout(Duration::from_secs(10))
        .expect("an event in time")
}

#[test]
fn traffic_shows_live() {
    let env = Env::new();
    let (mut serve, _stderr) = env.spawn(&["serve"], "is running");
    let (mut all, all_rx) = events(&env, &[]);
    let (mut filtered, filtered_rx) = events(&env, &["--filter", "exchange.response"]);

    let started = env.json(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    let proxy = started["proxy"]["listen"][0].as_str().unwrap().to_owned();
    let state = next(&all_rx);
    assert_eq!(state["event"], "proxy.state");
    assert_eq!(state["data"]["running"], true);

    // One request through the proxy, to a one-shot origin.
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_addr = origin.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut s, _) = origin.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = s.read(&mut buf).unwrap();
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
            .unwrap();
    });
    let mut client = TcpStream::connect(&proxy).unwrap();
    client
        .write_all(format!("GET http://{origin_addr}/live HTTP/1.1\r\n\r\n").as_bytes())
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();

    let request = next(&all_rx);
    assert_eq!(request["event"], "exchange.request");
    assert_eq!(request["data"]["method"], "GET");
    assert_eq!(
        request["data"]["target"],
        format!("http://{origin_addr}/live")
    );
    let done = next(&all_rx);
    assert_eq!(done["event"], "exchange.response");
    assert_eq!(done["data"]["id"], request["data"]["id"]);
    assert_eq!(done["data"]["status"], 200);

    // The filter let through only the response.
    let only = next(&filtered_rx);
    assert_eq!(only["event"], "exchange.response");

    // Both exit when the instance stops.
    assert!(env.run(&["instance", "stop"]).status.success());
    assert!(wait_exit(&mut serve).success());
    assert!(wait_exit(&mut all).success());
    assert!(wait_exit(&mut filtered).success());
    assert!(
        filtered_rx
            .try_iter()
            .all(|e| e["event"] == "exchange.response"),
        "nothing else got through"
    );
}
