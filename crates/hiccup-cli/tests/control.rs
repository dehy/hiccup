// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end checks of the control plane: `hiccup serve`, then other
//! `hiccup` processes controlling it (ADR 0004).

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use common::{Env, wait_exit};

/// A one-shot origin server.
fn origin() -> std::net::SocketAddr {
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = origin.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut s, _) = origin.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = s.read(&mut buf).unwrap();
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
            .unwrap();
    });
    addr
}

fn get_through(proxy: &str, origin: std::net::SocketAddr) -> Vec<u8> {
    let mut client = TcpStream::connect(proxy).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .write_all(format!("GET http://{origin}/ HTTP/1.1\r\n\r\n").as_bytes())
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    response
}

#[test]
fn the_cli_controls_a_running_daemon() {
    let env = Env::new();
    let (mut serve, _stderr) = env.spawn(&["serve"], "is running");

    let instances = env.json(&["instance", "list"]);
    assert_eq!(instances.as_array().unwrap().len(), 1, "{instances}");
    assert_eq!(instances[0]["name"], "default");
    assert_eq!(env.json(&["proxy", "status"])["running"], false);

    // A second instance with the same name is refused.
    let out = env.run(&["serve"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("already running"));

    let started = env.json(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    assert_eq!(started["proxy"]["running"], true);
    assert_eq!(started["ca_generated"], true);
    let proxy = started["proxy"]["listen"][0].as_str().unwrap().to_owned();

    let response = get_through(&proxy, origin());
    assert!(response.ends_with(b"\r\n\r\nhi"), "{response:?}");
    assert_eq!(env.json(&["proxy", "status"])["exchanges"], 1);

    let out = env.run(&["proxy", "start", "--listen", "127.0.0.1:0"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("already running"));

    // Human-readable output.
    let out = env.run(&["proxy", "status"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("running") && stdout.contains(&proxy),
        "{stdout}"
    );

    assert!(env.run(&["proxy", "stop"]).status.success());
    assert_eq!(env.json(&["proxy", "status"])["running"], false);
    assert!(env.run(&["instance", "stop"]).status.success());
    assert!(wait_exit(&mut serve).success());
    assert_eq!(env.json(&["instance", "list"]), serde_json::json!([]));
}

#[test]
fn a_foreground_proxy_is_an_instance() {
    let env = Env::new();
    let (mut fg, _stderr) = env.spawn(
        &[
            "--instance",
            "fg",
            "proxy",
            "start",
            "--foreground",
            "--listen",
            "127.0.0.1:0",
        ],
        "Press Ctrl+C",
    );
    let status = env.json(&["proxy", "status"]);
    assert_eq!(status["running"], true, "{status}");
    assert_eq!(env.json(&["instance", "list"])[0]["name"], "fg");

    // Stopping its proxy ends the foreground process.
    assert!(
        env.run(&["--instance", "fg", "proxy", "stop"])
            .status
            .success()
    );
    assert!(wait_exit(&mut fg).success());
}

#[test]
fn selection_errors_are_explained() {
    let env = Env::new();
    let out = env.run(&["proxy", "status"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("hiccup serve"));

    let (mut a, _ea) = env.spawn(&["--instance", "a", "serve"], "is running");
    let (mut b, _eb) = env.spawn(&["--instance", "b", "serve"], "is running");
    let out = env.run(&["proxy", "status"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("several") && stderr.contains("a, b"),
        "{stderr}"
    );
    let out = env.run(&["--instance", "c", "proxy", "status"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("no running Hiccup instance named"));

    for (name, child) in [("a", &mut a), ("b", &mut b)] {
        assert!(
            env.run(&["--instance", name, "instance", "stop"])
                .status
                .success()
        );
        assert!(wait_exit(child).success());
    }
}
