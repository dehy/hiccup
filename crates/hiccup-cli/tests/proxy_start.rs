// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end checks of `hiccup proxy start`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

fn hiccup() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hiccup"))
}

#[test]
fn without_foreground_explains_and_fails() {
    let out = hiccup().args(["proxy", "start"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--foreground"), "{stderr}");
}

#[test]
fn foreground_proxy_forwards_a_request() {
    // A one-shot origin server.
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_addr = origin.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut s, _) = origin.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = s.read(&mut buf).unwrap();
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
            .unwrap();
    });

    let mut child = hiccup()
        .args(["proxy", "start", "--foreground", "--listen", "127.0.0.1:0"])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    stderr.read_line(&mut line).unwrap();
    let addr = line
        .trim()
        .strip_prefix("Hiccup proxy listening on http://")
        .unwrap_or_else(|| panic!("unexpected first line: {line:?}"))
        .to_owned();

    let mut client = TcpStream::connect(&addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .write_all(format!("GET http://{origin_addr}/ HTTP/1.1\r\n\r\n").as_bytes())
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        response.ends_with(b"\r\n\r\nhi"),
        "{}",
        String::from_utf8_lossy(&response)
    );
}
