// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end checks of `hiccup proxy start`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

/// `hiccup` with a throwaway data directory, so that tests never touch the
/// user's CA.
fn hiccup(data_dir: &tempfile::TempDir) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hiccup"));
    cmd.arg("--data-dir")
        .arg(data_dir.path())
        .env_remove("HICCUP_DATA_DIR");
    cmd
}

#[test]
fn without_foreground_explains_and_fails() {
    let data = tempfile::tempdir().unwrap();
    let out = hiccup(&data).args(["proxy", "start"]).output().unwrap();
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

    let data = tempfile::tempdir().unwrap();
    let mut child = hiccup(&data)
        .args(["proxy", "start", "--foreground", "--listen", "127.0.0.1:0"])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let addr = loop {
        let mut line = String::new();
        assert!(
            stderr.read_line(&mut line).unwrap() > 0,
            "no listening line"
        );
        if let Some(addr) = line
            .trim()
            .strip_prefix("Hiccup proxy listening on http://")
        {
            break addr.to_owned();
        }
    };

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
