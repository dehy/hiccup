// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end checks of `hiccup proxy start`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

/// `hiccup` with throwaway data and runtime directories, so that tests never
/// touch the user's CA or instances.
fn hiccup(data_dir: &tempfile::TempDir) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hiccup"));
    cmd.arg("--data-dir")
        .arg(data_dir.path())
        .arg("--runtime-dir")
        .arg(data_dir.path().join("run"))
        .env_remove("HICCUP_DATA_DIR")
        .env_remove("HICCUP_RUNTIME_DIR")
        .env_remove("HICCUP_INSTANCE");
    cmd
}

#[test]
fn without_an_instance_explains_and_fails() {
    let data = tempfile::tempdir().unwrap();
    let out = hiccup(&data).args(["proxy", "start"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("hiccup serve"), "{stderr}");
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
    // Any PEM certificate and key will do for --client-cert: use the CA's.
    assert!(
        hiccup(&data)
            .args(["ca", "info"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let cert = data.path().join("ca-cert.pem");
    let key = data.path().join("ca-key.pem");
    let client_cert = format!("*.test={},{}", cert.display(), key.display());
    let mut child = hiccup(&data)
        .args(["proxy", "start", "--foreground", "--listen", "127.0.0.1:0"])
        // Every upstream option, to check that they parse and start.
        .args(["--resolve", "origin.test=127.0.0.1", "--no-verify-upstream"])
        .args(["--upstream-tls-min", "1.3", "--upstream-tls-max", "1.3"])
        .args([
            "--upstream-sni",
            "*.test=sni.example",
            "--client-cert",
            &client_cert,
        ])
        .args(["--connect-timeout", "2.5", "--read-timeout", "5"])
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
        // `origin.test` exists only through --resolve.
        .write_all(
            format!(
                "GET http://origin.test:{}/ HTTP/1.1\r\n\r\n",
                origin_addr.port()
            )
            .as_bytes(),
        )
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    stop(&data, child);

    assert!(
        response.ends_with(b"\r\n\r\nhi"),
        "{}",
        String::from_utf8_lossy(&response)
    );
}

#[test]
fn listening_beyond_loopback_warns() {
    let data = tempfile::tempdir().unwrap();
    let warned = |listen: &str| {
        let mut child = hiccup(&data)
            .args(["proxy", "start", "--foreground", "--listen", listen])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stderr = BufReader::new(child.stderr.take().unwrap());
        let mut warned = false;
        // The foreground proxy prints this last, once started.
        loop {
            let mut line = String::new();
            assert!(stderr.read_line(&mut line).unwrap() > 0, "no start lines");
            warned |= line.contains("reachable from other machines");
            if line.contains("Press Ctrl+C") {
                break;
            }
        }
        stop(&data, child);
        warned
    };
    assert!(warned("0.0.0.0:0"));
    assert!(!warned("127.0.0.1:0"));
}

/// Stops a foreground proxy the way a user would, so that it exits normally
/// (a killed process writes no coverage data).
fn stop(data: &tempfile::TempDir, mut child: std::process::Child) {
    let stopped = hiccup(data).args(["instance", "stop"]).output().unwrap();
    assert!(stopped.status.success(), "{stopped:?}");
    assert!(child.wait().unwrap().success());
}

/// The start lines of a foreground proxy, then stops it.
fn start_lines(data: &tempfile::TempDir, args: &[&str]) -> String {
    let mut child = hiccup(data)
        .args(["proxy", "start", "--foreground"])
        .args(args)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut lines = String::new();
    while !lines.contains("Press Ctrl+C") {
        assert!(stderr.read_line(&mut lines).unwrap() > 0, "{lines}");
    }
    stop(data, child);
    lines
}

#[test]
fn saved_defaults_apply_and_flags_win() {
    let data = tempfile::tempdir().unwrap();
    let config = |args: &[&str]| {
        let out = hiccup(&data).arg("config").args(args).output().unwrap();
        assert!(out.status.success(), "{args:?}: {out:?}");
    };
    config(&["set", "proxy.listen", "127.0.0.1:0"]);
    config(&["set", "proxy.verify-upstream", "false"]);
    let lines = start_lines(&data, &[]);
    assert!(lines.contains("listening on http://127.0.0.1:"), "{lines}");
    assert!(
        lines.contains("WARNING: upstream certificates are not verified"),
        "{lines}"
    );

    // A flag given wins over the saved default.
    let lines = start_lines(&data, &["--listen", "[::1]:0"]);
    assert!(lines.contains("listening on http://[::1]:"), "{lines}");

    config(&["unset", "proxy.verify-upstream"]);
    let lines = start_lines(&data, &[]);
    assert!(
        lines.contains("Upstream certificates are verified"),
        "{lines}"
    );
    let lines = start_lines(&data, &["--no-verify-upstream"]);
    assert!(
        lines.contains("WARNING: upstream certificates are not verified"),
        "{lines}"
    );

    // Reading the settings, as text and as JSON.
    let get = |args: &[&str]| hiccup(&data).arg("config").args(args).output().unwrap();
    let all = String::from_utf8(get(&["get"]).stdout).unwrap();
    assert!(all.contains("proxy.listen = 127.0.0.1:0"), "{all}");
    assert!(all.contains("proxy.verify-upstream = (not set)"), "{all}");
    let one = get(&["get", "proxy.listen"]);
    assert_eq!(String::from_utf8(one.stdout).unwrap(), "127.0.0.1:0\n");
    let json = hiccup(&data)
        .args(["--json", "config", "get"])
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(json["proxy.listen"], serde_json::json!(["127.0.0.1:0"]));
    let unset = hiccup(&data)
        .args(["--json", "config", "get", "project"])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8(unset.stdout).unwrap().trim(), "null");

    // Usage errors (2), and a damaged file (1).
    for args in [
        &["set", "colour", "red"][..],
        &["get", "colour"],
        &["unset", "colour"],
    ] {
        assert_eq!(get(args).status.code(), Some(2), "{args:?}");
    }
    assert_eq!(
        get(&["set", "proxy.verify-upstream", "maybe"])
            .status
            .code(),
        Some(2)
    );
    std::fs::write(data.path().join("config.json"), b"not json").unwrap();
    let damaged = get(&["get"]);
    assert_eq!(damaged.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&damaged.stderr).contains("is not valid"));
}

#[test]
fn invalid_upstream_options_are_rejected() {
    let data = tempfile::tempdir().unwrap();
    for (args, expected, code) in [
        (&["--upstream-tls-min", "1.1"][..], "not supported", 2),
        (&["--resolve", "host=not-an-ip"], "invalid IP address", 2),
        (&["--resolve", "no-equals"], "expected HOST=VALUE", 2),
        (&["--upstream-sni", "*.=x"], "invalid host pattern", 2),
        (
            &["--client-cert", "h=missing.pem"],
            "cannot read missing.pem",
            2,
        ),
        (&["--connect-timeout", "0"], "positive number of seconds", 2),
        (
            &["--upstream-tls-min", "1.3", "--upstream-tls-max", "1.2"],
            "no TLS version",
            1,
        ),
    ] {
        let out = hiccup(&data)
            .args(["proxy", "start", "--foreground", "--listen", "127.0.0.1:0"])
            .args(args)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(code), "{args:?}: {stderr}");
        assert!(stderr.contains(expected), "{args:?}: {stderr}");
    }
}
