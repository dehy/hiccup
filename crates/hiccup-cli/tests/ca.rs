// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end checks of `hiccup ca`.

use std::path::Path;
use std::process::{Command, Output};

fn hiccup(data_dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hiccup"))
        .arg("--data-dir")
        .arg(data_dir)
        .args(args)
        .env_remove("HICCUP_DATA_DIR")
        .output()
        .unwrap()
}

#[test]
fn export_der_to_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let out_file = dir.path().join("hiccup.der");
    let out = hiccup(
        &data,
        &[
            "ca",
            "export",
            "--format",
            "der",
            "-o",
            out_file.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("Generated a new CA"));

    let der = std::fs::read(&out_file).unwrap();
    assert_eq!(der.first(), Some(&0x30), "a DER SEQUENCE");

    // The same certificate, PEM-encoded, on standard output.
    let out = hiccup(&data, &["ca", "export"]);
    assert!(out.status.success(), "{out:?}");
    assert!(out.stderr.is_empty(), "generated only once");
    let pem = String::from_utf8(out.stdout).unwrap();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"), "{pem}");
    assert!(!pem.contains("PRIVATE KEY"), "{pem}");
    assert_eq!(
        pem,
        std::fs::read_to_string(data.join("ca-cert.pem")).unwrap()
    );
}

#[test]
fn info_shows_the_fingerprint() {
    let dir = tempfile::tempdir().unwrap();
    let out = hiccup(dir.path(), &["ca", "info"]);
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Subject:     CN=Hiccup CA"), "{stdout}");
    let fingerprint = stdout
        .lines()
        .find_map(|l| l.strip_prefix("SHA-256:     "))
        .unwrap();
    assert_eq!(fingerprint.len(), 32 * 3 - 1, "{fingerprint}");
}

#[test]
fn regenerate_needs_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    let cert = || std::fs::read(dir.path().join("ca-cert.pem")).unwrap();
    assert!(hiccup(dir.path(), &["ca", "info"]).status.success());
    let before = cert();

    let out = hiccup(dir.path(), &["ca", "regenerate"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--yes"));
    assert_eq!(cert(), before);

    let out = hiccup(dir.path(), &["ca", "regenerate", "--yes"]);
    assert!(out.status.success(), "{out:?}");
    assert_ne!(cert(), before);
}

#[test]
fn a_broken_ca_is_reported_not_replaced() {
    let dir = tempfile::tempdir().unwrap();
    assert!(hiccup(dir.path(), &["ca", "info"]).status.success());
    std::fs::remove_file(dir.path().join("ca-key.pem")).unwrap();
    let out = hiccup(dir.path(), &["ca", "export"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("incomplete CA"), "{stderr}");
}
