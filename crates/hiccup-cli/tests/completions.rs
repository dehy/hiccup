// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shell completions and man pages are generated from the CLI definition.

use std::process::Command;

fn hiccup() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hiccup"))
}

#[test]
fn completions_for_every_shell() {
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let out = hiccup().args(["completions", shell]).output().unwrap();
        assert!(out.status.success(), "{shell}: {out:?}");
        let script = String::from_utf8(out.stdout).unwrap();
        assert!(
            script.contains("intercept") && script.contains("history"),
            "{shell}"
        );
    }
    let out = hiccup().args(["completions", "tcsh"]).output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "an unknown shell is a usage error"
    );
}

#[test]
fn man_pages_for_every_command() {
    let dir = tempfile::tempdir().unwrap();
    let out = hiccup()
        .args(["man", "--output"])
        .arg(dir.path().join("man"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    for page in ["hiccup.1", "hiccup-proxy-start.1", "hiccup-history-list.1"] {
        let roff = std::fs::read_to_string(dir.path().join("man").join(page)).unwrap();
        assert!(
            roff.starts_with(".ie \\\\n(.g .ds Aq") || roff.contains(".TH"),
            "{page}"
        );
    }
}
