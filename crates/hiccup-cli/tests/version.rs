// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end checks of the `hiccup` binary.

use std::process::Command;

#[test]
fn version_flag_prints_package_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_hiccup"))
        .arg("--version")
        .output()
        .expect("failed to run hiccup");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout is not UTF-8");
    assert_eq!(
        stdout.trim(),
        format!("hiccup {}", env!("CARGO_PKG_VERSION"))
    );
}
