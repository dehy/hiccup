// SPDX-License-Identifier: AGPL-3.0-or-later

//! A project file another user created first is refused, untouched.
//!
//! Creates the file as `nobody` with `sudo -n`, which CI runners allow.
//! Skipped where `sudo` needs a password, except in CI (`CI` is set), where
//! it fails instead.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use hiccup_store::{Store, StoreError};

fn as_nobody(script: &str, arg: &std::path::Path) -> bool {
    Command::new("sudo")
        .args(["-n", "-u", "nobody", "sh", "-c", script, "sh"])
        .arg(arg)
        .output()
        .is_ok_and(|o| o.status.success())
}

#[test]
fn a_project_another_user_planted_is_refused() {
    if !as_nobody("true", std::path::Path::new("/")) {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI cannot run commands as nobody: the test would be skipped"
        );
        eprintln!("cannot run commands as nobody without a password; skipping");
        return;
    }
    // A shared, sticky directory, like /tmp itself.
    let base = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
    fs::set_permissions(base.path(), fs::Permissions::from_mode(0o1777)).unwrap();
    let path = base.path().join("p.hiccup");
    // World-writable, so that only Hiccup's own checks stop it.
    assert!(as_nobody("umask 0; : > \"$1\"", &path));

    // EPERM from chmod (or EACCES): both are PermissionDenied.
    match Store::open(&path) {
        Err(StoreError::Io(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}");
        }
        other => panic!("not refused as expected: {:?}", other.err()),
    }
    assert_eq!(fs::metadata(&path).unwrap().len(), 0, "nothing was written");
    assert!(!base.path().join("p.hiccup-wal").exists());
}
