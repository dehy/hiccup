// SPDX-License-Identifier: AGPL-3.0-or-later

//! A project file another user created first is refused, untouched.
//!
//! Unix: creates the file as `nobody` with `sudo -n`. Windows: gives it to a
//! throwaway local account, as an administrator. CI runners allow both;
//! elsewhere the tests are skipped, except in CI (`CI` is set), where they
//! fail instead.

use std::fs;
use std::process::Command;

use hiccup_store::{Store, StoreError};

fn skip(why: &str) {
    assert!(
        std::env::var_os("CI").is_none(),
        "{why}: the test would be skipped in CI"
    );
    eprintln!("{why}; skipping");
}

#[cfg(unix)]
fn as_nobody(script: &str, arg: &std::path::Path) -> bool {
    Command::new("sudo")
        .args(["-n", "-u", "nobody", "sh", "-c", script, "sh"])
        .arg(arg)
        .output()
        .is_ok_and(|o| o.status.success())
}

#[cfg(unix)]
#[test]
fn a_project_another_user_planted_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    if !as_nobody("true", std::path::Path::new("/")) {
        return skip("cannot run commands as nobody without a password");
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

#[cfg(windows)]
#[test]
fn a_project_another_user_owns_is_refused() {
    const USER: &str = "hiccup-test";
    let run = |program: &str, args: &[&str]| {
        Command::new(program)
            .args(args)
            .output()
            .is_ok_and(|o| o.status.success())
    };
    if !run("net", &["session"]) {
        return skip("not an administrator");
    }
    // A throwaway account, removed even if the test fails.
    struct Account;
    impl Drop for Account {
        fn drop(&mut self) {
            let _ = Command::new("net").args(["user", USER, "/delete"]).output();
        }
    }
    let _ = run("net", &["user", USER, "/delete"]);
    assert!(
        run("net", &["user", USER, "Hx-test-Pw9!q", "/add"]),
        "net user /add"
    );
    let _account = Account;

    // Planted: owned by the account, and writable by everyone, so that only
    // Hiccup's own check stops it.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.hiccup");
    fs::write(&path, b"").unwrap();
    let file = path.to_str().unwrap();
    assert!(
        run("icacls", &[file, "/setowner", USER]),
        "icacls /setowner"
    );
    assert!(
        run("icacls", &[file, "/grant", "*S-1-1-0:F"]),
        "icacls /grant"
    );

    match Store::open(&path) {
        Err(StoreError::Unsafe { reason, .. }) => assert!(reason.contains("another user")),
        other => panic!("not refused: {:?}", other.err()),
    }
    assert_eq!(fs::metadata(&path).unwrap().len(), 0, "nothing was written");
    assert!(!dir.path().join("p.hiccup-wal").exists());
}
