// SPDX-License-Identifier: AGPL-3.0-or-later

//! Another local user cannot connect to an instance (ADR 0004).
//!
//! Connects as `nobody` with `sudo -n`, which CI runners allow. Skipped where
//! `sudo` needs a password.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use hiccup_control::Registry;

/// Tries to connect to the Unix socket at `path`, as `user` if given.
/// Returns Python's error name, or `"ok"`.
fn connect_as(user: Option<&str>, path: &Path) -> String {
    let script = "import socket,sys\n\
                  s=socket.socket(socket.AF_UNIX)\n\
                  try:\n  s.connect(sys.argv[1]); print('ok')\n\
                  except OSError as e: print(type(e).__name__)";
    let mut cmd = match user {
        Some(user) => {
            let mut c = Command::new("sudo");
            c.args(["-n", "-u", user, "python3"]);
            c
        }
        None => Command::new("python3"),
    };
    let out = cmd.arg("-c").arg(script).arg(path).output().unwrap();
    assert!(out.status.success(), "{out:?}");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn can_sudo_as_nobody() -> bool {
    Command::new("sudo")
        .args(["-n", "-u", "nobody", "true"])
        .output()
        .is_ok_and(|o| o.status.success())
        && Command::new("python3").arg("--version").output().is_ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn another_user_cannot_connect() {
    if !can_sudo_as_nobody() {
        eprintln!("cannot run commands as nobody without a password; skipping");
        return;
    }
    // In /tmp, so that only Hiccup's own permissions protect the socket.
    let base = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
    fs::set_permissions(base.path(), fs::Permissions::from_mode(0o711)).unwrap();
    let registry = Registry::new(base.path().join("run"));
    let registration = registry.register("guarded").await.unwrap();
    let socket = Path::new(&registration.record().endpoint).to_owned();

    // Control: the owner can connect.
    assert_eq!(connect_as(None, &socket), "ok");
    // The 0700 directory stops other users.
    assert_eq!(connect_as(Some("nobody"), &socket), "PermissionError");

    // So does the 0600 socket alone, if the directory is opened up.
    fs::set_permissions(registry.dir(), fs::Permissions::from_mode(0o711)).unwrap();
    assert_eq!(connect_as(Some("nobody"), &socket), "PermissionError");
    eprintln!("another user was refused");
}
