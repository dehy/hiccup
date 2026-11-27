// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared harness for end-to-end tests: `hiccup` processes with private data
//! and runtime directories.

#![allow(dead_code)] // Each test file uses part of it.

use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStderr, Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

pub struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    pub fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    /// A path in the test's private directory.
    pub fn path(&self, name: &str) -> std::path::PathBuf {
        self.dir.path().join(name)
    }

    pub fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hiccup"));
        cmd.arg("--data-dir")
            .arg(self.dir.path().join("data"))
            .arg("--runtime-dir")
            .arg(self.dir.path().join("run"))
            .env_remove("HICCUP_DATA_DIR")
            .env_remove("HICCUP_RUNTIME_DIR")
            .env_remove("HICCUP_INSTANCE");
        cmd
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }

    pub fn json(&self, args: &[&str]) -> Value {
        let out = self.command().arg("--json").args(args).output().unwrap();
        assert!(out.status.success(), "{args:?}: {out:?}");
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// Spawns a long-running command and waits until stderr has a line
    /// containing `ready`.
    #[allow(clippy::zombie_processes)] // The caller waits for the returned child.
    pub fn spawn(&self, args: &[&str], ready: &str) -> (Child, BufReader<ChildStderr>) {
        let mut child = self
            .command()
            .args(args)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stderr = BufReader::new(child.stderr.take().unwrap());
        loop {
            let mut line = String::new();
            if stderr.read_line(&mut line).unwrap() == 0 {
                let status = child.wait();
                panic!("{args:?} exited: {status:?}");
            }
            if line.contains(ready) {
                return (child, stderr);
            }
        }
    }
}

pub fn wait_exit(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < deadline, "the instance did not exit");
        std::thread::sleep(Duration::from_millis(50));
    }
}
