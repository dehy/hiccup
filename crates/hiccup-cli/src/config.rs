// SPDX-License-Identifier: AGPL-3.0-or-later

//! `hiccup config`: defaults for flags, in `config.json` in the data
//! directory. Flags given on the command line win.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Subcommand;
use serde_json::{Map, Value};

/// The keys, and what they set.
const KEYS: &[(&str, &str)] = &[
    (
        "project",
        "the project file an instance started here records history in (--project)",
    ),
    (
        "proxy.listen",
        "the addresses `proxy start` listens on, comma-separated (--listen)",
    ),
    (
        "proxy.verify-upstream",
        "whether `proxy start` verifies upstream certificates: true or false (--verify-upstream)",
    ),
];

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Show one setting, or all of them.
    Get {
        /// The key; without it, every setting and the keys that exist.
        key: Option<String>,
    },
    /// Set a default.
    Set {
        /// The key (see `hiccup config get`).
        key: String,
        /// The value.
        value: String,
    },
    /// Go back to the built-in default.
    Unset {
        /// The key.
        key: String,
    },
}

/// The settings saved in the data directory.
#[derive(Debug, Default)]
pub struct Config(Map<String, Value>);

impl Config {
    fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("config.json")
    }

    /// The saved settings; none if there is no file yet.
    ///
    /// # Errors
    ///
    /// The file cannot be read or is not a JSON object: the message says so.
    pub fn load(data_dir: &Path) -> Result<Self, String> {
        let path = Self::path(data_dir);
        match std::fs::read(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("cannot read {}: {e}", path.display())),
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Self)
                .map_err(|e| format!("{} is not valid: {e}", path.display())),
        }
    }

    fn save(&self, data_dir: &Path) -> Result<(), String> {
        let path = Self::path(data_dir);
        let fail = |e: std::io::Error| format!("cannot write {}: {e}", path.display());
        std::fs::create_dir_all(data_dir).map_err(fail)?;
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let json = serde_json::to_vec_pretty(&self.0).expect("JSON serializes");
        std::fs::write(&tmp, json).map_err(fail)?;
        std::fs::rename(&tmp, &path).map_err(fail)
    }

    /// `project`.
    pub fn project(&self) -> Option<PathBuf> {
        self.0.get("project")?.as_str().map(PathBuf::from)
    }

    /// `proxy.listen`; empty if unset.
    pub fn listen(&self) -> Vec<SocketAddr> {
        let Some(Value::Array(addrs)) = self.0.get("proxy.listen") else {
            return Vec::new();
        };
        addrs
            .iter()
            .filter_map(|a| a.as_str()?.parse().ok())
            .collect()
    }

    /// `proxy.verify-upstream`.
    pub fn verify_upstream(&self) -> bool {
        self.0
            .get("proxy.verify-upstream")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }
}

/// The value to store for `key`, or why `value` is not one.
fn parse(key: &str, value: &str) -> Result<Value, String> {
    match key {
        // Stored absolute: it is used from wherever an instance is started.
        "project" => std::path::absolute(value)
            .map(|p| Value::String(p.display().to_string()))
            .map_err(|e| format!("invalid path {value:?}: {e}")),
        "proxy.listen" => value
            .split(',')
            .map(|a| {
                a.trim()
                    .parse::<SocketAddr>()
                    .map(|a| Value::String(a.to_string()))
                    .map_err(|_| format!("invalid address {a:?}, expected e.g. 127.0.0.1:8080"))
            })
            .collect::<Result<_, _>>()
            .map(Value::Array),
        "proxy.verify-upstream" => value
            .parse::<bool>()
            .map(Value::Bool)
            .map_err(|_| format!("invalid value {value:?}: expected true or false")),
        _ => Err(unknown(key)),
    }
}

fn unknown(key: &str) -> String {
    let keys: Vec<_> = KEYS.iter().map(|(k, _)| *k).collect();
    format!("unknown key {key:?}; the keys are: {}", keys.join(", "))
}

pub fn run(command: ConfigCommand, data_dir: &Path, json: bool) -> ExitCode {
    let mut config = match Config::load(data_dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hiccup: {e}");
            return ExitCode::FAILURE;
        }
    };
    let saved = match command {
        ConfigCommand::Get { key: None } => {
            if json {
                crate::print_json(&Value::Object(config.0));
            } else {
                for (key, about) in KEYS {
                    let value = config
                        .0
                        .get(*key)
                        .map_or_else(|| "(not set)".to_owned(), show);
                    println!("{key} = {value}\n    {about}");
                }
            }
            return ExitCode::SUCCESS;
        }
        ConfigCommand::Get { key: Some(key) } => {
            if !KEYS.iter().any(|(k, _)| *k == key) {
                eprintln!("hiccup: {}", unknown(&key));
                return ExitCode::from(2);
            }
            match config.0.get(&key) {
                Some(value) if json => crate::print_json(value),
                Some(value) => println!("{}", show(value)),
                None if json => crate::print_json(&Value::Null),
                None => println!("(not set)"),
            }
            return ExitCode::SUCCESS;
        }
        ConfigCommand::Set { key, value } => match parse(&key, &value) {
            Ok(value) => {
                config.0.insert(key, value);
                config.save(data_dir)
            }
            Err(e) => {
                eprintln!("hiccup: {e}");
                return ExitCode::from(2);
            }
        },
        ConfigCommand::Unset { key } => {
            if !KEYS.iter().any(|(k, _)| *k == key) {
                eprintln!("hiccup: {}", unknown(&key));
                return ExitCode::from(2);
            }
            config.0.remove(&key);
            config.save(data_dir)
        }
    };
    match saved {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hiccup: {e}");
            ExitCode::FAILURE
        }
    }
}

/// A value as the user typed it.
fn show(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(show).collect::<Vec<_>>().join(","),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_checked_and_read_back() {
        assert_eq!(
            parse("proxy.listen", "127.0.0.1:8081, [::1]:8081").unwrap(),
            serde_json::json!(["127.0.0.1:8081", "[::1]:8081"])
        );
        assert!(
            parse("proxy.listen", "nope")
                .unwrap_err()
                .contains("invalid address")
        );
        assert_eq!(
            parse("proxy.verify-upstream", "true").unwrap(),
            Value::Bool(true)
        );
        assert!(parse("proxy.verify-upstream", "yes").is_err());
        assert!(
            parse("colour", "x")
                .unwrap_err()
                .contains("the keys are: project")
        );
        let project = parse("project", "work.hiccup").unwrap();
        assert!(Path::new(project.as_str().unwrap()).is_absolute());

        let mut config = Config::default();
        assert_eq!(
            (config.project(), config.listen(), config.verify_upstream()),
            (None, Vec::new(), false)
        );
        config.0.insert(
            "proxy.listen".into(),
            parse("proxy.listen", "127.0.0.1:1").unwrap(),
        );
        config
            .0
            .insert("proxy.verify-upstream".into(), Value::Bool(true));
        assert_eq!(
            config.listen(),
            ["127.0.0.1:1".parse::<SocketAddr>().unwrap()]
        );
        assert!(config.verify_upstream());
        assert_eq!(show(&config.0["proxy.listen"]), "127.0.0.1:1");
    }
}
