// SPDX-License-Identifier: AGPL-3.0-or-later

//! The control API's methods, their parameters and results.
//!
//! [`METHODS`] and [`NOTIFICATIONS`] document every message; the reference in
//! `docs/control-api.md` is generated from them (see [`reference()`]).

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::API_VERSION;

/// Method names.
pub mod method {
    /// Describe the instance.
    pub const INSTANCE_INFO: &str = "instance.info";
    /// Stop the instance.
    pub const INSTANCE_SHUTDOWN: &str = "instance.shutdown";
    /// Start the proxy.
    pub const PROXY_START: &str = "proxy.start";
    /// Stop the proxy.
    pub const PROXY_STOP: &str = "proxy.stop";
    /// Describe the proxy.
    pub const PROXY_STATUS: &str = "proxy.status";
}

/// Notification names.
pub mod notification {
    /// The instance is about to stop.
    pub const INSTANCE_STOPPING: &str = "instance.stopping";
}

/// Result of `instance.info`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceInfo {
    /// The instance name.
    pub name: String,
    /// Its process ID.
    pub pid: u32,
    /// The Hiccup version.
    pub version: String,
    /// The control API version, `MAJOR.MINOR`.
    pub api_version: String,
    /// When the instance started, in seconds since the Unix epoch.
    pub started_at: u64,
}

/// A per-host rule: `host` is a pattern (`example.com`, `*.example.com` or
/// `*`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRule {
    /// Host pattern.
    pub host: String,
    /// The value for matching hosts.
    pub value: String,
}

/// A client certificate rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientCertRule {
    /// Host pattern.
    pub host: String,
    /// Absolute path of a PEM certificate chain, leaf first.
    pub cert: String,
    /// Absolute path of a PEM private key. Absent: read from `cert`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// Parameters of `proxy.start`. Every field is optional.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyStartParams {
    /// Addresses to listen on. Default: `["127.0.0.1:8080"]`.
    pub listen: Vec<String>,
    /// Host patterns whose HTTPS is relayed without interception.
    pub tls_passthrough: Vec<String>,
    /// Verify upstream certificates against the OS trust store.
    pub verify_upstream: bool,
    /// Lowest upstream TLS version, `"1.2"` or `"1.3"`. Default `"1.2"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_tls_min: Option<String>,
    /// Highest upstream TLS version, `"1.2"` or `"1.3"`. Default `"1.3"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_tls_max: Option<String>,
    /// SNI overrides: `value` is the server name.
    pub upstream_sni: Vec<HostRule>,
    /// DNS overrides: `value` is an IP address.
    pub resolve: Vec<HostRule>,
    /// Client certificates presented to matching hosts.
    pub client_certs: Vec<ClientCertRule>,
    /// Upstream connect timeout, in milliseconds. Default 10000.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,
    /// Read timeout, in milliseconds. Default 60000.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_timeout_ms: Option<u64>,
}

impl Default for ProxyStartParams {
    fn default() -> Self {
        Self {
            listen: vec!["127.0.0.1:8080".to_owned()],
            tls_passthrough: Vec::new(),
            verify_upstream: false,
            upstream_tls_min: None,
            upstream_tls_max: None,
            upstream_sni: Vec::new(),
            resolve: Vec::new(),
            client_certs: Vec::new(),
            connect_timeout_ms: None,
            read_timeout_ms: None,
        }
    }
}

/// The proxy's state: the result of `proxy.status` and `proxy.stop`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyStatus {
    /// Whether the proxy is running.
    pub running: bool,
    /// The addresses it listens on.
    pub listen: Vec<String>,
    /// Whether upstream certificates are verified.
    pub verify_upstream: bool,
    /// Exchanges completed since it started.
    pub exchanges: u64,
}

/// Result of `proxy.start`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyStartResult {
    /// The new state.
    pub proxy: ProxyStatus,
    /// Whether a CA was generated for this start: the user must install it.
    pub ca_generated: bool,
    /// SHA-256 fingerprint of the CA certificate, as `AB:CD:…`.
    pub ca_sha256: String,
}

/// Documentation of one method or notification.
#[derive(Clone, Copy, Debug)]
pub struct MessageDoc {
    /// Its name.
    pub name: &'static str,
    /// What it does.
    pub summary: &'static str,
    /// Example parameters.
    pub params: fn() -> Value,
    /// Example result (`Value::Null` for notifications).
    pub result: fn() -> Value,
    /// Errors it can return, as `(code, when)`.
    pub errors: &'static [(i64, &'static str)],
}

fn to_value<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("API types serialize")
}

fn example_status() -> ProxyStatus {
    ProxyStatus {
        running: true,
        listen: vec!["127.0.0.1:8080".to_owned()],
        verify_upstream: false,
        exchanges: 42,
    }
}

/// Every method.
pub const METHODS: &[MessageDoc] = &[
    MessageDoc {
        name: method::INSTANCE_INFO,
        summary: "Describe the instance. Clients call it first to check `api_version`.",
        params: || json!({}),
        result: || {
            to_value(&InstanceInfo {
                name: "default".to_owned(),
                pid: 4242,
                version: "0.1.0".to_owned(),
                api_version: API_VERSION.to_owned(),
                started_at: 1_790_000_000,
            })
        },
        errors: &[],
    },
    MessageDoc {
        name: method::INSTANCE_SHUTDOWN,
        summary: "Stop the instance, and its proxy. Connected clients first get an \
                  `instance.stopping` notification.",
        params: || json!({}),
        result: || json!({}),
        errors: &[],
    },
    MessageDoc {
        name: method::PROXY_START,
        summary: "Start the proxy with TLS interception, loading the CA (or generating it on \
                  first use). Every parameter is optional; paths must be absolute.",
        params: || {
            to_value(&ProxyStartParams {
                tls_passthrough: vec!["*.mozilla.com".to_owned()],
                resolve: vec![HostRule {
                    host: "app.test".to_owned(),
                    value: "10.0.0.5".to_owned(),
                }],
                client_certs: vec![ClientCertRule {
                    host: "*.corp.test".to_owned(),
                    cert: "/home/me/client.pem".to_owned(),
                    key: None,
                }],
                read_timeout_ms: Some(30_000),
                ..ProxyStartParams::default()
            })
        },
        result: || {
            to_value(&ProxyStartResult {
                proxy: ProxyStatus {
                    exchanges: 0,
                    ..example_status()
                },
                ca_generated: false,
                ca_sha256: "B3:F7:03:…:92:43".to_owned(),
            })
        },
        errors: &[
            (
                -32602,
                "a parameter is invalid (address, pattern, TLS version, file)",
            ),
            (-32001, "the proxy is already running"),
            (
                -32000,
                "an address cannot be bound, or the CA cannot be loaded",
            ),
        ],
    },
    MessageDoc {
        name: method::PROXY_STOP,
        summary: "Stop the proxy. In-flight exchanges get a short grace period.",
        params: || json!({}),
        result: || to_value(&ProxyStatus::default()),
        errors: &[(-32001, "the proxy is not running")],
    },
    MessageDoc {
        name: method::PROXY_STATUS,
        summary: "Describe the proxy.",
        params: || json!({}),
        result: || to_value(&example_status()),
        errors: &[],
    },
];

/// Every notification an instance sends.
pub const NOTIFICATIONS: &[MessageDoc] = &[MessageDoc {
    name: notification::INSTANCE_STOPPING,
    summary: "The instance is stopping; the connection will close.",
    params: || json!({}),
    result: || Value::Null,
    errors: &[],
}];

/// Renders the API reference (Markdown).
#[must_use]
pub fn reference() -> String {
    let pretty = |v: &Value| serde_json::to_string_pretty(v).expect("serializes");
    let mut out = String::new();
    let _ = write!(
        out,
        "# Control API reference\n\n\
         <!-- Generated by `cargo test -p hiccup-control`: edit \
         crates/hiccup-control/src/api.rs, then run it with HICCUP_BLESS=1. -->\n\n\
         API version **{API_VERSION}**. Hiccup instances (`hiccup serve`, `hiccup proxy start \
         --foreground`, the desktop apps) accept [JSON-RPC 2.0](https://www.jsonrpc.org/specification) \
         requests, one JSON object per line, on a local socket: a Unix domain socket \
         (mode `0600`, in a `0700` directory) on Linux and macOS, and a named pipe \
         restricted to the current user on Windows. See [ADR 0004](adr/0004-cli-control-plane.md).\n\n\
         Instances register in the per-user runtime directory (`$XDG_RUNTIME_DIR/hiccup` on \
         Linux, `hiccup/run` in the local data directory elsewhere): `<name>.json` gives the \
         instance's endpoint. The directory must be private to the user: on Unix, clients refuse one \
         that other users can access, as they could plant records pointing to their own \
         endpoints.\n\n\
         Clients call `instance.info` first and refuse an instance whose major `api_version` \
         differs. Minor versions only add methods, fields and notifications.\n\n\
         Errors use the JSON-RPC codes (-32700 parse error, -32600 invalid request, -32601 \
         unknown method, -32602 invalid parameters, -32603 internal error) and Hiccup's: \
         -32000 the operation failed, -32001 it conflicts with the current state.\n\n\
         ## Methods\n"
    );
    for m in METHODS {
        let _ = write!(
            out,
            "\n### `{}`\n\n{}\n\nParameters:\n\n```json\n{}\n```\n\nResult:\n\n```json\n{}\n```\n",
            m.name,
            m.summary,
            pretty(&(m.params)()),
            pretty(&(m.result)())
        );
        if !m.errors.is_empty() {
            out.push_str("\nErrors:\n\n");
            for (code, when) in m.errors {
                let _ = writeln!(out, "- `{code}`: {when}");
            }
        }
    }
    out.push_str("\n## Notifications\n");
    for n in NOTIFICATIONS {
        let _ = write!(
            out,
            "\n### `{}`\n\n{}\n\nParameters:\n\n```json\n{}\n```\n",
            n.name,
            n.summary,
            pretty(&(n.params)())
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn examples_match_the_types() {
        for m in METHODS {
            let params = (m.params)();
            if m.name == method::PROXY_START {
                serde_json::from_value::<ProxyStartParams>(params).unwrap();
            }
        }
        let start: ProxyStartParams = serde_json::from_value(json!({})).unwrap();
        assert_eq!(start, ProxyStartParams::default());
        assert!(serde_json::from_value::<ProxyStartParams>(json!({"lisen": []})).is_err());
    }

    /// `docs/control-api.md` is generated: run with `HICCUP_BLESS=1` to
    /// update it.
    #[test]
    fn reference_is_up_to_date() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/control-api.md");
        let expected = reference();
        if std::env::var_os("HICCUP_BLESS").is_some() {
            std::fs::write(path, &expected).unwrap();
        }
        let actual = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            actual.replace("\r\n", "\n") == expected,
            "docs/control-api.md is out of date: run `HICCUP_BLESS=1 cargo test -p hiccup-control`"
        );
    }
}
