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
    /// Describe the intercept settings.
    pub const INTERCEPT_STATUS: &str = "intercept.status";
    /// Replace the intercept settings.
    pub const INTERCEPT_SET: &str = "intercept.set";
    /// List held items.
    pub const INTERCEPT_LIST: &str = "intercept.list";
    /// Show one held item, with its bytes.
    pub const INTERCEPT_SHOW: &str = "intercept.show";
    /// Forward a held item, possibly edited.
    pub const INTERCEPT_FORWARD: &str = "intercept.forward";
    /// Drop a held item.
    pub const INTERCEPT_DROP: &str = "intercept.drop";
    /// Forward every held item unchanged.
    pub const INTERCEPT_FORWARD_ALL: &str = "intercept.forward_all";
    /// List the scope rules.
    pub const SCOPE_LIST: &str = "scope.list";
    /// Add a scope rule.
    pub const SCOPE_ADD: &str = "scope.add";
    /// Remove a scope rule.
    pub const SCOPE_REMOVE: &str = "scope.remove";
    /// Tell whether a URL is in scope.
    pub const SCOPE_TEST: &str = "scope.test";
    /// Receive events on this connection.
    pub const EVENTS_SUBSCRIBE: &str = "events.subscribe";
    /// List recorded exchanges.
    pub const HISTORY_LIST: &str = "history.list";
    /// Show one recorded exchange, with its bytes.
    pub const HISTORY_SHOW: &str = "history.show";
}

/// Notification names.
pub mod notification {
    /// The instance is about to stop.
    pub const INSTANCE_STOPPING: &str = "instance.stopping";
    /// A request was received.
    pub const EXCHANGE_REQUEST: &str = "exchange.request";
    /// An exchange completed.
    pub const EXCHANGE_RESPONSE: &str = "exchange.response";
    /// A message is held in the intercept queue.
    pub const INTERCEPT_PENDING: &str = "intercept.pending";
    /// A held message left the intercept queue.
    pub const INTERCEPT_RESOLVED: &str = "intercept.resolved";
    /// The proxy started or stopped.
    pub const PROXY_STATE: &str = "proxy.state";
    /// The subscriber fell behind and missed events; the connection closes.
    pub const EVENTS_LAGGED: &str = "events.lagged";
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
    /// The project file history is recorded in, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
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

/// Which exchanges to intercept in one direction. Every non-empty criterion
/// must match the request.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InterceptRulesParams {
    /// Host patterns (`example.com`, `*.example.com`, `*`); empty: any.
    pub hosts: Vec<String>,
    /// Methods; empty: any. Matched case-insensitively.
    pub methods: Vec<String>,
    /// A regular expression matched against the request target (path and
    /// query). Absent: any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Only what is in scope (see `scope.add`).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub in_scope: bool,
}

/// Parameters of `intercept.set`, and the result of `intercept.status`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InterceptSettingsParams {
    /// Request rules; `null` turns request interception off.
    pub requests: Option<InterceptRulesParams>,
    /// Response rules; `null` turns response interception off.
    pub responses: Option<InterceptRulesParams>,
    /// How long an item may wait, in milliseconds; `null`: forever.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// What happens on timeout: `"forward"` (default) or `"drop"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_timeout: Option<String>,
}

/// Result of `intercept.status` and `intercept.set`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterceptStatus {
    /// The settings.
    #[serde(flatten)]
    pub settings: InterceptSettingsParams,
    /// How many items are held.
    pub pending: usize,
}

/// A held item, without its bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingSummary {
    /// Its ID.
    pub id: u64,
    /// `"request"` or `"response"`.
    pub direction: String,
    /// The upstream `host:port`.
    pub upstream: String,
    /// Whether it is in an intercepted TLS tunnel.
    pub tls: bool,
    /// The request method.
    pub method: String,
    /// The request target.
    pub target: String,
    /// The response status, for responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Size of the held message, in bytes.
    pub size: usize,
    /// How long it has been held, in milliseconds.
    pub age_ms: u64,
}

/// Result of `intercept.show`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingItem {
    /// The summary.
    #[serde(flatten)]
    pub summary: PendingSummary,
    /// The exact bytes that would be sent, base64-encoded (RFC 4648).
    pub raw: String,
}

/// Parameters naming one held item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemParams {
    /// The item ID.
    pub id: u64,
}

/// Parameters of `intercept.forward`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardParams {
    /// The item ID.
    pub id: u64,
    /// Replacement bytes, base64-encoded, sent exactly. Absent: unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

/// Result of `intercept.forward_all`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardAllResult {
    /// How many items were forwarded.
    pub forwarded: usize,
}

/// One scope rule. Every criterion set must match.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScopeRuleParams {
    /// Excludes what the rule matches, instead of including it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub exclude: bool,
    /// `"http"` or `"https"`. Absent: both.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// A host pattern (`example.com`, `*.example.com`, `*`). Absent: any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The port. Absent: any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// A regular expression matched against the path and query. Absent: any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Result of `scope.list`, `scope.add` and `scope.remove`. In scope is what
/// matches an include rule and no exclude rule; with no include rule,
/// everything not excluded is in scope.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRules {
    /// The rules, in the order they were added.
    pub rules: Vec<ScopeRuleParams>,
}

/// Parameters of `scope.remove`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeRemoveParams {
    /// The rule's index in `rules`, from 0.
    pub index: usize,
}

/// Parameters of `scope.test`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeTestParams {
    /// An `http://` or `https://` URL.
    pub url: String,
}

/// Result of `scope.test`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeTestResult {
    /// Whether the URL is in scope.
    pub in_scope: bool,
}

/// Parameters of `history.list`. Every criterion set must match.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HistoryListParams {
    /// The host, exactly (ignoring case).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The request method, exactly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The response status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// A prefix of the response's media type: `image/` matches `image/png`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    /// Text found in the request or the response (bytes, case-sensitive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    /// Only exchanges in scope (see `scope.add`).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub in_scope: bool,
    /// Only exchanges older than this ID: the last one of the previous page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<u64>,
    /// At most this many (default 100, at most 1000).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// A recorded exchange, without its messages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistorySummary {
    /// Its ID in the project: higher is newer.
    pub id: u64,
    /// When the request was received in full, in milliseconds since the
    /// Unix epoch.
    pub started_ms: u64,
    /// How long the exchange took, in milliseconds.
    pub duration_ms: u64,
    /// The client's address.
    pub client: String,
    /// The upstream `host:port`.
    pub upstream: String,
    /// Whether it was decrypted from an intercepted TLS tunnel.
    pub tls: bool,
    /// The request method.
    pub method: String,
    /// The request target, as received.
    pub target: String,
    /// The response status, if a response arrived.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// The response's media type, lowercase, without parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    /// Size of the request as received, in bytes.
    pub request_size: u64,
    /// Size of the response as kept, in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_size: Option<u64>,
    /// Only the start of a very large response body was kept.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub response_truncated: bool,
    /// The user edited the request in the intercept queue.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub request_edited: bool,
    /// The user edited the response in the intercept queue.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub response_edited: bool,
    /// Why the exchange failed, if it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Result of `history.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryPage {
    /// Newest first.
    pub items: Vec<HistorySummary>,
}

/// Result of `history.show`. Messages are base64-encoded (RFC 4648).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryItem {
    /// The summary.
    #[serde(flatten)]
    pub summary: HistorySummary,
    /// The request exactly as received.
    pub received: String,
    /// The bytes forwarded upstream.
    pub forwarded: String,
    /// Interim (1xx) responses, concatenated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interim: Option<String>,
    /// The response exactly as received, if one arrived.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    /// The bytes sent to the client instead, when the user edited them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivered: Option<String>,
}

/// `exchange.request`: a request was received, before it is held or
/// forwarded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExchangeRequestEvent {
    /// Ties it to the `exchange.response` that follows.
    pub id: u64,
    /// The request method.
    pub method: String,
    /// The upstream `host:port`.
    pub upstream: String,
    /// Whether it was decrypted from an intercepted TLS tunnel.
    pub tls: bool,
    /// The request target, as received.
    pub target: String,
}

/// `exchange.response`: an exchange completed, or failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExchangeResponseEvent {
    /// The `exchange.request` this completes.
    pub id: u64,
    /// The response status, if a response arrived.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Size of the response, in bytes. A very large body counts only up to
    /// the part Hiccup keeps of it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// How long the exchange took, in milliseconds.
    pub duration_ms: u64,
    /// Why it failed, if it did (Hiccup answered the client with an error).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `intercept.resolved`: a held message left the queue.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterceptResolvedEvent {
    /// The held item's ID.
    pub id: u64,
    /// `"forwarded"`, `"edited"`, `"dropped"`, or `"abandoned"` (the
    /// connection closed while it was held).
    pub outcome: String,
}

/// `events.lagged`: the subscriber fell behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsLagged {
    /// How many events it missed.
    pub missed: u64,
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

fn example_summary() -> PendingSummary {
    PendingSummary {
        id: 7,
        direction: "request".to_owned(),
        upstream: "example.com:443".to_owned(),
        tls: true,
        method: "POST".to_owned(),
        target: "/api/login".to_owned(),
        status: None,
        size: 412,
        age_ms: 1500,
    }
}

fn example_intercept() -> InterceptStatus {
    InterceptStatus {
        settings: InterceptSettingsParams {
            requests: Some(InterceptRulesParams {
                hosts: vec!["*.example.com".to_owned()],
                methods: vec!["POST".to_owned()],
                path: Some("^/api/".to_owned()),
                in_scope: true,
            }),
            responses: None,
            timeout_ms: None,
            on_timeout: None,
        },
        pending: 1,
    }
}

fn example_history() -> HistorySummary {
    HistorySummary {
        id: 42,
        started_ms: 1_764_000_000_000,
        duration_ms: 87,
        client: "127.0.0.1:52344".to_owned(),
        upstream: "example.com:443".to_owned(),
        tls: true,
        method: "GET".to_owned(),
        target: "/api/items?page=2".to_owned(),
        status: Some(200),
        mime: Some("application/json".to_owned()),
        request_size: 412,
        response_size: Some(5321),
        response_truncated: false,
        request_edited: false,
        response_edited: false,
        error: None,
    }
}

const NO_PROJECT: (i64, &str) = (
    -32001,
    "no project is open (start the instance with --project)",
);

fn example_scope() -> ScopeRules {
    ScopeRules {
        rules: vec![
            ScopeRuleParams {
                host: Some("*.example.com".to_owned()),
                protocol: Some("https".to_owned()),
                ..ScopeRuleParams::default()
            },
            ScopeRuleParams {
                exclude: true,
                path: Some("^/logout".to_owned()),
                ..ScopeRuleParams::default()
            },
        ],
    }
}

const NOT_FOUND: &[(i64, &str)] = &[(-32001, "no held item has this ID (resolved or timed out)")];

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
                project: Some("/home/me/work/acme.hiccup".to_owned()),
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
    MessageDoc {
        name: method::INTERCEPT_STATUS,
        summary: "Describe the intercept settings. They belong to the instance and apply to its \
                  proxy whenever it runs.",
        params: || json!({}),
        result: || to_value(&example_intercept()),
        errors: &[],
    },
    MessageDoc {
        name: method::INTERCEPT_SET,
        summary: "Replace the intercept settings. Items held in a direction that is turned off \
                  are forwarded unchanged.",
        params: || to_value(&example_intercept().settings),
        result: || to_value(&example_intercept()),
        errors: &[(
            -32602,
            "a host pattern, regular expression or timeout is invalid",
        )],
    },
    MessageDoc {
        name: method::INTERCEPT_LIST,
        summary: "List the held items, oldest first.",
        params: || json!({}),
        result: || json!([to_value(&example_summary())]),
        errors: &[],
    },
    MessageDoc {
        name: method::INTERCEPT_SHOW,
        summary: "Show one held item with the exact bytes that would be sent.",
        params: || to_value(&ItemParams { id: 7 }),
        result: || {
            to_value(&PendingItem {
                summary: example_summary(),
                raw: "UE9TVCAvYXBpL2xvZ2luIEhUVFAvMS4xDQo…".to_owned(),
            })
        },
        errors: NOT_FOUND,
    },
    MessageDoc {
        name: method::INTERCEPT_FORWARD,
        summary: "Forward a held item. With `raw`, those bytes are sent instead, exactly as \
                  given; an edited response closes the client connection after it.",
        params: || {
            to_value(&ForwardParams {
                id: 7,
                raw: Some("UE9TVCAvYXBpL2xvZ2luIEhUVFAvMS4xDQo…".to_owned()),
            })
        },
        result: || json!({}),
        errors: &[
            (-32001, "no held item has this ID (resolved or timed out)"),
            (-32602, "`raw` is not valid base64"),
        ],
    },
    MessageDoc {
        name: method::INTERCEPT_DROP,
        summary: "Drop a held item. The client gets a 502 response from Hiccup.",
        params: || to_value(&ItemParams { id: 7 }),
        result: || json!({}),
        errors: NOT_FOUND,
    },
    MessageDoc {
        name: method::INTERCEPT_FORWARD_ALL,
        summary: "Forward every held item unchanged.",
        params: || json!({}),
        result: || to_value(&ForwardAllResult { forwarded: 3 }),
        errors: &[],
    },
    MessageDoc {
        name: method::EVENTS_SUBSCRIBE,
        summary: "Receive events on this connection, as notifications, until it closes. \
                  Events are buffered: a subscriber that falls too far behind gets \
                  `events.lagged`, then the connection closes; reconnect and subscribe \
                  again (state such as held items can be listed afresh).",
        params: || json!({}),
        result: || json!({}),
        errors: &[],
    },
    MessageDoc {
        name: method::HISTORY_LIST,
        summary: "List recorded exchanges, newest first. History is recorded when the \
                  instance has a project (`hiccup serve --project FILE`).",
        params: || {
            to_value(&HistoryListParams {
                host: Some("example.com".to_owned()),
                status: Some(200),
                limit: Some(50),
                ..HistoryListParams::default()
            })
        },
        result: || {
            to_value(&HistoryPage {
                items: vec![example_history()],
            })
        },
        errors: &[NO_PROJECT, (-32602, "`limit` is above 1000")],
    },
    MessageDoc {
        name: method::HISTORY_SHOW,
        summary: "Show one recorded exchange with its exact bytes.",
        params: || to_value(&ItemParams { id: 42 }),
        result: || {
            to_value(&HistoryItem {
                summary: example_history(),
                received: "R0VUIC9hcGkvaXRlbXM/cGFnZT0yIEhUVFAvMS4xDQo…".to_owned(),
                forwarded: "R0VUIC9hcGkvaXRlbXM/cGFnZT0yIEhUVFAvMS4xDQo…".to_owned(),
                interim: None,
                response: Some("SFRUUC8xLjEgMjAwIE9LDQo…".to_owned()),
                delivered: None,
            })
        },
        errors: &[NO_PROJECT, (-32602, "no recorded exchange has this ID")],
    },
    MessageDoc {
        name: method::SCOPE_LIST,
        summary: "List the scope rules. They belong to the instance; intercept rules with \
                  `in_scope` use them.",
        params: || json!({}),
        result: || to_value(&example_scope()),
        errors: &[],
    },
    MessageDoc {
        name: method::SCOPE_ADD,
        summary: "Add a scope rule at the end. Returns every rule.",
        params: || to_value(&example_scope().rules[0]),
        result: || to_value(&example_scope()),
        errors: &[(
            -32602,
            "the protocol, host pattern or regular expression is invalid",
        )],
    },
    MessageDoc {
        name: method::SCOPE_REMOVE,
        summary: "Remove a scope rule. Returns the remaining rules.",
        params: || to_value(&ScopeRemoveParams { index: 1 }),
        result: || {
            to_value(&ScopeRules {
                rules: example_scope().rules[..1].to_vec(),
            })
        },
        errors: &[(-32602, "no rule has this index")],
    },
    MessageDoc {
        name: method::SCOPE_TEST,
        summary: "Tell whether a URL is in scope.",
        params: || {
            to_value(&ScopeTestParams {
                url: "https://app.example.com/login".to_owned(),
            })
        },
        result: || to_value(&ScopeTestResult { in_scope: true }),
        errors: &[(-32602, "the URL is not an `http://` or `https://` URL")],
    },
];

/// Every notification an instance sends.
pub const NOTIFICATIONS: &[MessageDoc] = &[
    MessageDoc {
        name: notification::INSTANCE_STOPPING,
        summary: "The instance is stopping; the connection will close. Sent to every \
                  connection.",
        params: || json!({}),
        result: || Value::Null,
        errors: &[],
    },
    MessageDoc {
        name: notification::EXCHANGE_REQUEST,
        summary: "A request was received, before it is held or forwarded. Events from here \
                  on are sent after `events.subscribe` only.",
        params: || {
            to_value(&ExchangeRequestEvent {
                id: 12,
                method: "GET".to_owned(),
                upstream: "example.com:443".to_owned(),
                tls: true,
                target: "/api/items?page=2".to_owned(),
            })
        },
        result: || Value::Null,
        errors: &[],
    },
    MessageDoc {
        name: notification::EXCHANGE_RESPONSE,
        summary: "An exchange completed (its response was relayed in full), or failed.",
        params: || {
            to_value(&ExchangeResponseEvent {
                id: 12,
                status: Some(200),
                size: Some(5321),
                duration_ms: 87,
                error: None,
            })
        },
        result: || Value::Null,
        errors: &[],
    },
    MessageDoc {
        name: notification::INTERCEPT_PENDING,
        summary: "A message is held in the intercept queue (as in `intercept.list`).",
        params: || to_value(&example_summary()),
        result: || Value::Null,
        errors: &[],
    },
    MessageDoc {
        name: notification::INTERCEPT_RESOLVED,
        summary: "A held message left the intercept queue.",
        params: || {
            to_value(&InterceptResolvedEvent {
                id: 7,
                outcome: "edited".to_owned(),
            })
        },
        result: || Value::Null,
        errors: &[],
    },
    MessageDoc {
        name: notification::PROXY_STATE,
        summary: "The proxy started or stopped (as in `proxy.status`).",
        params: || to_value(&example_status()),
        result: || Value::Null,
        errors: &[],
    },
    MessageDoc {
        name: notification::EVENTS_LAGGED,
        summary: "The subscriber fell behind and missed events; the connection closes next.",
        params: || to_value(&EventsLagged { missed: 42 }),
        result: || Value::Null,
        errors: &[],
    },
];

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
            match m.name {
                method::PROXY_START => {
                    drop(serde_json::from_value::<ProxyStartParams>(params).unwrap())
                }
                method::INTERCEPT_SET => {
                    drop(serde_json::from_value::<InterceptSettingsParams>(params).unwrap());
                }
                method::INTERCEPT_FORWARD => {
                    drop(serde_json::from_value::<ForwardParams>(params).unwrap())
                }
                method::HISTORY_LIST => {
                    drop(serde_json::from_value::<HistoryListParams>(params).unwrap());
                }
                method::SCOPE_ADD => {
                    drop(serde_json::from_value::<ScopeRuleParams>(params).unwrap());
                }
                method::SCOPE_REMOVE => {
                    serde_json::from_value::<ScopeRemoveParams>(params).unwrap();
                }
                method::SCOPE_TEST => {
                    drop(serde_json::from_value::<ScopeTestParams>(params).unwrap());
                }
                _ => {}
            }
        }
        // Results whose fields may be left out read back as written.
        let item = to_value(&HistoryItem {
            summary: example_history(),
            received: String::new(),
            forwarded: String::new(),
            interim: None,
            response: None,
            delivered: None,
        });
        assert_eq!(
            serde_json::from_value::<HistoryItem>(item).unwrap().summary,
            example_history()
        );
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
