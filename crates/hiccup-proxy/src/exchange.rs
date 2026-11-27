// SPDX-License-Identifier: AGPL-3.0-or-later

//! The record of one proxied request/response exchange.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use hiccup_http::{Request, Response};

/// A change Hiccup made to a message before forwarding it. Every change is
/// recorded: nothing is altered silently (ADR 0003).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Modification {
    /// An absolute-form request target was rewritten to origin-form for the
    /// origin server (RFC 9112 §3.2.1).
    TargetRewritten {
        /// The target as received, e.g. `http://example.com/a`.
        original: Bytes,
        /// The target as forwarded, e.g. `/a`.
        rewritten: Bytes,
    },
    /// The user edited the request in the intercept queue: `forwarded` holds
    /// the edited bytes.
    RequestEdited,
    /// The user edited the response in the intercept queue:
    /// [`Exchange::delivered`] holds the bytes sent to the client.
    ResponseEdited,
}

/// One request and its response, as seen by the proxy.
#[derive(Clone, Debug)]
pub struct Exchange {
    /// When the request was received in full.
    pub started: SystemTime,
    /// From `started` until the exchange completed, including any time held
    /// in the intercept queue.
    pub duration: Duration,
    /// The client's address.
    pub client: SocketAddr,
    /// The upstream `host:port`.
    pub upstream: String,
    /// Whether the exchange was decrypted from an intercepted TLS tunnel
    /// (`https`), rather than received as a plain proxy request (`http`).
    pub tls: bool,
    /// The request exactly as received from the client.
    pub received: Request,
    /// The bytes forwarded upstream.
    pub forwarded: Bytes,
    /// Changes between `received` and `forwarded`.
    pub modifications: Vec<Modification>,
    /// Interim (1xx) responses relayed before the final response.
    pub interim: Vec<Response>,
    /// The final response as received from upstream, or `None` if the
    /// exchange failed before one arrived.
    pub response: Option<Response>,
    /// The bytes sent to the client instead of `response`, when the user
    /// edited it.
    pub delivered: Option<Bytes>,
    /// Why the exchange failed, if it did. Hiccup then answered the client
    /// with an error response of its own.
    pub error: Option<String>,
}

/// Called with every completed exchange. It runs on the connection's task:
/// keep it fast (for example, send to a channel).
pub type ExchangeObserver = Arc<dyn Fn(&Exchange) + Send + Sync>;
