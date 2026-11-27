// SPDX-License-Identifier: AGPL-3.0-or-later

//! Proxy configuration.

use std::net::SocketAddr;
use std::time::Duration;

use hiccup_http::Limits;

use crate::{HostPattern, UpstreamConfig};

/// Configuration of a [`crate::Proxy`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyConfig {
    /// Addresses to listen on. Port `0` picks a free port; see
    /// [`crate::Proxy::local_addrs`].
    pub listen: Vec<SocketAddr>,
    /// Parser limits for requests and responses.
    pub limits: Limits,
    /// Maximum time to establish an upstream TCP connection.
    pub connect_timeout: Duration,
    /// Maximum time to wait for the next request on an idle client
    /// connection.
    pub idle_timeout: Duration,
    /// Maximum time between two reads while a message is being received.
    pub read_timeout: Duration,
    /// How long in-flight exchanges may continue after shutdown is requested.
    pub shutdown_grace: Duration,
    /// Hosts whose `CONNECT` tunnels are relayed without TLS interception,
    /// for example clients that pin certificates. Only relevant when a CA is
    /// set with [`crate::Proxy::intercept_tls`].
    pub tls_passthrough: Vec<HostPattern>,
    /// How to connect to upstream servers.
    pub upstream: UpstreamConfig,
}

impl ProxyConfig {
    /// The default listen address, `127.0.0.1:8080`.
    pub const DEFAULT_LISTEN: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 8080);
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: vec![Self::DEFAULT_LISTEN],
            limits: Limits::DEFAULT,
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(60),
            read_timeout: Duration::from_secs(60),
            shutdown_grace: Duration::from_secs(5),
            tls_passthrough: Vec::new(),
            upstream: UpstreamConfig::default(),
        }
    }
}
