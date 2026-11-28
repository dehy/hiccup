// SPDX-License-Identifier: AGPL-3.0-or-later

//! The raw request sender: writes exactly the bytes the user wrote to a
//! target set apart from them, and reads the response with the codec.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use hiccup_http::{Framing, Limits, Response};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use crate::UpstreamConfig;
use crate::ca::CaError;
use crate::tls::Clients;

/// Where to send: set apart from the request, whose `Host` header may say
/// anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendTarget {
    /// A host name or IP address.
    pub host: String,
    /// The TCP port.
    pub port: u16,
    /// Whether to speak TLS (HTTPS).
    pub tls: bool,
}

/// How long each step took. A step that did not happen is `None`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timings {
    /// Resolving the host name; `None` for an IP address or a `--resolve`
    /// override.
    pub dns: Option<Duration>,
    /// Opening the TCP connection.
    pub connect: Option<Duration>,
    /// The TLS handshake.
    pub tls: Option<Duration>,
    /// From the end of the request to the first byte of the response.
    pub ttfb: Option<Duration>,
    /// From the start to the end of the exchange, or to the failure.
    pub total: Duration,
}

/// The outcome of a send. On failure, `error` says why, and the other fields
/// hold what happened until then.
#[derive(Clone, Debug)]
pub struct Sent {
    /// The address connected to.
    pub peer: Option<SocketAddr>,
    /// Interim (1xx) responses, before the final one.
    pub interim: Vec<Response>,
    /// The final response.
    pub response: Option<Response>,
    /// Every byte received, as received.
    pub raw_response: Bytes,
    /// How long each step took.
    pub timings: Timings,
    /// Why the send failed, if it did.
    pub error: Option<String>,
}

/// Sends raw requests with the upstream options of the proxy: TLS versions,
/// verification, SNI, `--resolve` and client certificates.
pub struct Sender {
    upstream: UpstreamConfig,
    clients: Clients,
    /// For DNS, the TCP connection, and the TLS handshake, each.
    pub connect_timeout: Duration,
    /// Between two reads of the response.
    pub read_timeout: Duration,
    /// Bounds for parsing the response.
    pub limits: Limits,
}

impl Sender {
    /// A sender with the proxy's default timeouts and limits.
    ///
    /// # Errors
    ///
    /// The TLS options are invalid: an empty version range, or a client
    /// certificate whose key type is not supported.
    pub fn new(upstream: UpstreamConfig) -> Result<Self, CaError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let defaults = crate::ProxyConfig::default();
        Ok(Self {
            clients: Clients::new(&provider, &upstream)?,
            upstream,
            connect_timeout: defaults.connect_timeout,
            read_timeout: defaults.read_timeout,
            limits: defaults.limits,
        })
    }

    // shortcut: the whole response is kept in memory, whatever its size; cap
    // it like the proxy's `max_kept_body` if repeated downloads get large.
    /// Sends `request` to `target`, byte for byte, and reads the response.
    /// `cancel` stops it at any point; the result then says so.
    pub async fn send(
        &self,
        target: &SendTarget,
        request: &[u8],
        cancel: &CancellationToken,
    ) -> Sent {
        let started = Instant::now();
        let mut sent = Sent {
            peer: None,
            interim: Vec::new(),
            response: None,
            raw_response: Bytes::new(),
            timings: Timings::default(),
            error: None,
        };
        let mut raw = BytesMut::new();
        let result = tokio::select! {
            r = self.exchange(target, request, &mut sent, &mut raw) => r,
            () = cancel.cancelled() => Err("cancelled".to_owned()),
        };
        sent.error = result.err();
        sent.raw_response = raw.freeze();
        sent.timings.total = started.elapsed();
        sent
    }

    async fn exchange(
        &self,
        target: &SendTarget,
        request: &[u8],
        sent: &mut Sent,
        raw: &mut BytesMut,
    ) -> Result<(), String> {
        let addrs = self.resolve(target, &mut sent.timings).await?;
        let started = Instant::now();
        let tcp = timeout(self.connect_timeout, TcpStream::connect(&addrs[..]))
            .await
            .map_err(|e| format!("cannot connect to {}: {e}", authority(target)))?;
        sent.timings.connect = Some(started.elapsed());
        sent.peer = tcp.peer_addr().ok();
        let _ = tcp.set_nodelay(true);
        if !target.tls {
            return self.round_trip(tcp, request, sent, raw).await;
        }

        let name = self
            .upstream
            .sni_for(&target.host)
            .unwrap_or(&target.host)
            .to_owned();
        let name = ServerName::try_from(name).map_err(|e| format!("invalid server name: {e}"))?;
        let started = Instant::now();
        let handshake = TlsConnector::from(self.clients.get(&target.host)).connect(name, tcp);
        let tls = timeout(self.connect_timeout, handshake)
            .await
            .map_err(|e| format!("TLS handshake with {} failed: {e}", authority(target)))?;
        sent.timings.tls = Some(started.elapsed());
        self.round_trip(tls, request, sent, raw).await
    }

    /// The addresses to try, from `--resolve` or DNS.
    async fn resolve(
        &self,
        target: &SendTarget,
        timings: &mut Timings,
    ) -> Result<Vec<SocketAddr>, String> {
        let host = target.host.trim_start_matches('[').trim_end_matches(']');
        if let Some(ip) = self
            .upstream
            .resolve_for(&target.host)
            .or_else(|| host.parse().ok())
        {
            return Ok(vec![SocketAddr::new(ip, target.port)]);
        }
        let started = Instant::now();
        let addrs: Vec<_> = timeout(
            self.connect_timeout,
            tokio::net::lookup_host((host, target.port)),
        )
        .await
        .map_err(|e| format!("cannot resolve {host}: {e}"))?
        .collect();
        timings.dns = Some(started.elapsed());
        if addrs.is_empty() {
            return Err(format!("cannot resolve {host}: no address"));
        }
        Ok(addrs)
    }

    async fn round_trip<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut stream: S,
        request: &[u8],
        sent: &mut Sent,
        raw: &mut BytesMut,
    ) -> Result<(), String> {
        stream
            .write_all(request)
            .await
            .and(stream.flush().await)
            .map_err(|e| format!("cannot send the request: {e}"))?;
        let written = Instant::now();
        // The method decides how a response is framed (HEAD); a malformed
        // request may have none.
        let method = request.split(|&b| b == b' ').next().unwrap_or_default();
        let (mut start, mut eof) = (0, false);
        loop {
            // At EOF, parsing never needs more: it returns a response or fails.
            while start < raw.len() {
                let parsed = Response::parse(&raw[start..], method, &self.limits, eof)
                    .map_err(|e| format!("invalid response: {e}"))?;
                let Some(response) = parsed else { break };
                start += response.len();
                let interim = matches!(response.head().status_code(), Some(100..=199))
                    && response.framing().framing != Framing::Tunnel;
                if !interim {
                    sent.response = Some(response);
                    return Ok(());
                }
                sent.interim.push(response);
            }
            if eof {
                return Err("the connection closed without a response".to_owned());
            }
            eof = timeout(self.read_timeout, stream.read_buf(raw))
                .await
                .map_err(|e| format!("cannot read the response: {e}"))?
                == 0;
            if sent.timings.ttfb.is_none() && !raw.is_empty() {
                sent.timings.ttfb = Some(written.elapsed());
            }
        }
    }
}

fn authority(target: &SendTarget) -> String {
    if target.host.contains(':') && !target.host.starts_with('[') {
        format!("[{}]:{}", target.host, target.port)
    } else {
        format!("{}:{}", target.host, target.port)
    }
}

/// Runs `step` with a timeout; both errors become one message.
async fn timeout<T>(
    limit: Duration,
    step: impl Future<Output = std::io::Result<T>>,
) -> Result<T, String> {
    match tokio::time::timeout(limit, step).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("timed out".to_owned()),
    }
}
