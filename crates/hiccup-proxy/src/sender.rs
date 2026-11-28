// SPDX-License-Identifier: AGPL-3.0-or-later

//! The raw request sender: writes exactly the bytes the user wrote to a
//! target set apart from them, and reads the response with the codec.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use hiccup_http::{Framing, Limits, RequestHead, Response};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use crate::ca::CaError;
use crate::connection::{is_idempotent, keep_alive};
use crate::helpers::{redirect, update_content_length};
use crate::io::Io;
use crate::tls::Clients;
use crate::{Scheme, Scope, ScopeTarget, UpstreamConfig};

/// Opt-in conveniences. With the default, all off, the bytes sent are the
/// bytes given, exactly.
#[derive(Clone, Debug, Default)]
pub struct Helpers {
    /// Set `Content-Length` to the length of the body (or add it).
    pub update_content_length: bool,
    /// Which redirects to follow.
    pub redirects: Redirects,
    /// How many redirects to follow at most.
    pub max_redirects: u8,
    /// Keep the connection open for the next send to the same target.
    pub reuse_connection: bool,
}

/// Which redirects to follow.
#[derive(Clone, Debug, Default)]
pub enum Redirects {
    /// None: the redirect is the response.
    #[default]
    Never,
    /// Every redirect.
    Always,
    /// Redirects to URLs in this scope.
    InScope(Scope),
}

/// A helper that changed a send, so that it can be shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    /// `Content-Length` was set to the length of the body.
    ContentLengthUpdated,
    /// This request follows a redirect from the previous one.
    FollowedRedirect,
    /// The connection of an earlier send was reused.
    ReusedConnection,
}

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
    /// Where the request went.
    pub target: SendTarget,
    /// The bytes sent.
    pub request: Bytes,
    /// The helpers that changed this send.
    pub applied: Vec<Applied>,
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

/// An open connection, with its target and peer address.
type Idle = (SendTarget, Option<SocketAddr>, Box<dyn Io>);

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
    /// A connection kept for [`Helpers::reuse_connection`].
    idle: Mutex<Option<Idle>>,
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
            idle: Mutex::new(None),
        })
    }

    // shortcut: the whole response is kept in memory, whatever its size; cap
    // it like the proxy's `max_kept_body` if repeated downloads get large.
    /// Sends `request` to `target` and reads the response. Without helpers,
    /// the bytes sent are `request`, exactly. Returns one [`Sent`] per
    /// request: the first, then one per redirect followed. `cancel` stops it
    /// at any point; the last [`Sent`] then says so.
    pub async fn send(
        &self,
        target: &SendTarget,
        request: &[u8],
        helpers: &Helpers,
        cancel: &CancellationToken,
    ) -> Vec<Sent> {
        let (max_hops, scope) = match &helpers.redirects {
            Redirects::Never => (0, None),
            Redirects::Always => (helpers.max_redirects, None),
            Redirects::InScope(scope) => (helpers.max_redirects, Some(scope)),
        };
        let mut next = (target.clone(), request.to_vec(), Vec::new());
        if helpers.update_content_length
            && let Some(fixed) = update_content_length(request, &self.limits)
        {
            next.1 = fixed;
            next.2.push(Applied::ContentLengthUpdated);
        }
        let mut hops: Vec<Sent> = Vec::new();
        loop {
            let (target, request, applied) = next;
            let sent = self
                .send_one(
                    target,
                    request.into(),
                    applied,
                    helpers.reuse_connection,
                    cancel,
                )
                .await;
            let found = sent
                .response
                .as_ref()
                .filter(|_| hops.len() < usize::from(max_hops))
                .and_then(|r| redirect(&sent.target, &sent.request, r.head(), &self.limits))
                .filter(|(next, request)| scope.is_none_or(|s| in_scope(s, next, request)));
            hops.push(sent);
            let Some((target, request)) = found else {
                return hops;
            };
            next = (target, request, vec![Applied::FollowedRedirect]);
        }
    }

    async fn send_one(
        &self,
        target: SendTarget,
        request: Bytes,
        applied: Vec<Applied>,
        reuse: bool,
        cancel: &CancellationToken,
    ) -> Sent {
        let started = Instant::now();
        let mut sent = Sent {
            target,
            request,
            applied,
            peer: None,
            interim: Vec::new(),
            response: None,
            raw_response: Bytes::new(),
            timings: Timings::default(),
            error: None,
        };
        let mut raw = BytesMut::new();
        let result = tokio::select! {
            r = self.exchange(&mut sent, &mut raw, reuse) => r,
            () = cancel.cancelled() => Err("cancelled".to_owned()),
        };
        sent.error = result.err();
        sent.raw_response = raw.freeze();
        sent.timings.total = started.elapsed();
        sent
    }

    async fn exchange(
        &self,
        sent: &mut Sent,
        raw: &mut BytesMut,
        reuse: bool,
    ) -> Result<(), String> {
        let idle = self.idle.lock().expect("not poisoned").take();
        if let Some((target, peer, mut stream)) = idle.filter(|(t, ..)| reuse && *t == sent.target)
        {
            sent.peer = peer;
            sent.applied.push(Applied::ReusedConnection);
            match self.round_trip(&mut stream, sent, raw).await {
                Ok(keep) => {
                    self.keep(keep, target, peer, stream);
                    return Ok(());
                }
                // Closed while idle: once on a new connection, if the
                // request may be repeated.
                Err(_) if raw.is_empty() && is_idempotent(method(&sent.request)) => {
                    sent.applied.retain(|a| *a != Applied::ReusedConnection);
                }
                Err(e) => return Err(e),
            }
        }
        let mut stream = self.connect(sent).await?;
        let keep = self.round_trip(&mut stream, sent, raw).await?;
        if reuse {
            self.keep(keep, sent.target.clone(), sent.peer, stream);
        }
        Ok(())
    }

    fn keep(&self, keep: bool, target: SendTarget, peer: Option<SocketAddr>, stream: Box<dyn Io>) {
        if keep {
            *self.idle.lock().expect("not poisoned") = Some((target, peer, stream));
        }
    }

    async fn connect(&self, sent: &mut Sent) -> Result<Box<dyn Io>, String> {
        let target = &sent.target;
        let addrs = self.resolve(target, &mut sent.timings).await?;
        let started = Instant::now();
        let tcp = timeout(self.connect_timeout, TcpStream::connect(&addrs[..]))
            .await
            .map_err(|e| format!("cannot connect to {}: {e}", authority(target)))?;
        sent.timings.connect = Some(started.elapsed());
        sent.peer = tcp.peer_addr().ok();
        let _ = tcp.set_nodelay(true);
        if !target.tls {
            return Ok(Box::new(tcp));
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
        Ok(Box::new(tls))
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

    /// Sends the request and reads the response; returns whether the
    /// connection can carry another request.
    async fn round_trip<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
        &self,
        stream: &mut S,
        sent: &mut Sent,
        raw: &mut BytesMut,
    ) -> Result<bool, String> {
        let request = sent.request.clone();
        let request = &request[..];
        stream
            .write_all(request)
            .await
            .and(stream.flush().await)
            .map_err(|e| format!("cannot send the request: {e}"))?;
        let written = Instant::now();
        // The method decides how a response is framed (HEAD); a malformed
        // request may have none.
        let method = method(request);
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
                    let keep = start == raw.len()
                        && response.framing().framing != Framing::UntilClose
                        && keep_alive(response.head(), response.head().version())
                        && RequestHead::parse(request, &self.limits)
                            .ok()
                            .flatten()
                            .is_some_and(|h| keep_alive(&h, h.version().unwrap_or_default()));
                    sent.response = Some(response);
                    return Ok(keep);
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

/// The method: the first word, which a malformed request may lack.
fn method(request: &[u8]) -> &[u8] {
    request.split(|&b| b == b' ').next().unwrap_or_default()
}

fn in_scope(scope: &Scope, target: &SendTarget, request: &[u8]) -> bool {
    let line = request.split(|&b| b == b'\n').next().unwrap_or_default();
    let path = String::from_utf8_lossy(line.split(|&b| b == b' ').nth(1).unwrap_or(b"/"));
    scope.contains(&ScopeTarget {
        scheme: if target.tls {
            Scheme::Https
        } else {
            Scheme::Http
        },
        host: &target.host,
        port: target.port,
        path: &path,
    })
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
