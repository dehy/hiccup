// SPDX-License-Identifier: AGPL-3.0-or-later

//! One client connection: read requests, forward them, relay responses.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use hiccup_http::{Error as HttpError, Framing, Head, Limits, Request, Response};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::intercept::{Direction, InterceptQueue, Pending, RequestInfo, Verdict};
use crate::io::{Io, Prefixed};
use crate::target::{AbsoluteTarget, Authority, TargetError};
use crate::tls::Interceptor;
use crate::{Exchange, ExchangeObserver, Modification, ProxyConfig};

const READ_CHUNK: usize = 16 * 1024;

/// Shared by all connections of a proxy.
pub(crate) struct Context {
    pub(crate) config: ProxyConfig,
    pub(crate) observer: Option<ExchangeObserver>,
    pub(crate) interceptor: Option<Interceptor>,
    pub(crate) intercept: Option<Arc<InterceptQueue>>,
    pub(crate) shutdown: CancellationToken,
}

/// An upstream connection kept alive between requests.
struct Upstream {
    authority: Authority,
    stream: Box<dyn Io>,
    buf: BytesMut,
}

/// What a client connection carries.
enum Mode {
    /// Proxy requests: absolute-form targets, and `CONNECT`.
    Proxy,
    /// Requests decrypted from an intercepted TLS tunnel to `authority`.
    /// They are forwarded as received, over TLS, with `server_name` as SNI.
    Intercepted {
        authority: Authority,
        server_name: ServerName<'static>,
    },
}

enum Next {
    Continue,
    Close,
}

pub(crate) async fn handle(mut client: TcpStream, peer: SocketAddr, ctx: Arc<Context>) {
    let mut buf = BytesMut::with_capacity(READ_CHUNK);
    let result = match serve(&mut client, &mut buf, peer, &Mode::Proxy, &ctx).await {
        Ok(Some(connect)) => handle_connect(client, buf, peer, &connect, &ctx).await,
        Ok(None) => Ok(()),
        Err(e) => Err(e),
    };
    match result {
        Ok(()) => debug!("connection closed"),
        Err(e) => debug!(error = %e, "connection ended with an error"),
    }
}

/// Serves requests until the connection closes. In proxy mode, returns a
/// `CONNECT` request for the caller to handle; `buf` then holds the bytes
/// received after it.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut S,
    buf: &mut BytesMut,
    peer: SocketAddr,
    mode: &Mode,
    ctx: &Context,
) -> io::Result<Option<Request>> {
    let mut upstream: Option<Upstream> = None;
    loop {
        let Some(request) = read_request(client, buf, ctx).await? else {
            return Ok(None);
        };
        let _ = buf.split_to(request.len());

        if matches!(mode, Mode::Proxy) && request.head().method() == b"CONNECT" {
            return Ok(Some(request));
        }
        match forward(client, buf, peer, request, mode, &mut upstream, ctx).await? {
            Next::Continue => {}
            Next::Close => {
                let _ = client.shutdown().await;
                return Ok(None);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Reading

/// Reads the next complete request. Returns `None` when the connection should
/// close without a response (EOF, idle timeout, shutdown, or an error that was
/// already answered).
async fn read_request<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut S,
    buf: &mut BytesMut,
    ctx: &Context,
) -> io::Result<Option<Request>> {
    let limits = &ctx.config.limits;
    loop {
        match Request::parse(buf, limits, false) {
            Ok(Some(request)) => return Ok(Some(request)),
            Ok(None) => {}
            Err(e) => {
                send_error(client, &e).await;
                return Ok(None);
            }
        }

        let n = if buf.is_empty() {
            // Between requests: idle timeout, and shutdown closes the connection.
            tokio::select! {
                () = ctx.shutdown.cancelled() => return Ok(None),
                r = tokio::time::timeout(ctx.config.idle_timeout, client.read_buf(buf)) => match r {
                    Ok(r) => r?,
                    Err(_) => {
                        debug!("idle timeout");
                        return Ok(None);
                    }
                },
            }
        } else {
            read_with_timeout(client, buf, ctx.config.read_timeout).await?
        };

        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return match Request::parse(buf, limits, true) {
                Ok(request) => Ok(request),
                Err(e) => {
                    debug!(error = %e, "client closed mid-request");
                    Ok(None)
                }
            };
        }
    }
}

/// Reads the next complete response from `upstream`. Returns `Ok(None)` if the
/// connection closed before any byte of a response arrived.
async fn read_response(
    upstream: &mut Upstream,
    method: &[u8],
    limits: &Limits,
    timeout: Duration,
) -> io::Result<Option<Response>> {
    loop {
        match Response::parse(&upstream.buf, method, limits, false) {
            Ok(Some(response)) => {
                let _ = upstream.buf.split_to(response.len());
                return Ok(Some(response));
            }
            Ok(None) => {}
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
        }
        if read_with_timeout(&mut upstream.stream, &mut upstream.buf, timeout).await? == 0 {
            if upstream.buf.is_empty() {
                return Ok(None);
            }
            return match Response::parse(&upstream.buf, method, limits, true) {
                Ok(Some(response)) => {
                    let _ = upstream.buf.split_to(response.len());
                    Ok(Some(response))
                }
                Ok(None) => unreachable!("parse with eof never returns None"),
                Err(e) => Err(io::Error::new(io::ErrorKind::UnexpectedEof, e)),
            };
        }
    }
}

async fn read_with_timeout<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut BytesMut,
    timeout: Duration,
) -> io::Result<usize> {
    buf.reserve(READ_CHUNK);
    match tokio::time::timeout(timeout, stream.read_buf(buf)).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "read timed out")),
    }
}

// ---------------------------------------------------------------------------
// Forwarding

async fn forward<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut S,
    client_buf: &mut BytesMut,
    peer: SocketAddr,
    request: Request,
    mode: &Mode,
    upstream: &mut Option<Upstream>,
    ctx: &Context,
) -> io::Result<Next> {
    // `path` is the target as forwarded: what intercept rules match.
    let (authority, forwarded, modifications, path) = match mode {
        Mode::Proxy => match proxy_target(client, &request).await {
            Some((target, forwarded, modification)) => {
                let path = String::from_utf8_lossy(&target.origin_form).into_owned();
                (target.authority, forwarded, vec![modification], path)
            }
            None => return Ok(Next::Close),
        },
        // Inside a tunnel, the client already addresses the origin server.
        Mode::Intercepted { authority, .. } => (
            authority.clone(),
            Bytes::from(request.to_bytes()),
            Vec::new(),
            String::from_utf8_lossy(request.head().target()).into_owned(),
        ),
    };

    let mut exchange = Exchange {
        client: peer,
        upstream: authority.to_string(),
        tls: matches!(mode, Mode::Intercepted { .. }),
        received: request,
        forwarded,
        modifications,
        interim: Vec::new(),
        response: None,
        delivered: None,
        error: None,
    };
    info!(
        method = %String::from_utf8_lossy(exchange.received.head().method()),
        upstream = %exchange.upstream,
        target = %String::from_utf8_lossy(exchange.received.head().target()),
        "request"
    );

    let method_name = String::from_utf8_lossy(exchange.received.head().method()).into_owned();
    let rule_input = RequestInfo {
        host: &authority.host,
        method: &method_name,
        target: &path,
    };
    let pending = |direction, raw: Bytes, status| {
        let (upstream, tls) = (exchange.upstream.clone(), exchange.tls);
        let (method, target) = (method_name.clone(), path.clone());
        move |id| Pending {
            id,
            direction,
            upstream,
            tls,
            method,
            target,
            status,
            raw,
            since: std::time::Instant::now(),
        }
    };
    if let Some(queue) = &ctx.intercept {
        let held = pending(Direction::Request, exchange.forwarded.clone(), None);
        match queue.hold(Direction::Request, &rule_input, held).await {
            Verdict::Forward => {}
            Verdict::ForwardEdited(bytes) => {
                exchange.forwarded = bytes;
                exchange.modifications.push(Modification::RequestEdited);
            }
            Verdict::Drop => {
                let detail = "the request was dropped in Hiccup's intercept queue".to_owned();
                return fail(client, exchange, 502, "Bad Gateway", detail, ctx).await;
            }
        }
    }

    // An edited request may use another method, which changes how the
    // response is framed (e.g. HEAD).
    let method = Request::parse(&exchange.forwarded, &ctx.config.limits, true)
        .ok()
        .flatten()
        .map_or_else(
            || exchange.received.head().method().to_vec(),
            |r| r.head().method().to_vec(),
        );
    let retry_allowed = is_idempotent(&method);
    let mut attempt = 0;
    let response = loop {
        attempt += 1;
        let reused = upstream.as_ref().is_some_and(|u| u.authority == authority);
        if !reused {
            match open_upstream(&authority, mode, ctx).await {
                Ok(stream) => {
                    *upstream = Some(Upstream {
                        authority: authority.clone(),
                        stream,
                        buf: BytesMut::with_capacity(READ_CHUNK),
                    });
                }
                Err(detail) => {
                    return fail(client, exchange, 502, "Bad Gateway", detail, ctx).await;
                }
            }
        }
        let up = upstream.as_mut().expect("upstream is connected");

        let result: io::Result<Option<Response>> = async {
            up.stream.write_all(&exchange.forwarded).await?;
            loop {
                let Some(response) =
                    read_response(up, &method, &ctx.config.limits, ctx.config.read_timeout).await?
                else {
                    return Ok(None);
                };
                match response.head().status_code() {
                    Some(100..=199) if response.framing().framing != Framing::Tunnel => {
                        client.write_all(response.head().as_bytes()).await?;
                        client.write_all(response.body()).await?;
                        exchange.interim.push(response);
                    }
                    // The final response is written below, after interception.
                    _ => return Ok(Some(response)),
                }
            }
        }
        .await;

        match result {
            Ok(Some(response)) => break response,
            // A reused connection closed while idle: retry once on a new one.
            Ok(None) if reused && retry_allowed && attempt == 1 && exchange.interim.is_empty() => {
                debug!("reused upstream connection was closed; retrying");
                *upstream = None;
            }
            Err(ref e)
                if reused
                    && retry_allowed
                    && attempt == 1
                    && exchange.interim.is_empty()
                    && is_closed_connection(e) =>
            {
                debug!(error = %e, "reused upstream connection failed; retrying");
                *upstream = None;
            }
            Ok(None) => {
                *upstream = None;
                let detail = format!("{} closed the connection without a response", authority);
                return fail(client, exchange, 502, "Bad Gateway", detail, ctx).await;
            }
            Err(e) => {
                *upstream = None;
                let detail = format!("error talking to {authority}: {e}");
                return fail(client, exchange, 502, "Bad Gateway", detail, ctx).await;
            }
        }
    };

    let framing = response.framing().framing;
    let mut keep_client = keep_alive(exchange.received.head()) && keep_alive(response.head());
    // Edited bytes may hold more than one request, or frame it differently:
    // the connection may then carry responses that belong to none of ours.
    let request_edited = exchange
        .modifications
        .contains(&Modification::RequestEdited);
    let keep_upstream = keep_client && framing != Framing::UntilClose && !request_edited;

    let verdict = match &ctx.intercept {
        // A protocol switch is relayed as is.
        Some(queue) if framing != Framing::Tunnel => {
            let raw = Bytes::from(response.to_bytes());
            let held = pending(Direction::Response, raw, response.head().status_code());
            queue.hold(Direction::Response, &rule_input, held).await
        }
        _ => Verdict::Forward,
    };
    let written = match verdict {
        Verdict::Forward => {
            async {
                client.write_all(response.head().as_bytes()).await?;
                client.write_all(response.body()).await
            }
            .await
        }
        Verdict::ForwardEdited(bytes) => {
            // The edited bytes may frame the message differently: close the
            // client connection after them rather than guess.
            keep_client = false;
            exchange.modifications.push(Modification::ResponseEdited);
            let written = client.write_all(&bytes).await;
            exchange.delivered = Some(bytes);
            written
        }
        Verdict::Drop => {
            exchange.response = Some(response);
            if !keep_upstream {
                *upstream = None;
            }
            let detail = "the response was dropped in Hiccup's intercept queue".to_owned();
            return fail(client, exchange, 502, "Bad Gateway", detail, ctx).await;
        }
    };
    exchange.response = Some(response);
    if let Err(e) = written {
        exchange.error = Some(format!("cannot send the response to the client: {e}"));
        notify(ctx, &exchange);
        return Err(e);
    }
    notify(ctx, &exchange);

    if framing == Framing::Tunnel {
        // 101 Switching Protocols: the connection now carries another protocol.
        let mut up = upstream.take().expect("upstream is connected");
        let client_pending = client_buf.split();
        return tunnel(client, &client_pending, &mut up.stream, &up.buf)
            .await
            .map(|()| Next::Close);
    }
    if !keep_upstream {
        *upstream = None;
    }
    Ok(if keep_client && framing != Framing::UntilClose {
        Next::Continue
    } else {
        Next::Close
    })
}

/// Parses a proxy request's absolute-form target and rewrites it to
/// origin-form. Answers the client and returns `None` if it cannot.
async fn proxy_target<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut S,
    request: &Request,
) -> Option<(AbsoluteTarget, Bytes, Modification)> {
    let (status, reason, detail) = match AbsoluteTarget::parse(request.head().target()) {
        Ok(target) => {
            let (forwarded, modification) = rewrite_target(request, &target);
            return Some((target, forwarded, modification));
        }
        Err(TargetError::OriginForm) => (
            400,
            "Bad Request",
            "request target is not in absolute-form; configure Hiccup as an HTTP proxy \
             (invisible proxying is not supported yet)"
                .to_owned(),
        ),
        Err(TargetError::UnsupportedScheme(s)) => (
            501,
            "Not Implemented",
            format!("scheme {s:?} is not supported in absolute-form requests"),
        ),
        Err(TargetError::Invalid) => (400, "Bad Request", "invalid request target".to_owned()),
    };
    write_error(client, status, reason, &detail).await;
    None
}

/// Connects to `authority`, over TLS in an intercepted tunnel. The error is a
/// message for the client.
async fn open_upstream(
    authority: &Authority,
    mode: &Mode,
    ctx: &Context,
) -> Result<Box<dyn Io>, String> {
    let tcp = connect(authority, ctx)
        .await
        .map_err(|e| format!("cannot connect to {authority}: {e}"))?;
    let Mode::Intercepted { server_name, .. } = mode else {
        return Ok(Box::new(tcp));
    };
    let interceptor = ctx
        .interceptor
        .as_ref()
        .expect("tunnels are intercepted only with an interceptor");
    let handshake = TlsConnector::from(interceptor.client_config(&authority.host))
        .connect(server_name.clone(), tcp);
    match tokio::time::timeout(ctx.config.connect_timeout, handshake).await {
        Ok(Ok(tls)) => Ok(Box::new(tls)),
        Ok(Err(e)) => Err(format!("TLS handshake with {authority} failed: {e}")),
        Err(_) => Err(format!("TLS handshake with {authority} timed out")),
    }
}

/// Replaces the absolute-form target with origin-form, keeping every other
/// byte of the request.
fn rewrite_target(request: &Request, target: &AbsoluteTarget) -> (Bytes, Modification) {
    let raw = request.head().as_bytes();
    let (_, span, _) = request.head().request_line_spans();
    let mut out = Vec::with_capacity(request.len());
    out.extend_from_slice(&raw[..span.start]);
    out.extend_from_slice(&target.origin_form);
    out.extend_from_slice(&raw[span.end..]);
    out.extend_from_slice(request.body());
    let modification = Modification::TargetRewritten {
        original: Bytes::copy_from_slice(span.slice(raw)),
        rewritten: Bytes::copy_from_slice(&target.origin_form),
    };
    (Bytes::from(out), modification)
}

/// Whether the sender of `head` expects the connection to stay open
/// (RFC 9112 §9.3).
fn keep_alive(head: &Head) -> bool {
    let version = head
        .as_bytes()
        .get(head.start_line().content.start..head.start_line().content.end)
        .unwrap_or_default();
    let has = |token: &str| {
        head.get_all("connection").any(|h| {
            h.value()
                .split(|&b| b == b',')
                .any(|t| t.trim_ascii().eq_ignore_ascii_case(token.as_bytes()))
        })
    };
    if has("close") {
        return false;
    }
    // HTTP/1.1 is persistent by default; HTTP/1.0 only with keep-alive.
    let http11 = version.windows(8).any(|w| w == b"HTTP/1.1");
    http11 || has("keep-alive")
}

/// Errors that mean the peer had already closed the connection.
fn is_closed_connection(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::UnexpectedEof
    )
}

/// RFC 9110 §9.2.2.
fn is_idempotent(method: &[u8]) -> bool {
    matches!(
        method,
        b"GET" | b"HEAD" | b"OPTIONS" | b"TRACE" | b"PUT" | b"DELETE"
    )
}

// ---------------------------------------------------------------------------
// CONNECT tunnels

/// Handles a `CONNECT` request: intercepts TLS, or relays bytes untouched.
/// `pending` holds the bytes the client sent after the request.
async fn handle_connect(
    mut client: TcpStream,
    mut pending: BytesMut,
    peer: SocketAddr,
    request: &Request,
    ctx: &Context,
) -> io::Result<()> {
    let Some(authority) = Authority::parse(request.head().target(), None) else {
        write_error(
            &mut client,
            400,
            "Bad Request",
            "invalid CONNECT target, expected host:port",
        )
        .await;
        return Ok(());
    };
    let intercept = ctx.interceptor.is_some()
        && !ctx
            .config
            .tls_passthrough
            .iter()
            .any(|p| p.matches(&authority.host));
    info!(%authority, intercept, "CONNECT");
    if !intercept {
        return pass_through(client, &pending, &authority, ctx).await;
    }

    // Answer first: the upstream connection is opened per request, so that
    // connection errors reach the client as error responses.
    client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;
    while pending.is_empty() {
        if read_with_timeout(&mut client, &mut pending, ctx.config.read_timeout).await? == 0 {
            return Ok(());
        }
    }
    // A TLS record starts with the handshake content type (RFC 8446 §5.1).
    if pending[0] != 0x16 {
        debug!("the tunnel does not carry TLS; relaying it");
        let mut upstream = connect(&authority, ctx).await?;
        return tunnel(&mut client, &pending, &mut upstream, &[]).await;
    }

    let interceptor = ctx.interceptor.as_ref().expect("checked above");
    let io = Prefixed::new(pending.freeze(), client);
    let accept = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io);
    let start = match tokio::time::timeout(ctx.config.read_timeout, accept).await {
        Ok(Ok(start)) => start,
        Ok(Err(e)) => {
            info!(%authority, error = %e, "invalid TLS ClientHello");
            return Ok(());
        }
        Err(_) => return Ok(()),
    };
    let sni = start.client_hello().server_name().map(str::to_owned);
    let host = sni.unwrap_or_else(|| authority.host.clone());
    let config = match interceptor.server_config(&host) {
        Ok(config) => config,
        Err(e) => {
            warn!(%host, error = %e, "cannot create a certificate");
            return Ok(());
        }
    };
    let mut tls =
        match tokio::time::timeout(ctx.config.read_timeout, start.into_stream(config)).await {
            Ok(Ok(tls)) => tls,
            Ok(Err(e)) => {
                // Usually the client does not trust the CA, or pins certificates.
                info!(
                    %host,
                    error = %e,
                    "TLS handshake with the client failed; is the Hiccup CA installed? \
                     Clients that pin certificates need --tls-passthrough"
                );
                return Ok(());
            }
            Err(_) => return Ok(()),
        };
    debug!(%host, "TLS intercepted");

    // The client's server name, unless overridden for this host.
    let upstream_name = ctx
        .config
        .upstream
        .sni_for(&authority.host)
        .map_or(host, str::to_owned);
    let server_name = ServerName::try_from(upstream_name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mode = Mode::Intercepted {
        authority,
        server_name,
    };
    let mut buf = BytesMut::with_capacity(READ_CHUNK);
    serve(&mut tls, &mut buf, peer, &mode, ctx).await.map(drop)
}

/// Relays a `CONNECT` tunnel without looking inside.
async fn pass_through(
    mut client: TcpStream,
    pending: &[u8],
    authority: &Authority,
    ctx: &Context,
) -> io::Result<()> {
    let mut upstream = match connect(authority, ctx).await {
        Ok(s) => s,
        Err(e) => {
            let detail = format!("cannot connect to {authority}: {e}");
            write_error(&mut client, 502, "Bad Gateway", &detail).await;
            return Ok(());
        }
    };
    client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;
    tunnel(&mut client, pending, &mut upstream, &[]).await
}

/// Relays bytes in both directions until either side closes.
async fn tunnel<C, U>(
    client: &mut C,
    client_pending: &[u8],
    upstream: &mut U,
    upstream_pending: &[u8],
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + ?Sized,
    U: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let started = Instant::now();
    upstream.write_all(client_pending).await?;
    client.write_all(upstream_pending).await?;
    let (to_upstream, to_client) = tokio::io::copy_bidirectional(client, upstream).await?;
    debug!(
        to_upstream,
        to_client,
        duration_ms = started.elapsed().as_millis(),
        "tunnel closed"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers

/// Opens a TCP connection to `authority`, or to its `--resolve` override.
async fn connect(authority: &Authority, ctx: &Context) -> io::Result<TcpStream> {
    let override_ip = ctx.config.upstream.resolve_for(&authority.host);
    if let Some(ip) = override_ip {
        debug!(%authority, %ip, "resolve override");
    }
    let connecting = async {
        match override_ip {
            Some(ip) => TcpStream::connect((ip, authority.port)).await,
            None => TcpStream::connect((authority.host.as_str(), authority.port)).await,
        }
    };
    let stream = tokio::time::timeout(ctx.config.connect_timeout, connecting)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connection timed out"))??;
    stream.set_nodelay(true)?;
    Ok(stream)
}

fn notify(ctx: &Context, exchange: &Exchange) {
    if let Some(observer) = &ctx.observer {
        observer(exchange);
    }
}

async fn fail<S: AsyncWrite + AsyncRead + Unpin>(
    client: &mut S,
    mut exchange: Exchange,
    status: u16,
    reason: &str,
    detail: String,
    ctx: &Context,
) -> io::Result<Next> {
    warn!(error = %detail, "exchange failed");
    // Record first: writing the error lingers on the connection.
    exchange.error = Some(detail.clone());
    notify(ctx, &exchange);
    write_error(client, status, reason, &detail).await;
    Ok(Next::Close)
}

async fn send_error<S: AsyncWrite + AsyncRead + Unpin>(client: &mut S, error: &HttpError) {
    let (status, reason) = match error {
        HttpError::HeadTooLarge { .. } | HttpError::TooManyHeaders { .. } => {
            (431, "Request Header Fields Too Large")
        }
        _ => (400, "Bad Request"),
    };
    write_error(client, status, reason, &error.to_string()).await;
}

/// Writes an error response generated by Hiccup and closes the connection.
async fn write_error<S: AsyncWrite + AsyncRead + Unpin>(
    client: &mut S,
    status: u16,
    reason: &str,
    detail: &str,
) {
    let body = format!("Hiccup: {detail}\n");
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    if client.write_all(response.as_bytes()).await.is_ok() {
        let _ = client.shutdown().await;
        linger(client).await;
    }
}

/// Discards unread input for a short while before the socket is closed.
///
/// Closing a socket with unread data makes the OS send a TCP reset, which can
/// destroy the error response before the client reads it (notably on
/// Windows). Draining first lets the response arrive ("lingering close").
async fn linger<S: AsyncRead + Unpin>(client: &mut S) {
    const MAX_BYTES: usize = 256 * 1024;
    let drain = async {
        let mut sink = [0u8; 8192];
        let mut total = 0;
        while total < MAX_BYTES {
            match client.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(1), drain).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(raw: &[u8]) -> hiccup_http::RequestHead {
        hiccup_http::RequestHead::parse(raw, &Limits::DEFAULT)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn keep_alive_rules() {
        assert!(keep_alive(&head(b"GET / HTTP/1.1\r\n\r\n")));
        assert!(!keep_alive(&head(
            b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n"
        )));
        assert!(!keep_alive(&head(
            b"GET / HTTP/1.1\r\nConnection: Upgrade, Close\r\n\r\n"
        )));
        assert!(!keep_alive(&head(b"GET / HTTP/1.0\r\n\r\n")));
        assert!(keep_alive(&head(
            b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n"
        )));
    }

    #[test]
    fn rewrite_keeps_everything_else() {
        let raw = b"GET http://example.com/a?b HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n";
        let request = Request::parse(raw, &Limits::DEFAULT, false)
            .unwrap()
            .unwrap();
        let target = AbsoluteTarget::parse(request.head().target()).unwrap();
        let (forwarded, modification) = rewrite_target(&request, &target);
        assert_eq!(
            &forwarded[..],
            b"GET /a?b HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n"
        );
        assert_eq!(
            modification,
            Modification::TargetRewritten {
                original: Bytes::from_static(b"http://example.com/a?b"),
                rewritten: Bytes::from_static(b"/a?b"),
            }
        );
    }
}
