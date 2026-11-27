// SPDX-License-Identifier: AGPL-3.0-or-later

//! One client connection: read requests, forward them, relay responses.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use hiccup_http::{Error as HttpError, Framing, Head, Limits, Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::target::{AbsoluteTarget, Authority, TargetError};
use crate::{Exchange, ExchangeObserver, Modification, ProxyConfig};

const READ_CHUNK: usize = 16 * 1024;

/// Shared by all connections of a proxy.
pub(crate) struct Context {
    pub(crate) config: ProxyConfig,
    pub(crate) observer: Option<ExchangeObserver>,
    pub(crate) shutdown: CancellationToken,
}

/// An upstream connection kept alive between requests.
struct Upstream {
    authority: Authority,
    stream: TcpStream,
    buf: BytesMut,
}

enum Next {
    Continue,
    Close,
}

pub(crate) async fn handle(mut client: TcpStream, peer: SocketAddr, ctx: Arc<Context>) {
    match serve(&mut client, peer, &ctx).await {
        Ok(()) => debug!("connection closed"),
        Err(e) => debug!(error = %e, "connection ended with an error"),
    }
}

async fn serve(client: &mut TcpStream, peer: SocketAddr, ctx: &Context) -> io::Result<()> {
    let mut buf = BytesMut::with_capacity(READ_CHUNK);
    let mut upstream: Option<Upstream> = None;
    loop {
        let Some(request) = read_request(client, &mut buf, ctx).await? else {
            return Ok(());
        };
        let _ = buf.split_to(request.len());

        if request.head().method() == b"CONNECT" {
            return connect_tunnel(client, &buf, &request, ctx).await;
        }
        match forward(client, &mut buf, peer, request, &mut upstream, ctx).await? {
            Next::Continue => {}
            Next::Close => {
                let _ = client.shutdown().await;
                return Ok(());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Reading

/// Reads the next complete request. Returns `None` when the connection should
/// close without a response (EOF, idle timeout, shutdown, or an error that was
/// already answered).
async fn read_request(
    client: &mut TcpStream,
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

async fn read_with_timeout(
    stream: &mut TcpStream,
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

async fn forward(
    client: &mut TcpStream,
    client_buf: &mut BytesMut,
    peer: SocketAddr,
    request: Request,
    upstream: &mut Option<Upstream>,
    ctx: &Context,
) -> io::Result<Next> {
    let target = match AbsoluteTarget::parse(request.head().target()) {
        Ok(t) => t,
        Err(e) => {
            let (status, reason, detail) = match e {
                TargetError::OriginForm => (
                    400,
                    "Bad Request",
                    "request target is not in absolute-form; configure Hiccup as an HTTP proxy \
                     (invisible proxying is not supported yet)"
                        .to_owned(),
                ),
                TargetError::UnsupportedScheme(s) => (
                    501,
                    "Not Implemented",
                    format!("scheme {s:?} is not supported in absolute-form requests"),
                ),
                TargetError::Invalid => (400, "Bad Request", "invalid request target".to_owned()),
            };
            write_error(client, status, reason, &detail).await;
            return Ok(Next::Close);
        }
    };

    let (forwarded, modification) = rewrite_target(&request, &target);
    let mut exchange = Exchange {
        client: peer,
        upstream: target.authority.to_string(),
        received: request,
        forwarded,
        modifications: vec![modification],
        interim: Vec::new(),
        response: None,
        error: None,
    };
    info!(
        method = %String::from_utf8_lossy(exchange.received.head().method()),
        target = %String::from_utf8_lossy(exchange.received.head().target()),
        "request"
    );

    let method = exchange.received.head().method().to_vec();
    let retry_allowed = is_idempotent(&method);
    let mut attempt = 0;
    let response = loop {
        attempt += 1;
        let reused = upstream
            .as_ref()
            .is_some_and(|u| u.authority == target.authority);
        if !reused {
            match connect(&target.authority, ctx.config.connect_timeout).await {
                Ok(stream) => {
                    *upstream = Some(Upstream {
                        authority: target.authority.clone(),
                        stream,
                        buf: BytesMut::with_capacity(READ_CHUNK),
                    });
                }
                Err(e) => {
                    let detail = format!("cannot connect to {}: {e}", target.authority);
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
                client.write_all(response.head().as_bytes()).await?;
                client.write_all(response.body()).await?;
                match response.head().status_code() {
                    Some(100..=199) if response.framing().framing != Framing::Tunnel => {
                        exchange.interim.push(response);
                    }
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
                let detail = format!(
                    "{} closed the connection without a response",
                    target.authority
                );
                return fail(client, exchange, 502, "Bad Gateway", detail, ctx).await;
            }
            Err(e) => {
                *upstream = None;
                let detail = format!("error talking to {}: {e}", target.authority);
                return fail(client, exchange, 502, "Bad Gateway", detail, ctx).await;
            }
        }
    };

    let framing = response.framing().framing;
    let keep_client = keep_alive(exchange.received.head()) && keep_alive(response.head());
    let keep_upstream = keep_client && framing != Framing::UntilClose;
    exchange.response = Some(response);
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

async fn connect_tunnel(
    client: &mut TcpStream,
    pending: &[u8],
    request: &Request,
    ctx: &Context,
) -> io::Result<()> {
    let Some(authority) = Authority::parse(request.head().target(), None) else {
        write_error(
            client,
            400,
            "Bad Request",
            "invalid CONNECT target, expected host:port",
        )
        .await;
        return Ok(());
    };
    info!(%authority, "CONNECT");
    let mut upstream = match connect(&authority, ctx.config.connect_timeout).await {
        Ok(s) => s,
        Err(e) => {
            let detail = format!("cannot connect to {authority}: {e}");
            write_error(client, 502, "Bad Gateway", &detail).await;
            return Ok(());
        }
    };
    client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;
    tunnel(client, pending, &mut upstream, &[]).await
}

/// Relays bytes in both directions until either side closes.
async fn tunnel(
    client: &mut TcpStream,
    client_pending: &[u8],
    upstream: &mut TcpStream,
    upstream_pending: &[u8],
) -> io::Result<()> {
    upstream.write_all(client_pending).await?;
    client.write_all(upstream_pending).await?;
    let (to_upstream, to_client) = tokio::io::copy_bidirectional(client, upstream).await?;
    debug!(to_upstream, to_client, "tunnel closed");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers

async fn connect(authority: &Authority, timeout: Duration) -> io::Result<TcpStream> {
    let stream = tokio::time::timeout(
        timeout,
        TcpStream::connect((authority.host.as_str(), authority.port)),
    )
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

async fn fail(
    client: &mut TcpStream,
    mut exchange: Exchange,
    status: u16,
    reason: &str,
    detail: String,
    ctx: &Context,
) -> io::Result<Next> {
    warn!(error = %detail, "exchange failed");
    write_error(client, status, reason, &detail).await;
    exchange.error = Some(detail);
    notify(ctx, &exchange);
    Ok(Next::Close)
}

async fn send_error(client: &mut TcpStream, error: &HttpError) {
    let (status, reason) = match error {
        HttpError::HeadTooLarge { .. } | HttpError::TooManyHeaders { .. } => {
            (431, "Request Header Fields Too Large")
        }
        _ => (400, "Bad Request"),
    };
    write_error(client, status, reason, &error.to_string()).await;
}

/// Writes an error response generated by Hiccup and closes the connection.
async fn write_error(client: &mut TcpStream, status: u16, reason: &str, detail: &str) {
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
async fn linger(client: &mut TcpStream) {
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
