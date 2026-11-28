// SPDX-License-Identifier: AGPL-3.0-or-later

//! The raw request sender, against servers that capture what they receive.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hiccup_proxy::{Applied, Helpers, Redirects, Scope, SendTarget, Sender, UpstreamConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

/// What a capturing server saw: the bytes, and the SNI for TLS.
type Captured = oneshot::Receiver<(Vec<u8>, Option<String>)>;

/// Reads until the client pauses, then writes `reply` and closes.
async fn capture<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, reply: &[u8]) -> Vec<u8> {
    let mut got = Vec::new();
    let mut chunk = [0u8; 4096];
    while let Ok(Ok(n)) =
        tokio::time::timeout(Duration::from_millis(150), stream.read(&mut chunk)).await
    {
        if n == 0 {
            break;
        }
        got.extend_from_slice(&chunk[..n]);
    }
    let _ = stream.write_all(reply).await;
    let _ = stream.shutdown().await;
    got
}

/// Without `reply`, the server reports the first read and never answers.
async fn plain_server(reply: Option<&'static [u8]>) -> (SocketAddr, Captured) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        if let Some(reply) = reply {
            let got = capture(&mut s, reply).await;
            let _ = tx.send((got, None));
        } else {
            let mut chunk = [0u8; 4096];
            let n = s.read(&mut chunk).await.unwrap_or(0);
            let _ = tx.send((chunk[..n].to_vec(), None));
            std::future::pending::<()>().await;
        }
    });
    (addr, rx)
}

async fn tls_server(reply: &'static [u8]) -> (SocketAddr, Captured) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["origin.test".into()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![CertificateDer::from(cert.der().to_vec())], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let sni = tls.get_ref().1.server_name().map(str::to_owned);
        let got = capture(&mut tls, reply).await;
        let _ = tx.send((got, sni));
    });
    (addr, rx)
}

fn target(addr: SocketAddr, tls: bool) -> SendTarget {
    SendTarget {
        host: addr.ip().to_string(),
        port: addr.port(),
        tls,
    }
}

/// The test origins have self-signed certificates.
fn insecure() -> UpstreamConfig {
    UpstreamConfig {
        verify: false,
        ..UpstreamConfig::default()
    }
}

fn sender() -> Sender {
    Sender::new(insecure()).unwrap()
}

/// Malformed on purpose: a bare LF, a space before the colon, a lowercase
/// method, a `Host` naming another site, and conflicting lengths.
const ODD: &[u8] = b"get  /x?a=%zz HTTP/1.1\nHost: elsewhere.test\r\nX-Odd :  1 \r\nContent-Length: 3\r\nContent-Length: 5\r\n\r\nabc";

#[tokio::test]
async fn the_exact_bytes_are_sent_to_the_target_whatever_the_host_header() {
    let (addr, captured) =
        plain_server(Some(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")).await;
    let sent = sender()
        .send(
            &target(addr, false),
            ODD,
            &Helpers::default(),
            &CancellationToken::new(),
        )
        .await
        .remove(0);
    assert_eq!(sent.error, None);
    assert_eq!(captured.await.unwrap().0, ODD, "byte for byte");
    assert!(
        sent.applied.is_empty() && sent.request == ODD,
        "helpers off"
    );

    let response = sent.response.unwrap();
    assert_eq!(response.head().status_code(), Some(200));
    assert_eq!(&response.body()[..], b"ok");
    assert_eq!(&sent.raw_response[..], response.to_bytes());
    assert_eq!(sent.peer, Some(addr));
    let t = sent.timings;
    assert!(t.dns.is_none() && t.tls.is_none(), "an IP, without TLS");
    assert!(t.connect.is_some() && t.ttfb.is_some() && t.total > Duration::ZERO);
}

#[tokio::test]
async fn tls_uses_the_upstream_options() {
    let (addr, captured) = tls_server(b"HTTP/1.1 204 No Content\r\n\r\n").await;
    let mut upstream = insecure();
    upstream
        .sni
        .push(("*".parse().unwrap(), "origin.test".to_owned()));
    let sender = Sender::new(upstream).unwrap();
    let sent = sender
        .send(
            &target(addr, true),
            ODD,
            &Helpers::default(),
            &CancellationToken::new(),
        )
        .await
        .remove(0);
    assert_eq!(sent.error, None);
    let (got, sni) = captured.await.unwrap();
    assert_eq!(got, ODD, "byte for byte, inside TLS");
    assert_eq!(sni.as_deref(), Some("origin.test"), "the SNI rule applies");
    assert_eq!(sent.response.unwrap().head().status_code(), Some(204));
    assert!(sent.timings.tls.is_some());
}

#[tokio::test]
async fn a_host_name_is_resolved_and_timed() {
    let (addr, _captured) =
        plain_server(Some(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")).await;
    let localhost = SendTarget {
        host: "localhost".to_owned(),
        port: addr.port(),
        tls: false,
    };
    let sent = sender()
        .send(
            &localhost,
            b"GET / HTTP/1.1\r\n\r\n",
            &Helpers::default(),
            &CancellationToken::new(),
        )
        .await
        .remove(0);
    assert_eq!(sent.error, None);
    assert!(sent.timings.dns.is_some());
}

#[tokio::test]
async fn interim_responses_come_before_the_final_one() {
    let (addr, _captured) = plain_server(Some(
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    ))
    .await;
    let sent = sender()
        .send(
            &target(addr, false),
            b"POST / HTTP/1.1\r\n\r\n",
            &Helpers::default(),
            &CancellationToken::new(),
        )
        .await
        .remove(0);
    assert_eq!(sent.interim.len(), 1);
    assert_eq!(sent.response.unwrap().head().status_code(), Some(200));
}

#[tokio::test]
async fn a_head_response_has_no_body() {
    let (addr, _captured) =
        plain_server(Some(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n")).await;
    let sent = sender()
        .send(
            &target(addr, false),
            b"HEAD / HTTP/1.1\r\n\r\n",
            &Helpers::default(),
            &CancellationToken::new(),
        )
        .await
        .remove(0);
    assert_eq!(sent.error, None, "complete without the 99 bytes");
}

#[tokio::test]
async fn failures_keep_what_was_received() {
    // Closed mid-body.
    let (addr, _captured) =
        plain_server(Some(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhalf")).await;
    let sent = sender()
        .send(
            &target(addr, false),
            b"GET / HTTP/1.1\r\n\r\n",
            &Helpers::default(),
            &CancellationToken::new(),
        )
        .await
        .remove(0);
    assert!(sent.error.unwrap().contains("invalid response"));
    assert!(sent.response.is_none());
    assert!(sent.raw_response.ends_with(b"half"));

    // Closed without a byte.
    let (addr, _captured) = plain_server(Some(b"")).await;
    let sent = sender()
        .send(
            &target(addr, false),
            b"GET / HTTP/1.1\r\n\r\n",
            &Helpers::default(),
            &CancellationToken::new(),
        )
        .await
        .remove(0);
    assert_eq!(
        sent.error.as_deref(),
        Some("the connection closed without a response")
    );

    // Nobody listening.
    let free = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = free.local_addr().unwrap();
    drop(free);
    let sent = sender()
        .send(
            &target(addr, false),
            b"GET / HTTP/1.1\r\n\r\n",
            &Helpers::default(),
            &CancellationToken::new(),
        )
        .await
        .remove(0);
    assert!(
        sent.error
            .unwrap()
            .starts_with("cannot connect to 127.0.0.1:")
    );
    assert!(sent.timings.connect.is_none());
}

#[tokio::test]
async fn a_silent_server_times_out_and_a_send_can_be_cancelled() {
    let (addr, captured) = plain_server(None).await;
    let mut sender = sender();
    sender.read_timeout = Duration::from_millis(200);
    let sent = sender
        .send(
            &target(addr, false),
            b"GET / HTTP/1.1\r\n\r\n",
            &Helpers::default(),
            &CancellationToken::new(),
        )
        .await
        .remove(0);
    assert_eq!(
        sent.error.as_deref(),
        Some("cannot read the response: timed out")
    );
    assert_eq!(captured.await.unwrap().0, b"GET / HTTP/1.1\r\n\r\n");

    let (addr, _captured) = plain_server(None).await;
    sender.read_timeout = Duration::from_secs(60);
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        stop.cancel();
    });
    let sent = sender
        .send(
            &target(addr, false),
            b"GET / HTTP/1.1\r\n\r\n",
            &Helpers::default(),
            &cancel,
        )
        .await
        .remove(0);
    assert_eq!(sent.error.as_deref(), Some("cancelled"));
    assert!(sent.timings.total < Duration::from_secs(5));
}

// ---------------------------------------------------------------------------
// Helpers (#20)

/// A server that answers each request on each connection with the next
/// reply, and records the requests and how many connections it saw.
async fn scripted(
    replies: Vec<&'static [u8]>,
) -> (
    SocketAddr,
    Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let replies = Arc::new(std::sync::Mutex::new(replies.into_iter()));
    let (rec, conns) = (seen.clone(), connections.clone());
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            conns.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (rec, replies) = (rec.clone(), replies.clone());
            tokio::spawn(async move {
                loop {
                    let mut buf = Vec::new();
                    while hiccup_http::Request::parse(&buf, &hiccup_http::Limits::DEFAULT, false)
                        .ok()
                        .flatten()
                        .is_none()
                    {
                        let mut chunk = [0u8; 4096];
                        match s.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    rec.lock().unwrap().push(buf);
                    let Some(reply) = replies.lock().unwrap().next() else {
                        return;
                    };
                    if s.write_all(reply).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, seen, connections)
}

#[tokio::test]
async fn content_length_is_updated_only_when_asked() {
    let ok: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let (addr, seen, _) = scripted(vec![ok, ok]).await;
    let request = b"POST / HTTP/1.1\r\nContent-Length: 1\r\n\r\nabc";
    let sender = sender();
    let helpers = Helpers {
        update_content_length: true,
        ..Helpers::default()
    };
    let sent = sender
        .send(
            &target(addr, false),
            request,
            &helpers,
            &CancellationToken::new(),
        )
        .await
        .remove(0);
    assert_eq!(sent.applied, [Applied::ContentLengthUpdated], "shown");
    assert_eq!(
        &sent.request[..],
        b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"
    );
    assert_eq!(seen.lock().unwrap()[0], sent.request);
}

#[tokio::test]
async fn redirects_are_followed_per_policy_up_to_the_limit() {
    let chain = || {
        scripted(vec![
            b"HTTP/1.1 302 Found\r\nLocation: /two\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 301 Moved\r\nLocation: /out\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        ])
    };
    let sender = sender();
    let request = b"GET /one HTTP/1.1\r\nHost: x\r\n\r\n";
    let cancel = CancellationToken::new();

    // Off by default: the redirect is the response.
    let (origin, _, _) = chain().await;
    let hops = sender
        .send(
            &target(origin, false),
            request,
            &Helpers::default(),
            &cancel,
        )
        .await;
    assert_eq!(hops.len(), 1);
    assert_eq!(
        hops[0].response.as_ref().unwrap().head().status_code(),
        Some(302)
    );

    // Always, but at most one hop.
    let (origin, seen, _) = chain().await;
    let always = Helpers {
        redirects: Redirects::Always,
        max_redirects: 1,
        ..Helpers::default()
    };
    let hops = sender
        .send(&target(origin, false), request, &always, &cancel)
        .await;
    assert_eq!(hops.len(), 2);
    assert_eq!(hops[1].applied, [Applied::FollowedRedirect]);
    assert_eq!(
        &hops[1].request[..],
        b"GET /two HTTP/1.1\r\nHost: x\r\n\r\n"
    );
    assert_eq!(
        hops[1].response.as_ref().unwrap().head().status_code(),
        Some(301)
    );
    assert_eq!(seen.lock().unwrap().len(), 2, "/out is not requested");

    // In scope only: /out is excluded, so the chain stops before it.
    let (origin, _, _) = chain().await;
    let mut scope = Scope::default();
    scope.rules.push(hiccup_proxy::ScopeRule {
        exclude: true,
        scheme: None,
        host: "*".parse().unwrap(),
        port: None,
        path: Some(regex::Regex::new("^/out").unwrap()),
    });
    let in_scope = Helpers {
        redirects: Redirects::InScope(scope),
        max_redirects: 5,
        ..Helpers::default()
    };
    let hops = sender
        .send(&target(origin, false), request, &in_scope, &cancel)
        .await;
    assert_eq!(hops.len(), 2, "/two, but not /out");
}

#[tokio::test]
async fn a_connection_is_reused_only_when_asked() {
    let ok: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let (addr, _, connections) = scripted(vec![ok, ok, ok, ok]).await;
    let sender = sender();
    let get = b"GET / HTTP/1.1\r\n\r\n";
    let reuse = Helpers {
        reuse_connection: true,
        ..Helpers::default()
    };
    let (to, cancel) = (target(addr, false), CancellationToken::new());
    let send = |helpers| sender.send(&to, get, helpers, &cancel);

    let first = send(&reuse).await.remove(0);
    assert!(first.applied.is_empty() && first.timings.connect.is_some());
    let second = send(&reuse).await.remove(0);
    assert_eq!(second.applied, [Applied::ReusedConnection]);
    assert!(second.timings.connect.is_none() && second.error.is_none());
    assert_eq!(connections.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Off: a new connection each time.
    send(&Helpers::default()).await;
    assert_eq!(connections.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_reused_connection_that_was_closed_is_replaced() {
    // Answers one request per connection, then closes it.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let conns = connections.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            conns.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut chunk = [0u8; 4096];
            let _ = s.read(&mut chunk).await;
            let _ = s
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });
    let sender = sender();
    let reuse = Helpers {
        reuse_connection: true,
        ..Helpers::default()
    };
    let get = b"GET / HTTP/1.1\r\n\r\n";
    let (to, cancel) = (target(addr, false), CancellationToken::new());
    let send = || sender.send(&to, get, &reuse, &cancel);
    assert_eq!(send().await[0].error, None);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let second = send().await.remove(0);
    assert_eq!(second.error, None, "retried on a new connection");
    assert!(second.applied.is_empty(), "not reused in the end");
    assert_eq!(connections.load(std::sync::atomic::Ordering::SeqCst), 2);
}
