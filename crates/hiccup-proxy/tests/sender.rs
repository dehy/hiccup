// SPDX-License-Identifier: AGPL-3.0-or-later

//! The raw request sender, against servers that capture what they receive.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hiccup_proxy::{SendTarget, Sender, UpstreamConfig};
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

fn sender() -> Sender {
    Sender::new(UpstreamConfig::default()).unwrap()
}

/// Malformed on purpose: a bare LF, a space before the colon, a lowercase
/// method, a `Host` naming another site, and conflicting lengths.
const ODD: &[u8] = b"get  /x?a=%zz HTTP/1.1\nHost: elsewhere.test\r\nX-Odd :  1 \r\nContent-Length: 3\r\nContent-Length: 5\r\n\r\nabc";

#[tokio::test]
async fn the_exact_bytes_are_sent_to_the_target_whatever_the_host_header() {
    let (addr, captured) =
        plain_server(Some(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")).await;
    let sent = sender()
        .send(&target(addr, false), ODD, &CancellationToken::new())
        .await;
    assert_eq!(sent.error, None);
    assert_eq!(captured.await.unwrap().0, ODD, "byte for byte");

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
    let mut upstream = UpstreamConfig::default();
    upstream
        .sni
        .push(("*".parse().unwrap(), "origin.test".to_owned()));
    let sender = Sender::new(upstream).unwrap();
    let sent = sender
        .send(&target(addr, true), ODD, &CancellationToken::new())
        .await;
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
            &CancellationToken::new(),
        )
        .await;
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
            &CancellationToken::new(),
        )
        .await;
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
            &CancellationToken::new(),
        )
        .await;
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
            &CancellationToken::new(),
        )
        .await;
    assert!(sent.error.unwrap().contains("invalid response"));
    assert!(sent.response.is_none());
    assert!(sent.raw_response.ends_with(b"half"));

    // Closed without a byte.
    let (addr, _captured) = plain_server(Some(b"")).await;
    let sent = sender()
        .send(
            &target(addr, false),
            b"GET / HTTP/1.1\r\n\r\n",
            &CancellationToken::new(),
        )
        .await;
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
            &CancellationToken::new(),
        )
        .await;
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
            &CancellationToken::new(),
        )
        .await;
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
        .send(&target(addr, false), b"GET / HTTP/1.1\r\n\r\n", &cancel)
        .await;
    assert_eq!(sent.error.as_deref(), Some("cancelled"));
    assert!(sent.timings.total < Duration::from_secs(5));
}
