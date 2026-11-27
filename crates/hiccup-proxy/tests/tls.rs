// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS interception: client → Hiccup (CONNECT + TLS) → local TLS origin.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hiccup_http::{Limits, Response};
use hiccup_proxy::{CertificateAuthority, Exchange, Proxy, ProxyConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Harness

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A TLS origin server with a self-signed certificate. Every response body is
/// `<SNI or "-">|<request line>`.
struct TlsOrigin {
    addr: SocketAddr,
    cert: CertificateDer<'static>,
    connections: Arc<AtomicUsize>,
}

impl TlsOrigin {
    async fn start() -> Self {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        let cert = cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let conns = connections.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                conns.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let sni = tls.get_ref().1.server_name().unwrap_or("-").to_owned();
                    let mut buf = Vec::new();
                    loop {
                        while let Some(end) = find(&buf, b"\r\n\r\n") {
                            let head: Vec<u8> = buf.drain(..end + 4).collect();
                            let line = String::from_utf8_lossy(&head);
                            let line = line.lines().next().unwrap_or_default();
                            let body = format!("{sni}|{line}");
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                                body.len()
                            );
                            if tls.write_all(response.as_bytes()).await.is_err() {
                                return;
                            }
                        }
                        let mut chunk = [0u8; 4096];
                        match tls.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                });
            }
        });
        Self {
            addr,
            cert,
            connections,
        }
    }
}

struct Harness {
    proxy: SocketAddr,
    ca: Arc<CertificateAuthority>,
    exchanges: Arc<Mutex<Vec<Exchange>>>,
    shutdown: CancellationToken,
}

impl Harness {
    async fn start(config: ProxyConfig) -> Self {
        let ca = Arc::new(CertificateAuthority::generate().unwrap());
        let exchanges = Arc::new(Mutex::new(Vec::new()));
        let recorded = exchanges.clone();
        let proxy = Proxy::bind(ProxyConfig {
            listen: vec!["127.0.0.1:0".parse().unwrap()],
            ..config
        })
        .await
        .unwrap()
        .with_observer(Arc::new(move |e: &Exchange| {
            recorded.lock().unwrap().push(e.clone());
        }))
        .intercept_tls(ca.clone())
        .unwrap();
        let addr = proxy.local_addrs()[0];
        let shutdown = CancellationToken::new();
        tokio::spawn(proxy.serve(shutdown.clone()));
        Self {
            proxy: addr,
            ca,
            exchanges,
            shutdown,
        }
    }

    /// Opens a `CONNECT` tunnel to `target` and returns it after the 200.
    async fn connect(&self, target: &str) -> TcpStream {
        let mut stream = TcpStream::connect(self.proxy).await.unwrap();
        stream
            .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut head = Vec::new();
        while find(&head, b"\r\n\r\n").is_none() {
            let mut byte = [0u8; 1];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 1, "proxy closed");
            head.push(byte[0]);
        }
        assert!(
            head.starts_with(b"HTTP/1.1 200 "),
            "{}",
            String::from_utf8_lossy(&head)
        );
        stream
    }

    fn exchanges(&self) -> Vec<Exchange> {
        self.exchanges.lock().unwrap().clone()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

fn client_config(trusted: &CertificateDer<'static>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(trusted.clone()).unwrap();
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

async fn tls_client<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    trusted: &CertificateDer<'static>,
    name: &str,
) -> std::io::Result<tokio_rustls::client::TlsStream<S>> {
    let name = ServerName::try_from(name.to_owned()).unwrap();
    TlsConnector::from(client_config(trusted))
        .connect(name, stream)
        .await
}

/// Sends `request` and reads one response.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, request: &[u8]) -> Response {
    stream.write_all(request).await.unwrap();
    let mut buf = Vec::new();
    loop {
        if let Some(r) = Response::parse(&buf, b"GET", &Limits::DEFAULT, false).unwrap() {
            return r;
        }
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await.unwrap();
        if n == 0 {
            return Response::parse(&buf, b"GET", &Limits::DEFAULT, true)
                .unwrap()
                .expect("a response before EOF");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn body(r: &Response) -> String {
    String::from_utf8_lossy(r.body()).into_owned()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Tests

#[tokio::test]
async fn https_is_intercepted_with_a_certificate_from_the_ca() {
    let origin = TlsOrigin::start().await;
    let h = Harness::start(ProxyConfig::default()).await;
    let target = format!("localhost:{}", origin.addr.port());

    let tunnel = h.connect(&target).await;
    let ca_cert = CertificateDer::from(h.ca.cert_der().to_vec());
    let mut tls = tls_client(tunnel, &ca_cert, "localhost").await.unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));

    let request = b"GET /one HTTP/1.1\r\nHost: localhost\r\nX-Odd:  kept  \r\n\r\n";
    let r = exchange(&mut tls, request).await;
    assert_eq!(body(&r), "localhost|GET /one HTTP/1.1");
    let r = exchange(&mut tls, b"GET /two HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
    assert_eq!(body(&r), "localhost|GET /two HTTP/1.1");
    assert_eq!(
        origin.connections.load(Ordering::SeqCst),
        1,
        "upstream reused"
    );

    let exchanges = h.exchanges();
    assert_eq!(exchanges.len(), 2);
    let first = &exchanges[0];
    assert!(first.tls);
    assert_eq!(first.upstream, target);
    assert_eq!(first.received.to_bytes(), request);
    assert_eq!(&first.forwarded[..], request, "forwarded as received");
    assert!(first.modifications.is_empty());
}

#[tokio::test]
async fn an_ip_target_without_sni_gets_an_ip_certificate() {
    let origin = TlsOrigin::start().await;
    let h = Harness::start(ProxyConfig::default()).await;

    let tunnel = h.connect(&origin.addr.to_string()).await;
    let ca_cert = CertificateDer::from(h.ca.cert_der().to_vec());
    // An IP server name: rustls sends no SNI and checks the IP SAN.
    let mut tls = tls_client(tunnel, &ca_cert, "127.0.0.1").await.unwrap();
    let r = exchange(&mut tls, b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").await;
    assert_eq!(body(&r), "-|GET / HTTP/1.1", "no SNI upstream either");
}

#[tokio::test]
async fn passthrough_hosts_are_not_intercepted() {
    let origin = TlsOrigin::start().await;
    let h = Harness::start(ProxyConfig {
        tls_passthrough: vec!["LOCALHOST".parse().unwrap()],
        ..ProxyConfig::default()
    })
    .await;

    let tunnel = h
        .connect(&format!("localhost:{}", origin.addr.port()))
        .await;
    // The client sees the origin's own certificate.
    let mut tls = tls_client(tunnel, &origin.cert, "localhost").await.unwrap();
    let r = exchange(&mut tls, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
    assert_eq!(body(&r), "localhost|GET / HTTP/1.1");
    assert!(h.exchanges().is_empty());
}

#[tokio::test]
async fn an_unreachable_upstream_gets_a_502_inside_the_tunnel() {
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let h = Harness::start(ProxyConfig::default()).await;

    let tunnel = h.connect(&format!("localhost:{port}")).await;
    let ca_cert = CertificateDer::from(h.ca.cert_der().to_vec());
    let mut tls = tls_client(tunnel, &ca_cert, "localhost").await.unwrap();
    let r = exchange(&mut tls, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
    assert_eq!(r.head().status_code(), Some(502));
    assert!(
        body(&r).starts_with("Hiccup: cannot connect to"),
        "{}",
        body(&r)
    );
    let exchanges = h.exchanges();
    assert_eq!(exchanges.len(), 1);
    assert!(exchanges[0].error.is_some());
}

#[tokio::test]
async fn a_tunnel_without_tls_is_relayed() {
    // A plain-text origin that answers one request.
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = origin.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = origin.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = s.read(&mut buf).await.unwrap();
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nplain")
            .await
            .unwrap();
    });
    let h = Harness::start(ProxyConfig::default()).await;

    let mut tunnel = h.connect(&addr.to_string()).await;
    let r = exchange(&mut tunnel, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert_eq!(body(&r), "plain");
    assert!(h.exchanges().is_empty());
}

#[tokio::test]
async fn a_client_that_rejects_the_certificate_does_not_break_the_proxy() {
    let origin = TlsOrigin::start().await;
    let h = Harness::start(ProxyConfig::default()).await;
    let target = format!("localhost:{}", origin.addr.port());

    // This client trusts only the origin's certificate, not the CA.
    let tunnel = h.connect(&target).await;
    assert!(tls_client(tunnel, &origin.cert, "localhost").await.is_err());

    let tunnel = h.connect(&target).await;
    let ca_cert = CertificateDer::from(h.ca.cert_der().to_vec());
    let mut tls = tls_client(tunnel, &ca_cert, "localhost").await.unwrap();
    let r = exchange(&mut tls, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
    assert_eq!(r.head().status_code(), Some(200));
}

/// A real TLS client: curl validates the intercepted certificate with its own
/// TLS library (OpenSSL, LibreSSL or Schannel). Skipped without curl.
#[tokio::test(flavor = "multi_thread")]
async fn curl_trusts_the_intercepted_certificate() {
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("curl not found; skipping");
        return;
    }
    let origin = TlsOrigin::start().await;
    let h = Harness::start(ProxyConfig::default()).await;
    let dir = tempfile::tempdir().unwrap();
    let ca_file = dir.path().join("hiccup.pem");
    std::fs::write(&ca_file, h.ca.cert_pem()).unwrap();

    let mut cmd = tokio::process::Command::new("curl");
    cmd.args(["--silent", "--show-error", "--max-time", "10"])
        .args(["--noproxy", "", "-x", &format!("http://{}", h.proxy)])
        .arg("--cacert")
        .arg(&ca_file);
    if cfg!(windows) {
        // Schannel checks revocation by default, and the CA has no CRL.
        cmd.arg("--ssl-no-revoke");
    }
    let url = format!("https://localhost:{}/curl", origin.addr.port());
    let out = cmd.arg(&url).output().await.unwrap();
    assert!(
        out.status.success(),
        "curl failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"localhost|GET /curl HTTP/1.1");
    assert_eq!(h.exchanges().len(), 1);
}
