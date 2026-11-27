// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS interception: client → Hiccup (CONNECT + TLS) → local TLS origin.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hiccup_http::{Limits, Response};
use hiccup_proxy::{
    CertificateAuthority, ClientCert, Exchange, Proxy, ProxyConfig, TlsVersion, UpstreamConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
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
/// `<SNI or "-">|<request line>`; the `X-Tls` header gives the TLS version and
/// `X-Client-Cert` whether the client presented a certificate.
struct TlsOrigin {
    addr: SocketAddr,
    cert: CertificateDer<'static>,
    connections: Arc<AtomicUsize>,
}

impl TlsOrigin {
    async fn start() -> Self {
        Self::start_with(None).await
    }

    /// With `client_ca`, asks for a client certificate signed by it
    /// (optional).
    async fn start_with(client_ca: Option<CertificateDer<'static>>) -> Self {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        let cert = cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let builder = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap();
        let builder = match client_ca {
            Some(ca) => {
                let mut roots = RootCertStore::empty();
                roots.add(ca).unwrap();
                let verifier =
                    WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
                        .allow_unauthenticated()
                        .build()
                        .unwrap();
                builder.with_client_cert_verifier(verifier)
            }
            None => builder.with_no_client_auth(),
        };
        let mut config = builder.with_single_cert(vec![cert.clone()], key).unwrap();
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
                    let conn = tls.get_ref().1;
                    let sni = conn.server_name().unwrap_or("-").to_owned();
                    let version = match conn.protocol_version() {
                        Some(rustls::ProtocolVersion::TLSv1_2) => "1.2",
                        Some(rustls::ProtocolVersion::TLSv1_3) => "1.3",
                        _ => "?",
                    };
                    let client_cert = if conn.peer_certificates().is_some() {
                        "yes"
                    } else {
                        "no"
                    };
                    let mut buf = Vec::new();
                    loop {
                        while let Some(end) = find(&buf, b"\r\n\r\n") {
                            let head: Vec<u8> = buf.drain(..end + 4).collect();
                            let line = String::from_utf8_lossy(&head);
                            let line = line.lines().next().unwrap_or_default();
                            if line.contains("/hang") {
                                std::future::pending::<()>().await;
                            }
                            let body = format!("{sni}|{line}");
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nX-Tls: {version}\r\n\
                                 X-Client-Cert: {client_cert}\r\n\
                                 Content-Length: {}\r\n\r\n{body}",
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

// ---------------------------------------------------------------------------
// Upstream options (#11)

fn header(r: &Response, name: &str) -> String {
    let h = r
        .head()
        .get(name)
        .unwrap_or_else(|| panic!("no {name} header"));
    String::from_utf8_lossy(h.value()).into_owned()
}

/// Opens an intercepted tunnel to `target` and sends one GET for `path`.
async fn get(h: &Harness, target: &str, server_name: &str, path: &str) -> Response {
    let tunnel = h.connect(target).await;
    let ca_cert = CertificateDer::from(h.ca.cert_der().to_vec());
    let mut tls = tls_client(tunnel, &ca_cert, server_name).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: {server_name}\r\n\r\n");
    exchange(&mut tls, request.as_bytes()).await
}

fn with_upstream(upstream: UpstreamConfig) -> ProxyConfig {
    ProxyConfig {
        upstream,
        ..ProxyConfig::default()
    }
}

#[tokio::test]
async fn verification_rejects_an_untrusted_upstream() {
    let origin = TlsOrigin::start().await;
    let target = format!("localhost:{}", origin.addr.port());

    let h = Harness::start(with_upstream(UpstreamConfig {
        verify: true,
        ..UpstreamConfig::default()
    }))
    .await;
    let r = get(&h, &target, "localhost", "/").await;
    assert_eq!(r.head().status_code(), Some(502));
    assert!(
        body(&r).contains("invalid peer certificate"),
        "{}",
        body(&r)
    );

    // Off by default: the self-signed origin is accepted.
    let h = Harness::start(ProxyConfig::default()).await;
    let r = get(&h, &target, "localhost", "/").await;
    assert_eq!(r.head().status_code(), Some(200));
}

#[tokio::test]
async fn sni_can_be_overridden_per_host() {
    let origin = TlsOrigin::start().await;
    let h = Harness::start(with_upstream(UpstreamConfig {
        sni: vec![("*.test".parse().unwrap(), "override.example".into())],
        resolve: vec![("app.test".parse().unwrap(), "127.0.0.1".parse().unwrap())],
        ..UpstreamConfig::default()
    }))
    .await;
    let target = format!("app.test:{}", origin.addr.port());
    let r = get(&h, &target, "app.test", "/").await;
    assert_eq!(body(&r), "override.example|GET / HTTP/1.1");
}

#[tokio::test]
async fn resolve_overrides_dns() {
    let origin = TlsOrigin::start().await;
    let h = Harness::start(with_upstream(UpstreamConfig {
        resolve: vec![(
            "Target.Invalid".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
        )],
        ..UpstreamConfig::default()
    }))
    .await;
    // `.invalid` never resolves (RFC 6761): only the override can reach it.
    let target = format!("target.invalid:{}", origin.addr.port());
    let r = get(&h, &target, "target.invalid", "/").await;
    assert_eq!(body(&r), "target.invalid|GET / HTTP/1.1");
}

#[tokio::test]
async fn tls_versions_can_be_limited() {
    let origin = TlsOrigin::start().await;
    let target = format!("localhost:{}", origin.addr.port());

    let h = Harness::start(ProxyConfig::default()).await;
    assert_eq!(
        header(&get(&h, &target, "localhost", "/").await, "x-tls"),
        "1.3"
    );

    let h = Harness::start(with_upstream(UpstreamConfig {
        tls_max: TlsVersion::Tls12,
        ..UpstreamConfig::default()
    }))
    .await;
    assert_eq!(
        header(&get(&h, &target, "localhost", "/").await, "x-tls"),
        "1.2"
    );

    // An empty range is refused up front.
    let err = Proxy::bind(ProxyConfig {
        listen: vec!["127.0.0.1:0".parse().unwrap()],
        upstream: UpstreamConfig {
            tls_min: TlsVersion::Tls13,
            tls_max: TlsVersion::Tls12,
            ..UpstreamConfig::default()
        },
        ..ProxyConfig::default()
    })
    .await
    .unwrap()
    .intercept_tls(Arc::new(CertificateAuthority::generate().unwrap()))
    .err()
    .unwrap();
    assert!(err.to_string().contains("no TLS version"), "{err}");
}

#[tokio::test]
async fn client_certificates_are_presented_per_host() {
    // A client CA, and a client certificate it signed.
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let client_key = rcgen::KeyPair::generate().unwrap();
    let client_cert = rcgen::CertificateParams::new(vec!["client".to_owned()])
        .unwrap()
        .signed_by(&client_key, &issuer)
        .unwrap();
    let client = ClientCert::from_pem(
        client_cert.pem().as_bytes(),
        client_key.serialize_pem().as_bytes(),
    )
    .unwrap();

    let origin = TlsOrigin::start_with(Some(ca_cert.der().clone())).await;
    let target = format!("localhost:{}", origin.addr.port());

    let h = Harness::start(with_upstream(UpstreamConfig {
        client_certs: vec![("localhost".parse().unwrap(), client)],
        ..UpstreamConfig::default()
    }))
    .await;
    let r = get(&h, &target, "localhost", "/").await;
    assert_eq!(header(&r, "x-client-cert"), "yes");

    let h = Harness::start(ProxyConfig::default()).await;
    let r = get(&h, &target, "localhost", "/").await;
    assert_eq!(header(&r, "x-client-cert"), "no");
}

#[tokio::test]
async fn upstream_timeouts_answer_502() {
    let origin = TlsOrigin::start().await;
    // Accepts TCP but never speaks TLS.
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_port = silent.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = silent.accept().await {
            held.push(s);
        }
    });
    let h = Harness::start(ProxyConfig {
        connect_timeout: std::time::Duration::from_millis(300),
        read_timeout: std::time::Duration::from_millis(300),
        ..ProxyConfig::default()
    })
    .await;

    let started = std::time::Instant::now();
    let r = get(&h, &format!("localhost:{silent_port}"), "localhost", "/").await;
    assert_eq!(r.head().status_code(), Some(502));
    assert!(body(&r).contains("timed out"), "{}", body(&r));

    let target = format!("localhost:{}", origin.addr.port());
    let r = get(&h, &target, "localhost", "/hang").await;
    assert_eq!(r.head().status_code(), Some(502));
    assert!(body(&r).contains("timed out"), "{}", body(&r));
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}
