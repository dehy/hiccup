// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end tests: client → Hiccup → local origin server.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hiccup_http::{Limits, Request, Response};
use hiccup_proxy::{Exchange, Modification, Proxy, ProxyConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Harness

type Handler = Arc<dyn Fn(&Request) -> Vec<u8> + Send + Sync>;

/// A minimal origin server that records every request it receives.
struct Origin {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    connections: Arc<AtomicUsize>,
}

impl Origin {
    async fn start(handler: Handler) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let (rec, conns) = (received.clone(), connections.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                conns.fetch_add(1, Ordering::SeqCst);
                let (rec, handler) = (rec.clone(), handler.clone());
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    loop {
                        while let Ok(Some(req)) = Request::parse(&buf, &Limits::DEFAULT, false) {
                            buf.drain(..req.len());
                            rec.lock().unwrap().push(req.to_bytes());
                            let response = handler(&req);
                            if stream.write_all(&response).await.is_err() {
                                return;
                            }
                            if response
                                .windows(17)
                                .any(|w| w.eq_ignore_ascii_case(b"connection: close"))
                            {
                                return;
                            }
                        }
                        let mut chunk = [0u8; 4096];
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                });
            }
        });
        Self {
            addr,
            received,
            connections,
        }
    }

    fn ok(body: &'static str) -> Handler {
        Arc::new(move |_| {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .into_bytes()
        })
    }

    fn received(&self) -> Vec<Vec<u8>> {
        self.received.lock().unwrap().clone()
    }
}

struct Running {
    addr: SocketAddr,
    exchanges: Arc<Mutex<Vec<Exchange>>>,
    /// IDs given to the request observer.
    requests: Arc<Mutex<Vec<u64>>>,
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

async fn start_proxy() -> Running {
    start_proxy_with(|_| {}).await
}

async fn start_proxy_with(configure: impl FnOnce(&mut ProxyConfig)) -> Running {
    let mut config = ProxyConfig {
        listen: vec!["127.0.0.1:0".parse().unwrap()],
        connect_timeout: Duration::from_secs(2),
        shutdown_grace: Duration::from_millis(500),
        ..ProxyConfig::default()
    };
    configure(&mut config);
    let exchanges = Arc::new(Mutex::new(Vec::new()));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let (sink, request_sink) = (exchanges.clone(), requests.clone());
    let proxy = Proxy::bind(config)
        .await
        .unwrap()
        .with_observer(Arc::new(move |e: &Exchange| {
            sink.lock().unwrap().push(e.clone())
        }))
        .with_request_observer(Arc::new(move |e: &Exchange| {
            assert!(e.response.is_none());
            request_sink.lock().unwrap().push(e.id);
        }));
    let addr = proxy.local_addrs()[0];
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(proxy.serve(shutdown.clone()));
    Running {
        addr,
        exchanges,
        requests,
        shutdown,
        task,
    }
}

/// Reads one complete response from `stream`.
async fn read_response(stream: &mut TcpStream, buf: &mut Vec<u8>, method: &[u8]) -> Response {
    loop {
        if let Some(r) = Response::parse(buf, method, &Limits::DEFAULT, false).unwrap() {
            buf.drain(..r.len());
            return r;
        }
        let mut chunk = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .expect("response timed out")
            .unwrap();
        if n == 0 {
            return Response::parse(buf, method, &Limits::DEFAULT, true)
                .unwrap()
                .expect("complete at EOF");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Reads until the peer closes; returns whether it closed.
async fn closes(stream: &mut TcpStream) -> bool {
    let mut chunk = [0u8; 64];
    matches!(
        tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await,
        Ok(Ok(0) | Err(_))
    )
}

// ---------------------------------------------------------------------------
// Tests

#[tokio::test]
async fn forwards_origin_form_and_keeps_everything_else() {
    let origin = Origin::start(Origin::ok("hello")).await;
    let proxy = start_proxy().await;

    let request = format!(
        "GET http://{}/path?q=1 HTTP/1.1\r\nHost: example.test\r\nX-Weird : v\r\nProxy-Connection: keep-alive\r\n\r\n",
        origin.addr
    );
    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let response = read_response(&mut client, &mut Vec::new(), b"GET").await;

    assert_eq!(
        response.to_bytes(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    );
    // Only the target changed; Host, odd headers and hop-by-hop headers are kept.
    assert_eq!(
        origin.received(),
        [b"GET /path?q=1 HTTP/1.1\r\nHost: example.test\r\nX-Weird : v\r\nProxy-Connection: keep-alive\r\n\r\n".to_vec()]
    );

    let exchanges = proxy.exchanges.lock().unwrap();
    let e = &exchanges[0];
    assert_eq!(e.received.to_bytes(), request.as_bytes());
    assert_eq!(e.upstream, origin.addr.to_string());
    assert_eq!(
        e.modifications,
        [Modification::TargetRewritten {
            original: format!("http://{}/path?q=1", origin.addr)
                .into_bytes()
                .into(),
            rewritten: b"/path?q=1".to_vec().into(),
        }]
    );
    assert!(e.response.is_some() && e.error.is_none());
}

#[tokio::test]
async fn keep_alive_reuses_the_upstream_connection() {
    let origin = Origin::start(Origin::ok("x")).await;
    let proxy = start_proxy().await;
    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    let mut buf = Vec::new();
    for path in ["/a", "/b", "/c"] {
        let req = format!(
            "GET http://{}{path} HTTP/1.1\r\nHost: h\r\n\r\n",
            origin.addr
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let r = read_response(&mut client, &mut buf, b"GET").await;
        assert_eq!(r.head().status_code(), Some(200));
    }
    assert_eq!(origin.received().len(), 3);
    assert_eq!(origin.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn idempotent_request_is_retried_when_a_reused_upstream_was_closed() {
    // An origin that answers one request per connection, then closes without
    // saying so (no `Connection: close`), like a server whose idle timeout hit.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let conns = connections.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            conns.fetch_add(1, Ordering::SeqCst);
            let mut buf = Vec::new();
            while Request::parse(&buf, &Limits::DEFAULT, false)
                .unwrap()
                .is_none()
            {
                let mut chunk = [0u8; 1024];
                let n = s.read(&mut chunk).await.unwrap();
                buf.extend_from_slice(&chunk[..n]);
            }
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        }
    });
    let proxy = start_proxy().await;
    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    let mut buf = Vec::new();
    for _ in 0..2 {
        let req = format!("GET http://{addr}/ HTTP/1.1\r\n\r\n");
        client.write_all(req.as_bytes()).await.unwrap();
        let r = read_response(&mut client, &mut buf, b"GET").await;
        assert_eq!(r.head().status_code(), Some(200));
        // Let the origin's close reach the proxy before the next request.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn pipelined_requests_are_answered_in_order() {
    let origin = Origin::start(Arc::new(|req: &Request| {
        let body = req.head().target().to_vec();
        [
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes(),
            body,
        ]
        .concat()
    }))
    .await;
    let proxy = start_proxy().await;
    let req = |p: &str| format!("GET http://{}{p} HTTP/1.1\r\nHost: h\r\n\r\n", origin.addr);
    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client
        .write_all(format!("{}{}", req("/one"), req("/two")).as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    let a = read_response(&mut client, &mut buf, b"GET").await;
    let b = read_response(&mut client, &mut buf, b"GET").await;
    assert_eq!(&a.body()[..], b"/one");
    assert_eq!(&b.body()[..], b"/two");
}

#[tokio::test]
async fn chunked_bodies_pass_through_unchanged() {
    let origin = Origin::start(Arc::new(|_: &Request| {
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n0\r\nT: 1\r\n\r\n"
            .to_vec()
    }))
    .await;
    let proxy = start_proxy().await;
    let body = "4\r\nWiki\r\n0\r\n\r\n";
    let req = format!(
        "POST http://{}/up HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n{body}",
        origin.addr
    );
    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client.write_all(req.as_bytes()).await.unwrap();
    let r = read_response(&mut client, &mut Vec::new(), b"POST").await;
    assert_eq!(&r.body()[..], b"3;x=y\r\nabc\r\n0\r\nT: 1\r\n\r\n");
    assert!(origin.received()[0].ends_with(body.as_bytes()));
}

#[tokio::test]
async fn connection_close_and_http10_close_the_client() {
    let origin = Origin::start(Origin::ok("x")).await;
    let proxy = start_proxy().await;
    for req in [
        format!(
            "GET http://{}/ HTTP/1.1\r\nConnection: close\r\n\r\n",
            origin.addr
        ),
        format!("GET http://{}/ HTTP/1.0\r\n\r\n", origin.addr),
    ] {
        let mut client = TcpStream::connect(proxy.addr).await.unwrap();
        client.write_all(req.as_bytes()).await.unwrap();
        let r = read_response(&mut client, &mut Vec::new(), b"GET").await;
        assert_eq!(r.head().status_code(), Some(200));
        assert!(closes(&mut client).await, "{req}");
    }
}

#[tokio::test]
async fn interim_responses_are_relayed() {
    let origin = Origin::start(Arc::new(|_: &Request| {
        b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()
    }))
    .await;
    let proxy = start_proxy().await;
    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client
        .write_all(format!("GET http://{}/ HTTP/1.1\r\n\r\n", origin.addr).as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    assert_eq!(
        read_response(&mut client, &mut buf, b"GET")
            .await
            .head()
            .status_code(),
        Some(103)
    );
    assert_eq!(
        read_response(&mut client, &mut buf, b"GET")
            .await
            .head()
            .status_code(),
        Some(200)
    );
    let exchanges = proxy.exchanges.lock().unwrap();
    assert_eq!(exchanges[0].interim.len(), 1);
}

#[tokio::test]
async fn connect_tunnels_bytes_both_ways() {
    // An echo server stands in for a TLS server.
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let (mut r, mut w) = s.split();
        let _ = tokio::io::copy(&mut r, &mut w).await;
    });
    let proxy = start_proxy().await;

    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    // Bytes sent right after the CONNECT head must reach the server too.
    client
        .write_all(
            format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\nearly").as_bytes(),
        )
        .await
        .unwrap();
    let mut buf = Vec::new();
    let r = read_response(&mut client, &mut buf, b"CONNECT").await;
    assert_eq!(r.head().status_code(), Some(200));
    client.write_all(b"-late").await.unwrap();

    let expected = b"early-late";
    while buf.len() < expected.len() {
        let mut chunk = [0u8; 64];
        let n = client.read(&mut chunk).await.unwrap();
        assert!(n > 0, "tunnel closed early");
        buf.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(buf, expected);
}

#[tokio::test]
async fn errors_are_answered_by_hiccup() {
    let proxy = start_proxy().await;
    // A port that refuses connections.
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let cases = [
        (
            format!("GET http://{closed}/ HTTP/1.1\r\n\r\n"),
            502,
            b"GET".as_slice(),
        ),
        (
            format!("CONNECT {closed} HTTP/1.1\r\n\r\n"),
            502,
            b"CONNECT".as_slice(),
        ),
        (
            "GET /origin-form HTTP/1.1\r\nHost: x\r\n\r\n".to_owned(),
            400,
            b"GET".as_slice(),
        ),
        (
            "GET https://x/ HTTP/1.1\r\n\r\n".to_owned(),
            501,
            b"GET".as_slice(),
        ),
        (
            "CONNECT nohostport HTTP/1.1\r\n\r\n".to_owned(),
            400,
            b"CONNECT".as_slice(),
        ),
    ];
    for (req, status, method) in cases {
        let mut client = TcpStream::connect(proxy.addr).await.unwrap();
        client.write_all(req.as_bytes()).await.unwrap();
        let r = read_response(&mut client, &mut Vec::new(), method).await;
        assert_eq!(r.head().status_code(), Some(status), "{req}");
        assert!(r.body().starts_with(b"Hiccup: "), "{req}");
        assert!(closes(&mut client).await, "{req}");
    }
    // The failed forward is still reported, with its error.
    let exchanges = proxy.exchanges.lock().unwrap();
    assert_eq!(exchanges.len(), 1);
    assert!(
        exchanges[0]
            .error
            .as_deref()
            .unwrap()
            .contains("cannot connect")
    );
}

#[tokio::test]
async fn oversized_head_gets_431() {
    let proxy = start_proxy().await;
    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    let huge = format!(
        "GET http://x/ HTTP/1.1\r\nX: {}\r\n\r\n",
        "a".repeat(70_000)
    );
    // The proxy may close before reading everything; ignore write errors.
    let _ = client.write_all(huge.as_bytes()).await;
    let r = read_response(&mut client, &mut Vec::new(), b"GET").await;
    assert_eq!(r.head().status_code(), Some(431));
}

#[tokio::test]
async fn shutdown_closes_idle_connections_and_returns() {
    let proxy = start_proxy().await;
    let mut idle = TcpStream::connect(proxy.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    proxy.shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), proxy.task)
        .await
        .expect("serve returns after shutdown")
        .unwrap();
    assert!(closes(&mut idle).await);
    assert!(
        TcpStream::connect(proxy.addr).await.is_err(),
        "listener is closed"
    );
}

#[tokio::test]
async fn binding_fails_cleanly_when_the_port_is_taken() {
    let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = ProxyConfig {
        listen: vec![taken.local_addr().unwrap()],
        ..ProxyConfig::default()
    };
    let err = Proxy::bind(config).await.err().expect("bind fails");
    assert!(err.to_string().contains("cannot listen on"), "{err}");
}

/// The acceptance test from issue #8: real curl through the proxy, for plain
/// HTTP and a CONNECT tunnel. Skipped when curl is not installed.
#[tokio::test(flavor = "multi_thread")]
async fn curl_through_the_proxy() {
    if tokio::process::Command::new("curl")
        .arg("--version")
        .output()
        .await
        .is_err()
    {
        eprintln!("curl not found; skipping");
        return;
    }
    let origin = Origin::start(Origin::ok("from origin")).await;
    let proxy = start_proxy().await;
    let proxy_url = format!("http://{}", proxy.addr);
    let url = format!("http://{}/curl", origin.addr);
    for tunnel in [false, true] {
        let mut cmd = tokio::process::Command::new("curl");
        cmd.args([
            "--silent",
            "--show-error",
            "--max-time",
            "10",
            "--noproxy",
            "",
            "-x",
            &proxy_url,
        ]);
        if tunnel {
            cmd.arg("--proxytunnel");
        }
        let out = cmd.arg(&url).output().await.unwrap();
        assert!(
            out.status.success(),
            "curl failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"from origin", "tunnel={tunnel}");
    }
    // Plain HTTP is forwarded in origin-form; the tunnel carries curl's own request.
    let received = origin.received();
    assert_eq!(received.len(), 2);
    assert!(
        received
            .iter()
            .all(|r| r.starts_with(b"GET /curl HTTP/1.1\r\n"))
    );
}

/// An origin that answers one connection with `parts`, waiting for a signal
/// before each part after the first; it closes the connection at the end.
async fn scripted_origin(parts: Vec<&'static [u8]>) -> (SocketAddr, tokio::sync::mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (next, mut go) = tokio::sync::mpsc::channel::<()>(8);
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        while Request::parse(&buf, &Limits::DEFAULT, false)
            .unwrap()
            .is_none()
        {
            let mut chunk = [0u8; 4096];
            let n = stream.read(&mut chunk).await.unwrap();
            buf.extend_from_slice(&chunk[..n]);
        }
        for (i, part) in parts.into_iter().enumerate() {
            if i > 0 && go.recv().await.is_none() {
                return;
            }
            stream.write_all(part).await.unwrap();
        }
    });
    (addr, next)
}

/// Reads from `stream` until `buf` ends with `suffix`.
async fn read_until(stream: &mut TcpStream, buf: &mut Vec<u8>, suffix: &[u8]) {
    while !buf.ends_with(suffix) {
        let mut chunk = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .expect("timed out: the bytes were not relayed")
            .unwrap();
        assert!(n > 0, "closed early: {}", String::from_utf8_lossy(buf));
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[tokio::test]
async fn a_body_is_relayed_as_it_arrives() {
    // A stream that has not ended (like server-sent events).
    let (origin, next) = scripted_origin(vec![
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nfirst\r\n",
        b"4\r\nlast\r\n0\r\n\r\n",
    ])
    .await;
    let proxy = start_proxy().await;
    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client
        .write_all(format!("GET http://{origin}/events HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    read_until(&mut client, &mut buf, b"first\r\n").await;
    assert_eq!(*proxy.requests.lock().unwrap(), [1], "its request is known");
    assert!(
        proxy.exchanges.lock().unwrap().is_empty(),
        "not complete yet"
    );

    next.send(()).await.unwrap();
    read_until(&mut client, &mut buf, b"0\r\n\r\n").await;
    let exchanges = proxy.exchanges.lock().unwrap();
    let response = exchanges[0].response.as_ref().unwrap();
    assert_eq!(
        response.to_bytes(),
        buf,
        "kept whole: it is under the limit"
    );
    assert!(!exchanges[0].response_truncated && exchanges[0].error.is_none());
    assert_eq!(exchanges[0].id, 1, "the request observer's ID");
}

#[tokio::test]
async fn a_big_body_is_relayed_whole_and_kept_up_to_the_limit() {
    let origin = Origin::start(Origin::ok("0123456789abcdefghij")).await;
    let proxy = start_proxy_with(|c| c.max_kept_body = 8).await;
    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client
        .write_all(format!("GET http://{}/ HTTP/1.1\r\n\r\n", origin.addr).as_bytes())
        .await
        .unwrap();
    let response = read_response(&mut client, &mut Vec::new(), b"GET").await;
    assert_eq!(&response.body()[..], b"0123456789abcdefghij");

    let exchanges = proxy.exchanges.lock().unwrap();
    assert_eq!(
        &exchanges[0].response.as_ref().unwrap().body()[..],
        b"01234567"
    );
    assert!(exchanges[0].response_truncated);
}

#[tokio::test]
async fn an_upstream_dying_mid_body_closes_the_client() {
    // Ten bytes announced, four sent, then the origin closes.
    let (origin, _next) =
        scripted_origin(vec![b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhalf"]).await;
    let proxy = start_proxy().await;
    let mut client = TcpStream::connect(proxy.addr).await.unwrap();
    client
        .write_all(format!("GET http://{origin}/ HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    read_until(&mut client, &mut buf, b"half").await;
    assert!(closes(&mut client).await, "the client must see the cut");
    let exchanges = proxy.exchanges.lock().unwrap();
    let error = exchanges[0].error.as_deref().unwrap();
    assert!(error.contains("mid-body"), "{error}");
    assert_eq!(&exchanges[0].response.as_ref().unwrap().body()[..], b"half");
}
