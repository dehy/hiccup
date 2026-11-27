// SPDX-License-Identifier: AGPL-3.0-or-later

//! The intercept queue, end to end: client → Hiccup (held) → origin.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use hiccup_proxy::{
    Direction, Exchange, InterceptQueue, InterceptRules, InterceptSettings, Modification, Pending,
    Proxy, ProxyConfig, Verdict,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\norigin";

/// An origin that records each request it receives (one per connection)
/// and answers [`RESPONSE`].
async fn origin() -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let rec = received.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let rec = rec.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                rec.lock().unwrap().push(buf);
                let _ = s.write_all(RESPONSE).await;
            });
        }
    });
    (addr, received)
}

struct Harness {
    proxy: SocketAddr,
    queue: Arc<InterceptQueue>,
    exchanges: Arc<Mutex<Vec<Exchange>>>,
    shutdown: CancellationToken,
}

impl Harness {
    async fn start(settings: InterceptSettings) -> Self {
        let queue = InterceptQueue::new();
        queue.set(settings);
        let exchanges = Arc::new(Mutex::new(Vec::new()));
        let recorded = exchanges.clone();
        let proxy = Proxy::bind(ProxyConfig {
            listen: vec!["127.0.0.1:0".parse().unwrap()],
            ..ProxyConfig::default()
        })
        .await
        .unwrap()
        .with_intercept(queue.clone())
        .with_observer(Arc::new(move |e: &Exchange| {
            recorded.lock().unwrap().push(e.clone());
        }));
        let addr = proxy.local_addrs()[0];
        let shutdown = CancellationToken::new();
        tokio::spawn(proxy.serve(shutdown.clone()));
        Self {
            proxy: addr,
            queue,
            exchanges,
            shutdown,
        }
    }

    /// Waits for the next held item.
    async fn next_pending(&self) -> Pending {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(p) = self.queue.list().into_iter().next() {
                    return p;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("an item is held")
    }

    /// Sends `request` in a task and returns everything the client reads.
    fn send(&self, request: Vec<u8>) -> tokio::task::JoinHandle<Vec<u8>> {
        let addr = self.proxy;
        tokio::spawn(async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(&request).await.unwrap();
            let mut out = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
            out
        })
    }

    async fn exchanges(&self) -> Vec<Exchange> {
        tokio::time::sleep(Duration::from_millis(50)).await;
        self.exchanges.lock().unwrap().clone()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

fn requests() -> InterceptSettings {
    InterceptSettings {
        requests: Some(InterceptRules::default()),
        ..InterceptSettings::default()
    }
}

fn get(origin: SocketAddr, path: &str) -> Vec<u8> {
    format!("GET http://{origin}{path} HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

#[tokio::test]
async fn an_edited_request_is_sent_exactly_as_edited() {
    let (origin, received) = origin().await;
    let h = Harness::start(requests()).await;
    let client = h.send(get(origin, "/original"));

    let held = h.next_pending().await;
    assert_eq!(held.direction, Direction::Request);
    assert_eq!(held.method, "GET");
    assert_eq!(held.target, "/original");
    assert!(
        held.raw.starts_with(b"GET /original HTTP/1.1\r\n"),
        "origin-form"
    );
    assert!(received.lock().unwrap().is_empty(), "held before upstream");

    // Odd bytes on purpose: a lowercase header, a bare LF, extra spaces.
    let edited = Bytes::from_static(
        b"POST  /edited HTTP/1.1\r\nhost: x\nX-Odd:   1  \r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    h.queue
        .resolve(held.id, Verdict::ForwardEdited(edited.clone()))
        .unwrap();
    assert!(client.await.unwrap().ends_with(b"origin"));
    assert_eq!(received.lock().unwrap()[0], edited);

    let exchanges = h.exchanges().await;
    assert_eq!(exchanges[0].forwarded, edited);
    assert!(
        exchanges[0]
            .modifications
            .contains(&Modification::RequestEdited)
    );
}

#[tokio::test]
async fn a_dropped_request_never_reaches_the_origin() {
    let (origin, received) = origin().await;
    let h = Harness::start(requests()).await;
    let client = h.send(get(origin, "/"));
    let held = h.next_pending().await;
    h.queue.resolve(held.id, Verdict::Drop).unwrap();
    let response = client.await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 502 "), "{response:?}");
    assert!(String::from_utf8_lossy(&response).contains("dropped"));
    assert!(received.lock().unwrap().is_empty());
    assert!(
        h.exchanges().await[0]
            .error
            .as_deref()
            .unwrap()
            .contains("dropped")
    );
}

#[tokio::test]
async fn an_edited_response_is_delivered_exactly() {
    let (origin, _) = origin().await;
    let h = Harness::start(InterceptSettings {
        responses: Some(InterceptRules::default()),
        ..InterceptSettings::default()
    })
    .await;
    let client = h.send(get(origin, "/"));
    let held = h.next_pending().await;
    assert_eq!(held.direction, Direction::Response);
    assert_eq!(held.status, Some(200));
    assert_eq!(&held.raw[..], RESPONSE);

    let edited = Bytes::from_static(b"HTTP/1.1 418 Teapot\r\nContent-Length: 4\r\n\r\nbrew");
    h.queue
        .resolve(held.id, Verdict::ForwardEdited(edited.clone()))
        .unwrap();
    assert_eq!(client.await.unwrap(), edited);
    let exchanges = h.exchanges().await;
    assert_eq!(exchanges[0].delivered.as_ref(), Some(&edited));
    assert_eq!(exchanges[0].response.as_ref().unwrap().to_bytes(), RESPONSE);
    assert!(
        exchanges[0]
            .modifications
            .contains(&Modification::ResponseEdited)
    );
}

#[tokio::test]
async fn rules_select_what_is_held() {
    let (origin, received) = origin().await;
    let h = Harness::start(InterceptSettings {
        requests: Some(InterceptRules {
            methods: vec!["POST".into()],
            path: Some(regex::Regex::new("^/api/").unwrap()),
            ..InterceptRules::default()
        }),
        ..InterceptSettings::default()
    })
    .await;
    // Not a POST: forwarded without being held.
    let response = h.send(get(origin, "/api/x")).await.unwrap();
    assert!(response.ends_with(b"origin"));
    assert_eq!(received.lock().unwrap().len(), 1);
    assert!(h.queue.list().is_empty());

    let post = format!(
        "POST http://{origin}/api/x HTTP/1.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let client = h.send(post.into_bytes());
    let held = h.next_pending().await;
    assert_eq!(held.method, "POST");
    assert_eq!(h.queue.forward_all(), 1);
    assert!(client.await.unwrap().ends_with(b"origin"));
}

#[tokio::test]
async fn the_upstream_connection_is_not_reused_after_an_edited_request() {
    // A keep-alive origin that counts its connections.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = listener.local_addr().unwrap();
    let connections = Arc::new(Mutex::new(0));
    let count = connections.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            *count.lock().unwrap() += 1;
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        buf.drain(..end + 4);
                        if s.write_all(RESPONSE).await.is_err() {
                            return;
                        }
                    }
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
            });
        }
    });
    let h = Harness::start(InterceptSettings {
        requests: Some(InterceptRules {
            path: Some(regex::Regex::new("^/edit").unwrap()),
            ..InterceptRules::default()
        }),
        ..InterceptSettings::default()
    })
    .await;

    let mut client = TcpStream::connect(h.proxy).await.unwrap();
    let request =
        |path: &str| format!("GET http://{origin}{path} HTTP/1.1\r\nHost: {origin}\r\n\r\n");
    client.write_all(request("/edit").as_bytes()).await.unwrap();
    let held = h.next_pending().await;
    // Two requests in one edit: the origin answers both.
    let edited = Bytes::from(format!("{0}{0}", "GET /a HTTP/1.1\r\nHost: x\r\n\r\n"));
    h.queue
        .resolve(held.id, Verdict::ForwardEdited(edited))
        .unwrap();
    client.write_all(request("/next").as_bytes()).await.unwrap();

    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    while out.len() < 2 * RESPONSE.len() {
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut chunk))
            .await
            .unwrap()
            .unwrap();
        assert_ne!(n, 0, "the client connection stays open");
        out.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(out, [RESPONSE, RESPONSE].concat());
    assert_eq!(*connections.lock().unwrap(), 2, "a new upstream connection");
}
