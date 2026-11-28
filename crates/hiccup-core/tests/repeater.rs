// SPDX-License-Identifier: AGPL-3.0-or-later

//! Repeater tabs, through the control API: create, send, edit, go back,
//! close, and a restart in between.

use std::net::SocketAddr;
use std::sync::Arc;

use hiccup_control::Handler;
use hiccup_control::api::method;
use hiccup_core::Instance;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// An origin that answers each request with its request line as the body.
async fn origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let line = String::from_utf8_lossy(&buf);
                let line = line.lines().next().unwrap_or_default().to_owned();
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{line}",
                    line.len()
                );
                let _ = s.write_all(reply.as_bytes()).await;
            });
        }
    });
    addr
}

async fn call(instance: &Arc<Instance>, name: &str, params: Value) -> Result<Value, String> {
    instance
        .call(name, params)
        .await
        .map_err(|e| e.message.clone())
}

fn b64(bytes: &[u8]) -> String {
    data_encoding::BASE64.encode(bytes)
}

fn unb64(value: &Value) -> Vec<u8> {
    data_encoding::BASE64
        .decode(value.as_str().unwrap().as_bytes())
        .unwrap()
}

#[tokio::test]
async fn tabs_and_their_history_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("p.hiccup");
    let origin = origin().await;
    let target = json!({"host": "127.0.0.1", "port": origin.port(), "tls": false});

    let instance = Instance::new("t", dir.path());
    instance.open_project(&project).unwrap();
    // Malformed on purpose: sent as is, with the helpers off.
    let raw = b"GET /one HTTP/1.1\nHost: elsewhere.test\r\n\r\n";
    let tab = call(
        &instance,
        method::REPEATER_NEW,
        json!({"target": target, "request": b64(raw)}),
    )
    .await
    .unwrap();
    assert_eq!(tab["name"], "GET /one", "named after the request");
    let id = tab["id"].clone();

    let sent = call(&instance, method::REPEATER_SEND, json!({"id": id}))
        .await
        .unwrap();
    let first = &sent["sends"][0];
    assert_eq!(unb64(&first["request"]), raw, "the bytes, exactly");
    assert_eq!(first["status"], 200);
    assert!(unb64(&first["response"]).ends_with(b"GET /one HTTP/1.1"));
    assert!(first["timings"]["connect_us"].is_u64());

    // Edit and send again.
    let edited = b"GET /two HTTP/1.1\r\n\r\n";
    let updated = call(
        &instance,
        method::REPEATER_UPDATE,
        json!({"id": id, "request": b64(edited), "name": "two"}),
    )
    .await
    .unwrap();
    assert_eq!(updated["name"], "two");
    call(&instance, method::REPEATER_SEND, json!({"id": id}))
        .await
        .unwrap();
    instance.shutdown().await;
    drop(instance);

    // A new instance on the same project.
    let instance = Instance::new("t", dir.path());
    instance.open_project(&project).unwrap();
    let tabs = call(&instance, method::REPEATER_LIST, json!({}))
        .await
        .unwrap();
    assert_eq!(tabs["tabs"].as_array().unwrap().len(), 1);
    assert!(tabs["tabs"][0].get("request").is_none(), "lists stay small");
    let shown = call(&instance, method::REPEATER_SHOW, json!({"id": id}))
        .await
        .unwrap();
    assert_eq!(unb64(&shown["request"]), edited);
    let history = call(&instance, method::REPEATER_HISTORY, json!({"id": id}))
        .await
        .unwrap();
    let items = history["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "newest first");
    assert_eq!(items[0]["request_size"], edited.len());

    // Back: the first send's request, restored into the tab.
    let older = call(
        &instance,
        method::REPEATER_HISTORY_SHOW,
        json!({"id": items[1]["id"]}),
    )
    .await
    .unwrap();
    assert_eq!(unb64(&older["request"]), raw);
    let restored = call(
        &instance,
        method::REPEATER_UPDATE,
        json!({"id": id, "request": older["request"]}),
    )
    .await
    .unwrap();
    assert_eq!(unb64(&restored["request"]), raw);

    // Closing forgets the tab and its history.
    call(&instance, method::REPEATER_CLOSE, json!({"id": id}))
        .await
        .unwrap();
    let gone = call(&instance, method::REPEATER_SHOW, json!({"id": id})).await;
    assert!(gone.unwrap_err().contains("no repeater tab"));
    let gone = call(
        &instance,
        method::REPEATER_HISTORY_SHOW,
        json!({"id": items[0]["id"]}),
    )
    .await;
    assert!(gone.is_err());
    instance.shutdown().await;
}

#[tokio::test]
async fn a_tab_starts_from_a_history_item_and_failures_are_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let origin = origin().await;
    let instance = Instance::new("t", dir.path());
    instance.open_project(&dir.path().join("p.hiccup")).unwrap();

    // Record one exchange through the proxy.
    let started = call(
        &instance,
        method::PROXY_START,
        json!({"listen": ["127.0.0.1:0"]}),
    )
    .await
    .unwrap();
    let proxy = started["proxy"]["listen"][0].as_str().unwrap().to_owned();
    let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!("GET http://{origin}/from-proxy HTTP/1.1\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    let history = loop {
        let page = call(&instance, method::HISTORY_LIST, json!({}))
            .await
            .unwrap();
        if !page["items"].as_array().unwrap().is_empty() {
            break page;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };

    // Send to Repeater: what was forwarded, to the same upstream.
    let tab = call(
        &instance,
        method::REPEATER_NEW,
        json!({"from_history": history["items"][0]["id"]}),
    )
    .await
    .unwrap();
    assert_eq!(tab["target"]["port"], origin.port());
    assert!(unb64(&tab["request"]).starts_with(b"GET /from-proxy HTTP/1.1\r\n"));
    let sent = call(&instance, method::REPEATER_SEND, json!({"id": tab["id"]}))
        .await
        .unwrap();
    assert!(unb64(&sent["sends"][0]["response"]).ends_with(b"GET /from-proxy HTTP/1.1"));

    // A send that fails is recorded with its error.
    let free = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = free.local_addr().unwrap().port();
    drop(free);
    call(
        &instance,
        method::REPEATER_UPDATE,
        json!({"id": tab["id"], "target": {"host": "127.0.0.1", "port": port, "tls": false}}),
    )
    .await
    .unwrap();
    let failed = call(&instance, method::REPEATER_SEND, json!({"id": tab["id"]}))
        .await
        .unwrap();
    assert!(
        failed["sends"][0]["error"]
            .as_str()
            .unwrap()
            .contains("cannot connect")
    );
    let page = call(
        &instance,
        method::REPEATER_HISTORY,
        json!({"id": tab["id"]}),
    )
    .await
    .unwrap();
    assert!(page["items"][0]["error"].is_string());

    // Errors.
    let missing = call(&instance, method::REPEATER_NEW, json!({})).await;
    assert!(missing.unwrap_err().contains("are needed"));
    let bad = call(
        &instance,
        method::REPEATER_NEW,
        json!({"target": {"host": "a", "port": 1, "tls": false}, "request": "%%"}),
    )
    .await;
    assert!(bad.unwrap_err().contains("base64"));
    let none = call(
        &instance,
        method::REPEATER_NEW,
        json!({"from_history": 999}),
    )
    .await;
    assert!(none.unwrap_err().contains("no recorded exchange"));
    let big = call(
        &instance,
        method::REPEATER_HISTORY,
        json!({"id": tab["id"], "limit": 5000}),
    )
    .await;
    assert!(big.unwrap_err().contains("above 1000"));
    instance.shutdown().await;
}

#[tokio::test]
async fn the_repeater_needs_a_project() {
    let dir = tempfile::tempdir().unwrap();
    let instance = Instance::new("t", dir.path());
    let error = call(&instance, method::REPEATER_LIST, json!({})).await;
    assert!(error.unwrap_err().contains("no project is open"));
}
