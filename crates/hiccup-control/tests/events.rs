// SPDX-License-Identifier: AGPL-3.0-or-later

//! Events: only subscribers get them, and a subscriber that falls behind is
//! told so and dropped.

use std::sync::Arc;
use std::time::Duration;

use hiccup_control::api::{method, notification};
use hiccup_control::{
    BoxFuture, Client, Handler, InstanceRecord, Notifier, Registry, RpcError, serve,
};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

/// Answers `instance.info` (clients check it on connect) and nothing else.
struct Info;

impl Handler for Info {
    fn call<'a>(&'a self, _: &'a str, _: Value) -> BoxFuture<'a, Result<Value, RpcError>> {
        Box::pin(async {
            Ok(json!({
                "name": "t", "pid": 1, "version": "0", "started_at": 0,
                "api_version": hiccup_control::API_VERSION,
            }))
        })
    }
}

struct Server {
    record: InstanceRecord,
    notifier: Notifier,
    _dir: tempfile::TempDir,
    stop: CancellationToken,
}

async fn start() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let mut registration = Registry::new(dir.path().join("run"))
        .register("t")
        .await
        .unwrap();
    let record = registration.record().clone();
    let (notifier, stop) = (Notifier::default(), CancellationToken::new());
    let (n, s) = (notifier.clone(), stop.clone());
    tokio::spawn(async move { serve(&mut registration, Arc::new(Info), n, s).await });
    Server {
        record,
        notifier,
        _dir: dir,
        stop,
    }
}

#[tokio::test]
async fn only_subscribers_get_events() {
    let server = start().await;
    let mut subscriber = Client::connect(&server.record).await.unwrap();
    let _: Value = subscriber.call(method::EVENTS_SUBSCRIBE, ()).await.unwrap();
    let mut other = Client::connect(&server.record).await.unwrap();

    server
        .notifier
        .notify(notification::PROXY_STATE, json!({ "running": true }));
    let event = tokio::time::timeout(Duration::from_secs(5), subscriber.next_notification())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.method, notification::PROXY_STATE);
    assert_eq!(event.params["running"], true);

    // A call after the event: had it been sent here, it would be buffered.
    let _: Value = other.call(method::INSTANCE_INFO, ()).await.unwrap();
    assert!(other.take_notifications().is_empty());
    server.stop.cancel();
}

#[tokio::test]
async fn a_subscriber_that_falls_behind_is_told_and_dropped() {
    let server = start().await;
    let mut slow = Client::connect(&server.record).await.unwrap();
    let _: Value = slow.call(method::EVENTS_SUBSCRIBE, ()).await.unwrap();

    // Far more than the buffer holds, while `slow` reads nothing: the
    // server blocks on the full socket, and the subscription lags.
    let padding = "x".repeat(4096);
    for i in 0..5000 {
        server.notifier.notify(
            notification::EXCHANGE_REQUEST,
            json!({ "i": i, "pad": padding }),
        );
        if i % 100 == 0 {
            tokio::task::yield_now().await;
        }
    }

    let lagged = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let n = slow.next_notification().await.unwrap();
            if n.method == notification::EVENTS_LAGGED {
                return n;
            }
        }
    })
    .await
    .expect("told that it lagged");
    assert!(lagged.params["missed"].as_u64().unwrap() > 0);
    assert!(slow.next_notification().await.is_err(), "then dropped");
    server.stop.cancel();
}
