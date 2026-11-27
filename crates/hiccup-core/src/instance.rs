// SPDX-License-Identifier: AGPL-3.0-or-later

//! A running Hiccup instance.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use hiccup_control::api::{
    ExchangeRequestEvent, ExchangeResponseEvent, ForwardAllResult, ForwardParams, InstanceInfo,
    InterceptResolvedEvent, InterceptSettingsParams, InterceptStatus, ItemParams, PendingItem,
    PendingSummary, ProxyStartParams, ProxyStartResult, ProxyStatus, ScopeRemoveParams,
    ScopeRuleParams, ScopeRules, ScopeTestParams, ScopeTestResult, method, notification,
};
use hiccup_control::{API_VERSION, BoxFuture, ErrorCode, Handler, Notifier, RpcError};
use hiccup_proxy::{
    AbsoluteTarget, CertificateAuthority, Direction, Exchange, InterceptError, InterceptQueue,
    Outcome, Pending, Proxy, QueueEvent, Scheme, Scope, ScopeTarget, Verdict,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// One running Hiccup: the state behind the control API.
pub struct Instance {
    name: String,
    data_dir: PathBuf,
    started_at: u64,
    shutdown: CancellationToken,
    proxy: Mutex<Option<RunningProxy>>,
    proxy_running: watch::Sender<bool>,
    /// Outlives proxy restarts: its settings belong to the instance.
    intercept: Arc<InterceptQueue>,
    /// Events for connections that called `events.subscribe`.
    notifier: Notifier,
}

struct RunningProxy {
    stop: CancellationToken,
    task: JoinHandle<()>,
    listen: Vec<String>,
    verify_upstream: bool,
    exchanges: Arc<AtomicU64>,
}

impl RunningProxy {
    fn status(&self) -> ProxyStatus {
        ProxyStatus {
            running: true,
            listen: self.listen.clone(),
            verify_upstream: self.verify_upstream,
            exchanges: self.exchanges.load(Ordering::Relaxed),
        }
    }
}

impl Instance {
    /// An instance named `name`, keeping its data (the CA) in `data_dir`.
    #[must_use]
    pub fn new(name: impl Into<String>, data_dir: impl Into<PathBuf>) -> Arc<Self> {
        let notifier = Notifier::default();
        let events = notifier.clone();
        let intercept = InterceptQueue::with_listener(Arc::new(move |e: QueueEvent<'_>| match e {
            QueueEvent::Held(item) => {
                events.notify(notification::INTERCEPT_PENDING, value(&summary(item)));
            }
            QueueEvent::Resolved { id, outcome } => {
                let outcome = match outcome {
                    Outcome::Forwarded => "forwarded",
                    Outcome::Edited => "edited",
                    Outcome::Dropped => "dropped",
                    Outcome::Abandoned => "abandoned",
                };
                let event = InterceptResolvedEvent {
                    id,
                    outcome: outcome.to_owned(),
                };
                events.notify(notification::INTERCEPT_RESOLVED, value(&event));
            }
        }));
        Arc::new(Self {
            name: name.into(),
            data_dir: data_dir.into(),
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            shutdown: CancellationToken::new(),
            proxy: Mutex::new(None),
            proxy_running: watch::channel(false).0,
            intercept,
            notifier,
        })
    }

    /// The events this instance sends to connections that called
    /// `events.subscribe`: give it to [`hiccup_control::serve`].
    #[must_use]
    pub fn notifier(&self) -> Notifier {
        self.notifier.clone()
    }

    /// Cancelled when the instance is asked to stop (`instance.shutdown`).
    #[must_use]
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Follows whether the proxy is running.
    #[must_use]
    pub fn proxy_running(&self) -> watch::Receiver<bool> {
        self.proxy_running.subscribe()
    }

    /// Describes the instance.
    #[must_use]
    pub fn info(&self) -> InstanceInfo {
        InstanceInfo {
            name: self.name.clone(),
            pid: std::process::id(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            api_version: API_VERSION.to_owned(),
            started_at: self.started_at,
        }
    }

    /// Starts the proxy.
    ///
    /// # Errors
    ///
    /// See the `proxy.start` method in `docs/control-api.md`.
    pub async fn start_proxy(
        &self,
        params: ProxyStartParams,
    ) -> Result<ProxyStartResult, RpcError> {
        let mut slot = self.proxy.lock().await;
        if slot.as_ref().is_some_and(|p| !p.task.is_finished()) {
            return Err(RpcError::new(
                ErrorCode::InvalidState,
                "the proxy is already running",
            ));
        }
        let config = crate::params::proxy_config(&params)?;
        let verify_upstream = config.upstream.verify;
        let failed = |e: String| RpcError::new(ErrorCode::Failed, e);

        let (ca, ca_generated) = CertificateAuthority::load_or_generate(&self.data_dir)
            .map_err(|e| failed(format!("cannot load the CA: {e}")))?;
        let ca_sha256 = ca
            .info()
            .sha256
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        let exchanges = Arc::new(AtomicU64::new(0));
        let counter = exchanges.clone();
        let (on_request, on_response) = (self.notifier.clone(), self.notifier.clone());
        let proxy = Proxy::bind(config)
            .await
            .map_err(|e| failed(e.to_string()))?
            .with_intercept(self.intercept.clone())
            .with_observer(Arc::new(move |e: &Exchange| {
                counter.fetch_add(1, Ordering::Relaxed);
                on_response.notify(notification::EXCHANGE_RESPONSE, value(&response_event(e)));
            }))
            .with_request_observer(Arc::new(move |e: &Exchange| {
                on_request.notify(notification::EXCHANGE_REQUEST, value(&request_event(e)));
            }))
            .intercept_tls(Arc::new(ca))
            .map_err(|e| RpcError::invalid_params(e.to_string()))?;
        let listen: Vec<String> = proxy
            .local_addrs()
            .iter()
            .map(ToString::to_string)
            .collect();

        let stop = CancellationToken::new();
        let running = self.proxy_running.clone();
        let task = tokio::spawn(proxy.serve(stop.clone()));
        running.send_replace(true);
        info!(listen = ?listen, "proxy started");

        let proxy = RunningProxy {
            stop,
            task,
            listen,
            verify_upstream,
            exchanges,
        };
        let result = ProxyStartResult {
            proxy: proxy.status(),
            ca_generated,
            ca_sha256,
        };
        *slot = Some(proxy);
        self.notifier
            .notify(notification::PROXY_STATE, value(&result.proxy));
        Ok(result)
    }

    /// Stops the proxy, letting in-flight exchanges finish within the grace
    /// period.
    ///
    /// # Errors
    ///
    /// Fails if the proxy is not running.
    pub async fn stop_proxy(&self) -> Result<ProxyStatus, RpcError> {
        let Some(proxy) = self.proxy.lock().await.take() else {
            return Err(RpcError::new(
                ErrorCode::InvalidState,
                "the proxy is not running",
            ));
        };
        proxy.stop.cancel();
        let _ = proxy.task.await;
        self.proxy_running.send_replace(false);
        self.notifier
            .notify(notification::PROXY_STATE, value(&ProxyStatus::default()));
        Ok(ProxyStatus::default())
    }

    /// Describes the proxy.
    pub async fn proxy_status(&self) -> ProxyStatus {
        self.proxy
            .lock()
            .await
            .as_ref()
            .map_or_else(ProxyStatus::default, RunningProxy::status)
    }

    /// The intercept queue.
    #[must_use]
    pub fn intercept(&self) -> &Arc<InterceptQueue> {
        &self.intercept
    }

    fn intercept_status(&self) -> InterceptStatus {
        InterceptStatus {
            settings: crate::params::intercept_params(&self.intercept.settings()),
            pending: self.intercept.list().len(),
        }
    }

    fn set_intercept(&self, params: &InterceptSettingsParams) -> Result<InterceptStatus, RpcError> {
        self.intercept
            .set(crate::params::intercept_settings(params)?);
        Ok(self.intercept_status())
    }

    fn pending_item(&self, id: u64) -> Result<PendingItem, RpcError> {
        let item = self.intercept.get(id).ok_or_else(|| not_found(id))?;
        Ok(PendingItem {
            summary: summary(&item),
            raw: data_encoding::BASE64.encode(&item.raw),
        })
    }

    fn scope_rules(scope: &Scope) -> ScopeRules {
        ScopeRules {
            rules: scope
                .rules
                .iter()
                .map(crate::params::scope_params)
                .collect(),
        }
    }

    fn add_scope_rule(&self, params: &ScopeRuleParams) -> Result<ScopeRules, RpcError> {
        let rule = crate::params::scope_rule(params)?;
        Ok(self.intercept.update_scope(|scope| {
            scope.rules.push(rule);
            Self::scope_rules(scope)
        }))
    }

    fn remove_scope_rule(&self, index: usize) -> Result<ScopeRules, RpcError> {
        self.intercept.update_scope(|scope| {
            if index >= scope.rules.len() {
                return Err(RpcError::invalid_params(format!(
                    "no scope rule {index} (there are {})",
                    scope.rules.len()
                )));
            }
            scope.rules.remove(index);
            Ok(Self::scope_rules(scope))
        })
    }

    fn test_scope(&self, url: &str) -> Result<ScopeTestResult, RpcError> {
        let (https, target) = AbsoluteTarget::parse_url(url.as_bytes()).map_err(|_| {
            RpcError::invalid_params(format!("{url:?} is not an http:// or https:// URL"))
        })?;
        let path = String::from_utf8_lossy(&target.origin_form);
        let in_scope = self.intercept.scope().contains(&ScopeTarget {
            scheme: if https { Scheme::Https } else { Scheme::Http },
            host: &target.authority.host,
            port: target.authority.port,
            path: &path,
        });
        Ok(ScopeTestResult { in_scope })
    }

    fn forward(&self, params: ForwardParams) -> Result<Value, RpcError> {
        let verdict = match params.raw {
            None => Verdict::Forward,
            Some(raw) => Verdict::ForwardEdited(
                data_encoding::BASE64
                    .decode(raw.as_bytes())
                    .map_err(|e| RpcError::invalid_params(format!("invalid base64 in `raw`: {e}")))?
                    .into(),
            ),
        };
        self.resolve(params.id, verdict)
    }

    fn resolve(&self, id: u64, verdict: Verdict) -> Result<Value, RpcError> {
        self.intercept
            .resolve(id, verdict)
            .map_err(|InterceptError::NotFound(id)| not_found(id))?;
        Ok(serde_json::json!({}))
    }

    /// Stops the proxy if it runs, then cancels [`shutdown_token`](Self::shutdown_token).
    pub async fn shutdown(&self) {
        let _ = self.stop_proxy().await;
        self.shutdown.cancel();
    }
}

impl Handler for Instance {
    fn call<'a>(
        &'a self,
        method: &'a str,
        params: Value,
    ) -> BoxFuture<'a, Result<Value, RpcError>> {
        Box::pin(async move {
            match method {
                method::INSTANCE_INFO => reply(&self.info()),
                method::INSTANCE_SHUTDOWN => {
                    // Answer before the connection closes.
                    let shutdown = self.shutdown.clone();
                    let proxy = self.proxy.lock().await.take();
                    tokio::spawn(async move {
                        if let Some(proxy) = proxy {
                            proxy.stop.cancel();
                            let _ = proxy.task.await;
                        }
                        shutdown.cancel();
                    });
                    reply(&serde_json::json!({}))
                }
                method::PROXY_START => reply(&self.start_proxy(parse(params)?).await?),
                method::PROXY_STOP => reply(&self.stop_proxy().await?),
                method::PROXY_STATUS => reply(&self.proxy_status().await),
                method::INTERCEPT_STATUS => reply(&self.intercept_status()),
                method::INTERCEPT_SET => reply(&self.set_intercept(&parse(params)?)?),
                method::INTERCEPT_LIST => reply(
                    &self
                        .intercept
                        .list()
                        .iter()
                        .map(summary)
                        .collect::<Vec<_>>(),
                ),
                method::INTERCEPT_SHOW => {
                    let ItemParams { id } = parse(params)?;
                    reply(&self.pending_item(id)?)
                }
                method::INTERCEPT_FORWARD => self.forward(parse(params)?),
                method::INTERCEPT_DROP => {
                    let ItemParams { id } = parse(params)?;
                    self.resolve(id, Verdict::Drop)
                }
                method::INTERCEPT_FORWARD_ALL => reply(&ForwardAllResult {
                    forwarded: self.intercept.forward_all(),
                }),
                method::SCOPE_LIST => reply(&Self::scope_rules(&self.intercept.scope())),
                method::SCOPE_ADD => reply(&self.add_scope_rule(&parse(params)?)?),
                method::SCOPE_REMOVE => {
                    let ScopeRemoveParams { index } = parse(params)?;
                    reply(&self.remove_scope_rule(index)?)
                }
                method::SCOPE_TEST => {
                    let ScopeTestParams { url } = parse(params)?;
                    reply(&self.test_scope(&url)?)
                }
                _ => Err(RpcError::new(
                    ErrorCode::MethodNotFound,
                    format!("unknown method {method:?}"),
                )),
            }
        })
    }
}

fn not_found(id: u64) -> RpcError {
    RpcError::new(
        ErrorCode::InvalidState,
        format!("no held item {id} (it may have been resolved or timed out)"),
    )
}

fn value<T: Serialize>(event: &T) -> Value {
    serde_json::to_value(event).expect("API types serialize")
}

fn request_event(e: &Exchange) -> ExchangeRequestEvent {
    let head = e.received.head();
    ExchangeRequestEvent {
        id: e.id,
        method: String::from_utf8_lossy(head.method()).into_owned(),
        upstream: e.upstream.clone(),
        tls: e.tls,
        target: String::from_utf8_lossy(head.target()).into_owned(),
    }
}

fn response_event(e: &Exchange) -> ExchangeResponseEvent {
    ExchangeResponseEvent {
        id: e.id,
        status: e.response.as_ref().and_then(|r| r.head().status_code()),
        size: e.response.as_ref().map(|r| r.len() as u64),
        duration_ms: u64::try_from(e.duration.as_millis()).unwrap_or(u64::MAX),
        error: e.error.clone(),
    }
}

fn summary(item: &Pending) -> PendingSummary {
    PendingSummary {
        id: item.id,
        direction: match item.direction {
            Direction::Request => "request",
            Direction::Response => "response",
        }
        .to_owned(),
        upstream: item.upstream.clone(),
        tls: item.tls,
        method: item.method.clone(),
        target: item.target.clone(),
        status: item.status,
        size: item.raw.len(),
        age_ms: u64::try_from(item.since.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn parse<T: DeserializeOwned>(params: Value) -> Result<T, RpcError> {
    serde_json::from_value(params).map_err(|e| RpcError::invalid_params(e.to_string()))
}

fn reply<T: Serialize>(value: &T) -> Result<Value, RpcError> {
    serde_json::to_value(value).map_err(|e| RpcError::new(ErrorCode::InternalError, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn proxy_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let instance = Instance::new("t", dir.path());
        let call = |m: &'static str, p: Value| {
            let instance = instance.clone();
            async move { instance.call(m, p).await }
        };

        assert_eq!(
            call(method::PROXY_STATUS, json!({})).await.unwrap()["running"],
            false
        );
        let started = call(method::PROXY_START, json!({"listen": ["127.0.0.1:0"]}))
            .await
            .unwrap();
        assert_eq!(started["proxy"]["running"], true);
        assert_eq!(started["ca_generated"], true);
        assert!(
            started["proxy"]["listen"][0]
                .as_str()
                .unwrap()
                .starts_with("127.0.0.1:")
        );
        assert!(*instance.proxy_running().borrow());

        let again = call(method::PROXY_START, json!({})).await.unwrap_err();
        assert_eq!(again.code, ErrorCode::InvalidState as i64);

        call(method::PROXY_STOP, json!({})).await.unwrap();
        assert!(!*instance.proxy_running().borrow());
        let stopped = call(method::PROXY_STOP, json!({})).await.unwrap_err();
        assert_eq!(stopped.code, ErrorCode::InvalidState as i64);

        // The CA is generated once.
        let restarted = call(method::PROXY_START, json!({"listen": ["127.0.0.1:0"]}))
            .await
            .unwrap();
        assert_eq!(restarted["ca_generated"], false);
        assert_eq!(restarted["ca_sha256"], started["ca_sha256"]);

        let unknown = call("nope", json!({})).await.unwrap_err();
        assert_eq!(unknown.code, ErrorCode::MethodNotFound as i64);
        let bad = call(method::PROXY_START, json!({"listen": "x"}))
            .await
            .unwrap_err();
        assert_eq!(bad.code, ErrorCode::InvalidParams as i64);

        call(method::INSTANCE_SHUTDOWN, json!({})).await.unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            instance.shutdown_token().cancelled(),
        )
        .await
        .unwrap();
    }
}
