// SPDX-License-Identifier: AGPL-3.0-or-later

//! The repeater: tabs kept in the project, and the requests sent from them.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hiccup_control::api::{
    RedirectPolicy, RepeaterHistoryPage, RepeaterHistoryParams, RepeaterNewParams, RepeaterOptions,
    RepeaterSendItem, RepeaterSendSummary, RepeaterSent, RepeaterTab, RepeaterTabs, RepeaterTarget,
    RepeaterTimings, RepeaterUpdateParams,
};
use hiccup_control::{ErrorCode, RpcError};
use hiccup_proxy::{
    Applied, Authority, Helpers, Redirects, SendTarget, Sender, Sent, UpstreamConfig,
};
use hiccup_store::{RepeaterSend, Tab};
use serde::{Deserialize, Serialize};

use super::{Instance, blocking};

/// What a send's `details` column holds.
#[derive(Default, Serialize, Deserialize)]
struct Details {
    #[serde(default)]
    applied: Vec<String>,
    #[serde(default)]
    timings: RepeaterTimings,
}

impl Instance {
    pub(super) async fn repeater_list(&self) -> Result<RepeaterTabs, RpcError> {
        let store = self.project()?.store.clone();
        let tabs = blocking(move || store.lock().expect("not poisoned").tabs()).await?;
        Ok(RepeaterTabs {
            tabs: tabs.iter().map(|t| api_tab(t, false)).collect(),
        })
    }

    pub(super) async fn repeater_new(
        &self,
        params: RepeaterNewParams,
    ) -> Result<RepeaterTab, RpcError> {
        let store = self.project()?.store.clone();
        let mut target = params.target;
        let mut request = params.request.as_deref().map(decode).transpose()?;
        if let Some(id) = params.from_history {
            let (key, history) = (i64::try_from(id).unwrap_or(-1), store.clone());
            let record = blocking(move || history.lock().expect("not poisoned").get(key))
                .await?
                .ok_or_else(|| RpcError::invalid_params(format!("no recorded exchange {id}")))?;
            if target.is_none() {
                let upstream = Authority::parse(record.summary.upstream.as_bytes(), None)
                    .ok_or_else(|| RpcError::new(ErrorCode::Failed, "invalid recorded upstream"))?;
                target = Some(RepeaterTarget {
                    host: upstream.host,
                    port: upstream.port,
                    tls: record.summary.tls,
                });
            }
            // What was really sent upstream: in origin-form, edits applied.
            request.get_or_insert_with(|| record.forwarded.to_vec());
        }
        let (Some(target), Some(request)) = (target, request) else {
            return Err(RpcError::invalid_params(
                "`target` and `request` are needed without `from_history`",
            ));
        };
        check(&target)?;
        let draft = Tab {
            id: 0,
            name: params.name.unwrap_or_else(|| default_name(&request)),
            host: target.host,
            port: target.port,
            tls: target.tls,
            request,
            options: options_json(params.options.unwrap_or_default()),
        };
        let tab = blocking(move || store.lock().expect("not poisoned").create_tab(&draft)).await?;
        Ok(api_tab(&tab, true))
    }

    pub(super) async fn repeater_show(&self, id: u64) -> Result<RepeaterTab, RpcError> {
        Ok(api_tab(&self.load_tab(id).await?, true))
    }

    pub(super) async fn repeater_update(
        &self,
        params: RepeaterUpdateParams,
    ) -> Result<RepeaterTab, RpcError> {
        let mut tab = self.load_tab(params.id).await?;
        if let Some(name) = params.name {
            tab.name = name;
        }
        if let Some(target) = params.target {
            check(&target)?;
            (tab.host, tab.port, tab.tls) = (target.host, target.port, target.tls);
        }
        if let Some(request) = params.request {
            tab.request = decode(&request)?;
        }
        if let Some(options) = params.options {
            tab.options = options_json(options);
        }
        let store = self.project()?.store.clone();
        let saved = tab.clone();
        if !blocking(move || store.lock().expect("not poisoned").update_tab(&saved)).await? {
            return Err(no_tab(params.id));
        }
        Ok(api_tab(&tab, true))
    }

    pub(super) async fn repeater_close(&self, id: u64) -> Result<(), RpcError> {
        let store = self.project()?.store.clone();
        let key = i64::try_from(id).unwrap_or(-1);
        if !blocking(move || store.lock().expect("not poisoned").delete_tab(key)).await? {
            return Err(no_tab(id));
        }
        self.senders.lock().expect("not poisoned").remove(&key);
        Ok(())
    }

    pub(super) async fn repeater_send(&self, id: u64) -> Result<RepeaterSent, RpcError> {
        let tab = self.load_tab(id).await?;
        let options: RepeaterOptions = serde_json::from_str(&tab.options).unwrap_or_default();
        let helpers = Helpers {
            update_content_length: options.update_content_length,
            redirects: match options.redirects {
                RedirectPolicy::Never => Redirects::Never,
                RedirectPolicy::Always => Redirects::Always,
                RedirectPolicy::InScope => Redirects::InScope(self.intercept.scope()),
            },
            max_redirects: options.max_redirects,
            reuse_connection: options.reuse_connection,
        };
        let target = SendTarget {
            host: tab.host.clone(),
            port: tab.port,
            tls: tab.tls,
        };
        let sender = self.sender(tab.id)?;
        let mut started = SystemTime::now();
        let hops = sender
            .send(&target, &tab.request, &helpers, &self.shutdown)
            .await;
        let rows: Vec<RepeaterSend> = hops
            .iter()
            .map(|sent| {
                let row = record(tab.id, started, sent);
                started += sent.timings.total;
                row
            })
            .collect();
        let store = self.project()?.store.clone();
        let saved = rows.clone();
        let ids =
            blocking(move || store.lock().expect("not poisoned").insert_sends(&saved)).await?;
        let b64 = |b: &[u8]| data_encoding::BASE64.encode(b);
        Ok(RepeaterSent {
            sends: rows
                .into_iter()
                .zip(ids)
                .map(|(row, id)| {
                    let row = RepeaterSend { id, ..row };
                    RepeaterSendItem {
                        summary: send_summary(&row),
                        request: b64(&row.request),
                        response: b64(&row.response),
                    }
                })
                .collect(),
        })
    }

    pub(super) async fn repeater_history(
        &self,
        params: RepeaterHistoryParams,
    ) -> Result<RepeaterHistoryPage, RpcError> {
        let limit = params.limit.unwrap_or(100);
        if limit > 1000 {
            return Err(RpcError::invalid_params("`limit` is above 1000"));
        }
        let tab = self.load_tab(params.id).await?;
        let store = self.project()?.store.clone();
        let before = params.before.map(|b| i64::try_from(b).unwrap_or(i64::MAX));
        let sends = blocking(move || {
            store
                .lock()
                .expect("not poisoned")
                .sends(tab.id, before, limit)
        })
        .await?;
        Ok(RepeaterHistoryPage {
            items: sends.iter().map(send_summary).collect(),
        })
    }

    pub(super) async fn repeater_history_show(
        &self,
        id: u64,
    ) -> Result<RepeaterSendItem, RpcError> {
        let store = self.project()?.store.clone();
        let key = i64::try_from(id).unwrap_or(-1);
        let send = blocking(move || store.lock().expect("not poisoned").send(key))
            .await?
            .ok_or_else(|| RpcError::invalid_params(format!("nothing was sent with ID {id}")))?;
        let b64 = |b: &[u8]| data_encoding::BASE64.encode(b);
        Ok(RepeaterSendItem {
            summary: send_summary(&send),
            request: b64(&send.request),
            response: b64(&send.response),
        })
    }

    async fn load_tab(&self, id: u64) -> Result<Tab, RpcError> {
        let store = self.project()?.store.clone();
        let key = i64::try_from(id).unwrap_or(-1);
        blocking(move || store.lock().expect("not poisoned").tab(key))
            .await?
            .ok_or_else(|| no_tab(id))
    }

    /// The tab's sender: one per tab, so that a kept connection serves the
    /// tab that opened it.
    // shortcut: the default upstream options (no verification, no SNI,
    // `--resolve` or client certificate rules); take the tab's own when the
    // CLI exposes them (#22).
    fn sender(&self, tab: i64) -> Result<Arc<Sender>, RpcError> {
        let mut senders = self.senders.lock().expect("not poisoned");
        if let Some(sender) = senders.get(&tab) {
            return Ok(sender.clone());
        }
        let sender = Arc::new(
            Sender::new(UpstreamConfig::default())
                .map_err(|e| RpcError::new(ErrorCode::Failed, e.to_string()))?,
        );
        senders.insert(tab, sender.clone());
        Ok(sender)
    }
}

fn no_tab(id: u64) -> RpcError {
    RpcError::invalid_params(format!("no repeater tab {id}"))
}

fn decode(b64: &str) -> Result<Vec<u8>, RpcError> {
    data_encoding::BASE64
        .decode(b64.as_bytes())
        .map_err(|_| RpcError::invalid_params("`request` is not valid base64"))
}

fn check(target: &RepeaterTarget) -> Result<(), RpcError> {
    if target.host.is_empty() || target.port == 0 {
        return Err(RpcError::invalid_params(
            "the target needs a host and a port",
        ));
    }
    Ok(())
}

fn options_json(options: RepeaterOptions) -> String {
    serde_json::to_string(&options).expect("options serialize")
}

/// The request's method and target, as a reader would name the tab.
fn default_name(request: &[u8]) -> String {
    let line = request.split(|&b| b == b'\n').next().unwrap_or_default();
    let words: Vec<_> = line
        .split(|&b| b == b' ')
        .filter(|w| !w.is_empty())
        .take(2)
        .collect();
    let name = String::from_utf8_lossy(&words.join(&b' '))
        .trim()
        .to_owned();
    match name.char_indices().nth(60) {
        Some((end, _)) => format!("{}…", &name[..end]),
        None if name.is_empty() => "new tab".to_owned(),
        None => name,
    }
}

fn api_tab(tab: &Tab, with_request: bool) -> RepeaterTab {
    RepeaterTab {
        id: u64::try_from(tab.id).unwrap_or(0),
        name: tab.name.clone(),
        target: RepeaterTarget {
            host: tab.host.clone(),
            port: tab.port,
            tls: tab.tls,
        },
        options: serde_json::from_str(&tab.options).unwrap_or_default(),
        request: with_request.then(|| data_encoding::BASE64.encode(&tab.request)),
    }
}

fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

fn record(tab: i64, started: SystemTime, sent: &Sent) -> RepeaterSend {
    let details = Details {
        applied: sent
            .applied
            .iter()
            .map(|a| {
                match a {
                    Applied::ContentLengthUpdated => "content_length_updated",
                    Applied::FollowedRedirect => "followed_redirect",
                    Applied::ReusedConnection => "reused_connection",
                }
                .to_owned()
            })
            .collect(),
        timings: RepeaterTimings {
            dns_us: sent.timings.dns.map(micros),
            connect_us: sent.timings.connect.map(micros),
            tls_us: sent.timings.tls.map(micros),
            ttfb_us: sent.timings.ttfb.map(micros),
            total_us: micros(sent.timings.total),
        },
    };
    RepeaterSend {
        id: 0,
        tab,
        started,
        duration: sent.timings.total,
        host: sent.target.host.clone(),
        port: sent.target.port,
        tls: sent.target.tls,
        status: sent.response.as_ref().and_then(|r| r.head().status_code()),
        error: sent.error.clone(),
        details: serde_json::to_string(&details).expect("details serialize"),
        request: sent.request.to_vec(),
        response: sent.raw_response.to_vec(),
        response_size: sent.raw_response.len() as u64,
    }
}

fn send_summary(s: &RepeaterSend) -> RepeaterSendSummary {
    let details: Details = serde_json::from_str(&s.details).unwrap_or_default();
    RepeaterSendSummary {
        id: u64::try_from(s.id).unwrap_or(0),
        tab: u64::try_from(s.tab).unwrap_or(0),
        started_ms: u64::try_from(
            s.started
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX),
        target: RepeaterTarget {
            host: s.host.clone(),
            port: s.port,
            tls: s.tls,
        },
        status: s.status,
        error: s.error.clone(),
        request_size: s.request.len() as u64,
        response_size: s.response_size,
        applied: details.applied,
        timings: details.timings,
    }
}
