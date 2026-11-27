// SPDX-License-Identifier: AGPL-3.0-or-later

//! The intercept queue: matching requests and responses are held until the
//! user forwards (possibly edited) or drops them.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::oneshot;
use tracing::{debug, info};

use crate::HostPattern;

/// Which message is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// A request, before it is sent upstream.
    Request,
    /// A response, before it is sent to the client.
    Response,
}

/// Which exchanges to intercept. Every non-empty criterion must match.
#[derive(Clone, Debug, Default)]
pub struct InterceptRules {
    /// Target hosts; empty matches every host.
    pub hosts: Vec<HostPattern>,
    /// Request methods, uppercase; empty matches every method.
    pub methods: Vec<String>,
    /// Matched against the request target (path and query, or the whole
    /// absolute-form target as forwarded).
    pub path: Option<regex::Regex>,
}

impl InterceptRules {
    fn matches(&self, request: &RequestInfo<'_>) -> bool {
        (self.hosts.is_empty() || self.hosts.iter().any(|h| h.matches(request.host)))
            && (self.methods.is_empty() || self.methods.iter().any(|m| m == request.method))
            && self
                .path
                .as_ref()
                .is_none_or(|re| re.is_match(request.target))
    }
}

/// What happens to an item nobody acts on in time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutAction {
    /// Forward it unchanged.
    Forward,
    /// Drop it.
    Drop,
}

/// The intercept settings.
#[derive(Clone, Debug, Default)]
pub struct InterceptSettings {
    /// Rules for requests; `None` disables request interception.
    pub requests: Option<InterceptRules>,
    /// Rules for responses; `None` disables response interception.
    pub responses: Option<InterceptRules>,
    /// How long an item may wait, and what happens then. `None`: forever.
    pub timeout: Option<(Duration, TimeoutAction)>,
}

impl InterceptSettings {
    fn matches(&self, direction: Direction, request: &RequestInfo<'_>) -> bool {
        let rules = match direction {
            Direction::Request => self.requests.as_ref(),
            Direction::Response => self.responses.as_ref(),
        };
        rules.is_some_and(|r| r.matches(request))
    }
}

/// What the user decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Send the message unchanged.
    Forward,
    /// Send these bytes instead, exactly.
    ForwardEdited(Bytes),
    /// Do not send it.
    Drop,
}

/// A held message.
#[derive(Clone, Debug)]
pub struct Pending {
    /// Stable for the life of the queue.
    pub id: u64,
    /// Request or response.
    pub direction: Direction,
    /// The upstream `host:port`.
    pub upstream: String,
    /// Whether the exchange is in an intercepted TLS tunnel.
    pub tls: bool,
    /// The request method.
    pub method: String,
    /// The request target.
    pub target: String,
    /// The response status, for responses.
    pub status: Option<u16>,
    /// The exact bytes that will be sent if forwarded unchanged.
    pub raw: Bytes,
    /// When it was held.
    pub since: Instant,
}

/// Why a queue operation failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InterceptError {
    /// No pending item has this ID (it may have been resolved or timed out).
    #[error("no pending item {0}")]
    NotFound(u64),
}

/// The request an item belongs to, for rule matching.
pub(crate) struct RequestInfo<'a> {
    pub(crate) host: &'a str,
    pub(crate) method: &'a str,
    pub(crate) target: &'a str,
}

struct Entry {
    item: Pending,
    verdict: oneshot::Sender<Verdict>,
}

/// The queue of held messages, shared by every connection of a proxy and by
/// whoever resolves them.
#[derive(Default)]
pub struct InterceptQueue {
    settings: RwLock<InterceptSettings>,
    pending: Mutex<BTreeMap<u64, Entry>>,
    next_id: AtomicU64,
}

impl InterceptQueue {
    /// An empty queue with interception off.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The current settings.
    ///
    /// # Panics
    ///
    /// If a thread panicked while holding the lock.
    #[must_use]
    pub fn settings(&self) -> InterceptSettings {
        self.settings.read().expect("not poisoned").clone()
    }

    /// Replaces the settings. Items held in a direction that is now off are
    /// forwarded unchanged.
    ///
    /// # Panics
    ///
    /// If a thread panicked while holding a lock.
    pub fn set(&self, settings: InterceptSettings) {
        let (requests_off, responses_off) =
            (settings.requests.is_none(), settings.responses.is_none());
        // Store first, then release: `hold` lists an item while it still
        // holds the settings lock, so every item listed under the old
        // settings is already in the queue by now, and none is listed after.
        *self.settings.write().expect("not poisoned") = settings;
        self.release(|item| match item.direction {
            Direction::Request => requests_off,
            Direction::Response => responses_off,
        });
    }

    /// The held items, oldest first.
    ///
    /// # Panics
    ///
    /// If a thread panicked while holding the lock.
    #[must_use]
    pub fn list(&self) -> Vec<Pending> {
        let pending = self.pending.lock().expect("not poisoned");
        pending.values().map(|e| e.item.clone()).collect()
    }

    /// One held item.
    ///
    /// # Panics
    ///
    /// If a thread panicked while holding the lock.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<Pending> {
        let pending = self.pending.lock().expect("not poisoned");
        pending.get(&id).map(|e| e.item.clone())
    }

    /// Resolves a held item.
    ///
    /// # Errors
    ///
    /// Fails if no item has this ID.
    ///
    /// # Panics
    ///
    /// If a thread panicked while holding the lock.
    pub fn resolve(&self, id: u64, verdict: Verdict) -> Result<(), InterceptError> {
        let entry = self
            .pending
            .lock()
            .expect("not poisoned")
            .remove(&id)
            .ok_or(InterceptError::NotFound(id))?;
        // The connection may have closed meanwhile: nothing to do then.
        let _ = entry.verdict.send(verdict);
        Ok(())
    }

    /// Forwards every held item unchanged. Returns how many there were.
    pub fn forward_all(&self) -> usize {
        self.release(|_| true)
    }

    fn release(&self, which: impl Fn(&Pending) -> bool) -> usize {
        let released: Vec<Entry> = {
            let mut pending = self.pending.lock().expect("not poisoned");
            let ids: Vec<u64> = pending
                .values()
                .filter(|e| which(&e.item))
                .map(|e| e.item.id)
                .collect();
            ids.iter().filter_map(|id| pending.remove(id)).collect()
        };
        let count = released.len();
        for entry in released {
            let _ = entry.verdict.send(Verdict::Forward);
        }
        count
    }

    /// Whether [`hold`](Self::hold) would hold such a message now: it is
    /// then read in full rather than streamed.
    pub(crate) fn matches(&self, direction: Direction, request: &RequestInfo<'_>) -> bool {
        self.settings
            .read()
            .expect("not poisoned")
            .matches(direction, request)
    }

    /// Holds the message if the rules for `direction` match `request`, and
    /// waits for the verdict. Returns `Forward` at once otherwise.
    pub(crate) async fn hold(
        &self,
        direction: Direction,
        request: &RequestInfo<'_>,
        item: impl FnOnce(u64) -> Pending,
    ) -> Verdict {
        let (tx, rx) = oneshot::channel();
        let (id, timeout) = {
            // Listed while the settings are read-locked, so that `set` cannot
            // turn this direction off and release in between.
            let settings = self.settings.read().expect("not poisoned");
            if !settings.matches(direction, request) {
                return Verdict::Forward;
            }
            let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
            let item = item(id);
            info!(id, ?direction, method = %item.method, target = %item.target, "intercepted");
            self.pending
                .lock()
                .expect("not poisoned")
                .insert(id, Entry { item, verdict: tx });
            (id, settings.timeout)
        };
        // If the connection goes away while waiting, unlist the item.
        let guard = Unlist { queue: self, id };

        let verdict = match timeout {
            None => rx.await.unwrap_or(Verdict::Forward),
            Some((after, action)) => match tokio::time::timeout(after, rx).await {
                Ok(verdict) => verdict.unwrap_or(Verdict::Forward),
                Err(_) => {
                    debug!(id, ?action, "intercept timeout");
                    match action {
                        TimeoutAction::Forward => Verdict::Forward,
                        TimeoutAction::Drop => Verdict::Drop,
                    }
                }
            },
        };
        drop(guard);
        verdict
    }
}

struct Unlist<'a> {
    queue: &'a InterceptQueue,
    id: u64,
}

impl Drop for Unlist<'_> {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.queue.pending.lock() {
            pending.remove(&self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info<'a>(host: &'a str, method: &'a str, target: &'a str) -> RequestInfo<'a> {
        RequestInfo {
            host,
            method,
            target,
        }
    }

    fn pending(id: u64) -> Pending {
        Pending {
            id,
            direction: Direction::Request,
            upstream: "a.test:80".into(),
            tls: false,
            method: "GET".into(),
            target: "/".into(),
            status: None,
            raw: Bytes::from_static(b"GET / HTTP/1.1\r\n\r\n"),
            since: Instant::now(),
        }
    }

    #[test]
    fn rules() {
        let rules = InterceptRules {
            hosts: vec!["*.test".parse().unwrap()],
            methods: vec!["POST".into()],
            path: Some(regex::Regex::new("^/api/").unwrap()),
        };
        assert!(rules.matches(&info("a.test", "POST", "/api/x")));
        assert!(!rules.matches(&info("a.test", "GET", "/api/x")));
        assert!(!rules.matches(&info("other", "POST", "/api/x")));
        assert!(!rules.matches(&info("a.test", "POST", "/x")));
        assert!(InterceptRules::default().matches(&info("any", "ANY", "*")));
    }

    #[tokio::test]
    async fn not_matching_is_not_held() {
        let queue = InterceptQueue::new();
        let v = queue
            .hold(Direction::Request, &info("a", "GET", "/"), pending)
            .await;
        assert_eq!(v, Verdict::Forward);
        assert!(queue.list().is_empty());
    }

    #[tokio::test]
    async fn held_until_resolved() {
        let queue = InterceptQueue::new();
        queue.set(InterceptSettings {
            requests: Some(InterceptRules::default()),
            ..InterceptSettings::default()
        });
        let q = queue.clone();
        let held = tokio::spawn(async move {
            q.hold(Direction::Request, &info("a", "GET", "/"), pending)
                .await
        });
        while queue.list().is_empty() {
            tokio::task::yield_now().await;
        }
        let id = queue.list()[0].id;
        assert!(queue.get(id).is_some());
        let edited = Bytes::from_static(b"GET /edited HTTP/1.1\r\n\r\n");
        queue
            .resolve(id, Verdict::ForwardEdited(edited.clone()))
            .unwrap();
        assert_eq!(held.await.unwrap(), Verdict::ForwardEdited(edited));
        assert!(queue.list().is_empty());
        assert_eq!(
            queue.resolve(id, Verdict::Drop),
            Err(InterceptError::NotFound(id))
        );
    }

    /// Regression: an item listed while `set` turned its direction off was
    /// held forever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn turning_off_never_strands_a_racing_item() {
        let on = || InterceptSettings {
            requests: Some(InterceptRules::default()),
            ..InterceptSettings::default()
        };
        let queue = InterceptQueue::new();
        for _ in 0..500 {
            queue.set(on());
            let holds: Vec<_> = (0..4)
                .map(|_| {
                    let q = queue.clone();
                    tokio::spawn(async move {
                        q.hold(Direction::Request, &info("a", "GET", "/"), pending)
                            .await
                    })
                })
                .collect();
            queue.set(InterceptSettings::default());
            for held in holds {
                let verdict = tokio::time::timeout(Duration::from_secs(5), held)
                    .await
                    .expect("released, not stranded")
                    .unwrap();
                assert_eq!(verdict, Verdict::Forward);
            }
            assert!(queue.list().is_empty());
        }
    }

    #[tokio::test]
    async fn turning_off_releases_and_timeouts_apply() {
        let queue = InterceptQueue::new();
        queue.set(InterceptSettings {
            requests: Some(InterceptRules::default()),
            ..InterceptSettings::default()
        });
        let q = queue.clone();
        let held = tokio::spawn(async move {
            q.hold(Direction::Request, &info("a", "GET", "/"), pending)
                .await
        });
        while queue.list().is_empty() {
            tokio::task::yield_now().await;
        }
        queue.set(InterceptSettings::default());
        assert_eq!(held.await.unwrap(), Verdict::Forward);

        queue.set(InterceptSettings {
            requests: Some(InterceptRules::default()),
            timeout: Some((Duration::from_millis(20), TimeoutAction::Drop)),
            ..InterceptSettings::default()
        });
        let v = queue
            .hold(Direction::Request, &info("a", "GET", "/"), pending)
            .await;
        assert_eq!(v, Verdict::Drop);
        assert!(queue.list().is_empty(), "timed-out items are unlisted");
    }
}
