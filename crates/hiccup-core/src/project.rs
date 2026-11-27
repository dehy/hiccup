// SPDX-License-Identifier: AGPL-3.0-or-later

//! The project an instance records its history in.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use hiccup_proxy::Exchange;
use hiccup_store::{Store, StoreError};
use tracing::warn;

/// Exchanges waiting to be written. Inserts take ~50 µs, so this fills only
/// if the disk stalls; the proxy is never slowed down meanwhile.
const QUEUE: usize = 4096;

/// An open project: exchanges are queued by the proxy and written by one
/// thread; queries share its connection.
pub(crate) struct Project {
    pub(crate) path: PathBuf,
    pub(crate) store: Arc<Mutex<Store>>,
    writer: Mutex<Option<(SyncSender<Exchange>, JoinHandle<()>)>>,
    dropped: AtomicU64,
}

impl Project {
    pub(crate) fn open(path: &Path) -> Result<Self, StoreError> {
        let store = Arc::new(Mutex::new(Store::open(path)?));
        let (tx, rx) = std::sync::mpsc::sync_channel::<Exchange>(QUEUE);
        let writes = store.clone();
        let thread = std::thread::Builder::new()
            .name("hiccup-history".to_owned())
            .spawn(move || {
                for exchange in rx {
                    let inserted = writes.lock().expect("not poisoned").insert(&exchange);
                    if let Err(e) = inserted {
                        warn!(error = %e, "cannot record an exchange in the project");
                    }
                }
            })
            .map_err(StoreError::Io)?;
        Ok(Self {
            path: path.to_owned(),
            store,
            writer: Mutex::new(Some((tx, thread))),
            dropped: AtomicU64::new(0),
        })
    }

    /// Queues `exchange` for writing, without waiting.
    pub(crate) fn record(&self, exchange: &Exchange) {
        let writer = self.writer.lock().expect("not poisoned");
        let Some((tx, _)) = writer.as_ref() else {
            return;
        };
        if let Err(TrySendError::Full(_)) = tx.try_send(exchange.clone()) {
            let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            warn!(
                dropped,
                "the project cannot keep up: an exchange was not recorded"
            );
        }
    }

    /// Writes what is queued, then stops recording.
    pub(crate) fn close(&self) {
        let writer = self.writer.lock().expect("not poisoned").take();
        if let Some((tx, thread)) = writer {
            drop(tx);
            let _ = thread.join();
        }
    }
}
