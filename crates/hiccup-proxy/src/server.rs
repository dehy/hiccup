// SPDX-License-Identifier: AGPL-3.0-or-later

//! Listeners and the connection lifecycle.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, info_span, warn};

use crate::connection::{self, Context};
use crate::tls::Interceptor;
use crate::{CaError, CertificateAuthority, ExchangeObserver, ProxyConfig};

/// An intercepting HTTP proxy, bound and ready to serve.
///
/// ```no_run
/// # async fn run() -> std::io::Result<()> {
/// use hiccup_proxy::{Proxy, ProxyConfig};
/// use tokio_util::sync::CancellationToken;
///
/// let proxy = Proxy::bind(ProxyConfig::default()).await?;
/// println!("listening on {:?}", proxy.local_addrs());
/// let shutdown = CancellationToken::new();
/// proxy.serve(shutdown.clone()).await; // until `shutdown.cancel()`
/// # Ok(())
/// # }
/// ```
pub struct Proxy {
    listeners: Vec<TcpListener>,
    config: ProxyConfig,
    observer: Option<ExchangeObserver>,
    interceptor: Option<Interceptor>,
}

impl Proxy {
    /// Binds every address in [`ProxyConfig::listen`].
    ///
    /// # Errors
    ///
    /// Fails if any address cannot be bound; none are kept bound then.
    pub async fn bind(config: ProxyConfig) -> io::Result<Self> {
        let mut listeners = Vec::with_capacity(config.listen.len());
        for addr in &config.listen {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|e| io::Error::new(e.kind(), format!("cannot listen on {addr}: {e}")))?;
            listeners.push(listener);
        }
        Ok(Self {
            listeners,
            config,
            observer: None,
            interceptor: None,
        })
    }

    /// Calls `observer` with every completed exchange.
    #[must_use]
    pub fn with_observer(mut self, observer: ExchangeObserver) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Intercepts TLS in `CONNECT` tunnels with certificates signed by `ca`.
    ///
    /// Without it, every tunnel is relayed untouched.
    ///
    /// # Errors
    ///
    /// Fails if the key for leaf certificates cannot be generated.
    pub fn intercept_tls(mut self, ca: Arc<CertificateAuthority>) -> Result<Self, CaError> {
        self.interceptor = Some(Interceptor::new(ca)?);
        Ok(self)
    }

    /// The addresses actually bound (useful with port `0`).
    #[must_use]
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .filter_map(|l| l.local_addr().ok())
            .collect()
    }

    /// Serves connections until `shutdown` is cancelled.
    ///
    /// On shutdown, listeners stop accepting and idle connections close.
    /// In-flight exchanges and tunnels get [`ProxyConfig::shutdown_grace`] to
    /// finish, then they are aborted.
    pub async fn serve(self, shutdown: CancellationToken) {
        let ctx = Arc::new(Context {
            config: self.config,
            observer: self.observer,
            interceptor: self.interceptor,
            shutdown: shutdown.clone(),
        });
        let (tx, mut rx) = mpsc::channel::<(TcpStream, SocketAddr, SocketAddr)>(64);
        let mut acceptors = JoinSet::new();
        for listener in self.listeners {
            let local = listener.local_addr().ok();
            if let Some(local) = local {
                debug!(%local, "listening");
            }
            acceptors.spawn(accept_loop(listener, tx.clone(), shutdown.clone()));
        }
        drop(tx);

        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                accepted = rx.recv() => {
                    let Some((stream, peer, local)) = accepted else { break };
                    let span = info_span!("connection", %peer, %local);
                    connections.spawn(connection::handle(stream, peer, ctx.clone()).instrument(span));
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }

        acceptors.abort_all();
        drain(connections, ctx.config.shutdown_grace).await;
        info!("proxy stopped");
    }
}

async fn accept_loop(
    listener: TcpListener,
    tx: mpsc::Sender<(TcpStream, SocketAddr, SocketAddr)>,
    shutdown: CancellationToken,
) {
    let Ok(local) = listener.local_addr() else {
        return;
    };
    loop {
        let accepted = tokio::select! {
            () = shutdown.cancelled() => return,
            r = listener.accept() => r,
        };
        match accepted {
            Ok((stream, peer)) => {
                let _ = stream.set_nodelay(true);
                if tx.send((stream, peer, local)).await.is_err() {
                    return;
                }
            }
            Err(e) => {
                // Usually transient (e.g. too many open files): back off.
                warn!(%local, error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn drain(mut connections: JoinSet<()>, grace: Duration) {
    if connections.is_empty() {
        return;
    }
    debug!(
        count = connections.len(),
        "waiting for connections to finish"
    );
    let wait = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(grace, wait).await.is_err() {
        warn!(
            count = connections.len(),
            "aborting connections after the grace period"
        );
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
}
