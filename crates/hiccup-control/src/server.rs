// SPDX-License-Identifier: AGPL-3.0-or-later

//! The control server: accepts clients and dispatches requests to a
//! [`Handler`].

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::api::notification;
use crate::protocol::{ErrorCode, MAX_MESSAGE_LEN, Request, Response, RpcError};
use crate::registry::Registration;

/// A boxed future, for [`Handler`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Implements the API methods.
pub trait Handler: Send + Sync + 'static {
    /// Handles one request. Unknown methods return
    /// [`ErrorCode::MethodNotFound`].
    fn call<'a>(&'a self, method: &'a str, params: Value)
    -> BoxFuture<'a, Result<Value, RpcError>>;
}

/// Sends notifications to every connected client.
#[derive(Clone, Debug)]
pub struct Notifier(broadcast::Sender<Request>);

impl Notifier {
    /// Sends `method` with `params` to every client. Clients that fall too
    /// far behind miss notifications.
    pub fn notify(&self, method: &str, params: Value) {
        let _ = self.0.send(Request::notification(method, params));
    }
}

impl Default for Notifier {
    fn default() -> Self {
        Self(broadcast::channel(256).0)
    }
}

/// Serves the registered endpoint until `shutdown` is cancelled. Clients then
/// get an `instance.stopping` notification and are disconnected.
///
/// # Errors
///
/// Fails if the registration's listener was already taken.
pub async fn serve(
    registration: &mut Registration,
    handler: Arc<dyn Handler>,
    notifier: Notifier,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let listener = registration
        .take_listener()
        .ok_or_else(|| io::Error::other("the control endpoint is already served"))?;
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok(stream) => {
                        let (handler, notifications, shutdown) =
                            (handler.clone(), notifier.0.subscribe(), shutdown.clone());
                        clients.spawn(async move {
                            if let Err(e) = client(stream, handler, notifications, shutdown).await {
                                debug!(error = %e, "control client error");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "control accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
            Some(_) = clients.join_next(), if !clients.is_empty() => {}
        }
    }
    // Clients see the cancellation, notify and close.
    while clients.join_next().await.is_some() {}
    Ok(())
}

async fn client<S: AsyncRead + AsyncWrite + Send>(
    stream: S,
    handler: Arc<dyn Handler>,
    mut notifications: broadcast::Receiver<Request>,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    // `read_until` keeps what it read in `line` when another branch wins, so
    // the buffer is only cleared once a line is complete.
    let mut reader = BufReader::new(reader).take(MAX_MESSAGE_LEN as u64);
    let mut line = Vec::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                let stopping = Request::notification(notification::INSTANCE_STOPPING, serde_json::json!({}));
                let _ = send(&mut writer, &stopping).await;
                return Ok(());
            }
            n = notifications.recv() => {
                match n {
                    Ok(n) => send(&mut writer, &n).await?,
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        debug!(missed, "control client missed notifications");
                    }
                    Err(broadcast::error::RecvError::Closed) => {}
                }
            }
            read = reader.read_until(b'\n', &mut line) => {
                if read? == 0 {
                    if line.len() >= MAX_MESSAGE_LEN {
                        let error = RpcError::new(ErrorCode::InvalidRequest, "message too long");
                        send(&mut writer, &Response::err(Value::Null, error)).await?;
                    }
                    return Ok(()); // The client closed the connection.
                }
                if line.last() != Some(&b'\n') {
                    continue; // Partial line: the limit is checked at EOF.
                }
                if let Some(response) = dispatch(&line, handler.as_ref()).await {
                    send(&mut writer, &response).await?;
                }
                line.clear();
                reader.set_limit(MAX_MESSAGE_LEN as u64);
            }
        }
    }
}

/// Handles one line. Notifications from the client get no response.
async fn dispatch(line: &[u8], handler: &dyn Handler) -> Option<Response> {
    if line.iter().all(u8::is_ascii_whitespace) {
        return None;
    }
    let value: Value = match serde_json::from_slice(line) {
        Ok(v) => v,
        Err(e) => {
            let error = RpcError::new(ErrorCode::ParseError, format!("invalid JSON: {e}"));
            return Some(Response::err(Value::Null, error));
        }
    };
    let id = value.get("id").cloned();
    let request: Request = match serde_json::from_value::<Request>(value) {
        Ok(r) if r.jsonrpc == "2.0" => r,
        _ => {
            let error = RpcError::new(ErrorCode::InvalidRequest, "not a JSON-RPC 2.0 request");
            return Some(Response::err(id.unwrap_or(Value::Null), error));
        }
    };
    let params = match request.params {
        Value::Null => Value::Object(serde_json::Map::new()),
        p => p,
    };
    let result = handler.call(&request.method, params).await;
    let id = request.id?;
    Some(match result {
        Ok(value) => Response::ok(id, value),
        Err(error) => Response::err(id, error),
    })
}

async fn send<W: AsyncWrite + Unpin, T: serde::Serialize>(
    writer: &mut W,
    message: &T,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(message).map_err(io::Error::other)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await
}
