// SPDX-License-Identifier: AGPL-3.0-or-later

//! A control API client.

use std::io;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};

use crate::api::{InstanceInfo, method};
use crate::protocol::{Incoming, MAX_MESSAGE_LEN, Request, RpcError, is_compatible};
use crate::registry::{InstanceRecord, Stream, connect};

/// Why a call failed.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The connection failed.
    #[error("cannot talk to the Hiccup instance: {0}")]
    Io(#[from] io::Error),
    /// The instance sent something unexpected.
    #[error("unexpected message from the Hiccup instance: {0}")]
    Protocol(String),
    /// The instance speaks an incompatible API version.
    #[error(
        "the Hiccup instance speaks control API {theirs}, this CLI speaks {ours}: \
         use matching versions"
    )]
    Incompatible {
        /// The instance's version.
        theirs: String,
        /// This client's version.
        ours: &'static str,
    },
    /// The method failed.
    #[error("{}", .0.message)]
    Rpc(RpcError),
}

/// A connection to an instance.
pub struct Client {
    reader: BufReader<ReadHalf<Stream>>,
    writer: WriteHalf<Stream>,
    next_id: u64,
    notifications: Vec<Request>,
}

impl Client {
    /// Connects to `record` and checks its API version.
    ///
    /// # Errors
    ///
    /// Fails if the instance cannot be reached or is incompatible.
    pub async fn connect(record: &InstanceRecord) -> Result<Self, ClientError> {
        let (reader, writer) = tokio::io::split(connect(&record.endpoint).await?);
        let mut client = Self {
            reader: BufReader::new(reader),
            writer,
            next_id: 1,
            notifications: Vec::new(),
        };
        let info: InstanceInfo = client.call(method::INSTANCE_INFO, ()).await?;
        if !is_compatible(&info.api_version) {
            return Err(ClientError::Incompatible {
                theirs: info.api_version,
                ours: crate::API_VERSION,
            });
        }
        Ok(client)
    }

    /// Calls `method` and decodes its result.
    ///
    /// # Errors
    ///
    /// Fails on I/O and protocol errors, or if the method fails.
    pub async fn call<P: Serialize, R: DeserializeOwned>(
        &mut self,
        method: &str,
        params: P,
    ) -> Result<R, ClientError> {
        let value = self.call_value(method, params).await?;
        serde_json::from_value(value).map_err(|e| ClientError::Protocol(e.to_string()))
    }

    /// Calls `method` and returns its raw result.
    ///
    /// # Errors
    ///
    /// See [`call`](Self::call).
    pub async fn call_value<P: Serialize>(
        &mut self,
        method: &str,
        params: P,
    ) -> Result<Value, ClientError> {
        let id = self.next_id;
        self.next_id += 1;
        let params = match serde_json::to_value(params) {
            Ok(Value::Null) => Value::Object(serde_json::Map::new()),
            Ok(v) => v,
            Err(e) => return Err(ClientError::Protocol(e.to_string())),
        };
        let mut line = serde_json::to_vec(&Request::new(id, method, params))
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        line.push(b'\n');
        self.writer.write_all(&line).await?;
        self.writer.flush().await?;

        loop {
            match self.next_message().await? {
                Incoming::Notification(n) => self.notifications.push(n),
                Incoming::Response(r) if r.id == id => {
                    return match (r.result, r.error) {
                        (_, Some(error)) => Err(ClientError::Rpc(error)),
                        (Some(result), None) => Ok(result),
                        (None, None) => Ok(Value::Null),
                    };
                }
                Incoming::Response(r) => {
                    return Err(ClientError::Protocol(format!(
                        "response to unknown request {}",
                        r.id
                    )));
                }
            }
        }
    }

    /// Notifications received so far, oldest first.
    pub fn take_notifications(&mut self) -> Vec<Request> {
        std::mem::take(&mut self.notifications)
    }

    async fn next_message(&mut self) -> Result<Incoming, ClientError> {
        let mut line = String::new();
        let n = (&mut self.reader)
            .take(MAX_MESSAGE_LEN as u64)
            .read_line(&mut line)
            .await?;
        if n == 0 {
            return Err(ClientError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the instance closed the connection",
            )));
        }
        Incoming::parse(&line).map_err(|e| ClientError::Protocol(e.to_string()))
    }
}
