// SPDX-License-Identifier: AGPL-3.0-or-later

//! JSON-RPC 2.0 messages. Each message is one line of JSON (newline-delimited
//! JSON), which keeps the protocol easy to debug with standard tools.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The control API version, `MAJOR.MINOR`. Clients refuse a different major
/// version; minor versions only add methods, fields and notifications.
pub const API_VERSION: &str = "1.0";

/// The longest message accepted, in bytes, newline included.
pub const MAX_MESSAGE_LEN: usize = 16 * 1024 * 1024;

/// A request (with `id`) or a notification (without).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Request {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// Absent for notifications, which get no response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    /// The method name, e.g. `proxy.start`.
    pub method: String,
    /// Named parameters. Absent and `null` are treated as `{}`.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub params: Value,
}

impl Request {
    /// A request with the given `id`.
    #[must_use]
    pub fn new(id: u64, method: &str, params: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id: Some(id.into()),
            method: method.to_owned(),
            params,
        }
    }

    /// A notification: a request without `id`.
    #[must_use]
    pub fn notification(method: &str, params: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id: None,
            method: method.to_owned(),
            params,
        }
    }
}

/// A response to a request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Response {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// The request's `id`, or `null` if the request could not be parsed.
    pub id: Value,
    /// The result, on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// The error, on failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl Response {
    /// A successful response.
    #[must_use]
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// A failed response.
    #[must_use]
    pub fn err(id: Value, error: RpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

/// A JSON-RPC error object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, thiserror::Error)]
#[error("{message} (code {code})")]
pub struct RpcError {
    /// See [`ErrorCode`].
    pub code: i64,
    /// A sentence for humans.
    pub message: String,
    /// Structured details, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcError {
    /// An error with `code` and `message`.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code as i64,
            message: message.into(),
            data: None,
        }
    }

    /// Invalid method parameters.
    #[must_use]
    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidParams, message)
    }
}

/// Error codes: the JSON-RPC 2.0 ones, then Hiccup's (from -32000 down).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i64)]
pub enum ErrorCode {
    /// The message is not valid JSON.
    ParseError = -32700,
    /// The message is not a valid request.
    InvalidRequest = -32600,
    /// No such method.
    MethodNotFound = -32601,
    /// The parameters are invalid.
    InvalidParams = -32602,
    /// A bug or an unexpected failure in the instance.
    InternalError = -32603,
    /// The operation failed, e.g. a listen address is in use.
    Failed = -32000,
    /// The operation conflicts with the current state, e.g. starting a
    /// proxy that is already running.
    InvalidState = -32001,
}

/// Any message a client receives: a response, or a notification pushed by
/// the instance.
#[derive(Clone, Debug, PartialEq)]
pub enum Incoming {
    /// A response to one of the client's requests.
    Response(Response),
    /// A server-push notification.
    Notification(Request),
}

impl Incoming {
    /// Parses one line.
    ///
    /// # Errors
    ///
    /// Fails if the line is neither a response nor a notification.
    pub fn parse(line: &str) -> Result<Self, serde_json::Error> {
        let value: Value = serde_json::from_str(line)?;
        if value.get("method").is_some() {
            serde_json::from_value(value).map(Self::Notification)
        } else {
            serde_json::from_value(value).map(Self::Response)
        }
    }
}

/// Whether `version` (`MAJOR.MINOR`) is compatible with [`API_VERSION`].
#[must_use]
pub fn is_compatible(version: &str) -> bool {
    let major = |v: &str| v.split('.').next().map(str::to_owned);
    major(version) == major(API_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn wire_format() {
        let r = Request::new(7, "proxy.status", Value::Null);
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"jsonrpc":"2.0","id":7,"method":"proxy.status"}"#
        );
        let n = Request::notification("instance.stopping", json!({}));
        assert_eq!(
            serde_json::to_string(&n).unwrap(),
            r#"{"jsonrpc":"2.0","method":"instance.stopping","params":{}}"#
        );
        let e = Response::err(json!(1), RpcError::invalid_params("bad"));
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad"}}"#
        );
    }

    #[test]
    fn incoming() {
        let r = Incoming::parse(r#"{"jsonrpc":"2.0","id":1,"result":{"a":1}}"#).unwrap();
        assert!(matches!(r, Incoming::Response(r) if r.result == Some(json!({"a": 1}))));
        let n = Incoming::parse(r#"{"jsonrpc":"2.0","method":"x"}"#).unwrap();
        assert!(matches!(n, Incoming::Notification(n) if n.method == "x"));
        assert!(Incoming::parse("[]").is_err());
    }

    #[test]
    fn compatibility() {
        assert!(is_compatible("1.0"));
        assert!(is_compatible("1.7"));
        assert!(!is_compatible("2.0"));
        assert!(!is_compatible(""));
    }
}
