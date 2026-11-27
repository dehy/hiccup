// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local control API: JSON-RPC 2.0 over a Unix socket or Windows named pipe.
//!
//! Every user-visible feature is reachable through this API, which is what
//! makes Hiccup entirely controllable from the CLI. See ADR 0004 and the
//! reference in `docs/control-api.md`.
//!
//! - [`Registry`]: where running instances are found, and how one registers.
//! - [`serve`]: runs a control server for an instance, dispatching to a
//!   [`Handler`].
//! - [`Client`]: calls an instance's methods.
//! - [`api`]: the methods, their parameters and results.

pub mod api;
mod client;
mod protocol;
mod registry;
mod server;

pub use client::{Client, ClientError};
pub use protocol::{
    API_VERSION, ErrorCode, Incoming, MAX_MESSAGE_LEN, Request, Response, RpcError, is_compatible,
};
pub use registry::{InstanceRecord, RegisterError, Registration, Registry, SelectError};
pub use server::{BoxFuture, Handler, Notifier, serve};
