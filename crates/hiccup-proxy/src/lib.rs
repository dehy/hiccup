// SPDX-License-Identifier: AGPL-3.0-or-later

//! Intercepting HTTP/1.1 proxy engine.
//!
//! - Explicit HTTP proxy: absolute-form requests are forwarded with their
//!   target rewritten to origin-form. The rewrite is recorded as a
//!   [`Modification`]; every other byte is forwarded as received, including
//!   hop-by-hop headers (ADR 0003).
//! - Persistent connections on both sides, with upstream reuse per host.
//! - `CONNECT` tunnels (pass-through; TLS interception comes later).
//! - Every completed [`Exchange`] is reported to an optional observer.
//! - A local [`CertificateAuthority`] for TLS interception.

pub mod ca;

mod config;
mod connection;
mod exchange;
mod server;
mod target;

pub use ca::{CaError, CaInfo, CertificateAuthority};
pub use config::ProxyConfig;
pub use exchange::{Exchange, ExchangeObserver, Modification};
pub use server::Proxy;
pub use target::{AbsoluteTarget, Authority, TargetError};
