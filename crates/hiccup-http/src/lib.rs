// SPDX-License-Identifier: AGPL-3.0-or-later

//! Raw-preserving HTTP/1.1 codec.
//!
//! Messages keep their exact original bytes; parsed fields are a derived,
//! read-only view made of [`Span`]s into those bytes. Parsing never rejects
//! or rewrites a malformed message: it records [`Anomaly`]s instead, so
//! Hiccup can show and forward exactly what was on the wire. The only hard
//! errors are [`Limits`] violations and chunked framing that cannot be
//! followed. See ADR 0003.
//!
//! The codec is sans-IO: it parses byte buffers and never touches sockets.
//!
//! ```
//! use hiccup_http::{AnomalyKind, Framing, Limits, Request};
//!
//! let raw = b"POST /login HTTP/1.1\r\n\
//!             Host: example.com\r\n\
//!             Content-Length: 4\r\n\
//!             Transfer-Encoding: chunked\r\n\r\n\
//!             0\r\n\r\n";
//! let req = Request::parse(raw, &Limits::DEFAULT, false)?.expect("complete");
//!
//! assert_eq!(req.head().method(), b"POST");
//! assert_eq!(req.framing().framing, Framing::Chunked);
//! assert_eq!(
//!     req.framing().anomalies[0].kind,
//!     AnomalyKind::ContentLengthWithTransferEncoding,
//! );
//! assert_eq!(req.to_bytes(), raw); // byte-identical
//! # Ok::<(), hiccup_http::Error>(())
//! ```

mod anomaly;
mod body;
mod error;
mod framing;
mod head;
mod limits;
mod message;
mod span;

pub use anomaly::{Anomaly, AnomalyKind};
pub use body::{BodyDecoder, Dechunked, dechunk};
pub use error::Error;
pub use framing::{Framing, FramingDecision};
pub use head::{Head, Header, HeaderField, Line, RequestHead, ResponseHead};
pub use limits::Limits;
pub use message::{Message, Request, Response};
pub use span::Span;
