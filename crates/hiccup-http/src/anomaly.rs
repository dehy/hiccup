// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deviations from RFC 9112 found while parsing.
//!
//! The codec never rejects a message because it is malformed. It records an
//! [`Anomaly`] instead, so the user sees exactly what was on the wire and
//! why it is unusual. See ADR 0003.

use crate::Span;

/// What is unusual about a message. New kinds may be added in minor releases.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AnomalyKind {
    // --- Line structure -------------------------------------------------
    /// Empty lines before the start line (RFC 9112 §2.2 allows servers to
    /// ignore at least one).
    LeadingEmptyLines,
    /// A line ends with LF instead of CRLF.
    BareLf,
    /// A CR that is not immediately followed by LF.
    BareCr,

    // --- Start line -------------------------------------------------------
    /// The start line does not have the expected number of parts.
    MalformedStartLine,
    /// The start line uses more than one space between parts, or has leading
    /// or trailing whitespace.
    IrregularWhitespace,
    /// The start line uses a horizontal tab as a separator.
    TabInStartLine,
    /// The method contains characters that are not `tchar`.
    InvalidMethod,
    /// The request target contains whitespace (the request line has more
    /// than three parts).
    WhitespaceInTarget,
    /// The request target contains control or non-ASCII bytes.
    InvalidTarget,
    /// The request line has no HTTP version (HTTP/0.9 style).
    MissingVersion,
    /// The version is not of the form `HTTP/<digit>.<digit>`.
    InvalidVersion,
    /// The version is well-formed but neither `HTTP/1.0` nor `HTTP/1.1`.
    UnsupportedVersion,
    /// The status code is not exactly three digits.
    InvalidStatusCode,

    // --- Header fields ----------------------------------------------------
    /// A header line has no colon.
    MissingColon,
    /// A header line starts with a colon.
    EmptyHeaderName,
    /// Whitespace between the field name and the colon. RFC 9112 §5.1
    /// requires servers to reject this; it is a classic smuggling vector
    /// (`Transfer-Encoding : chunked`).
    WhitespaceBeforeColon,
    /// The field name contains characters that are not `tchar`.
    InvalidHeaderName,
    /// The field value contains control characters other than HTAB.
    InvalidHeaderValue,
    /// A line continues the previous field value (obsolete line folding).
    ObsFold,
    /// The first header line starts with whitespace.
    WhitespaceBeforeFirstHeader,

    // --- Framing (RFC 9112 §6.3) -------------------------------------------
    /// Both `Transfer-Encoding` and `Content-Length` are present.
    /// `Transfer-Encoding` takes precedence.
    ContentLengthWithTransferEncoding,
    /// `Content-Length` appears more than once with the same value.
    DuplicateContentLength,
    /// `Content-Length` appears more than once with different values.
    /// The first valid value is used.
    ConflictingContentLength,
    /// A `Content-Length` value is not a valid non-negative integer.
    InvalidContentLength,
    /// `Transfer-Encoding` is present but `chunked` is not the final coding.
    TransferEncodingNotChunked,
    /// `chunked` appears in `Transfer-Encoding` other than as the final,
    /// single occurrence.
    MisplacedChunked,

    // --- Chunked body -------------------------------------------------------
    /// The chunk size has whitespace before its extension or line end.
    ChunkSizeWhitespace,
}

/// An [`AnomalyKind`] located at a [`Span`].
///
/// For heads, the span is an offset into the head's raw bytes. For bodies,
/// it is an offset into the body's raw bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Anomaly {
    /// What is unusual.
    pub kind: AnomalyKind,
    /// Where it is.
    pub span: Span,
}

impl Anomaly {
    pub(crate) const fn new(kind: AnomalyKind, span: Span) -> Self {
        Self { kind, span }
    }
}
