// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hard errors: input that exceeds limits or cannot be framed at all.
//!
//! Malformed but framable input is never an error; see [`crate::Anomaly`].

/// An error that stops parsing.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The head is larger than [`crate::Limits::max_head_len`].
    #[error("message head exceeds {limit} bytes")]
    HeadTooLarge {
        /// The configured limit.
        limit: usize,
    },
    /// The head has more fields than [`crate::Limits::max_headers`].
    #[error("message has more than {limit} header fields")]
    TooManyHeaders {
        /// The configured limit.
        limit: usize,
    },
    /// A chunk-size line is longer than [`crate::Limits::max_chunk_line_len`].
    #[error("chunk size line exceeds {limit} bytes")]
    ChunkLineTooLong {
        /// The configured limit.
        limit: usize,
    },
    /// A chunk-size line does not start with a hexadecimal size.
    #[error("invalid chunk size")]
    InvalidChunkSize,
    /// A chunk size does not fit in 64 bits.
    #[error("chunk size overflows")]
    ChunkSizeOverflow,
    /// Chunk data is not followed by a line ending.
    #[error("chunk data not followed by CRLF")]
    MissingChunkTerminator,
    /// The chunked trailer section is larger than
    /// [`crate::Limits::max_trailers_len`].
    #[error("chunked trailers exceed {limit} bytes")]
    TrailersTooLarge {
        /// The configured limit.
        limit: usize,
    },
    /// The input ended before the message was complete.
    #[error("unexpected end of input")]
    UnexpectedEof,
}
