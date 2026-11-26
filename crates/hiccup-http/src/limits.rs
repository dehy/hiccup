// SPDX-License-Identifier: AGPL-3.0-or-later

//! Resource limits that protect the parser against hostile input.

/// Bounds applied while parsing. The body size is not limited here: bodies
/// are streamed, and callers decide how much to keep.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum size of a head (start line, header fields and the final empty
    /// line, including any leading empty lines).
    pub max_head_len: usize,
    /// Maximum number of header fields in a head.
    pub max_headers: usize,
    /// Maximum length of a chunk-size line, including extensions.
    pub max_chunk_line_len: usize,
    /// Maximum size of the trailer section of a chunked body.
    pub max_trailers_len: usize,
}

impl Limits {
    /// The default limits: 64 KiB heads, 256 fields, 4 KiB chunk lines and
    /// 64 KiB trailers.
    pub const DEFAULT: Self = Self {
        max_head_len: 64 * 1024,
        max_headers: 256,
        max_chunk_line_len: 4 * 1024,
        max_trailers_len: 64 * 1024,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}
