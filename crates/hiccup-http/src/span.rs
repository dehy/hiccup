// SPDX-License-Identifier: AGPL-3.0-or-later

//! Byte ranges into a message's raw bytes.

/// A half-open byte range `start..end` into the raw bytes of a message.
///
/// Every parsed element (method, header name, header value, …) is a `Span`,
/// so the parsed view never copies or rewrites the original bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Span {
    /// Offset of the first byte.
    pub start: usize,
    /// Offset one past the last byte.
    pub end: usize,
}

impl Span {
    /// Creates a span. `start` must not be greater than `end`.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        debug_assert!(start <= end);
        Self { start, end }
    }

    /// An empty span at `at`.
    #[must_use]
    pub const fn empty(at: usize) -> Self {
        Self { start: at, end: at }
    }

    /// Length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the span covers no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// The bytes this span covers in `bytes`.
    ///
    /// # Panics
    ///
    /// Panics if the span is out of bounds of `bytes`.
    #[must_use]
    pub fn slice<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        &bytes[self.start..self.end]
    }
}
