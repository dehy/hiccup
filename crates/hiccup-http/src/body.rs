// SPDX-License-Identifier: AGPL-3.0-or-later

//! Streaming, sans-IO body decoder.
//!
//! [`BodyDecoder`] finds where a body ends in a byte stream. The caller keeps
//! the raw bytes (chunk framing included); the decoder can also hand out the
//! decoded payload.

use crate::{Anomaly, AnomalyKind, Error, Framing, Limits, Span};

/// Finds the end of a message body in a byte stream.
///
/// Feed it the bytes that follow the head with [`feed`](Self::feed); it
/// reports how many of them belong to the body. Bytes after that belong to the
/// next message (pipelining) or to a tunnel.
#[derive(Clone, Debug)]
pub struct BodyDecoder {
    state: State,
    limits: Limits,
    /// Bytes consumed so far; anomaly spans are relative to the body start.
    offset: usize,
    /// Partial line being accumulated (chunk-size or trailer line).
    line: Vec<u8>,
    trailers_len: usize,
    anomalies: Vec<Anomaly>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Done,
    Length { remaining: u64 },
    UntilClose,
    ChunkSize,
    ChunkData { remaining: u64 },
    ChunkDataEnd { seen_cr: bool },
    Trailers,
}

impl BodyDecoder {
    /// Creates a decoder for a body with the given framing.
    ///
    /// [`Framing::NoBody`] and [`Framing::Tunnel`] produce a decoder that is
    /// already complete: the body is empty.
    #[must_use]
    pub fn new(framing: Framing, limits: Limits) -> Self {
        let state = match framing {
            Framing::NoBody | Framing::Tunnel | Framing::Length(0) => State::Done,
            Framing::Length(n) => State::Length { remaining: n },
            Framing::UntilClose => State::UntilClose,
            Framing::Chunked => State::ChunkSize,
        };
        Self {
            state,
            limits,
            offset: 0,
            line: Vec::new(),
            trailers_len: 0,
            anomalies: Vec::new(),
        }
    }

    /// Whether the whole body has been consumed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.state == State::Done
    }

    /// Anomalies found in the body so far. Spans are relative to the start
    /// of the body.
    #[must_use]
    pub fn anomalies(&self) -> &[Anomaly] {
        &self.anomalies
    }

    /// Consumes body bytes from the start of `input` and returns how many
    /// were consumed. Stops at the end of the body.
    ///
    /// # Errors
    ///
    /// Fails if the chunked framing is broken or exceeds [`Limits`].
    pub fn feed(&mut self, input: &[u8]) -> Result<usize, Error> {
        self.feed_with(input, |_| {})
    }

    /// Like [`feed`](Self::feed), and also passes each piece of decoded
    /// payload (chunk data without framing) to `on_data`.
    ///
    /// # Errors
    ///
    /// Fails if the chunked framing is broken or exceeds [`Limits`].
    pub fn feed_with(
        &mut self,
        input: &[u8],
        mut on_data: impl FnMut(&[u8]),
    ) -> Result<usize, Error> {
        let mut pos = 0;
        while pos < input.len() {
            let rest = &input[pos..];
            let used = match self.state {
                State::Done => break,
                State::UntilClose => {
                    on_data(rest);
                    rest.len()
                }
                State::Length { remaining } | State::ChunkData { remaining } => {
                    let n = take(remaining, rest.len());
                    on_data(&rest[..n]);
                    let remaining = remaining - n as u64;
                    self.state = match (self.state, remaining) {
                        (State::Length { .. }, 0) => State::Done,
                        (State::Length { .. }, _) => State::Length { remaining },
                        (_, 0) => State::ChunkDataEnd { seen_cr: false },
                        (_, _) => State::ChunkData { remaining },
                    };
                    n
                }
                State::ChunkDataEnd { seen_cr } => {
                    match (rest[0], seen_cr) {
                        (b'\r', false) => self.state = State::ChunkDataEnd { seen_cr: true },
                        (b'\n', seen_cr) => {
                            if !seen_cr {
                                self.anomaly(AnomalyKind::BareLf, 0, 1);
                            }
                            self.state = State::ChunkSize;
                        }
                        _ => return Err(Error::MissingChunkTerminator),
                    }
                    1
                }
                State::ChunkSize | State::Trailers => self.line_bytes(rest)?,
            };
            pos += used;
            self.offset += used;
        }
        Ok(pos)
    }

    /// Signals that the input has ended (the connection closed).
    ///
    /// # Errors
    ///
    /// Fails with [`Error::UnexpectedEof`] unless the body is complete or is
    /// delimited by the connection closing.
    pub fn finish(&mut self) -> Result<(), Error> {
        match self.state {
            State::Done => Ok(()),
            State::UntilClose => {
                self.state = State::Done;
                Ok(())
            }
            _ => Err(Error::UnexpectedEof),
        }
    }

    /// Accumulates a chunk-size or trailer line; processes it once complete.
    fn line_bytes(&mut self, rest: &[u8]) -> Result<usize, Error> {
        let (used, complete) = match rest.iter().position(|&b| b == b'\n') {
            Some(lf) => (lf + 1, true),
            None => (rest.len(), false),
        };
        self.line.extend_from_slice(&rest[..used]);
        match self.state {
            State::ChunkSize if self.line.len() > self.limits.max_chunk_line_len => {
                return Err(Error::ChunkLineTooLong {
                    limit: self.limits.max_chunk_line_len,
                });
            }
            State::Trailers
                if self.trailers_len + self.line.len() > self.limits.max_trailers_len =>
            {
                return Err(Error::TrailersTooLarge {
                    limit: self.limits.max_trailers_len,
                });
            }
            _ => {}
        }
        if complete {
            // The line started `line.len() - used` bytes before this call's
            // offset; anomaly spans are computed from its start.
            let line_start = self.offset + used - self.line.len();
            let line = std::mem::take(&mut self.line);
            match self.state {
                State::ChunkSize => self.chunk_size_line(&line, line_start)?,
                State::Trailers => self.trailer_line(&line, line_start),
                _ => unreachable!("line_bytes called in a non-line state"),
            }
        }
        Ok(used)
    }

    fn chunk_size_line(&mut self, line: &[u8], line_start: usize) -> Result<(), Error> {
        let content = self.strip_line_ending(line, line_start);
        let digits = content.iter().take_while(|b| b.is_ascii_hexdigit()).count();
        if digits == 0 {
            return Err(Error::InvalidChunkSize);
        }
        let size = content[..digits].iter().try_fold(0u64, |n, &d| {
            let v = u64::from(char::from(d).to_digit(16).expect("hex digit"));
            n.checked_mul(16)?.checked_add(v)
        });
        let size = size.ok_or(Error::ChunkSizeOverflow)?;

        let after = &content[digits..];
        let ws = after.iter().take_while(|&&b| crate::head::is_ws(b)).count();
        match after.get(ws) {
            None | Some(b';') => {
                if ws > 0 {
                    let start = line_start + digits;
                    self.anomalies.push(Anomaly::new(
                        AnomalyKind::ChunkSizeWhitespace,
                        Span::new(start, start + ws),
                    ));
                }
            }
            Some(_) => return Err(Error::InvalidChunkSize),
        }

        self.state = if size == 0 {
            State::Trailers
        } else {
            State::ChunkData { remaining: size }
        };
        Ok(())
    }

    fn trailer_line(&mut self, line: &[u8], line_start: usize) {
        let content = self.strip_line_ending(line, line_start);
        if content.is_empty() {
            self.state = State::Done;
        } else {
            self.trailers_len += line.len();
        }
    }

    /// Returns the line without its line ending, flagging a bare LF.
    fn strip_line_ending<'l>(&mut self, line: &'l [u8], line_start: usize) -> &'l [u8] {
        let without_lf = &line[..line.len() - 1];
        if let Some(content) = without_lf.strip_suffix(b"\r") {
            content
        } else {
            let lf = line_start + line.len() - 1;
            self.anomalies
                .push(Anomaly::new(AnomalyKind::BareLf, Span::new(lf, lf + 1)));
            without_lf
        }
    }

    /// Records an anomaly at `rel` bytes from the current offset.
    fn anomaly(&mut self, kind: AnomalyKind, rel: usize, len: usize) {
        let start = self.offset + rel;
        self.anomalies
            .push(Anomaly::new(kind, Span::new(start, start + len)));
    }
}

/// `min(remaining, available)` without lossy casts.
fn take(remaining: u64, available: usize) -> usize {
    usize::try_from(remaining).map_or(available, |r| r.min(available))
}

/// The decoded payload of a complete chunked body, and its trailer section.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dechunked {
    /// The concatenated chunk data.
    pub data: Vec<u8>,
    /// Whether the body ended with the terminating zero-size chunk.
    pub complete: bool,
}

/// Decodes the chunked body in `raw`, ignoring anything after its end.
///
/// # Errors
///
/// Fails if the chunked framing is broken or exceeds [`Limits`].
pub fn dechunk(raw: &[u8], limits: Limits) -> Result<Dechunked, Error> {
    let mut decoder = BodyDecoder::new(Framing::Chunked, limits);
    let mut data = Vec::new();
    decoder.feed_with(raw, |d| data.extend_from_slice(d))?;
    Ok(Dechunked {
        data,
        complete: decoder.is_complete(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(framing: Framing, input: &[u8]) -> (usize, Vec<u8>, BodyDecoder) {
        let mut d = BodyDecoder::new(framing, Limits::DEFAULT);
        let mut data = Vec::new();
        let used = d.feed_with(input, |p| data.extend_from_slice(p)).unwrap();
        (used, data, d)
    }

    /// Feeds one byte at a time, to exercise every partial state.
    fn decode_bytewise(framing: Framing, input: &[u8]) -> (usize, Vec<u8>, BodyDecoder) {
        let mut d = BodyDecoder::new(framing, Limits::DEFAULT);
        let mut data = Vec::new();
        let mut used = 0;
        for i in 0..input.len() {
            used += d
                .feed_with(&input[i..=i], |p| data.extend_from_slice(p))
                .unwrap();
            if d.is_complete() {
                break;
            }
        }
        (used, data, d)
    }

    #[test]
    fn content_length() {
        let (used, data, d) = decode_all(Framing::Length(5), b"helloGET /");
        assert_eq!((used, &data[..], d.is_complete()), (5, &b"hello"[..], true));

        let (used, _, d) = decode_all(Framing::Length(5), b"hel");
        assert_eq!((used, d.is_complete()), (3, false));
    }

    #[test]
    fn no_body_and_tunnel_are_complete() {
        for f in [Framing::NoBody, Framing::Tunnel, Framing::Length(0)] {
            let (used, _, d) = decode_all(f, b"next");
            assert_eq!((used, d.is_complete()), (0, true), "{f:?}");
        }
    }

    #[test]
    fn until_close() {
        let (used, data, mut d) = decode_all(Framing::UntilClose, b"abc");
        assert_eq!((used, &data[..], d.is_complete()), (3, &b"abc"[..], false));
        d.finish().unwrap();
        assert!(d.is_complete());
    }

    #[test]
    fn chunked() {
        let body = b"4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\nTrailer: x\r\n\r\nGET";
        for decode in [decode_all, decode_bytewise] {
            let (used, data, d) = decode(Framing::Chunked, body);
            assert_eq!(used, body.len() - 3);
            assert_eq!(data, b"Wikipedia");
            assert!(d.is_complete());
            assert!(d.anomalies().is_empty());
        }
    }

    #[test]
    fn chunked_lenient_line_endings() {
        let body = b"3\nabc\n0\n\n";
        let (used, data, d) = decode_all(Framing::Chunked, body);
        assert_eq!((used, &data[..]), (body.len(), &b"abc"[..]));
        let spans: Vec<_> = d.anomalies().iter().map(|a| (a.kind, a.span)).collect();
        assert_eq!(
            spans,
            [
                (AnomalyKind::BareLf, Span::new(1, 2)),
                (AnomalyKind::BareLf, Span::new(5, 6)),
                (AnomalyKind::BareLf, Span::new(7, 8)),
                (AnomalyKind::BareLf, Span::new(8, 9)),
            ]
        );
        // Same spans when fed byte by byte.
        let (_, _, d2) = decode_bytewise(Framing::Chunked, body);
        assert_eq!(d.anomalies(), d2.anomalies());
    }

    #[test]
    fn chunk_size_whitespace() {
        let body = b"3  \r\nabc\r\n0\r\n\r\n";
        for decode in [decode_all, decode_bytewise] {
            let (_, data, d) = decode(Framing::Chunked, body);
            assert_eq!(data, b"abc");
            assert_eq!(
                d.anomalies(),
                [Anomaly::new(
                    AnomalyKind::ChunkSizeWhitespace,
                    Span::new(1, 3)
                )]
            );
        }
    }

    #[test]
    fn chunked_errors() {
        let cases: &[(&[u8], Error)] = &[
            (b"zz\r\n", Error::InvalidChunkSize),
            (b"\r\n", Error::InvalidChunkSize),
            (b"3x\r\n", Error::InvalidChunkSize),
            (b"10000000000000000\r\n", Error::ChunkSizeOverflow),
            (b"3\r\nabcX", Error::MissingChunkTerminator),
        ];
        for (input, err) in cases {
            let mut d = BodyDecoder::new(Framing::Chunked, Limits::DEFAULT);
            assert_eq!(d.feed(input), Err(err.clone()), "{input:?}");
        }
    }

    #[test]
    fn chunked_limits() {
        let limits = Limits {
            max_chunk_line_len: 8,
            max_trailers_len: 8,
            ..Limits::DEFAULT
        };
        let mut d = BodyDecoder::new(Framing::Chunked, limits);
        assert_eq!(
            d.feed(b"1;aaaaaaaaaa"),
            Err(Error::ChunkLineTooLong { limit: 8 })
        );
        let mut d = BodyDecoder::new(Framing::Chunked, limits);
        assert_eq!(
            d.feed(b"0\r\nA: 1\r\nB: 2\r\n"),
            Err(Error::TrailersTooLarge { limit: 8 })
        );
    }

    #[test]
    fn eof_before_end_is_an_error() {
        let mut d = BodyDecoder::new(Framing::Length(10), Limits::DEFAULT);
        d.feed(b"abc").unwrap();
        assert_eq!(d.finish(), Err(Error::UnexpectedEof));
    }

    #[test]
    fn dechunk_helper() {
        let out = dechunk(b"3\r\nabc\r\n0\r\n\r\n", Limits::DEFAULT).unwrap();
        assert_eq!(out.data, b"abc");
        assert!(out.complete);
        assert!(!dechunk(b"3\r\nab", Limits::DEFAULT).unwrap().complete);
    }
}
