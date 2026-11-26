// SPDX-License-Identifier: AGPL-3.0-or-later

//! Complete messages parsed from a buffer: head, raw body and framing.

use std::borrow::Cow;

use bytes::Bytes;

use crate::{
    Anomaly, BodyDecoder, Error, Framing, FramingDecision, Limits, RequestHead, ResponseHead,
    dechunk,
};

/// A complete HTTP/1.1 message: its head and its raw body bytes.
///
/// [`to_bytes`](Self::to_bytes) returns exactly the bytes that were parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message<H> {
    head: H,
    body: Bytes,
    framing: FramingDecision,
    body_anomalies: Vec<Anomaly>,
}

/// A complete request.
pub type Request = Message<RequestHead>;
/// A complete response.
pub type Response = Message<ResponseHead>;

impl<H: std::ops::Deref<Target = crate::Head>> Message<H> {
    /// The head.
    pub fn head(&self) -> &H {
        &self.head
    }

    /// The raw body bytes, with any chunk framing and trailers.
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// How the body is delimited, and the framing ambiguities.
    pub fn framing(&self) -> &FramingDecision {
        &self.framing
    }

    /// Anomalies found in the body. Spans are relative to the body start.
    pub fn body_anomalies(&self) -> &[Anomaly] {
        &self.body_anomalies
    }

    /// Total length on the wire (head plus body).
    pub fn len(&self) -> usize {
        self.head.len() + self.body.len()
    }

    /// Always `false`: a message contains at least a head.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The exact bytes of the message, as received.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len());
        out.extend_from_slice(self.head.as_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    /// The body without transfer coding: chunk framing and trailers removed.
    /// Content codings (`Content-Encoding`) are not decoded.
    ///
    /// # Errors
    ///
    /// Fails if the chunked framing is broken.
    pub fn decoded_body(&self) -> Result<Cow<'_, [u8]>, Error> {
        match self.framing.framing {
            Framing::Chunked => Ok(Cow::Owned(dechunk(&self.body, Limits::DEFAULT)?.data)),
            _ => Ok(Cow::Borrowed(&self.body)),
        }
    }
}

impl Request {
    /// Parses a complete request from the start of `buf`.
    ///
    /// Returns `Ok(None)` if more bytes are needed. Set `eof` when `buf` is
    /// everything there is (for example, an edited request or a closed
    /// connection); a body delimited by the connection closing then ends at
    /// the end of `buf`. Bytes after [`len`](Message::len) belong to the next
    /// message.
    ///
    /// # Errors
    ///
    /// Fails if a [`Limits`] bound is exceeded, if the chunked framing is
    /// broken, or if `eof` is set and the body is incomplete.
    pub fn parse(buf: &[u8], limits: &Limits, eof: bool) -> Result<Option<Self>, Error> {
        let Some(head) = RequestHead::parse(buf, limits)? else {
            return if eof {
                Err(Error::UnexpectedEof)
            } else {
                Ok(None)
            };
        };
        let framing = head.framing();
        Self::with_body(head, framing, buf, limits, eof)
    }
}

impl Response {
    /// Parses a complete response from the start of `buf`.
    ///
    /// `request_method` is the method of the request this response answers;
    /// see [`ResponseHead::framing`]. Otherwise behaves like
    /// [`Request::parse`].
    ///
    /// # Errors
    ///
    /// See [`Request::parse`].
    pub fn parse(
        buf: &[u8],
        request_method: &[u8],
        limits: &Limits,
        eof: bool,
    ) -> Result<Option<Self>, Error> {
        let Some(head) = ResponseHead::parse(buf, limits)? else {
            return if eof {
                Err(Error::UnexpectedEof)
            } else {
                Ok(None)
            };
        };
        let framing = head.framing(request_method);
        Self::with_body(head, framing, buf, limits, eof)
    }
}

impl<H: std::ops::Deref<Target = crate::Head>> Message<H> {
    fn with_body(
        head: H,
        framing: FramingDecision,
        buf: &[u8],
        limits: &Limits,
        eof: bool,
    ) -> Result<Option<Self>, Error> {
        let rest = &buf[head.len()..];
        let mut decoder = BodyDecoder::new(framing.framing, *limits);
        let used = decoder.feed(rest)?;
        if !decoder.is_complete() {
            if !eof {
                return Ok(None);
            }
            decoder.finish()?;
        }
        Ok(Some(Self {
            head,
            body: Bytes::copy_from_slice(&rest[..used]),
            framing,
            body_anomalies: decoder.anomalies().to_vec(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipelined_requests() {
        let buf = b"POST /a HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcGET /b HTTP/1.1\r\n\r\n";
        let first = Request::parse(buf, &Limits::DEFAULT, false)
            .unwrap()
            .unwrap();
        assert_eq!(first.head().target(), b"/a");
        assert_eq!(&first.body()[..], b"abc");
        let second = Request::parse(&buf[first.len()..], &Limits::DEFAULT, false)
            .unwrap()
            .unwrap();
        assert_eq!(second.head().target(), b"/b");
        assert_eq!(first.len() + second.len(), buf.len());
    }

    #[test]
    fn incomplete_and_eof() {
        let buf = b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc";
        assert_eq!(Request::parse(buf, &Limits::DEFAULT, false), Ok(None));
        assert_eq!(
            Request::parse(buf, &Limits::DEFAULT, true),
            Err(Error::UnexpectedEof)
        );
        assert_eq!(
            Request::parse(b"GET / HTTP/1.1\r\n", &Limits::DEFAULT, true),
            Err(Error::UnexpectedEof)
        );
    }

    #[test]
    fn response_until_close() {
        let buf = b"HTTP/1.0 200 OK\r\n\r\nhello";
        assert_eq!(
            Response::parse(buf, b"GET", &Limits::DEFAULT, false),
            Ok(None)
        );
        let r = Response::parse(buf, b"GET", &Limits::DEFAULT, true)
            .unwrap()
            .unwrap();
        assert_eq!(&r.body()[..], b"hello");
        assert_eq!(r.to_bytes(), buf);
    }

    #[test]
    fn chunked_response_decodes() {
        let buf = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        let r = Response::parse(buf, b"GET", &Limits::DEFAULT, false)
            .unwrap()
            .unwrap();
        assert_eq!(r.to_bytes(), buf);
        assert_eq!(&*r.decoded_body().unwrap(), b"abc");
    }

    #[test]
    fn interim_response_then_final() {
        let buf = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let interim = Response::parse(buf, b"POST", &Limits::DEFAULT, false)
            .unwrap()
            .unwrap();
        assert_eq!(interim.head().status_code(), Some(100));
        assert!(interim.body().is_empty());
        let fin = Response::parse(&buf[interim.len()..], b"POST", &Limits::DEFAULT, false)
            .unwrap()
            .unwrap();
        assert_eq!(fin.head().status_code(), Some(200));
        assert_eq!(&fin.body()[..], b"ok");
    }
}
