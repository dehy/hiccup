// SPDX-License-Identifier: AGPL-3.0-or-later

//! Message body length, following RFC 9112 §6.3.
//!
//! Ambiguous framing is where request smuggling lives. The codec resolves it
//! the way RFC 9112 says a recipient should, and records every ambiguity as
//! an [`Anomaly`] so it is visible to the user.

use crate::{Anomaly, AnomalyKind, Head, RequestHead, ResponseHead, Span};

/// How the body of a message is delimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// The message has no body.
    NoBody,
    /// The body is exactly this many bytes (`Content-Length`).
    Length(u64),
    /// The body uses the chunked transfer coding.
    Chunked,
    /// The body extends until the connection closes.
    UntilClose,
    /// The connection switches to another protocol after this message
    /// (`101 Switching Protocols`, or a 2xx response to `CONNECT`).
    Tunnel,
}

/// A framing decision and the ambiguities found while making it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramingDecision {
    /// How to read the body.
    pub framing: Framing,
    /// Ambiguities in the framing headers. Spans point into the head.
    pub anomalies: Vec<Anomaly>,
}

impl RequestHead {
    /// Determines how the request body is delimited (RFC 9112 §6.3).
    ///
    /// - `Transfer-Encoding` with `chunked` as the final coding: chunked.
    ///   Any `Content-Length` is ignored, and flagged.
    /// - `Transfer-Encoding` without final `chunked`: the request cannot be
    ///   framed reliably; it is read until the connection closes, and flagged.
    /// - A valid `Content-Length`: that many bytes. With several values, the
    ///   first valid one is used, and flagged.
    /// - Otherwise: no body.
    #[must_use]
    pub fn framing(&self) -> FramingDecision {
        let mut anomalies = Vec::new();
        let te = transfer_encoding(self, &mut anomalies);
        let cl = content_length(self, &mut anomalies);
        let framing = match (te, cl) {
            (Some(te), cl) => {
                if let Some(cl) = cl {
                    anomalies.push(Anomaly::new(
                        AnomalyKind::ContentLengthWithTransferEncoding,
                        cl.span,
                    ));
                }
                if te.chunked {
                    Framing::Chunked
                } else {
                    anomalies.push(Anomaly::new(
                        AnomalyKind::TransferEncodingNotChunked,
                        te.span,
                    ));
                    Framing::UntilClose
                }
            }
            (None, Some(ContentLength { value: Some(n), .. })) => Framing::Length(n),
            (None, _) => Framing::NoBody,
        };
        FramingDecision { framing, anomalies }
    }
}

impl ResponseHead {
    /// Determines how the response body is delimited (RFC 9112 §6.3).
    ///
    /// `request_method` is the method of the request this response answers:
    /// responses to `HEAD` have no body, and 2xx responses to `CONNECT`
    /// start a tunnel.
    #[must_use]
    pub fn framing(&self, request_method: &[u8]) -> FramingDecision {
        let mut anomalies = Vec::new();
        let status = self.status_code();
        let no_body = match status {
            Some(101) => return decided(Framing::Tunnel),
            Some(200..=299) if request_method == b"CONNECT" => return decided(Framing::Tunnel),
            Some(100..=199 | 204 | 304) => true,
            _ => request_method == b"HEAD",
        };
        if no_body {
            return decided(Framing::NoBody);
        }

        let te = transfer_encoding(self, &mut anomalies);
        let cl = content_length(self, &mut anomalies);
        let framing = match (te, cl) {
            (Some(te), cl) => {
                if let Some(cl) = cl {
                    anomalies.push(Anomaly::new(
                        AnomalyKind::ContentLengthWithTransferEncoding,
                        cl.span,
                    ));
                }
                if te.chunked {
                    Framing::Chunked
                } else {
                    Framing::UntilClose
                }
            }
            (None, Some(ContentLength { value: Some(n), .. })) => Framing::Length(n),
            (None, _) => Framing::UntilClose,
        };
        FramingDecision { framing, anomalies }
    }
}

fn decided(framing: Framing) -> FramingDecision {
    FramingDecision {
        framing,
        anomalies: Vec::new(),
    }
}

struct TransferEncoding {
    chunked: bool,
    /// Span of the first `Transfer-Encoding` field.
    span: Span,
}

/// Combines all `Transfer-Encoding` fields into one coding list.
fn transfer_encoding(head: &Head, anomalies: &mut Vec<Anomaly>) -> Option<TransferEncoding> {
    let mut span = None;
    let mut codings: Vec<(Vec<u8>, Span)> = Vec::new();
    for h in head.get_all("transfer-encoding") {
        let field_span = h.field().raw;
        span.get_or_insert(field_span);
        for coding in h.value_unfolded().split(|&b| b == b',') {
            let coding = trim_ows(coding);
            if !coding.is_empty() {
                codings.push((coding.to_ascii_lowercase(), field_span));
            }
        }
    }
    let span = span?;
    let chunked_count = codings.iter().filter(|(c, _)| c == b"chunked").count();
    let last_is_chunked = codings.last().is_some_and(|(c, _)| c == b"chunked");
    if chunked_count > 1 || (chunked_count == 1 && !last_is_chunked) {
        let at = codings
            .iter()
            .find(|(c, _)| c == b"chunked")
            .map_or(span, |(_, s)| *s);
        anomalies.push(Anomaly::new(AnomalyKind::MisplacedChunked, at));
    }
    Some(TransferEncoding {
        chunked: last_is_chunked,
        span,
    })
}

#[derive(Clone, Copy)]
struct ContentLength {
    /// The first valid value, if any.
    value: Option<u64>,
    /// Span of the first `Content-Length` field.
    span: Span,
}

/// Combines all `Content-Length` fields and comma-separated values.
fn content_length(head: &Head, anomalies: &mut Vec<Anomaly>) -> Option<ContentLength> {
    let mut span = None;
    let mut first = None;
    let mut count = 0usize;
    let mut conflicting = false;
    for h in head.get_all("content-length") {
        let field_span = h.field().raw;
        span.get_or_insert(field_span);
        for item in h.value_unfolded().split(|&b| b == b',') {
            count += 1;
            match parse_u64(trim_ows(item)) {
                Some(n) => match first {
                    None => first = Some(n),
                    Some(f) if f != n => conflicting = true,
                    Some(_) => {}
                },
                None => anomalies.push(Anomaly::new(AnomalyKind::InvalidContentLength, field_span)),
            }
        }
    }
    let span = span?;
    if conflicting {
        anomalies.push(Anomaly::new(AnomalyKind::ConflictingContentLength, span));
    } else if count > 1 && first.is_some() {
        anomalies.push(Anomaly::new(AnomalyKind::DuplicateContentLength, span));
    }
    Some(ContentLength { value: first, span })
}

/// Parses `1*DIGIT` without overflow.
fn parse_u64(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0u64, |n, &d| {
        if d.is_ascii_digit() {
            n.checked_mul(10)?.checked_add(u64::from(d - b'0'))
        } else {
            None
        }
    })
}

fn trim_ows(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().take_while(|&&b| crate::head::is_ws(b)).count();
    let end = bytes.len()
        - bytes[start..]
            .iter()
            .rev()
            .take_while(|&&b| crate::head::is_ws(b))
            .count();
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Limits;

    fn request(headers: &str) -> RequestHead {
        let input = format!("POST / HTTP/1.1\r\n{headers}\r\n");
        RequestHead::parse(input.as_bytes(), &Limits::DEFAULT)
            .unwrap()
            .unwrap()
    }

    fn response(status: u16, headers: &str) -> ResponseHead {
        let input = format!("HTTP/1.1 {status} X\r\n{headers}\r\n");
        ResponseHead::parse(input.as_bytes(), &Limits::DEFAULT)
            .unwrap()
            .unwrap()
    }

    fn kinds(d: &FramingDecision) -> Vec<AnomalyKind> {
        d.anomalies.iter().map(|a| a.kind).collect()
    }

    #[test]
    fn request_framing() {
        use AnomalyKind::*;
        let cases: &[(&str, Framing, &[AnomalyKind])] = &[
            ("", Framing::NoBody, &[]),
            ("Content-Length: 5\r\n", Framing::Length(5), &[]),
            ("Content-Length: 0\r\n", Framing::Length(0), &[]),
            ("Transfer-Encoding: chunked\r\n", Framing::Chunked, &[]),
            (
                "Transfer-Encoding: gzip, Chunked\r\n",
                Framing::Chunked,
                &[],
            ),
            (
                "Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n",
                Framing::Chunked,
                &[],
            ),
            (
                "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n",
                Framing::Chunked,
                &[ContentLengthWithTransferEncoding],
            ),
            (
                "Transfer-Encoding: gzip\r\n",
                Framing::UntilClose,
                &[TransferEncodingNotChunked],
            ),
            (
                "Transfer-Encoding: chunked, gzip\r\n",
                Framing::UntilClose,
                &[MisplacedChunked, TransferEncodingNotChunked],
            ),
            (
                "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
                Framing::Chunked,
                &[MisplacedChunked],
            ),
            (
                "Content-Length: 5\r\nContent-Length: 5\r\n",
                Framing::Length(5),
                &[DuplicateContentLength],
            ),
            (
                "Content-Length: 5, 5\r\n",
                Framing::Length(5),
                &[DuplicateContentLength],
            ),
            (
                "Content-Length: 5\r\nContent-Length: 6\r\n",
                Framing::Length(5),
                &[ConflictingContentLength],
            ),
            (
                "Content-Length: abc\r\n",
                Framing::NoBody,
                &[InvalidContentLength],
            ),
            (
                "Content-Length: -1\r\n",
                Framing::NoBody,
                &[InvalidContentLength],
            ),
            (
                "Content-Length: +5\r\n",
                Framing::NoBody,
                &[InvalidContentLength],
            ),
            (
                "Content-Length: 99999999999999999999\r\n",
                Framing::NoBody,
                &[InvalidContentLength],
            ),
            // Not recognized as Transfer-Encoding: the name is verbatim.
            // The head itself carries a `WhitespaceBeforeColon` anomaly.
            ("Transfer-Encoding : chunked\r\n", Framing::NoBody, &[]),
        ];
        for (headers, framing, expected) in cases {
            let d = request(headers).framing();
            assert_eq!(d.framing, *framing, "{headers:?}");
            assert_eq!(kinds(&d), *expected, "{headers:?}");
        }
    }

    #[test]
    fn response_framing() {
        let cases: &[(u16, &[u8], &str, Framing)] = &[
            (200, b"GET", "Content-Length: 3\r\n", Framing::Length(3)),
            (
                200,
                b"GET",
                "Transfer-Encoding: chunked\r\n",
                Framing::Chunked,
            ),
            (
                200,
                b"GET",
                "Transfer-Encoding: gzip\r\n",
                Framing::UntilClose,
            ),
            (200, b"GET", "", Framing::UntilClose),
            (200, b"HEAD", "Content-Length: 3\r\n", Framing::NoBody),
            (204, b"GET", "Content-Length: 3\r\n", Framing::NoBody),
            (304, b"GET", "Content-Length: 3\r\n", Framing::NoBody),
            (100, b"POST", "", Framing::NoBody),
            (101, b"GET", "Upgrade: websocket\r\n", Framing::Tunnel),
            (200, b"CONNECT", "", Framing::Tunnel),
            (407, b"CONNECT", "Content-Length: 2\r\n", Framing::Length(2)),
        ];
        for (status, method, headers, framing) in cases {
            let d = response(*status, headers).framing(method);
            assert_eq!(d.framing, *framing, "{status} {method:?} {headers:?}");
        }
    }
}
