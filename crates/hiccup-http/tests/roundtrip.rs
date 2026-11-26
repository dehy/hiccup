// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wire fidelity: parsing then serializing is byte-identical (ADR 0003).

use hiccup_http::{AnomalyKind, Framing, Limits, Request, Response};
use proptest::prelude::*;

/// Edge cases a security proxy must carry through unchanged. Each entry is
/// a complete request, its expected framing and an anomaly it must report.
const REQUEST_CORPUS: &[(&[u8], Framing, Option<AnomalyKind>)] = &[
    (b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", Framing::NoBody, None),
    (b"GET / HTTP/1.1\nHost: a\n\n", Framing::NoBody, Some(AnomalyKind::BareLf)),
    (
        b"GET / HTTP/1.1\r\nHost: a\r\nhost: b\r\nHOST: c\r\n\r\n",
        Framing::NoBody,
        None,
    ),
    (
        b"POST / HTTP/1.1\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        Framing::Chunked,
        Some(AnomalyKind::ContentLengthWithTransferEncoding),
    ),
    (
        b"POST / HTTP/1.1\r\nTransfer-Encoding : chunked\r\nContent-Length: 3\r\n\r\nabc",
        Framing::Length(3),
        Some(AnomalyKind::WhitespaceBeforeColon),
    ),
    (
        b"POST / HTTP/1.1\r\nTransfer-Encoding: xchunked\r\n\r\nrest of stream",
        Framing::UntilClose,
        Some(AnomalyKind::TransferEncodingNotChunked),
    ),
    (
        b"POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 5\r\n\r\nabc",
        Framing::Length(3),
        Some(AnomalyKind::ConflictingContentLength),
    ),
    (
        b"POST / HTTP/1.1\r\nX: a\r\n b\r\nContent-Length: 1\r\n\r\nz",
        Framing::Length(1),
        Some(AnomalyKind::ObsFold),
    ),
    (
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5;name=val\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n",
        Framing::Chunked,
        None,
    ),
    (b"GET /a b c HTTP/1.1\r\n\r\n", Framing::NoBody, Some(AnomalyKind::WhitespaceInTarget)),
    (b"GET /\r\n\r\n", Framing::NoBody, Some(AnomalyKind::MissingVersion)),
    (b"\r\nGET / HTTP/1.1\r\n\r\n", Framing::NoBody, Some(AnomalyKind::LeadingEmptyLines)),
    (b"GET / HTTP/1.1\r\nX: \x00\x01\x7f\xff\r\n\r\n", Framing::NoBody, Some(AnomalyKind::InvalidHeaderValue)),
    (b"GET / HTTP/1.1\r\nNoColonHere\r\n\r\n", Framing::NoBody, Some(AnomalyKind::MissingColon)),
];

#[test]
fn request_corpus_roundtrips() {
    for (raw, framing, anomaly) in REQUEST_CORPUS {
        let req = Request::parse(raw, &Limits::DEFAULT, true)
            .unwrap_or_else(|e| panic!("{e} for {:?}", String::from_utf8_lossy(raw)))
            .expect("complete");
        let shown = String::from_utf8_lossy(raw);
        assert_eq!(req.to_bytes(), *raw, "{shown}");
        assert_eq!(req.framing().framing, *framing, "{shown}");
        if let Some(kind) = anomaly {
            let found = req.head().has_anomaly(*kind)
                || req.framing().anomalies.iter().any(|a| a.kind == *kind)
                || req.body_anomalies().iter().any(|a| a.kind == *kind);
            assert!(found, "expected {kind:?} in {shown}");
        }
    }
}

// ---------------------------------------------------------------------------
// Properties

/// Bytes biased towards HTTP syntax, so random input reaches deep states.
fn http_ish_bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    let byte = prop_oneof![
        4 => prop::sample::select(b"GET POST HTTP/1.1 :;,0123456789abcdefABCDEF-chunked".to_vec()),
        2 => prop::sample::select(b"\r\n \t".to_vec()),
        1 => any::<u8>(),
    ];
    prop::collection::vec(byte, 0..max)
}

/// A header line made of hostile but newline-free bytes.
fn header_line() -> impl Strategy<Value = Vec<u8>> {
    let name = prop::collection::vec(
        any::<u8>().prop_filter("name byte", |b| {
            !matches!(b, b'\n' | b':' | b' ' | b'\t' | b'\r')
        }),
        1..20,
    );
    let value = prop::collection::vec(
        any::<u8>().prop_filter("value byte", |b| *b != b'\n'),
        0..40,
    );
    let sep = prop::sample::select(vec![&b":"[..], b": ", b" : ", b":\t"]);
    let ending = prop::sample::select(vec![&b"\r\n"[..], b"\n"]);
    (name, sep, value, ending).prop_map(|(name, sep, mut value, ending)| {
        // A trailing CR would merge with an LF ending into CRLF; that is
        // still a valid round trip but changes the field count, so avoid it.
        while value.last() == Some(&b'\r') {
            value.pop();
        }
        [name, sep.to_vec(), value, ending.to_vec()].concat()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    #[test]
    fn arbitrary_input_never_panics(input in http_ish_bytes(512)) {
        let limits = Limits::DEFAULT;
        if let Ok(Some(head)) = hiccup_http::RequestHead::parse(&input, &limits) {
            prop_assert_eq!(head.as_bytes(), &input[..head.len()]);
            for a in head.anomalies() {
                prop_assert!(a.span.end <= head.len());
            }
            let _ = head.framing();
        }
        if let Ok(Some(head)) = hiccup_http::ResponseHead::parse(&input, &limits) {
            prop_assert_eq!(head.as_bytes(), &input[..head.len()]);
            let _ = head.framing(b"GET");
        }
        for eof in [false, true] {
            if let Ok(Some(req)) = Request::parse(&input, &limits, eof) {
                prop_assert_eq!(req.to_bytes(), &input[..req.len()]);
            }
            if let Ok(Some(resp)) = Response::parse(&input, b"GET", &limits, eof) {
                prop_assert_eq!(resp.to_bytes(), &input[..resp.len()]);
            }
        }
    }

    #[test]
    fn hostile_headers_roundtrip(
        lines in prop::collection::vec(header_line(), 0..20),
        body in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut raw = b"POST /x HTTP/1.1\r\n".to_vec();
        for line in &lines {
            raw.extend_from_slice(line);
        }
        raw.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        raw.extend_from_slice(&body);

        let req = Request::parse(&raw, &Limits::DEFAULT, true).unwrap().unwrap();
        prop_assert_eq!(req.to_bytes(), raw);
        prop_assert_eq!(req.head().headers().count(), lines.len() + 1);
        prop_assert_eq!(&req.body()[..], &body[..]);
    }

    #[test]
    fn chunked_bodies_decode_whatever_the_split(
        payload in prop::collection::vec(any::<u8>(), 0..300),
        sizes in prop::collection::vec(1usize..50, 1..10),
        split in 0usize..400,
    ) {
        // Encode `payload` with the given chunk sizes (cycling).
        let mut wire = Vec::new();
        let mut rest = &payload[..];
        let mut i = 0;
        while !rest.is_empty() {
            let n = sizes[i % sizes.len()].min(rest.len());
            wire.extend_from_slice(format!("{n:x}\r\n").as_bytes());
            wire.extend_from_slice(&rest[..n]);
            wire.extend_from_slice(b"\r\n");
            rest = &rest[n..];
            i += 1;
        }
        wire.extend_from_slice(b"0\r\n\r\n");

        // Feed in two parts split at an arbitrary point.
        let split = split.min(wire.len());
        let mut decoder = hiccup_http::BodyDecoder::new(Framing::Chunked, Limits::DEFAULT);
        let mut data = Vec::new();
        let a = decoder.feed_with(&wire[..split], |d| data.extend_from_slice(d)).unwrap();
        prop_assert_eq!(a, split);
        let b = decoder.feed_with(&wire[split..], |d| data.extend_from_slice(d)).unwrap();
        prop_assert_eq!(a + b, wire.len());
        prop_assert!(decoder.is_complete());
        prop_assert_eq!(data, payload);
    }
}
