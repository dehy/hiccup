// SPDX-License-Identifier: AGPL-3.0-or-later

//! Opt-in request helpers of the repeater. Each returns new bytes and leaves
//! everything it does not need to change as it was.

use hiccup_http::{Limits, RequestHead, ResponseHead, Span};

use crate::{AbsoluteTarget, SendTarget};

/// `raw` with each span replaced by its bytes. The spans must not overlap.
fn splice(raw: &[u8], mut edits: Vec<(Span, Vec<u8>)>) -> Vec<u8> {
    edits.sort_by_key(|(span, _)| span.start);
    let mut out = Vec::with_capacity(raw.len());
    let mut at = 0;
    for (span, bytes) in edits {
        out.extend_from_slice(&raw[at..span.start]);
        out.extend_from_slice(&bytes);
        at = span.end;
    }
    out.extend_from_slice(&raw[at..]);
    out
}

/// `request` with its `Content-Length` values set to the length of what
/// follows the head, or with one added if there is none and there is a body.
/// `None` if nothing changes, the head is incomplete or the body is chunked.
pub(crate) fn update_content_length(request: &[u8], limits: &Limits) -> Option<Vec<u8>> {
    let head = RequestHead::parse(request, limits).ok()??;
    if head.get("transfer-encoding").is_some() {
        return None;
    }
    let len = (request.len() - head.len()).to_string().into_bytes();
    if head.get("content-length").is_some() {
        let edits: Vec<_> = head
            .headers()
            .filter(|h| h.is("content-length") && h.value() != len)
            .map(|h| (h.field().value, len.clone()))
            .collect();
        return (!edits.is_empty()).then(|| splice(request, edits));
    }
    if request.len() == head.len() {
        return None;
    }
    let at = head.end_line().full.start;
    let field = [&b"Content-Length: "[..], &len, b"\r\n"].concat();
    Some(splice(request, vec![(Span::new(at, at), field)]))
}

/// Where `response` to `request` (sent to `target`) redirects, and the
/// request to send there; `None` if it does not redirect.
///
/// 307 and 308 repeat the request. 303, and 301 or 302 after a `POST`, turn
/// it into a `GET` without a body (RFC 9110 §15.4). When the redirect leaves
/// the target (scheme, host or port), the `Host` header is set to the new
/// one, and credentials are dropped (`Authorization`, `Cookie`,
/// `Proxy-Authorization`): they were meant for the target only.
pub(crate) fn redirect(
    target: &SendTarget,
    request: &[u8],
    response: &ResponseHead,
    limits: &Limits,
) -> Option<(SendTarget, Vec<u8>)> {
    let status = response.status_code()?;
    if !matches!(status, 301 | 302 | 303 | 307 | 308) {
        return None;
    }
    let location = response.get("location")?.value();
    let head = RequestHead::parse(request, limits).ok()??;
    let (next, path) = resolve(target, head.target(), location)?;

    let (method, request_target, _) = head.request_line_spans();
    let mut edits = vec![(request_target, path)];
    let to_get = (status == 303 && head.method() != b"HEAD")
        || (matches!(status, 301 | 302) && head.method() == b"POST");
    if to_get {
        edits.push((method, b"GET".to_vec()));
        edits.extend(
            head.headers()
                .filter(|h| {
                    h.is("content-length") || h.is("transfer-encoding") || h.is("content-type")
                })
                .map(|h| (h.field().raw, Vec::new())),
        );
    }
    if next != *target {
        if let Some(host) = head.get("host") {
            edits.push((host.field().value, host_header(&next).into_bytes()));
        }
        edits.extend(
            head.headers()
                .filter(|h| h.is("authorization") || h.is("cookie") || h.is("proxy-authorization"))
                .map(|h| (h.field().raw, Vec::new())),
        );
    }
    let mut out = splice(&request[..head.len()], edits);
    if !to_get {
        out.extend_from_slice(&request[head.len()..]);
    }
    Some((next, out))
}

/// The target and request target that `location` points to.
fn resolve(target: &SendTarget, current: &[u8], location: &[u8]) -> Option<(SendTarget, Vec<u8>)> {
    let absolute = |url: &[u8]| {
        let (
            tls,
            AbsoluteTarget {
                authority,
                origin_form,
            },
        ) = AbsoluteTarget::parse_url(url).ok()?;
        let next = SendTarget {
            host: authority.host,
            port: authority.port,
            tls,
        };
        Some((next, origin_form))
    };
    if location.starts_with(b"//") {
        let scheme: &[u8] = if target.tls { b"https:" } else { b"http:" };
        return absolute(&[scheme, location].concat());
    }
    if location.starts_with(b"/") {
        return Some((target.clone(), location.to_vec()));
    }
    if let Some(found) = absolute(location) {
        return Some(found);
    }
    // Relative to the current path's directory.
    let path = current.split(|&b| b == b'?').next().unwrap_or_default();
    let dir = match path.iter().rposition(|&b| b == b'/') {
        Some(i) if path.starts_with(b"/") => &path[..=i],
        _ => b"/",
    };
    Some((target.clone(), [dir, location].concat()))
}

/// A `Host` value for `target`, without the default port.
fn host_header(target: &SendTarget) -> String {
    let host = if target.host.contains(':') {
        format!("[{}]", target.host)
    } else {
        target.host.clone()
    };
    let default = if target.tls { 443 } else { 80 };
    if target.port == default {
        host
    } else {
        format!("{host}:{}", target.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: Limits = Limits::DEFAULT;

    fn cl(raw: &[u8]) -> Option<String> {
        update_content_length(raw, &LIMITS).map(|b| String::from_utf8(b).unwrap())
    }

    #[test]
    fn content_length_is_fixed_added_or_left_alone() {
        assert_eq!(
            cl(b"POST / HTTP/1.1\r\nContent-Length: 1\r\nX: y\r\n\r\nabc").as_deref(),
            Some("POST / HTTP/1.1\r\nContent-Length: 3\r\nX: y\r\n\r\nabc")
        );
        // Every copy, keeping the rest byte for byte.
        assert_eq!(
            cl(b"POST / HTTP/1.1\nContent-Length:  9 \r\ncontent-length: 3\r\n\r\nabc").as_deref(),
            Some("POST / HTTP/1.1\nContent-Length:  3 \r\ncontent-length: 3\r\n\r\nabc")
        );
        assert_eq!(
            cl(b"POST / HTTP/1.1\r\nHost: a\r\n\r\nab").as_deref(),
            Some("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nab")
        );
        assert_eq!(cl(b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"), None);
        assert_eq!(cl(b"GET / HTTP/1.1\r\n\r\n"), None, "no body, no header");
        assert_eq!(
            cl(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"),
            None
        );
        assert_eq!(cl(b"POST / HTTP/1.1\r\nContent-Length: 1"), None, "no head");
    }

    fn target(host: &str, port: u16, tls: bool) -> SendTarget {
        SendTarget {
            host: host.to_owned(),
            port,
            tls,
        }
    }

    fn follow(status: &str, location: &str, request: &[u8]) -> Option<(SendTarget, String)> {
        let raw = format!("HTTP/1.1 {status} X\r\nLocation: {location}\r\n\r\n");
        let response = ResponseHead::parse(raw.as_bytes(), &LIMITS)
            .unwrap()
            .unwrap();
        redirect(&target("a.test", 8080, false), request, &response, &LIMITS)
            .map(|(t, r)| (t, String::from_utf8(r).unwrap()))
    }

    const POST: &[u8] =
        b"POST /dir/form?x HTTP/1.1\r\nHost: a.test:8080\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi";

    #[test]
    fn redirects_follow_the_rfc() {
        let same = target("a.test", 8080, false);
        // 307 repeats the request, body included; same target, same Host.
        assert_eq!(
            follow("307", "/next", POST),
            Some((
                same.clone(),
                "POST /next HTTP/1.1\r\nHost: a.test:8080\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi".to_owned()
            ))
        );
        // 303 turns it into a GET without a body, to another site.
        assert_eq!(
            follow("303", "https://b.test/done", POST),
            Some((
                target("b.test", 443, true),
                "GET /done HTTP/1.1\r\nHost: b.test\r\n\r\n".to_owned()
            ))
        );
        // Relative to the current directory, and scheme-relative.
        assert_eq!(
            follow("302", "other", b"GET /dir/page HTTP/1.1\r\n\r\n")
                .unwrap()
                .1,
            "GET /dir/other HTTP/1.1\r\n\r\n"
        );
        let (next, _) = follow("301", "//c.test:81/", b"GET / HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(next, target("c.test", 81, false));
        // Credentials stay with the target.
        let with_creds = b"GET / HTTP/1.1\r\nHost: a.test:8080\r\nAuthorization: Basic x\r\nCookie: s=1\r\nX: y\r\n\r\n";
        assert_eq!(
            follow("302", "/same", with_creds).unwrap().1,
            "GET /same HTTP/1.1\r\nHost: a.test:8080\r\nAuthorization: Basic x\r\nCookie: s=1\r\nX: y\r\n\r\n"
        );
        assert_eq!(
            follow("302", "http://evil.test/", with_creds).unwrap().1,
            "GET / HTTP/1.1\r\nHost: evil.test\r\nX: y\r\n\r\n"
        );
        assert_eq!(follow("200", "/x", POST), None);
        assert_eq!(follow("304", "/x", POST), None);
    }

    #[test]
    fn host_headers_omit_the_default_port() {
        assert_eq!(host_header(&target("a.test", 443, true)), "a.test");
        assert_eq!(host_header(&target("a.test", 443, false)), "a.test:443");
        assert_eq!(host_header(&target("::1", 80, false)), "[::1]");
    }
}
