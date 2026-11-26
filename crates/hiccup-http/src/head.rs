// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lenient tokenizer for HTTP/1.1 message heads.
//!
//! A head is split into lines at LF. Lines are then interpreted as a start
//! line and header fields, recording [`Span`]s into the raw bytes and an
//! [`Anomaly`] for anything that deviates from RFC 9112. Nothing is rejected
//! or rewritten.

use std::borrow::Cow;

use bytes::Bytes;

use crate::{Anomaly, AnomalyKind, Error, Limits, Span};

/// One line of a head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line {
    /// The line without its line ending.
    pub content: Span,
    /// The line including its line ending (CRLF or bare LF).
    pub full: Span,
}

/// A header field, possibly spread over several lines by obsolete folding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderField {
    /// The field name: every byte before the colon, verbatim (including any
    /// whitespace before the colon).
    pub name: Span,
    /// The field value without leading and trailing whitespace. For folded
    /// fields, it includes the raw folding (line endings and indentation).
    pub value: Span,
    /// All lines of the field, including line endings.
    pub raw: Span,
    /// Whether the field uses obsolete line folding.
    pub folded: bool,
}

/// A borrowed view of a [`HeaderField`] together with the bytes it points to.
#[derive(Clone, Copy, Debug)]
pub struct Header<'a> {
    field: &'a HeaderField,
    bytes: &'a [u8],
}

impl<'a> Header<'a> {
    /// The field name, verbatim.
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.field.name.slice(self.bytes)
    }

    /// The field value, trimmed, with folding left as-is.
    #[must_use]
    pub fn value(&self) -> &'a [u8] {
        self.field.value.slice(self.bytes)
    }

    /// The field value with each obsolete line fold replaced by one space,
    /// as RFC 9112 §5.2 allows recipients to do.
    #[must_use]
    pub fn value_unfolded(&self) -> Cow<'a, [u8]> {
        let value = self.value();
        if !self.field.folded {
            return Cow::Borrowed(value);
        }
        let mut out = Vec::with_capacity(value.len());
        let mut i = 0;
        while i < value.len() {
            let fold_len = match value[i..] {
                [b'\r', b'\n', ..] => 2,
                [b'\n', ..] => 1,
                _ => 0,
            };
            if fold_len > 0 {
                i += fold_len;
                while i < value.len() && is_ws(value[i]) {
                    i += 1;
                }
                out.push(b' ');
            } else {
                out.push(value[i]);
                i += 1;
            }
        }
        Cow::Owned(out)
    }

    /// The raw lines of the field, including line endings.
    #[must_use]
    pub fn raw(&self) -> &'a [u8] {
        self.field.raw.slice(self.bytes)
    }

    /// Whether the name equals `name`, ignoring ASCII case. The comparison is
    /// on the verbatim name, so `Host ` does not match `host`.
    #[must_use]
    pub fn is(&self, name: &str) -> bool {
        self.name().eq_ignore_ascii_case(name.as_bytes())
    }

    /// The spans of this field.
    #[must_use]
    pub fn field(&self) -> &'a HeaderField {
        self.field
    }
}

/// The parts shared by request and response heads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    raw: Bytes,
    leading: Span,
    start_line: Line,
    fields: Vec<HeaderField>,
    end: Line,
    anomalies: Vec<Anomaly>,
}

impl Head {
    /// The exact bytes of the head, including the final empty line.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// The exact bytes of the head as a cheaply clonable buffer.
    #[must_use]
    pub fn raw(&self) -> &Bytes {
        &self.raw
    }

    /// Length of the head in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// Always `false`: a head contains at least a start line and an empty line.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// Empty lines before the start line (usually empty).
    #[must_use]
    pub fn leading(&self) -> Span {
        self.leading
    }

    /// The start line (request line or status line).
    #[must_use]
    pub fn start_line(&self) -> Line {
        self.start_line
    }

    /// The empty line that ends the head.
    #[must_use]
    pub fn end_line(&self) -> Line {
        self.end
    }

    /// The header fields in wire order, duplicates included.
    pub fn headers(&self) -> impl Iterator<Item = Header<'_>> {
        self.fields.iter().map(|field| Header {
            field,
            bytes: &self.raw,
        })
    }

    /// The fields whose name equals `name`, ignoring ASCII case.
    pub fn get_all<'a, 'n>(
        &'a self,
        name: &'n str,
    ) -> impl Iterator<Item = Header<'a>> + use<'a, 'n> {
        self.headers().filter(move |h| h.is(name))
    }

    /// The first field whose name equals `name`, ignoring ASCII case.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Header<'_>> {
        self.get_all(name).next()
    }

    /// Anomalies found in the head, ordered by position.
    #[must_use]
    pub fn anomalies(&self) -> &[Anomaly] {
        &self.anomalies
    }

    /// Whether the head has an anomaly of the given kind.
    #[must_use]
    pub fn has_anomaly(&self, kind: AnomalyKind) -> bool {
        self.anomalies.iter().any(|a| a.kind == kind)
    }

    fn parse(buf: &[u8], limits: &Limits) -> Result<Option<Self>, Error> {
        let Some(scan) = scan(buf, limits)? else {
            return Ok(None);
        };
        let raw = Bytes::copy_from_slice(&buf[..scan.len]);
        let mut anomalies = Vec::new();
        if !scan.leading.is_empty() {
            anomalies.push(Anomaly::new(AnomalyKind::LeadingEmptyLines, scan.leading));
        }
        for line in std::iter::once(&scan.start_line)
            .chain(&scan.field_lines)
            .chain(std::iter::once(&scan.end))
        {
            check_line(&raw, line, &mut anomalies);
        }
        let fields = parse_fields(&raw, &scan.field_lines, &mut anomalies);
        let head = Self {
            raw,
            leading: scan.leading,
            start_line: scan.start_line.line,
            fields,
            end: scan.end.line,
            anomalies,
        };
        debug_assert!(head.spans_tile(), "head spans must cover every byte");
        Ok(Some(head))
    }

    fn finish(&mut self) {
        self.anomalies.sort_by_key(|a| (a.span.start, a.span.end));
    }

    /// Checks that leading lines, start line, fields and end line cover the
    /// raw bytes exactly once, in order.
    fn spans_tile(&self) -> bool {
        let mut pos = self.leading.end;
        if self.leading.start != 0 || self.start_line.full.start != pos {
            return false;
        }
        pos = self.start_line.full.end;
        for f in &self.fields {
            if f.raw.start != pos {
                return false;
            }
            pos = f.raw.end;
        }
        self.end.full.start == pos && self.end.full.end == self.raw.len()
    }
}

/// A parsed request head: request line plus header fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestHead {
    head: Head,
    method: Span,
    target: Span,
    version: Option<Span>,
}

impl RequestHead {
    /// Parses a request head from the start of `buf`.
    ///
    /// Returns `Ok(None)` if `buf` does not yet contain a complete head.
    /// The head's length is [`Head::len`]; the bytes after it belong to the
    /// body or to the next message.
    ///
    /// # Errors
    ///
    /// Fails only when a [`Limits`] bound is exceeded.
    pub fn parse(buf: &[u8], limits: &Limits) -> Result<Option<Self>, Error> {
        let Some(mut head) = Head::parse(buf, limits)? else {
            return Ok(None);
        };
        let (method, target, version) =
            parse_request_line(&head.raw, head.start_line, &mut head.anomalies);
        head.finish();
        Ok(Some(Self {
            head,
            method,
            target,
            version,
        }))
    }

    /// The method, verbatim (methods are case-sensitive).
    #[must_use]
    pub fn method(&self) -> &[u8] {
        self.method.slice(&self.head.raw)
    }

    /// The request target, verbatim.
    #[must_use]
    pub fn target(&self) -> &[u8] {
        self.target.slice(&self.head.raw)
    }

    /// The HTTP version, verbatim, if present.
    #[must_use]
    pub fn version(&self) -> Option<&[u8]> {
        self.version.map(|v| v.slice(&self.head.raw))
    }

    /// Spans of the method, target and version.
    #[must_use]
    pub fn request_line_spans(&self) -> (Span, Span, Option<Span>) {
        (self.method, self.target, self.version)
    }
}

impl std::ops::Deref for RequestHead {
    type Target = Head;

    fn deref(&self) -> &Head {
        &self.head
    }
}

/// A parsed response head: status line plus header fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseHead {
    head: Head,
    version: Span,
    status: Span,
    status_code: Option<u16>,
    reason: Span,
}

impl ResponseHead {
    /// Parses a response head from the start of `buf`.
    ///
    /// Returns `Ok(None)` if `buf` does not yet contain a complete head.
    ///
    /// # Errors
    ///
    /// Fails only when a [`Limits`] bound is exceeded.
    pub fn parse(buf: &[u8], limits: &Limits) -> Result<Option<Self>, Error> {
        let Some(mut head) = Head::parse(buf, limits)? else {
            return Ok(None);
        };
        let (version, status, status_code, reason) =
            parse_status_line(&head.raw, head.start_line, &mut head.anomalies);
        head.finish();
        Ok(Some(Self {
            head,
            version,
            status,
            status_code,
            reason,
        }))
    }

    /// The HTTP version, verbatim.
    #[must_use]
    pub fn version(&self) -> &[u8] {
        self.version.slice(&self.head.raw)
    }

    /// The status code, if it is exactly three digits.
    #[must_use]
    pub fn status_code(&self) -> Option<u16> {
        self.status_code
    }

    /// The status code bytes, verbatim.
    #[must_use]
    pub fn status(&self) -> &[u8] {
        self.status.slice(&self.head.raw)
    }

    /// The reason phrase, verbatim (may be empty).
    #[must_use]
    pub fn reason(&self) -> &[u8] {
        self.reason.slice(&self.head.raw)
    }

    /// Spans of the version, status code and reason phrase.
    #[must_use]
    pub fn status_line_spans(&self) -> (Span, Span, Span) {
        (self.version, self.status, self.reason)
    }
}

impl std::ops::Deref for ResponseHead {
    type Target = Head;

    fn deref(&self) -> &Head {
        &self.head
    }
}

// ---------------------------------------------------------------------------
// Scanning

#[derive(Clone, Copy, Debug)]
struct ScannedLine {
    line: Line,
    bare_lf: bool,
}

struct Scan {
    leading: Span,
    start_line: ScannedLine,
    field_lines: Vec<ScannedLine>,
    end: ScannedLine,
    len: usize,
}

/// Splits the head into lines without interpreting them.
fn scan(buf: &[u8], limits: &Limits) -> Result<Option<Scan>, Error> {
    let too_large = Error::HeadTooLarge {
        limit: limits.max_head_len,
    };
    let mut pos = 0;
    let mut leading_end = 0;
    let mut start_line = None;
    let mut field_lines = Vec::new();
    let mut fields = 0usize;

    loop {
        let Some(rel) = buf[pos..].iter().position(|&b| b == b'\n') else {
            return if buf.len() > limits.max_head_len {
                Err(too_large)
            } else {
                Ok(None)
            };
        };
        let lf = pos + rel;
        let full = Span::new(pos, lf + 1);
        if full.end > limits.max_head_len {
            return Err(too_large);
        }
        let bare_lf = !(lf > pos && buf[lf - 1] == b'\r');
        let content_end = if bare_lf { lf } else { lf - 1 };
        let line = ScannedLine {
            line: Line {
                content: Span::new(pos, content_end),
                full,
            },
            bare_lf,
        };
        pos = full.end;

        if line.line.content.is_empty() {
            match start_line {
                None => leading_end = pos,
                Some(start_line) => {
                    return Ok(Some(Scan {
                        leading: Span::new(0, leading_end),
                        start_line,
                        field_lines,
                        end: line,
                        len: pos,
                    }));
                }
            }
        } else if start_line.is_none() {
            start_line = Some(line);
        } else {
            if !is_ws(buf[line.line.content.start]) {
                fields += 1;
                if fields > limits.max_headers {
                    return Err(Error::TooManyHeaders {
                        limit: limits.max_headers,
                    });
                }
            }
            field_lines.push(line);
        }
    }
}

fn check_line(raw: &[u8], line: &ScannedLine, anomalies: &mut Vec<Anomaly>) {
    if line.bare_lf {
        let lf = line.line.full.end - 1;
        anomalies.push(Anomaly::new(AnomalyKind::BareLf, Span::new(lf, lf + 1)));
    }
    let content = line.line.content;
    for (i, &b) in content.slice(raw).iter().enumerate() {
        if b == b'\r' {
            let at = content.start + i;
            anomalies.push(Anomaly::new(AnomalyKind::BareCr, Span::new(at, at + 1)));
        }
    }
}

// ---------------------------------------------------------------------------
// Header fields

fn parse_fields(
    raw: &[u8],
    lines: &[ScannedLine],
    anomalies: &mut Vec<Anomaly>,
) -> Vec<HeaderField> {
    let mut fields: Vec<HeaderField> = Vec::with_capacity(lines.len());
    for scanned in lines {
        let line = scanned.line;
        let content = line.content;
        let bytes = content.slice(raw);

        if is_ws(bytes[0]) {
            if let Some(prev) = fields.last_mut() {
                anomalies.push(Anomaly::new(AnomalyKind::ObsFold, line.full));
                let cont = trim(raw, content);
                if !cont.is_empty() {
                    check_value(raw, cont, anomalies);
                    if prev.value.is_empty() {
                        prev.value.start = cont.start;
                    }
                    prev.value.end = cont.end;
                }
                prev.raw.end = line.full.end;
                prev.folded = true;
                continue;
            }
            anomalies.push(Anomaly::new(
                AnomalyKind::WhitespaceBeforeFirstHeader,
                content,
            ));
        }

        let Some(colon) = bytes.iter().position(|&b| b == b':') else {
            anomalies.push(Anomaly::new(AnomalyKind::MissingColon, content));
            fields.push(HeaderField {
                name: content,
                value: Span::empty(content.end),
                raw: line.full,
                folded: false,
            });
            continue;
        };
        let colon = content.start + colon;
        let name = Span::new(content.start, colon);
        check_name(raw, name, anomalies);
        let value = trim(raw, Span::new(colon + 1, content.end));
        check_value(raw, value, anomalies);
        fields.push(HeaderField {
            name,
            value,
            raw: line.full,
            folded: false,
        });
    }
    fields
}

fn check_name(raw: &[u8], name: Span, anomalies: &mut Vec<Anomaly>) {
    if name.is_empty() {
        anomalies.push(Anomaly::new(
            AnomalyKind::EmptyHeaderName,
            Span::new(name.end, name.end + 1),
        ));
        return;
    }
    let bytes = name.slice(raw);
    let trailing_ws = bytes.iter().rev().take_while(|&&b| is_ws(b)).count();
    if trailing_ws > 0 {
        anomalies.push(Anomaly::new(
            AnomalyKind::WhitespaceBeforeColon,
            Span::new(name.end - trailing_ws, name.end),
        ));
    }
    let leading_ws = bytes.iter().take_while(|&&b| is_ws(b)).count();
    let core_end = bytes.len() - trailing_ws;
    if leading_ws < core_end && bytes[leading_ws..core_end].iter().any(|&b| !is_tchar(b)) {
        anomalies.push(Anomaly::new(AnomalyKind::InvalidHeaderName, name));
    }
}

fn check_value(raw: &[u8], value: Span, anomalies: &mut Vec<Anomaly>) {
    // CR is reported as `BareCr` by `check_line`.
    if value
        .slice(raw)
        .iter()
        .any(|&b| (b < 0x20 && b != b'\t' && b != b'\r') || b == 0x7f)
    {
        anomalies.push(Anomaly::new(AnomalyKind::InvalidHeaderValue, value));
    }
}

// ---------------------------------------------------------------------------
// Start lines

/// Splits a start line into whitespace-separated tokens, recording
/// irregular whitespace.
fn tokens(raw: &[u8], content: Span, anomalies: &mut Vec<Anomaly>) -> Vec<Span> {
    let bytes = content.slice(raw);
    let mut toks = Vec::with_capacity(3);
    let mut i = 0;
    while i < bytes.len() {
        if is_ws(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && !is_ws(bytes[i]) {
            i += 1;
        }
        toks.push(Span::new(content.start + start, content.start + i));
    }
    check_separators(raw, content, &toks, anomalies);
    toks
}

fn check_separators(raw: &[u8], content: Span, toks: &[Span], anomalies: &mut Vec<Anomaly>) {
    if content.slice(raw).contains(&b'\t') {
        anomalies.push(Anomaly::new(AnomalyKind::TabInStartLine, content));
    }
    let irregular = match (toks.first(), toks.last()) {
        (Some(first), Some(last)) => {
            first.start != content.start
                || last.end != content.end
                || toks.windows(2).any(|w| w[1].start - w[0].end != 1)
        }
        _ => true,
    };
    if irregular {
        anomalies.push(Anomaly::new(AnomalyKind::IrregularWhitespace, content));
    }
}

fn parse_request_line(
    raw: &[u8],
    line: Line,
    anomalies: &mut Vec<Anomaly>,
) -> (Span, Span, Option<Span>) {
    let content = line.content;
    let toks = tokens(raw, content, anomalies);
    let (method, target, version) = match toks.as_slice() {
        [] => {
            anomalies.push(Anomaly::new(AnomalyKind::MalformedStartLine, content));
            let at = Span::empty(content.start);
            (at, at, None)
        }
        [method] => {
            anomalies.push(Anomaly::new(AnomalyKind::MalformedStartLine, content));
            (*method, Span::empty(method.end), None)
        }
        [method, target] => {
            anomalies.push(Anomaly::new(AnomalyKind::MissingVersion, content));
            (*method, *target, None)
        }
        [method, rest @ .., version] => {
            let target = Span::new(rest[0].start, rest[rest.len() - 1].end);
            if rest.len() > 1 {
                anomalies.push(Anomaly::new(AnomalyKind::WhitespaceInTarget, target));
            }
            (*method, target, Some(*version))
        }
    };
    if method.slice(raw).iter().any(|&b| !is_tchar(b)) {
        anomalies.push(Anomaly::new(AnomalyKind::InvalidMethod, method));
    }
    if target
        .slice(raw)
        .iter()
        .any(|&b| !is_ws(b) && (b <= 0x20 || b >= 0x7f))
    {
        anomalies.push(Anomaly::new(AnomalyKind::InvalidTarget, target));
    }
    if let Some(version) = version {
        check_version(raw, version, anomalies);
    }
    (method, target, version)
}

fn parse_status_line(
    raw: &[u8],
    line: Line,
    anomalies: &mut Vec<Anomaly>,
) -> (Span, Span, Option<u16>, Span) {
    let content = line.content;
    let bytes = content.slice(raw);
    if bytes.contains(&b'\t') {
        anomalies.push(Anomaly::new(AnomalyKind::TabInStartLine, content));
    }
    if is_ws(bytes[0]) {
        anomalies.push(Anomaly::new(AnomalyKind::IrregularWhitespace, content));
    }

    let Some(sp) = bytes.iter().position(|&b| is_ws(b)) else {
        anomalies.push(Anomaly::new(AnomalyKind::MalformedStartLine, content));
        check_version(raw, content, anomalies);
        let end = Span::empty(content.end);
        return (content, end, None, end);
    };
    let version = Span::new(content.start, content.start + sp);

    let mut i = sp;
    while i < bytes.len() && is_ws(bytes[i]) {
        i += 1;
    }
    if i - sp > 1 {
        anomalies.push(Anomaly::new(AnomalyKind::IrregularWhitespace, content));
    }
    let status_start = i;
    while i < bytes.len() && !is_ws(bytes[i]) {
        i += 1;
    }
    let status = Span::new(content.start + status_start, content.start + i);
    let reason = if i < bytes.len() {
        Span::new(content.start + i + 1, content.end)
    } else {
        Span::empty(content.end)
    };

    let code = status.slice(raw);
    let status_code = if code.len() == 3 && code.iter().all(u8::is_ascii_digit) {
        Some(code.iter().fold(0u16, |n, &d| n * 10 + u16::from(d - b'0')))
    } else {
        anomalies.push(Anomaly::new(AnomalyKind::InvalidStatusCode, status));
        None
    };

    check_version(raw, version, anomalies);
    (version, status, status_code, reason)
}

fn check_version(raw: &[u8], version: Span, anomalies: &mut Vec<Anomaly>) {
    match version.slice(raw) {
        b"HTTP/1.1" | b"HTTP/1.0" => {}
        [b'H', b'T', b'T', b'P', b'/', major, b'.', minor]
            if major.is_ascii_digit() && minor.is_ascii_digit() =>
        {
            anomalies.push(Anomaly::new(AnomalyKind::UnsupportedVersion, version));
        }
        _ => anomalies.push(Anomaly::new(AnomalyKind::InvalidVersion, version)),
    }
}

// ---------------------------------------------------------------------------
// Helpers

pub(crate) const fn is_ws(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// `tchar` from RFC 9110 §5.6.2.
pub(crate) const fn is_tchar(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    ) || b.is_ascii_alphanumeric()
}

fn trim(raw: &[u8], span: Span) -> Span {
    let bytes = span.slice(raw);
    let start = bytes.iter().take_while(|&&b| is_ws(b)).count();
    let end = bytes.len()
        - bytes[start..]
            .iter()
            .rev()
            .take_while(|&&b| is_ws(b))
            .count();
    Span::new(span.start + start, span.start + end)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Request line, method, target, version, expected anomalies.
    type RequestLineCase = (
        &'static [u8],
        &'static [u8],
        &'static [u8],
        Option<&'static [u8]>,
        &'static [AnomalyKind],
    );
    /// Status line, version, status code, reason, expected anomalies.
    type StatusLineCase = (
        &'static [u8],
        &'static [u8],
        Option<u16>,
        &'static [u8],
        &'static [AnomalyKind],
    );

    fn req(input: &[u8]) -> RequestHead {
        RequestHead::parse(input, &Limits::DEFAULT)
            .expect("no error")
            .expect("complete head")
    }

    fn kinds(head: &Head) -> Vec<AnomalyKind> {
        head.anomalies().iter().map(|a| a.kind).collect()
    }

    #[test]
    fn well_formed_request_has_no_anomalies() {
        let input = b"GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let head = req(input);
        assert_eq!(head.as_bytes(), input);
        assert_eq!(head.method(), b"GET");
        assert_eq!(head.target(), b"/path?q=1");
        assert_eq!(head.version(), Some(&b"HTTP/1.1"[..]));
        let names: Vec<_> = head.headers().map(|h| h.name()).collect();
        assert_eq!(names, [&b"Host"[..], b"Accept"]);
        assert_eq!(
            head.get("host").map(|h| h.value()),
            Some(&b"example.com"[..])
        );
        assert!(head.anomalies().is_empty(), "{:?}", head.anomalies());
    }

    #[test]
    fn incomplete_head_returns_none() {
        for input in [
            &b""[..],
            b"GET / HTTP/1.1",
            b"GET / HTTP/1.1\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\n\r",
            b"\r\n\r\n",
        ] {
            assert_eq!(
                RequestHead::parse(input, &Limits::DEFAULT),
                Ok(None),
                "{input:?}"
            );
        }
    }

    #[test]
    fn head_length_excludes_body() {
        let head = req(b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcGET");
        assert_eq!(head.len(), 38);
    }

    #[test]
    fn keeps_header_order_case_and_duplicates() {
        let head = req(b"GET / HTTP/1.1\r\nx-B: 1\r\nX-a: 2\r\nx-b: 3\r\n\r\n");
        let all: Vec<_> = head.headers().map(|h| (h.name(), h.value())).collect();
        assert_eq!(
            all,
            [(&b"x-B"[..], &b"1"[..]), (b"X-a", b"2"), (b"x-b", b"3")]
        );
        let dups: Vec<_> = head.get_all("X-B").map(|h| h.value()).collect();
        assert_eq!(dups, [&b"1"[..], b"3"]);
    }

    #[test]
    fn whitespace_before_colon_keeps_name_verbatim() {
        let head = req(b"POST / HTTP/1.1\r\nTransfer-Encoding : chunked\r\n\r\n");
        let h = head.headers().next().unwrap();
        assert_eq!(h.name(), b"Transfer-Encoding ");
        assert_eq!(h.value(), b"chunked");
        assert!(!h.is("transfer-encoding"));
        assert_eq!(kinds(&head), [AnomalyKind::WhitespaceBeforeColon]);
    }

    #[test]
    fn bare_lf_and_mixed_line_endings() {
        let head = req(b"GET / HTTP/1.1\nHost: a\r\n\n");
        assert_eq!(head.get("Host").unwrap().value(), b"a");
        assert_eq!(kinds(&head), [AnomalyKind::BareLf, AnomalyKind::BareLf]);
    }

    #[test]
    fn obs_fold_is_one_field() {
        let input = b"GET / HTTP/1.1\r\nX: a\r\n  b\r\n\tc\r\nY: 1\r\n\r\n";
        let head = req(input);
        let x = head.get("X").unwrap();
        assert_eq!(x.value(), b"a\r\n  b\r\n\tc");
        assert_eq!(&*x.value_unfolded(), b"a b c");
        assert_eq!(x.raw(), b"X: a\r\n  b\r\n\tc\r\n");
        assert_eq!(head.headers().count(), 2);
        assert_eq!(kinds(&head), [AnomalyKind::ObsFold, AnomalyKind::ObsFold]);
    }

    #[test]
    fn malformed_header_lines_are_kept() {
        let head = req(b"GET / HTTP/1.1\r\n Leading: ws\r\nGarbage\r\n: novalue\r\nX{y: z\r\n\r\n");
        let names: Vec<_> = head.headers().map(|h| h.name()).collect();
        assert_eq!(names, [&b" Leading"[..], b"Garbage", b"", b"X{y"]);
        assert_eq!(
            kinds(&head),
            [
                AnomalyKind::WhitespaceBeforeFirstHeader,
                AnomalyKind::MissingColon,
                AnomalyKind::EmptyHeaderName,
                AnomalyKind::InvalidHeaderName,
            ]
        );
    }

    #[test]
    fn control_bytes_in_values() {
        let head = req(b"GET / HTTP/1.1\r\nA: x\x00y\r\nB: x\ry\r\nC: \xff\xfe\r\n\r\n");
        assert_eq!(head.get("A").unwrap().value(), b"x\x00y");
        assert_eq!(head.get("C").unwrap().value(), b"\xff\xfe");
        assert_eq!(
            kinds(&head),
            [AnomalyKind::InvalidHeaderValue, AnomalyKind::BareCr]
        );
    }

    #[test]
    fn request_line_variants() {
        let cases: &[RequestLineCase] = &[
            (b"get / HTTP/1.1", b"get", b"/", Some(b"HTTP/1.1"), &[]),
            (
                b"GET  / HTTP/1.1",
                b"GET",
                b"/",
                Some(b"HTTP/1.1"),
                &[AnomalyKind::IrregularWhitespace],
            ),
            (
                b"GET\t/\tHTTP/1.1",
                b"GET",
                b"/",
                Some(b"HTTP/1.1"),
                &[AnomalyKind::TabInStartLine],
            ),
            (
                b"GET /a b HTTP/1.1",
                b"GET",
                b"/a b",
                Some(b"HTTP/1.1"),
                &[AnomalyKind::WhitespaceInTarget],
            ),
            (b"GET /", b"GET", b"/", None, &[AnomalyKind::MissingVersion]),
            (
                b"GET / HTTP/1.2",
                b"GET",
                b"/",
                Some(b"HTTP/1.2"),
                &[AnomalyKind::UnsupportedVersion],
            ),
            (
                b"GET / FOO",
                b"GET",
                b"/",
                Some(b"FOO"),
                &[AnomalyKind::InvalidVersion],
            ),
            (
                b"G(T / HTTP/1.1",
                b"G(T",
                b"/",
                Some(b"HTTP/1.1"),
                &[AnomalyKind::InvalidMethod],
            ),
            (
                b"GET /\xc3\xa9 HTTP/1.1",
                b"GET",
                b"/\xc3\xa9",
                Some(b"HTTP/1.1"),
                &[AnomalyKind::InvalidTarget],
            ),
            (
                b"GARBAGE",
                b"GARBAGE",
                b"",
                None,
                &[AnomalyKind::MalformedStartLine],
            ),
        ];
        for (line, method, target, version, expected) in cases {
            let mut input = line.to_vec();
            input.extend_from_slice(b"\r\n\r\n");
            let head = req(&input);
            assert_eq!(head.method(), *method, "{line:?}");
            assert_eq!(head.target(), *target, "{line:?}");
            assert_eq!(head.version(), *version, "{line:?}");
            assert_eq!(kinds(&head), *expected, "{line:?}");
        }
    }

    #[test]
    fn leading_empty_lines() {
        let head = req(b"\r\n\nGET / HTTP/1.1\r\n\r\n");
        assert_eq!(head.method(), b"GET");
        assert_eq!(head.leading(), Span::new(0, 3));
        // The leading lines are reported as one anomaly, whatever their endings.
        assert_eq!(kinds(&head), [AnomalyKind::LeadingEmptyLines]);
    }

    #[test]
    fn status_line_variants() {
        let cases: &[StatusLineCase] = &[
            (b"HTTP/1.1 200 OK", b"HTTP/1.1", Some(200), b"OK", &[]),
            (
                b"HTTP/1.1 404 Not Found",
                b"HTTP/1.1",
                Some(404),
                b"Not Found",
                &[],
            ),
            (b"HTTP/1.1 204 ", b"HTTP/1.1", Some(204), b"", &[]),
            (b"HTTP/1.1 204", b"HTTP/1.1", Some(204), b"", &[]),
            (
                b"HTTP/1.1  200 OK",
                b"HTTP/1.1",
                Some(200),
                b"OK",
                &[AnomalyKind::IrregularWhitespace],
            ),
            (
                b"HTTP/1.1 2000 OK",
                b"HTTP/1.1",
                None,
                b"OK",
                &[AnomalyKind::InvalidStatusCode],
            ),
            (
                b"HTTP/1.1",
                b"HTTP/1.1",
                None,
                b"",
                &[AnomalyKind::MalformedStartLine],
            ),
            (
                b"ICY 200 OK",
                b"ICY",
                Some(200),
                b"OK",
                &[AnomalyKind::InvalidVersion],
            ),
        ];
        for (line, version, code, reason, expected) in cases {
            let mut input = line.to_vec();
            input.extend_from_slice(b"\r\n\r\n");
            let head = ResponseHead::parse(&input, &Limits::DEFAULT)
                .unwrap()
                .unwrap();
            assert_eq!(head.version(), *version, "{line:?}");
            assert_eq!(head.status_code(), *code, "{line:?}");
            assert_eq!(head.reason(), *reason, "{line:?}");
            assert_eq!(kinds(&head), *expected, "{line:?}");
        }
    }

    #[test]
    fn limits_are_enforced() {
        let limits = Limits {
            max_head_len: 32,
            max_headers: 2,
            ..Limits::DEFAULT
        };
        assert_eq!(
            RequestHead::parse(&[b'A'; 33], &limits),
            Err(Error::HeadTooLarge { limit: 32 })
        );
        assert_eq!(
            RequestHead::parse(
                b"GET / HTTP/1.1\r\nHost: aaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n",
                &limits
            ),
            Err(Error::HeadTooLarge { limit: 32 })
        );
        assert_eq!(
            RequestHead::parse(b"GET / HTTP/1.1\r\nA:\r\nB:\r\nC:\r\n\r\n", &limits),
            Err(Error::TooManyHeaders { limit: 2 })
        );
        assert!(
            RequestHead::parse(b"GET / HTTP/1.1\r\nA:\r\nB:\r\n x\r\n\r\n", &limits)
                .unwrap()
                .is_some(),
            "continuation lines do not count as fields"
        );
    }
}
