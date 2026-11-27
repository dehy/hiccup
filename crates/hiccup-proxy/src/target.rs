// SPDX-License-Identifier: AGPL-3.0-or-later

//! Request targets: authorities, absolute-form URIs and the origin-form
//! rewrite (RFC 9112 §3.2).

use std::fmt;

/// A `host:port` pair. IPv6 literals are stored without brackets.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Authority {
    /// Host name or IP literal.
    pub host: String,
    /// TCP port.
    pub port: u16,
}

impl Authority {
    /// Parses `host[:port]`, `[v6]` or `[v6]:port`. Without a port,
    /// `default_port` is used; `None` makes the port mandatory (as in
    /// `CONNECT`).
    #[must_use]
    pub fn parse(bytes: &[u8], default_port: Option<u16>) -> Option<Self> {
        let s = std::str::from_utf8(bytes).ok()?;
        let (host, port) = if let Some(rest) = s.strip_prefix('[') {
            let (host, after) = rest.split_once(']')?;
            let port = match after {
                "" => None,
                p => Some(p.strip_prefix(':')?),
            };
            (host, port)
        } else {
            match s.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (s, None),
            }
        };
        let port = match port {
            Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => p.parse().ok()?,
            Some(_) => return None,
            None => default_port?,
        };
        let valid_host = !host.is_empty()
            && host.bytes().all(|b| {
                b.is_ascii_graphic() && !matches!(b, b'/' | b'@' | b'?' | b'#' | b'[' | b']')
            });
        valid_host.then(|| Self {
            host: host.to_owned(),
            port,
        })
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// An absolute-form request target split for forwarding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbsoluteTarget {
    /// Where to connect.
    pub authority: Authority,
    /// The equivalent origin-form target (`/path?query`).
    pub origin_form: Vec<u8>,
}

/// Why a request target cannot be forwarded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetError {
    /// The target is in origin-form (`/path`): the client is not talking to
    /// a proxy. Invisible proxying is not supported yet.
    OriginForm,
    /// The scheme is not `http`.
    UnsupportedScheme(String),
    /// The target cannot be parsed.
    Invalid,
}

impl AbsoluteTarget {
    /// Parses an `http://` absolute-form target.
    ///
    /// # Errors
    ///
    /// See [`TargetError`].
    pub fn parse(target: &[u8]) -> Result<Self, TargetError> {
        if target.first() == Some(&b'/') {
            return Err(TargetError::OriginForm);
        }
        let sep = find(target, b"://").ok_or(TargetError::Invalid)?;
        let scheme = &target[..sep];
        if !scheme.eq_ignore_ascii_case(b"http") {
            return Err(TargetError::UnsupportedScheme(
                String::from_utf8_lossy(scheme).into_owned(),
            ));
        }
        let rest = &target[sep + 3..];
        let auth_end = rest
            .iter()
            .position(|&b| matches!(b, b'/' | b'?' | b'#'))
            .unwrap_or(rest.len());
        let mut authority = &rest[..auth_end];
        // Userinfo (`user@host`) is deprecated (RFC 9110 §4.2.4); skip it.
        if let Some(at) = authority.iter().rposition(|&b| b == b'@') {
            authority = &authority[at + 1..];
        }
        let authority = Authority::parse(authority, Some(80)).ok_or(TargetError::Invalid)?;

        let path = &rest[auth_end..];
        let path = path.split(|&b| b == b'#').next().unwrap_or_default();
        let origin_form = match path.first() {
            Some(b'/') => path.to_vec(),
            _ => [b"/".as_slice(), path].concat(),
        };
        Ok(Self {
            authority,
            origin_form,
        })
    }
}

/// A host name pattern: `*` (any host), `*.example.com` (any subdomain of
/// `example.com`, not `example.com` itself) or an exact host. Matching is
/// case-insensitive; IPv6 literals may be bracketed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostPattern {
    /// Matches every host.
    Any,
    /// Matches hosts ending with `.suffix`. Stored lowercase.
    Subdomains(String),
    /// Matches this host only. Stored lowercase, without brackets.
    Exact(String),
}

impl HostPattern {
    /// Whether `host` matches.
    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        let host = host.trim_matches(|c| c == '[' || c == ']');
        match self {
            Self::Any => true,
            Self::Exact(h) => host.eq_ignore_ascii_case(h),
            Self::Subdomains(suffix) => {
                host.len() > suffix.len() + 1 && {
                    let (sub, rest) = host.split_at(host.len() - suffix.len());
                    sub.ends_with('.') && rest.eq_ignore_ascii_case(suffix)
                }
            }
        }
    }
}

impl std::str::FromStr for HostPattern {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim().to_ascii_lowercase();
        if s == "*" {
            return Ok(Self::Any);
        }
        let (pattern, host) = match s.strip_prefix("*.") {
            Some(suffix) => (Self::Subdomains(suffix.to_owned()), suffix),
            None => {
                let host = s.trim_start_matches('[').trim_end_matches(']');
                (Self::Exact(host.to_owned()), host)
            }
        };
        let valid = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'));
        if valid {
            Ok(pattern)
        } else {
            Err(format!(
                "invalid host pattern {s:?}: expected `*`, `*.example.com` or a host name"
            ))
        }
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("*"),
            Self::Subdomains(s) => write!(f, "*.{s}"),
            Self::Exact(h) => f.write_str(h),
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(host: &str, port: u16) -> Authority {
        Authority {
            host: host.into(),
            port,
        }
    }

    #[test]
    fn authorities() {
        assert_eq!(
            Authority::parse(b"example.com:443", None),
            Some(auth("example.com", 443))
        );
        assert_eq!(
            Authority::parse(b"example.com", Some(80)),
            Some(auth("example.com", 80))
        );
        assert_eq!(Authority::parse(b"example.com", None), None);
        assert_eq!(
            Authority::parse(b"[::1]:8443", None),
            Some(auth("::1", 8443))
        );
        assert_eq!(Authority::parse(b"[::1]", Some(80)), Some(auth("::1", 80)));
        assert_eq!(
            Authority::parse(b"10.0.0.1:1", None),
            Some(auth("10.0.0.1", 1))
        );
        for bad in [
            &b""[..],
            b":80",
            b"host:",
            b"host:99999",
            b"host:8x",
            b"a b:80",
            b"[::1:80",
        ] {
            assert_eq!(Authority::parse(bad, Some(80)), None, "{bad:?}");
        }
        assert_eq!(auth("::1", 443).to_string(), "[::1]:443");
        assert_eq!(auth("a", 1).to_string(), "a:1");
    }

    #[test]
    fn host_patterns() {
        let p = |s: &str| s.parse::<HostPattern>().unwrap();
        assert!(p("*").matches("anything.test"));
        assert!(p("example.com").matches("EXAMPLE.com"));
        assert!(!p("example.com").matches("www.example.com"));
        assert!(p("*.Example.com").matches("www.example.com"));
        assert!(p("*.example.com").matches("a.b.example.com"));
        assert!(!p("*.example.com").matches("example.com"));
        assert!(!p("*.example.com").matches("badexample.com"));
        assert!(p("[::1]").matches("::1"));
        assert!(p("::1").matches("[::1]"));
        for bad in ["", "*.", "a b", "*example.com", "a/b"] {
            assert!(bad.parse::<HostPattern>().is_err(), "{bad:?}");
        }
        assert_eq!(p("*.EXAMPLE.com").to_string(), "*.example.com");
    }

    #[test]
    fn absolute_targets() {
        let cases: &[(&[u8], &str, u16, &[u8])] = &[
            (b"http://example.com/a?b=1", "example.com", 80, b"/a?b=1"),
            (b"HTTP://example.com:8080", "example.com", 8080, b"/"),
            (b"http://example.com?q", "example.com", 80, b"/?q"),
            (b"http://user:pw@example.com/x", "example.com", 80, b"/x"),
            (b"http://example.com/x#frag", "example.com", 80, b"/x"),
            (b"http://[::1]:81/", "::1", 81, b"/"),
        ];
        for (target, host, port, origin) in cases {
            let t = AbsoluteTarget::parse(target).unwrap();
            assert_eq!(t.authority, auth(host, *port), "{target:?}");
            assert_eq!(t.origin_form, *origin, "{target:?}");
        }
        assert_eq!(
            AbsoluteTarget::parse(b"/path"),
            Err(TargetError::OriginForm)
        );
        assert_eq!(
            AbsoluteTarget::parse(b"https://example.com/"),
            Err(TargetError::UnsupportedScheme("https".into()))
        );
        assert_eq!(AbsoluteTarget::parse(b"*"), Err(TargetError::Invalid));
        assert_eq!(
            AbsoluteTarget::parse(b"http:///x"),
            Err(TargetError::Invalid)
        );
    }
}
