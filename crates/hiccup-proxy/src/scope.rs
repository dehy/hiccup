// SPDX-License-Identifier: AGPL-3.0-or-later

//! Target scope: which URLs the user is testing.

use crate::HostPattern;

/// `http` or `https`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// Plain HTTP.
    Http,
    /// HTTP over TLS.
    Https,
}

/// One include or exclude rule. Every criterion set must match.
#[derive(Clone, Debug)]
pub struct ScopeRule {
    /// Excludes what it matches, instead of including it.
    pub exclude: bool,
    /// The scheme; `None` matches both.
    pub scheme: Option<Scheme>,
    /// The host.
    pub host: HostPattern,
    /// The port; `None` matches any.
    pub port: Option<u16>,
    /// Matched against the path and query (`/a?b`).
    pub path: Option<regex::Regex>,
}

/// A URL, as scope rules see it.
#[derive(Clone, Copy, Debug)]
pub struct ScopeTarget<'a> {
    /// The scheme.
    pub scheme: Scheme,
    /// The host.
    pub host: &'a str,
    /// The port.
    pub port: u16,
    /// The path and query, or a whole absolute-form target (its path is
    /// then what rules match).
    pub path: &'a str,
}

impl ScopeRule {
    fn matches(&self, target: &ScopeTarget<'_>) -> bool {
        self.scheme.is_none_or(|s| s == target.scheme)
            && self.host.matches(target.host)
            && self.port.is_none_or(|p| p == target.port)
            && self
                .path
                .as_ref()
                .is_none_or(|re| re.is_match(origin_form(target.path)))
    }
}

/// The scope: in it is what matches an include rule and no exclude rule.
/// With no include rule, everything not excluded is in scope.
#[derive(Clone, Debug, Default)]
pub struct Scope {
    /// The rules, in the order they were added.
    pub rules: Vec<ScopeRule>,
}

impl Scope {
    /// Whether `target` is in scope.
    #[must_use]
    pub fn contains(&self, target: &ScopeTarget<'_>) -> bool {
        let (mut includes, mut included) = (false, false);
        for rule in &self.rules {
            let matches = rule.matches(target);
            if rule.exclude {
                if matches {
                    return false;
                }
            } else {
                includes = true;
                included |= matches;
            }
        }
        included || !includes
    }
}

/// The path and query of `target`, which may be in absolute-form.
fn origin_form(target: &str) -> &str {
    if target.starts_with('/') {
        return target;
    }
    let Some(sep) = target.find("://") else {
        return target;
    };
    let rest = &target[sep + 3..];
    rest.find('/').map_or("/", |i| &rest[i..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(exclude: bool, host: &str, path: Option<&str>) -> ScopeRule {
        ScopeRule {
            exclude,
            scheme: None,
            host: host.parse().unwrap(),
            port: None,
            path: path.map(|p| regex::Regex::new(p).unwrap()),
        }
    }

    fn url(
        scheme: Scheme,
        host: &'static str,
        port: u16,
        path: &'static str,
    ) -> ScopeTarget<'static> {
        ScopeTarget {
            scheme,
            host,
            port,
            path,
        }
    }

    #[test]
    fn include_then_exclude() {
        let https = |host, path| url(Scheme::Https, host, 443, path);
        assert!(
            Scope::default().contains(&https("any.test", "/")),
            "empty: all in scope"
        );

        let mut scope = Scope {
            rules: vec![
                rule(false, "*.example.com", None),
                rule(true, "*", Some("^/logout")),
            ],
        };
        assert!(scope.contains(&https("app.example.com", "/a")));
        assert!(
            !scope.contains(&https("example.com", "/a")),
            "subdomains only"
        );
        assert!(
            !scope.contains(&https("app.example.com", "/logout?x")),
            "excluded"
        );
        assert!(!scope.contains(&https("other.test", "/a")), "not included");
        // An absolute-form target: its path is what rules see.
        assert!(!scope.contains(&https("app.example.com", "https://app.example.com/logout")));

        scope.rules = vec![ScopeRule {
            scheme: Some(Scheme::Https),
            port: Some(8443),
            ..rule(false, "a.test", None)
        }];
        assert!(scope.contains(&url(Scheme::Https, "A.test", 8443, "/")));
        assert!(!scope.contains(&url(Scheme::Http, "a.test", 8443, "/")));
        assert!(!scope.contains(&url(Scheme::Https, "a.test", 443, "/")));

        scope.rules = vec![rule(true, "ads.test", None)];
        assert!(
            scope.contains(&https("a.test", "/")),
            "only excludes: the rest is in"
        );
        assert!(!scope.contains(&https("ads.test", "/")));
    }

    #[test]
    fn origin_form_of_targets() {
        assert_eq!(origin_form("/a?b"), "/a?b");
        assert_eq!(origin_form("http://h:1/a?b"), "/a?b");
        assert_eq!(origin_form("http://h"), "/");
        assert_eq!(origin_form("h:443"), "h:443");
    }
}
