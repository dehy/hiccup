// SPDX-License-Identifier: AGPL-3.0-or-later

//! How Hiccup connects to upstream servers.

use std::fmt;
use std::net::IpAddr;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::HostPattern;

/// Options for connections to upstream servers. Per-host rules match the
/// target host (the `CONNECT` or absolute-form host); the first matching
/// rule applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamConfig {
    /// Verify server certificates against the OS trust store. On by
    /// default; turn it off to test targets with self-signed or invalid
    /// certificates.
    pub verify: bool,
    /// Lowest TLS version offered to servers.
    pub tls_min: TlsVersion,
    /// Highest TLS version offered to servers.
    pub tls_max: TlsVersion,
    /// Server names to send as SNI (and to verify against) instead of the
    /// client's.
    pub sni: Vec<(HostPattern, String)>,
    /// Addresses to connect to instead of resolving the host name.
    pub resolve: Vec<(HostPattern, IpAddr)>,
    /// Certificates to present when a server asks for one.
    pub client_certs: Vec<(HostPattern, ClientCert)>,
}

impl Default for UpstreamConfig {
    /// Verification on, TLS 1.2 to 1.3, no per-host rules.
    fn default() -> Self {
        Self {
            verify: true,
            tls_min: TlsVersion::Tls12,
            tls_max: TlsVersion::Tls13,
            sni: Vec::new(),
            resolve: Vec::new(),
            client_certs: Vec::new(),
        }
    }
}

impl UpstreamConfig {
    /// The SNI override for `host`, if any.
    #[must_use]
    pub fn sni_for(&self, host: &str) -> Option<&str> {
        first_match(&self.sni, host).map(String::as_str)
    }

    /// The address override for `host`, if any.
    #[must_use]
    pub fn resolve_for(&self, host: &str) -> Option<IpAddr> {
        first_match(&self.resolve, host).copied()
    }
}

pub(crate) fn first_match<'a, T>(rules: &'a [(HostPattern, T)], host: &str) -> Option<&'a T> {
    rules
        .iter()
        .find(|(pattern, _)| pattern.matches(host))
        .map(|(_, value)| value)
}

/// A TLS protocol version. Only the versions rustls implements are
/// available; servers limited to TLS 1.0 or 1.1 cannot be reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    /// TLS 1.2.
    Tls12,
    /// TLS 1.3.
    Tls13,
}

impl TlsVersion {
    pub(crate) fn rustls(self) -> &'static rustls::SupportedProtocolVersion {
        match self {
            Self::Tls12 => &rustls::version::TLS12,
            Self::Tls13 => &rustls::version::TLS13,
        }
    }
}

impl std::str::FromStr for TlsVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "1.2" => Ok(Self::Tls12),
            "1.3" => Ok(Self::Tls13),
            "1.0" | "1.1" => Err(format!(
                "TLS {s} is not supported (Hiccup's TLS library implements 1.2 and 1.3)"
            )),
            _ => Err(format!("invalid TLS version {s:?}: expected 1.2 or 1.3")),
        }
    }
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tls12 => "1.2",
            Self::Tls13 => "1.3",
        })
    }
}

/// A client certificate chain and its private key.
pub struct ClientCert {
    pub(crate) chain: Vec<CertificateDer<'static>>,
    pub(crate) key: PrivateKeyDer<'static>,
}

impl ClientCert {
    /// Parses a PEM certificate chain (leaf first) and a PEM private key
    /// (PKCS#8, PKCS#1 or SEC1).
    ///
    /// # Errors
    ///
    /// Fails if either has no valid PEM block of the right kind.
    pub fn from_pem(chain: &[u8], key: &[u8]) -> Result<Self, String> {
        let chain = CertificateDer::pem_slice_iter(chain)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("invalid certificate: {e}"))?;
        if chain.is_empty() {
            return Err("no certificate found".to_owned());
        }
        let key =
            PrivateKeyDer::from_pem_slice(key).map_err(|e| format!("invalid private key: {e}"))?;
        Ok(Self { chain, key })
    }
}

impl Clone for ClientCert {
    fn clone(&self) -> Self {
        Self {
            chain: self.chain.clone(),
            key: self.key.clone_key(),
        }
    }
}

impl PartialEq for ClientCert {
    fn eq(&self, other: &Self) -> bool {
        self.chain == other.chain && self.key.secret_der() == other.key.secret_der()
    }
}

impl Eq for ClientCert {}

impl fmt::Debug for ClientCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the key.
        f.debug_struct("ClientCert")
            .field("chain_len", &self.chain.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!("1.3".parse(), Ok(TlsVersion::Tls13));
        assert!(
            "1.1"
                .parse::<TlsVersion>()
                .unwrap_err()
                .contains("not supported")
        );
        assert!("tls1.2".parse::<TlsVersion>().is_err());
        assert!(TlsVersion::Tls12 < TlsVersion::Tls13);
    }

    #[test]
    fn first_rule_wins() {
        let config = UpstreamConfig {
            sni: vec![
                ("a.example.com".parse().unwrap(), "first".into()),
                ("*.example.com".parse().unwrap(), "second".into()),
            ],
            ..UpstreamConfig::default()
        };
        assert_eq!(config.sni_for("a.example.com"), Some("first"));
        assert_eq!(config.sni_for("b.example.com"), Some("second"));
        assert_eq!(config.sni_for("example.com"), None);
    }

    #[test]
    fn client_cert_pem() {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["client".into()]).unwrap();
        let parsed = ClientCert::from_pem(
            cert.pem().as_bytes(),
            signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        assert_eq!(parsed.chain.len(), 1);
        assert!(!format!("{parsed:?}").contains("PRIVATE"));
        assert!(ClientCert::from_pem(b"", signing_key.serialize_pem().as_bytes()).is_err());
        assert!(ClientCert::from_pem(cert.pem().as_bytes(), b"nope").is_err());
    }
}
