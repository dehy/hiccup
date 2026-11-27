// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS interception: leaf certificates for clients, and TLS to upstreams.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};

use crate::CertificateAuthority;
use crate::ca::CaError;

/// Leaf certificates kept in memory.
const CACHE_CAPACITY: usize = 1000;

/// HTTP/2 is not supported yet: both sides negotiate HTTP/1.1.
const ALPN: &[u8] = b"http/1.1";

/// Everything needed to intercept TLS, shared by all connections.
pub(crate) struct Interceptor {
    ca: Arc<CertificateAuthority>,
    /// One key for every leaf certificate: generating a key per host would
    /// only slow down the first connection to each host.
    leaf_key: KeyPair,
    provider: Arc<CryptoProvider>,
    cache: Mutex<Cache>,
    client: Arc<ClientConfig>,
}

impl Interceptor {
    pub(crate) fn new(ca: Arc<CertificateAuthority>) -> Result<Self, CaError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(tls_setup)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider.clone())))
            .with_no_client_auth();
        client.alpn_protocols = vec![ALPN.to_vec()];
        Ok(Self {
            ca,
            leaf_key: KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?,
            provider,
            cache: Mutex::new(Cache::default()),
            client: Arc::new(client),
        })
    }

    /// The configuration for connections to upstream servers.
    pub(crate) fn client_config(&self) -> Arc<ClientConfig> {
        self.client.clone()
    }

    /// A server configuration presenting a certificate for `host`, signed by
    /// the CA. Cached per host.
    pub(crate) fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, CaError> {
        let host = host.to_ascii_lowercase();
        if let Some(config) = self.cache.lock().expect("not poisoned").get(&host) {
            return Ok(config);
        }
        let leaf = self.ca.sign_leaf(&host, &self.leaf_key)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()));
        let mut config = ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(tls_setup)?
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(leaf)], key)
            .map_err(tls_setup)?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        let config = Arc::new(config);
        self.cache
            .lock()
            .expect("not poisoned")
            .insert(host, config.clone());
        Ok(config)
    }
}

fn tls_setup(e: rustls::Error) -> CaError {
    CaError::Tls(e.to_string())
}

/// A least-recently-used cache. Eviction scans all entries, which is cheap
/// at this size and only happens when a new host is seen.
#[derive(Default)]
struct Cache {
    entries: HashMap<String, (Arc<ServerConfig>, u64)>,
    clock: u64,
}

impl Cache {
    fn get(&mut self, host: &str) -> Option<Arc<ServerConfig>> {
        self.clock += 1;
        let (config, used) = self.entries.get_mut(host)?;
        *used = self.clock;
        Some(config.clone())
    }

    fn insert(&mut self, host: String, config: Arc<ServerConfig>) {
        if self.entries.len() >= CACHE_CAPACITY && !self.entries.contains_key(&host) {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(host, _)| host.clone());
            if let Some(oldest) = oldest {
                self.entries.remove(&oldest);
            }
        }
        self.clock += 1;
        self.entries.insert(host, (config, self.clock));
    }
}

/// Accepts any upstream certificate, as testing targets often use
/// self-signed or invalid ones. Handshake signatures are still checked, so
/// the server must hold the key of the certificate it presents.
#[derive(Debug)]
struct AcceptAnyServerCert(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_evicts_the_least_recently_used() {
        let ca = Arc::new(CertificateAuthority::generate().unwrap());
        let interceptor = Interceptor::new(ca).unwrap();
        let config = interceptor.server_config("a.test").unwrap();
        // Case-insensitive, and served from the cache.
        assert!(Arc::ptr_eq(
            &config,
            &interceptor.server_config("A.test").unwrap()
        ));

        let mut cache = Cache::default();
        for i in 0..CACHE_CAPACITY {
            cache.insert(format!("h{i}"), config.clone());
        }
        assert!(cache.get("h0").is_some()); // h1 is now the oldest.
        cache.insert("new".into(), config.clone());
        assert_eq!(cache.entries.len(), CACHE_CAPACITY);
        assert!(cache.get("h1").is_none());
        assert!(cache.get("h0").is_some());
        assert!(cache.get("new").is_some());
    }
}
