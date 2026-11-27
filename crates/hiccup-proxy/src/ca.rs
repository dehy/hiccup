// SPDX-License-Identifier: AGPL-3.0-or-later

//! The local certificate authority used to intercept TLS.
//!
//! Each installation generates its own root CA (ECDSA P-256) on first use. The
//! user installs the certificate in their browser or OS trust store; Hiccup
//! then signs a leaf certificate per intercepted host with the private key.
//!
//! Anyone holding the private key can impersonate any site to a machine that
//! trusts the certificate, so the key file is created readable by its owner
//! only:
//!
//! - Unix: the key file has mode `0600`, and directories created for it `0700`.
//! - Windows: files inherit the ACL of their directory. The per-user data
//!   directory (`%APPDATA%`) grants access to the user, `SYSTEM` and
//!   administrators only. A data directory chosen elsewhere must be protected
//!   the same way.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType, SerialNumber,
};
use ring::rand::{SecureRandom, SystemRandom};
use time::{Duration, OffsetDateTime};

/// File name of the CA certificate (PEM) inside the data directory.
pub const CERT_FILE: &str = "ca-cert.pem";
/// File name of the CA private key (PKCS#8 PEM) inside the data directory.
pub const KEY_FILE: &str = "ca-key.pem";

/// How long a generated CA is valid.
const VALIDITY: Duration = Duration::days(3650);
/// Backdating of `notBefore`, to tolerate clients with a slow clock.
const BACKDATE: Duration = Duration::days(1);
/// How long a leaf certificate is valid. Apple platforms reject server
/// certificates valid for more than 825 days, even from a local CA.
const LEAF_VALIDITY: Duration = Duration::days(365);

/// Why the CA cannot be loaded, generated or saved.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CaError {
    /// A file could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The file or directory involved.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// Only one of the certificate and the key exists.
    #[error("incomplete CA: {missing} is missing")]
    Incomplete {
        /// The file that does not exist.
        missing: PathBuf,
    },
    /// The certificate or the key cannot be parsed.
    #[error("{path}: invalid {what}")]
    Invalid {
        /// The file involved.
        path: PathBuf,
        /// `"certificate"` or `"private key"`.
        what: &'static str,
    },
    /// The certificate was not issued for the private key.
    #[error("{cert} does not match the private key in {key}")]
    KeyMismatch {
        /// The certificate file.
        cert: PathBuf,
        /// The key file.
        key: PathBuf,
    },
    /// Certificate generation failed.
    #[error("cannot generate the CA: {0}")]
    Generate(#[from] rcgen::Error),
    /// The TLS configuration for a certificate cannot be built.
    #[error("cannot set up TLS: {0}")]
    Tls(String),
}

/// Information about a CA certificate, for display.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaInfo {
    /// The subject distinguished name, e.g. `CN=Hiccup CA, O=Hiccup`.
    pub subject: String,
    /// Start of validity.
    pub not_before: OffsetDateTime,
    /// End of validity.
    pub not_after: OffsetDateTime,
    /// SHA-256 of the DER certificate, as shown by browsers and trust stores.
    pub sha256: [u8; 32],
}

/// A root CA: its certificate and signing key.
pub struct CertificateAuthority {
    cert_pem: String,
    cert_der: Vec<u8>,
    key_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl std::fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the private key.
        f.debug_struct("CertificateAuthority")
            .field("cert_pem", &self.cert_pem)
            .finish_non_exhaustive()
    }
}

impl CertificateAuthority {
    /// Generates a new CA in memory.
    ///
    /// # Errors
    ///
    /// Fails only if the platform cannot provide randomness or sign.
    pub fn generate() -> Result<Self, CaError> {
        let now = OffsetDateTime::now_utc();
        let serial = random_serial()?;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Hiccup CA");
        dn.push(DnType::OrganizationName, "Hiccup");
        dn.push(
            DnType::OrganizationalUnitName,
            format!(
                "Local interception CA, generated {}",
                now.date() // YYYY-MM-DD: tells installations apart.
            ),
        );
        let mut params = CertificateParams::default();
        params.distinguished_name = dn;
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        params.not_before = now - BACKDATE;
        params.not_after = now + VALIDITY;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let cert = params.self_signed(&key)?;
        Ok(Self {
            cert_pem: cert.pem(),
            cert_der: cert.der().to_vec(),
            key_pem: key.serialize_pem(),
            issuer: Issuer::new(params, key),
        })
    }

    /// Loads the CA saved in `dir`, or returns `None` if there is none.
    ///
    /// # Errors
    ///
    /// Fails if only one of the two files exists, if a file cannot be read
    /// or parsed, or if the certificate does not match the key.
    pub fn load(dir: &Path) -> Result<Option<Self>, CaError> {
        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);
        let cert_pem = read_optional(&cert_path)?;
        let key_pem = read_optional(&key_path)?;
        let (cert_pem, key_pem) = match (cert_pem, key_pem) {
            (None, None) => return Ok(None),
            (Some(c), Some(k)) => (c, k),
            (None, Some(_)) => return Err(CaError::Incomplete { missing: cert_path }),
            (Some(_), None) => return Err(CaError::Incomplete { missing: key_path }),
        };

        let invalid_cert = || CaError::Invalid {
            path: cert_path.clone(),
            what: "certificate",
        };
        let key = KeyPair::from_pem(&key_pem).map_err(|_| CaError::Invalid {
            path: key_path.clone(),
            what: "private key",
        })?;
        let cert_der = pem_der(&cert_pem).ok_or_else(invalid_cert)?;
        let (_, x509) =
            x509_parser::parse_x509_certificate(&cert_der).map_err(|_| invalid_cert())?;
        if x509.public_key().subject_public_key.data.as_ref() != key.public_key_raw() {
            return Err(CaError::KeyMismatch {
                cert: cert_path,
                key: key_path,
            });
        }
        let issuer = Issuer::from_ca_cert_der(&cert_der.as_slice().into(), key)
            .map_err(|_| invalid_cert())?;
        Ok(Some(Self {
            cert_pem,
            cert_der,
            key_pem,
            issuer,
        }))
    }

    /// Loads the CA saved in `dir`, generating and saving one if there is
    /// none. The flag is `true` when a CA was generated.
    ///
    /// # Errors
    ///
    /// See [`load`](Self::load) and [`save`](Self::save).
    pub fn load_or_generate(dir: &Path) -> Result<(Self, bool), CaError> {
        // Instances share `dir`: two generating at once could leave one CA's
        // key next to the other's certificate. Released when dropped.
        let io_err = |path: PathBuf| move |source| CaError::Io { path, source };
        create_private_dir(dir).map_err(io_err(dir.to_owned()))?;
        let lock_path = dir.join("ca.lock");
        let lock = fs::File::create(&lock_path).map_err(io_err(lock_path.clone()))?;
        lock.lock().map_err(io_err(lock_path))?;
        if let Some(ca) = Self::load(dir)? {
            return Ok((ca, false));
        }
        let ca = Self::generate()?;
        ca.save(dir)?;
        Ok((ca, true))
    }

    /// Saves the CA in `dir`, replacing any CA already there. `dir` is
    /// created if needed.
    ///
    /// Each file is written to a temporary name and renamed into place, so a
    /// crash leaves the previous file intact.
    ///
    /// # Errors
    ///
    /// Fails if `dir` or a file cannot be written.
    pub fn save(&self, dir: &Path) -> Result<(), CaError> {
        create_private_dir(dir).map_err(|source| CaError::Io {
            path: dir.to_owned(),
            source,
        })?;
        write_atomically(&dir.join(KEY_FILE), self.key_pem.as_bytes(), true)?;
        write_atomically(&dir.join(CERT_FILE), self.cert_pem.as_bytes(), false)
    }

    /// Signs a server certificate for `host` (a DNS name or an IP literal)
    /// with the public key of `key`. Returns it in DER format.
    pub(crate) fn sign_leaf(&self, host: &str, key: &KeyPair) -> Result<Vec<u8>, rcgen::Error> {
        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, host);
        params.subject_alt_names = vec![match host.parse() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(host.try_into()?),
        }];
        params.serial_number = Some(SerialNumber::from_slice(&random_serial()?));
        params.not_before = now - BACKDATE;
        params.not_after = now + LEAF_VALIDITY;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        Ok(params.signed_by(key, &self.issuer)?.der().to_vec())
    }

    /// The certificate in PEM format.
    #[must_use]
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The certificate in DER format.
    #[must_use]
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// Subject, validity and fingerprint of the certificate.
    #[must_use]
    pub fn info(&self) -> CaInfo {
        let (_, x509) = x509_parser::parse_x509_certificate(&self.cert_der)
            .expect("the certificate was parsed or generated by this type");
        let digest = ring::digest::digest(&ring::digest::SHA256, &self.cert_der);
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(digest.as_ref());
        CaInfo {
            subject: x509.subject().to_string(),
            not_before: x509.validity().not_before.to_datetime(),
            not_after: x509.validity().not_after.to_datetime(),
            sha256,
        }
    }
}

/// A random positive 127-bit serial number (RFC 5280 §4.1.2.2).
fn random_serial() -> Result<[u8; 16], rcgen::Error> {
    let mut serial = [0u8; 16];
    SystemRandom::new()
        .fill(&mut serial)
        .map_err(|_| rcgen::Error::RingUnspecified)?;
    serial[0] &= 0x7f;
    Ok(serial)
}

fn read_optional(path: &Path) -> Result<Option<String>, CaError> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(CaError::Io {
            path: path.to_owned(),
            source,
        }),
    }
}

/// Decodes the first `CERTIFICATE` block of a PEM document.
fn pem_der(pem: &str) -> Option<Vec<u8>> {
    let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).ok()?;
    (block.label == "CERTIFICATE").then_some(block.contents)
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

fn write_atomically(path: &Path, contents: &[u8], private: bool) -> Result<(), CaError> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let io_err = |path: &Path| {
        let path = path.to_owned();
        move |source| CaError::Io { path, source }
    };

    // A leftover from a crash may have other permissions: start afresh.
    match fs::remove_file(&tmp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(io_err(&tmp)(e)),
        _ => {}
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, if private { 0o600 } else { 0o644 });
    #[cfg(not(unix))]
    let _ = private; // The directory ACL applies (see the module docs).
    let mut file = options.open(&tmp).map_err(io_err(&tmp))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(io_err(&tmp))?;
    drop(file);
    fs::rename(&tmp, path).map_err(io_err(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ca_is_a_ca() {
        let ca = CertificateAuthority::generate().unwrap();
        let (_, x509) = x509_parser::parse_x509_certificate(ca.cert_der()).unwrap();
        let bc = x509.basic_constraints().unwrap().unwrap().value;
        assert!(bc.ca);
        assert_eq!(bc.path_len_constraint, Some(0));
        let ku = x509.key_usage().unwrap().unwrap().value;
        assert!(ku.key_cert_sign());
        assert!(x509.validity().is_valid());
        assert!(ca.info().subject.contains("CN=Hiccup CA"));
        assert_eq!(pem_der(ca.cert_pem()).unwrap(), ca.cert_der());
    }

    #[test]
    fn a_reloaded_ca_signs_valid_leaves() {
        let dir = tempfile::tempdir().unwrap();
        CertificateAuthority::generate()
            .unwrap()
            .save(dir.path())
            .unwrap();
        let ca = CertificateAuthority::load(dir.path()).unwrap().unwrap();

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let (_, root) = x509_parser::parse_x509_certificate(ca.cert_der()).unwrap();
        for (host, san) in [
            ("example.com", "DNSName(\"example.com\")"),
            ("127.0.0.1", "IPAddress([127, 0, 0, 1])"),
            (
                "::1",
                "IPAddress([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])",
            ),
        ] {
            let der = ca.sign_leaf(host, &leaf_key).unwrap();
            let (_, leaf) = x509_parser::parse_x509_certificate(&der).unwrap();
            assert_eq!(leaf.issuer(), root.subject());
            leaf.verify_signature(Some(root.public_key())).unwrap();
            let sans = leaf.subject_alternative_name().unwrap().unwrap();
            assert_eq!(
                format!("{:?}", sans.value.general_names),
                format!("[{san}]")
            );
            assert!(!leaf.is_ca());
        }
    }

    #[test]
    fn debug_hides_the_key() {
        let ca = CertificateAuthority::generate().unwrap();
        let debug = format!("{ca:?}");
        assert!(!debug.contains("PRIVATE KEY"), "{debug}");
    }
}
