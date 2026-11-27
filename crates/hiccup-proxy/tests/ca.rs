// SPDX-License-Identifier: AGPL-3.0-or-later

//! Persistence of the local CA.

use std::fs;
use std::path::Path;

use hiccup_proxy::ca::{CERT_FILE, KEY_FILE};
use hiccup_proxy::{CaError, CertificateAuthority};

#[test]
fn saved_ca_loads_back() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("nested").join("hiccup");
    assert!(CertificateAuthority::load(&data).unwrap().is_none());

    let (ca, created) = CertificateAuthority::load_or_generate(&data).unwrap();
    assert!(created);
    let (again, created) = CertificateAuthority::load_or_generate(&data).unwrap();
    assert!(!created);
    assert_eq!(again.cert_der(), ca.cert_der());
    assert_eq!(again.info(), ca.info());
    assert_eq!(
        fs::read_to_string(data.join(CERT_FILE)).unwrap(),
        ca.cert_pem()
    );
}

#[test]
fn save_replaces_the_previous_ca() {
    let dir = tempfile::tempdir().unwrap();
    let (old, _) = CertificateAuthority::load_or_generate(dir.path()).unwrap();
    let new = CertificateAuthority::generate().unwrap();
    new.save(dir.path()).unwrap();
    let loaded = CertificateAuthority::load(dir.path()).unwrap().unwrap();
    assert_eq!(loaded.cert_der(), new.cert_der());
    assert_ne!(loaded.cert_der(), old.cert_der());
    // No temporary file is left behind (the lock file stays, empty).
    assert_eq!(files(dir.path()), [CERT_FILE, KEY_FILE, "ca.lock"]);
}

#[test]
fn a_missing_half_is_an_error() {
    for (keep, missing) in [(CERT_FILE, KEY_FILE), (KEY_FILE, CERT_FILE)] {
        let dir = tempfile::tempdir().unwrap();
        CertificateAuthority::generate()
            .unwrap()
            .save(dir.path())
            .unwrap();
        fs::remove_file(dir.path().join(missing)).unwrap();
        let err = CertificateAuthority::load(dir.path()).unwrap_err();
        assert!(
            matches!(&err, CaError::Incomplete { missing: m } if m.ends_with(missing)),
            "kept {keep}: {err}"
        );
        // Never silently replaced: the user may have installed that CA.
        assert!(CertificateAuthority::load_or_generate(dir.path()).is_err());
    }
}

#[test]
fn a_certificate_from_another_ca_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    CertificateAuthority::generate()
        .unwrap()
        .save(dir.path())
        .unwrap();
    let other = CertificateAuthority::generate().unwrap();
    fs::write(dir.path().join(CERT_FILE), other.cert_pem()).unwrap();
    let err = CertificateAuthority::load(dir.path()).unwrap_err();
    assert!(matches!(err, CaError::KeyMismatch { .. }), "{err}");
}

#[test]
fn garbage_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    CertificateAuthority::generate()
        .unwrap()
        .save(dir.path())
        .unwrap();
    fs::write(dir.path().join(CERT_FILE), "not a certificate").unwrap();
    let err = CertificateAuthority::load(dir.path()).unwrap_err();
    assert!(
        matches!(
            err,
            CaError::Invalid {
                what: "certificate",
                ..
            }
        ),
        "{err}"
    );

    fs::write(dir.path().join(KEY_FILE), "not a key").unwrap();
    let err = CertificateAuthority::load(dir.path()).unwrap_err();
    assert!(
        matches!(
            err,
            CaError::Invalid {
                what: "private key",
                ..
            }
        ),
        "{err}"
    );
}

#[cfg(unix)]
#[test]
fn the_private_key_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("hiccup");
    // A world-readable leftover from an interrupted write must not leak its
    // permissions to the new key.
    fs::create_dir(&data).unwrap();
    let tmp = data.join(format!("{KEY_FILE}.tmp"));
    fs::write(&tmp, "stale").unwrap();
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644)).unwrap();

    CertificateAuthority::generate()
        .unwrap()
        .save(&data)
        .unwrap();
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&data.join(KEY_FILE)), 0o600);
    assert_eq!(mode(&data.join(CERT_FILE)), 0o644);
    assert!(!tmp.exists());

    let fresh = dir.path().join("fresh").join("hiccup");
    CertificateAuthority::generate()
        .unwrap()
        .save(&fresh)
        .unwrap();
    assert_eq!(mode(&fresh), 0o700);
}

#[cfg(windows)]
#[test]
fn the_private_key_is_owner_only() {
    // Files under the user profile inherit an ACL granting the user, SYSTEM
    // and administrators only. Check that nothing broader is granted.
    let dir = tempfile::tempdir().unwrap();
    CertificateAuthority::generate()
        .unwrap()
        .save(dir.path())
        .unwrap();
    let out = std::process::Command::new("icacls")
        .arg(dir.path().join(KEY_FILE))
        .output()
        .unwrap();
    assert!(out.status.success());
    let acl = String::from_utf8_lossy(&out.stdout);
    for broad in [
        "Everyone",
        "BUILTIN\\Users",
        "Authenticated Users",
        "S-1-1-0",
        "S-1-5-32-545",
        "S-1-5-11",
    ] {
        assert!(!acl.contains(broad), "{broad} in:\n{acl}");
    }
}

fn files(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn instances_starting_together_share_one_ca() {
    let dir = tempfile::tempdir().unwrap();
    let results: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| CertificateAuthority::load_or_generate(dir.path()).unwrap()))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(
        results.iter().filter(|(_, generated)| *generated).count(),
        1
    );
    let on_disk = CertificateAuthority::load(dir.path()).unwrap().unwrap();
    for (ca, _) in &results {
        assert_eq!(ca.info().sha256, on_disk.info().sha256);
    }
}
