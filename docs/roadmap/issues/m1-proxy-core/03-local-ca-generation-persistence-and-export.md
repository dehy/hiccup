# Local CA generation, persistence and export

labels: type:feature, area:tls

## Goal

Generate a per-installation root CA used for TLS interception.

## Tasks

- [ ] Generate the CA with `rcgen` on first run and store it in the per-user data dir (key file mode 0600 / user-only ACL on Windows)
- [ ] Export as PEM and DER; regenerate on request
- [ ] Per-OS install instructions (Linux NSS/p11-kit, macOS Keychain, Windows cert store, Firefox)

## Acceptance criteria

- [ ] `hiccup ca export --format der -o hiccup.der` works
- [ ] The private key is never written world-readable (tested)
