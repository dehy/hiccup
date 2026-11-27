# Installing the Hiccup CA

To show and edit HTTPS traffic, Hiccup decrypts it with certificates signed by
a certificate authority (CA) that is unique to your installation. Clients
reject those certificates until you tell them to trust the Hiccup CA.

> [!NOTE]
> TLS interception is in progress
> ([#10](https://github.com/dehy/hiccup/issues/10)). Until it lands, the proxy
> passes HTTPS through without decrypting it, so the CA is not used yet.

> [!WARNING]
> Anyone who has Hiccup's CA private key (`ca-key.pem`) can impersonate any
> website to every client that trusts the CA. Never share the key. Trust the
> CA only in browsers or profiles you use for testing, and remove it when you
> are done. If the key may have leaked, run `hiccup ca regenerate --yes` and
> remove the old CA everywhere you installed it.

## Get the certificate

The CA is generated the first time you need it.

```sh
hiccup ca info                                     # location and SHA-256 fingerprint
hiccup ca export -o hiccup.pem                     # PEM: Linux, macOS, Firefox, curl
hiccup ca export --format der -o hiccup.der        # DER: Windows, Android
```

It is stored in the per-user data directory, or the one given by
`--data-dir` or `HICCUP_DATA_DIR`:

| OS      | Directory                                  |
| ------- | ------------------------------------------ |
| Linux   | `$XDG_DATA_HOME/hiccup` (`~/.local/share/hiccup`) |
| macOS   | `~/Library/Application Support/hiccup`     |
| Windows | `%APPDATA%\hiccup`                         |

On Linux and macOS the private key is created with mode `0600`. On Windows it
inherits the permissions of its directory: `%APPDATA%` is readable only by
you, SYSTEM and administrators. If you choose another data directory on
Windows, make sure other users cannot read it.

When a trust store shows the fingerprint, check that it matches
`hiccup ca info`. The certificate's name is **Hiccup CA**.

## Firefox (all platforms)

Firefox has its own trust store.

1. Open **Settings → Privacy & Security → Certificates → View Certificates…**
2. In the **Authorities** tab, click **Import…** and choose `hiccup.pem`.
3. Check **Trust this CA to identify websites** and confirm.

To remove it, select **Hiccup → Hiccup CA** in the same tab and click
**Delete or Distrust…**.

## Linux

Chrome and Chromium read the per-user NSS database (`certutil` is in the
`libnss3-tools` package on Debian, Ubuntu and Kali, or `nss-tools` on Fedora):

```sh
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "Hiccup CA" -i hiccup.pem
# Remove:
certutil -d sql:$HOME/.pki/nssdb -D -n "Hiccup CA"
```

System-wide trust (curl, wget, most command-line tools) on Debian, Ubuntu and
Kali:

```sh
sudo cp hiccup.pem /usr/local/share/ca-certificates/hiccup.crt
sudo update-ca-certificates
# Remove:
sudo rm /usr/local/share/ca-certificates/hiccup.crt
sudo update-ca-certificates --fresh
```

On Fedora, Arch and other p11-kit systems:

```sh
sudo trust anchor --store hiccup.pem
# Remove:
sudo trust anchor --remove hiccup.pem
```

## macOS

Trust the CA for your user (macOS asks for your password):

```sh
security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db hiccup.pem
# Remove:
security delete-certificate -c "Hiccup CA" ~/Library/Keychains/login.keychain-db
```

Safari, Chrome and command-line tools that use the system TLS library follow
the keychain. You can also open `hiccup.pem` in **Keychain Access**, then set
**Trust → When using this certificate** to **Always Trust**.

## Windows

Trust the CA for your user (Windows asks for confirmation):

```powershell
certutil -user -addstore Root hiccup.der
# Remove:
certutil -user -delstore Root "Hiccup CA"
```

Edge, Chrome and most Windows applications follow the Windows certificate
store.

## Command-line tools

Without installing the CA, point the tool at the certificate:

```sh
curl --proxy http://127.0.0.1:8080 --cacert hiccup.pem https://example.com/
```

Python `requests` uses `REQUESTS_CA_BUNDLE=hiccup.pem`, and Node.js uses
`NODE_EXTRA_CA_CERTS=hiccup.pem`.
