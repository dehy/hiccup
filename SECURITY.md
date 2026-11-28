# Security Policy

Hiccup is a security tool, and we take vulnerabilities in it seriously. Examples include flaws in the TLS interception, the CA key handling, the HTTP parser and the local control API.

## Supported versions

Hiccup is pre-1.0. Only the **latest release** and the `main` branch receive security fixes.

| Version        | Supported |
|----------------|-----------|
| latest release | ✅        |
| older releases | ❌        |

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for security problems.**

Report privately through GitHub: use **[Report a vulnerability](https://github.com/dehy/hiccup/security/advisories/new)**, which is under the repository's *Security* tab. Only the maintainers can see the report.

Please include:

- the affected version or commit, and the OS;
- a description of the issue and its impact;
- steps to reproduce or a proof of concept;
- any suggested fix or mitigation.

## What to expect

- **Acknowledgement** within 5 business days.
- **Initial assessment** (validity, severity) within 14 days.
- **Fix and coordinated disclosure.** We aim to release a fix within 90 days of the report and to publish a GitHub Security Advisory, crediting you unless you prefer otherwise. We will keep you updated, and we will agree the disclosure date with you.

## Scope

In scope: code in this repository and the official release artifacts.

Out of scope:

- vulnerabilities in **target applications** you test with Hiccup;
- issues that require an already-compromised local user account;
- insecure upstream options that pentesting needs and that you turn on yourself, such as `--no-verify-upstream`. They are off by default, documented, and Hiccup shows a warning when they are active.

Please only test against systems you own or are authorized to test.
