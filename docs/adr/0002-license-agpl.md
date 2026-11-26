# ADR 0002: License under AGPL-3.0-or-later

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Hiccup is a security tool that could be repackaged as a hosted service or a closed product. The maintainers want improvements to flow back to the community.

## Decision

All Hiccup code is licensed under **AGPL-3.0-or-later**. Each crate declares `license = "AGPL-3.0-or-later"` in `Cargo.toml`, and source files carry an SPDX header: `// SPDX-License-Identifier: AGPL-3.0-or-later`.

Contributions are accepted under the **Developer Certificate of Origin** (`Signed-off-by` trailer). There is no CLA.

## Consequences

- Dependencies must be AGPL-compatible. `cargo-deny` enforces an allow-list (MIT, Apache-2.0, BSD-*, ISC, Zlib, MPL-2.0, Unicode-*, LGPL-*, GPL-3.0, AGPL-3.0, …).
- Platform SDKs (GTK: LGPL; Windows App SDK; Apple frameworks) are system libraries or LGPL, which is compatible.
- Some companies forbid AGPL software. This is accepted.
- Relicensing later would require agreement from every contributor, because there is no CLA.
