// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core domain model and services shared by every Hiccup frontend.
//!
//! All user-facing behaviour lives here (or in the crates it composes) so that
//! frontends stay thin. See ADR 0001.
//!
//! [`Instance`] is one running Hiccup: it owns the proxy and implements the
//! control API ([`hiccup_control::Handler`]). The CLI, the daemon and the
//! desktop apps all drive Hiccup through it.

mod instance;
mod params;
mod project;

pub use instance::Instance;
