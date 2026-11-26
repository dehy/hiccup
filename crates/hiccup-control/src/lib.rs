// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local control API: JSON-RPC 2.0 over a Unix socket or Windows named pipe.
//!
//! Every user-visible feature is reachable through this API, which is what
//! makes Hiccup entirely controllable from the CLI. See ADR 0004.
