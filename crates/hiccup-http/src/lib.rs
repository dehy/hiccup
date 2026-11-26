// SPDX-License-Identifier: AGPL-3.0-or-later

//! Raw-preserving HTTP/1.1 codec.
//!
//! Messages keep their exact original bytes; parsed fields are a derived,
//! read-only view. See ADR 0003.
