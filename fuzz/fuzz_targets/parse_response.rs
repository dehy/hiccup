// SPDX-License-Identifier: AGPL-3.0-or-later
#![no_main]

use hiccup_http::{Limits, Response};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::DEFAULT;
    for method in [&b"GET"[..], b"HEAD", b"CONNECT"] {
        if let Ok(Some(resp)) = Response::parse(data, method, &limits, true) {
            assert_eq!(resp.to_bytes(), &data[..resp.len()]);
            let _ = resp.decoded_body();
        }
    }
});
