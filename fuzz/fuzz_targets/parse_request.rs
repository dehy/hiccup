// SPDX-License-Identifier: AGPL-3.0-or-later
#![no_main]

use hiccup_http::{Limits, Request, RequestHead};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::DEFAULT;
    if let Ok(Some(head)) = RequestHead::parse(data, &limits) {
        assert_eq!(head.as_bytes(), &data[..head.len()]);
        let _ = head.framing();
        for h in head.headers() {
            let _ = h.value_unfolded();
        }
    }
    for eof in [false, true] {
        if let Ok(Some(req)) = Request::parse(data, &limits, eof) {
            assert_eq!(req.to_bytes(), &data[..req.len()]);
            let _ = req.decoded_body();
        }
    }
});
