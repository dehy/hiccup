// SPDX-License-Identifier: AGPL-3.0-or-later
#![no_main]

use hiccup_http::{BodyDecoder, Framing, Limits};
use libfuzzer_sys::fuzz_target;

// Feeding the input whole or byte by byte must give the same result.
fuzz_target!(|data: &[u8]| {
    let limits = Limits::DEFAULT;

    let mut whole = BodyDecoder::new(Framing::Chunked, limits);
    let mut whole_data = Vec::new();
    let whole_res = whole.feed_with(data, |d| whole_data.extend_from_slice(d));

    let mut split = BodyDecoder::new(Framing::Chunked, limits);
    let mut split_data = Vec::new();
    let mut split_res = Ok(0);
    for i in 0..data.len() {
        match split.feed_with(&data[i..=i], |d| split_data.extend_from_slice(d)) {
            Ok(n) => {
                split_res = split_res.map(|total| total + n);
                if split.is_complete() {
                    break;
                }
            }
            Err(e) => {
                split_res = Err(e);
                break;
            }
        }
    }

    assert_eq!(whole_res, split_res);
    if whole_res.is_ok() {
        assert_eq!(whole_data, split_data);
        assert_eq!(whole.is_complete(), split.is_complete());
        assert_eq!(whole.anomalies(), split.anomalies());
    }
});
