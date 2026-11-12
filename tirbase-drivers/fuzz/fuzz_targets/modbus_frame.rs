// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use tirbase_drivers::{decode_read_registers_response, parse_rtu_frame, parse_tcp_adu};

fuzz_target!(|data: &[u8]| {
    let _ = parse_tcp_adu(data);
    if let Ok(adu) = parse_tcp_adu(data) {
        let _ = decode_read_registers_response(&adu.pdu, adu.pdu.first().copied().unwrap_or(0));
    }
    let _ = parse_rtu_frame(data);
});
