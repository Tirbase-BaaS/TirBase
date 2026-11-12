#![no_main]
// SPDX-License-Identifier: AGPL-3.0-only


use libfuzzer_sys::fuzz_target;
use tirbase_drivers::ModbusRegisterMap;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = ModbusRegisterMap::parse(s);
    }
});
