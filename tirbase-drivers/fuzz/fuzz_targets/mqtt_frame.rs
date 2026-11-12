// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use tirbase_drivers::MqttBridgeCodec;

fuzz_target!(|data: &[u8]| {
    let c = MqttBridgeCodec::new();
    let _ = c.decode_publish(data);
    let _ = c.decode_puback(data);
});
