// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use tirbase_drivers::mqtt::{parse_sensor_payload, MqttBridgeCodec, MqttQoS};

fuzz_target!(|data: &[u8]| {
    let c = MqttBridgeCodec::new();
    let _ = c.decode_publish(data);
    let _ = c.decode_puback(data);
    // CC-07: the payload schema parser is another untrusted-input boundary.
    let _ = parse_sensor_payload(data, 4096, MqttQoS::AtMostOnce);
});
