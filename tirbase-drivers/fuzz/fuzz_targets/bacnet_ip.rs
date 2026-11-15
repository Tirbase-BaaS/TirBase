// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use tirbase_driver_api::bacnet_codec::{
    encode_i_am, encode_read_property, encode_read_property_ack, parse_apdu, parse_bvlc,
    parse_message, BacnetMessage,
};

fuzz_target!(|data: &[u8]| {
    // The parser is the untrusted-input boundary: it must never panic.
    let _ = parse_message(data);
    if let Ok(bvlc) = parse_bvlc(data) {
        let _ = parse_apdu(bvlc.apdu);
    }

    // Decode/re-encode round trips for every structural message the codec emits.
    match parse_message(data) {
        Ok(BacnetMessage::IAm(i_am)) => {
            if let Ok(frame) = encode_i_am(&i_am) {
                let _ = parse_message(&frame);
            }
        }
        Ok(BacnetMessage::ReadProperty(request)) => {
            if let Ok(frame) =
                encode_read_property(request.invoke_id, request.object, request.property)
            {
                let _ = parse_message(&frame);
            }
        }
        Ok(BacnetMessage::ReadPropertyAck { invoke_id, value }) => {
            let frame = encode_read_property_ack(invoke_id, &value);
            let _ = parse_message(&frame);
        }
        _ => {}
    }
});
