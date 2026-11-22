// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzz target for the ST-03 decoders.
//!
//! Every entry point must reject malformed input with an error, never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tirbase_venue_access::crypto::AesKey;
use tirbase_venue_access::desfire::DesfireReader;
use tirbase_venue_access::osdp::{OsdpFrame, OsdpPoller};
use tirbase_venue_access::sim::DesfireSim;
use tirbase_venue_access::wiegand::{decode, DataLine, WiegandPulse, WiegandTiming};

fuzz_target!(|data: &[u8]| {
    let _ = OsdpFrame::decode(data);

    if let Ok(mut poller) = OsdpPoller::new(0) {
        let _ = poller.accept(data);
    }

    let key = AesKey::from_array([0x11u8; 16]);
    if let Ok(mut card) = DesfireSim::new(0, key.clone(), [0u8; 7]) {
        let _ = card.handle(data);
    }
    if let Ok(mut reader) = DesfireReader::new(0, key) {
        let _ = reader.accept_file_data(data);
    }

    if data.len() >= 26 {
        let pulses: Vec<WiegandPulse> = data[..26]
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                WiegandPulse::new(
                    if byte & 1 == 0 {
                        DataLine::Zero
                    } else {
                        DataLine::One
                    },
                    u32::from(*byte),
                    u32::from(data[(index + 1) % 26]),
                )
            })
            .collect();
        let _ = decode(&pulses, &WiegandTiming::default());
    }
});
