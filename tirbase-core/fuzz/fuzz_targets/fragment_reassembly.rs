// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

//! Fuzz target for MTU fragmentation and reassembly (task 24.3, PV-6.3).
//!
//! Drives the real [`fragment`], [`reassemble`] and [`ReassemblyBuffer`] code
//! that processes untrusted fragment metadata from low-MTU peers. A panic in
//! any of them aborts the fuzz run and fails CI.

use libfuzzer_sys::fuzz_target;
use tirbase_core::transport::fragment::{
    fragment, reassemble, DeltaFragment, ReassemblyBuffer, MAX_FRAGMENTS_PER_DELTA,
};
use tirbase_core::transport::message::GossipMessage;

const SENDER: &str = "did:key:z6MkFuzzSender";

fn delta_id_from(bytes: &[u8]) -> [u8; 32] {
    let mut id = [0u8; 32];
    for (slot, b) in id.iter_mut().zip(bytes.iter().cycle()) {
        *slot = *b;
    }
    id
}

fuzz_target!(|data: &[u8]| {
    // 1. A fragment-bearing wire message: decode it and push it through the
    //    real buffer exactly as `process_wire_message` does.
    if let Some(GossipMessage::InboundDeltaFragment(frag)) = GossipMessage::from_bytes(data) {
        let mut buffer = ReassemblyBuffer::default();
        let _ = buffer.add_fragment(frag, &SENDER.to_string());
    }

    // 2. Split arbitrary bytes with an arbitrary MTU (0..=255) and reassemble.
    if let Some((head, payload)) = data.split_first() {
        let mtu = *head as usize;
        let id = delta_id_from(data);
        let fragments = fragment(id, payload, mtu);
        let sender = SENDER.to_string();

        if mtu > 0 && !payload.is_empty() {
            // The round-trip invariant must hold on arbitrary input.
            let reassembled = reassemble(fragments.clone(), &sender)
                .expect("fragment() output must always reassemble");
            assert_eq!(reassembled, payload);
        } else {
            let _ = reassemble(fragments.clone(), &sender);
        }

        // 3. Same fragments, delivered out of order and then duplicated:
        //    exercises the slot-array, duplicate handling and completion paths.
        let mut buffer = ReassemblyBuffer::default();
        for frag in fragments.iter().rev() {
            let _ = buffer.add_fragment(frag.clone(), &sender);
        }
        for frag in &fragments {
            let _ = buffer.add_fragment(frag.clone(), &sender);
        }
    }

    // 4. Adversarial fragment metadata straight from the fuzzer, including
    //    total_fragments past `MAX_FRAGMENTS_PER_DELTA` and enough distinct
    //    delta ids to reach `MAX_REASSEMBLY_SLOTS` / trigger eviction.
    if data.len() >= 8 {
        let total = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let index = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let sender = SENDER.to_string();
        let mut buffer = ReassemblyBuffer::default();
        let frag = DeltaFragment {
            delta_id: delta_id_from(&data[8..]),
            fragment_index: index,
            total_fragments: total,
            payload: data[8..].to_vec(),
        };
        let _ = buffer.add_fragment(frag, &sender);

        // A bounded soak over distinct delta ids (slot-array bookkeeping and
        // completion), plus one fragment past MAX_FRAGMENTS_PER_DELTA so the
        // allocation guard is exercised.
        let entries = 8 + (data.len() % 64);
        for i in 0..entries {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let frag = DeltaFragment {
                delta_id: id,
                fragment_index: 0,
                total_fragments: 1,
                payload: vec![data[i % data.len()]],
            };
            let _ = buffer.add_fragment(frag, &sender);
        }
        let oversized = DeltaFragment {
            delta_id: [0xFF; 32],
            fragment_index: 0,
            total_fragments: MAX_FRAGMENTS_PER_DELTA.saturating_add(1),
            payload: data.to_vec(),
        };
        assert!(buffer.add_fragment(oversized, &sender).is_err());
    }
});
