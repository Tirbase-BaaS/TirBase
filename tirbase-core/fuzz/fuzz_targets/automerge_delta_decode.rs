#![no_main]

//! Fuzz target for the inbound delta decode path (task 24.3, PV-6.3).
//!
//! Drives the *real* decoders used on untrusted peer input:
//!
//! 1. `automerge::AutoCommit::load` — the decoder `crdt::hardening` and
//!    `CrdtEngine::apply` run over `Delta::automerge_bytes`.
//! 2. `serde_json` deserialisation of `Delta` — the wire representation.
//! 3. `GossipMessage::from_bytes` — what `process_wire_message` runs on every
//!    Gossipsub message before routing.
//!
//! No `catch_unwind`: a panic anywhere in these decoders is a finding and must
//! abort the fuzz run (and therefore fail CI).

use libfuzzer_sys::fuzz_target;
use tirbase_core::crdt::delta::Delta;
use tirbase_core::transport::message::GossipMessage;

fn decode_automerge(bytes: &[u8]) {
    if let Ok(mut doc) = automerge::AutoCommit::load(bytes) {
        let _ = doc.get_changes(&[]);
        // Exercise the other direction of the codec as well.
        let _ = doc.save();
    }
}

fn decode_delta(delta: &Delta) {
    decode_automerge(&delta.automerge_bytes);
    // Canonicalisation + content-addressing are on the merge hot path.
    let canonical = delta.canonical_bytes();
    let _ = Delta::compute_id(&canonical);
}

fuzz_target!(|data: &[u8]| {
    // Raw bytes straight into the Automerge decoder.
    decode_automerge(data);

    // JSON `Delta` decode (the on-wire form of a Delta).
    if let Ok(delta) = serde_json::from_slice::<Delta>(data) {
        decode_delta(&delta);
    }

    // Full GossipMessage envelope decode, including the delta it carries.
    if let Some(msg) = GossipMessage::from_bytes(data) {
        match msg {
            GossipMessage::InboundDelta(delta) => decode_delta(&delta),
            GossipMessage::RelayDelta { delta, .. } => decode_delta(&delta),
            _ => {}
        }
    }
});
