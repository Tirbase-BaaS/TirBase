// SPDX-License-Identifier: AGPL-3.0-only

//! Scenario S34 — partial-signature replay across commands (PV-4.16).
//!
//! Co-signatures are bound to `SHA-256(canonical_cbor(payload))`. A signature
//! collected for payload A must not satisfy the quorum for payload B, even when
//! both payloads use the same domain context.

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_guard::signed_operation::{SignedOperation, SignedOperationError};
use tirbase_guard::time::TimeBeacon;
use tirbase_types::CommandRole;

fn beacon(wall_time_secs: i64) -> TimeBeacon {
    TimeBeacon {
        wall_time_secs,
        issuer_did: "did:key:z6Mkanchor".to_string(),
        mono_seq: 1,
        valid_for_secs: 300,
    }
}

fn resolver<'a>(anchors: &'a [&'a InMemoryKeyProvider]) -> impl Fn(&str) -> Option<Vec<u8>> + 'a {
    move |did| {
        anchors
            .iter()
            .find(|anchor| anchor.did() == did)
            .map(|anchor| anchor.public_key_bytes())
    }
}

/// S34 — signatures cannot be replayed across payloads.
pub fn run_s34(seed: u64) -> Result<(), String> {
    let anchor_a = InMemoryKeyProvider::generate().map_err(|e| format!("S34 anchor A: {e}"))?;
    let anchor_b = InMemoryKeyProvider::generate().map_err(|e| format!("S34 anchor B: {e}"))?;
    let anchors = [&anchor_a, &anchor_b];

    let payload_a = beacon(1_800_000_000 + seed as i64);
    let payload_b = beacon(1_800_000_100 + seed as i64);

    let mut operation_a =
        SignedOperation::<TimeBeacon>::new(&payload_a, payload_a.wall_time_secs, None)
            .map_err(|e| format!("S34 wrap A: {e}"))?;
    operation_a
        .sign_with(&anchor_a, CommandRole::TimeAnchor)
        .map_err(|e| format!("S34 sign A1: {e}"))?;
    operation_a
        .sign_with(&anchor_b, CommandRole::TimeAnchor)
        .map_err(|e| format!("S34 sign A2: {e}"))?;
    operation_a
        .verify(&payload_a, resolver(&anchors))
        .map_err(|e| format!("S34 FAIL: genuine quorum for A did not verify: {e}"))?;

 // Attacker assembles the partial signatures collected for A onto a wrapper
 // for B. The payload hash binding must reject every entry.
    let mut forged = SignedOperation::<TimeBeacon>::new(&payload_b, payload_b.wall_time_secs, None)
        .map_err(|e| format!("S34 wrap B: {e}"))?;
    forged.signatures = operation_a.signatures.clone();
    match forged.verify(&payload_b, resolver(&anchors)) {
        Err(SignedOperationError::SignatureVerification { .. }) => {}
        other => {
            return Err(format!(
                "S34 FAIL: cross-payload signature replay was not rejected: {other:?}"
            ))
        }
    }

 // A signature from a third payload also cannot be spliced into a valid set.
    let mut single_a =
        SignedOperation::<TimeBeacon>::new(&payload_a, payload_a.wall_time_secs, None)
            .map_err(|e| format!("S34 wrap single: {e}"))?;
    single_a
        .sign_with(&anchor_a, CommandRole::TimeAnchor)
        .map_err(|e| format!("S34 sign single: {e}"))?;
    let mut mixed = SignedOperation::<TimeBeacon>::new(&payload_b, payload_b.wall_time_secs, None)
        .map_err(|e| format!("S34 wrap mixed: {e}"))?;
    mixed.signatures.extend(single_a.signatures.clone());
    mixed
        .sign_with(&anchor_b, CommandRole::TimeAnchor)
        .map_err(|e| format!("S34 sign mixed B: {e}"))?;
    if mixed.verify(&payload_b, resolver(&anchors)).is_ok() {
        return Err("S34 FAIL: mixed-payload quorum was accepted".to_string());
    }

 // Control: a genuine quorum over B still verifies.
    let mut genuine =
        SignedOperation::<TimeBeacon>::new(&payload_b, payload_b.wall_time_secs, None)
            .map_err(|e| format!("S34 wrap genuine: {e}"))?;
    genuine
        .sign_with(&anchor_a, CommandRole::TimeAnchor)
        .map_err(|e| format!("S34 sign genuine A: {e}"))?;
    genuine
        .sign_with(&anchor_b, CommandRole::TimeAnchor)
        .map_err(|e| format!("S34 sign genuine B: {e}"))?;
    genuine
        .verify(&payload_b, resolver(&anchors))
        .map_err(|e| format!("S34 FAIL: genuine quorum for B rejected: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s34_partial_signature_replay_rejected() {
        run_s34(1).expect("S34");
    }
}
