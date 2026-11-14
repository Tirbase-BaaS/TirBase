// SPDX-License-Identifier: AGPL-3.0-only

//! Scenario S12 — partition and rejoin convergence.
//!
//! Two nodes write independently while the virtual network is partitioned.
//! After healing, the deltas are exchanged through the production CRDT inbound
//! path and both documents must converge to the same state.

use std::sync::{Arc, Mutex};

use crate::network::{NetworkFault, NodeId, SimNetwork, DEFAULT_LINK_DELAY_MS};
use tirbase_core::crdt::merge::{apply_incoming_delta, MergeOutcome};
use tirbase_core::crdt::{derive_did_from_public_key, CrdtEngine};
use tirbase_core::identity::keypair::generate_keypair;
use tirbase_core::schema::hash::compute_schema_identifier_hash;

use super::common::{automerge_payload, signed_delta};

fn schema() -> [u8; 32] {
    compute_schema_identifier_hash(&[("controls", &[("id", "TEXT"), ("setpoint", "TEXT")])])
}

fn engine(secret: [u8; 32], public: [u8; 32], did: String, schema: [u8; 32]) -> CrdtEngine {
    let connection = rusqlite::Connection::open_in_memory().expect("in-memory db");
    connection
        .execute_batch(tirbase_core::store::sqlite::CREATE_SCHEMA_SQL)
        .expect("schema");
    CrdtEngine::new(
        secret,
        public,
        did,
        schema,
        Arc::new(Mutex::new(connection)),
    )
}

fn apply(engine: &mut CrdtEngine, delta: &tirbase_core::crdt::delta::Delta) -> Result<(), String> {
    match apply_incoming_delta(engine, delta)
        .map_err(|error| format!("S12 apply failed: {error}"))?
    {
        MergeOutcome::Merged { .. } => Ok(()),
        other => Err(format!("S12 FAIL: delta not merged: {other:?}")),
    }
}

/// S12 — partition, independent writes, heal, then convergence.
pub fn run_s12(seed: u64) -> Result<(), String> {
    let (secret_a, public_a) = generate_keypair().map_err(|e| format!("S12 keygen A: {e}"))?;
    let did_a = derive_did_from_public_key(&public_a);
    let (secret_b, public_b) = generate_keypair().map_err(|e| format!("S12 keygen B: {e}"))?;
    let did_b = derive_did_from_public_key(&public_b);
    let schema = schema();

    let mut node_a = engine(secret_a, public_a, did_a.clone(), schema);
    let mut node_b = engine(secret_b, public_b, did_b.clone(), schema);

    let delta_a = signed_delta(
        &secret_a,
        did_a,
        schema,
        1,
        automerge_payload(&public_a, "a", &format!("value-a-{seed}")),
        10,
    );
    let delta_b = signed_delta(
        &secret_b,
        did_b,
        schema,
        1,
        automerge_payload(&public_b, "b", &format!("value-b-{seed}")),
        11,
    );

 // Partition A <-> B: both messages are dropped on the wire.
    let mut network = SimNetwork::new(seed);
    network
        .add_fault(NetworkFault::Partition {
            src: NodeId::new(0),
            dst: NodeId::new(1),
        })
        .map_err(|error| format!("S12 partition: {error}"))?;
    if !network
        .send(0, NodeId::new(0), NodeId::new(1), delta_a.canonical_bytes())
        .is_empty()
    {
        return Err("S12 FAIL: partition did not drop A's delta".to_string());
    }
    if !network
        .send(0, NodeId::new(1), NodeId::new(0), delta_b.canonical_bytes())
        .is_empty()
    {
        return Err("S12 FAIL: partition did not drop B's delta".to_string());
    }

 // Local writes are visible on each side while partitioned.
    apply(&mut node_a, &delta_a)?;
    apply(&mut node_b, &delta_b)?;
    if node_a.doc_map_range_root().len() != 1 || node_b.doc_map_range_root().len() != 1 {
        return Err("S12 FAIL: local write did not land during partition".to_string());
    }

 // Heal and exchange the withheld deltas.
    network.heal_all();
    if network.is_partitioned(NodeId::new(0), NodeId::new(1)) {
        return Err("S12 FAIL: partition did not heal".to_string());
    }
    let to_b = network.send(0, NodeId::new(0), NodeId::new(1), delta_a.canonical_bytes());
    let to_a = network.send(0, NodeId::new(1), NodeId::new(0), delta_b.canonical_bytes());
    if to_b.is_empty() || to_a.is_empty() {
        return Err("S12 FAIL: healed network rejected delta exchange".to_string());
    }
    let delivered = network.deliver(DEFAULT_LINK_DELAY_MS);
    if delivered.len() != 2 {
        return Err(format!(
            "S12 FAIL: expected 2 post-heal deliveries, got {}",
            delivered.len()
        ));
    }

    apply(&mut node_a, &delta_b)?;
    apply(&mut node_b, &delta_a)?;

    let state_a = node_a.doc_map_range_root();
    let state_b = node_b.doc_map_range_root();
    if state_a != state_b {
        return Err(format!(
            "S12 FAIL: nodes diverged after rejoin: A={state_a:?} B={state_b:?}"
        ));
    }
    if state_a.len() != 2 {
        return Err(format!(
            "S12 FAIL: expected both writes after convergence, got {state_a:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s12_partition_and_rejoin_converges() {
        run_s12(1).expect("S12");
    }
}
