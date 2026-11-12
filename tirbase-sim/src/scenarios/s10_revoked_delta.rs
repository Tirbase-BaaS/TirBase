//! Scenario S10 — revoked-author delta propagation.
//!
//! A peer whose DID has been revoked keeps signing structurally valid deltas.
//! The production inbound path (`apply_incoming_delta` → `CrdtEngine::apply`)
//! must reject them before merge and leave the document unchanged.

use std::sync::{Arc, Mutex};

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

/// S10 — a delta authored by a revoked DID is rejected and cannot mutate state.
pub fn run_s10(seed: u64) -> Result<(), String> {
    let (honest_secret, honest_public) =
        generate_keypair().map_err(|error| format!("S10 honest keygen: {error}"))?;
    let honest_did = derive_did_from_public_key(&honest_public);
    let (revoked_secret, revoked_public) =
        generate_keypair().map_err(|error| format!("S10 revoked keygen: {error}"))?;
    let revoked_did = derive_did_from_public_key(&revoked_public);
    let schema = schema();
    let mut victim = engine(honest_secret, honest_public, honest_did.clone(), schema);

    let baseline = signed_delta(
        &honest_secret,
        honest_did,
        schema,
        1,
        automerge_payload(b"honest", "setpoint", "safe"),
        1,
    );
    match apply_incoming_delta(&mut victim, &baseline)
        .map_err(|error| format!("S10 baseline apply: {error}"))?
    {
        MergeOutcome::Merged { .. } => {}
        other => return Err(format!("S10 FAIL: honest baseline not merged: {other:?}")),
    }
    let before = victim.doc_map_range_root();

 // Revocation is applied through the production engine gate.
    victim.mark_did_revoked(&revoked_did);

    let attack = signed_delta(
        &revoked_secret,
        revoked_did.clone(),
        schema,
        2,
        automerge_payload(&revoked_public, "setpoint", &format!("pwned-{seed}")),
        2,
    );
    match apply_incoming_delta(&mut victim, &attack)
        .map_err(|error| format!("S10 attack apply: {error}"))?
    {
        MergeOutcome::Rejected { reason } => {
            if !reason.contains("REVOKED") {
                return Err(format!(
                    "S10 FAIL: delta rejected for the wrong reason: {reason}"
                ));
            }
        }
        other => {
            return Err(format!(
                "S10 FAIL: revoked-author delta was not rejected: {other:?}"
            ))
        }
    }

    let after = victim.doc_map_range_root();
    if before != after {
        return Err(format!(
            "S10 FAIL: revoked delta mutated state before={before:?} after={after:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s10_revoked_author_delta_rejected() {
        run_s10(1).expect("S10");
    }
}
