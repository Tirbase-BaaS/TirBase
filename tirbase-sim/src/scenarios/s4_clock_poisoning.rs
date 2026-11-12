//! Scenario S4 (CRDT clock/start_op poisoning, PV-6.1, PV-6.2, CLAIM-22.1–22.4).
//!
//! A malicious peer sends an Automerge delta whose `start_op` is inflated far
//! beyond the value implied by its causal dependencies. On an unprotected merge
//! this wins every LWW conflict (characterized in the tirbase-core tests). The
//! hardened production inbound path (`apply_incoming_delta` → `validate_start_op`)
//! must quarantine the delta as `ClockJump` and leave merged state unchanged.
//!
//! This scenario exercises the *production* path through two real `CoreHandle`
//! instances over a direct in-process inbound handoff (mirroring the gate-g1 mesh
//! integration style used elsewhere in this crate), so it satisfies the "S4 must
//! pass in tirbase-sim before CRDT hardening is considered complete" gate for
//! .

use std::sync::{Arc, Mutex};

use tirbase_core::crdt::delta::{Delta, Ed25519Signature, PriorityClass};
use tirbase_core::crdt::merge::{apply_incoming_delta, MergeOutcome, QuarantineReason};
use tirbase_core::crdt::{derive_did_from_public_key, CrdtEngine};
use tirbase_core::identity::keypair::{generate_keypair, sign};
use tirbase_core::schema::hash::compute_schema_identifier_hash;

/// Deterministic seed for the S4 scenario (reproducible, PV-12.2).
pub const S4_SEED: u64 = 0x00C1_0CC0_0000_0004;

fn schema() -> [u8; 32] {
    compute_schema_identifier_hash(&[("controls", &[("id", "TEXT"), ("setpoint", "TEXT")])])
}

fn make_engine(secret: [u8; 32], public: [u8; 32], did: String, schema: [u8; 32]) -> CrdtEngine {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory db");
    conn.execute_batch(tirbase_core::store::sqlite::CREATE_SCHEMA_SQL)
        .expect("schema");
    CrdtEngine::new(secret, public, did, schema, Arc::new(Mutex::new(conn)))
}

fn sign_delta(
    secret: &[u8; 32],
    author_did: String,
    schema: [u8; 32],
    lamport: u64,
    automerge_bytes: Vec<u8>,
) -> Delta {
    let mut d = Delta {
        id: [0u8; 32],
        author_did,
        signature: Ed25519Signature::default(),
        schema_hash: schema,
        automerge_bytes,
        priority: PriorityClass::Low,
        causal_parents: vec![],
        tags: vec![],
        lamport,
        created_at: 0,
    };
    let canonical = d.canonical_bytes();
    d.signature = sign(secret, &canonical).expect("sign");
    d.id = Delta::compute_id(&canonical);
    d
}

fn honest_payload(actor: &[u8], key: &str, value: &str) -> Vec<u8> {
    use automerge::transaction::Transactable;
    let mut doc = automerge::AutoCommit::new().with_actor(automerge::ActorId::from(actor));
    doc.put(automerge::ROOT, key, value).expect("put");
    doc.save()
}

/// Inflate `start_op` across the payload (mirrors the attack primitive). This is
/// the adversarial action S4 injects.
fn inflate_start_op(automerge_bytes: &[u8], offset: u64) -> Vec<u8> {
    let mut doc = automerge::AutoCommit::load(automerge_bytes).expect("load");
    let changes = doc.get_changes(&[]);
    let mut inflated = Vec::new();
    for change in changes {
        let mut expanded = change.decode();
        expanded.start_op = std::num::NonZeroU64::new(expanded.start_op.get() + offset).unwrap();
        inflated.push(automerge::Change::from(expanded));
    }
    let mut out = Vec::new();
    for ch in &mut inflated {
        out.extend_from_slice(&ch.bytes());
    }
    automerge::AutoCommit::load(&out).expect("loadable inflated");
    out
}

fn root_string(engine: &CrdtEngine, key: &str) -> Option<String> {
    engine.doc_map_range_root().into_iter().find_map(|(k, v)| {
        if k == key {
            Some(match v {
                serde_json::Value::String(s) => s,
                other => other.to_string(),
            })
        } else {
            None
        }
    })
}

/// Run S4: inflated `start_op` delta is quarantined as `ClockJump` on the
/// production inbound path; the honest node's state is preserved. Returns `Ok`
/// on pass; `Err` carries a diagnostic including the deterministic seed.
pub fn run_s4(seed: u64) -> Result<(), String> {
    let (sa, pa) = generate_keypair().map_err(|e| format!("seed={seed} keygen A: {e}"))?;
    let did_a = derive_did_from_public_key(&pa);
    let (sb, pb) = generate_keypair().map_err(|e| format!("seed={seed} keygen B: {e}"))?;
    let did_b = derive_did_from_public_key(&pb);
    let sch = schema();

 // Node A (honest victim) and Node B (attacker) — two real CRDT engines.
    let mut node_a = make_engine(sa, pa, did_a.clone(), sch);
    let _node_b = make_engine(sb, pb, did_b.clone(), sch);

 // Honest baseline on A.
    let honest = sign_delta(&sa, did_a, sch, 1, honest_payload(&pa, "setpoint", "safe"));
    match apply_incoming_delta(&mut node_a, &honest) {
        Ok(MergeOutcome::Merged { .. }) => {}
        other => return Err(format!("seed={seed} honest baseline not merged: {other:?}")),
    }
    let before = root_string(&node_a, "setpoint");

 // Attacker B forges an inflated-start_op delta targeting the same key.
    let offset = 1_000_000u64 + (seed % 10_000);
    let attack_bytes = inflate_start_op(&honest_payload(&pb, "setpoint", "pwned"), offset);
    let attack = sign_delta(&sb, did_b, sch, 2, attack_bytes);

 // Production inbound path must quarantine as ClockJump (PV-6.1, S4).
    match apply_incoming_delta(&mut node_a, &attack) {
        Ok(MergeOutcome::Quarantined {
            reason: QuarantineReason::ClockJump,
        }) => {}
        other => {
            return Err(format!(
                "seed={seed} S4 FAIL: inflated start_op (offset={offset}) was not quarantined as \
                 ClockJump on production path; outcome={other:?}"
            ))
        }
    }

    let after = root_string(&node_a, "setpoint");
    if before != after {
        return Err(format!(
            "seed={seed} S4 FAIL: ClockJump delta mutated state before={before:?} after={after:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

 /// S4 (clock/start_op poisoning) — deterministic seed, must pass before CRDT
 /// hardening is considered complete.
    #[test]
    fn s4_clock_poisoning_inflated_start_op_quarantined() {
        if let Err(e) = run_s4(S4_SEED) {
            panic!("S4 failed (seed={S4_SEED}): {e}");
        }
    }

 /// A small seeded sweep to guard against seed-fragility (PV-12.1 spirit).
    #[test]
    fn s4_clock_poisoning_seeded_sweep() {
        for seed in 0u64..16 {
            if let Err(e) = run_s4(S4_SEED.wrapping_add(seed)) {
                panic!("S4 failed (seed={}): {e}", S4_SEED.wrapping_add(seed));
            }
        }
    }
}
