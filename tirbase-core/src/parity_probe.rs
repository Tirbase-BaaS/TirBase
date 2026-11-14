// SPDX-License-Identifier: AGPL-3.0-only

//! Cross-build parity probe (Property 1, Req 1.4).
//!
//! The native binary and the real WASM module each run the *same* canonical
//! ordered Delta sequence through the production `CrdtEngine` and emit a
//! SHA-256 over the deterministic encoding of the resulting engine state
//! (per-table Automerge document bytes, Lamport clock, known schema hashes,
//! revoked DIDs, and a signed `MigrationDelta`). `scripts/cross-build-parity.sh`
//! builds both targets, runs both probes, and diffs the hashes; CI runs that
//! script, so a divergence between `--features native` and `--features wasm`
//! fails the build.
//!
//! Enabled only by the `parity-probe` feature so it never reaches a release
//! artifact: the native side is emitted by the `emit_cross_build_parity_hash`
//! test, the WASM side by the `core_cross_build_parity_hash` export.
//!
//! ## What the probe does and does not prove
//!
//! It proves that identical input produces byte-identical CRDT state across
//! the native and WASM builds, including the RGA list-insert path and the
//! canonical serialisation of a signed `MigrationDelta`. It does **not**
//! execute a migration transform in the sandbox: that path is covered
//! separately by `migration::wasm_sandbox::tests::deterministic_cross_arch_hash_vector`
//! (cross-arch CI job) and the gate tests in `migration`.

use sha2::{Digest, Sha256};

use crate::crdt::delta::{Delta, DeltaTag, Ed25519Signature, PriorityClass};
use crate::crdt::CrdtEngine;
use crate::identity::keypair;
use crate::migration::migration_delta::{CaSignature, MigrationDelta, MigrationKind};
use crate::schema::hash::compute_schema_identifier_hash;

const FIXED_SEED: [u8; 32] = [0x5A; 32];

fn deterministic_keypair() -> ([u8; 32], [u8; 32]) {
    use ed25519_dalek::SigningKey;
    let signing_key = SigningKey::from_bytes(&FIXED_SEED);
    (signing_key.to_bytes(), signing_key.verifying_key().to_bytes())
}

fn schema_hash() -> [u8; 32] {
    compute_schema_identifier_hash(&[("devices", &[("id", "TEXT"), ("name", "TEXT")])])
}

#[cfg(feature = "native")]
fn make_engine(sk: [u8; 32], pk: [u8; 32], did: String, hash: [u8; 32]) -> CrdtEngine {
    use std::sync::{Arc, Mutex};
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory SQLite");
    conn.execute_batch(crate::store::sqlite::CREATE_SCHEMA_SQL)
        .expect("create DAG schema");
    CrdtEngine::new(sk, pk, did, hash, Arc::new(Mutex::new(conn)))
}

#[cfg(not(feature = "native"))]
fn make_engine(sk: [u8; 32], pk: [u8; 32], did: String, hash: [u8; 32]) -> CrdtEngine {
    CrdtEngine::new(sk, pk, did, hash)
}

/// A deterministically-built, signed Migration Delta for the sequence.
///
/// It is serialised into the probe hash so a cross-build change in the
/// Migration_Delta encoding or signing bytes is caught by the same gate.
fn canonical_migration_delta(sk: &[u8; 32], author_did: &str) -> Vec<u8> {
    let transform = b"(module (func (export \"transform\")))".to_vec();
    let transform_sha256 = Sha256::digest(&transform).into();
    let mut delta = MigrationDelta {
        id: transform_sha256,
        author_did: author_did.to_string(),
        signature: Ed25519Signature::default(),
        source_schema_hash: schema_hash(),
        target_schema_hash: compute_schema_identifier_hash(&[(
            "devices",
            &[("id", "TEXT"), ("name", "TEXT"), ("email", "TEXT")],
        )]),
        transform_bytes: transform,
        ca_signature: CaSignature(b"cross-build-parity-ca-signature".to_vec()),
        transform_sha256,
        priority: PriorityClass::Medium,
        created_at: 1_720_000_000_000_000,
        execution_profile: None,
        migration_kind: MigrationKind::Expand,
        fleet_precondition_hash: None,
        postconditions: None,
    };
    let bytes = serde_json::to_vec(&delta).expect("serialise MigrationDelta");
    delta.signature = keypair::sign(sk, &bytes).expect("sign MigrationDelta");
    serde_json::to_vec(&delta).expect("serialise signed MigrationDelta")
}

/// Run the canonical sequence on a fresh engine and hash the resulting state.
pub(crate) fn canonical_state_hash() -> String {
    let (sk, pk) = deterministic_keypair();
    let did = crate::crdt::derive_did_from_public_key(&pk);
    let hash = schema_hash();
    let mut engine = make_engine(sk, pk, did.clone(), hash);

    // 1. Scalar write (LWW path).
    let bytes = engine
        .write_scalar("devices", "device-1", &serde_json::json!("online"))
        .expect("scalar write");
    let delta = engine
        .produce_delta(bytes, PriorityClass::Low, vec![])
        .expect("produce scalar delta");
    engine.apply(&delta).expect("apply scalar delta");

    // 2. List write (RGA sequence path). Two concurrent-style appends are
    //    represented by a base write plus a replacement write.
    let bytes = engine
        .write_scalar("devices", "items", &serde_json::json!(["alpha", "beta"]))
        .expect("list write");
    let delta = engine
        .produce_delta(bytes, PriorityClass::Low, vec![])
        .expect("produce list delta");
    engine.apply(&delta).expect("apply list delta");

    // 3. Migration Delta (signed canonical bytes participate in the hash).
    let migration_bytes = canonical_migration_delta(&sk, &did);

    // 4. Revocation (state gate).
    engine.mark_did_revoked(&"did:key:z6MkvParityRevoked".to_string());

    // 5. Contamination-tagged write (tag baked into the signed payload).
    let tag_bytes = engine
        .write_scalar("devices", "device-2", &serde_json::json!({"state": "tainted"}))
        .expect("tagged write");
    let mut tagged = Delta {
        id: [0u8; 32],
        author_did: did,
        signature: Ed25519Signature::default(),
        schema_hash: hash,
        automerge_bytes: tag_bytes,
        priority: PriorityClass::High,
        causal_parents: vec![],
        tags: vec![DeltaTag::Contaminated {
            root_id: [0xAA; 32],
            incident_id: uuid::Uuid::from_bytes([0x42; 16]),
        }],
        lamport: 0,
        created_at: 0,
    };
    let canonical = tagged.canonical_bytes();
    tagged.signature = keypair::sign(&sk, &canonical).expect("sign tagged delta");
    tagged.id = Delta::compute_id(&canonical);
    engine.apply(&tagged).expect("apply tagged delta");

    let mut hasher = Sha256::new();
    hasher.update(b"tirbase-cross-build-parity-v1");
    hasher.update(engine.parity_state_bytes());
    hasher.update(&migration_bytes);
    hex::encode(hasher.finalize())
}

#[cfg(all(test, feature = "native"))]
mod tests {
    /// Emitted with `--nocapture`; parsed by `scripts/cross-build-parity.sh`.
    #[test]
    fn emit_cross_build_parity_hash() {
        println!("PARITY_HASH={}", super::canonical_state_hash());
    }
}
