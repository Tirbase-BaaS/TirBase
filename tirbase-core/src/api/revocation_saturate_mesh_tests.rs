// SPDX-License-Identifier: AGPL-3.0-only

//! Workstream 4 (e2e wiring): multi-peer revocation gossip accumulation and
//! M-of-N Saturate_Mode termination over REAL mesh peers.
//!
//! Every test here drives production code paths only:
//!
//! - `CoreHandle::init` / `dial_peer` / `spawn_inbound_drain_loop` /
//!   `spawn_scheduler_tick_loop` — the same construction and background loops
//!   the production build spawns;
//! - `CoreHandle::initiate_revocation` with a real root-CA-signed
//!   `RevocationManager` Biscuit token, for a real device identity;
//! - the synthetic `tirbase/revocation` / `tirbase/saturate` gossip envelopes
//!   the production enqueue paths produce, published through
//!   `MeshTransport::send_delta` and dispatched by `receive_inbound`;
//! - `CoreHandle::activate_saturate_mode` / `renew_saturate_mode` /
//!   `request_saturate_termination` with real DISASTER_ALERT tokens and real
//!   Manager signatures over the canonical, lease-bound termination message.
//!
//! No `inject_inbound`, no `#[cfg(test)]`-only branch and no mock transport sits
//! on an asserted path. Negative cases publish deliberately malformed material
//! through the same wire framing and assert it fails closed.

use super::mesh_harness::*;
use super::*;
use crate::auth::RevocationStatus;
use crate::crdt::delta::Delta;
use crate::identity::file_key_provider::InMemoryKeyProvider;
use crate::transport::message::GossipMessage;
use crate::traits::KeyProvider;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

/// Upper bound on one production gossip round: the production DRR scheduler
/// epoch is 1 s (`SCHEDULER_TICK_INTERVAL_MS`) and the production inbound drain
/// cadence is 50 ms (`INBOUND_DRAIN_INTERVAL_MS`). Tests drive the identical
/// loops at a shorter interval, so a compliant implementation converges well
/// inside this bound; the assertion is about the production cadence, not the
/// test cadence.
const ONE_GOSSIP_ROUND_MICROS: u64 = 1_000_000 + 50_000;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Fresh root CA: returns the seed used to mint tokens and the public key
/// registered in every device's deployment config.
fn root_ca() -> (InMemoryKeyProvider, [u8; 32]) {
    let ca = InMemoryKeyProvider::generate().expect("root CA keypair");
    let public: [u8; 32] = ca
        .public_key_bytes()
        .try_into()
        .expect("root CA public key must be 32 bytes");
    (ca, public)
}

/// A root-CA-signed Biscuit token with the given role.
fn token_with_role(ca: &InMemoryKeyProvider, role: &str) -> Vec<u8> {
    crate::auth::biscuit::create_token("did:key:z6MkTestManager", role, 3600, &ca.secret_seed(), false)
        .expect("mint token")
}

/// A root-CA-signed DISASTER_ALERT token (Req 13.1).
fn disaster_alert_token(ca: &InMemoryKeyProvider) -> Vec<u8> {
    crate::auth::biscuit::create_token_with_caveat(
        "did:key:z6MkTestManager",
        "manager",
        3600,
        "disaster-alert",
        &ca.secret_seed(),
    )
    .expect("mint disaster-alert token")
}

/// Wall clock in seconds, the convention `initiate_revocation` uses.
fn now_secs() -> i64 {
    crate::traits::wall_hint_secs().unwrap_or_default()
}

/// Build a synthetic control-plane envelope carrying a pre-framed
/// `GossipMessage`, exactly as `enqueue_control_envelope` does in production.
/// `lamport` only varies the wrapper bytes so two envelopes carrying the same
/// inner message are distinct gossipsub payloads.
fn control_envelope(
    author: &str,
    message: &crate::transport::message::GossipMessage,
    lamport: u64,
) -> Delta {
    Delta {
        id: [0u8; 32],
        author_did: author.to_string(),
        signature: crate::crdt::delta::Ed25519Signature::default(),
        schema_hash: [0u8; 32],
        automerge_bytes: message.to_bytes(),
        priority: PriorityClass::High,
        causal_parents: vec![],
        tags: vec![],
        lamport,
        created_at: 0,
    }
}

/// Publish an envelope over the real transport (`send_delta` → Swarm publish).
fn publish(handle: &Arc<CoreHandle>, peer_did: &str, delta: &Delta) {
    handle
        .transport
        .lock()
        .expect("transport mutex")
        .send_delta(&peer_did.to_string(), delta)
        .expect("send_delta must publish over the real transport");
}

/// Build a JSON-envelope data Delta authored and signed by `handle`'s real
/// identity key (the framing a WASM peer publishes).
fn signed_row_delta(
    handle: &CoreHandle,
    table: &str,
    key: &str,
    data: &serde_json::Value,
) -> Delta {
    let mut envelope = serde_json::Map::new();
    envelope.insert(
        "_tirbase_table".to_string(),
        serde_json::Value::String(table.to_string()),
    );
    envelope.insert(
        "_tirbase_key".to_string(),
        serde_json::Value::String(key.to_string()),
    );
    for (k, v) in data.as_object().expect("object payload") {
        envelope.insert(k.clone(), v.clone());
    }
    let bytes = serde_json::to_vec(&serde_json::Value::Object(envelope)).expect("envelope");

    let mut delta = Delta {
        id: [0u8; 32],
        author_did: handle.identity.did().to_string(),
        signature: crate::crdt::delta::Ed25519Signature::default(),
        schema_hash: [0u8; 32],
        automerge_bytes: bytes,
        priority: PriorityClass::High,
        causal_parents: vec![],
        tags: vec![],
        lamport: 2,
        created_at: 0,
    };
    let canonical = delta.canonical_bytes();
    delta.signature =
        crate::identity::keypair::sign(&handle.identity.signing_key_bytes(), &canonical)
            .expect("sign delta");
    delta.id = Delta::compute_id(&canonical);
    delta
}

/// Poll `f` until it is true, panicking at the monotonic deadline.
async fn wait_until<F: FnMut() -> bool>(mut f: F, timeout: Duration, what: &str) {
    let deadline = crate::traits::monotonic_now() + timeout.as_micros() as u64;
    loop {
        if f() {
            return;
        }
        assert!(
            crate::traits::monotonic_now() < deadline,
            "timed out after {timeout:?} waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Revocation status of `did` on `handle` (Req 9.5).
fn revoked_status(handle: &CoreHandle, did: &str) -> Option<TrustLevel> {
    handle
        .device_revocation_status(did)
        .expect("status query")
        .map(|s| s.last_known_trust_level)
}

/// Accumulation state of `did` on `handle`.
fn accumulation(handle: &CoreHandle, did: &str) -> Option<RevocationStatus> {
    handle
        .revocation
        .lock()
        .expect("revocation mutex")
        .store_status(&did.to_string())
}

/// Does `handle`'s outbound publish point hold a HIGH-priority revocation
/// envelope for `did`?
fn published_revocation_envelope(handle: &CoreHandle, did: &str) -> bool {
    let transport = handle.transport.lock().expect("transport mutex");
    transport.outbound_published.iter().any(|payload| {
        let Some(GossipMessage::InboundDelta(wrapper)) = GossipMessage::from_bytes(payload) else {
            return false;
        };
        if wrapper.author_did != super::REVOCATION_GOSSIP_AUTHOR {
            return false;
        }
        if wrapper.priority != PriorityClass::High {
            return false;
        }
        matches!(
            GossipMessage::from_bytes(&wrapper.automerge_bytes),
            Some(GossipMessage::InboundRevocationDelta(rev)) if rev.target_did == did
        )
    })
}

/// Initialise a loopback device with a real Swarm and both production loops
/// (inbound drain + DRR scheduler tick).
async fn init_peer(
    suffix: &str,
    deployment: DeploymentConfig,
) -> (Arc<CoreHandle>, String) {
    let port = reserve_loopback_port();
    let handle = init_mesh_handle_with_deployment(suffix, port, deployment).await;
    CoreHandle::spawn_scheduler_tick_loop(&handle, Duration::from_millis(10));
    (handle, format!("/ip4/127.0.0.1/tcp/{port}"))
}

/// Connect two devices over the production dial path.
///
/// A single dial yields a bidirectional transport connection: both Swarms
/// observe `ConnectionEstablished` and the gossipsub subscription exchange
/// covers both directions (the existing real-mesh tests rely on the same
/// property). Dialling both ways simultaneously would race libp2p's
/// connection handling, so the mesh is built with one dial per edge.
async fn connect_pair(a: &(Arc<CoreHandle>, String), b: &(Arc<CoreHandle>, String)) {
    connect_peers(&a.0, &b.1).await;
}

// ─── PART A: revocation gossip accumulation over real mesh peers ────────────

/// A1 — three Managers revoke a device while partitioned; on reconnection every
/// peer accumulates all partial deltas to M=2 and isolates the device within
/// one production gossip round.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partial_revocation_deltas_accumulate_across_offline_managers() {
    let (ca, ca_public) = root_ca();
    let manager_token = token_with_role(&ca, "RevocationManager");

    let mut deployment = mesh_deployment();
    deployment.revocation_m = 2;
    deployment.revocation_n = 3;
    deployment.root_ca_keys = vec![ca_public];

    let m1 = init_peer("ws4_rev_m1", deployment.clone()).await;
    let m2 = init_peer("ws4_rev_m2", deployment.clone()).await;
    let m3 = init_peer("ws4_rev_m3", deployment.clone()).await;
    // The device being revoked: an isolated handle (never dialled), so the only
    // way its identity can be revoked is the Manager gossip itself.
    let target = init_peer("ws4_rev_target", deployment.clone()).await;

    let target_did = target.0.identity.did().to_string();
    let m1_did = m1.0.identity.did().to_string();
    let m2_did = m2.0.identity.did().to_string();

    // The mesh is genuinely partitioned: no peer is connected yet.
    for (name, peer) in [("m1", &m1), ("m2", &m2), ("m3", &m3)] {
        assert_eq!(
            peer.0.mesh_status().peer_count,
            0,
            "{name} must start disconnected so the accumulation is genuinely offline"
        );
    }

    let now = now_secs();
    for peer in [&m1, &m2, &m3] {
        peer.0
            .initiate_revocation(&target_did, &manager_token, now)
            .expect("a RevocationManager token must initiate revocation");
        assert_eq!(
            accumulation(&peer.0, &target_did),
            Some(RevocationStatus::Pending {
                collected: 1,
                required: 2
            }),
            "each Manager must hold exactly its own partial delta before reconnecting"
        );
        assert_eq!(
            revoked_status(&peer.0, &target_did),
            None,
            "one signature of two must never revoke"
        );
    }

    // HIGH-priority classification is observable at the publish point: the
    // partial delta left the scheduler as an InboundDelta wrapper marked High
    // that carries a GossipMessage::InboundRevocationDelta for the target.
    for (name, peer) in [("m1", &m1), ("m2", &m2), ("m3", &m3)] {
        wait_until(
            || published_revocation_envelope(&peer.0, &target_did),
            Duration::from_secs(2),
            &format!("{name} to publish a HIGH-priority revocation envelope"),
        )
        .await;
    }

    // Reconnect the full mesh.
    connect_pair(&m1, &m2).await;
    connect_pair(&m1, &m3).await;
    connect_pair(&m2, &m3).await;
    // Let the gossipsub subscription exchange settle before timing the round.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Isolation timing: measure from the FIRST peer that observes the revoked
    // state to the LAST one. That is exactly the propagation delay of one
    // gossip round (the HIGH-priority envelope fanning out over the mesh),
    // independent of how long the mesh takes to deliver the first copy on a
    // loaded machine.
    let mut first_seen: Option<u64> = None;
    wait_until(
        || {
            let any = [&m1, &m2, &m3]
                .iter()
                .any(|p| revoked_status(&p.0, &target_did) == Some(TrustLevel::Revoked));
            if any && first_seen.is_none() {
                first_seen = Some(crate::traits::monotonic_now());
            }
            [&m1, &m2, &m3]
                .iter()
                .all(|p| revoked_status(&p.0, &target_did) == Some(TrustLevel::Revoked))
        },
        Duration::from_secs(15),
        "every peer to isolate the revoked device",
    )
    .await;
    let elapsed = crate::traits::monotonic_now() - first_seen.expect("a first observer exists");
    assert!(
        elapsed <= ONE_GOSSIP_ROUND_MICROS,
        "revocation must reach every peer within one production gossip round of the first \
         observer ({ONE_GOSSIP_ROUND_MICROS} µs), took {elapsed} µs"
    );

    // Req 9.5: each peer observed and recorded the revocation causally.
    for peer in [&m1, &m2, &m3] {
        let status = peer
            .0
            .device_revocation_status(&target_did)
            .expect("status query")
            .expect("a revocation delta must be recorded");
        assert_eq!(status.last_known_trust_level, TrustLevel::Revoked);
        assert!(
            status.last_revocation_delta_received_at.unwrap_or_default() > 0,
            "the revocation receipt timestamp must be recorded"
        );

        let applied = peer
            .0
            .revocation
            .lock()
            .expect("revocation mutex")
            .build_recent_revocation_deltas(24 * 3600 * 1_000_000);
        let record = applied
            .iter()
            .find(|d| d.target_did == target_did)
            .expect("the applied RevocationDelta must be recoverable");
        assert_eq!(
            record.signatures.len(),
            2,
            "exactly M signatures must be recorded — no extra contribution"
        );
        assert!(record.created_at > 0, "the delta must be causally timestamped");
    }

    // Immutability: replaying a Manager's contribution after the threshold is
    // met must not append to the recorded delta (fail-closed, idempotent).
    let recorded_before = m1
        .0
        .revocation
        .lock()
        .expect("revocation mutex")
        .build_recent_revocation_deltas(24 * 3600 * 1_000_000);
    let created_at_before = recorded_before[0].created_at;
    m1.0.initiate_revocation(&target_did, &manager_token, now)
        .expect("a replayed initiation is idempotently Applied");
    let recorded_after = m1
        .0
        .revocation
        .lock()
        .expect("revocation mutex")
        .build_recent_revocation_deltas(24 * 3600 * 1_000_000);
    assert_eq!(
        recorded_after[0].signatures.len(),
        2,
        "an applied RevocationDelta is immutable"
    );
    assert_eq!(
        recorded_after[0].created_at, created_at_before,
        "the recorded delta must not be rewritten by a replay"
    );

    // Req 8.6: the revoked device's subsequent Deltas are rejected at
    // `apply_incoming_delta` on EVERY peer, while an honest author still merges.
    let forged = signed_row_delta(&target.0, "revoked", "row-1", &json!({ "seq": 1 }));
    let forged_id = forged.id;
    publish(&m1.0, &m2_did, &forged);
    publish(&m1.0, &m3.0.identity.did().to_string(), &forged);

    // Direct production merge call: the gate itself must reject it.
    {
        let mut crdt = m2.0.crdt.lock().expect("crdt mutex");
        let outcome =
            crate::crdt::merge::apply_incoming_delta(&mut crdt, &forged).expect("merge attempt");
        assert!(
            matches!(
                outcome,
                crate::crdt::merge::MergeOutcome::Rejected { .. }
            ),
            "apply_incoming_delta must reject a Delta authored by a revoked DID, got {outcome:?}"
        );
    }

    let control = signed_row_delta(&m1.0, "revoked", "row-control", &json!({ "seq": 2 }));
    publish(&m1.0, &m2_did, &control);
    wait_for_data(
        &m2.0,
        "revoked",
        "row-control",
        &json!({ "seq": 2 }),
        Duration::from_secs(10),
    )
    .await;

    // The rejected Delta never merged nor projected on any peer.
    tokio::time::sleep(Duration::from_millis(300)).await;
    for peer in [&m2, &m3] {
        assert!(
            peer.0
                .crdt
                .lock()
                .expect("crdt mutex")
                .dag_node(&forged_id)
                .expect("dag lookup")
                .is_none(),
            "a revoked author's Delta must not reach the DAG"
        );
        assert!(
            peer.0.read("revoked", "row-1").await.is_err(),
            "a revoked author's Delta must not be projected"
        );
    }

    let _ = m1_did;
    for suffix in ["ws4_rev_m1", "ws4_rev_m2", "ws4_rev_m3", "ws4_rev_target"] {
        cleanup(&tmp_path(suffix));
    }
}

/// A2 — M-1 of N never revokes; the M-th signature always does, over the mesh.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn below_threshold_never_revokes_and_threshold_signature_always_does() {
    let (ca, ca_public) = root_ca();
    let manager_token = token_with_role(&ca, "RevocationManager");

    let mut deployment = mesh_deployment();
    deployment.revocation_m = 3;
    deployment.revocation_n = 3;
    deployment.root_ca_keys = vec![ca_public];

    let m1 = init_peer("ws4_mthr_m1", deployment.clone()).await;
    let m2 = init_peer("ws4_mthr_m2", deployment.clone()).await;
    let m3 = init_peer("ws4_mthr_m3", deployment.clone()).await;
    let target = init_peer("ws4_mthr_target", deployment.clone()).await;
    let target_did = target.0.identity.did().to_string();

    // Two of the three Managers contribute while partitioned — M-1 = 2.
    let now = now_secs();
    for peer in [&m1, &m2] {
        peer.0
            .initiate_revocation(&target_did, &manager_token, now)
            .expect("initiate revocation");
    }

    connect_pair(&m1, &m2).await;
    connect_pair(&m1, &m3).await;
    connect_pair(&m2, &m3).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Give the mesh two full gossip rounds: M-1 must never revoke.
    tokio::time::sleep(Duration::from_micros(ONE_GOSSIP_ROUND_MICROS * 2)).await;
    for (name, peer) in [("m1", &m1), ("m2", &m2), ("m3", &m3)] {
        assert_eq!(
            revoked_status(&peer.0, &target_did),
            None,
            "{name} must not revoke with M-1 = 2 signatures"
        );
        assert_eq!(
            accumulation(&peer.0, &target_did),
            Some(RevocationStatus::Pending {
                collected: 2,
                required: 3
            }),
            "{name} must hold exactly the two accumulated signatures"
        );
    }

    // The M-th Manager contributes: every peer must now apply the revocation.
    m3.0.initiate_revocation(&target_did, &manager_token, now)
        .expect("initiate revocation");
    let mut first_seen: Option<u64> = None;
    wait_until(
        || {
            let any = [&m1, &m2, &m3]
                .iter()
                .any(|p| revoked_status(&p.0, &target_did) == Some(TrustLevel::Revoked));
            if any && first_seen.is_none() {
                first_seen = Some(crate::traits::monotonic_now());
            }
            [&m1, &m2, &m3]
                .iter()
                .all(|p| revoked_status(&p.0, &target_did) == Some(TrustLevel::Revoked))
        },
        Duration::from_secs(15),
        "the M-th signature to revoke on every peer",
    )
    .await;
    let elapsed = crate::traits::monotonic_now() - first_seen.expect("a first observer exists");
    assert!(
        elapsed <= ONE_GOSSIP_ROUND_MICROS,
        "threshold-triggered revocation must reach every peer within one gossip round of the \
         first observer, took {elapsed} µs"
    );

    for suffix in ["ws4_mthr_m1", "ws4_mthr_m2", "ws4_mthr_m3", "ws4_mthr_target"] {
        cleanup(&tmp_path(suffix));
    }
}

/// A3 — negative cases fail closed on the receiving peer: duplicate signatures,
/// cross-target replays, and expired / wrong-role / foreign-CA manager tokens.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_negative_cases_fail_closed() {
    use crate::auth::{ManagerSignature, RevocationDelta};

    let (ca, ca_public) = root_ca();
    let manager_token = token_with_role(&ca, "RevocationManager");

    let mut deployment = mesh_deployment();
    deployment.revocation_m = 2;
    deployment.revocation_n = 3;
    deployment.root_ca_keys = vec![ca_public];

    let p = init_peer("ws4_neg_p", deployment.clone()).await;
    let q = init_peer("ws4_neg_q", deployment.clone()).await;
    connect_pair(&p, &q).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let q_did = q.0.identity.did().to_string();
    let p_did = p.0.identity.did().to_string();
    let target = "did:key:z6MkNegativeTarget".to_string();
    let other_target = "did:key:z6MkOtherTarget".to_string();

    let p_sig = |payload_target: &str| -> ManagerSignature {
        let payload = RevocationDelta::signing_payload(payload_target);
        ManagerSignature {
            manager_did: p_did.clone(),
            signature: crate::identity::keypair::sign(
                &p.0.identity.signing_key_bytes(),
                &payload,
            )
            .expect("sign"),
        }
    };

    // (a) Duplicate manager signature: counts once, not twice.
    let duplicate = RevocationDelta {
        target_did: target.clone(),
        signatures: vec![p_sig(&target), p_sig(&target)],
        created_at: now_secs(),
    };
    publish(
        &p.0,
        &q_did,
        &control_envelope(
            super::REVOCATION_GOSSIP_AUTHOR,
            &GossipMessage::InboundRevocationDelta(duplicate),
            0,
        ),
    );
    wait_until(
        || accumulation(&q.0, &target).is_some(),
        Duration::from_secs(5),
        "the peer to accumulate the first partial delta",
    )
    .await;
    assert_eq!(
        accumulation(&q.0, &target),
        Some(RevocationStatus::Pending {
            collected: 1,
            required: 2
        }),
        "a duplicated Manager signature must never count twice"
    );

    // (b) Cross-target replay: a signature over target A presented for target B.
    let replayed = RevocationDelta {
        target_did: other_target.clone(),
        signatures: vec![p_sig(&target)],
        created_at: now_secs(),
    };
    publish(
        &p.0,
        &q_did,
        &control_envelope(
            super::REVOCATION_GOSSIP_AUTHOR,
            &GossipMessage::InboundRevocationDelta(replayed),
            1,
        ),
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        accumulation(&q.0, &other_target),
        None,
        "a signature bound to another target DID must be rejected outright"
    );
    assert_eq!(
        revoked_status(&q.0, &other_target),
        None,
        "a cross-target replay must never revoke"
    );

    // (c) Expired manager token: rejected before any signature is produced.
    let err = p
        .0
        .initiate_revocation(&target, &manager_token, now_secs() + 7_200)
        .expect_err("an expired manager token must be rejected");
    assert!(
        matches!(err, TirBaseError::AuthorisationFailed { .. }),
        "expected AuthorisationFailed for an expired token, got {err}"
    );

    // (d) Unauthorised role: a valid token, but not a RevocationManager.
    let auditor = token_with_role(&ca, "Auditor");
    let err = p
        .0
        .initiate_revocation(&target, &auditor, now_secs())
        .expect_err("a non-RevocationManager role must be rejected");
    assert!(
        matches!(err, TirBaseError::AuthorisationFailed { .. }),
        "expected AuthorisationFailed for a wrong role, got {err}"
    );

    // (e) Foreign CA: a token this deployment does not trust.
    let (foreign, _) = root_ca();
    let foreign_token = token_with_role(&foreign, "RevocationManager");
    let err = p
        .0
        .initiate_revocation(&target, &foreign_token, now_secs())
        .expect_err("a foreign-CA token must be rejected");
    assert!(
        matches!(err, TirBaseError::AuthorisationFailed { .. }),
        "expected AuthorisationFailed for a foreign CA, got {err}"
    );
    assert_eq!(
        accumulation(&p.0, &target),
        Some(RevocationStatus::Pending {
            collected: 1,
            required: 2
        }),
        "a rejected initiation must not contribute any signature"
    );

    // (f) Complete the threshold with the peer's real Manager signature, then
    // replay the completed delta and a late third signature: both are no-ops.
    let q_signature = {
        let payload = RevocationDelta::signing_payload(&target);
        ManagerSignature {
            manager_did: q_did.clone(),
            signature: crate::identity::keypair::sign(
                &q.0.identity.signing_key_bytes(),
                &payload,
            )
            .expect("sign"),
        }
    };
    let complete = RevocationDelta {
        target_did: target.clone(),
        signatures: vec![p_sig(&target), q_signature],
        created_at: now_secs(),
    };
    publish(
        &p.0,
        &q_did,
        &control_envelope(
            super::REVOCATION_GOSSIP_AUTHOR,
            &GossipMessage::InboundRevocationDelta(complete.clone()),
            2,
        ),
    );
    wait_until(
        || revoked_status(&q.0, &target) == Some(TrustLevel::Revoked),
        Duration::from_secs(5),
        "the peer to apply the M-of-N revocation",
    )
    .await;

    let recorded_at = q
        .0
        .revocation
        .lock()
        .expect("revocation mutex")
        .build_recent_revocation_deltas(24 * 3600 * 1_000_000)
        .into_iter()
        .find(|d| d.target_did == target)
        .expect("applied delta")
        .created_at;

    // Replayed complete delta.
    publish(
        &p.0,
        &q_did,
        &control_envelope(
            super::REVOCATION_GOSSIP_AUTHOR,
            &GossipMessage::InboundRevocationDelta(complete),
            3,
        ),
    );
    // A third distinct (self-certified) Manager contribution after the fact.
    let late_key = ed25519_dalek::SigningKey::from_bytes(&[0x5Au8; 32]);
    let late_did =
        crate::crdt::derive_did_from_public_key(&late_key.verifying_key().to_bytes());
    let late_payload = RevocationDelta::signing_payload(&target);
    let late = RevocationDelta {
        target_did: target.clone(),
        signatures: vec![ManagerSignature {
            manager_did: late_did,
            signature: crate::identity::keypair::sign(&late_key.to_bytes(), &late_payload)
                .expect("sign"),
        }],
        created_at: now_secs(),
    };
    publish(
        &p.0,
        &q_did,
        &control_envelope(
            super::REVOCATION_GOSSIP_AUTHOR,
            &GossipMessage::InboundRevocationDelta(late),
            4,
        ),
    );

    tokio::time::sleep(Duration::from_millis(500)).await;
    let applied = q
        .0
        .revocation
        .lock()
        .expect("revocation mutex")
        .build_recent_revocation_deltas(24 * 3600 * 1_000_000)
        .into_iter()
        .find(|d| d.target_did == target)
        .expect("applied delta");
    assert_eq!(
        applied.signatures.len(),
        2,
        "an applied RevocationDelta is immutable: replays and late signatures must not extend it"
    );
    assert_eq!(
        applied.created_at, recorded_at,
        "a replayed revocation must not rewrite the causal timestamp"
    );

    cleanup(&tmp_path("ws4_neg_p"));
    cleanup(&tmp_path("ws4_neg_q"));
}

// ─── PART B: M-of-N Saturate_Mode termination ───────────────────────────────

/// B1 — real CoreHandle path: activation routes HIGH only, MEDIUM/LOW are held
/// without drop, and M-of-N termination clears the scheduler mirror.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saturate_activation_routes_high_only_and_holds_medium_low() {
    use ed25519_dalek::{Signer, SigningKey};

    let (ca, ca_public) = root_ca();
    let mut deployment = mesh_deployment();
    deployment.revocation_m = 2;
    deployment.revocation_n = 3;
    deployment.root_ca_keys = vec![ca_public];

    let port = reserve_loopback_port();
    let handle = init_mesh_handle_with_deployment("ws4_sat_route", port, deployment).await;
    CoreHandle::spawn_scheduler_tick_loop(&handle, Duration::from_millis(10));

    let token = disaster_alert_token(&ca);
    handle
        .activate_saturate_mode(&token)
        .expect("a valid DISASTER_ALERT token must activate Saturate_Mode");

    {
        let transport = handle.transport.lock().expect("transport mutex");
        assert_eq!(
            transport.saturate.state(),
            crate::transport::saturate::SaturateState::Saturate
        );
        assert!(
            transport.scheduler.is_saturate_mode(),
            "the DRR scheduler mirror must follow activation"
        );
    }

    // One Delta per priority class through the production scheduler queue.
    let delta_with = |priority: PriorityClass, tag: u8| Delta {
        id: [tag; 32],
        author_did: "did:key:z6MkSchedulerProbe".to_string(),
        signature: crate::crdt::delta::Ed25519Signature::default(),
        schema_hash: [0u8; 32],
        automerge_bytes: vec![tag],
        priority,
        causal_parents: vec![],
        tags: vec![],
        lamport: 1,
        created_at: 0,
    };
    {
        let mut transport = handle.transport.lock().expect("transport mutex");
        transport.enqueue_outbound(delta_with(PriorityClass::High, 0x01));
        transport.enqueue_outbound(delta_with(PriorityClass::Medium, 0x02));
        transport.enqueue_outbound(delta_with(PriorityClass::Low, 0x03));
        assert_eq!(transport.scheduler.high_queue_depth(), 1);
        assert_eq!(transport.scheduler.medium_queue_depth(), 1);
        assert_eq!(transport.scheduler.low_queue_depth(), 1);
    }

    // In Saturate_Mode the production tick loop drains HIGH only; MEDIUM and LOW
    // must remain queued (held, never dropped).
    wait_until(
        || handle.transport.lock().expect("transport mutex").scheduler.high_queue_depth() == 0,
        Duration::from_secs(2),
        "the HIGH queue to be served in Saturate_Mode",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    {
        let transport = handle.transport.lock().expect("transport mutex");
        assert_eq!(
            transport.scheduler.medium_queue_depth(),
            1,
            "MEDIUM must be held without drop while Saturate_Mode is active"
        );
        assert_eq!(
            transport.scheduler.low_queue_depth(),
            1,
            "LOW must be held without drop while Saturate_Mode is active"
        );
    }

    // M-of-N termination: the canonical lease-bound message plus one real
    // co-manager signature meets the configured M = 2.
    let message = handle
        .saturate_termination_message()
        .expect("an active lease must expose a canonical termination message");
    let canonical = crate::transport::saturate::SaturateModeStateMachine::parse_termination_message(
        &message,
    )
    .expect("the canonical message must parse");
    assert_eq!(
        canonical.0, canonical.1,
        "the message epoch must be the lease activation timestamp"
    );

    let co_key = SigningKey::from_bytes(&[0x33u8; 32]);
    let co_did = crate::crdt::derive_did_from_public_key(&co_key.verifying_key().to_bytes());
    let co_sig = co_key.sign(&message).to_bytes().to_vec();
    handle
        .terminate_saturate_mode(&message, vec![(co_did, co_sig)])
        .expect("M-of-N termination must succeed with real distinct signatures");

    {
        let transport = handle.transport.lock().expect("transport mutex");
        assert_eq!(
            transport.saturate.state(),
            crate::transport::saturate::SaturateState::Normal
        );
        assert!(transport.saturate.lease().is_none(), "lease must be cleared");
        assert!(
            !transport.scheduler.is_saturate_mode(),
            "the scheduler mirror must be cleared by M-of-N termination"
        );
    }

    // Service resumes: the held MEDIUM/LOW Deltas are served after termination.
    wait_until(
        || {
            let transport = handle.transport.lock().expect("transport mutex");
            transport.scheduler.medium_queue_depth() == 0
                && transport.scheduler.low_queue_depth() == 0
        },
        Duration::from_secs(2),
        "held MEDIUM/LOW Deltas to be served after termination",
    )
    .await;

    cleanup(&tmp_path("ws4_sat_route"));
}

/// B2 — heartbeat renewal extends the configured lease, is bounded to one
/// window per renewal, and requires a valid DISASTER_ALERT token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saturate_renewal_is_bounded_and_requires_valid_tokens() {
    let (ca, ca_public) = root_ca();
    let mut deployment = mesh_deployment();
    deployment.revocation_m = 2;
    deployment.revocation_n = 3;
    deployment.root_ca_keys = vec![ca_public];
    deployment.saturate_lease_duration_secs = 60;

    let port = reserve_loopback_port();
    let handle = init_mesh_handle_with_deployment("ws4_sat_renew", port, deployment).await;

    let token = disaster_alert_token(&ca);
    handle
        .activate_saturate_mode(&token)
        .expect("activation with a valid token");

    let window = |h: &CoreHandle| {
        let transport = h.transport.lock().expect("transport mutex");
        let lease = transport.saturate.lease().expect("lease").clone();
        (lease.activated_at, lease.expires_at, lease.last_renewed_at)
    };

    let (activated_at, first_expiry, first_renew) = window(&handle);
    assert_eq!(
        first_expiry - activated_at,
        60,
        "activation must open the configured 60s window"
    );
    assert!(first_renew.is_none(), "no heartbeat yet");

    // Valid heartbeat extends the lease by the configured window from `now`.
    handle.renew_saturate_mode(&token).expect("valid renewal");
    let (_, renewed_expiry, renewed_at) = window(&handle);
    assert!(renewed_at.is_some(), "renewal must record last_renewed_at");
    assert!(
        renewed_expiry >= first_expiry,
        "renewal must not shorten the lease window"
    );
    assert!(
        renewed_expiry - renewed_at.unwrap() == 60,
        "a renewal is bounded to exactly one configured window"
    );

    // Repeated renewal stays within one window — it never accumulates.
    handle.renew_saturate_mode(&token).expect("second renewal");
    let (_, third_expiry, third_renew) = window(&handle);
    assert_eq!(
        third_expiry - third_renew.unwrap(),
        60,
        "repeated renewal must not accumulate windows"
    );
    assert!(third_expiry >= renewed_expiry);

    // Invalid tokens are rejected and preserve the lease.
    let (foreign, _) = root_ca();
    let foreign_token = disaster_alert_token(&foreign);
    let err = handle
        .renew_saturate_mode(&foreign_token)
        .expect_err("a foreign-CA token must not renew the lease");
    assert!(
        matches!(
            err,
            TirBaseError::AuthorisationFailed { .. }
                | TirBaseError::SignatureVerificationFailed { .. }
        ),
        "expected an authorisation/verification error, got {err}"
    );

    let without_caveat = token_with_role(&ca, "manager");
    let err = handle
        .renew_saturate_mode(&without_caveat)
        .expect_err("a token without the disaster-alert caveat must not renew");
    assert!(
        matches!(err, TirBaseError::SignatureVerificationFailed { .. }),
        "expected SignatureVerificationFailed for a missing caveat, got {err}"
    );
    let (_, unchanged_expiry, _) = window(&handle);
    assert_eq!(
        unchanged_expiry, third_expiry,
        "a rejected renewal must not move the lease"
    );

    // A device that is not in Saturate_Mode cannot renew at all.
    let port_b = reserve_loopback_port();
    let other = init_mesh_handle_with_deployment(
        "ws4_sat_renew_b",
        port_b,
        {
            let mut d = mesh_deployment();
            d.revocation_m = 2;
            d.revocation_n = 3;
            d.root_ca_keys = vec![ca.public_key_bytes().try_into().unwrap()];
            d
        },
    )
    .await;
    let err = other
        .renew_saturate_mode(&token)
        .expect_err("renewal outside SATURATE must fail");
    assert!(
        matches!(err, TirBaseError::SignatureVerificationFailed { .. }),
        "expected SignatureVerificationFailed outside SATURATE, got {err}"
    );

    cleanup(&tmp_path("ws4_sat_renew"));
    cleanup(&tmp_path("ws4_sat_renew_b"));
}

/// B4a — fewer than M co-signatures preserves SATURATE across the real mesh.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saturate_termination_below_threshold_preserves_mode_over_mesh() {
    let (ca, ca_public) = root_ca();
    let mut deployment = mesh_deployment();
    deployment.revocation_m = 3;
    deployment.revocation_n = 3;
    deployment.root_ca_keys = vec![ca_public];

    let a = init_peer("ws4_sat_below_a", deployment.clone()).await;
    let b = init_peer("ws4_sat_below_b", deployment.clone()).await;
    let token = disaster_alert_token(&ca);
    a.0.activate_saturate_mode(&token).expect("activate A");
    b.0.activate_saturate_mode(&token).expect("activate B");

    connect_pair(&a, &b).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    a.0.request_saturate_termination()
        .expect("A must be able to request termination");
    assert_eq!(
        a.0.saturate_termination_signature_count(),
        1,
        "only A's own signature is collected at request time"
    );

    // The peer co-signs and re-broadcasts; 2 of M=3 must never terminate.
    wait_until(
        || a.0.saturate_termination_signature_count() >= 2,
        Duration::from_micros(ONE_GOSSIP_ROUND_MICROS * 3),
        "B's co-signature to reach A",
    )
    .await;
    tokio::time::sleep(Duration::from_micros(ONE_GOSSIP_ROUND_MICROS * 2)).await;

    for (name, peer) in [("A", &a), ("B", &b)] {
        let transport = peer.0.transport.lock().expect("transport mutex");
        assert_eq!(
            transport.saturate.state(),
            crate::transport::saturate::SaturateState::Saturate,
            "{name} must stay in SATURATE below the M-of-N threshold"
        );
        assert!(
            transport.scheduler.is_saturate_mode(),
            "{name}'s scheduler mirror must stay in Saturate_Mode"
        );
    }
    assert_eq!(
        a.0.saturate_termination_signature_count(),
        2,
        "exactly two distinct Manager signatures were collected"
    );

    cleanup(&tmp_path("ws4_sat_below_a"));
    cleanup(&tmp_path("ws4_sat_below_b"));
}

/// B4b — M-of-N termination collected over the real mesh: invalid, duplicate,
/// stale and wrong-message co-signatures are rejected; M distinct valid ones
/// terminate every peer and clear the scheduler mirror.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saturate_termination_m_of_n_collected_over_real_mesh() {
    use ed25519_dalek::{Signer, SigningKey};

    let (ca, ca_public) = root_ca();
    let mut deployment = mesh_deployment();
    deployment.revocation_m = 3;
    deployment.revocation_n = 3;
    deployment.root_ca_keys = vec![ca_public];

    let a = init_peer("ws4_sat_mon_a", deployment.clone()).await;
    let b = init_peer("ws4_sat_mon_b", deployment.clone()).await;
    let c = init_peer("ws4_sat_mon_c", deployment.clone()).await;

    let token = disaster_alert_token(&ca);
    for (name, peer) in [("A", &a), ("B", &b), ("C", &c)] {
        peer.0
            .activate_saturate_mode(&token)
            .unwrap_or_else(|e| panic!("{name} activation must succeed: {e}"));
    }

    connect_pair(&a, &b).await;
    connect_pair(&a, &c).await;
    connect_pair(&b, &c).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let b_did = b.0.identity.did().to_string();
    let c_did = c.0.identity.did().to_string();
    let now = now_secs();
    let a_message = a
        .0
        .saturate_termination_message()
        .expect("A's canonical termination message");

    // (1) Invalid signature over A's canonical message: rejected, no vote.
    publish(
        &b.0,
        &a.0.identity.did().to_string(),
        &control_envelope(
            super::SATURATE_GOSSIP_AUTHOR,
            &GossipMessage::SaturateTerminationCoSignature {
                message: a_message.clone(),
                signer_did: b_did.clone(),
                signature: vec![0u8; 64],
            },
            10,
        ),
    );

    // (2) A real signature over a DIFFERENT (wrong) message: rejected because
    // the signature does not verify over the message it is carried with.
    let stale_key = b.0.identity.signing_key_bytes();
    let wrong_message = format!(
        "tirbase:saturate-terminate:v1|epoch={}|activated_at={}|expires_at={}|manager=did:key:z6MkOtherLease",
        now - 5,
        now - 5,
        now + 3_600
    )
    .into_bytes();
    let wrong_sig = crate::identity::keypair::sign(&stale_key, &a_message).expect("sign");
    publish(
        &b.0,
        &a.0.identity.did().to_string(),
        &control_envelope(
            super::SATURATE_GOSSIP_AUTHOR,
            &GossipMessage::SaturateTerminationCoSignature {
                message: wrong_message,
                signer_did: b_did.clone(),
                signature: wrong_sig.0,
            },
            11,
        ),
    );

    // (3) A signature over a well-formed but EXPIRED lease message: rejected by
    // the lease-window check even though the signature itself verifies.
    let expired_message = format!(
        "tirbase:saturate-terminate:v1|epoch={}|activated_at={}|expires_at={}|manager=did:key:z6MkOtherLease",
        now - 7_200,
        now - 7_200,
        now - 3_600
    )
    .into_bytes();
    let expired_sig =
        crate::identity::keypair::sign(&stale_key, &expired_message).expect("sign");
    publish(
        &b.0,
        &a.0.identity.did().to_string(),
        &control_envelope(
            super::SATURATE_GOSSIP_AUTHOR,
            &GossipMessage::SaturateTerminationCoSignature {
                message: expired_message,
                signer_did: b_did.clone(),
                signature: expired_sig.0,
            },
            12,
        ),
    );

    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        a.0.saturate_termination_signature_count(),
        0,
        "invalid, wrong-message and expired co-signatures must not be counted"
    );
    {
        let transport = a.0.transport.lock().expect("transport mutex");
        assert_eq!(
            transport.saturate.state(),
            crate::transport::saturate::SaturateState::Saturate,
            "rejected co-signatures must leave the mode untouched"
        );
    }

    // (4) Duplicate co-signature: the same (message, signer, signature) is
    // presented twice. The duplicate must be idempotent, not a second vote.
    let b_signing_key = b.0.identity.signing_key_bytes();
    let duplicate_signature =
        crate::identity::keypair::sign(&b_signing_key, &a_message).expect("sign");
    {
        let mut transport = a.0.transport.lock().expect("transport mutex");
        let first = transport
            .saturate
            .record_termination_signature(&a_message, &b_did, &duplicate_signature.0, now)
            .expect("a genuine co-signature must be recorded");
        assert_eq!(first, 1, "the first contribution is one distinct vote");
        let second = transport
            .saturate
            .record_termination_signature(&a_message, &b_did, &duplicate_signature.0, now)
            .expect("a duplicate contribution is idempotent");
        assert_eq!(
            second, 1,
            "a duplicated Manager signature must never count twice toward M"
        );
        assert_eq!(
            transport.saturate.state(),
            crate::transport::saturate::SaturateState::Saturate,
            "one vote of three must not terminate"
        );
    }

    // A requests termination: its own signature joins the collected set, and B
    // and C co-sign over the mesh until M = 3 is reached on every peer.
    let message = a
        .0
        .request_saturate_termination()
        .expect("A must be able to request termination over the mesh");
    assert_eq!(
        a.0.saturate_termination_signature_count(),
        2,
        "A's own signature joins the already-collected one"
    );

    // C's genuine co-signature completes M=3 on every peer.
    let round_start = crate::traits::monotonic_now();
    wait_until(
        || {
            [&a, &b, &c].iter().all(|p| {
                let transport = p.0.transport.lock().expect("transport mutex");
                transport.saturate.state() == crate::transport::saturate::SaturateState::Normal
                    && !transport.scheduler.is_saturate_mode()
            })
        },
        Duration::from_micros(ONE_GOSSIP_ROUND_MICROS * 4),
        "M-of-N termination to land on every peer and clear the scheduler mirror",
    )
    .await;
    let elapsed = crate::traits::monotonic_now() - round_start;
    assert!(
        elapsed <= ONE_GOSSIP_ROUND_MICROS * 2,
        "mesh-collected termination should converge within two gossip rounds, took {elapsed} µs"
    );

    for (name, peer) in [("A", &a), ("B", &b), ("C", &c)] {
        let transport = peer.0.transport.lock().expect("transport mutex");
        assert!(
            transport.saturate.lease().is_none(),
            "{name}'s lease must be cleared by termination"
        );
        assert!(
            !transport.scheduler.is_saturate_mode(),
            "{name}'s scheduler mirror must leave Saturate_Mode"
        );
    }

    // After termination the canonical message no longer exists and renewal is
    // rejected, so the state machine and mirror stay consistent.
    assert!(a.0.saturate_termination_message().is_none());
    assert!(a.0.renew_saturate_mode(&token).is_err());

    let _ = c_did;
    for suffix in ["ws4_sat_mon_a", "ws4_sat_mon_b", "ws4_sat_mon_c"] {
        cleanup(&tmp_path(suffix));
    }
}

/// B (support) — real co-manager signatures self-certify: a signature over a
/// different message or from a different lease epoch cannot terminate.
#[test]
fn canonical_termination_message_is_lease_bound() {
    use crate::transport::saturate::{
        SaturateModeStateMachine, SaturateState, SATURATE_LEASE_DURATION_SECS,
    };

    let (token, ca_pub) = crate::transport::saturate::make_disaster_alert_token_for_test(3600);
    let mut sm = SaturateModeStateMachine::new(2, ca_pub, SATURATE_LEASE_DURATION_SECS);
    let now = now_secs();
    sm.activate("did:key:z6MkManager".to_string(), &token, now)
        .expect("activation");

    let message = sm
        .canonical_termination_message()
        .expect("an active lease has a canonical message");
    let (epoch, activated_at, expires_at, manager) =
        SaturateModeStateMachine::parse_termination_message(&message).expect("canonical shape");
    assert_eq!(epoch, activated_at, "epoch is the lease activation time");
    assert_eq!(activated_at, now);
    assert_eq!(expires_at, now + SATURATE_LEASE_DURATION_SECS);
    assert_eq!(manager, "did:key:z6MkManager");

    // A stale window is rejected before any signature is considered.
    let stale = format!(
        "tirbase:saturate-terminate:v1|epoch={}|activated_at={}|expires_at={}|manager=did:key:z6MkManager",
        now - 10,
        now - 10,
        now - 1
    )
    .into_bytes();
    assert!(
        sm.validate_termination_message(&stale, now).is_err(),
        "an expired lease window must be rejected"
    );

    // A renewal moves the lease epoch, so the old message and any signature set
    // collected for it are no longer current.
    let old_message = message.clone();
    let lease_before = sm.lease().expect("lease").clone();
    sm.renew("did:key:z6MkManager".to_string(), &token, now + 5)
        .expect("renewal");
    let renewed = sm
        .canonical_termination_message()
        .expect("renewed lease message");
    assert_ne!(
        old_message, renewed,
        "renewal must change the canonical termination message (new epoch)"
    );
    assert!(!sm.is_current_termination_message(&old_message));
    assert!(sm.is_current_termination_message(&renewed));
    assert_eq!(sm.collected_termination_signature_count(), 0);
    assert_eq!(sm.state(), SaturateState::Saturate);
    assert!(
        sm.lease().expect("lease").expires_at > lease_before.expires_at,
        "renewal must extend the window"
    );
}
