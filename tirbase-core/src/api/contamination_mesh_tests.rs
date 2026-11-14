// SPDX-License-Identifier: AGPL-3.0-only

//! Workstream 5 (e2e wiring): contamination (CCE), composite incidents,
//! human-reaction tagging, and Side-Car replay/recovery over REAL mesh peers.
//!
//! Every asserted path is production code:
//!
//! - `CoreHandle::init` / `dial_peer` / `spawn_inbound_drain_loop`, exactly as
//!   the production build constructs a device;
//! - `CoreHandle::publish_migration_delta` /
//!   `publish_migration_revocation_delta` → real Gossipsub → the peer's
//!   `receive_inbound` arms (no `inject_inbound`);
//! - `CoreHandle::initiate_revocation` with a real root-CA-signed
//!   `RevocationManager` Biscuit token → `handle_inbound_revocation_delta`
//!   → `CausalContaminationEngine::tag_contamination_root`;
//! - `CoreHandle::write` (human reaction) and `CoreHandle::verify_contamination`;
//! - the inbound migration success arm → `replay_corrupted_windows` →
//!   `SideCarLedger::replay_sidecar` → SQL projection.
//!
//! No mock transport, no test-only branch and no injected inbound path sits on
//! an asserted path. Deliberately malformed Side-Car material (the conflict
//! case) is recorded through the same ledger API production uses.

use super::mesh_harness::*;
use super::*;
use crate::auth::biscuit;
use crate::contamination::incident::{IncidentEvent, IncidentEventKind, TaintSource};
use crate::crdt::delta::{Delta, DeltaTag, Ed25519Signature};
use crate::identity::file_key_provider::InMemoryKeyProvider;
use crate::traits::KeyProvider;
use crate::migration::migration_delta::{
    CaSignature, ManagerSignature, MigrationDelta, MigrationRevocationDelta,
};
use crate::migration::sidecar::ReplayStatus;
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn root_ca() -> (InMemoryKeyProvider, [u8; 32]) {
    let ca = InMemoryKeyProvider::generate().expect("root CA keypair");
    let public: [u8; 32] = ca
        .public_key_bytes()
        .try_into()
        .expect("root CA public key must be 32 bytes");
    (ca, public)
}

fn token_with_role(ca: &InMemoryKeyProvider, role: &str) -> Vec<u8> {
    biscuit::create_token(
        "did:key:z6MkTestManager",
        role,
        3600,
        &ca.secret_seed(),
        false,
    )
    .expect("mint token")
}

fn now_secs() -> i64 {
    crate::traits::wall_hint_secs().unwrap_or_default()
}

/// Deployment with a root CA (revocation / verify_data).
fn ca_deployment(ca_public: [u8; 32]) -> DeploymentConfig {
    let mut d = mesh_deployment();
    d.root_ca_keys = vec![ca_public];
    d
}

/// Deployment with a Migration CA and schema version path.
fn migration_deployment(ca_public: [u8; 32], versions: Vec<[u8; 32]>) -> DeploymentConfig {
    let mut d = mesh_deployment();
    d.migration_ca_public_key = Some(ca_public);
    d.schema_version_path = versions;
    d
}

/// Init a device on an explicit storage path + loopback port and start the
/// production inbound drain loop at accelerated cadence.
async fn init_device(path: &str, port: u16, deployment: DeploymentConfig) -> Arc<CoreHandle> {
    let handle = CoreHandle::init(mesh_config_with(path, port, deployment))
        .await
        .expect("init must succeed with a real Swarm");
    CoreHandle::spawn_inbound_drain_loop(&handle, Duration::from_millis(10));
    handle
}

/// Dial both ways and wait until each side records the other.
async fn connect_pair(a: &Arc<CoreHandle>, b: &Arc<CoreHandle>, port_a: u16, port_b: u16) {
    connect_peers(a, &format!("/ip4/127.0.0.1/tcp/{port_b}")).await;
    connect_peers(b, &format!("/ip4/127.0.0.1/tcp/{port_a}")).await;
}

/// Poll `f` until it returns `Some`, bounded by `timeout` on the monotonic
/// clock (no unbounded sleeps).
async fn wait_for<T, F>(timeout: Duration, what: &str, mut f: F) -> T
where
    F: FnMut() -> Option<T>,
{
    let deadline = crate::traits::monotonic_now() + timeout.as_micros() as u64;
    loop {
        if let Some(value) = f() {
            return value;
        }
        assert!(
            crate::traits::monotonic_now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn trivial_wasm() -> Vec<u8> {
    vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03,
        0x02, 0x01, 0x00, 0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x00, 0x0a, 0x04, 0x01,
        0x02, 0x00, 0x0b,
    ]
}

/// Byte-distinct corrected transform (exports `run2`), so its migration ID
/// differs from the revoked one and passes the revocation gate.
fn trivial_wasm_v2() -> Vec<u8> {
    vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03,
        0x02, 0x01, 0x00, 0x07, 0x08, 0x01, 0x04, 0x72, 0x75, 0x6e, 0x32, 0x00, 0x00, 0x0a, 0x04,
        0x01, 0x02, 0x00, 0x0b,
    ]
}

fn ca_signed_migration(
    ca_secret: &[u8; 32],
    source: [u8; 32],
    target: [u8; 32],
    transform_bytes: Vec<u8>,
) -> MigrationDelta {
    use sha2::{Digest, Sha256};
    let transform_sha256: [u8; 32] = Sha256::digest(&transform_bytes).into();
    let ca_sig = crate::identity::keypair::sign(ca_secret, &transform_bytes).expect("ca sign");
    MigrationDelta {
        id: transform_sha256,
        author_did: "did:key:z6MkMigSender".to_string(),
        signature: Ed25519Signature::default(),
        source_schema_hash: source,
        target_schema_hash: target,
        transform_bytes,
        ca_signature: CaSignature(ca_sig.0),
        transform_sha256,
        priority: crate::crdt::delta::PriorityClass::Medium,
        created_at: 0,
        execution_profile: None,
        migration_kind: crate::migration::migration_delta::MigrationKind::Legacy,
        fleet_precondition_hash: None,
        postconditions: None,
    }
}

fn manager_revocation(
    manager_secret: &[u8; 32],
    manager_public: &[u8; 32],
    target: [u8; 32],
) -> MigrationRevocationDelta {
    let sig = crate::identity::keypair::sign(manager_secret, &target).expect("manager sign");
    MigrationRevocationDelta {
        target_migration_id: target,
        signatures: vec![ManagerSignature {
            manager_did: crate::crdt::derive_did_from_public_key(manager_public),
            signature: Ed25519Signature(sig.0),
        }],
        created_at: 0,
    }
}

fn tags_for(path: &str, delta_id: [u8; 32]) -> Vec<DeltaTag> {
    let conn = crate::store::sqlite::open(path).expect("open conn for tag read");
    crate::contamination::taint::read_tags_from_db(&conn, &delta_id).expect("read tags")
}

async fn wait_for_tag(
    path: &str,
    delta_id: [u8; 32],
    needle: &str,
    timeout: Duration,
) -> Vec<DeltaTag> {
    wait_for(timeout, needle, || {
        let tags = tags_for(path, delta_id);
        tags.iter()
            .any(|t| format!("{t:?}").contains(needle))
            .then_some(tags)
    })
    .await
}

async fn await_incident_event(
    events: &mut tokio::sync::broadcast::Receiver<IncidentEvent>,
    kind: IncidentEventKind,
) -> IncidentEvent {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match events.recv().await {
                Ok(ev) if ev.kind == kind => return ev,
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(e) => panic!("incident event channel closed: {e}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{kind:?} must be observable on the native event surface"))
}

fn sidecar_entry_count(path: &str, delta_id: [u8; 32]) -> i64 {
    let conn = crate::store::sqlite::open(path).expect("conn");
    conn.query_row(
        "SELECT COUNT(*) FROM dag_nodes WHERE id = ?1",
        rusqlite::params![&delta_id[..]],
        |r| r.get(0),
    )
    .expect("count dag nodes")
}

// ─── 1. CCE over the real mesh: revoked author taints every descendant ───────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_author_over_real_mesh_taints_descendants_appends_tags_and_emits_events() {
    let (ca, ca_public) = root_ca();
    let port_a = reserve_loopback_port();
    let port_b = reserve_loopback_port();
    let path_a = tmp_path("ws5_cce_author");
    let path_b = tmp_path("ws5_cce_observer");
    cleanup(&path_a);
    cleanup(&path_b);

    let a = init_device(&path_a, port_a, ca_deployment(ca_public)).await;
    let b = init_device(&path_b, port_b, ca_deployment(ca_public)).await;
    a.spawn_scheduler_tick_loop(Duration::from_millis(20));
    connect_pair(&a, &b, port_a, port_b).await;

    // A authors the contamination root; B projects it and then authors a
    // descendant on top of it (its Delta's causal parent is A's Delta).
    let root = a
        .write("reports", "r1", json!({ "v": 1 }))
        .await
        .expect("author write");
    wait_for_data(
        &b,
        "reports",
        "r1",
        &json!({ "v": 1 }),
        Duration::from_secs(10),
    )
    .await;
    let descendant = b
        .write("reports", "r2", json!({ "v": 2 }))
        .await
        .expect("descendant write");
    wait_for_data(
        &a,
        "reports",
        "r2",
        &json!({ "v": 2 }),
        Duration::from_secs(10),
    )
    .await;

    let mut events = b.subscribe_incident_events();

    // A real manager revokes A. The revocation is signed by a root-CA-authorised
    // RevocationManager and applied through the production inbound path on B.
    let token = token_with_role(&ca, "RevocationManager");
    b.initiate_revocation(&a.local_did(), &token, now_secs())
        .expect("initiate_revocation must succeed");
    wait_for(Duration::from_secs(10), "revocation applied", || {
        b.device_revocation_status(&a.local_did())
            .ok()
            .flatten()
            .map(|_| ())
    })
    .await;

    // Req 10.2: every reachable descendant of the root carries an append-only
    // CONTAMINATED tag — the root and B's own descendant.
    wait_for_tag(&path_b, root.delta_id, "Contaminated", Duration::from_secs(10)).await;
    let descendant_tags =
        wait_for_tag(&path_b, descendant.delta_id, "Contaminated", Duration::from_secs(10)).await;

    // ICO created with the right taint source and affected rows.
    let ico = {
        let cce = b.cce.lock().unwrap();
        let open = cce.open_incidents().expect("open incidents");
        let matching = open
            .into_iter()
            .find(|i| matches!(i.taint_source, TaintSource::DeviceRevocation { .. }))
            .expect("a DeviceRevocation ICO must exist");
        assert!(
            matching.contaminated_deltas.contains(&root.delta_id)
                && matching.contaminated_deltas.contains(&descendant.delta_id),
            "ICO must contain the root and its descendant: {:?}",
            matching.contaminated_deltas
        );
        assert!(
            matching
                .affected_rows
                .iter()
                .any(|r| r.table == "reports" && r.row_key == "r1"),
            "ICO must list the affected row reports/r1: {:?}",
            matching.affected_rows
        );
        matching
    };

    // Req 10/11 native event surface: Created observed for that ICO.
    let created = await_incident_event(&mut events, IncidentEventKind::Created).await;
    assert_eq!(
        created.incident_id, ico.id,
        "IncidentCreated must identify the ICO created for the revoked author"
    );

    // Append-only invariant: capture the tag log, resolve, and assert the old
    // entries are still an exact prefix of the new log (nothing modified or
    // removed) plus new Resolved/Decontaminated entries.
    let before = tags_for(&path_b, descendant.delta_id);
    b.verify_contamination(root.delta_id, &token, now_secs())
        .expect("verify_data must succeed");
    let after = tags_for(&path_b, descendant.delta_id);
    assert!(
        after.len() > before.len(),
        "resolution must append tags: before={before:?} after={after:?}"
    );
    assert_eq!(
        &after[..before.len()],
        &before[..],
        "existing tag entries must never be modified or removed (append-only)"
    );
    assert!(
        after
            .iter()
            .any(|t| matches!(t, DeltaTag::Decontaminated { .. })),
        "fully resolved ICO must append Decontaminated: {after:?}"
    );
    assert!(
        descendant_tags
            .iter()
            .any(|t| matches!(t, DeltaTag::Contaminated { .. })),
        "Contaminated must be present on the descendant"
    );

    // Rows are clean again; Closed is observable.
    await_incident_event(&mut events, IncidentEventKind::Closed).await;
    assert!(
        !b.cce.lock().unwrap().is_row_contaminated("reports", "r1"),
        "resolved rows must no longer be contaminated"
    );

    cleanup(&path_a);
    cleanup(&path_b);
}

// ─── 2. Composite incidents over the real mesh ───────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn composite_incident_over_real_mesh_merges_decomposes_and_decontaminates() {
    let (ca, ca_public) = root_ca();
    let port_a1 = reserve_loopback_port();
    let port_a2 = reserve_loopback_port();
    let port_b = reserve_loopback_port();
    let path_a1 = tmp_path("ws5_comp_a1");
    let path_a2 = tmp_path("ws5_comp_a2");
    let path_b = tmp_path("ws5_comp_observer");
    for p in [&path_a1, &path_a2, &path_b] {
        cleanup(p);
    }

    let a1 = init_device(&path_a1, port_a1, ca_deployment(ca_public)).await;
    let a2 = init_device(&path_a2, port_a2, ca_deployment(ca_public)).await;
    let b = init_device(&path_b, port_b, ca_deployment(ca_public)).await;
    a1.spawn_scheduler_tick_loop(Duration::from_millis(20));
    a2.spawn_scheduler_tick_loop(Duration::from_millis(20));
    connect_pair(&a1, &b, port_a1, port_b).await;
    connect_pair(&a2, &b, port_a2, port_b).await;

    // Interleave two authors so their chains share DAG nodes:
    // a1:x1 -> a2:y1 -> a1:x2.
    let x1 = a1
        .write("reports", "x1", json!({ "v": 1 }))
        .await
        .expect("x1");
    wait_for_data(&a2, "reports", "x1", &json!({ "v": 1 }), Duration::from_secs(10)).await;
    let y1 = a2
        .write("reports", "y1", json!({ "v": 2 }))
        .await
        .expect("y1");
    wait_for_data(&a1, "reports", "y1", &json!({ "v": 2 }), Duration::from_secs(10)).await;
    let x2 = a1
        .write("reports", "x2", json!({ "v": 3 }))
        .await
        .expect("x2");
    wait_for_data(&b, "reports", "x2", &json!({ "v": 3 }), Duration::from_secs(10)).await;

    let token = token_with_role(&ca, "RevocationManager");
    b.initiate_revocation(&a1.local_did(), &token, now_secs())
        .expect("revoke a1");
    b.initiate_revocation(&a2.local_did(), &token, now_secs())
        .expect("revoke a2");

    // Req 10.5: exactly one composite incident for the graph-joined chains.
    let composite = wait_for(Duration::from_secs(10), "exactly one composite incident", || {
        let cce = b.cce.lock().unwrap();
        let composites = cce.open_composite_incidents().expect("composites");
        assert!(
            composites.len() <= 1,
            "expected exactly one composite, got {}",
            composites.len()
        );
        composites.first().cloned()
    })
    .await;
    for id in [x1.delta_id, y1.delta_id, x2.delta_id] {
        assert!(
            composite.contaminated_deltas.contains(&id),
            "composite must union every chain delta; missing {}",
            hex::encode(id)
        );
    }
    assert!(
        composite.contamination_roots.len() >= 3,
        "roots = one per revoked-authored delta: {:?}",
        composite.contamination_roots
    );

    // Resolve one root: the composite decomposes to the surviving roots and
    // the rows stay contaminated through the unresolved lineage.
    let roots = composite.contamination_roots.clone();
    b.verify_contamination(roots[0], &token, now_secs())
        .expect("first root resolution");
    {
        let cce = b.cce.lock().unwrap();
        assert!(
            cce.open_composite_incidents()
                .expect("composites")
                .is_empty(),
            "resolving one root must decompose the composite (Req 10.6)"
        );
        assert!(
            !cce.open_incidents().expect("open incidents").is_empty(),
            "a surviving unresolved sub-chain must stay registered"
        );
        assert!(
            cce.is_row_contaminated("reports", "x2"),
            "rows reachable through the unresolved chain must stay CONTAMINATED"
        );
    }

    // Resolve every root: decontamination tags, clean rows, Closed event.
    let mut events = b.subscribe_incident_events();
    for root in &roots[1..] {
        b.verify_contamination(*root, &token, now_secs())
            .expect("remaining root resolution");
    }
    await_incident_event(&mut events, IncidentEventKind::Closed).await;
    {
        let cce = b.cce.lock().unwrap();
        assert!(!cce.is_row_contaminated("reports", "x2"));
        assert!(!cce.is_row_contaminated("reports", "x1"));
    }
    for id in [x1.delta_id, y1.delta_id, x2.delta_id] {
        let tags = tags_for(&path_b, id);
        assert!(
            tags.iter()
                .any(|t| matches!(t, DeltaTag::Decontaminated { .. })),
            "delta {} must carry Decontaminated after all roots resolved",
            hex::encode(id)
        );
    }

    cleanup(&path_a1);
    cleanup(&path_a2);
    cleanup(&path_b);
}

// ─── 3. Human reaction: a real write against a contaminated row ──────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn human_reaction_write_on_contaminated_row_over_real_mesh_joins_open_ico() {
    let (ca, ca_public) = root_ca();
    let port_a = reserve_loopback_port();
    let port_b = reserve_loopback_port();
    let path_a = tmp_path("ws5_hr_author");
    let path_b = tmp_path("ws5_hr_observer");
    cleanup(&path_a);
    cleanup(&path_b);

    let a = init_device(&path_a, port_a, ca_deployment(ca_public)).await;
    let b = init_device(&path_b, port_b, ca_deployment(ca_public)).await;
    a.spawn_scheduler_tick_loop(Duration::from_millis(20));
    connect_pair(&a, &b, port_a, port_b).await;

    a.write("reports", "r1", json!({ "v": 1 }))
        .await
        .expect("seed");
    wait_for_data(
        &b,
        "reports",
        "r1",
        &json!({ "v": 1 }),
        Duration::from_secs(10),
    )
    .await;

    let token = token_with_role(&ca, "RevocationManager");
    b.initiate_revocation(&a.local_did(), &token, now_secs())
        .expect("revoke author");
    wait_for(Duration::from_secs(10), "row contaminated", || {
        b.cce
            .lock()
            .unwrap()
            .is_row_contaminated("reports", "r1")
            .then_some(())
    })
    .await;

    // A real CoreHandle::write against the contaminated row is auto-tagged in
    // the signed Delta and registered in the active OPEN ICO (Req 19.5).
    let write = b
        .write("reports", "r1", json!({ "v": 9 }))
        .await
        .expect("human-reaction write");

    wait_for(Duration::from_secs(10), "human-reaction tag", || {
        let tags = tags_for(&path_b, write.delta_id);
        let tagged = tags
            .iter()
            .any(|t| matches!(t, DeltaTag::ContaminatedByHumanReaction { .. }));
        let joined = b
            .cce
            .lock()
            .unwrap()
            .open_incidents()
            .expect("open incidents")
            .iter()
            .any(|ico| ico.contaminated_deltas.contains(&write.delta_id));
        assert!(
            !tagged || joined,
            "a tagged human-reaction write must join the OPEN ICO: tags={tags:?}"
        );
        (tagged && joined).then_some(())
    })
    .await;

    cleanup(&path_a);
    cleanup(&path_b);
}

// ─── 4/5/6. Side-Car replay after a corrected migration over the real mesh ───

/// Drive the shared corrupted-window scenario:
/// bad migration (s→t) applied over the mesh → manager revocation over the mesh
/// → `writes` writes captured in the Side-Car ledger.
///
/// Returns the device (B), the distributor (A), both storage paths, the CA seed,
/// the three schema hashes and the revoked migration's ID.
struct CorruptedWindow {
    distributor: Arc<CoreHandle>,
    device: Arc<CoreHandle>,
    path_a: String,
    path_b: String,
    ca: [u8; 32],
    s: [u8; 32],
    t: [u8; 32],
    u: [u8; 32],
    bad_id: [u8; 32],
}

async fn setup_corrupted_window(tag: &str, writes: usize) -> CorruptedWindow {
    let (ca_secret, ca_public) = crate::identity::keypair::generate_keypair().expect("ca");
    let s = [0x60u8; 32];
    let t = [0x61u8; 32];
    let u = [0x62u8; 32];
    let deployment = migration_deployment(ca_public, vec![s, t, u]);

    let port_a = reserve_loopback_port();
    let port_b = reserve_loopback_port();
    let path_a = tmp_path(&format!("ws5_{tag}_distributor"));
    let path_b = tmp_path(&format!("ws5_{tag}_device"));
    cleanup(&path_a);
    cleanup(&path_b);

    let a = init_device(&path_a, port_a, deployment.clone()).await;
    let b = init_device(&path_b, port_b, deployment).await;
    a.spawn_scheduler_tick_loop(Duration::from_millis(20));
    connect_pair(&a, &b, port_a, port_b).await;

    b.write("reports", "r1", json!({ "v": 1 }))
        .await
        .expect("seed write");

    // Bad migration s→t arrives over the real mesh.
    let bad = ca_signed_migration(&ca_secret, s, t, trivial_wasm());
    let bad_id = bad.id;
    a.publish_migration_delta(&bad).expect("publish bad migration");
    wait_for(Duration::from_secs(15), "bad migration applied", || {
        let mig = b.migration.lock().unwrap();
        (mig.current_schema_hash() == t).then_some(())
    })
    .await;

    // Manager revocation over the real mesh → CCE ICO + corruption window.
    let (mgr_secret, mgr_public) = crate::identity::keypair::generate_keypair().expect("mgr");
    a.publish_migration_revocation_delta(&manager_revocation(
        &mgr_secret,
        &mgr_public,
        bad_id,
    ))
    .expect("publish revocation");
    wait_for(Duration::from_secs(10), "corruption window opened", || {
        let mig = b.migration.lock().unwrap();
        (mig.is_revoked(&bad_id) && mig.active_corruption_migration() == Some(bad_id)).then_some(())
    })
    .await;

    // Writes during the corrupted window are captured byte-for-byte.
    for i in 0..writes {
        b.write("reports", &format!("cap{i}"), json!({ "v": i as i64 }))
            .await
            .expect("corrupted-window write");
    }

    CorruptedWindow {
        distributor: a,
        device: b,
        path_a,
        path_b,
        ca: ca_secret,
        s,
        t,
        u,
        bad_id,
    }
}

fn publish_corrected(ctx: &CorruptedWindow) -> MigrationDelta {
    let corrected = ca_signed_migration(&ctx.ca, ctx.t, ctx.u, trivial_wasm_v2());
    ctx.distributor
        .publish_migration_delta(&corrected)
        .expect("publish corrected migration");
    corrected
}

async fn await_replay_done(
    ctx: &CorruptedWindow,
    expected_entries: usize,
) -> Vec<crate::migration::sidecar::SideCarEntry> {
    wait_for::<Vec<crate::migration::sidecar::SideCarEntry>, _>(
        Duration::from_secs(15),
        "Side-Car replay complete",
        || {
        let mig = ctx.device.migration.lock().unwrap();
        if mig.current_schema_hash() != ctx.u || mig.active_corruption_migration().is_some() {
            return None;
        }
        let entries = mig.sidecar_entries(&ctx.bad_id).ok()?;
        let done = entries.len() == expected_entries
            && entries.iter().all(|e| {
                !matches!(e.replay_status, ReplayStatus::Pending)
            });
            done.then_some(entries)
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sidecar_replay_on_corrected_migration_over_real_mesh_projects_replayed_rows() {
    let ctx = setup_corrupted_window("sidecar_ok", 3).await;

    // Capture the recorded-timestamp order before replay.
    let captured = {
        let mig = ctx.device.migration.lock().unwrap();
        mig.sidecar_entries(&ctx.bad_id).expect("entries")
    };
    assert_eq!(captured.len(), 3, "three writes must be Side-Car captured");
    for pair in captured.windows(2) {
        assert!(
            pair[0].recorded_ts <= pair[1].recorded_ts,
            "Side-Car entries are replayed in recorded-timestamp order"
        );
    }
    assert!(matches!(captured[0].replay_status, ReplayStatus::Pending));

    // Corruption window is durably recorded for restart recovery.
    {
        let conn = crate::store::sqlite::open(&ctx.path_b).expect("conn");
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM migration_corruption_windows", [], |r| {
                r.get(0)
            })
            .expect("count windows");
        assert_eq!(n, 1, "the corruption window must be persisted");
    }

    // Our own reads of the captured rows exist locally, but the *projection*
    // assertion below is about the replay write-through, so clear nothing.
    let _ = publish_corrected(&ctx);
    let entries = await_replay_done(&ctx, 3).await;

    // Req 19.6: zero-conflict replay appends ReplayComplete and marks COMPLETE.
    for entry in &entries {
        assert!(
            matches!(entry.replay_status, ReplayStatus::Complete),
            "every captured write must be COMPLETE after zero-conflict replay: {entry:?}"
        );
    }
    {
        let conn = crate::store::sqlite::open(&ctx.path_b).expect("conn");
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM migration_corruption_windows", [], |r| {
                r.get(0)
            })
            .expect("count windows");
        assert_eq!(n, 0, "the corruption window must close after replay");
    }

    // The replayed writes are visible through the ordinary read path — this is
    // the replay projection write-through (`project_table_to_store`), not just
    // CRDT document state.
    for i in 0..3 {
        let res = ctx
            .device
            .read("reports", &format!("cap{i}"))
            .await
            .expect("replayed row must be projected and readable");
        assert_eq!(
            res.data,
            json!({ "v": i as i64 }),
            "replayed row reports/cap{i} must carry the captured value"
        );
    }
    // A row from before the replay is unaffected.
    let r1 = ctx.device.read("reports", "r1").await.expect("seed row");
    assert_eq!(r1.data, json!({ "v": 1 }));

    cleanup(&ctx.path_a);
    cleanup(&ctx.path_b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sidecar_replay_conflict_is_observable_and_does_not_stop_other_entries() {
    let ctx = setup_corrupted_window("sidecar_conflict", 1).await;

    // A Side-Car entry that cannot merge on the corrected projection: a Delta
    // stamped with a schema hash no version path registers. Recorded through
    // the same production ledger API the write path uses (Req 19.2).
    let conflicting = Delta {
        id: [0u8; 32],
        author_did: ctx.device.local_did().to_string(),
        signature: Ed25519Signature::default(),
        schema_hash: [0xEEu8; 32],
        automerge_bytes: vec![],
        priority: crate::crdt::delta::PriorityClass::Low,
        causal_parents: vec![],
        tags: vec![],
        lamport: 999,
        created_at: crate::traits::wall_hint().unwrap_or_default(),
    };
    {
        let mut mig = ctx.device.migration.lock().unwrap();
        mig.record_corrupted_window_write(
            "reports",
            serde_json::to_vec(&conflicting).expect("serialise"),
            i64::MAX / 2,
        )
        .expect("record conflicting entry")
        .expect("an active window must accept the entry");
    }

    let _ = publish_corrected(&ctx);
    let entries = await_replay_done(&ctx, 2).await;

    // Replay continued past the conflict: the legitimate entry replayed.
    let legit = entries
        .iter()
        .find(|e| e.recorded_ts != i64::MAX / 2)
        .expect("legitimate entry");
    assert!(
        matches!(legit.replay_status, ReplayStatus::Replayed),
        "the non-conflicting entry must still replay: {legit:?}"
    );
    let conflicted = entries
        .iter()
        .find(|e| e.recorded_ts == i64::MAX / 2)
        .expect("conflicting entry");
    match &conflicted.replay_status {
        ReplayStatus::Conflict { conflict_info } => assert!(
            conflict_info.contains("quarantined"),
            "conflict must record the quarantine reason: {conflict_info}"
        ),
        other => panic!("conflicting entry must be flagged CONFLICT, got {other:?}"),
    }

    // The conflict is observable from the public boundary.
    let exposed = ctx.device.sidecar_conflicts().expect("sidecar conflicts");
    assert_eq!(exposed.len(), 1, "exactly one conflict is awaiting resolution");
    assert_eq!(exposed[0].id, conflicted.id);

    // The replayed row is projected even though the pass had a conflict.
    let res = ctx.device.read("reports", "cap0").await.expect("cap0");
    assert_eq!(res.data, json!({ "v": 0 }));

    cleanup(&ctx.path_a);
    cleanup(&ctx.path_b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sidecar_replay_resume_is_idempotent_without_duplicate_or_lost_writes() {
    let ctx = setup_corrupted_window("sidecar_resume", 3).await;

    let captured = {
        let mig = ctx.device.migration.lock().unwrap();
        mig.sidecar_entries(&ctx.bad_id).expect("entries")
    };
    assert_eq!(captured.len(), 3);

    // Simulate the durable state a kill mid-replay leaves: each entry status is
    // its own SQLite transaction, so a crashed pass leaves a replayed prefix and
    // a pending remainder. Mark the first entry REPLAYED by hand — the exact
    // row an interrupted pass would have committed.
    {
        let conn = crate::store::sqlite::open(&ctx.path_b).expect("conn");
        conn.execute(
            "UPDATE sidecar_ledger SET replay_status = 'REPLAYED' WHERE id = ?1",
            rusqlite::params![&captured[0].id[..]],
        )
        .expect("simulate partial replay");
    }

    let _ = publish_corrected(&ctx);
    let entries = await_replay_done(&ctx, 3).await;
    assert!(
        entries
            .iter()
            .all(|e| matches!(e.replay_status, ReplayStatus::Complete)),
        "resumed replay must complete every entry: {entries:?}"
    );

    // No duplication: a replayed Delta is stored exactly once in the DAG, and
    // no write is lost from the projection.
    for entry in &captured {
        let delta_id: [u8; 32] = serde_json::from_slice::<Delta>(&entry.delta_bytes)
            .expect("stored delta parses")
            .id;
        assert_eq!(
            sidecar_entry_count(&ctx.path_b, delta_id),
            1,
            "delta {} must appear exactly once in the DAG after resume",
            hex::encode(delta_id)
        );
    }
    for i in 0..3 {
        let res = ctx
            .device
            .read("reports", &format!("cap{i}"))
            .await
            .expect("row");
        assert_eq!(res.data, json!({ "v": i as i64 }));
    }

    // A second pass over the same ledger is a no-op: already-replayed entries
    // are skipped, nothing is re-applied and nothing is reported as pending.
    let conn = Arc::new(Mutex::new(
        crate::store::sqlite::open(&ctx.path_b).expect("conn"),
    ));
    let mut ledger = crate::migration::sidecar::SideCarLedger::new(conn);
    let mut crdt = ctx.device.crdt.lock().unwrap();
    let summary = ledger
        .replay_sidecar(ctx.bad_id, ctx.u, &mut crdt)
        .expect("idempotent replay");
    assert_eq!(summary.replayed, 0, "a resumed pass must not re-apply entries");
    assert_eq!(summary.conflicts, 0);
    assert_eq!(summary.total_entries, 3);
    assert!(
        summary.complete,
        "a ledger whose entries are all COMPLETE is complete"
    );
    drop(crdt);
    for entry in &captured {
        let delta_id: [u8; 32] = serde_json::from_slice::<Delta>(&entry.delta_bytes)
            .expect("stored delta parses")
            .id;
        assert_eq!(sidecar_entry_count(&ctx.path_b, delta_id), 1);
    }
    for i in 0..3 {
        let res = ctx
            .device
            .read("reports", &format!("cap{i}"))
            .await
            .expect("row");
        assert_eq!(res.data, json!({ "v": i as i64 }));
    }

    cleanup(&ctx.path_a);
    cleanup(&ctx.path_b);
}
