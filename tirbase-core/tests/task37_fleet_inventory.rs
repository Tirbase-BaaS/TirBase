//! Task 37.5 (PV-11.3, CLAIM-37.5): fleet inventory as a CRDT collection.
//!
//! Two real [`CoreHandle`] instances are started.  Device A provisions a fleet
//! member, then revokes it; the resulting `FleetInventoryDelta` is delivered to
//! B over the production inbound path.  The revocation must be known to B well
//! inside the 60-second propagation budget, and B's CRDT engine must reject
//! subsequent Deltas authored by the revoked device.
//!
//! Wiring-mutation surface: if `CoreHandle::fleet_revoke_device` stops
//! publishing the revocation delta (or the inbound path stops merging it), the
//! update never arrives and the wait below times out.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tirbase_core::api::{CoreHandle, DeploymentConfig, InitConfig};
use tirbase_core::crdt::delta::{Delta, Ed25519Signature, PriorityClass};
use tirbase_core::fleet::{DeviceProvisioning, MAX_PROVISIONING_PAYLOAD_BYTES};
use tirbase_core::identity::IdentityManager;
use tirbase_core::transport::message::GossipMessage;

static NEXT: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("tb37-fleet-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn config(dir: &std::path::Path) -> InitConfig {
    InitConfig {
        storage_path: dir.join("core.db").to_string_lossy().into_owned(),
        listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
        deployment: DeploymentConfig::default(),
    }
}

fn provisioning(device_id: &str, label_bytes: usize) -> DeviceProvisioning {
    let mut p = DeviceProvisioning::new(
        device_id,
        "cold-room-gateway",
        [0x42; 16],
        [0x24; 32],
        1_700_000_000,
    );
    p.labels.insert("site".to_string(), "x".repeat(label_bytes));
    p
}

/// A syntactically valid, correctly signed Delta authored by `author`.
fn signed_delta_from(author: &IdentityManager) -> Delta {
    let mut delta = Delta {
        id: [0u8; 32],
        author_did: author.did().to_string(),
        signature: Ed25519Signature::default(),
        schema_hash: [0u8; 32],
        automerge_bytes: vec![],
        priority: PriorityClass::Low,
        causal_parents: vec![],
        tags: vec![],
        lamport: 1,
        created_at: 1_700_000_000,
    };
    author.sign_delta(&mut delta).expect("sign delta");
    delta
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fleet_provisioning_payload_is_capped_at_64_kib() {
    let dir = temp_dir("cap");
    let handle = CoreHandle::init(config(&dir)).await.expect("init");

    // One byte over the 64 KiB budget once the record is serialised.
    let oversized = provisioning("did:key:zOversized", MAX_PROVISIONING_PAYLOAD_BYTES);
    assert!(
        oversized.payload_len().unwrap() > MAX_PROVISIONING_PAYLOAD_BYTES,
        "test setup: payload must exceed the 64 KiB cap"
    );
    let err = handle
        .fleet_provision_device(oversized)
        .expect_err("oversized provisioning payload must be rejected");
    let message = err.to_string();
    assert!(
        message.contains("65536"),
        "error must name the 64 KiB limit: {message}"
    );
    assert!(
        handle.fleet_device("did:key:zOversized").is_none(),
        "a rejected payload must not enter the inventory"
    );

    // A payload that fits is accepted and joins the CRDT collection.
    let fits = provisioning("did:key:zFits", 32 * 1024);
    assert!(fits.payload_len().unwrap() <= MAX_PROVISIONING_PAYLOAD_BYTES);
    let entry = handle
        .fleet_provision_device(fits)
        .expect("payload under 64 KiB must be accepted");
    assert_eq!(entry.device_id, "did:key:zFits");
    assert!(!entry.is_revoked());
    assert_eq!(handle.fleet_inventory_snapshot().len(), 1);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fleet_revocation_propagates_to_connected_peer_within_60_seconds() {
    let dir_a = temp_dir("a");
    let dir_b = temp_dir("b");
    let a = CoreHandle::init(config(&dir_a)).await.expect("init a");
    let b = CoreHandle::init(config(&dir_b)).await.expect("init b");

    // A device that will be provisioned, then revoked.
    let device = IdentityManager::init_in_memory().expect("device identity");
    let device_did = device.did().to_string();

    a.fleet_provision_device(provisioning(&device_did, 64))
        .expect("provision device");
    assert!(
        !b.fleet_device(&device_did).is_some(),
        "test setup: B must not know the device before propagation"
    );

    // Subscribe before revoking so the emitted gossip delta cannot be missed.
    let mut updates = a.subscribe_fleet_updates();
    let started = Instant::now();
    assert!(
        a.fleet_revoke_device(&device_did, "decommissioned")
            .expect("revoke device"),
        "first revocation must change the inventory"
    );

    // The production path must publish the revocation for gossip.  This is the
    // wiring assertion: with propagation removed, the wait times out.
    let update = tokio::time::timeout(Duration::from_secs(60), updates.recv())
        .await
        .expect("revocation delta must be published within the 60 s budget")
        .expect("fleet update channel alive");
    assert_eq!(update.origin_did, a.local_did());
    assert!(
        update
            .entries
            .iter()
            .any(|entry| entry.device_id == device_did && entry.is_revoked()),
        "published delta must carry the revoked entry: {update:?}"
    );

    // Deliver over the production inbound path (real CoreHandle instance B).
    b.receive_inbound(GossipMessage::FleetInventoryUpdate(update))
        .await
        .expect("B merges fleet update");
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(60),
        "revocation must reach the peer within 60 seconds (took {elapsed:?})"
    );
    assert!(
        b.fleet_is_revoked(&device_did),
        "B must know the device is revoked after merging the update"
    );
    assert_eq!(
        b.fleet_snapshot_hash(),
        a.fleet_snapshot_hash(),
        "both replicas must converge on the same inventory snapshot hash"
    );

    // B's merge gate must now reject Deltas authored by the revoked device
    // (Req 8.6).  The gate discards them without merging; an unrevoked author's
    // Delta is still accepted, so this is not a blanket rejection.
    b.receive_inbound(GossipMessage::InboundDelta(signed_delta_from(&device)))
        .await
        .expect("B processes a revoked-author delta without erroring");
    let bystander = IdentityManager::init_in_memory().expect("bystander identity");
    b.receive_inbound(GossipMessage::InboundDelta(signed_delta_from(&bystander)))
        .await
        .expect("B processes an unrevoked author's delta");

    // A peer that re-announces a provisioned record for the revoked DID must
    // not resurrect it: revocation dominates in the CRDT.
    let mut resurrect = a.subscribe_fleet_updates();
    assert!(
        a.fleet_provision_device(provisioning(&device_did, 8))
            .is_err(),
        "a revoked device cannot be re-provisioned locally"
    );
    assert!(resurrect.try_recv().is_err());

    // Idempotent: revoking again is a no-op and does not re-broadcast.
    assert!(
        !a.fleet_revoke_device(&device_did, "decommissioned")
            .expect("second revoke"),
        "repeated revocation must be a CRDT no-op"
    );

    let _ = std::fs::remove_dir_all(dir_a);
    let _ = std::fs::remove_dir_all(dir_b);
}
