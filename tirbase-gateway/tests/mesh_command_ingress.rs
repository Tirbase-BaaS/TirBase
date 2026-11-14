// SPDX-License-Identifier: AGPL-3.0-only

//! CLAIM-35.7: the production mesh command receiver.
//!
//! Proves the receiver loop consumes commands from the mesh command channel and
//! sends every one through `admit_and_dispatch_blocking` (the same Stage 0–19
//! path as the local-admin/cloud receivers). The guard here has no pipeline
//! installed, so admission is expected to reject — the assertion is that the
//! receiver still calls the guard for every command and never writes the
//! effects ledger on a rejection.

use std::sync::Arc;
use std::time::Duration;

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_guard::epoch::{EpochRegistry, InMemoryEpochStore};
use tirbase_guard::{sign_command, single_target_guard};
use tirbase_gateway::command_ingress::mesh::run_mesh_command_receiver_with;
use tirbase_gateway::guard::SqliteStage16Store;
use tirbase_gateway::metrics::global_metrics;
use tirbase_types::command::CommandMessage;
use tirbase_types::{CommandRole, DeviceSignature, Did, FixedPointValue, TargetId, UNIT_PERCENT};

fn signed_command(issuer: &InMemoryKeyProvider, seq: u64) -> CommandMessage {
    let mut command = CommandMessage {
        issuer_did: Did::new(issuer.did()),
        role: CommandRole::CommandIssuer,
        target_id: TargetId::new("pump-1"),
        param: "speed".into(),
        desired_state: FixedPointValue::new(500, -1, UNIT_PERCENT),
        sequence_number: seq,
        idempotency_key: [seq as u8; 16],
        expiry_est: 9_999_999_999,
        policy_version: 1,
        enrollment_epoch: 0,
        challenge_nonce: None,
        co_signatures: Vec::new(),
        signature: DeviceSignature::Ed25519([0u8; 64]),
    };
    sign_command(&mut command, issuer).expect("sign mesh command");
    command
}

fn tmpdb(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tg-mesh-{name}-{}-{}",
        std::process::id(),
        tirbase_core::traits::monotonic_now()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir.join("primary.db")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mesh_command_receiver_runs_every_command_through_admission() {
    let metrics = global_metrics();
    let decisions_before = metrics.guard_decisions_total.load(std::sync::atomic::Ordering::Relaxed);
    let ledger_before = metrics
        .effects_ledger_writes_total
        .load(std::sync::atomic::Ordering::Relaxed);

    let issuer = InMemoryKeyProvider::generate().expect("issuer keypair");
    let epochs = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
    epochs
        .ensure_enrolled("did:key:zMeshDevice", 1_000)
        .expect("enrol device");
    let guard = Arc::new(single_target_guard(
        epochs,
        TargetId::new("pump-1"),
        "did:key:zMeshDevice".to_string(),
    ));
    let stage16 = Arc::new(SqliteStage16Store::open(&tmpdb("receiver")).expect("open stage16"));

    let (sender, receiver) = tokio::sync::broadcast::channel(8);
    let loop_handle = tokio::spawn(run_mesh_command_receiver_with(
        receiver,
        guard.clone(),
        stage16.clone(),
    ));

    sender.send(signed_command(&issuer, 1)).expect("send first");
    sender.send(signed_command(&issuer, 2)).expect("send second");

    let mut observed = decisions_before;
    for _ in 0..100 {
        observed = metrics.guard_decisions_total.load(std::sync::atomic::Ordering::Relaxed);
        if observed >= decisions_before + 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        observed >= decisions_before + 2,
        "receiver must run both mesh commands through the guard (before={decisions_before}, after={observed})"
    );
    assert_eq!(
        metrics
            .effects_ledger_writes_total
            .load(std::sync::atomic::Ordering::Relaxed),
        ledger_before,
        "a guard rejection must not write the effects ledger"
    );

    drop(sender);
    tokio::time::timeout(Duration::from_secs(5), loop_handle)
        .await
        .expect("receiver must stop when the mesh channel closes")
        .expect("receiver task must not panic")
        .expect("receiver must exit cleanly");
}
