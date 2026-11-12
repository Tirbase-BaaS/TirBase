//! Two-instance mesh wiring test for the security log (CLAIM-26.3, 26.4, 26.7,
//! 28.3, PV-7.9, PV-7.10, INV-4).
//!
//! Both instances are started exactly as the gateway starts them: a real
//! [`SecurityEventLog`] plus a real [`CoreHandle`], connected by
//! [`wire_security_log_to_mesh`] — the same production wiring used by
//! `tirbase-gateway/src/main.rs`. The test drives only public production APIs
//! (`publish_checkpoint_hash`, `receive_inbound`) and observes the effects
//! through the logs' persisted state, never through internal test hooks.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rusqlite::Connection;
use tirbase_core::api::{CoreHandle, DeploymentConfig, InitConfig};
use tirbase_core::events::{ReasonCode, SecurityEvent as Payload, SecurityEventCategory, Severity};
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_core::transport::message::GossipMessage;
use tirbase_gateway::mesh_wiring::wire_security_log_to_mesh;
use tirbase_gateway::security_log::SecurityEventLog;
use tirbase_guard::node_mode::{NodeMode, NodeModeState};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn tmp(tag: &str) -> PathBuf {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "tirbase-mesh-wiring-{tag}-{}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn payload(n: u64, target: &str) -> Payload {
    Payload::new(
        SecurityEventCategory::CommandDecision,
        Severity::Low,
        ReasonCode::CommandAccepted,
    )
    .with_actor(format!("did:test:{n}"))
    .with_target(target.to_string())
}

async fn wait_for(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..120 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

fn core_config(dir: &Path) -> InitConfig {
    InitConfig {
        storage_path: dir.join("core.db").to_string_lossy().into_owned(),
        listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
        deployment: DeploymentConfig::default(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_gateways_exchange_checkpoint_detect_tail_truncation_and_propagate_events() {
    let dir_a = tmp("a");
    let dir_b = tmp("b");

    let kp_a = Arc::new(InMemoryKeyProvider::generate().unwrap());
    let kp_b = Arc::new(InMemoryKeyProvider::generate().unwrap());
    let mode_a = NodeModeState::new(NodeMode::Normal);
    let mode_b = NodeModeState::new(NodeMode::Normal);

    let log_a = SecurityEventLog::new_persistent_with_mode(
        dir_a.join("primary.db"),
        Some(kp_a.clone()),
        false,
        Some(mode_a),
    );
    let log_b = SecurityEventLog::new_persistent_with_mode(
        dir_b.join("primary.db"),
        Some(kp_b.clone()),
        false,
        Some(mode_b.clone()),
    );
    log_a.set_rate_limit_enabled(false);
    log_b.set_rate_limit_enabled(false);

    let core_a = CoreHandle::init(core_config(&dir_a)).await.expect("init a");
    let core_b = CoreHandle::init(core_config(&dir_b)).await.expect("init b");

 // Outbound sync transport for instance A: the test forwards the batch to
 // instance B's production receive path.
    let (sync_tx, mut sync_rx) = tokio::sync::mpsc::unbounded_channel();
    wire_security_log_to_mesh(&core_a, &log_a, kp_a.did().to_string(), move |batch| {
        let _ = sync_tx.send(batch);
    });
    wire_security_log_to_mesh(&core_b, &log_b, kp_b.did().to_string(), |_batch| {});

 // Instance B checkpoints its own (shorter) chain first.
    for i in 1..=2u64 {
        log_b.append_payload(payload(i, "b-local"));
    }
    let b_checkpoint = log_b.try_checkpoint().unwrap().expect("b checkpoint");

 // Instance A appends and checkpoints; this is the checkpoint gossiped on
 // connection by the wired provider.
    for i in 1..=3u64 {
        log_a.append_payload(payload(i, "a-local"));
    }
    log_a.try_checkpoint().unwrap().expect("a checkpoint");
    let (a_seq, a_hash) = log_a
        .latest_checkpoint_hash()
        .unwrap()
        .expect("a latest checkpoint");
    assert!(
        a_seq > b_checkpoint,
        "test setup: A must be ahead of B (a_seq={a_seq}, b_seq={b_checkpoint})"
    );

 // 26.3: publish through the production checkpoint publisher, then deliver
 // over the production inbound receive path (instead of a live swarm).
    core_a
        .publish_checkpoint_hash(a_seq, a_hash, 1_700_000_000)
        .unwrap();
    core_b
        .receive_inbound(GossipMessage::CheckpointHash {
            reporter_did: kp_a.did().to_string(),
            seq: a_seq,
            checkpoint_hash: a_hash,
            observed_at: 1_700_000_000,
        })
        .await
        .expect("receive checkpoint");

 // 26.4: the wired observation path compares the peer checkpoint against the
 // local tail and enters Restricted with a TailTruncation event.
    let restricted = wait_for(|| mode_b.get() == NodeMode::Restricted).await;
    assert!(
        restricted,
        "26.4: peer checkpoint ahead of the local tail must enter Restricted (mode={:?})",
        mode_b.get()
    );
    assert!(
        log_b
            .chained_events()
            .iter()
            .any(|e| e.reason_code == ReasonCode::TailTruncation),
        "26.4: TailTruncation must be recorded in the local chain"
    );
    let witnesses = log_b.peer_checkpoint_witnesses().unwrap();
    assert!(
        witnesses
            .iter()
            .any(|w| w.peer_did == kp_a.did() && w.seq == a_seq && w.checkpoint_hash == a_hash),
        "26.4/26.5: observed peer checkpoint must be persisted as a witness: {witnesses:?}"
    );

 // 28.3: a security event appended on A is published by the wired sync loop
 // and persisted by B's receive-path merge.
    log_a.append_payload(payload(9, "propagate-28-3"));
    let batch = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let batch = sync_rx.recv().await.expect("sync channel closed");
            if batch
                .records
                .iter()
                .any(|r| r.target.as_deref() == Some("propagate-28-3"))
            {
                break batch;
            }
        }
    })
    .await
    .expect("28.3: local security event must be published as a sync batch");
    assert_eq!(
        batch.sender_did,
        kp_a.did(),
        "28.3: batch must be attributed to the sending device"
    );
    core_b
        .receive_inbound(GossipMessage::SecurityEventSync(batch))
        .await
        .expect("receive security event sync");

    let b_primary = dir_b.join("primary.db");
    let propagated = wait_for(|| {
        let Ok(conn) = Connection::open(&b_primary) else {
            return false;
        };
        conn.query_row(
            "SELECT COUNT(*) FROM synced_security_events WHERE target='propagate-28-3'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n > 0)
        .unwrap_or(false)
    })
    .await;
    assert!(
        propagated,
        "28.3: peer security event must be persisted in synced_security_events"
    );

    let _ = std::fs::remove_dir_all(dir_a);
    let _ = std::fs::remove_dir_all(dir_b);
}
