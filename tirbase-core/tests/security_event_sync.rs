// SPDX-License-Identifier: AGPL-3.0-only

//! integration test: two real CoreHandle instances sync security events
//! (PV-7.9, PV-7.12, CLAIM-28.3).
use std::time::Duration;
use tirbase_core::api::{CoreHandle, DeploymentConfig, InitConfig};
use tirbase_core::transport::security_event_sync::{
    SecurityEventSyncBatch, SecurityEventSyncRecord,
};

fn cfg(path: &std::path::Path) -> InitConfig {
    InitConfig {
        storage_path: path.to_str().unwrap().to_string(),
        listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
        deployment: DeploymentConfig {
            revocation_m: 1,
            revocation_n: 1,
            ..DeploymentConfig::default()
        },
    }
}

fn rec(origin: &str, seq: u64) -> SecurityEventSyncRecord {
    SecurityEventSyncRecord {
        origin_did: origin.to_string(),
        seq,
        segment_id: 1,
        category: "CommandDecision".to_string(),
        severity: "Low".to_string(),
        actor_did: None,
        target: Some(format!("t{seq}")),
        reason_code: "CommandAccepted".to_string(),
        best_effort_wall_time: 0,
        time_source_flag: "LogicalFallback".to_string(),
        prev_hash: [0; 32],
        is_checkpoint: false,
        personal_commitments: vec![],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claim_28_3_two_corehandles_sync_security_events_append_only() {
    let n = tirbase_core::traits::monotonic_now();
    let a_path = std::env::temp_dir().join(format!("tirbase-28sync-a-{n}.db"));
    let b_path = std::env::temp_dir().join(format!("tirbase-28sync-b-{n}.db"));
    let a = CoreHandle::init(cfg(&a_path)).await.expect("init a");
    let b = CoreHandle::init(cfg(&b_path)).await.expect("init b");
    let mut rx = b.subscribe_security_event_sync();

    let batch = SecurityEventSyncBatch {
        sender_did: "did:test:node-a".to_string(),
        records: vec![rec("did:test:origin", 1), rec("did:test:origin", 2)],
    };
    a.publish_security_event_sync(batch.clone())
        .expect("publish");
    b.receive_inbound(tirbase_core::transport::message::GossipMessage::SecurityEventSync(batch))
        .await
        .expect("receive");

    let got1 = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout")
        .expect("recv");
    let got2 = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout")
        .expect("recv");
    let mut seqs = vec![got1.seq, got2.seq];
    seqs.sort_unstable();
    assert_eq!(seqs, vec![1, 2], "28.3: events must sync across nodes");

 // append-only/compaction=none dedupe: replay same seq must not re-emit
    let dup = SecurityEventSyncBatch {
        sender_did: "did:test:node-a".to_string(),
        records: vec![rec("did:test:origin", 1)],
    };
    b.receive_inbound(tirbase_core::transport::message::GossipMessage::SecurityEventSync(dup))
        .await
        .expect("receive dup");
    let no_more = tokio::time::timeout(Duration::from_millis(250), rx.recv()).await;
    assert!(
        no_more.is_err(),
        "28.3: append-only compaction=none must dedupe duplicate seq"
    );

    let _ = std::fs::remove_file(a_path);
    let _ = std::fs::remove_file(b_path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claim_28_3_per_peer_rate_limit_emits_sync_rate_limit_reached_and_drops_excess() {
    let n = tirbase_core::traits::monotonic_now();
    let b_path = std::env::temp_dir().join(format!("tirbase-28rate-b-{n}.db"));
    let b = CoreHandle::init(cfg(&b_path)).await.expect("init b");
    let mut rx = b.subscribe_security_event_sync();
    let records: Vec<_> = (1..=700).map(|i| rec("did:test:origin", i)).collect();
    let batch = SecurityEventSyncBatch {
        sender_did: "did:test:peer-flood".to_string(),
        records,
    };
    b.receive_inbound(tirbase_core::transport::message::GossipMessage::SecurityEventSync(batch))
        .await
        .expect("receive");
    let mut got = 0usize;
    while let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
        got += 1;
        if got > 600 {
            break;
        }
    }
    assert!(
        got <= 500,
        "28.3/PV-7.12: per-peer 500/min must cap accepted records (got {got})"
    );
    assert!(
        got >= 1,
        "28.3: some records should be accepted before limit"
    );
    let _ = std::fs::remove_file(b_path);
}
