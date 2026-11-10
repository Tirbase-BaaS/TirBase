//! Cloud-anchor checkpoint ingress integration test (CLAIM-26.7a, PV-7.10).
//!
//! A mock cloud anchor speaks the production JSON-line protocol
//! (`tirbase-gateway/src/cloud_anchor.rs`) over TCP. The gateway side is the
//! real `CloudAnchorClient` + `run_cloud_anchor_loop` + `SecurityEventLog`, so
//! the test exercises the same path `tirbase-gateway/src/main.rs` boots.

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::Connection;
use tirbase_core::events::{ReasonCode, SecurityEvent as Payload, SecurityEventCategory, Severity};
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_gateway::cloud_anchor::{
    run_cloud_anchor_loop, CloudAnchorAcknowledgement, CloudAnchorClient, CloudAnchorRequest,
    CloudAnchorResponse,
};
use tirbase_gateway::config::load_config_from_toml_path;
use tirbase_gateway::security_log::SecurityEventLog;
use tirbase_guard::node_mode::{NodeMode, NodeModeState};
use tirbase_guard::signed_operation::SignedOperation;
use tirbase_types::CommandRole;

static NEXT: AtomicU64 = AtomicU64::new(0);

fn tmp(tag: &str) -> PathBuf {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "tirbase-cloud-anchor-{tag}-{}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Anchor-side view of the device's chain, shared with the mock server.
type AnchorWitness = Arc<Mutex<Option<(u64, [u8; 32])>>>;

/// Start a mock cloud anchor that signs acknowledgements with `signer`.
fn start_mock_anchor(
    signer: Arc<InMemoryKeyProvider>,
    witnessed: AnchorWitness,
) -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let signer = signer.clone();
            let witnessed = witnessed.clone();
            std::thread::spawn(move || {
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let Ok(request) = serde_json::from_str::<CloudAnchorRequest>(&line) else {
                    return;
                };
                let previous = *witnessed.lock().unwrap();
                let ack = CloudAnchorAcknowledgement {
                    anchor_did: signer.did().to_string(),
                    device_did: request.report.device_did.clone(),
                    acknowledged_seq: request.report.seq,
                    acknowledged_hash: request.report.checkpoint_hash,
                    previously_witnessed_seq: previous.map(|p| p.0),
                    previously_witnessed_hash: previous.map(|p| p.1),
                    observed_at: request.report.observed_at.saturating_add(1),
                };
                *witnessed.lock().unwrap() = Some((ack.acknowledged_seq, ack.acknowledged_hash));
                let mut operation = SignedOperation::new(
                    &ack,
                    ack.observed_at,
                    Some(ack.observed_at.saturating_add(300)),
                )
                .unwrap();
                operation
                    .sign_with(signer.as_ref(), CommandRole::Auditor)
                    .unwrap();
                let response = CloudAnchorResponse {
                    acknowledgement: ack,
                    signed_operation: operation,
                };
                let mut stream = stream;
                use std::io::Write;
                let _ = writeln!(stream, "{}", serde_json::to_string(&response).unwrap());
                let _ = stream.flush();
            });
        }
    });
    addr
}

fn write_config(
    dir: &Path,
    endpoint: std::net::SocketAddr,
    anchor: &InMemoryKeyProvider,
) -> tirbase_gateway::config::GatewayConfig {
    let config = dir.join("gateway.toml");
    let body = format!(
        "key_path = {:?}\n\
         counter_db_path = {:?}\n\
         derived_db_path = {:?}\n\
         admin_socket = {:?}\n\
         admin_enabled = false\n\
         health_addr = \"127.0.0.1:0\"\n\
         metrics_addr = \"127.0.0.1:0\"\n\
         cloud_anchor_endpoint = \"{endpoint}\"\n\
         cloud_anchor_did = {:?}\n\
         cloud_anchor_public_key_hex = {:?}\n\
         cloud_anchor_interval_secs = 1\n",
        dir.join("device-key.json"),
        dir.join("primary.db"),
        dir.join("derived.db"),
        dir.join("admin.sock"),
        anchor.did(),
        hex::encode(anchor.public_key_bytes()),
    );
    std::fs::write(&config, body).unwrap();
    load_config_from_toml_path(&config).expect("cloud anchor config must validate")
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
    for _ in 0..100 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

fn anchor_witness_rows(primary: &Path) -> i64 {
    let Ok(conn) = Connection::open(primary) else {
        return 0;
    };
    conn.query_row("SELECT COUNT(*) FROM cloud_anchor_witness", [], |r| {
        r.get::<_, i64>(0)
    })
    .unwrap_or(0)
}

fn no_witness_events(log: &SecurityEventLog) -> usize {
    log.chained_events()
        .iter()
        .filter(|e| e.reason_code == ReasonCode::NoWitnessAvailable)
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cloud_anchor_ack_is_verified_and_removes_the_no_witness_fallback() {
    let dir = tmp("ack");
    let primary = dir.join("primary.db");
    let anchor = Arc::new(InMemoryKeyProvider::generate().unwrap());
    let anchor_addr = start_mock_anchor(anchor.clone(), Arc::new(Mutex::new(None)));
    let config = write_config(&dir, anchor_addr, &anchor);

    let device = Arc::new(InMemoryKeyProvider::generate().unwrap());
    let mode = NodeModeState::new(NodeMode::Normal);
    let log = SecurityEventLog::new_persistent_with_mode(
        primary.clone(),
        Some(device.clone()),
        false,
        Some(mode.clone()),
    );
    log.set_rate_limit_enabled(false);
    for i in 1..=3u64 {
        log.append_payload(payload(i, "pre-anchor"));
    }
    log.try_checkpoint().unwrap().expect("local checkpoint");
    assert_eq!(
        no_witness_events(&log),
        1,
        "26.7: an isolated device records NoWitnessAvailable before the anchor is reached"
    );

    let client = CloudAnchorClient::from_config(&config, device.clone())
        .unwrap()
        .expect("cloud anchor configured");
    let loop_log = log.clone();
    tokio::spawn(run_cloud_anchor_loop(
        client,
        loop_log,
        Duration::from_millis(100),
    ));

    let witnessed = wait_for(|| anchor_witness_rows(&primary) > 0).await;
    assert!(
        witnessed,
        "26.7a: verified anchor acknowledgement must persist the cloud anchor witness"
    );

    // The anchor now counts as a witness, so the next checkpoint must not
    // report NoWitnessAvailable.
    log.append_payload(payload(4, "post-anchor"));
    log.try_checkpoint().unwrap().expect("second checkpoint");
    assert_eq!(
        no_witness_events(&log),
        1,
        "26.7a: a live cloud anchor must suppress the NoWitnessAvailable fallback"
    );
    assert_eq!(mode.get(), NodeMode::Normal);

    let conn = Connection::open(&primary).unwrap();
    let (anchor_did, seq, observed_at): (String, i64, i64) = conn
        .query_row(
            "SELECT anchor_did, seq, observed_at FROM cloud_anchor_witness",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(anchor_did, anchor.did());
    assert!(seq >= 4, "anchor must have witnessed the latest checkpoint");
    assert!(observed_at > 0);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cloud_anchor_previous_witness_ahead_of_local_tail_enters_restricted() {
    let dir = tmp("truncation");
    let primary = dir.join("primary.db");
    let anchor = Arc::new(InMemoryKeyProvider::generate().unwrap());
    // The anchor has already witnessed a longer chain from this device.
    let anchor_addr = start_mock_anchor(
        anchor.clone(),
        Arc::new(Mutex::new(Some((500, [0xAB; 32])))),
    );
    let config = write_config(&dir, anchor_addr, &anchor);

    let device = Arc::new(InMemoryKeyProvider::generate().unwrap());
    let mode = NodeModeState::new(NodeMode::Normal);
    let log = SecurityEventLog::new_persistent_with_mode(
        primary.clone(),
        Some(device.clone()),
        false,
        Some(mode.clone()),
    );
    log.set_rate_limit_enabled(false);
    for i in 1..=2u64 {
        log.append_payload(payload(i, "truncated-tail"));
    }
    log.try_checkpoint().unwrap().expect("local checkpoint");

    let client = CloudAnchorClient::from_config(&config, device.clone())
        .unwrap()
        .expect("cloud anchor configured");
    let loop_log = log.clone();
    tokio::spawn(run_cloud_anchor_loop(
        client,
        loop_log,
        Duration::from_millis(100),
    ));

    let restricted = wait_for(|| mode.get() == NodeMode::Restricted).await;
    assert!(
        restricted,
        "26.7a: anchor witness ahead of the local tail must enter Restricted"
    );
    assert!(
        log.chained_events()
            .iter()
            .any(|e| e.reason_code == ReasonCode::TailTruncation),
        "26.7a: TailTruncation must be recorded from the cloud anchor observation"
    );
    assert!(anchor_witness_rows(&primary) > 0);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cloud_anchor_ack_from_untrusted_signer_is_rejected() {
    let dir = tmp("untrusted");
    let primary = dir.join("primary.db");
    let trusted = Arc::new(InMemoryKeyProvider::generate().unwrap());
    let rogue = Arc::new(InMemoryKeyProvider::generate().unwrap());
    // Endpoint signs with `rogue`, but configuration trusts `trusted`.
    let anchor_addr = start_mock_anchor(rogue, Arc::new(Mutex::new(None)));
    let config = write_config(&dir, anchor_addr, &trusted);

    let device = Arc::new(InMemoryKeyProvider::generate().unwrap());
    let mode = NodeModeState::new(NodeMode::Normal);
    let log = SecurityEventLog::new_persistent_with_mode(
        primary.clone(),
        Some(device.clone()),
        false,
        Some(mode.clone()),
    );
    for i in 1..=2u64 {
        log.append_payload(payload(i, "untrusted"));
    }
    log.try_checkpoint().unwrap();
    let (seq, hash) = log.latest_checkpoint_hash().unwrap().expect("checkpoint");

    let client = CloudAnchorClient::from_config(&config, device)
        .unwrap()
        .expect("cloud anchor configured");
    let error = client
        .exchange_checkpoint(seq, hash, 1_700_000_000)
        .await
        .expect_err("an acknowledgement from the wrong signer must be rejected");
    assert!(
        error.contains("verification") || error.contains("unexpected anchor"),
        "26.7a: rejection must name the failed anchor verification: {error}"
    );
    assert_eq!(mode.get(), NodeMode::Normal);
    assert_eq!(anchor_witness_rows(&primary), 0);

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn cloud_anchor_config_requires_endpoint_did_and_key_together() {
    let dir = tmp("config");
    let config = dir.join("gateway.toml");
    std::fs::write(
        &config,
        "key_path = \"device-key.json\"\ncloud_anchor_endpoint = \"127.0.0.1:9000\"\n",
    )
    .unwrap();
    let error = load_config_from_toml_path(&config).expect_err("partial config must be rejected");
    assert!(
        error.to_string().contains("must be set together"),
        "unexpected validation error: {error}"
    );
    let _ = std::fs::remove_dir_all(dir);
}
