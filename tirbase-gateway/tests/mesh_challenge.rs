// SPDX-License-Identifier: AGPL-3.0-only

//! (PV-22.3, INV-9): challenge nonce issuance over the mesh channel.
//!
//! Two real [`CoreHandle`] instances are started. Guard B registers a
//! challenge issuer; A sends a `ChallengeRequest`. The response must be routed
//! back to the originating guard only: a response addressed to a different
//! `origin_guard_did` must not be delivered locally (wiring-mutation surface).

use std::sync::{Arc, Mutex};

use tirbase_core::api::{CoreHandle, DeploymentConfig, InitConfig};
use tirbase_core::transport::challenge::{
    MeshChallengeHandler, MeshChallengeNonce, MeshChallengeRequest, MeshChallengeResponse,
};
use tirbase_core::transport::message::GossipMessage;

static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "tb36-mesh-challenge-{tag}-{}-{n}",
        std::process::id()
    ));
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

#[derive(Default)]
struct RecordingIssuer {
    seen: Mutex<Vec<MeshChallengeRequest>>,
}

impl MeshChallengeHandler for RecordingIssuer {
    fn issue_challenge(
        &self,
        request: &MeshChallengeRequest,
    ) -> Result<MeshChallengeNonce, String> {
        self.seen.lock().unwrap().push(request.clone());
        Ok(MeshChallengeNonce {
            nonce: [0x5au8; 32],
            issued_at_mono: 1_000,
            expires_at_mono: 1_300,
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn challenge_is_issued_by_peer_and_routed_only_to_originating_guard() {
    let dir_a = temp_dir("a");
    let dir_b = temp_dir("b");
    let a = CoreHandle::init(config(&dir_a)).await.expect("init a");
    let b = CoreHandle::init(config(&dir_b)).await.expect("init b");

    let issuer = Arc::new(RecordingIssuer::default());
    b.set_challenge_handler(issuer.clone());

    let origin_did = a.local_did().to_string();
    let responder_did = b.local_did().to_string();
    let request_id = [7u8; 32];
    let request = MeshChallengeRequest {
        request_id,
        origin_guard_did: origin_did.clone(),
        requester_did: origin_did.clone(),
        issuer_did: "did:key:remote-issuer".into(),
        target_id: "cold-room-1".into(),
        param: "setpoint_c".into(),
        command_hash: [9u8; 32],
        requested_at_mono: 999,
    };

 // B receives the request over the production inbound path; the registered
 // guard-side issuer is invoked.
    b.receive_inbound(GossipMessage::ChallengeRequest(request.clone()))
        .await
        .expect("B handles challenge request");
    let seen = issuer.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "peer guard must issue for the request");
    assert_eq!(seen[0].request_id, request_id);
    assert_eq!(seen[0].command_hash, [9u8; 32]);

 // The production handler publishes a ChallengeResponse carrying origin DID;
 // forward it to A to model mesh delivery.
    let response = MeshChallengeResponse {
        request_id,
        origin_guard_did: origin_did.clone(),
        responder_guard_did: responder_did.clone(),
        issuer_did: request.issuer_did.clone(),
        target_id: request.target_id.clone(),
        param: request.param.clone(),
        nonce: Some([0x5au8; 32]),
        issued_at_mono: 1_000,
        expires_at_mono: 1_300,
        error: None,
    };
    let mut subscriber = a.subscribe_mesh_challenge_responses();
    a.receive_inbound(GossipMessage::ChallengeResponse(response))
        .await
        .expect("A receives response");
    let delivered = tokio::time::timeout(std::time::Duration::from_secs(2), subscriber.recv())
        .await
        .expect("response delivered")
        .expect("subscriber alive");
    assert_eq!(delivered.request_id, request_id);
    assert_eq!(delivered.nonce, Some([0x5au8; 32]));

 // INV-9 routing mutation: a response addressed to a different origin guard
 // must NOT be delivered to this instance.
    let foreign = MeshChallengeResponse {
        request_id: [3u8; 32],
        origin_guard_did: "did:key:some-other-guard".into(),
        responder_guard_did: responder_did,
        issuer_did: "did:key:remote-issuer".into(),
        target_id: "cold-room-1".into(),
        param: "setpoint_c".into(),
        nonce: Some([0x11u8; 32]),
        issued_at_mono: 1_000,
        expires_at_mono: 1_300,
        error: None,
    };
    a.receive_inbound(GossipMessage::ChallengeResponse(foreign))
        .await
        .expect("foreign response ignored");
    let unexpected =
        tokio::time::timeout(std::time::Duration::from_millis(200), subscriber.recv()).await;
    assert!(
        unexpected.is_err() || matches!(unexpected, Ok(Err(_))),
        "response for another originating guard must not be delivered locally"
    );
}
