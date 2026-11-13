//! WS6 — fragmentation, multi-hop relay, and Noise session resumption /
//! rotation over the real mesh (native only).
//!
//! Every test drives production code:
//!
//! - `CoreHandle::init` → real libp2p Swarm + production inbound drain loop;
//! - `CoreHandle::write` → `MeshTransport::send_delta` → `prepare_outbound`
//!   (fragmenting at the configured `mesh_mtu`) → Gossipsub;
//! - the receiving Swarm poll task → `process_wire_message` (reassembly) →
//!   `receive_inbound` (merge + projection);
//! - the multi-hop path: `send_delta` relay selection → `RelayDelta` envelope
//!   → the relay node's production Swarm poll task → `MeshTransport::relay_decision`
//!   → re-publish → target delivery;
//! - the Noise path: `MeshTransport::initiate_session_with_payload` /
//!   `MeshTransport::accept_noise_session` over a real loopback TCP stream.
//!
//! No mock transport and no `inject_inbound` sits on any asserted path.

use super::mesh_harness::*;
use super::*;
use crate::api::types::TrustLevel;
use crate::crdt::delta::{Delta, Ed25519Signature, PriorityClass};
use crate::transport::message::GossipMessage;
use crate::transport::session::{
    AsyncNoiseStream, DuplexNoiseStream, ResumptionCredential, TcpNoiseStream,
    CREDENTIAL_VALIDITY_SECS,
};
use crate::transport::{RelayDecision, SessionEstablishment};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

fn now_secs() -> i64 {
    crate::traits::wall_hint_secs().unwrap_or(0)
}

/// Build a correctly signed JSON-envelope Delta authored by `handle`.
///
/// The envelope shape (`_tirbase_table` / `_tirbase_key` + flattened data) is
/// exactly what a peer projects in `receive_inbound`, so a Delta built here
/// takes the production merge + projection path.
fn signed_delta(
    handle: &CoreHandle,
    table: &str,
    key: &str,
    data: &serde_json::Value,
    lamport: u64,
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
    let envelope_bytes =
        serde_json::to_vec(&serde_json::Value::Object(envelope)).expect("envelope");

    let mut delta = Delta {
        id: [0u8; 32],
        author_did: handle.identity.did().to_string(),
        signature: Ed25519Signature::default(),
        schema_hash: [0u8; 32],
        automerge_bytes: envelope_bytes,
        priority: PriorityClass::Low,
        causal_parents: vec![],
        tags: vec![],
        lamport,
        created_at: 0,
    };
    let canonical = delta.canonical_bytes();
    delta.signature =
        crate::identity::keypair::sign(&handle.identity.signing_key_bytes(), &canonical)
            .expect("sign");
    delta.id = Delta::compute_id(&canonical);
    delta
}

async fn wait_until<F: FnMut() -> bool>(mut cond: F, timeout: Duration, what: &str) {
    let deadline = crate::traits::monotonic_now() + timeout.as_micros() as u64;
    loop {
        if cond() {
            return;
        }
        assert!(
            crate::traits::monotonic_now() < deadline,
            "{what} did not happen within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ── PART A: fragmentation at mesh_mtu = 256 ─────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fragmented_large_row_crosses_a_256_byte_mesh_mtu() {
    let port_a = reserve_loopback_port();
    let port_b = reserve_loopback_port();
    assert_ne!(port_a, port_b);

    let mut deployment = mesh_deployment();
    deployment.mesh_mtu = 256;

    let a = init_mesh_handle_with_deployment("ws6_frag_a", port_a, deployment.clone()).await;
    let b = init_mesh_handle_with_deployment("ws6_frag_b", port_b, deployment).await;

    connect_peers(&a, &format!("/ip4/127.0.0.1/tcp/{port_b}")).await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    let payload = json!({
        "blob": "x".repeat(1_200),
        "seq": 1,
    });

    let written = a
        .write("frag", "row-big", payload.clone())
        .await
        .expect("write must succeed");

    // The Delta must have been split on the wire at the configured MTU.
    // Publishing is asynchronous: wait (bounded) for the frames to reach the
    // publish point rather than sampling once at t=0.
    wait_until(
        || a.transport.lock().unwrap().outbound_published.len() > 1,
        Duration::from_secs(10),
        "fragment frames reaching the publish point",
    )
    .await;
    let published = a
        .transport
        .lock()
        .expect("transport")
        .outbound_published
        .clone();
    let fragments: Vec<_> = published
        .iter()
        .filter_map(|p| match GossipMessage::from_bytes(p) {
            Some(GossipMessage::InboundDeltaFragment(f)) => Some(f),
            _ => None,
        })
        .collect();
    let whole: Vec<_> = published
        .iter()
        .filter(|p| matches!(GossipMessage::from_bytes(p), Some(GossipMessage::InboundDelta(_))))
        .collect();

    assert!(
        fragments.len() > 1,
        "a >1 KiB row at mtu=256 must produce several fragments (got {})",
        fragments.len()
    );
    assert!(
        whole.is_empty(),
        "no whole-Delta frame may be published when the MTU forces fragmentation"
    );
    for f in &fragments {
        assert!(
            f.payload.len() <= 256,
            "fragment payload {} exceeds the configured MTU",
            f.payload.len()
        );
        assert_eq!(f.delta_id, written.delta_id);
        assert_eq!(f.total_fragments as usize, fragments.len());
    }

    // Reassembled and readable on the receiver through the ordinary read path.
    let observed = wait_for_data(&b, "frag", "row-big", &payload, Duration::from_secs(20)).await;
    assert_eq!(observed.data, payload);

    assert!(
        b.crdt
            .lock()
            .unwrap()
            .dag_node(&written.delta_id)
            .expect("dag")
            .is_some(),
        "the reassembled Delta must be merged exactly as a whole-Delta would be"
    );

    cleanup(&tmp_path("ws6_frag_a"));
    cleanup(&tmp_path("ws6_frag_b"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incomplete_fragment_set_is_never_partially_applied() {
    let port_a = reserve_loopback_port();
    let port_b = reserve_loopback_port();

    let mut deployment = mesh_deployment();
    deployment.mesh_mtu = 256;

    let a = init_mesh_handle_with_deployment("ws6_partial_a", port_a, deployment.clone()).await;
    let b = init_mesh_handle_with_deployment("ws6_partial_b", port_b, deployment).await;

    let data = json!({ "blob": "y".repeat(1_200) });
    let delta = signed_delta(&a, "frag", "row-partial", &data, 4);

    let prepared = a
        .transport
        .lock()
        .unwrap()
        .prepare_outbound(&delta)
        .expect("prepare");
    assert!(prepared.len() > 2);

    // Deliver every fragment except index 1.
    let mut delivered = 0;
    for msg in prepared {
        let GossipMessage::InboundDeltaFragment(frag) = msg else {
            panic!("expected a fragment frame");
        };
        if frag.fragment_index == 1 {
            continue;
        }
        if b.transport
            .lock()
            .unwrap()
            .process_wire_message(GossipMessage::InboundDeltaFragment(frag))
            .is_some()
        {
            delivered += 1;
        }
    }
    assert_eq!(delivered, 0, "an incomplete Delta must never be delivered");

    assert_eq!(b.process_inbound_messages().await.unwrap(), 0);
    match b.read("frag", "row-partial").await {
        Ok(row) => assert_ne!(row.data, data, "no partial row may be projected"),
        Err(_) => {}
    }
    assert!(
        b.crdt
            .lock()
            .unwrap()
            .dag_node(&delta.id)
            .expect("dag")
            .is_none(),
        "a partially reassembled Delta must never reach the DAG"
    );

    // The missing fragment times out rather than pinning memory forever.
    let expired = b.transport.lock().unwrap().reassembly_buffer.expire_stale(
        crate::traits::monotonic_now() as i64
            + crate::transport::fragment::FRAGMENT_STALE_TIMEOUT_US
            + 1,
    );
    assert_eq!(expired, 1, "the partial assembly must be discarded on timeout");

    // And a complete retransmission applies cleanly.
    let prepared = a
        .transport
        .lock()
        .unwrap()
        .prepare_outbound(&delta)
        .expect("prepare");
    let mut completed = None;
    for msg in prepared {
        if let Some(m) = b.transport.lock().unwrap().process_wire_message(msg) {
            completed = Some(m);
        }
    }
    b.receive_inbound(completed.expect("all fragments delivered"))
        .await
        .expect("merge");
    wait_for_data(&b, "frag", "row-partial", &data, Duration::from_secs(10)).await;

    cleanup(&tmp_path("ws6_partial_a"));
    cleanup(&tmp_path("ws6_partial_b"));
}

// ── PART B: 3-node chain A–B–C ──────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_node_chain_relays_a_delta_with_bounded_hops_and_no_duplicates() {
    let port_a = reserve_loopback_port();
    let port_b = reserve_loopback_port();
    let port_c = reserve_loopback_port();
    assert!(
        port_a != port_b && port_b != port_c && port_a != port_c,
        "the three devices need distinct ports"
    );

    let a = init_mesh_handle("ws6_relay_a", port_a).await;
    let b = init_mesh_handle("ws6_relay_b", port_b).await;
    let c = init_mesh_handle("ws6_relay_c", port_c).await;

    // Chain topology: A–B and C–B. A and C never dial each other.
    let addr_b = format!("/ip4/127.0.0.1/tcp/{port_b}");
    connect_peers(&a, &addr_b).await;
    connect_peers(&c, &addr_b).await;
    wait_until(
        || b.mesh_status().peer_count >= 2,
        Duration::from_secs(10),
        "B observing both neighbours",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    assert_eq!(
        a.mesh_status().peer_count,
        1,
        "A must have exactly one neighbour (B) — no direct A–C link"
    );

    let c_did = c.identity.did().to_string();
    let b_did = b.identity.did().to_string();
    let a_did = a.identity.did().to_string();

    // A knows a relay for peers it cannot reach directly (what relay discovery
    // would register in production).
    a.transport
        .lock()
        .unwrap()
        .on_peer_discovered(
            crate::transport::discovery::DiscoveredPeer {
                did: "did:key:relay-for-c".to_string(),
                transport: crate::transport::discovery::PeerTransport::MultiHopRelay {
                    next_hop_did: "did:key:relay-for-c".to_string(),
                },
                hop_count: 1,
            },
            now_micros(),
        )
        .expect("relay discovery");

    let data = json!({ "via": "relay", "seq": 9 });
    let delta = signed_delta(&a, "relay", "row-1", &data, 5);

    a.transport
        .lock()
        .unwrap()
        .send_delta(&c_did, &delta)
        .expect("send_delta must route through the relay");

    // A published exactly one relay envelope, at hop 0 (asynchronously).
    wait_until(
        || {
            a.transport
                .lock()
                .unwrap()
                .outbound_published
                .iter()
                .any(|p| {
                    matches!(
                        GossipMessage::from_bytes(p),
                        Some(GossipMessage::RelayDelta { .. })
                    )
                })
        },
        Duration::from_secs(10),
        "the relay envelope reaching the publish point",
    )
    .await;
    let sent: Vec<_> = a
        .transport
        .lock()
        .unwrap()
        .outbound_published
        .iter()
        .filter_map(|p| match GossipMessage::from_bytes(p) {
            Some(GossipMessage::RelayDelta {
                target_did,
                hop_count,
                visited,
                ..
            }) => Some((target_did, hop_count, visited)),
            _ => None,
        })
        .collect();
    assert_eq!(sent.len(), 1, "exactly one relay envelope must leave A");
    assert_eq!(sent[0].0, c_did);
    assert_eq!(sent[0].1, 0, "the originator sends hop 0");
    assert_eq!(sent[0].2, vec![a_did.clone()]);

    // The Delta reaches C through the production relay path.
    let observed = wait_for_data(&c, "relay", "row-1", &data, Duration::from_secs(20)).await;
    assert_eq!(observed.data, data);

    // B actually forwarded it: one forward, hop advanced by one, visited chain
    // carries B (so the envelope cannot loop back through B).
    wait_until(
        || b.transport.lock().unwrap().relay_forwarded.len() >= 1,
        Duration::from_secs(10),
        "B forwarding the relay envelope",
    )
    .await;
    let forwards = b.transport.lock().unwrap().relay_forwarded.clone();
    assert_eq!(forwards.len(), 1, "B must forward exactly once (no duplicates)");
    assert_eq!(forwards[0].0, c_did);
    assert_eq!(forwards[0].1, 1, "the relay hop count advances by one");
    assert!(
        forwards[0].2.contains(&b_did),
        "the forwarded envelope records B in its visited set"
    );

    // C is the target: it delivers, it does not forward.
    assert!(
        c.transport.lock().unwrap().relay_forwarded.is_empty(),
        "the target must not re-forward a delivered envelope"
    );

    // Applied exactly once: the DAG holds one node for this Delta and C never
    // emitted a second relay copy.
    assert!(
        c.crdt
            .lock()
            .unwrap()
            .dag_node(&delta.id)
            .expect("dag")
            .is_some(),
        "the relayed Delta must be merged on C"
    );

    cleanup(&tmp_path("ws6_relay_a"));
    cleanup(&tmp_path("ws6_relay_b"));
    cleanup(&tmp_path("ws6_relay_c"));
}

#[test]
fn relay_hop_bound_is_enforced_by_the_transport() {
    let mut config = crate::transport::TransportConfig::default();
    config.max_hop_count = 2;
    let transport = crate::transport::MeshTransport::new("did:key:relay".to_string(), [0u8; 32], config);
    let delta = signed_delta_for_relay_unit_test();

    match transport.relay_decision(
        "did:key:target".to_string(),
        delta.clone(),
        1,
        vec!["did:key:origin".to_string()],
    ) {
        RelayDecision::Forward(GossipMessage::RelayDelta { hop_count, .. }) => {
            assert_eq!(hop_count, 2)
        }
        other => panic!("expected a forward at hop 1, got {other:?}"),
    }

    match transport.relay_decision(
        "did:key:target".to_string(),
        delta,
        2,
        vec!["did:key:origin".to_string()],
    ) {
        RelayDecision::Drop(reason) => assert!(reason.contains("hop budget"), "{reason}"),
        other => panic!("expected a drop at the hop limit, got {other:?}"),
    }
}

fn signed_delta_for_relay_unit_test() -> Delta {
    Delta {
        id: [0x11u8; 32],
        author_did: "did:key:origin".to_string(),
        signature: Ed25519Signature::default(),
        schema_hash: [0u8; 32],
        automerge_bytes: vec![1, 2, 3],
        priority: PriorityClass::Low,
        causal_parents: vec![],
        tags: vec![],
        lamport: 1,
        created_at: 0,
    }
}

// ── PART D: 0-RTT resumption, rotation and revocation ──────────────────────

fn x25519_pub(handle: &CoreHandle) -> Vec<u8> {
    let sk = ed25519_dalek::SigningKey::from_bytes(&handle.identity.signing_key_bytes());
    crate::transport::session::ed25519_pubkey_to_x25519(&sk.verifying_key().to_bytes())
        .expect("Ed25519 → X25519")
}

/// Accept exactly one Noise handshake on `listener`, in a dedicated OS thread.
///
/// The responder needs `&mut MeshTransport` across the handshake; the transport
/// is behind a `std::sync::Mutex`, so a dedicated thread with its own
/// current-thread runtime keeps the guard on one thread (a `Send` future is not
/// required). This is the test harness around the production
/// `accept_noise_session`.
fn spawn_noise_responder(
    handle: Arc<CoreHandle>,
    listener: std::net::TcpListener,
    initiator_did: String,
    now: i64,
) -> std::thread::JoinHandle<Result<(SessionEstablishment, Vec<u8>), String>> {
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        runtime.block_on(async move {
            let (sock, _) = listener.accept().map_err(|e| e.to_string())?;
            // `TcpStream::from_std` requires a non-blocking socket.
            sock.set_nonblocking(true).map_err(|e| e.to_string())?;
            let std_stream = tokio::net::TcpStream::from_std(sock).map_err(|e| e.to_string())?;
            let mut stream = TcpNoiseStream::new(std_stream);
            let seed = handle.identity.signing_key_bytes();
            let mut transport = handle.transport.lock().unwrap();
            transport
                .accept_noise_session(initiator_did, &seed, &mut stream, now)
                .await
                .map_err(|e| e.to_string())
        })
    })
}

/// One full client/server Noise exchange over a fresh loopback TCP connection.
async fn attempt_session(
    initiator: &Arc<CoreHandle>,
    responder: &Arc<CoreHandle>,
    trust: TrustLevel,
    payload: &[u8],
    now: i64,
) -> (
    Result<SessionEstablishment, String>,
    Result<(SessionEstablishment, Vec<u8>), String>,
) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener
        .local_addr()
        .expect("local addr")
        .to_string();
    let responder_did = responder.identity.did().to_string();
    let initiator_did = initiator.identity.did().to_string();
    let thread = spawn_noise_responder(responder.clone(), listener, initiator_did, now);

    let client = async {
        let mut stream = TcpNoiseStream::connect(&addr)
            .await
            .map_err(|e| e.to_string())?;
        let seed = initiator.identity.signing_key_bytes();
        let mut transport = initiator.transport.lock().unwrap();
        transport
            .initiate_session_with_payload(
                responder_did,
                trust,
                &seed,
                &x25519_pub(responder),
                Some(&mut stream),
                now,
                payload,
            )
            .await
            .map_err(|e| e.to_string())
    }
    .await;

    (client, thread.join().expect("responder thread"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn noise_session_resumes_with_0rtt_and_rotates_keys_in_place() {
    let port_a = reserve_loopback_port();
    let port_b = reserve_loopback_port();

    let a = init_mesh_handle("ws6_sess_a", port_a).await;
    let b = init_mesh_handle("ws6_sess_b", port_b).await;

    // Two real Swarms on loopback, connected through the production dial path.
    connect_peers(&a, &format!("/ip4/127.0.0.1/tcp/{port_b}")).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let now = now_secs();
    let b_did = b.identity.did().to_string();

    // 1. First connection: no ticket yet → full handshake, no 0-RTT payload.
    let (client, server) = attempt_session(&a, &b, TrustLevel::Verified, b"", now).await;
    let first = client.expect("full handshake must succeed");
    let (server_est, server_payload) = server.expect("responder handshake");
    assert!(!first.resumed, "the first connection cannot resume");
    assert_eq!(first.zero_rtt_payload_len, 0);
    assert!(!server_est.resumed);
    assert!(server_payload.is_empty());
    {
        let stats = a.transport.lock().unwrap().session_manager.resumption_stats();
        assert_eq!(stats.full_handshakes, 1, "exactly one full handshake");
        assert_eq!(stats.resumptions, 0);
    }
    assert!(
        a.transport
            .lock()
            .unwrap()
            .session_manager
            .can_resume(&b_did, now),
        "a successful handshake must cache a resumption ticket"
    );

    // 2. Reconnect: the cached ticket is used and the first application frame
    //    rides in handshake message 1 (0-RTT).
    let frame = b"first-frame-after-reconnect";
    let (client, server) = attempt_session(&a, &b, TrustLevel::Verified, frame, now + 5).await;
    let resumed = client.expect("resumption must succeed");
    let (server_est, server_payload) = server.expect("responder resumption");
    assert!(
        resumed.resumed,
        "the reconnect must take the 0-RTT resumption path"
    );
    assert_eq!(resumed.zero_rtt_payload_len, frame.len());
    assert!(server_est.resumed);
    assert_eq!(
        server_payload, frame,
        "the 0-RTT payload must be delivered with the handshake flight"
    );
    {
        let stats = a.transport.lock().unwrap().session_manager.resumption_stats();
        assert_eq!(stats.resumptions, 1, "exactly one resumption");
        assert_eq!(
            stats.full_handshakes, 1,
            "a resumption must not perform another full handshake"
        );
    }

    // ── Key rotation while the session (connection) stays up ────────────
    let a_did = a.identity.did().to_string();

    let encrypt = |handle: &Arc<CoreHandle>, peer: &str, msg: &[u8]| -> Vec<u8> {
        let mut transport = handle.transport.lock().unwrap();
        let session = transport
            .active_sessions
            .get_mut(peer)
            .expect("live session");
        let state = session.transport.as_mut().expect("transport state");
        let mut out = vec![0u8; 65535];
        let n = state.write_message(msg, &mut out).expect("encrypt");
        out.truncate(n);
        out
    };
    let decrypt = |handle: &Arc<CoreHandle>, peer: &str, frame: &[u8]| -> Option<Vec<u8>> {
        let mut transport = handle.transport.lock().unwrap();
        let session = transport
            .active_sessions
            .get_mut(peer)
            .expect("live session");
        let state = session.transport.as_mut().expect("transport state");
        let mut out = vec![0u8; 65535];
        match state.read_message(frame, &mut out) {
            Ok(n) => {
                out.truncate(n);
                Some(out)
            }
            Err(_) => None,
        }
    };

    // Data flows before rotation.
    let pre = encrypt(&a, &b_did, b"pre-rotation");
    assert_eq!(
        decrypt(&b, &a_did, &pre),
        Some(b"pre-rotation".to_vec()),
        "the live session must carry data before rotation"
    );

    // Drive the production rotation clock past the configured interval while
    // both sides keep the session (the connection is never torn down).
    let rotate_at = now + 3_600 + 10;
    a.transport.lock().unwrap().tick_key_rotation(rotate_at);
    b.transport.lock().unwrap().tick_key_rotation(rotate_at);
    {
        let transport = a.transport.lock().unwrap();
        let session = transport.active_sessions.get(&b_did).expect("session");
        assert!(
            session.last_rotated_secs >= rotate_at,
            "the session must record the rotation"
        );
        assert!(
            session.transport.is_some(),
            "rotation must rekey in place, not tear the session down"
        );
    }

    // Data continues to flow under the rotated keys…
    let post = encrypt(&a, &b_did, b"post-rotation");
    assert_eq!(
        decrypt(&b, &a_did, &post),
        Some(b"post-rotation".to_vec()),
        "the session must keep carrying data after rekeying"
    );

    // …and a frame captured under the pre-rotation key is not accepted.
    assert_eq!(
        decrypt(&b, &a_did, &pre),
        None,
        "no frame encrypted under the pre-rotation key may be accepted after rotation"
    );

    cleanup(&tmp_path("ws6_sess_a"));
    cleanup(&tmp_path("ws6_sess_b"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resumption_negative_cases_fall_back_or_fail_closed() {
    let port_a = reserve_loopback_port();
    let port_b = reserve_loopback_port();

    let a = init_mesh_handle("ws6_neg_a", port_a).await;
    let b = init_mesh_handle("ws6_neg_b", port_b).await;
    let b_did = b.identity.did().to_string();
    let now = now_secs();

    // A ticket belonging to another peer can never be used for this one.
    {
        let mut transport = a.transport.lock().unwrap();
        transport.session_manager.store_credential(
            "did:key:some-other-peer".to_string(),
            ResumptionCredential {
                peer_did: "did:key:some-other-peer".to_string(),
                issued_at: now,
                credential_bytes: vec![0xAB; 32],
            },
        );
        assert!(
            !transport.session_manager.can_resume(&b_did, now),
            "another peer's ticket must not satisfy this peer's lookup"
        );
    }

    // No ticket for B at all → full handshake.
    let (client, server) = attempt_session(&a, &b, TrustLevel::Verified, b"x", now).await;
    let est = client.expect("full handshake with no ticket");
    assert!(!est.resumed);
    assert!(server.expect("responder").0.resumed == false);
    let full_after_first = a.transport.lock().unwrap().session_manager.resumption_stats().full_handshakes;

    // Expired ticket (injected clock advance beyond the 24 h window).
    let (client, _server) = attempt_session(
        &a,
        &b,
        TrustLevel::Verified,
        b"x",
        now + CREDENTIAL_VALIDITY_SECS + 1,
    )
    .await;
    let est = client.expect("expired ticket must fall back to a full handshake");
    assert!(!est.resumed, "an expired ticket must not be used");
    {
        let stats = a.transport.lock().unwrap().session_manager.resumption_stats();
        assert!(
            stats.full_handshakes > full_after_first,
            "the fallback must be a real full handshake"
        );
        assert!(stats.resumption_fallbacks >= 1);
    }

    // Tampered ticket: the resumption flight is rejected (fail closed), the
    // poisoned ticket is dropped, and a fresh connection completes a full
    // handshake.
    let tamper_now = now_secs();
    {
        let mut transport = a.transport.lock().unwrap();
        transport.session_manager.store_credential(
            b_did.clone(),
            ResumptionCredential {
                peer_did: b_did.clone(),
                issued_at: tamper_now,
                credential_bytes: vec![0x7u8; 32],
            },
        );
    }
    let (client, _server) = attempt_session(&a, &b, TrustLevel::Verified, b"x", tamper_now).await;
    assert!(
        client.is_err(),
        "a tampered ticket must fail closed rather than silently succeed"
    );
    assert!(
        !a.transport
            .lock()
            .unwrap()
            .session_manager
            .can_resume(&b_did, tamper_now),
        "the rejected ticket must be evicted"
    );

    // The rejected resumption attempts a full handshake on the poisoned
    // stream, which fails and records the Req 6.6 retry backoff; advance past
    // it (30 s) for the fresh connection.
    let (client, _server) =
        attempt_session(&a, &b, TrustLevel::Verified, b"x", tamper_now + 31).await;
    let est = client.expect("after eviction a full handshake must succeed");
    assert!(!est.resumed);

    // Cache eviction beyond 1024 entries: B's ticket is gone, so the next
    // connection is a full handshake again.
    {
        let evict_at = tamper_now + 32;
        let mut transport = a.transport.lock().unwrap();
        for i in 0..1024u32 {
            let peer = format!("did:key:evict-{i}");
            transport.session_manager.store_credential(
                peer.clone(),
                ResumptionCredential {
                    peer_did: peer,
                    issued_at: evict_at,
                    credential_bytes: vec![i as u8; 32],
                },
            );
        }
        assert_eq!(
            transport.session_manager.cache_size(),
            crate::transport::session::MAX_RESUMPTION_CACHE
        );
        assert!(
            !transport.session_manager.can_resume(&b_did, evict_at),
            "B's ticket must be evicted once the cache overflows"
        );
    }
    let (client, _server) =
        attempt_session(&a, &b, TrustLevel::Verified, b"x", tamper_now + 32).await;
    let est = client.expect("post-eviction handshake");
    assert!(!est.resumed, "an evicted ticket forces a full handshake");

    cleanup(&tmp_path("ws6_neg_a"));
    cleanup(&tmp_path("ws6_neg_b"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_peer_is_refused_at_the_handshake_layer() {
    let port_a = reserve_loopback_port();
    let a = init_mesh_handle("ws6_revoked", port_a).await;

    let b_did = "did:key:z6MkRevokedPeer".to_string();
    let (mut client, mut peer) = DuplexNoiseStream::pair();

    let seed = a.identity.signing_key_bytes();
    let mut transport = a.transport.lock().unwrap();
    let err = transport
        .initiate_session(
            b_did.clone(),
            TrustLevel::Revoked,
            &seed,
            &[9u8; 32],
            Some(&mut client),
            now_secs(),
        )
        .await
        .expect_err("a revoked peer must be refused");

    assert!(
        matches!(err, TirBaseError::PeerRevoked { .. }),
        "expected PeerRevoked at the handshake layer, got: {err}"
    );
    assert!(
        !transport.active_sessions.contains_key(&b_did),
        "a refused handshake must not register a session"
    );

    // No handshake byte was written: the peer side sees nothing.
    let mut buf = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(200), peer.read_noise_message(&mut buf))
            .await
            .is_err(),
        "a revoked peer must be refused before any data exchange"
    );

    cleanup(&tmp_path("ws6_revoked"));
}
