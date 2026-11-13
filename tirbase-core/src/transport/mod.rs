//! MeshTransport — rust-libp2p Swarm setup and peer lifecycle management (Req 5).
//!
//! The `MeshTransport` struct and `TransportConfig` are defined unconditionally
//! so the API surface is identical on both build targets (Req 1.2, 1.5).
//! All `libp2p`-specific code is gated behind `#[cfg(feature = "native")]`.

#![allow(dead_code, unused_variables, unused_imports)]

#[cfg(feature = "native")]
pub mod ble;
pub mod challenge;
pub mod discovery;
pub mod fragment;
pub mod message;
pub mod priority;
pub mod saturate;
pub mod scheduler;
pub mod session;

use crate::api::types::TrustLevel;
use crate::crdt::delta::{Delta, Did, PriorityClass};
use crate::errors::TirBaseError;
use crate::events::{emit_transport, ReasonCode, Severity};
use crate::identity::did::resolve_did;
#[cfg(feature = "native")]
use crate::transport::session::{ed25519_privkey_to_x25519, ed25519_pubkey_to_x25519};
use crate::transport::{
    discovery::{DiscoveredPeer, PeerDiscovery, PeerTransport, RetryEntry},
    fragment::{fragment as fragment_delta, ReassemblyBuffer},
    saturate::{SaturateModeStateMachine, SaturateState, SATURATE_LEASE_DURATION_SECS},
    scheduler::{DrrScheduler, QueuedDelta},
    session::SessionManager,
};

/// Current wall-clock time in microseconds since the Unix epoch.
///
/// Reads through the injected [`crate::traits::TimeSource`] wall-clock hint
/// (PV-3.8, PV-3.12); the transport never calls the system clock directly.
fn current_timestamp_micros() -> i64 {
    crate::traits::wall_hint().unwrap_or_default()
}

/// Default link capacity (bytes/sec) for the DRR scheduler when no transport
/// link speed has been reported (Req 12).
///
/// Used both when constructing the scheduler and when ticking it from the
/// production loop, so the per-epoch budget and the quantum allotments stay
/// in sync.
pub(crate) const DEFAULT_LINK_CAPACITY_BYTES: u64 = 1_000_000;

// ─── TransportConfig ──────────────────────────────────────────────────────────

/// Runtime configuration for the mesh transport layer.
#[derive(Debug, Clone)]
pub struct TransportConfig {
 /// Seconds without contact before removing a peer from the active list (Req 5.6).
    pub peer_timeout_secs: u64,
 /// Seconds between delivery retry attempts (Req 5.6).
    pub retry_interval_secs: u64,
 /// Maximum entries in the retry queue (Req 5.6).
    pub max_retry_queue: usize,
 /// Maximum hop count for multi-hop relay routing (Req 5.5).
    pub max_hop_count: u8,
 /// Active transport MTU in bytes. Deltas are fragmented when `mtu < 256`
 /// (Req 5.7). A value of 0 means "do not fragment".
    pub mtu: usize,
 /// Key rotation interval in seconds — clamped to `[60, 86400]` (Req 6.4).
    pub key_rotation_interval_secs: u64,
 /// libp2p listen address (native-only; ignored on wasm).
    pub listen_addr: String,
 /// M-of-N manager-signature threshold for terminating Saturate_Mode via a
 /// Lease Termination Delta (Req 13.6). Clamped to `>= 1` at construction.
    pub saturate_termination_threshold_m: usize,
 /// 32-byte Ed25519 root CA public key used by the Saturate_Mode state
 /// machine to verify Manager DISASTER_ALERT Biscuit tokens offline
 /// (Req 13.1, 13.7). Empty = explicit unconfigured state: activation
 /// fails until a key is configured.
    pub root_ca_public_key: Vec<u8>,
 /// Duration in seconds of a Saturate_Mode Lease opened by a DISASTER_ALERT
 /// activation or heartbeat renewal (Req 13.3). Defaults to
 /// [`SATURATE_LEASE_DURATION_SECS`] (60 minutes — the spec window); a
 /// deployment may configure a shorter window (e.g. faster failover or
 /// runtime tests) or a longer one. Clamped to `>= 1` at construction so a
 /// misconfigured zero never opens an already-expired lease.
    pub saturate_lease_duration_secs: i64,
 /// Enable BLE transport bridge (native-only).
    pub mesh_ble_enabled: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            peer_timeout_secs: 60,
            retry_interval_secs: 30,
            max_retry_queue: 1_000,
            max_hop_count: 4,
            mtu: 0, // no fragmentation by default
            key_rotation_interval_secs: 3_600,
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            saturate_termination_threshold_m: 1,
            root_ca_public_key: vec![],
            saturate_lease_duration_secs: SATURATE_LEASE_DURATION_SECS,
            mesh_ble_enabled: false,
        }
    }
}

/// Outcome of establishing a Noise session with a peer (Req 6.2–6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionEstablishment {
 /// `true` when the cached 0-RTT ticket was reused and the first application
 /// frame travelled inside handshake message 1.
    pub resumed: bool,
 /// Bytes of 0-RTT payload that accompanied the handshake flight (0 on a
 /// full handshake).
    pub zero_rtt_payload_len: usize,
}

/// Decision taken by a relay node for an inbound `RelayDelta`.
#[derive(Debug)]
pub(crate) enum RelayDecision {
    /// Addressed to this node: deliver the wrapped Delta locally.
    Deliver(crate::transport::message::GossipMessage),
    /// Not addressed to this node: re-publish this relay envelope onward.
    Forward(crate::transport::message::GossipMessage),
    /// Hop budget exhausted or the envelope already traversed this node.
    Drop(&'static str),
}

// ─── Native-only libp2p behaviour ────────────────────────────────────────────

/// Combined libp2p network behaviour for TirBase (native-only).
///
/// The `#[derive(NetworkBehaviour)]` macro combines the sub-behaviours into
/// a single type accepted by the Swarm.
#[cfg(feature = "native")]
#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct TirBaseBehaviour {
 /// Automatic peer discovery on local IP networks (Req 5.2).
    pub mdns: libp2p::mdns::tokio::Behaviour,
 /// Gossip-based Delta propagation.
    pub gossipsub: libp2p::gossipsub::Behaviour,
 /// Peer identification (exchanges DID-compatible public keys).
    pub identify: libp2p::identify::Behaviour,
 /// Connectivity keep-alive.
    pub ping: libp2p::ping::Behaviour,
}

#[cfg(feature = "native")]
pub use libp2p::swarm::NetworkBehaviour;

// ─── mDNS discovery → dialing (Req 5.2) ──────────────────────────────────────

/// Dial every peer reported by an mDNS `Discovered` event and register it as a
/// Gossipsub explicit peer.
///
/// mDNS only *announces* peers — a connection is never opened until the
/// application asks the Swarm to dial the announced address. This is the
/// missing half of discovery: without it, mDNS neighbours stay unconnected and
/// the `add_explicit_peer` registration (which Gossipsub only honours for
/// connected peers) has nothing to gossip over.
///
/// Each announced address has the remote `/p2p/<peer-id>` suffix appended
/// before dialing. Repeated `Discovered` events for an already-connected or
/// in-flight peer are no-ops (the default `DialOpts` condition is
/// `DisconnectedAndNotDialing`), so periodic mDNS re-announcements never
/// trigger duplicate dials.
///
/// Production caller: the Swarm polling task spawned in `CoreHandle::init`
/// (`api/mod.rs`, `Mdns(Discovered)` event arm) forwards every discovered
/// `(PeerId, Multiaddr)` pair here.
#[cfg(feature = "native")]
pub(crate) fn dial_discovered_mdns_peers(
    swarm: &mut libp2p::Swarm<TirBaseBehaviour>,
    discovered: Vec<(libp2p::PeerId, libp2p::Multiaddr)>,
) {
    for (peer_id, addr) in discovered {
 // Keep the peer in Gossipsub's explicit set (pre-existing behaviour).
        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);

 // Append `/p2p/<peer-id>` unless the announced address already ends
 // with it; an address bound to a *different* peer id is unusable.
        let dial_addr = match addr.with_p2p(peer_id) {
            Ok(addr) => addr,
            Err(addr) => {
                emit_transport(Severity::Medium, ReasonCode::HandshakeFailed, None, format!(
                    "[transport] mDNS: skipping {peer_id} — announced address {addr} carries a different peer id"
                ));
                continue;
            }
        };

        match swarm.dial(
            libp2p::swarm::dial_opts::DialOpts::peer_id(peer_id)
                .addresses(vec![dial_addr])
                .build(),
        ) {
            Ok(()) => {
                emit_transport(
                    Severity::Low,
                    ReasonCode::PeerConnected,
                    None,
                    format!("[transport] mDNS: dialing discovered peer {peer_id}"),
                );
            }
            Err(e) => {
                emit_transport(
                    Severity::Medium,
                    ReasonCode::HandshakeFailed,
                    None,
                    format!("[transport] mDNS: dial to discovered peer {peer_id} failed: {e}"),
                );
            }
        }
    }
}

// ─── MeshTransport ────────────────────────────────────────────────────────────

/// The mesh transport layer — manages peer connections, scheduling, and
/// session cryptography (Req 5.1).
pub struct MeshTransport {
 /// Runtime configuration.
    pub config: TransportConfig,

 /// Peer discovery and retry state.
    pub discovery: PeerDiscovery,

 /// Noise session manager.
    pub session_manager: SessionManager,

 /// Per-Delta fragment reassembly buffer.
    pub reassembly_buffer: ReassemblyBuffer,

 /// The local device DID.
    pub local_did: Did,

 /// The local Ed25519 static private key bytes (used for Noise_IK session
 /// initiation when wiring into the libp2p transport — Req 6.1).
    pub local_static_privkey: [u8; 32],

 /// The shared Gossipsub topic all TirBase nodes subscribe to.
    pub gossip_topic: String,

 /// DRR Scheduler for outbound Delta prioritisation (Req 12).
    pub scheduler: DrrScheduler,

 /// Native-only: libp2p Swarm (None before `start()` is called, and None
 /// after the Swarm is detached into the polling task via `take_swarm`).
    #[cfg(feature = "native")]
    swarm: Option<libp2p::Swarm<TirBaseBehaviour>>,

 /// Native-only: outbound publish channel sender. Installed by
 /// `take_swarm` when the Swarm is detached; `send_delta` forwards
 /// prepared payloads here and the Swarm polling task (which owns the
 /// receiver end) publishes them to the Gossipsub topic.
    #[cfg(feature = "native")]
    pub(crate) outbound_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,

 /// Native-only BLE transport: outbound channel for BLE-bound payloads.
 /// The BLE I/O task (spawned in `start` when `mesh_ble_enabled` is true)
 /// drains this receiver and writes chunks to the peer's GATT characteristic.
    #[cfg(feature = "native")]
    pub(crate) ble_outbound_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,

 /// Native-only BLE transport: inbound channel for reassembled BLE Deltas.
 /// The BLE I/O task pushes completed Deltas here; `poll_ble_inbound` drains
 /// this receiver and dispatches each message through `process_wire_message`.
    #[cfg(feature = "native")]
    pub(crate) ble_inbound_tx:
        Option<tokio::sync::mpsc::Sender<crate::transport::message::GossipMessage>>,
    #[cfg(feature = "native")]
    pub(crate) ble_inbound_rx:
        Option<tokio::sync::mpsc::Receiver<crate::transport::message::GossipMessage>>,

 /// Native-only BLE transport: outbound payload receiver, handed to the
 /// bridge runner (`ble::run_ble_bridge`) when the link attaches.
    #[cfg(feature = "native")]
    pub(crate) ble_outbound_rx: Option<tokio::sync::mpsc::Receiver<Vec<u8>>>,

 /// Native-only BLE transport: the mesh inbound channel that fully
 /// reassembled BLE messages are dispatched to. Installed by
 /// `CoreHandle::init` so BLE Deltas merge through the same
 /// `receive_inbound` path as Gossipsub Deltas.
    #[cfg(feature = "native")]
    pub(crate) ble_dispatch_tx:
        Option<tokio::sync::mpsc::Sender<crate::transport::message::GossipMessage>>,

 /// Test-only: last inbound message received over BLE.
    #[cfg(all(feature = "native", test))]
    pub(crate) last_ble_inbound: Option<crate::transport::message::GossipMessage>,

 /// Test-only: payloads that reached the outbound publish point (recorded
 /// by the Swarm polling task immediately before `gossipsub.publish`).
    #[cfg(all(feature = "native", test))]
    pub(crate) outbound_published: Vec<Vec<u8>>,

 /// Test-only: relay envelopes this node forwarded, recorded by the Swarm
 /// polling task as `(target_did, hop_count, visited)`.
 ///
 /// Evidence that a relay node actually carried a Delta onward, that the hop
 /// count advanced by exactly one, and that it forwarded the envelope once.
    #[cfg(all(feature = "native", test))]
    pub(crate) relay_forwarded: Vec<(Did, u8, Vec<Did>)>,

 /// Active Noise_IK sessions keyed by remote DID (Req 6.1).
    pub(crate) active_sessions:
        std::collections::BTreeMap<Did, crate::transport::session::NoiseSession>,

 /// Saturate_Mode state machine (Req 13): owns the lease lifecycle
 /// (activate / renew / M-of-N terminate / expiry tick) and verifies
 /// Manager DISASTER_ALERT Biscuit tokens offline. Instantiated here in
 /// production code — never only in tests — and driven by
 /// [`MeshTransport::activate_saturate_mode`].
    pub(crate) saturate: SaturateModeStateMachine,
}

// The transport owns the local Noise static private key, so it is registered
// key material and zeroized on drop (CLAIM-6.2, PV-3.7).
impl zeroize::Zeroize for MeshTransport {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.local_static_privkey);
    }
}

impl Drop for MeshTransport {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.local_static_privkey);
    }
}

impl zeroize::ZeroizeOnDrop for MeshTransport {}

impl MeshTransport {
 /// Create a new `MeshTransport` with the given configuration.
    pub fn new(local_did: Did, local_static_privkey: [u8; 32], config: TransportConfig) -> Self {
        let discovery = PeerDiscovery::new(
            config.max_hop_count,
            config.peer_timeout_secs,
            config.retry_interval_secs,
            config.max_retry_queue,
        );
        let session_manager =
            SessionManager::new(local_did.clone(), config.key_rotation_interval_secs);

 // The Saturate_Mode state machine is production-instanceable here
 // (Subphase 3.1): its termination threshold and root CA verification
 // key come from `TransportConfig`, which `CoreHandle::init` feeds from
 // the deployment config.
        let saturate = SaturateModeStateMachine::new(
            config.saturate_termination_threshold_m.max(1),
            config.root_ca_public_key.clone(),
 // Subphase 3.4: the lease window is deployment-configurable; a
 // short configured duration is what lets a runtime test let the
 // lease expire through the wall clock instead of backdating it.
            config.saturate_lease_duration_secs.max(1),
        );

        Self {
            discovery,
            session_manager,
            reassembly_buffer: ReassemblyBuffer::default(),
            local_did,
            local_static_privkey,
            config,
            gossip_topic: "tirbase/v1".to_string(),
            scheduler: DrrScheduler::new(DEFAULT_LINK_CAPACITY_BYTES),
            active_sessions: std::collections::BTreeMap::new(),
            saturate,
            #[cfg(feature = "native")]
            swarm: None,
            #[cfg(feature = "native")]
            outbound_tx: None,
            #[cfg(feature = "native")]
            ble_outbound_tx: None,
            #[cfg(feature = "native")]
            ble_inbound_tx: None,
            #[cfg(feature = "native")]
            ble_inbound_rx: None,
            #[cfg(feature = "native")]
            ble_outbound_rx: None,
            #[cfg(feature = "native")]
            ble_dispatch_tx: None,
            #[cfg(all(feature = "native", test))]
            outbound_published: Vec::new(),
            #[cfg(all(feature = "native", test))]
            relay_forwarded: Vec::new(),
            #[cfg(all(feature = "native", test))]
            last_ble_inbound: None,
        }
    }

 // ── Peer lifecycle ────────────────────────────────────────────────────────

 // ── Peer lifecycle ────────────────────────────────────────────────────────

 /// Return the list of currently active peer DIDs.
    pub fn active_peers(&self) -> Vec<Did> {
        self.discovery.active_peers()
    }

 /// Record a peer as discovered and add it to the active peer table.
 ///
 /// Multi-hop peers whose `hop_count > max_hop_count` are silently
 /// rejected (Req 5.5).
    pub fn on_peer_discovered(
        &mut self,
        peer: DiscoveredPeer,
        now_us: i64,
    ) -> Result<(), TirBaseError> {
        self.discovery.on_peer_discovered(peer, now_us)
    }

 /// Decide what a relay node does with an inbound relay envelope.
 ///
 /// This is the loop- and hop-bound half of multi-hop routing (Req 5.5):
 /// an envelope addressed to this node is delivered locally; one whose
 /// `visited` set already contains this node is dropped (a cycle in the relay
 /// graph would otherwise loop forever); one whose `hop_count` reached
 /// `max_hop_count` is dropped (the chain length is bounded); anything else is
 /// forwarded with `hop_count + 1` and this node appended to `visited`.
 ///
 /// Production caller: the Swarm polling task in `CoreHandle::init`, which
 /// re-publishes `Forward` results onto the shared topic.
    pub(crate) fn relay_decision(
        &self,
        target_did: Did,
        delta: Delta,
        hop_count: u8,
        visited: Vec<Did>,
    ) -> RelayDecision {
        if target_did == self.local_did {
            return RelayDecision::Deliver(
                crate::transport::message::GossipMessage::InboundDelta(delta),
            );
        }

        if visited.iter().any(|d| d == &self.local_did) {
            return RelayDecision::Drop("relay loop: envelope already traversed this node");
        }

        if hop_count >= self.config.max_hop_count {
            return RelayDecision::Drop("relay hop budget exhausted");
        }

        let mut next_visited = visited;
        next_visited.push(self.local_did.clone());

        RelayDecision::Forward(crate::transport::message::GossipMessage::RelayDelta {
            target_did,
            delta,
            hop_count: hop_count.saturating_add(1),
            visited: next_visited,
        })
    }

 /// Remove a peer from the active list immediately.
    pub fn remove_peer(&mut self, peer_did: &Did) {
        self.discovery.remove_peer(peer_did);
    }

 /// Dial a peer via a BLE routing bridge (Req 5.3).
 ///
 /// Records the target peer as reachable through the given BLE bridge.
 /// The BLE transport itself is out of scope for v1; this method ensures
 /// the `BleBridge` transport variant is populated and the peer is active.
    pub fn dial_ble_bridge(
        &mut self,
        target_did: Did,
        bridge_did: Did,
        now_us: i64,
    ) -> Result<(), TirBaseError> {
        self.on_peer_discovered(
            DiscoveredPeer {
                did: target_did.clone(),
                transport: PeerTransport::BleBridge {
                    bridge_did: bridge_did.clone(),
                },
                hop_count: 1,
            },
            now_us,
        )?;
        emit_transport(
            Severity::Medium,
            ReasonCode::HandshakeFailed,
            None,
            format!("[transport] BLE bridge: dialing {target_did} via bridge {bridge_did}"),
        );
        Ok(())
    }

 /// Initiate a Noise_IK session with a peer after a libp2p connection is
 /// established (Req 6.1).
 ///
 /// When `remote_static_pubkey` is non-empty (direct-connect path), performs
 /// a full Noise_IK handshake via `SessionManager::initiate` with the
 /// peer's static public key as-is (already in X25519 form).
 ///
 /// When `remote_static_pubkey` is empty (production libp2p path), attempts
 /// to resolve the peer's static public key from their DID (`did:key:` →
 /// Ed25519 → X25519 Montgomery conversion) and calls `SessionManager::initiate`
 /// with the converted key. The libp2p transport has already performed
 /// its own Noise XX transport encryption; this application-layer Noise IK
 /// handshake establishes the session credentials for the CRDT mesh layer.
 ///
 /// If the peer's DID cannot be resolved (e.g. a libp2p PeerId-based
 /// pseudo-DID that is not a valid `did:key:`), falls back to
 /// `SessionManager::register_session` so the `register_session` path is
 /// preserved for backward compatibility.
    #[cfg(feature = "native")]
    pub async fn initiate_session(
        &mut self,
        peer_did: Did,
        peer_trust_level: TrustLevel,
        local_static_privkey: &[u8],
        remote_static_pubkey: &[u8],
        stream: Option<&mut dyn crate::transport::session::AsyncNoiseStream>,
        now_secs: i64,
    ) -> Result<(), TirBaseError> {
        self.initiate_session_with_payload(
            peer_did,
            peer_trust_level,
            local_static_privkey,
            remote_static_pubkey,
            stream,
            now_secs,
            &[],
        )
        .await
        .map(|_| ())
    }

 /// Initiate a session, attempting 0-RTT resumption from the cached ticket
 /// and carrying `zero_rtt_payload` in handshake message 1 when it succeeds.
 ///
 /// Returns whether the resumption path was taken; a full handshake reports
 /// `resumed: false` and an empty `zero_rtt_payload_len`.
 #[cfg(feature = "native")]
    #[allow(clippy::too_many_arguments)]
    pub async fn initiate_session_with_payload(
        &mut self,
        peer_did: Did,
        peer_trust_level: TrustLevel,
        local_static_privkey: &[u8],
        remote_static_pubkey: &[u8],
        stream: Option<&mut dyn crate::transport::session::AsyncNoiseStream>,
        now_secs: i64,
        zero_rtt_payload: &[u8],
    ) -> Result<SessionEstablishment, TirBaseError> {
 // Convert the Ed25519 private key seed to the X25519 scalar used by
 // Noise_IK_25519. `local_static_privkey` is always the Ed25519 signing
 // seed (from `IdentityManager::signing_key_bytes()`); `snow`'s builder
 // applies clamping internally via `mul_base_clamped`.
        let x25519_local_privkey = ed25519_privkey_to_x25519(local_static_privkey)?;

        let session = if remote_static_pubkey.is_empty() {
 // Production libp2p path: resolve the peer's Ed25519 public key from
 // their DID, convert to X25519 Montgomery form for Noise_IK_25519,
 // and perform the full application-layer handshake (Req 6.1).
 //
 // If the DID cannot be resolved (e.g. the caller passed a libp2p
 // PeerId-derived pseudo-DID), fall back to register_session — the
 // libp2p transport has already completed its own Noise handshake
 // and we only need rotation tracking + resumption cache sync.
            match resolve_did(&peer_did) {
                Ok(ed25519_pk) => match ed25519_pubkey_to_x25519(&ed25519_pk) {
                    Ok(x25519_pk) => {
                        self.session_manager
                            .initiate_with_0rtt(
                                peer_did.clone(),
                                peer_trust_level,
                                &x25519_local_privkey,
                                &x25519_pk,
                                stream,
                                now_secs,
                                zero_rtt_payload,
                            )
                            .await?
                    }
                    Err(e) => {
                        emit_transport(
                            Severity::Medium,
                            ReasonCode::HandshakeFailed,
                            None,
                            format!(
                                "[transport] initiate_session: X25519 conversion \
                                 failed for peer '{}' ({e}); falling back to register_session",
                                peer_did
                            ),
                        );
                        self.session_manager
                            .register_session(peer_did.clone(), now_secs)
                    }
                },
                Err(e) => {
                    emit_transport(
                        Severity::Medium,
                        ReasonCode::HandshakeFailed,
                        None,
                        format!(
                            "[transport] initiate_session: DID '{}' not resolvable \
                         for Noise IK handshake ({e}); falling back to register_session",
                            peer_did
                        ),
                    );
                    self.session_manager
                        .register_session(peer_did.clone(), now_secs)
                }
            }
        } else {
            self.session_manager
                .initiate_with_0rtt(
                    peer_did.clone(),
                    peer_trust_level,
                    &x25519_local_privkey,
                    remote_static_pubkey,
                    stream,
                    now_secs,
                    zero_rtt_payload,
                )
                .await?
        };
        let establishment = SessionEstablishment {
            resumed: session.resumed,
            zero_rtt_payload_len: if session.resumed {
                zero_rtt_payload.len()
            } else {
                0
            },
        };
        self.active_sessions.insert(peer_did.clone(), session);
        Ok(establishment)
    }

 /// Accept an inbound Noise_IK handshake and register the responder session.
 ///
 /// Returns the 0-RTT payload the initiator carried in handshake message 1
 /// (empty for a full handshake) together with the establishment summary.
 /// Production caller: the session listener of a peer-facing transport; the
 /// two-Swarm loopback tests drive it over a real TCP stream.
 #[cfg(feature = "native")]
    pub async fn accept_noise_session(
        &mut self,
        peer_did: Did,
        local_static_privkey: &[u8],
        stream: &mut dyn crate::transport::session::AsyncNoiseStream,
        now_secs: i64,
    ) -> Result<(SessionEstablishment, Vec<u8>), TirBaseError> {
        // The caller passes the Ed25519 signing seed (same convention as
        // `initiate_session`); `snow` needs the X25519 scalar.
        let x25519_local_privkey = ed25519_privkey_to_x25519(local_static_privkey)?;
        let (session, payload) = self
            .session_manager
            .respond(
                peer_did.clone(),
                &x25519_local_privkey,
                stream,
                now_secs,
            )
            .await?;
        let establishment = SessionEstablishment {
            resumed: session.resumed,
            zero_rtt_payload_len: payload.len(),
        };
        self.active_sessions.insert(peer_did, session);
        Ok((establishment, payload))
    }

 /// Register an already-established Noise session (backward-compatible path).
 ///
 /// Use this when the application layer already holds a live
 /// `snow::TransportState` (e.g. obtained via an out-of-band handshake)
 /// and merely needs to register it in `active_sessions` so that rotation
 /// tracking and the resumption cache stay in sync with connectivity.
 /// For the full Noise IK handshake path, use [`MeshTransport::initiate_session`].
    #[cfg(all(feature = "native", test))]
    pub fn register_established_session(&mut self, peer_did: Did, now_secs: i64) {
        let session = self
            .session_manager
            .register_session(peer_did.clone(), now_secs);
        self.active_sessions.insert(peer_did, session);
    }

 /// Advance the peer-timeout clock: removes peers not seen within
 /// `peer_timeout_secs` (Req 5.6).
    pub fn tick_timeouts(&mut self, now_us: i64) {
        self.discovery.tick_timeouts(now_us);
    }

 /// Open a Noise IK application-layer substream to a peer (Req 6.1).
 ///
 /// Returns a `DuplexNoiseStream` connected to a transport-side half that
 /// will bridge the Noise IK handshake messages onto the real libp2p
 /// connection once a substream handler is available. In the current
 /// release, the transport-side half is a `tokio::io::DuplexStream` whose
 /// reads/writes are no-ops until a future libp2p `ConnectionHandler` is
 /// wired to forward bytes. This allows `initiate_session` to proceed with
 /// the Noise IK handshake protocol logic while the actual wire I/O is
 /// deferred to the substream handler (Subphase 5.2).
    #[cfg(feature = "native")]
    pub fn open_noise_substream(&self) -> crate::transport::session::DuplexNoiseStream {
        let (client, _transport_half) = crate::transport::session::DuplexNoiseStream::pair();
 // NOTE: In production, `_transport_half` would be bridged to a real
 // libp2p substream via `libp2p::swarm::Swarm::new_handler` or a custom
 // `ConnectionHandler` that implements the Noise protocol. When that
 // handler is added, replace this no-op with the bridged half.
 //
 // For now, the handshake protocol logic runs end-to-end (message
 // framing, key derivation, 0-RTT resumption) so it can be tested
 // and verified independently of the transport's substream availability.
        let _ = _transport_half;
        client
    }

 // ── Retry queue ───────────────────────────────────────────────────────────

 /// Queue an undelivered Delta for retry delivery (Req 5.6).
    pub fn enqueue_retry(
        &mut self,
        peer_did: Did,
        delta_bytes: Vec<u8>,
        now_us: i64,
    ) -> Result<(), TirBaseError> {
        let entry = RetryEntry {
            peer_did,
            delta_bytes,
            next_retry_at: now_us + self.config.retry_interval_secs as i64 * 1_000_000,
            attempts: 1,
        };
        self.discovery.enqueue_retry(entry)
    }

 /// Drain retry entries that are due for reattempt.
    pub fn drain_due_retries(&mut self, now_us: i64) -> Vec<RetryEntry> {
        self.discovery.drain_due_retries(now_us)
    }

 // ── Saturate Mode ─────────────────────────────────────────────────────────
 //
 // Subphase 3.2: the transport exposes one facade method per lease-lifecycle
 // event (activate / renew / M-of-N terminate). Each delegates to the real
 // [`SaturateModeStateMachine`] and — only on success — reconciles the DRR
 // scheduler flag from the resulting state. The scheduler is a mirror, not
 // a second source of truth: nothing in production may flip it directly.

 /// Reconcile the DRR scheduler's Saturate_Mode flag with the state machine.
 ///
 /// This is the **only** production writer of the scheduler flag: the
 /// scheduler holds no independent opinion about whether Saturate_Mode is
 /// active — it mirrors `saturate.state()`. Every lifecycle transition
 /// funnels through [`SaturateModeStateMachine`] first and then runs this
 /// reconciler, so the boolean can never drift from the lease. In
 /// particular a successful M-of-N termination (Req 13.6) demotes the state
 /// machine AND clears the scheduler together; the bare
 /// `scheduler.set_saturate_mode(true)` bypass this replaces could set the
 /// flag with no lease, renewal, or termination machinery behind it,
 /// leaving a device in Saturate_Mode forever (audit B-3).
    fn reconcile_scheduler_saturate_mode(&mut self) {
        let active = self.saturate.state() == SaturateState::Saturate;
        self.scheduler.set_saturate_mode(active);
    }

 /// Activate Saturate_Mode from a DISASTER_ALERT Biscuit token (Req 13.1).
 ///
 /// Delegates to the transport's [`SaturateModeStateMachine`]: the token is
 /// verified offline against the configured root CA key (signature, expiry,
 /// `disaster-alert` caveat — Req 13.7) and a 60-minute lease is opened on
 /// success. On success the DRR scheduler is reconciled into Saturate Mode
 /// (all bandwidth to HIGH, Req 13.2) via
 /// [`MeshTransport::reconcile_scheduler_saturate_mode`].
 ///
 /// Any verification failure returns `SignatureVerificationFailed` and
 /// leaves both the state machine and the scheduler untouched (Req 13.7).
 ///
 /// Production caller: `CoreHandle::activate_saturate_mode`
 /// (api/mod.rs) — the shared WASM + native entry point — which the WASM
 /// export `core_activate_saturate_mode` (lib.rs) delegates to.
    pub(crate) fn activate_saturate_mode(
        &mut self,
        manager_did: Did,
        biscuit_token: &[u8],
        now_secs: i64,
    ) -> Result<(), TirBaseError> {
        self.saturate
            .activate(manager_did, biscuit_token, now_secs)?;
        self.reconcile_scheduler_saturate_mode();
        Ok(())
    }

 /// Renew a Saturate_Mode Lease with a heartbeat DISASTER_ALERT token
 /// (Req 13.4).
 ///
 /// Delegates to [`SaturateModeStateMachine::renew`]: valid only while the
 /// state machine is in SATURATE; a valid heartbeat extends the lease by
 /// 60 minutes from the renewal timestamp. On success the scheduler is
 /// reconciled from the state machine (still SATURATE — all bandwidth to
 /// HIGH). Any failure returns `SignatureVerificationFailed` and preserves
 /// both the state machine and the scheduler untouched (Req 13.7).
 ///
 /// Production caller: `CoreHandle::renew_saturate_mode` (api/mod.rs) —
 /// the shared WASM + native entry point — which the WASM export
 /// `core_renew_saturate_mode` (lib.rs) delegates to.
    pub(crate) fn renew_saturate_mode(
        &mut self,
        manager_did: Did,
        biscuit_token: &[u8],
        now_secs: i64,
    ) -> Result<(), TirBaseError> {
        self.saturate.renew(manager_did, biscuit_token, now_secs)?;
        self.reconcile_scheduler_saturate_mode();
        Ok(())
    }

 /// Terminate Saturate_Mode via an M-of-N Lease Termination (Req 13.6).
 ///
 /// Delegates to [`SaturateModeStateMachine::terminate`]: when at least
 /// `termination_threshold_m` valid **distinct** Manager DID signatures
 /// over `message` are supplied, the state machine transitions to NORMAL
 /// immediately regardless of remaining lease duration. On success the
 /// scheduler is reconciled from the state machine — this is the transition
 /// that clears the scheduler's Saturate_Mode flag (MEDIUM/LOW resumes
 /// normal service, Req 13.5).
 ///
 /// A signature set below the threshold returns `ThresholdNotMet` and
 /// leaves both the state machine and the scheduler untouched (invariant
 /// (b), Req 13.7). When not in SATURATE the call is a no-op that returns
 /// `Ok(())`.
 ///
 /// Production caller: `CoreHandle::terminate_saturate_mode`
 /// (api/mod.rs) — the shared WASM + native entry point — which the WASM
 /// export `core_terminate_saturate_mode` (lib.rs) delegates to.
    pub(crate) fn terminate_saturate_mode(
        &mut self,
        signatures: Vec<(Did, Vec<u8>)>,
        message: &[u8],
        now_secs: i64,
    ) -> Result<(), TirBaseError> {
        self.saturate.terminate(signatures, message, now_secs)?;
        self.reconcile_scheduler_saturate_mode();
        Ok(())
    }

 /// Advance the Saturate_Mode state machine's clock (Req 13.5).
 ///
 /// Delegates to [`SaturateModeStateMachine::tick`]: when the active lease
 /// has expired without renewal, the state machine transitions to NORMAL
 /// and drops the lease. The DRR scheduler is then reconciled from the
 /// resulting state — a lease-expiry demotion clears the scheduler's
 /// Saturate_Mode flag (MEDIUM/LOW resumes normal service, Req 13.5)
 /// exactly like an M-of-N termination does. The reconcile runs
 /// unconditionally: `set_saturate_mode` is idempotent and cheap, so this
 /// stays the single reconciler every lifecycle transition funnels through.
 ///
 /// Production caller: `CoreHandle::spawn_scheduler_tick_loop`
 /// (api/mod.rs) — the Phase 1.4 production tick loop — calls this every
 /// epoch with the wall clock, so lease expiry and auto-demotion happen
 /// automatically without manual (test-driven) ticking.
    pub(crate) fn tick_saturate(&mut self, now_secs: i64) {
        self.saturate.tick(now_secs);
        self.reconcile_scheduler_saturate_mode();
    }

 /// Advance the Noise session key-rotation clock: for every active session
 /// in `active_sessions`, if `rotation_due(now_secs)` is true, call
 /// `SessionManager::rotate_keys` and update the session (Req 6.4).
 ///
 /// Best-effort per session: a rotation failure for one session is logged
 /// and does not prevent rotation of the remaining sessions.
    #[cfg(feature = "native")]
    pub(crate) fn tick_key_rotation(&mut self, now_secs: i64) {
        for (peer_did, session) in self.active_sessions.iter_mut() {
            if session.rotation_due(now_secs) {
                if let Err(e) = self.session_manager.rotate_keys(session, now_secs) {
                    emit_transport(
                        Severity::Medium,
                        ReasonCode::HandshakeFailed,
                        None,
                        format!("[transport] key rotation failed for peer {peer_did}: {e}"),
                    );
                }
            }
        }
    }

 // ── Scheduler interface ───────────────────────────────────────────────────

 /// Returns `true` if the DRR scheduler has any pending Deltas (any priority queue).
    pub fn has_backlog(&self) -> bool {
        self.scheduler.has_backlog()
    }

 /// Returns the current depth of the HIGH priority queue.
    pub fn high_queue_depth(&self) -> usize {
        self.scheduler.high_queue_depth()
    }

 /// Enqueue a Delta for outbound transmission via the DRR scheduler.
 ///
 /// The Delta is placed in the queue corresponding to its `priority` field.
 /// Actual Gossipsub publish happens when the scheduler is ticked.
    pub fn enqueue_outbound(&mut self, delta: Delta) {
        let serialized_len = serde_json::to_vec(&delta)
            .map(|b| b.len() as u64)
            .unwrap_or(0);
        let queued = QueuedDelta {
            delta,
            serialized_len,
            enqueued_at: current_timestamp_micros(),
        };
        self.scheduler.enqueue(queued);
    }

 /// Drain the DRR scheduler and return the serialised wire frames a host
 /// transport must send.
 ///
 /// This is the WASM counterpart of [`Self::tick_scheduler`]: on WASM there
 /// is no libp2p Swarm or outbound channel, so the JavaScript transport owns
 /// delivery. Each returned `Vec<u8>` is a full `GossipMessage` payload (the
 /// output of `prepare_outbound(...).to_bytes()`), exactly as the native
 /// Swarm publish path frames it. Synthetic revocation envelopes
 /// (`author_did == "tirbase/revocation"`, produced by
 /// `enqueue_revocation_gossip`) already carry a pre-framed `GossipMessage`
 /// in `automerge_bytes` and are returned verbatim so the receiver can
 /// dispatch them as `InboundRevocationDelta`.
 ///
 /// Production caller on WASM: `core_drain_outbound_messages` (lib.rs).
    #[cfg(not(feature = "native"))]
    pub(crate) fn drain_outbound_frames(
        &mut self,
        link_capacity_bytes: u64,
    ) -> Result<Vec<Vec<u8>>, TirBaseError> {
        let drained = self.scheduler.tick(link_capacity_bytes);
        let mut frames = Vec::new();
        for queued in drained {
            if queued.delta.author_did == "tirbase/revocation"
                || queued.delta.author_did == "tirbase/saturate"
            {
                frames.push(queued.delta.automerge_bytes.clone());
                continue;
            }
            for msg in self.prepare_outbound(&queued.delta)? {
                frames.push(msg.to_bytes());
            }
        }
        Ok(frames)
    }

 // ── Fragmentation ─────────────────────────────────────────────────────────

 /// Serialise and optionally fragment a Delta for transmission (Req 5.7).
 ///
 /// Returns a list of `GossipMessage` payloads to send. When `config.mtu`
 /// is in `(0, 256)` the Delta is split into fragments ≤ MTU, each framed
 /// as `GossipMessage::InboundDeltaFragment`; otherwise the full serialised
 /// Delta is returned as a single `GossipMessage::InboundDelta`.
 ///
 /// Framing at the source (rather than raw bytes) ensures the receiving
 /// Swarm poll task can dispatch each payload by variant tag without
 /// heuristics — fragments are never mis-parsed as whole Delta messages
 /// (Subphase 7.4 wire framing for low-MTU transport).
    pub fn prepare_outbound(
        &self,
        delta: &Delta,
    ) -> Result<Vec<crate::transport::message::GossipMessage>, TirBaseError> {
        let bytes = serde_json::to_vec(delta).map_err(|e| TirBaseError::DeltaMalformed {
            reason: format!("serialisation error: {e}"),
        })?;

        // Any non-zero MTU enables fragmentation at that size. A deployment
        // that configures `mesh_mtu = 256` therefore fragments at 256 bytes
        // (Req 5.7); `0` keeps whole-Delta framing.
        if self.config.mtu > 0 {
            let frags = fragment_delta(delta.id, &bytes, self.config.mtu);
            let msgs = frags
                .into_iter()
                .map(|f| {
                    crate::transport::message::GossipMessage::InboundDeltaFragment(
                        crate::transport::fragment::DeltaFragment {
                            delta_id: f.delta_id,
                            fragment_index: f.fragment_index,
                            total_fragments: f.total_fragments,
                            payload: f.payload,
                        },
                    )
                })
                .collect();
            Ok(msgs)
        } else {
            Ok(vec![
                crate::transport::message::GossipMessage::InboundDelta(delta.clone()),
            ])
        }
    }

 // ── Multi-hop relay (Req 5.5) ────────────────────────────────────────────

 // ── BLE bridge ────────────────────────────────────────────────────────────

 /// Create the BLE bridge channels (idempotent).
 ///
 /// Called from `MeshTransport::start` when the deployment enables BLE, and by
 /// an emulated-link test before `bind_ble_link`.
 #[cfg(feature = "native")]
    pub fn init_ble_channels(&mut self) -> Result<(), TirBaseError> {
        if self.ble_outbound_tx.is_some() {
            return Ok(());
        }
        let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        let (in_tx, in_rx) =
            tokio::sync::mpsc::channel::<crate::transport::message::GossipMessage>(32);
        self.ble_outbound_tx = Some(out_tx);
        self.ble_outbound_rx = Some(out_rx);
        self.ble_inbound_tx = Some(in_tx);
        self.ble_inbound_rx = Some(in_rx);
        Ok(())
    }

 /// Hand the bridge channels to a bridge runner.
 #[cfg(feature = "native")]
    fn take_ble_bridge_channels(
        &mut self,
    ) -> Option<(
        tokio::sync::mpsc::Receiver<Vec<u8>>,
        tokio::sync::mpsc::Sender<crate::transport::message::GossipMessage>,
    )> {
        Some((self.ble_outbound_rx.take()?, self.ble_inbound_tx.clone()?))
    }

 /// Run the BLE bridge over `link`.
 ///
 /// Framing, chunking, reassembly and dispatch all happen inside
 /// `ble::run_ble_bridge` — the same loop the platform radio uses — so an
 /// emulated link is a substitute for the radio only, never for the bridge.
 #[cfg(feature = "native")]
    pub fn bind_ble_link<L: crate::transport::ble::BleLink + 'static>(
        &mut self,
        link: L,
    ) -> Result<(), TirBaseError> {
        let (outbound_rx, inbound_tx) = self.take_ble_bridge_channels().ok_or_else(|| {
            TirBaseError::MeshUnavailable {
                reason: "BLE bridge channels not initialised (call init_ble_channels first)"
                    .to_string(),
            }
        })?;
        tokio::spawn(crate::transport::ble::run_ble_bridge(
            link,
            outbound_rx,
            inbound_tx,
        ));
        Ok(())
    }

 /// Install the mesh inbound channel that BLE messages dispatch into.
 #[cfg(feature = "native")]
    pub fn set_ble_dispatch(
        &mut self,
        tx: tokio::sync::mpsc::Sender<crate::transport::message::GossipMessage>,
    ) {
        self.ble_dispatch_tx = Some(tx);
    }

 /// Connect the platform BLE radio and run the bridge over it.
 ///
 /// Spawned by `CoreHandle::init` when the deployment enables BLE. The adapter
 /// is a real `btleplug` peripheral; without an adapter this logs and exits,
 /// leaving the device's other transports untouched.
 #[cfg(feature = "native")]
    pub fn spawn_platform_ble_bridge(
        transport: std::sync::Arc<std::sync::Mutex<MeshTransport>>,
    ) {
        use crate::transport::ble::BleAdapter;

        tokio::spawn(async move {
            let local_did = match transport.lock() {
                Ok(t) => t.local_did.clone(),
                Err(_) => return,
            };

            let mut adapter = match BleAdapter::new(local_did.clone(), local_did).await {
                Ok(a) => a,
                Err(e) => {
                    emit_transport(
                        Severity::Medium,
                        ReasonCode::HandshakeFailed,
                        None,
                        format!("[transport] BLE adapter init failed: {e}"),
                    );
                    return;
                }
            };

            if let Err(e) = adapter.scan_and_connect(30).await {
                emit_transport(
                    Severity::Medium,
                    ReasonCode::HandshakeFailed,
                    None,
                    format!("[transport] BLE scan/connect failed: {e}"),
                );
                return;
            }
            if let Err(e) = adapter.subscribe_notifications().await {
                emit_transport(
                    Severity::Medium,
                    ReasonCode::HandshakeFailed,
                    None,
                    format!("[transport] BLE subscribe failed: {e}"),
                );
                return;
            }
            adapter.take_notifications();

            let channels = match transport.lock() {
                Ok(mut t) => t.take_ble_bridge_channels(),
                Err(_) => None,
            };
            if let Some((outbound_rx, inbound_tx)) = channels {
                crate::transport::ble::run_ble_bridge(adapter, outbound_rx, inbound_tx).await;
            }
        });
    }

 // ── Native-only: Swarm startup ────────────────────────────────────────────

 /// Build the libp2p Swarm and start listening for connections (Req 5.1).
 ///
 /// - Generates an ephemeral Ed25519 keypair for the Swarm (the TirBase
 /// identity keypair is separate; used for DID-layer crypto only).
 /// - Configures mDNS for automatic local peer discovery (Req 5.2).
 /// - Configures Gossipsub for Delta propagation.
    #[cfg(feature = "native")]
    pub async fn start(&mut self) -> Result<(), TirBaseError> {
        use libp2p::{
            gossipsub, identify, mdns, noise as libp2p_noise, ping, tcp, yamux, SwarmBuilder,
        };
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::Duration;

        let swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                libp2p_noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| TirBaseError::NoiseHandshakeFailed {
                peer_did: self.local_did.clone(),
                reason: format!("transport build error: {e}"),
            })?
            .with_behaviour(|key| {
 // Gossipsub: message-id is SHA-256 of content hash
                let message_id_fn = |msg: &gossipsub::Message| {
                    let mut s = DefaultHasher::new();
                    msg.data.hash(&mut s);
                    gossipsub::MessageId::from(s.finish().to_string())
                };
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(10))
                    .message_id_fn(message_id_fn)
                    .build()
                    .expect("valid gossipsub config");

                let gossipsub_behaviour = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )
                .expect("valid gossipsub behaviour");

                let mdns_behaviour =
                    mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())
                        .expect("valid mDNS config");

                let identify_behaviour = identify::Behaviour::new(identify::Config::new(
                    "/tirbase/1.0.0".to_string(),
                    key.public(),
                ));

                let ping_behaviour = ping::Behaviour::default();

                Ok(TirBaseBehaviour {
                    mdns: mdns_behaviour,
                    gossipsub: gossipsub_behaviour,
                    identify: identify_behaviour,
                    ping: ping_behaviour,
                })
            })
            .map_err(|e| TirBaseError::NoiseHandshakeFailed {
                peer_did: self.local_did.clone(),
                reason: format!("behaviour build error: {e:?}"),
            })?
            .build();

        self.swarm = Some(swarm);

        // ── BLE transport initialisation ─────────────────────────────────────
        //
        // Only the bridge channels are created here. The framing / chunk
        // assembly loop lives in `ble::run_ble_bridge` and is started by
        // `spawn_platform_ble_bridge` (real radio) or `bind_ble_link`
        // (emulated link in CI), so both run the identical code path.
        #[cfg(feature = "native")]
        if self.config.mesh_ble_enabled {
            self.init_ble_channels()?;
        }


 // Subscribe to the shared TirBase Gossipsub topic (Req 5.1).
        if let Some(ref mut swarm) = self.swarm {
            use libp2p::gossipsub::IdentTopic;
            let topic = IdentTopic::new(&self.gossip_topic);
            swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&topic)
                .map_err(|e| TirBaseError::NoiseHandshakeFailed {
                    peer_did: self.local_did.clone(),
                    reason: format!("gossipsub subscribe failed: {e:?}"),
                })?;

 // Start listening for incoming connections (Req 5.1).
            let listen_addr: libp2p::Multiaddr = self.config.listen_addr.parse().map_err(|e| {
                TirBaseError::NoiseHandshakeFailed {
                    peer_did: self.local_did.clone(),
                    reason: format!("invalid listen addr: {e}"),
                }
            })?;
            swarm
                .listen_on(listen_addr)
                .map_err(|e| TirBaseError::NoiseHandshakeFailed {
                    peer_did: self.local_did.clone(),
                    reason: format!("listen_on failed: {e}"),
                })?;
        }

        Ok(())
    }

 /// Take ownership of the native libp2p Swarm out of this transport and
 /// install the outbound publish channel.
 ///
 /// Used by `CoreHandle::init` to move the Swarm into a dedicated polling
 /// task so it can be polled across `.await` points without holding the
 /// `MeshTransport` mutex (Rust forbids holding a sync mutex across `.await`).
 ///
 /// The `outbound_tx` sender is retained here: [`MeshTransport::send_delta`]
 /// forwards prepared payloads over it, and the polling task — which owns
 /// the receiver end — publishes them to the Gossipsub topic. Outbound
 /// delivery therefore keeps working after `self.swarm` is emptied; when no
 /// polling task is draining the channel (transport never started, or shut
 /// down), the device is simply offline-only (Req 3.3).
    #[cfg(feature = "native")]
    pub fn take_swarm(
        &mut self,
        outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Option<libp2p::Swarm<TirBaseBehaviour>> {
        self.outbound_tx = Some(outbound_tx);
        self.swarm.take()
    }

 /// Forward a Delta to the shared Gossipsub topic (Req 5.1).
 ///
 /// The `peer_did` argument is accepted for API compatibility but the
 /// message is published to the shared `tirbase/v1` topic so all subscribed
 /// peers receive it. Fragmentation and Noise encryption are handled by the
 /// libp2p transport stack.
 ///
 /// Prepared payloads are sent over the outbound publish channel to the
 /// Swarm polling task, which owns the `&mut Swarm` and performs the actual
 /// `gossipsub.publish`. This is the re-architecture that keeps outbound
 /// delivery working after `take_swarm` empties `self.swarm`: the channel
 /// sender replaces the Swarm handle as the publish path.
 ///
 /// ## Wire framing (Subphase 1.5)
 ///
 /// The documented mesh protocol (`transport/message.rs`) frames **every**
 /// message as a tagged `GossipMessage` variant so the receiving side can
 /// dispatch without heuristics. Whole-Delta payloads are therefore
 /// wrapped in `GossipMessage::InboundDelta` here, at the send side. (A
 /// real peer round-trip test — Phase 0.3(b) — exposed that the write path
 /// previously published the bare serialised `Delta`, which the receiving
 /// poll task could never parse: "unrecognised gossipsub message".)
 ///
 /// Fragmented payloads (`config.mtu` in `(0, 256)`) are framed as
 /// `GossipMessage::InboundDeltaFragment` (Subphase 7.4 — low-MTU
 /// fragmented transport), so the receiving Swarm poll task can dispatch
 /// each fragment to the `ReassemblyBuffer` by variant tag, exactly as it
 /// dispatches whole-Delta payloads as `InboundDelta`.
 ///
 /// Returns [`TirBaseError::MeshUnavailable`] when no outbound channel is
 /// installed (transport never started) or the channel cannot accept the
 /// payload (polling task backlogged or shut down). Callers treat this as
 /// best-effort: the local store and the durability queue remain
 /// authoritative while the device is offline (Req 3.3).
    #[cfg(feature = "native")]
    pub fn send_delta(&mut self, peer_did: &Did, delta: &Delta) -> Result<(), TirBaseError> {
 // ── BLE bridge path ─────────────────────────────────────────────────────
 //
 // If the destination peer is reachable via a BLE routing bridge, bypass
 // the libp2p Gossipsub outbound channel and send the framed Delta over
 // the dedicated BLE outbound channel instead. The BLE I/O task drains
 // this channel and writes the serialised chunks to the peer's GATT
 // characteristic.
        let is_ble_peer = self
            .discovery
            .peer_transport(peer_did)
            .map(|t| matches!(t, PeerTransport::BleBridge { .. }))
            .unwrap_or(false);

        if is_ble_peer {
            let messages = self.prepare_outbound(delta)?;
            let ble_tx =
                self.ble_outbound_tx
                    .as_ref()
                    .ok_or_else(|| TirBaseError::MeshUnavailable {
                        reason: "BLE transport not initialised (outbound channel missing)"
                            .to_string(),
                    })?;
            for msg in messages {
                let wire_payload = msg.to_bytes();
                ble_tx
                    .try_send(wire_payload)
                    .map_err(|e| TirBaseError::MeshUnavailable {
                        reason: format!("BLE outbound channel unavailable: {e}"),
                    })?;
            }
            return Ok(());
        }

 // Req 5.5: if the destination is not a direct neighbor, route through
 // a relay peer.
        if !self.discovery.is_direct_neighbor(peer_did) {
            if let Some(relay_did) = self.discovery.find_relay_peer(peer_did) {
                emit_transport(
                    Severity::Low,
                    ReasonCode::RelaySelected,
                    None,
                    format!(
                        "[transport] relay: {peer_did} is not a direct neighbor; \
                     routing delta through relay peer {relay_did}"
                    ),
                );
                let relay_msg = crate::transport::message::GossipMessage::RelayDelta {
                    target_did: peer_did.clone(),
                    delta: delta.clone(),
                    hop_count: 0,
                    visited: vec![self.local_did.clone()],
                };
                let wire_payload = relay_msg.to_bytes();
                let tx =
                    self.outbound_tx
                        .as_ref()
                        .ok_or_else(|| TirBaseError::MeshUnavailable {
                            reason: "transport not started (no outbound channel installed)"
                                .to_string(),
                        })?;
                tx.try_send(wire_payload)
                    .map_err(|e| TirBaseError::MeshUnavailable {
                        reason: format!("outbound publish channel unavailable: {e}"),
                    })?;
                return Ok(());
            }
        }

 // Compute framed messages before borrowing the channel.
        let messages = self.prepare_outbound(delta)?;

        let tx = self
            .outbound_tx
            .as_ref()
            .ok_or_else(|| TirBaseError::MeshUnavailable {
                reason: "transport not started (no outbound channel installed)".to_string(),
            })?;

        for msg in messages {
 // Each message is already a properly-framed GossipMessage variant
 // (InboundDelta or InboundDeltaFragment) — see `prepare_outbound`.
 // No additional framing/sniffing is needed: the receiver dispatches
 // by variant tag.
            let wire_payload = msg.to_bytes();
            tx.try_send(wire_payload)
                .map_err(|e| TirBaseError::MeshUnavailable {
                    reason: format!("outbound publish channel unavailable: {e}"),
                })?;
        }
        Ok(())
    }

 /// Process an inbound wire message, performing fragment reassembly (Req 5.8).
 ///
 /// When the active transport has a low MTU, a Delta arrives as multiple
 /// `GossipMessage::InboundDeltaFragment` messages. This method:
 ///
 /// - **Fragments**: feeds each `DeltaFragment` into the per-`MeshTransport`
 /// `ReassemblyBuffer`. If the fragment completes a Delta, the reassembled
 /// bytes are parsed into a `Delta` and returned as `Some(GossipMessage::InboundDelta)`.
 /// If reassembly fails (missing/truncated/malformed fragments, or the
 /// reassembled bytes don't parse as a valid `Delta`), the failure is
 /// logged with the sender DID and fragment count and `None` is returned —
 /// the partial Delta is discarded without corrupting any engine state
 /// (Req 5.8 / Subphase 7.4 acceptance: clean reassembly failure handling).
 ///
 /// - **Non-fragments**: passes `InboundDelta`, `InboundDurabilityReceipt`,
 /// `InboundRevocationDelta`, `InboundMigrationDelta`, and
 /// `InboundMigrationRevocationDelta` through unchanged.
 ///
 /// Production caller: the Swarm polling task spawned in
 /// [`crate::api::CoreHandle::init`] calls this for every Gossipsub message
 /// before forwarding the result to `inbound_tx`. On the WASM target the
 /// JS transport layer calls `core_receive_peer_message`, which deserialises
 /// into a `GossipMessage` and delegates to `receive_inbound_wasm` (which
 /// calls this same method for parity).
    pub(crate) fn process_wire_message(
        &mut self,
        msg: crate::transport::message::GossipMessage,
    ) -> Option<crate::transport::message::GossipMessage> {
        use crate::transport::message::GossipMessage;

        match msg {
            GossipMessage::InboundDeltaFragment(frag) => {
                let sender_did = frag
                    .payload
                    .first()
                    .map(|_| "unknown".to_string())
                    .unwrap_or_else(|| "unknown".to_string());

 // Feed the fragment to the reassembly buffer. The sender_did
 // here is a best-effort label for the failure log; the real
 // author DID is only known after the Delta is fully reassembled
 // and its signature is verified by CrdtEngine::apply.
                let buffer_did = format!("fragment-delta-{}", hex::encode(frag.delta_id));
                match self.reassembly_buffer.add_fragment(frag, &buffer_did) {
                    Ok(Some(reassembled_bytes)) => {
 // Full Delta reassembled — parse it.
                        match serde_json::from_slice::<Delta>(&reassembled_bytes) {
                            Ok(delta) => Some(GossipMessage::InboundDelta(delta)),
                            Err(e) => {
 // Reassembled bytes are not a valid Delta —
 // malformed/truncated payload. Discard
 // cleanly: log with sender + fragment context
 // and return None so the message is dropped
 // from the inbound pipeline without touching
 // the CRDT engine or DAG state.
                                emit_transport(
                                    Severity::Medium,
                                    ReasonCode::FragmentReassemblyFailed,
                                    None,
                                    format!(
                                    "[transport] reassembled Delta failed to parse as Delta: {e} — \
                                     discarding (delta_id was from fragment reassembly)"
                                ),
                                );
                                None
                            }
                        }
                    }
                    Ok(None) => {
 // Partial — awaiting more fragments. Suppress silently.
                        None
                    }
                    Err(e) => {
 // Reassembly failure: missing fragments, inconsistent
 // totals, oversized allocation, or slot eviction
 // discarded a partial Delta mid-flight (Req 5.8).
                        emit_transport(
                            Severity::Medium,
                            ReasonCode::FragmentReassemblyFailed,
                            None,
                            format!(
                                "[transport] fragment reassembly failed: {e} — \
                             partial Delta discarded without corrupting state"
                            ),
                        );
                        None
                    }
                }
            }
            other => Some(other),
        }
    }

 /// (Req 14.6 — the receipt-issuance half of Tier-1 durability, Subphase
 /// 4.5).
 ///
 /// Frames the receipt as `GossipMessage::InboundDurabilityReceipt` so the
 /// receiving Swarm poll task can dispatch it to the Durability Subsystem
 /// without heuristics — the same wire framing `send_delta` applies to
 /// whole-Delta payloads (Subphase 1.5). The framed bytes go over the
 /// outbound publish channel to the Swarm polling task, which performs the
 /// actual `gossipsub.publish`; a receipt is small and latency-sensitive
 /// (it completes the writer's quorum), so it is sent directly rather than
 /// queued through the DRR scheduler.
 ///
 /// Production caller: [`crate::api::CoreHandle::issue_durability_receipt`]
 /// (api/mod.rs), which runs after a peer Delta merges in
 /// `CoreHandle::receive_inbound` (Subphase 4.5).
    #[cfg(feature = "native")]
    pub fn send_receipt(
        &mut self,
        receipt: &crate::durability::receipt::DurabilityReceipt,
    ) -> Result<(), TirBaseError> {
        let wire_payload =
            crate::transport::message::GossipMessage::InboundDurabilityReceipt(receipt.clone())
                .to_bytes();

        let tx = self
            .outbound_tx
            .as_ref()
            .ok_or_else(|| TirBaseError::MeshUnavailable {
                reason: "transport not started (no outbound channel installed)".to_string(),
            })?;

        tx.try_send(wire_payload)
            .map_err(|e| TirBaseError::MeshUnavailable {
                reason: format!("outbound publish channel unavailable: {e}"),
            })?;
        Ok(())
    }

 /// Publish a pre-framed `GossipMessage` verbatim over the mesh.
 ///
 /// Control-plane messages that are not CRDT Deltas (Migration_Delta and
 /// Migration_Revocation_Delta) carry their own variant tag, and
 /// `process_wire_message` forwards every non-fragment variant unchanged —
 /// so they must not be wrapped in a synthetic Delta envelope. Like
 /// [`MeshTransport::send_receipt`], this bypasses the DRR scheduler: these
 /// messages are small and latency-sensitive (a corrected migration is what
 /// unblocks Side-Car replay, Req 19.3).
 ///
 /// Production callers: `CoreHandle::publish_migration_delta` and
 /// `CoreHandle::publish_migration_revocation_delta`.
    #[cfg(feature = "native")]
    pub fn send_message(
        &mut self,
        msg: &crate::transport::message::GossipMessage,
    ) -> Result<(), TirBaseError> {
        let wire_payload = msg.to_bytes();
        let tx = self
            .outbound_tx
            .as_ref()
            .ok_or_else(|| TirBaseError::MeshUnavailable {
                reason: "transport not started (no outbound channel installed)".to_string(),
            })?;
        tx.try_send(wire_payload)
            .map_err(|e| TirBaseError::MeshUnavailable {
                reason: format!("outbound publish channel unavailable: {e}"),
            })?;
        Ok(())
    }
 ///
 /// Called by the production scheduler tick loop spawned from
 /// `CoreHandle::init`; the Swarm polling task (Subphase 1.1) receives the
 /// forwarded payloads on the outbound channel and publishes them to the
 /// shared Gossipsub topic. Without this, Deltas enqueued via
 /// [`MeshTransport::enqueue_outbound`] (HIGH-priority revocation
 /// rebroadcast, mDNS re-announcement) would accumulate in the scheduler
 /// queues forever.
 ///
 /// Returns the number of payloads forwarded. Best-effort by design: if
 /// the outbound channel is full or closed, the unsent Delta is re-enqueued
 /// so it is not silently dropped — the next epoch reschedules it (the
 /// durability queue remains authoritative while the mesh is unavailable,
 /// Req 3.3).
    #[cfg(feature = "native")]
    pub(crate) fn tick_scheduler(
        &mut self,
        link_capacity_bytes: u64,
    ) -> Result<usize, TirBaseError> {
        let drained = self.scheduler.tick(link_capacity_bytes);
        if drained.is_empty() {
            return Ok(0);
        }

        let tx = self
            .outbound_tx
            .as_ref()
            .ok_or_else(|| TirBaseError::MeshUnavailable {
                reason: "transport not started (no outbound channel installed)".to_string(),
            })?;

        let mut forwarded = 0usize;
        for queued in drained {
            let messages = self.prepare_outbound(&queued.delta)?;
            for msg in messages {
                let wire_payload = msg.to_bytes();
                match tx.try_send(wire_payload) {
                    Ok(()) => forwarded += 1,
                    Err(e) => {
 // Channel full/closed — put the Delta back so it is
 // rescheduled on the next epoch rather than lost.
                        self.scheduler.enqueue(queued);
                        return Err(TirBaseError::MeshUnavailable {
                            reason: format!("outbound publish channel unavailable: {e}"),
                        });
                    }
                }
            }
        }
        Ok(forwarded)
    }

 /// Receive inbound Deltas from any transport (BLE, WASM inbound, etc.)
 /// and dispatch them through `process_wire_message`.
 ///
 /// For BLE: the BLE I/O task pushes reassembled `GossipMessage` values
 /// onto `ble_inbound_rx`; this method drains them and runs the same
 /// fragment-reassembly → dispatch pipeline as the native Gossipsub path.
    #[cfg(feature = "native")]
    pub(crate) fn poll_ble_inbound(&mut self) {
        use crate::transport::message::GossipMessage;

        let Some(mut rx) = self.ble_inbound_rx.take() else {
            return;
        };

        while let Ok(msg) = rx.try_recv() {
            let processed = self.process_wire_message(msg);
            if let Some(dispatch_msg) = processed {
                #[cfg(test)]
                {
                    self.last_ble_inbound = Some(dispatch_msg.clone());
                }
                // Production dispatch: a reassembled BLE message enters the
                // same mesh inbound channel as a Gossipsub message, so it is
                // merged by `receive_inbound` with no BLE-specific handling.
                if let Some(tx) = self.ble_dispatch_tx.as_ref() {
                    let _ = tx.try_send(dispatch_msg);
                }
            }
        }

        self.ble_inbound_rx = Some(rx);
    }

 /// Receive a raw inbound Delta payload from the BLE transport, deserialise
 /// it into a `GossipMessage`, and run it through the normal inbound
 /// fragment-reassembly → dispatch pipeline.
    #[cfg(feature = "native")]
    pub(crate) fn receive_delta(&mut self, bytes: &[u8]) -> Result<(), TirBaseError> {
        use crate::transport::message::GossipMessage;

        let msg =
            GossipMessage::from_bytes(bytes).ok_or_else(|| TirBaseError::MeshUnavailable {
                reason: "receive_delta: bytes could not be deserialised as GossipMessage"
                    .to_string(),
            })?;

        let processed = self.process_wire_message(msg);
        if let Some(dispatch_msg) = processed {
            #[cfg(test)]
            {
                self.last_ble_inbound = Some(dispatch_msg.clone());
            }
        }
        Ok(())
    }

 /// Record a payload at the outbound publish point (test-only).
 ///
 /// Called by the Swarm polling task just before `gossipsub.publish` so
 /// integration tests can observe that outbound Deltas reached the mesh
 /// layer without requiring a live peer.
    #[cfg(all(feature = "native", test))]
    pub(crate) fn record_outbound_payload(&mut self, payload: Vec<u8>) {
        self.outbound_published.push(payload);
    }

 /// Record a relay forward at the publish point (test-only).
    #[cfg(all(feature = "native", test))]
    pub(crate) fn record_relay_forward(&mut self, target: Did, hop_count: u8, visited: Vec<Did>) {
        self.relay_forwarded.push((target, hop_count, visited));
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::transport::discovery::PeerTransport;

    fn make_transport() -> MeshTransport {
        let mut dummy_key = [0u8; 32];
        dummy_key.copy_from_slice(b"tirbase-dummy-key-00000000000000");
        MeshTransport::new(
            "did:key:local".to_string(),
            dummy_key,
            TransportConfig {
                peer_timeout_secs: 30,
                retry_interval_secs: 10,
                max_retry_queue: 5,
                max_hop_count: 3,
                mtu: 0,
                key_rotation_interval_secs: 3_600,
                listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
                saturate_termination_threshold_m: 1,
                root_ca_public_key: vec![],
                saturate_lease_duration_secs: SATURATE_LEASE_DURATION_SECS,
                mesh_ble_enabled: false,
            },
        )
    }

 /// Transport with a configured Saturate_Mode termination threshold and root
 /// CA key — the production construction path (`CoreHandle::init` feeds the
 /// same two values from the deployment config).
    fn make_saturate_transport(
        termination_threshold_m: usize,
        root_ca_public_key: Vec<u8>,
    ) -> MeshTransport {
        let mut dummy_key = [0u8; 32];
        dummy_key.copy_from_slice(b"tirbase-dummy-key-00000000000000");
        MeshTransport::new(
            "did:key:local".to_string(),
            dummy_key,
            TransportConfig {
                peer_timeout_secs: 30,
                retry_interval_secs: 10,
                max_retry_queue: 5,
                max_hop_count: 3,
                mtu: 0,
                key_rotation_interval_secs: 3_600,
                listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
                saturate_termination_threshold_m: termination_threshold_m,
                root_ca_public_key,
                saturate_lease_duration_secs: SATURATE_LEASE_DURATION_SECS,
                mesh_ble_enabled: false,
            },
        )
    }

    fn mdns_peer(did: &str, hop_count: u8) -> DiscoveredPeer {
        DiscoveredPeer {
            did: did.to_string(),
            transport: PeerTransport::Mdns {
                multiaddr: "/ip4/127.0.0.1/tcp/9000".to_string(),
            },
            hop_count,
        }
    }

 // ── Peer lifecycle ────────────────────────────────────────────────────────

    #[test]
    fn newly_discovered_peer_appears_in_active_list() {
        let mut t = make_transport();
        t.on_peer_discovered(mdns_peer("did:key:A", 0), 1_000)
            .unwrap();
        assert!(t.active_peers().contains(&"did:key:A".to_string()));
    }

    #[test]
    fn peer_removed_immediately_is_no_longer_active() {
        let mut t = make_transport();
        t.on_peer_discovered(mdns_peer("did:key:B", 0), 1_000)
            .unwrap();
        t.remove_peer(&"did:key:B".to_string());
        assert!(!t.active_peers().contains(&"did:key:B".to_string()));
    }

    #[test]
    fn peer_beyond_max_hop_count_not_added() {
        let mut t = make_transport(); // max_hop_count = 3
        t.on_peer_discovered(mdns_peer("did:key:far", 4), 1_000)
            .unwrap();
        assert!(!t.active_peers().contains(&"did:key:far".to_string()));
    }

    #[test]
    fn peer_removed_by_timeout() {
        let mut t = make_transport(); // peer_timeout_secs = 30
        t.on_peer_discovered(mdns_peer("did:key:timeout", 0), 0)
            .unwrap();
        t.tick_timeouts(31 * 1_000_000); // 31s later
        assert!(!t.active_peers().contains(&"did:key:timeout".to_string()));
    }

 // ── Retry queue ───────────────────────────────────────────────────────────

    #[test]
    fn retry_queue_bounded() {
        let mut t = make_transport(); // max_retry_queue = 5
        for i in 0..10 {
            t.enqueue_retry(format!("did:key:p{i}"), vec![i as u8], 0)
                .unwrap();
        }
        assert_eq!(t.discovery.retry_queue_len(), 5);
    }

    #[test]
    fn due_retries_are_drained() {
        let mut t = make_transport(); // retry_interval_secs = 10
        let now_us = 0i64;
        t.enqueue_retry("did:key:retry".to_string(), vec![0xAA], now_us)
            .unwrap();

 // Not yet due
        assert_eq!(t.drain_due_retries(5_000_000).len(), 0);
 // Due after retry_interval_secs (10s = 10_000_000 µs)
        assert_eq!(t.drain_due_retries(10_000_001).len(), 1);
    }

 // ── Retry queue tick (Req 5.6) ─────────────────────────────────────────────

    #[test]
    fn retry_tick_drains_due_entries_and_advances_timeouts() {
        let mut t = make_transport(); // retry_interval_secs = 10, peer_timeout_secs = 30
        let now_us = 0i64;

 // Add a peer and a retry entry
        t.on_peer_discovered(mdns_peer("did:key:peer", 0), now_us)
            .unwrap();
        t.enqueue_retry("did:key:peer".to_string(), vec![0xBB], now_us)
            .unwrap();

 // Before tick: peer is active, retry not yet due
        assert!(t.active_peers().contains(&"did:key:peer".to_string()));
        assert_eq!(t.drain_due_retries(5_000_000).len(), 0);

 // Advance past retry interval but not past peer timeout
        let tick_us = 11 * 1_000_000;
        t.tick_timeouts(tick_us);
        let due = t.drain_due_retries(tick_us);

 // Retry entry is now drained
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].peer_did, "did:key:peer");
 // Peer is still active (timeout is 30s)
        assert!(t.active_peers().contains(&"did:key:peer".to_string()));
    }

 // ── Fragmentation ─────────────────────────────────────────────────────────

    #[test]
    fn prepare_outbound_no_fragmentation_when_mtu_zero() {
        let t = make_transport(); // mtu = 0 → no fragmentation
        let delta = crate::crdt::delta::Delta {
            id: [0u8; 32],
            author_did: "did:key:test".to_string(),
            signature: crate::crdt::delta::Ed25519Signature::default(),
            schema_hash: [0u8; 32],
            automerge_bytes: vec![0xBBu8; 200],
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport: 1,
            created_at: 1_000_000,
        };
        let messages = t.prepare_outbound(&delta).unwrap();
        assert_eq!(messages.len(), 1);
        assert!(
            matches!(
                messages[0],
                crate::transport::message::GossipMessage::InboundDelta(_)
            ),
            "unfragmented payload must be InboundDelta"
        );
    }

    #[test]
    fn prepare_outbound_fragments_when_mtu_small() {
        let mut t = make_transport();
        t.config.mtu = 50; // < 256 → fragment
        let delta = crate::crdt::delta::Delta {
            id: [0u8; 32],
            author_did: "did:key:test".to_string(),
            signature: crate::crdt::delta::Ed25519Signature::default(),
            schema_hash: [0u8; 32],
            automerge_bytes: vec![0xCCu8; 300],
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport: 1,
            created_at: 1_000_000,
        };
        let messages = t.prepare_outbound(&delta).unwrap();
 // Serialised Delta > 50 bytes → multiple fragments
        assert!(
            messages.len() > 1,
            "fragmented Delta must produce >1 message"
        );
        for msg in &messages {
            assert!(
                matches!(
                    msg,
                    crate::transport::message::GossipMessage::InboundDeltaFragment(_)
                ),
                "each fragmented payload must be InboundDeltaFragment"
            );
        }
    }

 // ── Outbound publish channel (Subphase 1.1) ─────────────────────────────
 //
 // `send_delta` must not require a live `self.swarm` (it is emptied by
 // `take_swarm` at init): prepared payloads are forwarded over the outbound
 // channel to the Swarm polling task, which performs the actual publish.

    #[cfg(feature = "native")]
    fn sample_delta() -> crate::crdt::delta::Delta {
        crate::crdt::delta::Delta {
            id: [0x42u8; 32],
            author_did: "did:key:test".to_string(),
            signature: crate::crdt::delta::Ed25519Signature::default(),
            schema_hash: [0u8; 32],
            automerge_bytes: vec![0xBBu8; 64],
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport: 1,
            created_at: 1_000_000,
        }
    }

    #[cfg(feature = "native")]
    #[tokio::test]
    async fn send_delta_forwards_prepared_payloads_to_outbound_channel() {
        use tokio::sync::mpsc;

        let mut t = make_transport(); // mtu = 0 → single unfragmented payload
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(16);
 // No live Swarm in this unit test — take_swarm just installs the channel.
        assert!(
            t.take_swarm(tx).is_none(),
            "no Swarm was started in this test"
        );

        let delta = sample_delta();
        t.send_delta(&"did:key:peer".to_string(), &delta)
            .expect("send_delta must succeed once an outbound channel is installed");

        let payload = rx
            .recv()
            .await
            .expect("prepared payload must be forwarded to the outbound channel");

 // The wire protocol frames whole-Delta payloads as
 // `GossipMessage::InboundDelta` (Subphase 1.5) so the receiving poll
 // task can dispatch without heuristics; the framed message must carry
 // the exact prepared Delta.
        let wire: crate::transport::message::GossipMessage =
            serde_json::from_slice(&payload).expect("payload must be a GossipMessage");
        let carried = match wire {
            crate::transport::message::GossipMessage::InboundDelta(d) => d,
            other => panic!("expected InboundDelta framing, got: {other:?}"),
        };
        assert_eq!(carried.id, delta.id, "framed message must carry the Delta");
        assert_eq!(
            carried.automerge_bytes, delta.automerge_bytes,
            "framed message must carry the prepared payload bytes"
        );
    }

    #[cfg(feature = "native")]
    #[test]
    fn send_delta_without_outbound_channel_returns_mesh_unavailable() {
        let mut t = make_transport();
        let delta = sample_delta();
        let err = t
            .send_delta(&"did:key:peer".to_string(), &delta)
            .expect_err("send_delta must fail when no outbound channel is installed");
        assert!(
            matches!(err, TirBaseError::MeshUnavailable { .. }),
            "expected MeshUnavailable, got: {err}"
        );
    }

 // ── Saturate Mode wiring (Subphase 3.1–3.2) ───────────────────────────
 //
 // `SaturateModeStateMachine` is instantiated inside `MeshTransport` in
 // production code (`MeshTransport::new`). These integration tests drive
 // the production entry points (`MeshTransport::activate_saturate_mode` /
 // `renew_saturate_mode` / `terminate_saturate_mode`, reached from
 // `CoreHandle` on both the WASM and native builds) with real tokens and
 // signatures, and assert the state machine AND the DRR scheduler stay in
 // lock-step — the scheduler flag is reconciled from the state machine,
 // never set by a bare boolean.

    fn now_secs() -> i64 {
        crate::traits::wall_hint_secs().unwrap_or(0)
    }

 /// Sign `message` with a fresh Ed25519 key derived from `seed` and return
 /// `(did:key, signature_bytes)` — a stand-in for one Manager DID's
 /// contribution to an M-of-N Lease Termination Delta (Req 13.6).
    #[cfg(not(target_arch = "wasm32"))]
    fn manager_signature(message: &[u8], seed: u8) -> (Did, Vec<u8>) {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let did = crate::crdt::derive_did_from_public_key(&sk.verifying_key().to_bytes());
        let sig = sk.sign(message).to_bytes().to_vec();
        (did, sig)
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn activate_saturate_mode_drives_state_machine_and_scheduler() {
        use crate::transport::saturate::{
            make_disaster_alert_token_for_test, SaturateState, SATURATE_LEASE_DURATION_SECS,
        };

 // Real DISASTER_ALERT token signed by a fresh CA keypair; the transport
 // is constructed with that CA public key, exactly as `CoreHandle::init`
 // does from `DeploymentConfig::root_ca_keys`.
        let (token, ca_pub) = make_disaster_alert_token_for_test(3600);
        let mut t = make_saturate_transport(2, ca_pub);
        let now = now_secs();

        t.activate_saturate_mode("did:key:z6MkManager".to_string(), &token, now)
            .expect("a valid disaster-alert token must activate Saturate_Mode");

 // The transport's production state machine is now in SATURATE with a
 // 60-minute lease opened by the activating manager.
        assert_eq!(t.saturate.state(), SaturateState::Saturate);
        let lease = t.saturate.lease().expect("activation must open a lease");
        assert_eq!(lease.expires_at, now + SATURATE_LEASE_DURATION_SECS);
        assert_eq!(lease.activating_manager_did, "did:key:z6MkManager");

 // …and the DRR scheduler is in Saturate Mode (all bandwidth to HIGH).
        assert!(
            t.scheduler.is_saturate_mode(),
            "scheduler must follow the state machine into Saturate_Mode"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn renew_saturate_mode_drives_state_machine_and_keeps_scheduler_in_saturate() {
        use crate::transport::saturate::{SaturateState, SATURATE_LEASE_DURATION_SECS};

 // One CA keypair; the transport is configured with its public key, and
 // BOTH the activation and the heartbeat tokens are signed by it — the
 // production construction `CoreHandle::init` uses.
        use biscuit_auth::{builder::Algorithm, KeyPair};
        let kp = KeyPair::new();
        let ca_private = kp.private().to_bytes().to_vec();
        let ca_pub = kp.public().to_bytes().to_vec();
        let make_token = |ttl: u64| {
            crate::auth::biscuit::create_token_with_caveat(
                "did:key:z6MkManager",
                "manager",
                ttl,
                "disaster-alert",
                &ca_private,
            )
            .expect("token creation must succeed")
        };

        let mut t = make_saturate_transport(2, ca_pub);
        let now = now_secs();

        t.activate_saturate_mode("did:key:z6MkManager".to_string(), &make_token(3600), now)
            .expect("activation must succeed");
        let expiry_before = t
            .saturate
            .lease()
            .expect("activation must open a lease")
            .expires_at;

 // Heartbeat renewal 5 minutes later (Req 13.4): the state machine must
 // extend the lease by 60 minutes from the renewal timestamp and the
 // scheduler must remain in Saturate Mode.
        let renew_at = now + 5 * 60;
        t.renew_saturate_mode(
            "did:key:z6MkManager".to_string(),
            &make_token(3600),
            renew_at,
        )
        .expect("a valid heartbeat token must renew the lease");

        assert_eq!(t.saturate.state(), SaturateState::Saturate);
        let lease = t.saturate.lease().expect("renewal must keep the lease");
        assert_eq!(
            lease.expires_at,
            renew_at + SATURATE_LEASE_DURATION_SECS,
            "renewal must extend by 60 minutes from the renewal timestamp"
        );
        assert!(
            lease.expires_at > expiry_before,
            "renewal must push the expiry later"
        );
        assert!(
            t.scheduler.is_saturate_mode(),
            "scheduler must stay in Saturate Mode across a valid renewal"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn renew_saturate_mode_with_invalid_token_preserves_mode_and_scheduler() {
        use crate::transport::saturate::{make_disaster_alert_token_for_test, SaturateState};

        let (token, ca_pub) = make_disaster_alert_token_for_test(3600);
        let mut t = make_saturate_transport(2, ca_pub);
        let now = now_secs();
        t.activate_saturate_mode("did:key:z6MkManager".to_string(), &token, now)
            .expect("activation must succeed");

 // An invalid heartbeat must be rejected with the mode — and therefore
 // the scheduler mirror — untouched (Req 13.7).
        let err = t
            .renew_saturate_mode(
                "did:key:z6MkManager".to_string(),
                b"not-a-biscuit",
                now + 60,
            )
            .expect_err("an invalid heartbeat token must be rejected");
        assert!(
            matches!(err, TirBaseError::SignatureVerificationFailed { .. }),
            "expected SignatureVerificationFailed, got: {err}"
        );
        assert_eq!(t.saturate.state(), SaturateState::Saturate);
        assert!(t.scheduler.is_saturate_mode());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn terminate_saturate_mode_at_threshold_clears_state_machine_and_scheduler() {
        use crate::transport::saturate::{make_disaster_alert_token_for_test, SaturateState};

        let (token, ca_pub) = make_disaster_alert_token_for_test(3600);
        let mut t = make_saturate_transport(2, ca_pub);
        let now = now_secs();
        t.activate_saturate_mode("did:key:z6MkManager".to_string(), &token, now)
            .expect("activation must succeed");

 // M-of-N termination (Req 13.6): two distinct valid Manager signatures
 // over the same termination message meet the configured threshold of 2.
        let message = b"saturate-terminate:v1";
        let (did1, sig1) = manager_signature(message, 0x11);
        let (did2, sig2) = manager_signature(message, 0x22);
        assert_ne!(did1, did2, "the two Managers must be distinct DIDs");

        t.terminate_saturate_mode(vec![(did1, sig1), (did2, sig2)], message, now + 60)
            .expect("M-of-N termination must succeed");

 // The state machine demotes to NORMAL and drops the lease…
        assert_eq!(t.saturate.state(), SaturateState::Normal);
        assert!(t.saturate.lease().is_none(), "lease must be cleared");

 // …and the scheduler mirror follows: the bare `set_saturate_mode(true)`
 // boolean bypass this replaces would have left the scheduler in
 // Saturate Mode forever after a termination.
        assert!(
            !t.scheduler.is_saturate_mode(),
            "scheduler must leave Saturate Mode when M-of-N termination demotes the state machine"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn terminate_saturate_mode_below_threshold_preserves_mode_and_scheduler() {
        use crate::transport::saturate::{make_disaster_alert_token_for_test, SaturateState};

        let (token, ca_pub) = make_disaster_alert_token_for_test(3600);
        let mut t = make_saturate_transport(2, ca_pub);
        let now = now_secs();
        t.activate_saturate_mode("did:key:z6MkManager".to_string(), &token, now)
            .expect("activation must succeed");

 // Only 1 of the 2 required Manager signatures — the termination must
 // fail with ThresholdNotMet and leave mode + scheduler untouched
 // (invariant (b), Req 13.6).
        let message = b"saturate-terminate:v1";
        let (did1, sig1) = manager_signature(message, 0x33);
        let err = t
            .terminate_saturate_mode(vec![(did1, sig1)], message, now + 60)
            .expect_err("below-threshold termination must fail");
        assert!(
            matches!(err, TirBaseError::ThresholdNotMet { got: 1, need: 2 }),
            "expected ThresholdNotMet(1, 2), got: {err}"
        );
        assert_eq!(t.saturate.state(), SaturateState::Saturate);
        assert!(t.scheduler.is_saturate_mode());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn activate_saturate_mode_with_invalid_token_preserves_normal_state() {
        use crate::transport::saturate::SaturateState;

 // Unconfigured CA key (empty would be "unconfigured"; a zeroed key is
 // simply wrong) — no token can verify against it.
        let mut t = make_saturate_transport(2, vec![0u8; 32]);
        let err = t
            .activate_saturate_mode(
                "did:key:z6MkManager".to_string(),
                b"not-a-biscuit",
                now_secs(),
            )
            .expect_err("an invalid token must be rejected");
        assert!(
            matches!(err, TirBaseError::SignatureVerificationFailed { .. }),
            "expected SignatureVerificationFailed, got: {err}"
        );

 // Req 13.7: mode is preserved — neither the state machine nor the
 // scheduler may move on failure.
        assert_eq!(t.saturate.state(), SaturateState::Normal);
        assert!(!t.scheduler.is_saturate_mode());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn tick_saturate_demotes_expired_lease_and_clears_scheduler() {
        use crate::transport::saturate::{
            make_disaster_alert_token_for_test, SaturateState, SATURATE_LEASE_DURATION_SECS,
        };

        let (token, ca_pub) = make_disaster_alert_token_for_test(3600);
        let mut t = make_saturate_transport(2, ca_pub);
        let now = now_secs();
        t.activate_saturate_mode("did:key:z6MkManager".to_string(), &token, now)
            .expect("activation must succeed");
        assert_eq!(t.saturate.state(), SaturateState::Saturate);
        assert!(t.scheduler.is_saturate_mode());

 // A tick inside the lease window (even within the renewal window) must
 // not demote — only expiry does (Req 13.5).
        t.tick_saturate(now + SATURATE_LEASE_DURATION_SECS - 60);
        assert_eq!(t.saturate.state(), SaturateState::Saturate);
        assert!(t.scheduler.is_saturate_mode());

 // A tick past the lease deadline demotes the state machine AND clears
 // the scheduler mirror — expiry must flow through the same reconciler
 // as M-of-N termination; the bare `set_saturate_mode(true)` boolean
 // bypass could never demote the scheduler again.
        t.tick_saturate(now + SATURATE_LEASE_DURATION_SECS + 1);
        assert_eq!(t.saturate.state(), SaturateState::Normal);
        assert!(
            t.saturate.lease().is_none(),
            "lease must be cleared on lease-expiry demotion"
        );
        assert!(
            !t.scheduler.is_saturate_mode(),
            "scheduler must leave Saturate Mode when lease expiry demotes the state machine"
        );
    }

    #[test]
    fn transport_constructs_saturate_state_machine_in_normal_state() {
        use crate::transport::saturate::SaturateState;

 // The state machine is instantiated by `MeshTransport::new` in
 // production code — not only in test constructions — and starts in
 // NORMAL with the scheduler out of Saturate Mode.
        let t = make_transport();
        assert_eq!(t.saturate.state(), SaturateState::Normal);
        assert!(!t.scheduler.is_saturate_mode());
    }

 // ── Peer dialing (Subphase 1.2) ─────────────────────────────────────────
 //
 // mDNS discovery previously registered Gossipsub explicit peers but never
 // dialed them, so discovered peers never connected. The production Swarm
 // polling task (`CoreHandle::init`, `api/mod.rs`) calls
 // `dial_discovered_mdns_peers` on every `Mdns(Discovered)` event. This
 // integration test starts two real Swarms built by the production
 // `MeshTransport::start()` path and asserts that handing one swarm the
 // other's mDNS-style (peer, address) announcement actually establishes a
 // connection in both directions — no multicast, no test-only injection
 // helpers.
 //
 // The drivers keep their Swarm alive until the test aborts them: dropping
 // a Swarm the moment its side sees `ConnectionEstablished` closes the
 // socket while the remote's independent upgrade task may still be
 // finishing, which fails the remote's negotiation.

    #[cfg(feature = "native")]
    async fn drive_swarm_until_connected(
        mut swarm: libp2p::Swarm<TirBaseBehaviour>,
        peer: libp2p::PeerId,
        mut on_connected: Option<tokio::sync::oneshot::Sender<()>>,
    ) {
        use libp2p::futures::StreamExt as _;
        loop {
            if swarm.is_connected(&peer) {
                if let Some(tx) = on_connected.take() {
                    let _ = tx.send(());
                }
            }
            swarm.select_next_some().await;
        }
    }

    #[cfg(feature = "native")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discovered_mdns_peers_are_dialed_and_connect() {
        use libp2p::futures::StreamExt as _;
        use libp2p::swarm::SwarmEvent;
        use libp2p::Multiaddr;
        use std::time::Duration;
        use tokio::sync::{mpsc, oneshot};

        fn transport_config() -> TransportConfig {
            TransportConfig {
                listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
                ..Default::default()
            }
        }

 // Two real device instances: each `MeshTransport::start()` builds a
 // libp2p Swarm with TCP + Noise + Yamux + mDNS + Gossipsub + Identify
 // + Ping, exactly as `CoreHandle::init` does in production.
        let mut transport_a =
            MeshTransport::new("did:key:node-a".to_string(), [0u8; 32], transport_config());
        transport_a.start().await.expect("transport A must start");
        let (tx_a, _rx_a) = mpsc::channel::<Vec<u8>>(16);
        let mut swarm_a = transport_a
            .take_swarm(tx_a)
            .expect("transport A must own a Swarm after start");

        let mut transport_b =
            MeshTransport::new("did:key:node-b".to_string(), [0u8; 32], transport_config());
        transport_b.start().await.expect("transport B must start");
        let (tx_b, _rx_b) = mpsc::channel::<Vec<u8>>(16);
        let mut swarm_b = transport_b
            .take_swarm(tx_b)
            .expect("transport B must own a Swarm after start");

        let peer_a = *swarm_a.local_peer_id();
        let peer_b = *swarm_b.local_peer_id();
        assert_ne!(
            peer_a, peer_b,
            "the two transports must have distinct peer ids"
        );

 // Learn B's real listen address — the address its mDNS announcement
 // would carry. A's mDNS service reports this exact (peer, address)
 // pair when it discovers B.
        let b_listen_addr: Multiaddr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm_b.select_next_some().await {
                break address;
            }
        };

 // This is the Subphase 1.2 wiring under test: exactly what the
 // production poll loop does on `Mdns(Discovered)`. Before this fix
 // the loop only called `gossipsub.add_explicit_peer`, so B stayed
 // unreachable regardless of what mDNS announced.
        dial_discovered_mdns_peers(&mut swarm_a, vec![(peer_b, b_listen_addr.clone())]);

 // Drive both Swarms until the connection is established end-to-end
 // (A dials → TCP + Noise + Yamux handshake → B accepts).
        let (a_connected_tx, a_connected_rx) = oneshot::channel::<()>();
        let (b_connected_tx, b_connected_rx) = oneshot::channel::<()>();
        tokio::spawn(drive_swarm_until_connected(
            swarm_a,
            peer_b,
            Some(a_connected_tx),
        ));
        tokio::spawn(drive_swarm_until_connected(
            swarm_b,
            peer_a,
            Some(b_connected_tx),
        ));

        tokio::time::timeout(Duration::from_secs(15), async {
            a_connected_rx
                .await
                .expect("A must observe the connection to B");
            b_connected_rx
                .await
                .expect("B must observe the connection from A");
        })
        .await
        .expect("the mDNS-discovered peer was never dialed into a real connection within 15s");
    }

 // ── BLE transport bridge ────────────────────────────────────────────────
 //
 // Integration tests for the BLE transport path. These tests exercise the
 // channel-based BLE plumbing without requiring actual BLE hardware: the
 // BLE I/O task is bypassed and messages are injected/observed directly on
 // the `ble_outbound_tx` / `ble_inbound_rx` channels.

    #[cfg(feature = "native")]
    #[test]
    fn ble_send_delta_routes_to_ble_outbound_channel() {
        use crate::transport::message::GossipMessage;

        let mut t = make_transport();
        t.config.mesh_ble_enabled = true;

        let (ble_outbound_tx, mut ble_outbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        let (ble_inbound_tx, ble_inbound_rx) = tokio::sync::mpsc::channel::<GossipMessage>(32);

        t.ble_outbound_tx = Some(ble_outbound_tx);
        t.ble_inbound_tx = Some(ble_inbound_tx);
        t.ble_inbound_rx = Some(ble_inbound_rx);

        t.on_peer_discovered(
            DiscoveredPeer {
                did: "did:key:ble-peer".to_string(),
                transport: PeerTransport::BleBridge {
                    bridge_did: "did:key:ble-bridge".to_string(),
                },
                hop_count: 1,
            },
            1_000,
        )
        .unwrap();

        let delta = sample_delta();
        t.send_delta(&"did:key:ble-peer".to_string(), &delta)
            .expect("send_delta must succeed for BLE peer");

        let payload = ble_outbound_rx
            .blocking_recv()
            .expect("BLE outbound channel must carry the framed Delta");

        let wire: GossipMessage =
            serde_json::from_slice(&payload).expect("payload must be a GossipMessage");
        match wire {
            GossipMessage::InboundDelta(d) => {
                assert_eq!(d.id, delta.id);
            }
            other => panic!("expected InboundDelta over BLE, got: {other:?}"),
        }
    }

    #[cfg(feature = "native")]
    #[test]
    fn ble_receive_delta_dispatches_through_process_wire_message() {
        use crate::transport::message::GossipMessage;

        let mut t = make_transport();
        t.config.mesh_ble_enabled = true;

        let (ble_outbound_tx, _ble_outbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        let (ble_inbound_tx, ble_inbound_rx) = tokio::sync::mpsc::channel::<GossipMessage>(32);

        t.ble_outbound_tx = Some(ble_outbound_tx);
        t.ble_inbound_tx = Some(ble_inbound_tx);
        t.ble_inbound_rx = Some(ble_inbound_rx);

        let delta = sample_delta();
        let msg = GossipMessage::InboundDelta(delta.clone());
        let bytes = msg.to_bytes();

        t.receive_delta(&bytes).expect("receive_delta must succeed");

        let processed = t
            .last_ble_inbound
            .take()
            .expect("BLE inbound must be recorded");
        match processed {
            GossipMessage::InboundDelta(d) => {
                assert_eq!(d.id, delta.id);
            }
            other => panic!("expected InboundDelta after receive_delta, got: {other:?}"),
        }
    }

 // ── BLE-class MTU fragmentation (Req 5.7–5.8) ────────────────────────

    fn large_delta() -> Delta {
        Delta {
            id: [0x5Au8; 32],
            author_did: "did:key:test".to_string(),
            signature: crate::crdt::delta::Ed25519Signature::default(),
            schema_hash: [0u8; 32],
            automerge_bytes: (0u8..=255).cycle().take(1_400).collect(),
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport: 3,
            created_at: 2_000_000,
        }
    }

    #[test]
    fn prepare_outbound_fragments_at_mesh_mtu_256() {
        let mut t = make_transport();
        t.config.mtu = 256;

        let delta = large_delta();
        let messages = t.prepare_outbound(&delta).expect("prepare");

        assert!(
            messages.len() > 1,
            "a {} byte Delta at mtu=256 must span more than one fragment (got {})",
            serde_json::to_vec(&delta).unwrap().len(),
            messages.len()
        );
        for m in &messages {
            match m {
                crate::transport::message::GossipMessage::InboundDeltaFragment(f) => {
                    assert!(
                        f.payload.len() <= 256,
                        "fragment payload {} exceeds mtu 256",
                        f.payload.len()
                    );
                    assert_eq!(f.delta_id, delta.id);
                }
                other => panic!("expected InboundDeltaFragment, got {other:?}"),
            }
        }
    }

    #[test]
    fn out_of_order_and_duplicate_fragments_reassemble_exactly_once() {
        use crate::transport::message::GossipMessage;

        let mut sender = make_transport();
        sender.config.mtu = 256;
        let delta = large_delta();
        let mut frames = sender.prepare_outbound(&delta).expect("prepare");

 // Reverse order; duplicate the first envelope, as an at-most-once
 // network may deliver twice.
        frames.reverse();
        frames.push(frames[0].clone());

        let mut receiver = make_transport();
        let mut completed = None;
        for frame in frames {
            if let Some(msg) = receiver.process_wire_message(frame) {
                assert!(completed.is_none(), "the Delta completed twice");
                completed = Some(msg);
            }
        }

        match completed.expect("all fragments were delivered") {
            GossipMessage::InboundDelta(d) => {
                assert_eq!(d.id, delta.id);
                assert_eq!(d.automerge_bytes, delta.automerge_bytes);
                assert_eq!(d.signature, delta.signature);
            }
            other => panic!("expected a reassembled InboundDelta, got {other:?}"),
        }
        assert_eq!(
            receiver.reassembly_buffer.pending_count(),
            0,
            "the completed assembly must not be retained"
        );
    }

    #[test]
    fn missing_fragment_leaves_no_partial_delta_and_times_out() {
        let mut sender = make_transport();
        sender.config.mtu = 256;
        let delta = large_delta();
        let frames = sender.prepare_outbound(&delta).expect("prepare");
        assert!(frames.len() > 2);

        let mut receiver = make_transport();
        let mut delivered = 0;
        for (i, frame) in frames.into_iter().enumerate() {
            if i == 1 {
                continue; // drop one fragment
            }
            if receiver.process_wire_message(frame).is_some() {
                delivered += 1;
            }
        }
        assert_eq!(delivered, 0, "an incomplete Delta must never be delivered");
        assert_eq!(receiver.reassembly_buffer.pending_count(), 1);

 // The partial is bounded: it expires rather than pending forever.
        let expired = receiver.reassembly_buffer.expire_stale(
            crate::traits::monotonic_now() as i64
                + crate::transport::fragment::FRAGMENT_STALE_TIMEOUT_US
                + 1,
        );
        assert_eq!(expired, 1, "the partial assembly must be discarded on timeout");
        assert_eq!(receiver.reassembly_buffer.pending_count(), 0);
    }

 // ── Multi-hop relay bounds (Req 5.5) ───────────────────────────────────

    #[test]
    fn relay_delivers_for_the_target_and_is_hop_bounded() {
        let relay = make_transport(); // did:key:local, max_hop_count = 3
        let delta = sample_delta();

        match relay.relay_decision(
            "did:key:local".to_string(),
            delta.clone(),
            0,
            vec!["did:key:origin".to_string()],
        ) {
            RelayDecision::Deliver(crate::transport::message::GossipMessage::InboundDelta(d)) => {
                assert_eq!(d.id, delta.id)
            }
            other => panic!("an envelope for this node must be delivered, got {other:?}"),
        }

        match relay.relay_decision(
            "did:key:target".to_string(),
            delta.clone(),
            0,
            vec!["did:key:origin".to_string()],
        ) {
            RelayDecision::Forward(crate::transport::message::GossipMessage::RelayDelta {
                hop_count,
                visited,
                ..
            }) => {
                assert_eq!(hop_count, 1, "a relay increments the hop count by exactly one");
                assert_eq!(
                    visited,
                    vec!["did:key:origin".to_string(), "did:key:local".to_string()],
                    "the relay appends itself to the visited set"
                );
            }
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn relay_drops_loops_and_exhausted_hop_budget() {
        let relay = make_transport();
        let delta = sample_delta();

        match relay.relay_decision(
            "did:key:target".to_string(),
            delta.clone(),
            1,
            vec![
                "did:key:origin".to_string(),
                "did:key:local".to_string(),
            ],
        ) {
            RelayDecision::Drop(reason) => assert!(reason.contains("loop"), "{reason}"),
            other => panic!("a repeated relay must be dropped, got {other:?}"),
        }

        match relay.relay_decision(
            "did:key:target".to_string(),
            delta,
            3, // max_hop_count
            vec!["did:key:origin".to_string()],
        ) {
            RelayDecision::Drop(reason) => assert!(reason.contains("hop budget"), "{reason}"),
            other => panic!("an envelope at the hop limit must be dropped, got {other:?}"),
        }
    }

 // ── BLE bridge over an emulated link (Req 5.3) ────────────────────────

    struct InMemoryBleLink {
        inbox: std::sync::Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
        outbox: tokio::sync::mpsc::Sender<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl crate::transport::ble::BleLink for InMemoryBleLink {
        async fn send_chunk(&mut self, chunk: &[u8]) -> Result<(), TirBaseError> {
            self.outbox
                .send(chunk.to_vec())
                .await
                .map_err(|e| TirBaseError::MeshUnavailable {
                    reason: format!("emulated BLE write failed: {e}"),
                })
        }

        async fn recv_chunk(&mut self) -> Result<Option<Vec<u8>>, TirBaseError> {
            Ok(self.inbox.lock().await.recv().await)
        }
    }

 /// Two transports joined by an emulated BLE link. The chunk framing,
 /// assembly, selection and dispatch are the production `ble.rs` code; only
 /// the radio is replaced.
    #[tokio::test]
    async fn ble_bridge_carries_a_fragmented_delta_over_an_emulated_link() {
        use crate::transport::message::GossipMessage;

        // a → b radio queues
        let (a_to_b_tx, a_to_b_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        let (b_to_a_tx, b_to_a_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

        let mut sender = make_transport();
        sender.init_ble_channels().expect("BLE channels");
        sender
            .bind_ble_link(InMemoryBleLink {
                inbox: std::sync::Arc::new(tokio::sync::Mutex::new(b_to_a_rx)),
                outbox: a_to_b_tx,
            })
            .expect("bind sender link");

 // A non-BLE outbound channel must stay empty: BLE peers are selected
        // away from Gossipsub by `send_delta`.
        let (gossip_tx, mut gossip_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        assert!(sender.take_swarm(gossip_tx).is_none());

        sender
            .on_peer_discovered(
                DiscoveredPeer {
                    did: "did:key:ble-peer".to_string(),
                    transport: PeerTransport::BleBridge {
                        bridge_did: "did:key:ble-bridge".to_string(),
                    },
                    hop_count: 1,
                },
                1_000,
            )
            .unwrap();

        let mut receiver = make_transport();
        receiver.init_ble_channels().expect("BLE channels");
        receiver
            .bind_ble_link(InMemoryBleLink {
                inbox: std::sync::Arc::new(tokio::sync::Mutex::new(a_to_b_rx)),
                outbox: b_to_a_tx,
            })
            .expect("bind receiver link");
        let (dispatch_tx, mut dispatch_rx) = tokio::sync::mpsc::channel::<GossipMessage>(8);
        receiver.set_ble_dispatch(dispatch_tx);

        let delta = large_delta();
        sender
            .send_delta(&"did:key:ble-peer".to_string(), &delta)
            .expect("BLE send must succeed");

 // Nothing may have been published on the Gossipsub path.
        assert!(
            gossip_rx.try_recv().is_err(),
            "a BleBridge peer must not also publish over Gossipsub"
        );

 // Drive the production poll loop until the reassembled Delta dispatches.
        let deadline = crate::traits::monotonic_now() + 5_000_000;
        let dispatched = loop {
            receiver.poll_ble_inbound();
            if let Ok(msg) = dispatch_rx.try_recv() {
                break msg;
            }
            assert!(
                crate::traits::monotonic_now() < deadline,
                "the emulated BLE link never delivered the Delta within 5s"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };

        match dispatched {
            GossipMessage::InboundDelta(d) => {
                assert_eq!(d.id, delta.id);
                assert_eq!(d.automerge_bytes, delta.automerge_bytes);
            }
            other => panic!("expected InboundDelta over BLE, got {other:?}"),
        }
    }

    #[test]
    fn ble_chunk_assembler_accepts_out_of_order_and_duplicate_chunks() {
        use crate::transport::ble::{chunk_id_for, fragment_for_ble, BleChunkAssembler};

        let payload: Vec<u8> = (0u8..=255).cycle().take(1_500).collect();
        let mut chunks = fragment_for_ble(chunk_id_for(&payload), &payload);
        assert!(chunks.len() > 1);

        chunks.reverse();
        chunks.push(chunks[0].clone());

        let mut assembler = BleChunkAssembler::default();
        let mut done = None;
        for chunk in chunks {
            if let Some(bytes) = assembler.push_chunk(chunk).expect("chunk accepted") {
                assert!(done.is_none(), "payload assembled twice");
                done = Some(bytes);
            }
        }
        assert_eq!(done.expect("all chunks delivered"), payload);
        assert_eq!(assembler.pending_count(), 0);
    }

    /// Hardware-gated: real BLE radio verification (never run in CI).
 ///
 /// Requires a Bluetooth adapter and a TirBase peripheral advertising the
 /// TirBase GATT service. Run on a machine with hardware:
 /// `cargo test -p tirbase-core --features native --lib ble_hardware -- --ignored`.
    #[cfg(feature = "native")]
    #[ignore = "requires a real BLE adapter and a TirBase peripheral"]
    #[tokio::test]
    async fn ble_hardware_scan_connect_and_write_round_trip() {
        use crate::transport::ble::BleAdapter;

        let mut adapter = BleAdapter::new("did:key:hw-local".to_string(), "did:key:hw-peer".to_string())
            .await
            .expect("a BLE adapter must be present");
        adapter
            .scan_and_connect(30)
            .await
            .expect("a TirBase peripheral must be advertising");
        adapter
            .subscribe_notifications()
            .await
            .expect("notifications must be subscribable");
        let mut link = adapter;
        crate::transport::ble::BleLink::send_chunk(&mut link, &[0u8; 8])
            .await
            .expect("a chunk write must succeed over the radio");
    }
}

pub mod security_event_sync;
pub use security_event_sync::{
    AppendOnlySecurityEventCollection, PeerSecurityEventSyncLimiter, SecurityEventSyncBatch,
    SecurityEventSyncHandler, SecurityEventSyncRecord, SyncInboundDecision,
    SECURITY_EVENT_SYNC_MAX_PER_PEER_PER_MIN, SECURITY_EVENT_SYNC_RETRY_SECS,
};
