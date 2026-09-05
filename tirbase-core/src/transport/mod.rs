//! MeshTransport — rust-libp2p Swarm setup and peer lifecycle management (Req 5).
//!
//! The `MeshTransport` struct and `TransportConfig` are defined unconditionally
//! so the API surface is identical on both build targets (Req 1.2, 1.5).
//! All `libp2p`-specific code is gated behind `#[cfg(feature = "native")]`.

#![allow(dead_code, unused_variables, unused_imports)]

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
use crate::transport::{
    discovery::{DiscoveredPeer, PeerDiscovery, PeerTransport, RetryEntry},
    fragment::{fragment as fragment_delta, ReassemblyBuffer},
    saturate::{SaturateModeStateMachine, SaturateState, SATURATE_LEASE_DURATION_SECS},
    scheduler::{DrrScheduler, QueuedDelta},
    session::SessionManager,
};

fn current_timestamp_micros() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
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
    /// Active transport MTU in bytes.  Deltas are fragmented when `mtu < 256`
    /// (Req 5.7).  A value of 0 means "do not fragment".
    pub mtu: usize,
    /// Key rotation interval in seconds — clamped to `[60, 86400]` (Req 6.4).
    pub key_rotation_interval_secs: u64,
    /// libp2p listen address (native-only; ignored on wasm).
    pub listen_addr: String,
    /// M-of-N manager-signature threshold for terminating Saturate_Mode via a
    /// Lease Termination Delta (Req 13.6).  Clamped to `>= 1` at construction.
    pub saturate_termination_threshold_m: usize,
    /// 32-byte Ed25519 root CA public key used by the Saturate_Mode state
    /// machine to verify Manager DISASTER_ALERT Biscuit tokens offline
    /// (Req 13.1, 13.7).  Empty = explicit unconfigured state: activation
    /// fails until a key is configured.
    pub root_ca_public_key: Vec<u8>,
    /// Duration in seconds of a Saturate_Mode Lease opened by a DISASTER_ALERT
    /// activation or heartbeat renewal (Req 13.3).  Defaults to
    /// [`SATURATE_LEASE_DURATION_SECS`] (60 minutes — the spec window); a
    /// deployment may configure a shorter window (e.g. faster failover or
    /// runtime tests) or a longer one.  Clamped to `>= 1` at construction so a
    /// misconfigured zero never opens an already-expired lease.
    pub saturate_lease_duration_secs: i64,
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
        }
    }
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
/// application asks the Swarm to dial the announced address.  This is the
/// missing half of discovery: without it, mDNS neighbours stay unconnected and
/// the `add_explicit_peer` registration (which Gossipsub only honours for
/// connected peers) has nothing to gossip over.
///
/// Each announced address has the remote `/p2p/<peer-id>` suffix appended
/// before dialing.  Repeated `Discovered` events for an already-connected or
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
                eprintln!(
                    "[transport] mDNS: skipping {peer_id} — announced address {addr} carries a different peer id"
                );
                continue;
            }
        };

        match swarm.dial(
            libp2p::swarm::dial_opts::DialOpts::peer_id(peer_id)
                .addresses(vec![dial_addr])
                .build(),
        ) {
            Ok(()) => {
                eprintln!("[transport] mDNS: dialing discovered peer {peer_id}");
            }
            Err(e) => {
                eprintln!("[transport] mDNS: dial to discovered peer {peer_id} failed: {e}");
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

    /// Native-only: outbound publish channel sender.  Installed by
    /// `take_swarm` when the Swarm is detached; `send_delta` forwards
    /// prepared payloads here and the Swarm polling task (which owns the
    /// receiver end) publishes them to the Gossipsub topic.
    #[cfg(feature = "native")]
    pub(crate) outbound_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,

    /// Test-only: payloads that reached the outbound publish point (recorded
    /// by the Swarm polling task immediately before `gossipsub.publish`).
    #[cfg(all(feature = "native", test))]
    pub(crate) outbound_published: Vec<Vec<u8>>,

    /// Active Noise_IK sessions keyed by remote DID (Req 6.1).
    pub(crate) active_sessions: std::collections::HashMap<Did, crate::transport::session::NoiseSession>,

    /// Saturate_Mode state machine (Req 13): owns the lease lifecycle
    /// (activate / renew / M-of-N terminate / expiry tick) and verifies
    /// Manager DISASTER_ALERT Biscuit tokens offline.  Instantiated here in
    /// production code — never only in tests — and driven by
    /// [`MeshTransport::activate_saturate_mode`].
    pub(crate) saturate: SaturateModeStateMachine,
}

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
            active_sessions: std::collections::HashMap::new(),
            saturate,
            #[cfg(feature = "native")]
            swarm: None,
            #[cfg(feature = "native")]
            outbound_tx: None,
            #[cfg(all(feature = "native", test))]
            outbound_published: Vec::new(),
        }
    }

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
                transport: PeerTransport::BleBridge { bridge_did: bridge_did.clone() },
                hop_count: 1,
            },
            now_us,
        )?;
        eprintln!("[transport] BLE bridge: dialing {target_did} via bridge {bridge_did}");
        Ok(())
    }

    /// Initiate a Noise_IK session with a peer after a libp2p connection is
    /// established (Req 6.1).
    ///
    /// When `remote_static_pubkey` is provided, performs a full Noise_IK
    /// handshake via `SessionManager::initiate` (test / direct-connect path).
    /// When `remote_static_pubkey` is empty, registers the already-established
    /// session via `SessionManager::register_session` (production libp2p path,
    /// where the transport has already completed the Noise exchange).
    pub fn initiate_session(
        &mut self,
        peer_did: Did,
        peer_trust_level: TrustLevel,
        local_static_privkey: &[u8],
        remote_static_pubkey: &[u8],
        now_secs: i64,
    ) -> Result<(), TirBaseError> {
        let session = if remote_static_pubkey.is_empty() {
            self.session_manager
                .register_session(peer_did.clone(), now_secs)
        } else {
            self.session_manager.initiate(
                peer_did.clone(),
                peer_trust_level,
                local_static_privkey,
                remote_static_pubkey,
                now_secs,
            )?
        };
        self.active_sessions.insert(peer_did.clone(), session);
        Ok(())
    }

    /// Advance the peer-timeout clock: removes peers not seen within
    /// `peer_timeout_secs` (Req 5.6).
    pub fn tick_timeouts(&mut self, now_us: i64) {
        self.discovery.tick_timeouts(now_us);
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
    // event (activate / renew / M-of-N terminate).  Each delegates to the real
    // [`SaturateModeStateMachine`] and — only on success — reconciles the DRR
    // scheduler flag from the resulting state.  The scheduler is a mirror, not
    // a second source of truth: nothing in production may flip it directly.

    /// Reconcile the DRR scheduler's Saturate_Mode flag with the state machine.
    ///
    /// This is the **only** production writer of the scheduler flag: the
    /// scheduler holds no independent opinion about whether Saturate_Mode is
    /// active — it mirrors `saturate.state()`.  Every lifecycle transition
    /// funnels through [`SaturateModeStateMachine`] first and then runs this
    /// reconciler, so the boolean can never drift from the lease.  In
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
    /// success.  On success the DRR scheduler is reconciled into Saturate Mode
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
    /// 60 minutes from the renewal timestamp.  On success the scheduler is
    /// reconciled from the state machine (still SATURATE — all bandwidth to
    /// HIGH).  Any failure returns `SignatureVerificationFailed` and preserves
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
    /// immediately regardless of remaining lease duration.  On success the
    /// scheduler is reconciled from the state machine — this is the transition
    /// that clears the scheduler's Saturate_Mode flag (MEDIUM/LOW resumes
    /// normal service, Req 13.5).
    ///
    /// A signature set below the threshold returns `ThresholdNotMet` and
    /// leaves both the state machine and the scheduler untouched (invariant
    /// (b), Req 13.7).  When not in SATURATE the call is a no-op that returns
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
    /// and drops the lease.  The DRR scheduler is then reconciled from the
    /// resulting state — a lease-expiry demotion clears the scheduler's
    /// Saturate_Mode flag (MEDIUM/LOW resumes normal service, Req 13.5)
    /// exactly like an M-of-N termination does.  The reconcile runs
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

    // ── Fragmentation ─────────────────────────────────────────────────────────

    /// Serialise and optionally fragment a Delta for transmission (Req 5.7).
    ///
    /// Returns a list of `GossipMessage` payloads to send.  When `config.mtu`
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

        if self.config.mtu > 0 && self.config.mtu < 256 {
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

    // ── Native-only: Swarm startup ────────────────────────────────────────────

    /// Build the libp2p Swarm and start listening for connections (Req 5.1).
    ///
    /// - Generates an ephemeral Ed25519 keypair for the Swarm (the TirBase
    ///   identity keypair is separate; used for DID-layer crypto only).
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
    /// the receiver end — publishes them to the Gossipsub topic.  Outbound
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
    /// peers receive it.  Fragmentation and Noise encryption are handled by the
    /// libp2p transport stack.
    ///
    /// Prepared payloads are sent over the outbound publish channel to the
    /// Swarm polling task, which owns the `&mut Swarm` and performs the actual
    /// `gossipsub.publish`.  This is the re-architecture that keeps outbound
    /// delivery working after `take_swarm` empties `self.swarm`: the channel
    /// sender replaces the Swarm handle as the publish path.
    ///
    /// ## Wire framing (Subphase 1.5)
    ///
    /// The documented mesh protocol (`transport/message.rs`) frames **every**
    /// message as a tagged `GossipMessage` variant so the receiving side can
    /// dispatch without heuristics.  Whole-Delta payloads are therefore
    /// wrapped in `GossipMessage::InboundDelta` here, at the send side.  (A
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
    /// payload (polling task backlogged or shut down).  Callers treat this as
    /// best-effort: the local store and the durability queue remain
    /// authoritative while the device is offline (Req 3.3).
    #[cfg(feature = "native")]
    pub fn send_delta(&mut self, peer_did: &Did, delta: &Delta) -> Result<(), TirBaseError> {
        // Req 5.5: if the destination is not a direct neighbor, route through
        // a relay peer.
        if !self.discovery.is_direct_neighbor(peer_did) {
            if let Some(relay_did) = self.discovery.find_relay_peer(peer_did) {
                eprintln!(
                    "[transport] relay: {peer_did} is not a direct neighbor; \
                     routing delta through relay peer {relay_did}"
                );
                let relay_msg = crate::transport::message::GossipMessage::RelayDelta {
                    target_did: peer_did.clone(),
                    delta: delta.clone(),
                };
                let wire_payload = relay_msg.to_bytes();
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
    /// `GossipMessage::InboundDeltaFragment` messages.  This method:
    ///
    /// - **Fragments**: feeds each `DeltaFragment` into the per-`MeshTransport`
    ///   `ReassemblyBuffer`.  If the fragment completes a Delta, the reassembled
    ///   bytes are parsed into a `Delta` and returned as `Some(GossipMessage::InboundDelta)`.
    ///   If reassembly fails (missing/truncated/malformed fragments, or the
    ///   reassembled bytes don't parse as a valid `Delta`), the failure is
    ///   logged with the sender DID and fragment count and `None` is returned —
    ///   the partial Delta is discarded without corrupting any engine state
    ///   (Req 5.8 / Subphase 7.4 acceptance: clean reassembly failure handling).
    ///
    /// - **Non-fragments**: passes `InboundDelta`, `InboundDurabilityReceipt`,
    ///   `InboundRevocationDelta`, `InboundMigrationDelta`, and
    ///   `InboundMigrationRevocationDelta` through unchanged.
    ///
    /// Production caller: the Swarm polling task spawned in
    /// [`crate::api::CoreHandle::init`] calls this for every Gossipsub message
    /// before forwarding the result to `inbound_tx`.  On the WASM target the
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

                // Feed the fragment to the reassembly buffer.  The sender_did
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
                                // malformed/truncated payload.  Discard
                                // cleanly: log with sender + fragment context
                                // and return None so the message is dropped
                                // from the inbound pipeline without touching
                                // the CRDT engine or DAG state.
                                eprintln!(
                                    "[transport] reassembled Delta failed to parse as Delta: {e} — \
                                     discarding (delta_id was from fragment reassembly)"
                                );
                                None
                            }
                        }
                    }
                    Ok(None) => {
                        // Partial — awaiting more fragments.  Suppress silently.
                        None
                    }
                    Err(e) => {
                        // Reassembly failure: missing fragments, inconsistent
                        // totals, oversized allocation, or slot eviction
                        // discarded a partial Delta mid-flight (Req 5.8).
                        eprintln!(
                            "[transport] fragment reassembly failed: {e} — \
                             partial Delta discarded without corrupting state"
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
    /// whole-Delta payloads (Subphase 1.5).  The framed bytes go over the
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
    ///
    /// Called by the production scheduler tick loop spawned from
    /// `CoreHandle::init`; the Swarm polling task (Subphase 1.1) receives the
    /// forwarded payloads on the outbound channel and publishes them to the
    /// shared Gossipsub topic.  Without this, Deltas enqueued via
    /// [`MeshTransport::enqueue_outbound`] (HIGH-priority revocation
    /// rebroadcast, mDNS re-announcement) would accumulate in the scheduler
    /// queues forever.
    ///
    /// Returns the number of payloads forwarded.  Best-effort by design: if
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

    /// Record a payload at the outbound publish point (test-only).
    ///
    /// Called by the Swarm polling task just before `gossipsub.publish` so
    /// integration tests can observe that outbound Deltas reached the mesh
    /// layer without requiring a live peer.
    #[cfg(all(feature = "native", test))]
    pub(crate) fn record_outbound_payload(&mut self, payload: Vec<u8>) {
        self.outbound_published.push(payload);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
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
    // production code (`MeshTransport::new`).  These integration tests drive
    // the production entry points (`MeshTransport::activate_saturate_mode` /
    // `renew_saturate_mode` / `terminate_saturate_mode`, reached from
    // `CoreHandle` on both the WASM and native builds) with real tokens and
    // signatures, and assert the state machine AND the DRR scheduler stay in
    // lock-step — the scheduler flag is reconciled from the state machine,
    // never set by a bare boolean.

    fn now_secs() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
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
    // dialed them, so discovered peers never connected.  The production Swarm
    // polling task (`CoreHandle::init`, `api/mod.rs`) calls
    // `dial_discovered_mdns_peers` on every `Mdns(Discovered)` event.  This
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
        let mut transport_a = MeshTransport::new(
            "did:key:node-a".to_string(),
            [0u8; 32],
            transport_config(),
        );
        transport_a.start().await.expect("transport A must start");
        let (tx_a, _rx_a) = mpsc::channel::<Vec<u8>>(16);
        let mut swarm_a = transport_a
            .take_swarm(tx_a)
            .expect("transport A must own a Swarm after start");

        let mut transport_b = MeshTransport::new(
            "did:key:node-b".to_string(),
            [0u8; 32],
            transport_config(),
        );
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
        // would carry.  A's mDNS service reports this exact (peer, address)
        // pair when it discovers B.
        let b_listen_addr: Multiaddr = loop {
            match swarm_b.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => break address,
                _ => {}
            }
        };

        // This is the Subphase 1.2 wiring under test: exactly what the
        // production poll loop does on `Mdns(Discovered)`.  Before this fix
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
}
