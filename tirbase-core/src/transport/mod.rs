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
    discovery::{DiscoveredPeer, PeerDiscovery, RetryEntry},
    fragment::{fragment as fragment_delta, ReassemblyBuffer},
    scheduler::{DrrScheduler, QueuedDelta},
    session::SessionManager,
};

fn current_timestamp_micros() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_micros() as i64
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
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            peer_timeout_secs: 60,
            retry_interval_secs: 30,
            max_retry_queue: 1_000,
            max_hop_count: 4,
            mtu: 0,         // no fragmentation by default
            key_rotation_interval_secs: 3_600,
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
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

        match swarm
            .dial(
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
    outbound_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,

    /// Test-only: payloads that reached the outbound publish point (recorded
    /// by the Swarm polling task immediately before `gossipsub.publish`).
    #[cfg(all(feature = "native", test))]
    pub(crate) outbound_published: Vec<Vec<u8>>,

    /// Whether Saturate Mode is active (used on WASM where there is no live scheduler).
    pub saturate_active: bool,
}

impl MeshTransport {
    /// Create a new `MeshTransport` with the given configuration.
    pub fn new(local_did: Did, config: TransportConfig) -> Self {
        let discovery = PeerDiscovery::new(
            config.max_hop_count,
            config.peer_timeout_secs,
            config.retry_interval_secs,
            config.max_retry_queue,
        );
        let session_manager =
            SessionManager::new(local_did.clone(), config.key_rotation_interval_secs);

        Self {
            discovery,
            session_manager,
            reassembly_buffer: ReassemblyBuffer::default(),
            local_did,
            config,
            gossip_topic: "tirbase/v1".to_string(),
            scheduler: DrrScheduler::new(DEFAULT_LINK_CAPACITY_BYTES),
            #[cfg(feature = "native")]
            swarm: None,
            #[cfg(feature = "native")]
            outbound_tx: None,
            #[cfg(all(feature = "native", test))]
            outbound_published: Vec::new(),
            saturate_active: false,
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

    /// Activate or deactivate Saturate Mode (Req 13.2).
    ///
    /// On the native build this is ordinarily coordinated through `DrrScheduler`;
    /// on the WASM build we track the flag here so `core_activate_saturate_mode`
    /// can record the transition.
    pub fn set_saturate_mode(&mut self, active: bool) {
        self.saturate_active = active;
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
        let serialized_len = serde_json::to_vec(&delta).map(|b| b.len() as u64).unwrap_or(0);
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
    /// Returns a list of byte payloads to send.  When `config.mtu < 256` the
    /// Delta is split into fragments ≤ MTU; otherwise the full serialised
    /// bytes are returned as a single entry.
    pub fn prepare_outbound(
        &self,
        delta: &Delta,
    ) -> Result<Vec<Vec<u8>>, TirBaseError> {
        let bytes = serde_json::to_vec(delta)
            .map_err(|e| TirBaseError::DeltaMalformed {
                reason: format!("serialisation error: {e}"),
            })?;

        if self.config.mtu > 0 && self.config.mtu < 256 {
            let frags = fragment_delta(delta.id, &bytes, self.config.mtu);
            let payloads = frags
                .into_iter()
                .map(|f| {
                    serde_json::to_vec(&crate::transport::fragment::DeltaFragment {
                        delta_id: f.delta_id,
                        fragment_index: f.fragment_index,
                        total_fragments: f.total_fragments,
                        payload: f.payload,
                    })
                    .unwrap_or_default()
                })
                .collect();
            Ok(payloads)
        } else {
            Ok(vec![bytes])
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
            gossipsub, identify, mdns, noise as libp2p_noise, ping, tcp, SwarmBuilder,
            yamux,
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

                let gossipsub_behaviour =
                    gossipsub::Behaviour::new(
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
            let listen_addr: libp2p::Multiaddr =
                self.config.listen_addr.parse().map_err(|e| {
                    TirBaseError::NoiseHandshakeFailed {
                        peer_did: self.local_did.clone(),
                        reason: format!("invalid listen addr: {e}"),
                    }
                })?;
            swarm.listen_on(listen_addr).map_err(|e| {
                TirBaseError::NoiseHandshakeFailed {
                    peer_did: self.local_did.clone(),
                    reason: format!("listen_on failed: {e}"),
                }
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
    /// Returns [`TirBaseError::MeshUnavailable`] when no outbound channel is
    /// installed (transport never started) or the channel cannot accept the
    /// payload (polling task backlogged or shut down).  Callers treat this as
    /// best-effort: the local store and the durability queue remain
    /// authoritative while the device is offline (Req 3.3).
    #[cfg(feature = "native")]
    pub fn send_delta(
        &mut self,
        peer_did: &Did,
        delta: &Delta,
    ) -> Result<(), TirBaseError> {
        // Compute payloads before borrowing the channel.
        let payloads = self.prepare_outbound(delta)?;

        let tx = self.outbound_tx.as_ref().ok_or_else(|| {
            TirBaseError::MeshUnavailable {
                reason: "transport not started (no outbound channel installed)".to_string(),
            }
        })?;

        for payload in payloads {
            tx.try_send(payload).map_err(|e| TirBaseError::MeshUnavailable {
                reason: format!("outbound publish channel unavailable: {e}"),
            })?;
        }
        Ok(())
    }

    /// Run one DRR scheduling epoch and forward the drained Deltas to the
    /// outbound publish channel (Subphase 1.4 — Req 12).
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

        let tx = self.outbound_tx.as_ref().ok_or_else(|| {
            TirBaseError::MeshUnavailable {
                reason: "transport not started (no outbound channel installed)".to_string(),
            }
        })?;

        let mut forwarded = 0usize;
        for queued in drained {
            let payloads = self.prepare_outbound(&queued.delta)?;
            for payload in payloads {
                match tx.try_send(payload) {
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
        MeshTransport::new(
            "did:key:local".to_string(),
            TransportConfig {
                peer_timeout_secs: 30,
                retry_interval_secs: 10,
                max_retry_queue: 5,
                max_hop_count: 3,
                mtu: 0,
                key_rotation_interval_secs: 3_600,
                listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
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
        t.on_peer_discovered(mdns_peer("did:key:A", 0), 1_000).unwrap();
        assert!(t.active_peers().contains(&"did:key:A".to_string()));
    }

    #[test]
    fn peer_removed_immediately_is_no_longer_active() {
        let mut t = make_transport();
        t.on_peer_discovered(mdns_peer("did:key:B", 0), 1_000).unwrap();
        t.remove_peer(&"did:key:B".to_string());
        assert!(!t.active_peers().contains(&"did:key:B".to_string()));
    }

    #[test]
    fn peer_beyond_max_hop_count_not_added() {
        let mut t = make_transport(); // max_hop_count = 3
        t.on_peer_discovered(mdns_peer("did:key:far", 4), 1_000).unwrap();
        assert!(!t.active_peers().contains(&"did:key:far".to_string()));
    }

    #[test]
    fn peer_removed_by_timeout() {
        let mut t = make_transport(); // peer_timeout_secs = 30
        t.on_peer_discovered(mdns_peer("did:key:timeout", 0), 0).unwrap();
        t.tick_timeouts(31 * 1_000_000); // 31s later
        assert!(!t.active_peers().contains(&"did:key:timeout".to_string()));
    }

    // ── Retry queue ───────────────────────────────────────────────────────────

    #[test]
    fn retry_queue_bounded() {
        let mut t = make_transport(); // max_retry_queue = 5
        for i in 0..10 {
            t.enqueue_retry(
                format!("did:key:p{i}"),
                vec![i as u8],
                0,
            )
            .unwrap();
        }
        assert_eq!(t.discovery.retry_queue_len(), 5);
    }

    #[test]
    fn due_retries_are_drained() {
        let mut t = make_transport(); // retry_interval_secs = 10
        let now_us = 0i64;
        t.enqueue_retry("did:key:retry".to_string(), vec![0xAA], now_us).unwrap();

        // Not yet due
        assert_eq!(t.drain_due_retries(5_000_000).len(), 0);
        // Due after retry_interval_secs (10s = 10_000_000 µs)
        assert_eq!(t.drain_due_retries(10_000_001).len(), 1);
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
        let payloads = t.prepare_outbound(&delta).unwrap();
        assert_eq!(payloads.len(), 1);
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
        let payloads = t.prepare_outbound(&delta).unwrap();
        // Serialised Delta > 50 bytes → multiple fragments
        assert!(payloads.len() > 1);
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
        assert_eq!(
            payload,
            serde_json::to_vec(&delta).unwrap(),
            "send_delta must forward the exact output of prepare_outbound"
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
        let mut transport_a =
            MeshTransport::new("did:key:node-a".to_string(), transport_config());
        transport_a.start().await.expect("transport A must start");
        let (tx_a, _rx_a) = mpsc::channel::<Vec<u8>>(16);
        let mut swarm_a = transport_a
            .take_swarm(tx_a)
            .expect("transport A must own a Swarm after start");

        let mut transport_b =
            MeshTransport::new("did:key:node-b".to_string(), transport_config());
        transport_b.start().await.expect("transport B must start");
        let (tx_b, _rx_b) = mpsc::channel::<Vec<u8>>(16);
        let mut swarm_b = transport_b
            .take_swarm(tx_b)
            .expect("transport B must own a Swarm after start");

        let peer_a = *swarm_a.local_peer_id();
        let peer_b = *swarm_b.local_peer_id();
        assert_ne!(peer_a, peer_b, "the two transports must have distinct peer ids");

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
