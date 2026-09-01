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
    session::SessionManager,
};

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

    /// Native-only: libp2p Swarm (None before `start()` is called).
    #[cfg(feature = "native")]
    swarm: Option<libp2p::Swarm<TirBaseBehaviour>>,

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
            #[cfg(feature = "native")]
            swarm: None,
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

    /// Take ownership of the native libp2p Swarm out of this transport.
    ///
    /// Used by `CoreHandle::init` to move the Swarm into a dedicated polling
    /// task so it can be polled across `.await` points without holding the
    /// `MeshTransport` mutex (Rust forbids holding a sync mutex across `.await`).
    ///
    /// After this call `self.swarm` is `None`; `send_delta` will be unavailable
    /// until a new Swarm is re-installed (or the device is offline-only).
    #[cfg(feature = "native")]
    pub fn take_swarm(&mut self) -> Option<libp2p::Swarm<TirBaseBehaviour>> {
        self.swarm.take()
    }

    /// Send serialised bytes to the shared Gossipsub topic (Req 5.1).
    ///
    /// The `peer_did` argument is accepted for API compatibility but the
    /// message is published to the shared `tirbase/v1` topic so all subscribed
    /// peers receive it.  Routing, fragmentation, and Noise encryption are
    /// handled by the libp2p transport stack.
    #[cfg(feature = "native")]
    pub async fn send_delta(
        &mut self,
        peer_did: &Did,
        delta: &Delta,
    ) -> Result<(), TirBaseError> {
        use libp2p::gossipsub::IdentTopic;

        // Compute payloads before borrowing swarm (avoids split-borrow conflict).
        let payloads = self.prepare_outbound(delta)?;

        let swarm = self.swarm.as_mut().ok_or_else(|| TirBaseError::DeltaMalformed {
            reason: "transport not started".to_string(),
        })?;

        // Publish to the shared topic (not per-peer) so all subscribers receive it.
        let topic = IdentTopic::new(&self.gossip_topic);

        for payload in payloads {
            swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic.clone(), payload)
                .map_err(|e| TirBaseError::DeltaMalformed {
                    reason: format!("gossipsub publish error: {e:?}"),
                })?;
        }
        Ok(())
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
}
