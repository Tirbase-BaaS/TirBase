//! Peer discovery — mDNS on local IP networks and BLE routing bridges (Req 5.2–5.3).
//!
//! mDNS integration uses `libp2p::mdns::tokio::Behaviour` (native-only).
//! BLE bridge peers are modelled as relay-routed entries discovered via
//! application-layer announcement (the BLE transport itself is out of scope
//! for the rust-libp2p layer in v1; data-structure support is provided here).

#![allow(dead_code, unused_variables, unused_imports)]

use crate::crdt::delta::Did;
use crate::errors::TirBaseError;
use std::collections::HashMap;

// ─── DiscoveredPeer ───────────────────────────────────────────────────────────

/// Represents a discovered peer and the transport path to reach it.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub did: Did,
    pub transport: PeerTransport,
    /// Number of hops to reach this peer (multi-hop relay — Req 5.5).
    pub hop_count: u8,
}

// ─── PeerTransport ────────────────────────────────────────────────────────────

/// The transport mechanism used to reach a discovered peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerTransport {
    /// Direct mDNS-discovered peer on a local IP network (Req 5.2).
    Mdns { multiaddr: String },
    /// Peer reachable via a BLE routing bridge (Req 5.3).
    BleBridge { bridge_did: Did },
    /// Peer reachable via multi-hop relay (Req 5.5).
    MultiHopRelay { next_hop_did: Did },
    /// Peer connected via an explicitly configured address (application-initiated
    /// dial — `CoreHandle::dial_peer`, Subphase 1.5).  Used for topologies where
    /// mDNS discovery is unavailable (WAN peers, cloud relay) and recorded when
    /// the libp2p connection is established.
    Explicit { multiaddr: String },
}

// ─── RetryEntry ───────────────────────────────────────────────────────────────

/// A queued Delta awaiting retry delivery to an unreachable peer (Req 5.6).
#[derive(Debug, Clone)]
pub struct RetryEntry {
    pub peer_did: Did,
    /// Serialised Delta bytes.
    pub delta_bytes: Vec<u8>,
    /// Next retry wall-clock time (UTC microseconds).
    pub next_retry_at: i64,
    /// Number of delivery attempts so far.
    pub attempts: u32,
}

// ─── PeerState ────────────────────────────────────────────────────────────────

/// Lifecycle state of a known peer.
#[derive(Debug, Clone)]
pub struct PeerState {
    pub peer: DiscoveredPeer,
    /// UTC microseconds when this peer was last seen/contacted successfully.
    pub last_seen_us: i64,
    /// Whether this peer is currently considered active.
    pub active: bool,
}

// ─── PeerDiscovery ────────────────────────────────────────────────────────────

/// Discovery and retry state for the mesh transport (Req 5.2–5.6).
pub struct PeerDiscovery {
    /// Configurable maximum hop count (Req 5.5).
    pub max_hop_count: u8,
    /// How long (seconds) without a successful contact before a peer is
    /// considered unreachable and removed from the active list (Req 5.6).
    pub peer_timeout_secs: u64,
    /// How long (seconds) between delivery retry attempts (Req 5.6).
    pub retry_interval_secs: u64,
    /// Bounded retry queue (Req 5.6).
    retry_queue: std::collections::VecDeque<RetryEntry>,
    /// Maximum entries in the retry queue (Req 5.6).
    pub max_retry_queue: usize,
    /// Active peer table: DID → PeerState.
    peers: HashMap<Did, PeerState>,
}

impl PeerDiscovery {
    /// Create a new `PeerDiscovery` with the given configuration.
    pub fn new(
        max_hop_count: u8,
        peer_timeout_secs: u64,
        retry_interval_secs: u64,
        max_retry_queue: usize,
    ) -> Self {
        Self {
            max_hop_count,
            peer_timeout_secs,
            retry_interval_secs,
            retry_queue: std::collections::VecDeque::new(),
            max_retry_queue,
            peers: HashMap::new(),
        }
    }

    // ── Peer lifecycle ────────────────────────────────────────────────────────

    /// Handle a newly discovered peer.
    ///
    /// Rejects multi-hop peers whose hop count exceeds `max_hop_count` (Req 5.5).
    /// Adds accepted peers to the active peer table.
    /// In production this would trigger a Noise session initiation (Req 5.4),
    /// which is performed by `SessionManager::initiate()` in `transport/mod.rs`.
    pub fn on_peer_discovered(
        &mut self,
        peer: DiscoveredPeer,
        now_us: i64,
    ) -> Result<(), TirBaseError> {
        if peer.hop_count > self.max_hop_count {
            // Peer exceeds configured hop-count limit — silently discard (Req 5.5).
            return Ok(());
        }

        self.peers.insert(
            peer.did.clone(),
            PeerState {
                peer,
                last_seen_us: now_us,
                active: true,
            },
        );
        Ok(())
    }

    /// Record a successful contact with a peer (resets its timeout clock).
    pub fn touch_peer(&mut self, peer_did: &Did, now_us: i64) {
        if let Some(state) = self.peers.get_mut(peer_did) {
            state.last_seen_us = now_us;
            state.active = true;
        }
    }

    /// Remove a peer from the active peer list immediately (Req 5.6).
    pub fn remove_peer(&mut self, peer_did: &Did) {
        self.peers.remove(peer_did);
    }

    /// Tick the peer timeout clock.
    ///
    /// Removes peers that have not been seen for longer than
    /// `peer_timeout_secs` from the active list (Req 5.6).
    pub fn tick_timeouts(&mut self, now_us: i64) {
        let timeout_us = self.peer_timeout_secs as i64 * 1_000_000;
        self.peers.retain(|_, state| {
            let elapsed = now_us - state.last_seen_us;
            elapsed < timeout_us
        });
    }

    /// Return the list of currently active peer DIDs.
    pub fn active_peers(&self) -> Vec<Did> {
        self.peers.keys().cloned().collect()
    }

    /// Return `true` if the given DID is an active peer.
    pub fn is_active(&self, peer_did: &Did) -> bool {
        self.peers.contains_key(peer_did)
    }

    // ── Retry queue ───────────────────────────────────────────────────────────

    /// Queue an undelivered Delta for retry (Req 5.6).
    ///
    /// Silently drops the entry if the queue is full (bounded per Req 5.6).
    pub fn enqueue_retry(&mut self, entry: RetryEntry) -> Result<(), TirBaseError> {
        if self.retry_queue.len() >= self.max_retry_queue {
            // Queue is full — drop new entry to preserve bound (Req 5.6).
            return Ok(());
        }
        self.retry_queue.push_back(entry);
        Ok(())
    }

    /// Drain entries from the retry queue that are due for reattempt
    /// (`next_retry_at` ≤ `now_us`).
    ///
    /// Returns the entries to attempt; removes them from the queue.
    pub fn drain_due_retries(&mut self, now_us: i64) -> Vec<RetryEntry> {
        let mut due = Vec::new();
        let mut remaining = std::collections::VecDeque::new();
        for entry in self.retry_queue.drain(..) {
            if entry.next_retry_at <= now_us {
                due.push(entry);
            } else {
                remaining.push_back(entry);
            }
        }
        self.retry_queue = remaining;
        due
    }

    /// Current retry queue depth.
    pub fn retry_queue_len(&self) -> usize {
        self.retry_queue.len()
    }
}

// ─── mDNS event adapter (native only) ────────────────────────────────────────

/// Adapter that translates libp2p mDNS events into `PeerDiscovery` calls.
///
/// In the actual `MeshTransport::poll()` loop this is called whenever the
/// libp2p Swarm yields an `MdnsEvent`.
///
/// Feature-gated to avoid importing libp2p on the WASM target.
#[cfg(feature = "native")]
pub mod mdns_adapter {
    use super::*;
    use libp2p::mdns::Event as MdnsEvent;
    use libp2p::PeerId;

    /// Map a libp2p `PeerId` to a TirBase DID.
    ///
    /// TirBase DIDs are `did:key:` DIDs derived from the peer's Ed25519 key.
    /// For peers discovered via libp2p mDNS we use the `PeerId`'s multihash
    /// encoding as a stable identifier until the full DID exchange has
    /// occurred during the Noise handshake.
    pub fn peer_id_to_did(peer_id: &PeerId) -> Did {
        format!("did:key:{}", peer_id)
    }

    /// Handle an `MdnsEvent` from the libp2p Swarm.
    ///
    /// - `Discovered`: add each peer to the active list (hop_count = 0).
    /// - `Expired`:    remove each peer from the active list (Req 5.6).
    pub fn handle_mdns_event(
        discovery: &mut PeerDiscovery,
        event: MdnsEvent,
        now_us: i64,
    ) {
        match event {
            MdnsEvent::Discovered(peers) => {
                for (peer_id, addr) in peers {
                    let did = peer_id_to_did(&peer_id);
                    let discovered = DiscoveredPeer {
                        did,
                        transport: PeerTransport::Mdns {
                            multiaddr: addr.to_string(),
                        },
                        hop_count: 0,
                    };
                    // On discovery failure (e.g. hop-count exceeded) we log
                    // and continue — a single bad peer must not block others.
                    let _ = discovery.on_peer_discovered(discovered, now_us);
                }
            }
            MdnsEvent::Expired(peers) => {
                for (peer_id, _addr) in peers {
                    let did = peer_id_to_did(&peer_id);
                    discovery.remove_peer(&did);
                }
            }
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_discovery() -> PeerDiscovery {
        PeerDiscovery::new(3, 30, 10, 100)
    }

    fn mdns_peer(did: &str) -> DiscoveredPeer {
        DiscoveredPeer {
            did: did.to_string(),
            transport: PeerTransport::Mdns {
                multiaddr: "/ip4/192.168.1.1/tcp/9000".to_string(),
            },
            hop_count: 0,
        }
    }

    // ── on_peer_discovered ────────────────────────────────────────────────────

    #[test]
    fn discovered_peer_added_to_active_list() {
        let mut disc = make_discovery();
        disc.on_peer_discovered(mdns_peer("did:key:peerA"), 1_000_000).unwrap();
        assert!(disc.is_active(&"did:key:peerA".to_string()));
    }

    #[test]
    fn peer_exceeding_max_hop_count_is_rejected() {
        let mut disc = make_discovery(); // max_hop_count = 3
        let far_peer = DiscoveredPeer {
            did: "did:key:far".to_string(),
            transport: PeerTransport::MultiHopRelay {
                next_hop_did: "did:key:hop1".to_string(),
            },
            hop_count: 4, // exceeds max
        };
        disc.on_peer_discovered(far_peer, 1_000_000).unwrap();
        assert!(!disc.is_active(&"did:key:far".to_string()));
    }

    #[test]
    fn peer_at_exact_max_hop_count_is_accepted() {
        let mut disc = make_discovery(); // max_hop_count = 3
        let relay_peer = DiscoveredPeer {
            did: "did:key:relay3".to_string(),
            transport: PeerTransport::MultiHopRelay {
                next_hop_did: "did:key:hop1".to_string(),
            },
            hop_count: 3, // exactly at max
        };
        disc.on_peer_discovered(relay_peer, 1_000_000).unwrap();
        assert!(disc.is_active(&"did:key:relay3".to_string()));
    }

    // ── peer timeout ──────────────────────────────────────────────────────────

    #[test]
    fn peer_timeout_removes_stale_peer() {
        let mut disc = make_discovery(); // peer_timeout_secs = 30
        disc.on_peer_discovered(mdns_peer("did:key:stale"), 0).unwrap();
        assert!(disc.is_active(&"did:key:stale".to_string()));

        // 31 seconds later (in microseconds)
        disc.tick_timeouts(31 * 1_000_000);
        assert!(!disc.is_active(&"did:key:stale".to_string()));
    }

    #[test]
    fn peer_not_removed_before_timeout() {
        let mut disc = make_discovery(); // peer_timeout_secs = 30
        disc.on_peer_discovered(mdns_peer("did:key:active"), 0).unwrap();

        disc.tick_timeouts(29 * 1_000_000); // 29s later
        assert!(disc.is_active(&"did:key:active".to_string()));
    }

    #[test]
    fn touch_peer_resets_timeout_clock() {
        let mut disc = make_discovery(); // peer_timeout_secs = 30
        disc.on_peer_discovered(mdns_peer("did:key:renew"), 0).unwrap();

        disc.touch_peer(&"did:key:renew".to_string(), 20 * 1_000_000);
        // Now 50s from original discovery but only 29s since touch
        disc.tick_timeouts(49 * 1_000_000);
        assert!(disc.is_active(&"did:key:renew".to_string()));
    }

    // ── retry queue ───────────────────────────────────────────────────────────

    #[test]
    fn retry_queue_bounded_at_max() {
        let mut disc = PeerDiscovery::new(3, 30, 10, 5); // max_retry_queue = 5
        for i in 0..10 {
            disc.enqueue_retry(RetryEntry {
                peer_did: format!("did:key:peer-{i}"),
                delta_bytes: vec![i as u8],
                next_retry_at: 1_000,
                attempts: 0,
            })
            .unwrap();
        }
        assert_eq!(disc.retry_queue_len(), 5);
    }

    #[test]
    fn drain_due_retries_returns_only_due_entries() {
        let mut disc = make_discovery();
        disc.enqueue_retry(RetryEntry {
            peer_did: "did:key:a".to_string(),
            delta_bytes: vec![1],
            next_retry_at: 500,   // due at t=500
            attempts: 0,
        })
        .unwrap();
        disc.enqueue_retry(RetryEntry {
            peer_did: "did:key:b".to_string(),
            delta_bytes: vec![2],
            next_retry_at: 2_000, // not yet due at t=1000
            attempts: 0,
        })
        .unwrap();

        let due = disc.drain_due_retries(1_000);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].peer_did, "did:key:a");
        assert_eq!(disc.retry_queue_len(), 1); // b still in queue
    }

    // ── BLE bridge peer ───────────────────────────────────────────────────────

    #[test]
    fn ble_bridge_peer_added_to_active_list() {
        let mut disc = make_discovery();
        let ble_peer = DiscoveredPeer {
            did: "did:key:ble-peer".to_string(),
            transport: PeerTransport::BleBridge {
                bridge_did: "did:key:bridge".to_string(),
            },
            hop_count: 1,
        };
        disc.on_peer_discovered(ble_peer, 1_000_000).unwrap();
        assert!(disc.is_active(&"did:key:ble-peer".to_string()));
    }

    // ── remove_peer ───────────────────────────────────────────────────────────

    #[test]
    fn remove_peer_makes_peer_inactive() {
        let mut disc = make_discovery();
        disc.on_peer_discovered(mdns_peer("did:key:remove-me"), 0).unwrap();
        disc.remove_peer(&"did:key:remove-me".to_string());
        assert!(!disc.is_active(&"did:key:remove-me".to_string()));
    }

    // ── active_peers ─────────────────────────────────────────────────────────

    #[test]
    fn active_peers_returns_all_active_dids() {
        let mut disc = make_discovery();
        disc.on_peer_discovered(mdns_peer("did:key:p1"), 0).unwrap();
        disc.on_peer_discovered(mdns_peer("did:key:p2"), 0).unwrap();
        disc.on_peer_discovered(mdns_peer("did:key:p3"), 0).unwrap();
        let active = disc.active_peers();
        assert_eq!(active.len(), 3);
    }
}
