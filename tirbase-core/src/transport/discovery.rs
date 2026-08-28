//! Peer discovery — mDNS on local IP networks and BLE routing bridges (Req 5.2–5.3).

#![allow(dead_code, unused_variables, unused_imports)]

use crate::crdt::delta::Did;
use crate::errors::TirBaseError;

/// Represents a discovered peer and the transport path to reach it.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub did: Did,
    pub transport: PeerTransport,
    /// Number of hops to reach this peer (multi-hop relay — Req 5.5).
    pub hop_count: u8,
}

/// The transport mechanism used to reach a discovered peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerTransport {
    /// Direct mDNS-discovered peer on a local IP network (Req 5.2).
    Mdns { multiaddr: String },
    /// Peer reachable via a BLE routing bridge (Req 5.3).
    BleBridge { bridge_did: Did },
    /// Peer reachable via multi-hop relay (Req 5.5).
    MultiHopRelay { next_hop_did: Did },
}

/// Retry queue entry for an undelivered Delta (Req 5.6).
#[derive(Debug, Clone)]
pub struct RetryEntry {
    pub peer_did: Did,
    pub delta_bytes: Vec<u8>,
    /// Next retry time (UTC microseconds).
    pub next_retry_at: i64,
    pub attempts: u32,
}

/// Discovery and retry state for the mesh transport.
pub struct PeerDiscovery {
    /// Configurable maximum hop count (Req 5.5).
    max_hop_count: u8,
    /// Configurable peer-unreachable timeout in seconds (Req 5.6).
    peer_timeout_secs: u64,
    /// Configurable retry interval in seconds (Req 5.6).
    retry_interval_secs: u64,
    /// Bounded retry queue (Req 5.6).
    retry_queue: std::collections::VecDeque<RetryEntry>,
    /// Maximum entries in the retry queue (Req 5.6).
    max_retry_queue: usize,
}

impl PeerDiscovery {
    pub fn new(max_hop_count: u8, peer_timeout_secs: u64, retry_interval_secs: u64, max_retry_queue: usize) -> Self {
        Self {
            max_hop_count,
            peer_timeout_secs,
            retry_interval_secs,
            retry_queue: std::collections::VecDeque::new(),
            max_retry_queue,
        }
    }

    /// Handle a newly discovered peer and initiate a Noise session (Req 5.4).
    pub async fn on_peer_discovered(&mut self, peer: DiscoveredPeer) -> Result<(), TirBaseError> {
        todo!("Task 9: trigger Noise handshake on discovery")
    }

    /// Queue an undelivered Delta for retry (Req 5.6).
    pub fn enqueue_retry(&mut self, entry: RetryEntry) -> Result<(), TirBaseError> {
        if self.retry_queue.len() >= self.max_retry_queue {
            // Queue is full — bounded per Req 5.6
            return Ok(());
        }
        self.retry_queue.push_back(entry);
        Ok(())
    }
}
