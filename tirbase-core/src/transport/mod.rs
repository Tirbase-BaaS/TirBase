//! MeshTransport — rust-libp2p Swarm setup and peer lifecycle management (Req 5).

#![allow(dead_code, unused_variables, unused_imports)]

pub mod discovery;
pub mod fragment;
pub mod priority;
pub mod saturate;
pub mod scheduler;
pub mod session;

use crate::crdt::delta::{Delta, Did};
use crate::errors::TirBaseError;

/// The mesh transport layer managing peer connections, scheduling, and
/// session cryptography.
pub struct MeshTransport {
    // TODO(task-9): embed libp2p Swarm, DrrScheduler, peer table
}

impl MeshTransport {
    /// Start the mesh transport, begin mDNS discovery, and listen for incoming peers.
    pub async fn start(&mut self) -> Result<(), TirBaseError> {
        todo!("Task 9: implement libp2p Swarm startup")
    }

    /// Send a Delta to a specific peer (routed through DrrScheduler).
    pub async fn send_delta(&mut self, peer_did: &Did, delta: &Delta) -> Result<(), TirBaseError> {
        todo!("Task 9: implement Delta send")
    }

    /// Return the list of currently active peer DIDs.
    pub fn active_peers(&self) -> Vec<Did> {
        todo!("Task 9: implement peer list")
    }

    /// Remove a peer from the active peer list after a configurable timeout (Req 5.6).
    pub fn remove_peer(&mut self, peer_did: &Did) {
        todo!("Task 9: implement peer removal")
    }
}
