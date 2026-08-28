//! MTU fragmentation and reassembly for low-bandwidth transports (Req 5.7–5.8).
//!
//! When the active transport MTU is below 256 bytes, Deltas are split into
//! fragments not exceeding that MTU. The receiving peer reassembles them
//! before processing.

#![allow(dead_code, unused_variables)]

use crate::crdt::delta::Did;
use crate::errors::TirBaseError;

/// A single fragment of a larger Delta payload.
#[derive(Debug, Clone)]
pub struct DeltaFragment {
    /// Identifies which Delta this fragment belongs to.
    pub delta_id: [u8; 32],
    /// Zero-indexed fragment number within the complete Delta.
    pub fragment_index: u32,
    /// Total number of fragments for this Delta.
    pub total_fragments: u32,
    /// Payload bytes (≤ MTU).
    pub payload: Vec<u8>,
}

/// Split a serialised Delta into fragments of at most `mtu` bytes each (Req 5.7).
pub fn fragment(
    delta_id: [u8; 32],
    delta_bytes: &[u8],
    mtu: usize,
) -> Vec<DeltaFragment> {
    todo!("Task 9: implement fragmentation")
}

/// Reassemble a complete set of fragments into the original Delta bytes (Req 5.8).
///
/// Returns `FragmentReassemblyFailed` if any fragment is missing or the set is
/// inconsistent. Discards the partial Delta and logs `{sender_did, fragment_count}`.
pub fn reassemble(
    fragments: Vec<DeltaFragment>,
    sender_did: &Did,
) -> Result<Vec<u8>, TirBaseError> {
    todo!("Task 9: implement reassembly with failure logging")
}

/// Partial reassembly buffer held until all fragments arrive.
#[derive(Debug, Default)]
pub struct ReassemblyBuffer {
    /// Keyed by delta_id.
    pending: std::collections::HashMap<[u8; 32], Vec<Option<DeltaFragment>>>,
}

impl ReassemblyBuffer {
    /// Add a fragment to the buffer. Returns the complete Delta bytes if all
    /// fragments for this Delta have arrived; otherwise returns None.
    pub fn add_fragment(
        &mut self,
        fragment: DeltaFragment,
        sender_did: &Did,
    ) -> Result<Option<Vec<u8>>, TirBaseError> {
        todo!("Task 9: implement buffer management")
    }
}
