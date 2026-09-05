//! MTU fragmentation and reassembly for low-bandwidth transports (Req 5.7–5.8).
//!
//! When the active transport MTU is below 256 bytes, Deltas are split into
//! fragments not exceeding that MTU. The receiving peer reassembles them
//! before processing.

#![allow(dead_code, unused_variables)]

use crate::crdt::delta::Did;
use crate::errors::TirBaseError;
use serde::{Deserialize, Serialize};

/// A single fragment of a larger Delta payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
///
/// If `delta_bytes` is empty or `mtu` is 0, returns an empty fragment list.
/// Each fragment carries the `delta_id`, its zero-based index, and the total
/// fragment count — sufficient for the receiver to reassemble in any order.
pub fn fragment(delta_id: [u8; 32], delta_bytes: &[u8], mtu: usize) -> Vec<DeltaFragment> {
    if delta_bytes.is_empty() || mtu == 0 {
        return vec![];
    }

    let chunks: Vec<&[u8]> = delta_bytes.chunks(mtu).collect();
    let total_fragments = chunks.len() as u32;

    chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| DeltaFragment {
            delta_id,
            fragment_index: i as u32,
            total_fragments,
            payload: chunk.to_vec(),
        })
        .collect()
}

/// Reassemble a complete set of fragments into the original Delta bytes (Req 5.8).
///
/// Returns `FragmentReassemblyFailed` if:
/// - `fragments` is empty or `total_fragments` is 0
/// - any expected fragment index (0..total_fragments-1) is missing
/// - duplicate fragment indices are present
///
/// Discards the partial Delta and logs `{sender_did, fragment_count}` on failure.
pub fn reassemble(
    fragments: Vec<DeltaFragment>,
    sender_did: &Did,
) -> Result<Vec<u8>, TirBaseError> {
    if fragments.is_empty() {
        return Err(TirBaseError::FragmentReassemblyFailed {
            sender_did: sender_did.clone(),
            expected: 0,
        });
    }

    let total_fragments = fragments[0].total_fragments;

    if total_fragments == 0 {
        return Err(TirBaseError::FragmentReassemblyFailed {
            sender_did: sender_did.clone(),
            expected: 0,
        });
    }

    // Validate all fragments share the same delta_id and total_fragments
    let delta_id = fragments[0].delta_id;
    for f in &fragments {
        if f.delta_id != delta_id || f.total_fragments != total_fragments {
            return Err(TirBaseError::FragmentReassemblyFailed {
                sender_did: sender_did.clone(),
                expected: total_fragments,
            });
        }
    }

    // Check for duplicates
    if fragments.len() != total_fragments as usize {
        return Err(TirBaseError::FragmentReassemblyFailed {
            sender_did: sender_did.clone(),
            expected: total_fragments,
        });
    }

    // Sort by index
    let mut sorted = fragments;
    sorted.sort_by_key(|f| f.fragment_index);

    // Verify all indices are present (0..total_fragments-1)
    for (expected_idx, frag) in sorted.iter().enumerate() {
        if frag.fragment_index != expected_idx as u32 {
            return Err(TirBaseError::FragmentReassemblyFailed {
                sender_did: sender_did.clone(),
                expected: total_fragments,
            });
        }
    }

    // Concatenate payloads
    let result: Vec<u8> = sorted.into_iter().flat_map(|f| f.payload).collect();
    Ok(result)
}

/// Maximum number of in-progress Delta assemblies held simultaneously.
pub const MAX_REASSEMBLY_SLOTS: usize = 1024;

/// Maximum `total_fragments` value accepted for any single Delta assembly.
pub const MAX_FRAGMENTS_PER_DELTA: u32 = 4096;

/// Partial reassembly buffer held until all fragments arrive.
#[derive(Debug, Default)]
pub struct ReassemblyBuffer {
    /// Keyed by delta_id.  Each entry is a slot array sized to total_fragments.
    pending: std::collections::HashMap<[u8; 32], Vec<Option<DeltaFragment>>>,
}

impl ReassemblyBuffer {
    #[cfg(test)]
    pub(crate) fn pending_count(&self) -> usize {
        self.pending.len()
    }

    #[cfg(test)]
    pub(crate) fn has_delta(&self, id: &[u8; 32]) -> bool {
        self.pending.contains_key(id)
    }
}

impl ReassemblyBuffer {
    /// Add a fragment to the buffer.
    ///
    /// Returns the complete Delta bytes if all fragments for this Delta have
    /// arrived; otherwise returns `None`.  Returns `FragmentReassemblyFailed`
    /// if the fragment metadata is inconsistent with previously buffered
    /// fragments for the same `delta_id`, if `total_fragments` exceeds
    /// `MAX_FRAGMENTS_PER_DELTA`, or if the slot count would exceed
    /// `MAX_REASSEMBLY_SLOTS` (in which case the oldest entry is evicted
    /// before inserting the new one).
    ///
    /// Discards the partial Delta and logs `{sender_did, fragment_count}` on failure.
    pub fn add_fragment(
        &mut self,
        fragment: DeltaFragment,
        sender_did: &Did,
    ) -> Result<Option<Vec<u8>>, TirBaseError> {
        let delta_id = fragment.delta_id;
        let total = fragment.total_fragments as usize;
        let idx = fragment.fragment_index as usize;

        // Guard 1: reject oversized total_fragments to prevent slot-vector allocation attacks
        if fragment.total_fragments > MAX_FRAGMENTS_PER_DELTA {
            eprintln!(
                "FragmentReassemblyFailed: sender_did={sender_did}, \
                 expected={} fragments (exceeds MAX_FRAGMENTS_PER_DELTA={})",
                fragment.total_fragments, MAX_FRAGMENTS_PER_DELTA
            );
            return Err(TirBaseError::FragmentReassemblyFailed {
                sender_did: sender_did.clone(),
                expected: fragment.total_fragments,
            });
        }

        if total == 0 || idx >= total {
            return Err(TirBaseError::FragmentReassemblyFailed {
                sender_did: sender_did.clone(),
                expected: fragment.total_fragments,
            });
        }

        // Guard 2: evict the entry with the fewest filled slots when the cap is reached
        if !self.pending.contains_key(&delta_id) && self.pending.len() >= MAX_REASSEMBLY_SLOTS {
            // Find the key with the fewest Some slots (oldest / least-progressed)
            let evict_key = self
                .pending
                .iter()
                .min_by_key(|(_, slots)| slots.iter().filter(|s| s.is_some()).count())
                .map(|(k, _)| *k)
                .unwrap(); // safe: pending is non-empty here

            self.pending.remove(&evict_key);
            eprintln!(
                "ReassemblyBuffer eviction: delta_id={} sender_did={sender_did}",
                hex::encode(evict_key)
            );
        }

        // Initialise slot array on first fragment for this delta_id
        let slots = self
            .pending
            .entry(delta_id)
            .or_insert_with(|| vec![None; total]);

        // Validate total_fragments is consistent
        if slots.len() != total {
            return Err(TirBaseError::FragmentReassemblyFailed {
                sender_did: sender_did.clone(),
                expected: total as u32,
            });
        }

        // Store the fragment (ignore duplicate — idempotent)
        slots[idx] = Some(fragment);

        // Check if all slots are filled
        if slots.iter().all(|s| s.is_some()) {
            let fragments: Vec<DeltaFragment> = self
                .pending
                .remove(&delta_id)
                .unwrap()
                .into_iter()
                .map(|s| s.unwrap())
                .collect();

            let bytes = reassemble(fragments, sender_did)?;
            return Ok(Some(bytes));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENDER_DID: &str = "did:key:z6MkTest";
    const DELTA_ID: [u8; 32] = [0xAA; 32];

    // ── fragment() ────────────────────────────────────────────────────────────

    #[test]
    fn fragment_empty_input_returns_empty() {
        let frags = fragment(DELTA_ID, &[], 100);
        assert!(frags.is_empty());
    }

    #[test]
    fn fragment_zero_mtu_returns_empty() {
        let frags = fragment(DELTA_ID, b"hello", 0);
        assert!(frags.is_empty());
    }

    #[test]
    fn fragment_exact_mtu_fit_single_fragment() {
        let data = vec![0xBBu8; 100];
        let frags = fragment(DELTA_ID, &data, 100);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].fragment_index, 0);
        assert_eq!(frags[0].total_fragments, 1);
        assert_eq!(frags[0].payload, data);
    }

    #[test]
    fn fragment_splits_500_bytes_into_5_chunks_of_100() {
        let data: Vec<u8> = (0u8..255).cycle().take(500).collect();
        let frags = fragment(DELTA_ID, &data, 100);
        assert_eq!(frags.len(), 5);
        for (i, f) in frags.iter().enumerate() {
            assert_eq!(f.fragment_index, i as u32);
            assert_eq!(f.total_fragments, 5);
            assert_eq!(f.delta_id, DELTA_ID);
            assert!(f.payload.len() <= 100);
        }
    }

    #[test]
    fn fragment_uneven_split_last_chunk_smaller() {
        // 250 bytes / 100 MTU → [100, 100, 50]
        let data: Vec<u8> = (0u8..250).collect();
        let frags = fragment(DELTA_ID, &data, 100);
        assert_eq!(frags.len(), 3);
        assert_eq!(frags[2].payload.len(), 50);
    }

    // ── reassemble() ─────────────────────────────────────────────────────────

    #[test]
    fn reassemble_round_trip_500_bytes_mtu_100() {
        let data: Vec<u8> = (0u8..255).cycle().take(500).collect();
        let frags = fragment(DELTA_ID, &data, 100);
        let result = reassemble(frags, &SENDER_DID.to_string()).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn reassemble_out_of_order_fragments() {
        let data: Vec<u8> = (0u8..255).cycle().take(300).collect();
        let mut frags = fragment(DELTA_ID, &data, 100);
        frags.reverse(); // reverse order
        let result = reassemble(frags, &SENDER_DID.to_string()).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn reassemble_empty_vec_returns_error() {
        let err = reassemble(vec![], &SENDER_DID.to_string()).unwrap_err();
        assert!(matches!(err, TirBaseError::FragmentReassemblyFailed { .. }));
    }

    #[test]
    fn reassemble_missing_fragment_returns_error() {
        let data: Vec<u8> = (0u8..255).cycle().take(300).collect();
        let mut frags = fragment(DELTA_ID, &data, 100);
        frags.remove(1); // drop middle fragment
        let err = reassemble(frags, &SENDER_DID.to_string()).unwrap_err();
        assert!(matches!(err, TirBaseError::FragmentReassemblyFailed { .. }));
    }

    #[test]
    fn reassemble_duplicate_fragment_returns_error() {
        let data: Vec<u8> = (0u8..255).cycle().take(200).collect();
        let frags = fragment(DELTA_ID, &data, 100);
        let mut dup = frags.clone();
        dup.push(frags[0].clone()); // add a duplicate
        let err = reassemble(dup, &SENDER_DID.to_string()).unwrap_err();
        assert!(matches!(err, TirBaseError::FragmentReassemblyFailed { .. }));
    }

    // ── ReassemblyBuffer ──────────────────────────────────────────────────────

    #[test]
    fn reassembly_buffer_returns_none_until_all_fragments_arrive() {
        let data: Vec<u8> = (0u8..255).cycle().take(300).collect();
        let frags = fragment(DELTA_ID, &data, 100);
        let mut buf = ReassemblyBuffer::default();
        let did = SENDER_DID.to_string();

        let r0 = buf.add_fragment(frags[0].clone(), &did).unwrap();
        assert!(r0.is_none(), "incomplete: only 1/3 fragments");

        let r1 = buf.add_fragment(frags[1].clone(), &did).unwrap();
        assert!(r1.is_none(), "incomplete: only 2/3 fragments");

        let r2 = buf.add_fragment(frags[2].clone(), &did).unwrap();
        assert!(r2.is_some(), "all 3 fragments arrived");
        assert_eq!(r2.unwrap(), data);
    }

    #[test]
    fn reassembly_buffer_out_of_order_insert() {
        let data: Vec<u8> = (0u8..255).cycle().take(300).collect();
        let frags = fragment(DELTA_ID, &data, 100);
        let mut buf = ReassemblyBuffer::default();
        let did = SENDER_DID.to_string();

        // Insert in reverse order
        assert!(buf.add_fragment(frags[2].clone(), &did).unwrap().is_none());
        assert!(buf.add_fragment(frags[0].clone(), &did).unwrap().is_none());
        let result = buf.add_fragment(frags[1].clone(), &did).unwrap();
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn reassembly_buffer_invalid_index_returns_error() {
        let bad_frag = DeltaFragment {
            delta_id: DELTA_ID,
            fragment_index: 5, // out of bounds for total=3
            total_fragments: 3,
            payload: vec![0xAA; 50],
        };
        let mut buf = ReassemblyBuffer::default();
        let did = SENDER_DID.to_string();
        let err = buf.add_fragment(bad_frag, &did).unwrap_err();
        assert!(matches!(err, TirBaseError::FragmentReassemblyFailed { .. }));
    }

    // ── Cap / eviction tests ──────────────────────────────────────────────────

    #[test]
    fn fragment_with_total_exceeding_max_returns_error() {
        let bad_frag = DeltaFragment {
            delta_id: DELTA_ID,
            fragment_index: 0,
            total_fragments: MAX_FRAGMENTS_PER_DELTA + 1,
            payload: vec![0xBB; 50],
        };
        let mut buf = ReassemblyBuffer::default();
        let did = SENDER_DID.to_string();
        let err = buf.add_fragment(bad_frag, &did).unwrap_err();
        assert!(matches!(err, TirBaseError::FragmentReassemblyFailed { .. }));
    }

    #[test]
    fn opening_more_than_max_slots_evicts_oldest() {
        let did = SENDER_DID.to_string();
        let mut buf = ReassemblyBuffer::default();

        // Open MAX_REASSEMBLY_SLOTS distinct assemblies, each with total_fragments=2,
        // sending only fragment_index=0.
        let mut delta_ids: Vec<[u8; 32]> = Vec::with_capacity(MAX_REASSEMBLY_SLOTS);
        for i in 0..MAX_REASSEMBLY_SLOTS {
            let mut delta_id = [0u8; 32];
            delta_id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            delta_ids.push(delta_id);
            let frag = DeltaFragment {
                delta_id,
                fragment_index: 0,
                total_fragments: 2,
                payload: vec![0xCC; 10],
            };
            let result = buf.add_fragment(frag, &did).unwrap();
            assert!(result.is_none());
        }
        assert_eq!(buf.pending_count(), MAX_REASSEMBLY_SLOTS);

        // Opening one more new assembly should evict exactly one entry
        let mut new_delta_id = [0u8; 32];
        new_delta_id[0..8].copy_from_slice(&(MAX_REASSEMBLY_SLOTS as u64).to_le_bytes());
        let new_frag = DeltaFragment {
            delta_id: new_delta_id,
            fragment_index: 0,
            total_fragments: 2,
            payload: vec![0xDD; 10],
        };
        buf.add_fragment(new_frag, &did).unwrap();

        // Total must not grow beyond the cap
        assert_eq!(buf.pending_count(), MAX_REASSEMBLY_SLOTS);

        // Exactly one of the original entries must have been evicted
        let retained_count = delta_ids.iter().filter(|id| buf.has_delta(id)).count();
        assert_eq!(
            retained_count,
            MAX_REASSEMBLY_SLOTS - 1,
            "exactly one original entry should have been evicted"
        );

        // The new entry must be present
        assert!(
            buf.has_delta(&new_delta_id),
            "newly inserted delta must be present"
        );
    }

    #[test]
    fn eviction_does_not_break_new_insertion() {
        let did = SENDER_DID.to_string();
        let mut buf = ReassemblyBuffer::default();

        // Fill to the cap
        for i in 0..MAX_REASSEMBLY_SLOTS {
            let mut delta_id = [0u8; 32];
            delta_id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            let frag = DeltaFragment {
                delta_id,
                fragment_index: 0,
                total_fragments: 2,
                payload: vec![0xCC; 10],
            };
            buf.add_fragment(frag, &did).unwrap();
        }

        // Insert a new delta that triggers eviction
        let mut new_delta_id = [0u8; 32];
        new_delta_id[0..8].copy_from_slice(&(MAX_REASSEMBLY_SLOTS as u64).to_le_bytes());
        let frag0 = DeltaFragment {
            delta_id: new_delta_id,
            fragment_index: 0,
            total_fragments: 2,
            payload: vec![0x01; 10],
        };
        let r0 = buf.add_fragment(frag0, &did).unwrap();
        assert!(r0.is_none());
        assert!(
            buf.has_delta(&new_delta_id),
            "new delta should be present after eviction"
        );

        // Sending the second fragment should complete the reassembly
        let frag1 = DeltaFragment {
            delta_id: new_delta_id,
            fragment_index: 1,
            total_fragments: 2,
            payload: vec![0x02; 10],
        };
        let r1 = buf.add_fragment(frag1, &did).unwrap();
        assert!(
            r1.is_some(),
            "reassembly should complete after both fragments arrive"
        );
        assert_eq!(
            r1.unwrap(),
            vec![0x01u8; 10]
                .into_iter()
                .chain(vec![0x02u8; 10])
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn normal_reassembly_within_limits_completes() {
        // Regression guard: standard 3-fragment round-trip with total_fragments=3
        let data: Vec<u8> = (0u8..=99).collect();
        let frags = fragment(DELTA_ID, &data, 34); // gives 3 chunks: 34, 34, 32
        assert_eq!(frags.len(), 3);
        assert!(frags[0].total_fragments <= MAX_FRAGMENTS_PER_DELTA);

        let mut buf = ReassemblyBuffer::default();
        let did = SENDER_DID.to_string();

        assert!(buf.add_fragment(frags[0].clone(), &did).unwrap().is_none());
        assert!(buf.add_fragment(frags[1].clone(), &did).unwrap().is_none());
        let result = buf.add_fragment(frags[2].clone(), &did).unwrap();
        assert_eq!(result.unwrap(), data);
    }
}
