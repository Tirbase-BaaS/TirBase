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
///
/// If `delta_bytes` is empty or `mtu` is 0, returns an empty fragment list.
/// Each fragment carries the `delta_id`, its zero-based index, and the total
/// fragment count — sufficient for the receiver to reassemble in any order.
pub fn fragment(
    delta_id: [u8; 32],
    delta_bytes: &[u8],
    mtu: usize,
) -> Vec<DeltaFragment> {
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

/// Partial reassembly buffer held until all fragments arrive.
#[derive(Debug, Default)]
pub struct ReassemblyBuffer {
    /// Keyed by delta_id.  Each entry is a slot array sized to total_fragments.
    pending: std::collections::HashMap<[u8; 32], Vec<Option<DeltaFragment>>>,
}

impl ReassemblyBuffer {
    /// Add a fragment to the buffer.
    ///
    /// Returns the complete Delta bytes if all fragments for this Delta have
    /// arrived; otherwise returns `None`.  Returns `FragmentReassemblyFailed`
    /// if the fragment metadata is inconsistent with previously buffered
    /// fragments for the same `delta_id`.
    pub fn add_fragment(
        &mut self,
        fragment: DeltaFragment,
        sender_did: &Did,
    ) -> Result<Option<Vec<u8>>, TirBaseError> {
        let delta_id = fragment.delta_id;
        let total = fragment.total_fragments as usize;
        let idx = fragment.fragment_index as usize;

        if total == 0 || idx >= total {
            return Err(TirBaseError::FragmentReassemblyFailed {
                sender_did: sender_did.clone(),
                expected: fragment.total_fragments,
            });
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
        let mut bad_frag = DeltaFragment {
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
}
