//! Bounded pending queue for inbound deltas with unresolved causal dependencies
//! (PV-6.1, CLAIM-23.1, CLAIM-23.2, S33).
//!
//! When `start_op` validation cannot resolve a delta's causal dependencies, the
//! delta is held here until the missing dependency arrives (processed via the
//! Automerge sync/merge path) or the entry ages out. The queue is bounded by:
//! - global byte cap (default 64 MiB)
//! - per-peer byte cap (default 8 MiB, keyed by sender DID)
//! - age-out (default 24h, configurable up to 7 days)
//!
//! On overflow, the oldest entries (by `received_at_mono`) are evicted and
//! quarantined as `PendingQueueOverflow`. Overflow quarantine is replayable and
//! requires a PolicyAuthority signature (PV-6.1).

use std::collections::BTreeMap;

use crate::crdt::delta::{Delta, DeltaId, Did};
use crate::events::ReasonCode;

/// Default age-out: 24 hours in microseconds.
pub const DEFAULT_PENDING_AGE_OUT_MICROS: u64 = 24 * 60 * 60 * 1_000_000;
/// Maximum configurable age-out: 7 days in microseconds.
pub const MAX_PENDING_AGE_OUT_MICROS: u64 = 7 * 24 * 60 * 60 * 1_000_000;
/// Default global pending-queue byte cap: 64 MiB.
pub const DEFAULT_PENDING_GLOBAL_BYTES: usize = 64 * 1024 * 1024;
/// Default per-peer pending-queue byte cap: 8 MiB.
pub const DEFAULT_PENDING_PER_PEER_BYTES: usize = 8 * 1024 * 1024;

/// A queued inbound delta awaiting missing causal dependencies.
#[derive(Debug, Clone)]
pub struct PendingEntry {
    pub delta: Delta,
    pub received_at_mono: u64,
    pub sender_did: Did,
    pub approx_bytes: usize,
}

/// Overflow/age-out eviction result requiring quarantine (replayable).
#[derive(Debug, Clone)]
pub struct PendingEviction {
    pub delta: Delta,
    pub sender_did: Did,
    pub received_at_mono: u64,
    pub reason: ReasonCode,
    pub detail: String,
}

/// Bounded pending queue keyed by `DeltaId`.
///
/// Insertion order for eviction is tracked by `received_at_mono`; ties are
/// broken by `DeltaId` for deterministic behavior.
#[derive(Debug)]
pub struct PendingQueue {
    entries: BTreeMap<DeltaId, PendingEntry>,
    by_peer_bytes: BTreeMap<Did, usize>,
    total_bytes: usize,
    age_out_micros: u64,
    global_cap_bytes: usize,
    per_peer_cap_bytes: usize,
}

impl Default for PendingQueue {
    fn default() -> Self {
        Self::new(
            DEFAULT_PENDING_AGE_OUT_MICROS,
            DEFAULT_PENDING_GLOBAL_BYTES,
            DEFAULT_PENDING_PER_PEER_BYTES,
        )
    }
}

impl PendingQueue {
    pub fn new(age_out_micros: u64, global_cap_bytes: usize, per_peer_cap_bytes: usize) -> Self {
        let age_out_micros = age_out_micros.clamp(1, MAX_PENDING_AGE_OUT_MICROS);
        Self {
            entries: BTreeMap::new(),
            by_peer_bytes: BTreeMap::new(),
            total_bytes: 0,
            age_out_micros,
            global_cap_bytes,
            per_peer_cap_bytes,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn peer_bytes(&self, did: &str) -> usize {
        self.by_peer_bytes.get(did).copied().unwrap_or(0)
    }

    pub fn age_out_micros(&self) -> u64 {
        self.age_out_micros
    }

    pub fn contains(&self, id: &DeltaId) -> bool {
        self.entries.contains_key(id)
    }

 /// Approximate serialized size for cap accounting.
    pub fn approx_delta_bytes(delta: &Delta) -> usize {
 // automerge_bytes dominate; fixed overhead covers metadata/hash/ids.
        delta
            .automerge_bytes
            .len()
            .saturating_add(delta.author_did.len())
            .saturating_add(256)
    }

 /// Insert a delta with missing dependencies. Returns evictions that must be
 /// quarantined as `PENDING_QUEUE_OVERFLOW` (replayable, PV-6.1).
 ///
 /// The newly inserted entry is never evicted by the same insertion unless it
 /// alone exceeds the global cap (in which case it is accepted only if within
 /// global cap; callers should size-check before enqueueing pathological data).
    pub fn enqueue(
        &mut self,
        delta: Delta,
        received_at_mono: u64,
        sender_did: Did,
    ) -> Vec<PendingEviction> {
        let mut evictions = self.evict_timed_out(received_at_mono);

        let approx_bytes = Self::approx_delta_bytes(&delta);
        let id = delta.id;
        if self.entries.contains_key(&id) {
            return evictions;
        }

 // Ensure per-peer cap by evicting this peer's oldest entries first.
        let peer_before = self.peer_bytes(&sender_did);
        let mut peer_after = peer_before.saturating_add(approx_bytes);
        while peer_after > self.per_peer_cap_bytes {
            if let Some(ev) = self.evict_oldest_from_peer(&sender_did, "per-peer byte cap exceeded")
            {
                peer_after = peer_after.saturating_sub(Self::approx_delta_bytes(&ev.delta));
                evictions.push(ev);
            } else {
                break;
            }
        }

 // Ensure global cap by evicting globally oldest entries.
        let mut total_after = self.total_bytes.saturating_add(approx_bytes);
        while total_after > self.global_cap_bytes {
            if let Some(ev) = self.evict_oldest_global("global byte cap exceeded") {
                total_after = total_after.saturating_sub(Self::approx_delta_bytes(&ev.delta));
                evictions.push(ev);
            } else {
                break;
            }
        }

 // If a single entry is larger than global cap, reject via overflow
 // quarantine rather than retaining an over-cap entry.
        if approx_bytes > self.global_cap_bytes {
            evictions.push(PendingEviction {
                delta,
                sender_did,
                received_at_mono,
                reason: ReasonCode::PendingQueueOverflow,
                detail: format!(
                    "single pending delta exceeds global cap ({} > {})",
                    approx_bytes, self.global_cap_bytes
                ),
            });
            return evictions;
        }

        self.entries.insert(
            id,
            PendingEntry {
                delta,
                received_at_mono,
                sender_did: sender_did.clone(),
                approx_bytes,
            },
        );
        self.total_bytes = self.total_bytes.saturating_add(approx_bytes);
        *self.by_peer_bytes.entry(sender_did).or_insert(0) += approx_bytes;
        evictions
    }

    fn oldest_key(&self) -> Option<DeltaId> {
        self.entries
            .iter()
            .min_by(|(ida, a), (idb, b)| {
                a.received_at_mono
                    .cmp(&b.received_at_mono)
                    .then_with(|| ida.cmp(idb))
            })
            .map(|(id, _)| *id)
    }

    fn oldest_key_for_peer(&self, did: &str) -> Option<DeltaId> {
        self.entries
            .iter()
            .filter(|(_, e)| e.sender_did == did)
            .min_by(|(ida, a), (idb, b)| {
                a.received_at_mono
                    .cmp(&b.received_at_mono)
                    .then_with(|| ida.cmp(idb))
            })
            .map(|(id, _)| *id)
    }

    fn remove(&mut self, id: &DeltaId) -> Option<PendingEntry> {
        let entry = self.entries.remove(id)?;
        self.total_bytes = self.total_bytes.saturating_sub(entry.approx_bytes);
        if let Some(b) = self.by_peer_bytes.get_mut(&entry.sender_did) {
            *b = b.saturating_sub(entry.approx_bytes);
            if *b == 0 {
                self.by_peer_bytes.remove(&entry.sender_did);
            }
        }
        Some(entry)
    }

    fn evict_oldest_from_peer(&mut self, did: &str, detail: &str) -> Option<PendingEviction> {
        let id = self.oldest_key_for_peer(did)?;
        let entry = self.remove(&id)?;
        Some(PendingEviction {
            delta: entry.delta,
            sender_did: entry.sender_did,
            received_at_mono: entry.received_at_mono,
            reason: ReasonCode::PendingQueueOverflow,
            detail: detail.to_string(),
        })
    }

    fn evict_oldest_global(&mut self, detail: &str) -> Option<PendingEviction> {
        let id = self.oldest_key()?;
        let entry = self.remove(&id)?;
        Some(PendingEviction {
            delta: entry.delta,
            sender_did: entry.sender_did,
            received_at_mono: entry.received_at_mono,
            reason: ReasonCode::PendingQueueOverflow,
            detail: detail.to_string(),
        })
    }

 /// Evict entries older than `now_mono - age_out_micros`. Returns evictions
 /// that must be quarantined as `MISSING_DEPENDENCY_TIMEOUT` (replayable).
    pub fn evict_timed_out(&mut self, now_mono: u64) -> Vec<PendingEviction> {
        let cutoff = now_mono.saturating_sub(self.age_out_micros);
        let expired: Vec<DeltaId> = self
            .entries
            .iter()
            .filter(|(_, e)| e.received_at_mono < cutoff)
            .map(|(id, _)| *id)
            .collect();
        let mut ev = Vec::with_capacity(expired.len());
        for id in expired {
            if let Some(entry) = self.remove(&id) {
                ev.push(PendingEviction {
                    delta: entry.delta,
                    sender_did: entry.sender_did,
                    received_at_mono: entry.received_at_mono,
                    reason: ReasonCode::MissingDependencyTimeout,
                    detail: format!(
                        "missing dependency timed out (age_out_micros={})",
                        self.age_out_micros
                    ),
                });
            }
        }
        ev
    }

 /// Drain all pending entries in deterministic `received_at_mono`, then
 /// `DeltaId` order so dependency arrival can retry them through the merge
 /// path (PV-6.1). Callers are responsible for re-enqueueing entries that
 /// still have missing dependencies.
    pub fn drain_all_ordered(&mut self) -> Vec<PendingEntry> {
        let mut items: Vec<(DeltaId, PendingEntry)> = self
            .entries
            .iter()
            .map(|(id, e)| (*id, e.clone()))
            .collect();
        items.sort_by(|(ida, a), (idb, b)| {
            a.received_at_mono
                .cmp(&b.received_at_mono)
                .then_with(|| ida.cmp(idb))
        });
        let ids: Vec<DeltaId> = items.iter().map(|(id, _)| *id).collect();
        for id in ids {
            let _ = self.remove(&id);
        }
        items.into_iter().map(|(_, e)| e).collect()
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::crdt::delta::{Delta, Ed25519Signature, PriorityClass};

    fn mk_delta(id_byte: u8, payload_len: usize, author: &str) -> Delta {
        let mut id = [0u8; 32];
        id[0] = id_byte;
        Delta {
            id,
            author_did: author.to_string(),
            signature: Ed25519Signature::default(),
            schema_hash: [0u8; 32],
            automerge_bytes: vec![0xAB; payload_len],
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport: 1,
            created_at: 0,
        }
    }

    #[test]
    fn per_peer_cap_evicts_oldest_for_that_peer_only() {
        let mut q = PendingQueue::new(DEFAULT_PENDING_AGE_OUT_MICROS, 1024 * 1024, 1200);
        let d1 = mk_delta(1, 400, "did:key:a");
        let d2 = mk_delta(2, 400, "did:key:a");
        let d3 = mk_delta(3, 100, "did:key:b");
        assert!(q.enqueue(d1, 10, "did:key:a".into()).is_empty());
        assert!(q.enqueue(d3, 11, "did:key:b".into()).is_empty());
        let ev = q.enqueue(d2, 12, "did:key:a".into());
        assert!(!ev.is_empty(), "per-peer overflow must evict");
        assert!(ev.iter().all(|e| e.sender_did == "did:key:a"));
        assert!(ev
            .iter()
            .all(|e| e.reason == ReasonCode::PendingQueueOverflow));
        assert!(q.contains(&[3u8; 32]) || q.entries.values().any(|e| e.sender_did == "did:key:b"));
    }

    #[test]
    fn global_cap_evicts_globally_oldest() {
 // approx_delta_bytes: 300 + author.len() + automerge_bytes.len(); author "did:key:a" = 9.
        let mut q = PendingQueue::new(DEFAULT_PENDING_AGE_OUT_MICROS, 2000, 10000);
        let d1 = mk_delta(1, 600, "did:key:a"); // 909
        let d2 = mk_delta(2, 600, "did:key:b"); // 909
        let d3 = mk_delta(3, 700, "did:key:a"); // 1009
        assert!(q.enqueue(d1, 1, "did:key:a".into()).is_empty());
        assert!(q.enqueue(d2, 2, "did:key:b".into()).is_empty()); // total 1818
        let ev = q.enqueue(d3, 3, "did:key:a".into()); // would be 2827 -> evict oldest
        assert!(!ev.is_empty(), "global overflow must evict");
        assert!(
            ev.iter().any(|e| e.delta.id[0] == 1),
            "oldest evicted first: {:?}",
            ev.iter().map(|e| e.delta.id[0]).collect::<Vec<_>>()
        );
        assert_eq!(ev[0].reason, ReasonCode::PendingQueueOverflow);
    }

    #[test]
    fn age_out_produces_missing_dependency_timeout() {
        let mut q = PendingQueue::new(100, 1024 * 1024, 1024 * 1024);
        let d1 = mk_delta(1, 10, "did:key:a");
        assert!(q.enqueue(d1, 10, "did:key:a".into()).is_empty());
        let ev = q.evict_timed_out(200);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].reason, ReasonCode::MissingDependencyTimeout);
        assert!(q.is_empty());
    }
}
