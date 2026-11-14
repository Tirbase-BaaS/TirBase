// SPDX-License-Identifier: AGPL-3.0-only

//! Memory budgets with eviction metrics (PV-6.5).
//!
//! DAG node cache 32 MiB, ICO index 8 MiB, reassembly buffers 16 MiB.
//! Each cache exposes current_bytes, eviction_count, hit_count, miss_count.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub const DAG_NODE_CACHE_BYTES: usize = 32 * 1024 * 1024;
pub const ICO_INDEX_BYTES: usize = 8 * 1024 * 1024;
pub const REASSEMBLY_BUFFERS_BYTES: usize = 16 * 1024 * 1024;
pub const PENDING_QUEUE_GLOBAL_BYTES: usize = 64 * 1024 * 1024; // as per 

/// Cap for the in-memory rate-quarantine counters ().
///
/// These are per-sender counters (`sender_did -> window state`), not payload
/// buffers, so the cap is small: 1 MiB covers far more senders than
/// `rate_quarantine::RATE_QUARANTINE_GLOBAL_ENTRIES` allows.
pub const RATE_QUARANTINE_MEMORY_BYTES: usize = 1024 * 1024;

/// Documented process RSS budget baseline (MiB) for a gateway process with all
/// configured caches loaded. will replace this provisional number
/// with a measured value; until then it is the budget the memory gate asserts
/// against and the denominator for the 90% ledger rule.
pub const RSS_BUDGET_BYTES: usize = 256 * 1024 * 1024;

/// Sum of every configured cache/buffer cap tracked in the memory ledger.
pub fn total_configured_caps_bytes() -> usize {
    DAG_NODE_CACHE_BYTES
        + ICO_INDEX_BYTES
        + REASSEMBLY_BUFFERS_BYTES
        + PENDING_QUEUE_GLOBAL_BYTES
        + RATE_QUARANTINE_MEMORY_BYTES
}

#[derive(Debug, Default)]
pub struct CacheMetrics {
    current_bytes: AtomicU64,
    eviction_count: AtomicU64,
    hit_count: AtomicU64,
    miss_count: AtomicU64,
}

#[derive(Clone, Debug)]
pub struct CacheMetricsHandle {
    inner: Arc<CacheMetrics>,
}

impl Default for CacheMetricsHandle {
    fn default() -> Self {
        Self {
            inner: Arc::new(CacheMetrics::default()),
        }
    }
}

impl CacheMetricsHandle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn current_bytes(&self) -> u64 {
        self.inner.current_bytes.load(Ordering::Relaxed)
    }

    pub fn eviction_count(&self) -> u64 {
        self.inner.eviction_count.load(Ordering::Relaxed)
    }

    pub fn hit_count(&self) -> u64 {
        self.inner.hit_count.load(Ordering::Relaxed)
    }

    pub fn miss_count(&self) -> u64 {
        self.inner.miss_count.load(Ordering::Relaxed)
    }

    pub fn record_hit(&self) {
        self.inner.hit_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_miss(&self) {
        self.inner.miss_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_eviction(&self, bytes: u64) {
        self.inner.eviction_count.fetch_add(1, Ordering::Relaxed);
        self.inner.current_bytes.fetch_sub(bytes, Ordering::Relaxed);
    }

    pub fn allocate(&self, bytes: u64) {
        self.inner.current_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn free(&self, bytes: u64) {
        self.inner.current_bytes.fetch_sub(bytes, Ordering::Relaxed);
    }
}

#[derive(Clone, Debug)]
pub struct MemoryBudgetCaches {
    pub dag_node_cache: CacheMetricsHandle,
    pub ico_index: CacheMetricsHandle,
    pub reassembly_buffers: CacheMetricsHandle,
}

impl Default for MemoryBudgetCaches {
    fn default() -> Self {
        Self {
            dag_node_cache: CacheMetricsHandle::new(),
            ico_index: CacheMetricsHandle::new(),
            reassembly_buffers: CacheMetricsHandle::new(),
        }
    }
}

impl MemoryBudgetCaches {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    #[test]
    fn cache_has_required_metrics() {
        let c = CacheMetricsHandle::new();
        c.allocate(100);
        assert_eq!(c.current_bytes(), 100);
        c.record_hit();
        c.record_miss();
        assert_eq!(c.hit_count(), 1);
        assert_eq!(c.miss_count(), 1);
        c.record_eviction(50);
        assert_eq!(c.eviction_count(), 1);
    }
}

#[cfg(all(test, feature = "native"))]
mod memory_budget_tests {
    use super::*;

    #[test]
    fn claim_24_2_caches_expose_metrics() {
        let caches = MemoryBudgetCaches::new();
        caches.dag_node_cache.allocate(1024);
        let _ = caches.dag_node_cache.current_bytes();
        caches.dag_node_cache.record_hit();
        caches.dag_node_cache.record_miss();
        assert_eq!(caches.dag_node_cache.hit_count(), 1);
        assert_eq!(caches.dag_node_cache.miss_count(), 1);
        caches.dag_node_cache.record_eviction(512);
        assert_eq!(caches.dag_node_cache.eviction_count(), 1);
        let _ = caches.ico_index.current_bytes();
        let _ = caches.ico_index.eviction_count();
        let _ = caches.ico_index.hit_count();
        let _ = caches.ico_index.miss_count();
        let _ = caches.reassembly_buffers.current_bytes();
        let _ = caches.reassembly_buffers.eviction_count();
        let _ = caches.reassembly_buffers.hit_count();
        let _ = caches.reassembly_buffers.miss_count();
    }
}
