// SPDX-License-Identifier: AGPL-3.0-only

//! Real memory-budget gate for (PV-6.5).
//!
//! The CI job `memory-budget-check` runs this ignored test. Unlike a static
//! arithmetic check, it *loads* every configured cache up to its documented cap
//! and measures the process's peak resident set size, so the gate fails if the
//! ledger in `docs/memory-budget.md` stops describing what the process actually
//! allocates or if the budget is exceeded.
//!
//! Run manually with:
//! ```text
//! cargo test -p tirbase-core --test memory_budget_gate -- --ignored --nocapture
//! ```

use tirbase_core::crdt::memory_budget::{
    total_configured_caps_bytes, MemoryBudgetCaches, DAG_NODE_CACHE_BYTES, ICO_INDEX_BYTES,
    PENDING_QUEUE_GLOBAL_BYTES, RATE_QUARANTINE_MEMORY_BYTES, REASSEMBLY_BUFFERS_BYTES,
    RSS_BUDGET_BYTES,
};

/// Peak resident set size of this process, in bytes.
#[cfg(unix)]
fn peak_rss_bytes() -> u64 {
 // SAFETY: `getrusage` writes into a zeroed `rusage` for a valid resource.
    let usage = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        assert_eq!(libc::getrusage(libc::RUSAGE_SELF, &mut usage), 0);
        usage
    };
    let raw = usage.ru_maxrss as u64;
    if cfg!(target_os = "macos") {
 // macOS reports bytes.
        raw
    } else {
 // Linux/BSD report KiB.
        raw * 1024
    }
}

#[cfg(not(unix))]
fn peak_rss_bytes() -> u64 {
 // No portable peak-RSS API; the CI gate runs on Linux.
    0
}

/// Allocate `bytes` and touch every page so it is resident (not just reserved).
fn allocate_touched(bytes: usize) -> Vec<u8> {
    assert!(bytes > 0);
    let mut buf = vec![0u8; bytes];
    for offset in (0..bytes).step_by(4096) {
        buf[offset] = 0xA5;
    }
    buf[bytes - 1] = 0x5A;
    buf
}

#[test]
#[ignore = "memory measurement gate; run explicitly (CI job memory-budget-check)"]
fn configured_caps_load_and_peak_rss_stays_under_budget() {
 // 1. The ledger is internally consistent: every configured cap, summed,
 // must leave 10% headroom inside the documented RSS budget.
    let total = total_configured_caps_bytes();
    assert!(
        total <= RSS_BUDGET_BYTES * 9 / 10,
        "configured caps ({total} bytes) exceed 90% of the {RSS_BUDGET_BYTES}-byte RSS budget"
    );

    let baseline = peak_rss_bytes();

 // 2. Actually load every configured cache/buffer and record it through the
 // production metrics handles (`CoreHandle::memory_budget_metrics`).
    let caches = MemoryBudgetCaches::new();
    let dag = allocate_touched(DAG_NODE_CACHE_BYTES);
    caches.dag_node_cache.allocate(DAG_NODE_CACHE_BYTES as u64);

    let ico = allocate_touched(ICO_INDEX_BYTES);
    caches.ico_index.allocate(ICO_INDEX_BYTES as u64);

    let reassembly = allocate_touched(REASSEMBLY_BUFFERS_BYTES);
    caches
        .reassembly_buffers
        .allocate(REASSEMBLY_BUFFERS_BYTES as u64);

    let pending = allocate_touched(PENDING_QUEUE_GLOBAL_BYTES);
    let rate = allocate_touched(RATE_QUARANTINE_MEMORY_BYTES);

    let peak = peak_rss_bytes();

    println!(
        "memory budget gate: total_caps={} MiB, budget={} MiB, baseline_peak_rss={} MiB, measured_peak_rss={} MiB",
        total / (1024 * 1024),
        RSS_BUDGET_BYTES / (1024 * 1024),
        baseline / (1024 * 1024),
        peak / (1024 * 1024),
    );

 // 3. The measurement must be real: loading the caps has to move peak RSS.
    #[cfg(unix)]
    assert!(
        peak > baseline,
        "peak RSS did not grow after allocating {} MiB of caches",
        total / (1024 * 1024)
    );

 // 4. The documented budget is the gate.
    assert!(
        peak <= RSS_BUDGET_BYTES as u64,
        "peak RSS {peak} bytes exceeds the documented {RSS_BUDGET_BYTES}-byte budget"
    );

 // Metrics report exactly what was loaded.
    assert_eq!(
        caches.dag_node_cache.current_bytes(),
        DAG_NODE_CACHE_BYTES as u64
    );
    assert_eq!(caches.ico_index.current_bytes(), ICO_INDEX_BYTES as u64);
    assert_eq!(
        caches.reassembly_buffers.current_bytes(),
        REASSEMBLY_BUFFERS_BYTES as u64
    );

    drop((dag, ico, reassembly, pending, rate));
}
