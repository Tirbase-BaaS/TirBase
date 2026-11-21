// SPDX-License-Identifier: AGPL-3.0-only

//! F-07 storage budgets for gateway flash and long-lived ledgers.
//!
//! Flash wear itself is covered by [`crate::flash_budget`] (block-layer writes
//! per day). This module bounds *occupancy*: primary/derived databases and the
//! signed archive directory. A deployment sets a soft budget; exceeding it is
//! reported with the retention classes that can free space, so an operator (or
//! the retention job) can act before SQLite returns `SQLITE_FULL`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageBudget {
    /// Bytes allowed for primary.db plus derived.db.
    pub ledgers_bytes: u64,
    /// Bytes allowed for the signed archive directory.
    pub archive_bytes: u64,
}

impl Default for StorageBudget {
    fn default() -> Self {
        Self {
            ledgers_bytes: 8 * 1024 * 1024 * 1024,
            archive_bytes: 32 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageUsage {
    pub primary_db_bytes: u64,
    pub derived_db_bytes: u64,
    pub archive_bytes: u64,
    pub ledger_bytes: u64,
    pub budget: StorageBudget,
    pub ledger_utilization_ppm: u64,
    pub archive_utilization_ppm: u64,
    pub within_budget: bool,
    /// Classes whose retention can free ledger space, in policy order.
    pub reclaimable_classes: Vec<String>,
}

fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn dir_len(path: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| {
            let path = entry.path();
            match entry.metadata() {
                Ok(meta) if meta.is_dir() => dir_len(&path),
                Ok(meta) => meta.len(),
                Err(_) => 0,
            }
        })
        .sum()
}

fn ppm(value: u64, budget: u64) -> u64 {
    if budget == 0 {
        return 0;
    }
    value.saturating_mul(1_000_000) / budget
}

/// Measure the configured paths against a budget. Missing paths count as zero
/// (a fresh install is within budget).
pub fn evaluate(
    primary_db: &Path,
    derived_db: &Path,
    archive_dir: &Path,
    budget: StorageBudget,
) -> StorageUsage {
    let primary = file_len(primary_db);
    let derived = file_len(derived_db);
    let archive = dir_len(archive_dir);
    let ledgers = primary.saturating_add(derived);
    let within = ledgers <= budget.ledgers_bytes && archive <= budget.archive_bytes;
    let mut reclaimable = Vec::new();
    if ledgers > budget.ledgers_bytes {
        reclaimable.push("operational".to_string());
        reclaimable.push("audit".to_string());
        reclaimable.push("money".to_string());
        reclaimable.push("safety".to_string());
    }
    if archive > budget.archive_bytes {
        reclaimable.push("audit".to_string());
    }
    StorageUsage {
        primary_db_bytes: primary,
        derived_db_bytes: derived,
        archive_bytes: archive,
        ledger_bytes: ledgers,
        budget,
        ledger_utilization_ppm: ppm(ledgers, budget.ledgers_bytes),
        archive_utilization_ppm: ppm(archive, budget.archive_bytes),
        within_budget: within,
        reclaimable_classes: reclaimable,
    }
}

/// Per-class byte estimate for the long-lived ledger budget. This is a
/// report-only view: deletion remains gated by retention and legal holds.
pub fn class_bytes(conn: &rusqlite::Connection) -> Result<BTreeMap<String, i64>, String> {
    let mut out = BTreeMap::new();
    for (class, table) in [
        ("operational", "idempotency_keys"),
        ("audit", "security_events"),
        ("money", "applied_effects_ledger"),
        ("safety", "pending_approvals"),
    ] {
        let bytes: i64 = conn
            .query_row(
                &format!("SELECT COALESCE(SUM(LENGTH(QUOTE({table}))),0) FROM {table}"),
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        out.insert(class.to_string(), bytes);
    }
    Ok(out)
}

/// Production helper used by the admin CLI and tests.
pub fn evaluate_default(data_dir: &Path, budget: StorageBudget) -> StorageUsage {
    let primary = data_dir.join("primary.db");
    let derived = data_dir.join("derived.db");
    let archive = data_dir.join("archive");
    evaluate(&primary, &derived, &archive, budget)
}

/// Paths that make up the gateway's durable footprint, for diagnostics.
pub fn footprint_paths(data_dir: &Path) -> Vec<PathBuf> {
    vec![
        data_dir.join("primary.db"),
        data_dir.join("derived.db"),
        data_dir.join("archive"),
    ]
}
