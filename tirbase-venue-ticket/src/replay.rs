// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded anti-replay store.
//!
//! Each admitted ticket leaves one entry (`ticket_id#nonce`). Entries are
//! pruned once older than the retention window, and the store is hard-capped at
//! `capacity`, evicting the oldest entry when full. Both bounds are validated at
//! construction so a deployment cannot configure an unbounded store.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::TicketError;

/// Largest accepted capacity.
pub const MAX_REPLAY_CAPACITY: usize = 100_000;
/// Longest accepted retention.
pub const MAX_RETENTION_US: i64 = 30 * 24 * 60 * 60 * 1_000_000;

/// Bounded set of admitted ticket presentations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayStore {
    capacity: usize,
    retention_us: i64,
    entries: BTreeMap<String, i64>,
    evicted: u64,
}

impl ReplayStore {
    /// Create a store. `capacity` must be in `1..=MAX_REPLAY_CAPACITY` and
    /// `retention_us` in `1..=MAX_RETENTION_US`.
    pub fn new(capacity: usize, retention_us: i64) -> Result<Self, TicketError> {
        if capacity == 0 || capacity > MAX_REPLAY_CAPACITY {
            return Err(TicketError::InvalidConfig("replay capacity out of range"));
        }
        if retention_us <= 0 || retention_us > MAX_RETENTION_US {
            return Err(TicketError::InvalidConfig("replay retention out of range"));
        }
        Ok(Self {
            capacity,
            retention_us,
            entries: BTreeMap::new(),
            evicted: 0,
        })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn retention_us(&self) -> i64 {
        self.retention_us
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries evicted because the store was full.
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Whether the key is currently retained.
    pub fn contains(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    /// Try to record a presentation.
    ///
    /// Returns `false` when the key is already retained (a replay). Otherwise
    /// prunes expired entries, evicts the oldest if still full, and records the
    /// key with `at_utc_us`.
    pub fn record(&mut self, key: String, at_utc_us: i64) -> bool {
        self.prune(at_utc_us);
        if self.entries.contains_key(&key) {
            return false;
        }
        while self.entries.len() >= self.capacity {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, seen)| **seen)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.entries.remove(&oldest);
            self.evicted = self.evicted.saturating_add(1);
        }
        self.entries.insert(key, at_utc_us);
        true
    }

    /// Drop entries older than the retention window.
    pub fn prune(&mut self, now_utc_us: i64) {
        let retention = self.retention_us;
        self.entries
            .retain(|_, seen| now_utc_us.saturating_sub(*seen) < retention);
    }

    pub fn to_json(&self) -> Result<String, TicketError> {
        serde_json::to_string(self).map_err(|_| TicketError::InvalidEncoding("serialize failed"))
    }

    pub fn from_json(json: &str) -> Result<Self, TicketError> {
        let store: Self = serde_json::from_str(json)
            .map_err(|_| TicketError::InvalidEncoding("parse failed"))?;
        if store.capacity == 0
            || store.capacity > MAX_REPLAY_CAPACITY
            || store.retention_us <= 0
            || store.retention_us > MAX_RETENTION_US
        {
            return Err(TicketError::InvalidConfig("stored replay bounds out of range"));
        }
        Ok(store)
    }
}
