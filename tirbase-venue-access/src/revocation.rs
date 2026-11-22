// SPDX-License-Identifier: AGPL-3.0-only

//! Revocation state, monotonic versioned deltas and the offline reader cache.
//!
//! A reader that loses its link must keep denying revoked cards. The cache
//! therefore persists the whole revocation list together with the version it
//! came from, and refuses a delta that would move the version backwards or
//! that does not build on the version currently held.

use std::collections::{BTreeMap, BTreeSet};

use tirbase_venue::{AccessPolicyId, GateId, ReaderId, TicketId, ZoneId};

use crate::credential::CredentialId;
use crate::error::AccessError;
use crate::ids::CardholderId;

/// A versioned set of revoked credentials.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RevocationList {
    version: u64,
    issued_at_utc_us: i64,
    revoked: BTreeSet<CredentialId>,
}

impl Default for RevocationList {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl RevocationList {
    /// Empty list at `version`.
    pub fn new(version: u64, issued_at_utc_us: i64) -> Self {
        Self {
            version,
            issued_at_utc_us,
            revoked: BTreeSet::new(),
        }
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn issued_at_utc_us(&self) -> i64 {
        self.issued_at_utc_us
    }

    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }

    pub fn is_revoked(&self, id: &CredentialId) -> bool {
        self.revoked.contains(id)
    }

    pub fn revoked_ids(&self) -> impl Iterator<Item = &CredentialId> {
        self.revoked.iter()
    }

    /// Record a local revocation without changing the published version.
    ///
    /// Use [`RevocationList::apply`] for an operator-published delta.
    pub fn revoke(&mut self, id: CredentialId) -> bool {
        self.revoked.insert(id)
    }

    /// Apply an operator delta, enforcing monotonicity.
    pub fn apply(&mut self, delta: &RevocationDelta) -> Result<AppliedRevocation, AccessError> {
        if delta.to_version == self.version {
            return Ok(AppliedRevocation::AlreadyCurrent);
        }
        if delta.to_version < self.version {
            return Err(AccessError::RevocationRegression {
                current: self.version,
                offered: delta.to_version,
            });
        }
        if delta.base_version != self.version {
            return Err(AccessError::RevocationOutOfOrder {
                expected: self.version,
                offered: delta.base_version,
            });
        }
        let mut newly_revoked = 0u32;
        let mut reinstated = 0u32;
        for id in &delta.revoke {
            if self.revoked.insert(id.clone()) {
                newly_revoked += 1;
            }
        }
        for id in &delta.reinstate {
            if self.revoked.remove(id) {
                reinstated += 1;
            }
        }
        let from = self.version;
        self.version = delta.to_version;
        self.issued_at_utc_us = delta.issued_at_utc_us;
        Ok(AppliedRevocation::Applied {
            from,
            to: delta.to_version,
            newly_revoked,
            reinstated,
        })
    }
}

/// An operator-published change between two revocation versions.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RevocationDelta {
    pub base_version: u64,
    pub to_version: u64,
    pub issued_at_utc_us: i64,
    #[serde(default)]
    pub revoke: Vec<CredentialId>,
    #[serde(default)]
    pub reinstate: Vec<CredentialId>,
}

/// Outcome of applying a delta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppliedRevocation {
    Applied {
        from: u64,
        to: u64,
        newly_revoked: u32,
        reinstated: u32,
    },
    AlreadyCurrent,
}

/// A grant remembered for offline operation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CachedGrant {
    pub credential_id: CredentialId,
    pub holder_id: CardholderId,
    pub gate_id: GateId,
    pub zone_id: ZoneId,
    pub policy_id: AccessPolicyId,
    pub ticket_id: TicketId,
    pub expires_at_utc_us: i64,
}

/// Everything a reader needs to decide access without a back-office link.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OfflineCache {
    pub reader_id: ReaderId,
    pub revocation: RevocationList,
    pub secure_channel: bool,
    grants: BTreeMap<String, CachedGrant>,
}

impl OfflineCache {
    pub fn new(reader_id: ReaderId) -> Self {
        Self {
            reader_id,
            revocation: RevocationList::default(),
            secure_channel: false,
            grants: BTreeMap::new(),
        }
    }

    pub fn is_secure(&self) -> bool {
        self.secure_channel
    }

    pub fn set_secure(&mut self, secure: bool) {
        self.secure_channel = secure;
    }

    /// Remember a grant for a card fingerprint until `expires_at_utc_us`.
    pub fn remember_grant(&mut self, fingerprint: &str, grant: CachedGrant) {
        self.grants.insert(fingerprint.to_owned(), grant);
    }

    /// A grant valid at `ts_utc_us` for the same gate.
    pub fn grant(&self, fingerprint: &str, gate_id: &GateId, ts_utc_us: i64) -> Option<&CachedGrant> {
        self.grants.get(fingerprint).filter(|grant| {
            &grant.gate_id == gate_id && grant.expires_at_utc_us > ts_utc_us
        })
    }

    pub fn grants(&self) -> impl Iterator<Item = (&String, &CachedGrant)> {
        self.grants.iter()
    }

    pub fn prune(&mut self, ts_utc_us: i64) {
        self.grants
            .retain(|_, grant| grant.expires_at_utc_us > ts_utc_us);
    }

    /// Serialize the cache for durable storage on the reader.
    pub fn to_json(&self) -> Result<String, AccessError> {
        serde_json::to_string(self).map_err(|_| AccessError::CacheCorrupt("serialize failed"))
    }

    /// Restore a cache written by [`OfflineCache::to_json`].
    pub fn from_json(json: &str) -> Result<Self, AccessError> {
        serde_json::from_str(json).map_err(|_| AccessError::CacheCorrupt("parse failed"))
    }
}
