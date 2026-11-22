// SPDX-License-Identifier: AGPL-3.0-only

//! Local, bounded, tamper-evident audit log.
//!
//! Every decision a gate takes offline is recorded locally with a monotonic
//! sequence number and a SHA-256 hash chain, so a reader that never reaches the
//! back office still has an ordered record of what it allowed and refused, and
//! an edited entry is detectable.

use std::collections::VecDeque;

use tirbase_venue::GateId;
use tirbase_venue_access::crypto::digest_hex;
use tirbase_venue_access::CredentialId;

use crate::error::GateError;

const AUDIT_DOMAIN: &str = "TirBase/v1/GateAudit";

/// What the gate did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Granted,
    Denied,
    Replayed,
    Passage,
    UnpermittedPassage,
    FireAlarm,
    Tamper,
    PowerLoss,
    PowerRestored,
    Timeout,
    Fault,
    Locked,
    Unlocked,
}

impl AuditAction {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditAction::Granted => "granted",
            AuditAction::Denied => "denied",
            AuditAction::Replayed => "replayed",
            AuditAction::Passage => "passage",
            AuditAction::UnpermittedPassage => "unpermitted_passage",
            AuditAction::FireAlarm => "fire_alarm",
            AuditAction::Tamper => "tamper",
            AuditAction::PowerLoss => "power_loss",
            AuditAction::PowerRestored => "power_restored",
            AuditAction::Timeout => "timeout",
            AuditAction::Fault => "fault",
            AuditAction::Locked => "locked",
            AuditAction::Unlocked => "unlocked",
        }
    }
}

/// One local audit entry.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub at_utc_us: i64,
    pub gate_id: GateId,
    pub credential_id: Option<CredentialId>,
    /// Card fingerprint, never the card material.
    pub fingerprint: Option<String>,
    pub action: AuditAction,
    pub detail: String,
    pub prev_digest: String,
    pub digest: String,
}

impl AuditEntry {
    fn compute_digest(&self) -> String {
        let credential = self
            .credential_id
            .as_ref()
            .map(|id| id.as_str())
            .unwrap_or("-");
        let fingerprint = self.fingerprint.as_deref().unwrap_or("-");
        let canonical = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            self.seq,
            self.at_utc_us,
            self.gate_id,
            credential,
            fingerprint,
            self.action.as_str(),
            self.detail,
            self.prev_digest
        );
        digest_hex(AUDIT_DOMAIN, canonical.as_bytes())
    }
}

/// Bounded audit log with a hash chain.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuditLog {
    gate_id: GateId,
    capacity: usize,
    dropped: u64,
    last_digest: String,
    entries: VecDeque<AuditEntry>,
}

impl AuditLog {
    /// Create a log for a gate. Capacity must be non-zero.
    pub fn new(gate_id: GateId, capacity: usize) -> Result<Self, GateError> {
        if capacity == 0 {
            return Err(GateError::InvalidCapacity("audit_capacity"));
        }
        let genesis = digest_hex(AUDIT_DOMAIN, format!("genesis|{gate_id}").as_bytes());
        Ok(Self {
            gate_id,
            capacity,
            dropped: 0,
            last_digest: genesis,
            entries: VecDeque::with_capacity(capacity.min(1024)),
        })
    }

    pub fn gate_id(&self) -> &GateId {
        &self.gate_id
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries evicted because the log is bounded.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn last_digest(&self) -> &str {
        &self.last_digest
    }

    pub fn entries(&self) -> impl DoubleEndedIterator<Item = &AuditEntry> + ExactSizeIterator {
        self.entries.iter()
    }

    /// Most recent entry.
    pub fn last(&self) -> Option<&AuditEntry> {
        self.entries.back()
    }

    /// Append an entry, computing its digest.
    pub fn record(
        &mut self,
        at_utc_us: i64,
        credential_id: Option<CredentialId>,
        fingerprint: Option<String>,
        action: AuditAction,
        detail: impl Into<String>,
    ) -> AuditEntry {
        let seq = self
            .entries
            .back()
            .map(|entry| entry.seq + 1)
            .unwrap_or(1);
        let mut entry = AuditEntry {
            seq,
            at_utc_us,
            gate_id: self.gate_id.clone(),
            credential_id,
            fingerprint,
            action,
            detail: detail.into(),
            prev_digest: self.last_digest.clone(),
            digest: String::new(),
        };
        entry.digest = entry.compute_digest();
        self.last_digest = entry.digest.clone();
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.entries.push_back(entry.clone());
        entry
    }

    /// Recompute the chain over the retained entries.
    pub fn verify(&self) -> Result<(), GateError> {
        let mut previous = self
            .entries
            .front()
            .map(|entry| entry.prev_digest.clone())
            .unwrap_or_else(|| digest_hex(AUDIT_DOMAIN, format!("genesis|{}", self.gate_id).as_bytes()));
        for entry in &self.entries {
            if entry.gate_id != self.gate_id {
                return Err(GateError::AuditChainBroken(entry.seq));
            }
            if entry.prev_digest != previous {
                return Err(GateError::AuditChainBroken(entry.seq));
            }
            if entry.compute_digest() != entry.digest {
                return Err(GateError::AuditChainBroken(entry.seq));
            }
            previous = entry.digest.clone();
        }
        if previous != self.last_digest && !self.entries.is_empty() {
            return Err(GateError::AuditChainBroken(
                self.entries.back().map(|entry| entry.seq).unwrap_or(0),
            ));
        }
        Ok(())
    }

    /// Persist the log for a reader restart.
    pub fn to_json(&self) -> Result<String, GateError> {
        serde_json::to_string(self).map_err(|_| GateError::InvalidConfig("audit serialize failed"))
    }

    /// Restore a persisted log and verify the chain.
    pub fn from_json(json: &str, capacity: usize) -> Result<Self, GateError> {
        let mut log: Self =
            serde_json::from_str(json).map_err(|_| GateError::AuditCorrupt("parse failed"))?;
        if capacity == 0 {
            return Err(GateError::InvalidCapacity("audit_capacity"));
        }
        log.capacity = capacity;
        while log.entries.len() > capacity {
            log.entries.pop_front();
            log.dropped = log.dropped.saturating_add(1);
        }
        log.verify()?;
        Ok(log)
    }
}
