// SPDX-License-Identifier: AGPL-3.0-only

//! Signed revocation deltas with version, expiry and M-of-N approval, plus
//! offline accumulation.
//!
//! A delta is a chained change: `base_version -> version`, adding and/or
//! removing ticket ids. Every delta carries its own expiry and its approval
//! threshold. Each approver signs the same canonical bytes with its own key, so
//! an emergency revocation can be authorised by M of N custodians without any
//! of them holding the others' keys. Gateways that are offline accept deltas in
//! any order: out-of-order deltas wait in a bounded queue and are applied as
//! soon as the chain closes.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use tirbase_venue::TicketId;
use tirbase_venue_ticket::{IssuerKeyRing, TicketSigner};

use crate::error::RevocationError;

/// Domain separation for delta signatures.
pub const DELTA_DOMAIN: &str = "TirBase/v1/VenueRevocationDelta";
/// Most ids one delta may add or remove.
pub const MAX_DELTA_IDS: usize = 4_096;
/// Default bounded queue for offline out-of-order deltas.
pub const MAX_PENDING_DELTAS: usize = 64;
/// Longest identifier accepted in a signed delta.
const MAX_ID_LEN: usize = 256;

/// A chained revocation change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationDelta {
    pub base_version: u64,
    pub version: u64,
    pub issued_at_utc_us: i64,
    pub expires_at_utc_us: i64,
    pub added: Vec<TicketId>,
    pub removed: Vec<TicketId>,
    /// M in the M-of-N approval.
    pub approvals_required: u32,
    /// Emergency revocations need the stricter policy threshold.
    pub emergency: bool,
}

impl RevocationDelta {
    /// Build a routine delta. An empty change is a legal heartbeat that renews
    /// the list's expiry at a new version.
    pub fn new(
        base_version: u64,
        version: u64,
        issued_at_utc_us: i64,
        expires_at_utc_us: i64,
        mut added: Vec<TicketId>,
        mut removed: Vec<TicketId>,
    ) -> Result<Self, RevocationError> {
        if version <= base_version {
            return Err(RevocationError::InvalidDelta(
                "version must be greater than base version",
            ));
        }
        if expires_at_utc_us <= issued_at_utc_us {
            return Err(RevocationError::InvalidDelta(
                "expiry must be after the issue time",
            ));
        }
        if added.len() > MAX_DELTA_IDS || removed.len() > MAX_DELTA_IDS {
            return Err(RevocationError::InvalidDelta("too many ticket ids"));
        }
        added.sort();
        added.dedup();
        removed.sort();
        removed.dedup();
        if added.iter().any(|id| removed.binary_search(id).is_ok()) {
            return Err(RevocationError::InvalidDelta(
                "a ticket cannot be added and removed by the same delta",
            ));
        }
        Ok(Self {
            base_version,
            version,
            issued_at_utc_us,
            expires_at_utc_us,
            added,
            removed,
            approvals_required: 1,
            emergency: false,
        })
    }

    /// Mark the delta as an emergency revocation needing `approvals_required`
    /// distinct signatures (subject to the policy minimum).
    pub fn with_emergency(mut self, approvals_required: u32) -> Result<Self, RevocationError> {
        if approvals_required == 0 {
            return Err(RevocationError::InvalidDelta(
                "emergency approval threshold must be positive",
            ));
        }
        self.approvals_required = approvals_required;
        self.emergency = true;
        Ok(self)
    }

    /// Set the routine approval threshold.
    pub fn with_approvals(mut self, approvals_required: u32) -> Result<Self, RevocationError> {
        if approvals_required == 0 {
            return Err(RevocationError::InvalidDelta(
                "approval threshold must be positive",
            ));
        }
        self.approvals_required = approvals_required;
        Ok(self)
    }

    pub fn ttl_us(&self) -> i64 {
        self.expires_at_utc_us
            .saturating_sub(self.issued_at_utc_us)
    }

    /// Deterministic bytes one approver signs, bound to their key id.
    pub fn signing_bytes(&self, key_id: &str) -> Result<Vec<u8>, RevocationError> {
        let mut out = Vec::with_capacity(128 + self.added.len() * 16 + self.removed.len() * 16);
        out.extend_from_slice(DELTA_DOMAIN.as_bytes());
        out.push(0);
        push_str(&mut out, key_id)?;
        out.extend_from_slice(&self.base_version.to_le_bytes());
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.issued_at_utc_us.to_le_bytes());
        out.extend_from_slice(&self.expires_at_utc_us.to_le_bytes());
        out.extend_from_slice(&self.approvals_required.to_le_bytes());
        out.push(self.emergency as u8);
        out.extend_from_slice(&(self.added.len() as u32).to_le_bytes());
        for id in &self.added {
            push_str(&mut out, id.as_str())?;
        }
        out.extend_from_slice(&(self.removed.len() as u32).to_le_bytes());
        for id in &self.removed {
            push_str(&mut out, id.as_str())?;
        }
        Ok(out)
    }
}

fn push_str(out: &mut Vec<u8>, value: &str) -> Result<(), RevocationError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_ID_LEN {
        return Err(RevocationError::InvalidEncoding(
            "identifier length out of range",
        ));
    }
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// One approver's signature over a delta.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaSignature {
    pub key_id: String,
    pub signature: String,
}

/// Policy thresholds verification enforces on top of what the delta claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaPolicy {
    /// Minimum signatures for a routine delta.
    pub required: u32,
    /// Minimum signatures for an emergency delta.
    pub emergency_required: u32,
    /// Longest accepted emergency validity, in microseconds.
    pub emergency_max_ttl_us: i64,
}

impl DeltaPolicy {
    /// One signature routinely, two in an emergency, six hours of emergency
    /// validity.
    pub fn standard() -> Self {
        Self {
            required: 1,
            emergency_required: 2,
            emergency_max_ttl_us: 6 * 3_600_000_000,
        }
    }

    /// Build a policy.
    pub fn new(
        required: u32,
        emergency_required: u32,
        emergency_max_ttl_us: i64,
    ) -> Result<Self, RevocationError> {
        if required == 0 {
            return Err(RevocationError::InvalidConfig(
                "routine threshold must be positive",
            ));
        }
        if emergency_required == 0 {
            return Err(RevocationError::InvalidConfig(
                "emergency threshold must be positive",
            ));
        }
        if emergency_max_ttl_us <= 0 {
            return Err(RevocationError::InvalidConfig(
                "emergency validity must be positive",
            ));
        }
        Ok(Self {
            required,
            emergency_required,
            emergency_max_ttl_us,
        })
    }
}

impl Default for DeltaPolicy {
    fn default() -> Self {
        Self::standard()
    }
}

/// A delta with its approvers' signatures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRevocationDelta {
    pub delta: RevocationDelta,
    pub signatures: Vec<DeltaSignature>,
}

impl SignedRevocationDelta {
    /// Sign a delta once per given signer.
    pub fn sign(
        delta: RevocationDelta,
        signers: &[&dyn TicketSigner],
    ) -> Result<Self, RevocationError> {
        if signers.is_empty() {
            return Err(RevocationError::InvalidConfig("no signers"));
        }
        let mut signatures = Vec::with_capacity(signers.len());
        for signer in signers {
            let message = delta.signing_bytes(signer.key_id())?;
            signatures.push(DeltaSignature {
                key_id: signer.key_id().to_owned(),
                signature: hex::encode(signer.sign(&message)),
            });
        }
        Ok(Self { delta, signatures })
    }

    /// Verify the delta's expiry, every signature and the M-of-N threshold.
    ///
    /// Returns the number of valid distinct approvers.
    pub fn verify(
        &self,
        ring: &IssuerKeyRing,
        policy: &DeltaPolicy,
        at_utc_us: i64,
    ) -> Result<u32, RevocationError> {
        if self.delta.expires_at_utc_us <= at_utc_us {
            return Err(RevocationError::Expired {
                expires_at_utc_us: self.delta.expires_at_utc_us,
            });
        }
        if self.delta.emergency && self.delta.ttl_us() > policy.emergency_max_ttl_us {
            return Err(RevocationError::EmergencyTtlTooLong {
                ttl_us: self.delta.ttl_us(),
            });
        }
        let mut seen = BTreeSet::new();
        for signature in &self.signatures {
            if !seen.insert(signature.key_id.clone()) {
                return Err(RevocationError::DuplicateSigner {
                    key_id: signature.key_id.clone(),
                });
            }
            let message = self.delta.signing_bytes(&signature.key_id)?;
            ring.verify(
                &signature.key_id,
                &message,
                &signature.signature,
                at_utc_us,
            )
            .map_err(|_| RevocationError::Signature {
                key_id: signature.key_id.clone(),
            })?;
        }
        let provided = self.signatures.len() as u32;
        let threshold = if self.delta.emergency {
            self.delta
                .approvals_required
                .max(policy.emergency_required)
        } else {
            self.delta.approvals_required.max(policy.required)
        };
        if provided < threshold {
            return Err(RevocationError::InsufficientApprovals {
                provided,
                required: threshold,
            });
        }
        Ok(provided)
    }
}

/// Result of applying one delta to a ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApplyOutcome {
    Applied {
        version: u64,
        added: usize,
        removed: usize,
        expires_at_utc_us: i64,
    },
    AlreadyApplied {
        version: u64,
    },
}

/// The accumulated revocation state a gate holds offline.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationLedger {
    version: u64,
    expires_at_utc_us: i64,
    revoked: BTreeSet<TicketId>,
    deltas: u64,
}

impl RevocationLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn expires_at_utc_us(&self) -> i64 {
        self.expires_at_utc_us
    }

    pub fn is_empty(&self) -> bool {
        self.version == 0
    }

    pub fn is_revoked(&self, ticket_id: &TicketId) -> bool {
        self.revoked.contains(ticket_id)
    }

    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    pub fn revoked(&self) -> impl Iterator<Item = &TicketId> {
        self.revoked.iter()
    }

    pub fn deltas_applied(&self) -> u64 {
        self.deltas
    }

    /// Verify and apply a delta that must chain onto the current version.
    pub fn apply(
        &mut self,
        signed: &SignedRevocationDelta,
        ring: &IssuerKeyRing,
        policy: &DeltaPolicy,
        at_utc_us: i64,
    ) -> Result<ApplyOutcome, RevocationError> {
        signed.verify(ring, policy, at_utc_us)?;
        let delta = &signed.delta;
        if delta.version <= self.version {
            return Ok(ApplyOutcome::AlreadyApplied {
                version: self.version,
            });
        }
        if delta.base_version != self.version {
            return Err(RevocationError::Gap {
                expected: self.version,
                offered: delta.base_version,
            });
        }
        self.apply_verified(delta);
        Ok(ApplyOutcome::Applied {
            version: self.version,
            added: delta.added.len(),
            removed: delta.removed.len(),
            expires_at_utc_us: self.expires_at_utc_us,
        })
    }

    fn apply_verified(&mut self, delta: &RevocationDelta) {
        for ticket_id in &delta.removed {
            self.revoked.remove(ticket_id);
        }
        for ticket_id in &delta.added {
            self.revoked.insert(ticket_id.clone());
        }
        self.version = delta.version;
        self.expires_at_utc_us = delta.expires_at_utc_us;
        self.deltas = self.deltas.saturating_add(1);
    }
}

/// Result of submitting a delta to an accumulator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubmitOutcome {
    Applied { version: u64 },
    Queued { waiting_for: u64 },
    AlreadyApplied { version: u64 },
}

/// Offline accumulator for gateways that receive deltas out of order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationAccumulator {
    ledger: RevocationLedger,
    pending: BTreeMap<u64, SignedRevocationDelta>,
    pending_capacity: usize,
}

impl RevocationAccumulator {
    pub fn new() -> Self {
        Self {
            ledger: RevocationLedger::new(),
            pending: BTreeMap::new(),
            pending_capacity: MAX_PENDING_DELTAS,
        }
    }

    pub fn with_pending_capacity(
        pending_capacity: usize,
    ) -> Result<Self, RevocationError> {
        if pending_capacity == 0 || pending_capacity > 4_096 {
            return Err(RevocationError::InvalidConfig(
                "pending capacity out of range",
            ));
        }
        Ok(Self {
            ledger: RevocationLedger::new(),
            pending: BTreeMap::new(),
            pending_capacity,
        })
    }

    pub fn ledger(&self) -> &RevocationLedger {
        &self.ledger
    }

    /// Mutable access for a gateway that applies a verified delta directly.
    pub fn ledger_mut(&mut self) -> &mut RevocationLedger {
        &mut self.ledger
    }

    pub fn pending(&self) -> impl Iterator<Item = &SignedRevocationDelta> {
        self.pending.values()
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// The version the ledger waits for next.
    pub fn next_version(&self) -> u64 {
        self.ledger.version.saturating_add(1)
    }

    /// Verify and submit one delta, queuing it if its base has not arrived.
    pub fn submit(
        &mut self,
        signed: &SignedRevocationDelta,
        ring: &IssuerKeyRing,
        policy: &DeltaPolicy,
        at_utc_us: i64,
    ) -> Result<SubmitOutcome, RevocationError> {
        signed.verify(ring, policy, at_utc_us)?;
        let delta = &signed.delta;
        if delta.version <= self.ledger.version {
            return Ok(SubmitOutcome::AlreadyApplied {
                version: self.ledger.version,
            });
        }
        if delta.base_version == self.ledger.version {
            self.ledger.apply_verified(delta);
            self.drain();
            Ok(SubmitOutcome::Applied {
                version: self.ledger.version,
            })
        } else if delta.base_version > self.ledger.version {
            self.queue(signed)?;
            Ok(SubmitOutcome::Queued {
                waiting_for: self.next_version(),
            })
        } else {
            Err(RevocationError::Gap {
                expected: self.ledger.version,
                offered: delta.base_version,
            })
        }
    }

    /// Submit a bundle of deltas in version order, returning how many applied.
    ///
    /// Deltas whose base has not arrived stay queued.
    pub fn apply_bundle(
        &mut self,
        deltas: &[SignedRevocationDelta],
        ring: &IssuerKeyRing,
        policy: &DeltaPolicy,
        at_utc_us: i64,
    ) -> Result<usize, RevocationError> {
        let mut ordered: Vec<&SignedRevocationDelta> = deltas.iter().collect();
        ordered.sort_by_key(|signed| signed.delta.version);
        let mut applied = 0;
        for signed in ordered {
            if let SubmitOutcome::Applied { .. } =
                self.submit(signed, ring, policy, at_utc_us)?
            {
                applied += 1;
            }
        }
        Ok(applied)
    }

    fn queue(&mut self, signed: &SignedRevocationDelta) -> Result<(), RevocationError> {
        let version = signed.delta.version;
        if let Some(queued) = self.pending.get(&version) {
            if queued.delta != signed.delta {
                return Err(RevocationError::ConflictingVersion { version });
            }
            return Ok(());
        }
        if self.pending.len() >= self.pending_capacity {
            return Err(RevocationError::PendingFull {
                capacity: self.pending_capacity,
            });
        }
        self.pending.insert(version, signed.clone());
        Ok(())
    }

    fn drain(&mut self) {
        loop {
            let next = self.next_version();
            let Some(queued) = self.pending.remove(&next) else {
                break;
            };
            if queued.delta.base_version != self.ledger.version {
                // Cannot chain; keep it for a later base (should not happen for
                // a verified chain, but never silently drop it).
                self.pending.insert(next, queued);
                break;
            }
            self.ledger.apply_verified(&queued.delta);
        }
    }
}

impl Default for RevocationAccumulator {
    fn default() -> Self {
        Self::new()
    }
}
