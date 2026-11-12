//! Fleet inventory — a CRDT collection of provisioned devices (PV-11.3,
//! ).
//!
//! The inventory is a *state-based* CRDT: every device is one entry in a
//! `BTreeMap` keyed by DID, and two inventories merge by joining each entry
//! with the corresponding entry of the other replica.
//!
//! ## Lattice properties
//!
//! * **Per-device join:** a revoked entry always dominates a provisioned entry
//! (revocation is monotonic — a device can never be un-revoked by a stale
//! peer), and two entries in the same lifecycle keep the greater
//! `(version, updated_by)` pair. This is a total order, so the join is
//! commutative, associative, and idempotent.
//! * **Clock:** `lamport` is the maximum version ever observed, and a local
//! mutation writes `lamport + 1`, so a later local change always dominates
//! the state it was based on.
//! * **Determinism:** entries are held in a `BTreeMap`, so iteration and the
//! snapshot hash are byte-stable across replicas and platforms.
//!
//! ## Provisioning payload cap
//!
//! PV-11.3 limits a provisioning payload to 64 KiB. The cap is enforced at
//! both the local mutation boundary ([`FleetInventory::provision`]) and the
//! untrusted inbound boundary ([`FleetInventory::apply_update`]): an oversized
//! payload is rejected instead of being merged, so a peer can neither store nor
//! re-broadcast a payload above the limit.
//!
//! ## Propagation
//!
//! [`FleetInventoryDelta`] is the wire form. `CoreHandle` emits one for every
//! local fleet change, merges inbound deltas from peers, and re-broadcasts only
//! when a merge actually changed local state — so a CRDT-identical update
//! terminates instead of looping around the mesh.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crdt::delta::Did;
use crate::errors::TirBaseError;
use crate::migration::fleet_precondition::{
    DynFleetPreconditionVerifier, FleetPreconditionVerifier,
};
use crate::migration::migration_delta::MigrationId;

/// Maximum serialised provisioning payload accepted for one device (PV-11.3):
/// 64 KiB.
pub const MAX_PROVISIONING_PAYLOAD_BYTES: usize = 64 * 1024;

/// Maximum number of entries a single inbound [`FleetInventoryDelta`] may
/// carry. Bounds the work one peer message can trigger; the inventory itself
/// has no entry-count limit.
pub const MAX_ENTRIES_PER_UPDATE: usize = 4096;

/// Lifecycle state of one fleet member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceLifecycle {
 /// Device is enrolled in the fleet and may participate.
    Provisioned,
 /// Device has been revoked; this state is terminal in the CRDT.
    Revoked,
}

/// Provisioning record for one device.
///
/// The whole serialised record is the "provisioning payload" bounded by
/// [`MAX_PROVISIONING_PAYLOAD_BYTES`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceProvisioning {
 /// Device DID (`did:key:z…`).
    pub device_id: Did,
 /// Deployment device class (e.g. `"cold-room-gateway"`).
    pub device_class: String,
 /// Envelope profile the device is provisioned with (`ProfileId`).
    pub profile_id: [u8; 16],
 /// Ed25519 public key of the device.
    pub public_key: Vec<u8>,
 /// Enrolment timestamp in authenticated wall time (UTC seconds).
    pub enrolled_at_est: i64,
 /// Free-form operator labels (site, rack, asset tag, …).
    pub labels: BTreeMap<String, String>,
}

impl DeviceProvisioning {
 /// Construct a minimal provisioning record with a 32-byte Ed25519 key.
    pub fn new(
        device_id: impl Into<Did>,
        device_class: impl Into<String>,
        profile_id: [u8; 16],
        public_key: [u8; 32],
        enrolled_at_est: i64,
    ) -> Self {
        Self {
            device_id: device_id.into(),
            device_class: device_class.into(),
            profile_id,
            public_key: public_key.to_vec(),
            enrolled_at_est,
            labels: BTreeMap::new(),
        }
    }

 /// Serialised size of this provisioning payload in bytes.
    pub fn payload_len(&self) -> Result<usize, FleetError> {
        serde_json::to_vec(self)
            .map(|bytes| bytes.len())
            .map_err(|e| FleetError::Serialisation {
                reason: e.to_string(),
            })
    }

 /// Enforce the 64 KiB provisioning-payload cap.
    pub fn validate_size(&self) -> Result<(), FleetError> {
        let size = self.payload_len()?;
        if size > MAX_PROVISIONING_PAYLOAD_BYTES {
            return Err(FleetError::ProvisioningPayloadTooLarge {
                size,
                max: MAX_PROVISIONING_PAYLOAD_BYTES,
            });
        }
        Ok(())
    }
}

/// One device entry in the fleet inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetEntry {
 /// Device DID; always equal to the map key it is stored under.
    pub device_id: Did,
 /// Current lifecycle state.
    pub lifecycle: DeviceLifecycle,
 /// CRDT version of the last state change (Lamport value).
    pub version: u64,
 /// DID of the node that produced this state change (deterministic
 /// tie-break for concurrent changes at the same version).
    pub updated_by: Did,
 /// Authenticated wall time of the last state change (UTC seconds).
    pub updated_at_est: i64,
 /// Provisioning record (retained after revocation for audit).
    pub provisioning: Option<DeviceProvisioning>,
 /// Reason string recorded with a revocation.
    pub revocation_reason: Option<String>,
}

impl FleetEntry {
 /// `true` when this entry records a revocation.
    pub fn is_revoked(&self) -> bool {
        self.lifecycle == DeviceLifecycle::Revoked
    }

 /// Join two entries for the same device into the CRDT-dominant one.
 ///
 /// Returns the dominant entry (which may be `self`).
    fn join(&self, other: &FleetEntry) -> FleetEntry {
        let other_wins = match (self.lifecycle, other.lifecycle) {
 // Revocation is monotonic: it always dominates provisioning,
 // regardless of version.
            (DeviceLifecycle::Provisioned, DeviceLifecycle::Revoked) => true,
            (DeviceLifecycle::Revoked, DeviceLifecycle::Provisioned) => false,
 // Same lifecycle: greatest (version, updated_by) wins.
            _ => match (other.version, &other.updated_by).cmp(&(self.version, &self.updated_by)) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Less => false,
 // Identical version and actor can only differ if a peer sent an
 // entry it did not derive (or two nodes shared an actor id).
 // Fall back to a canonical-content tie-break so every replica
 // still converges on the same entry.
                std::cmp::Ordering::Equal => {
                    let self_bytes = serde_json::to_vec(self).unwrap_or_default();
                    let other_bytes = serde_json::to_vec(other).unwrap_or_default();
                    other_bytes > self_bytes
                }
            },
        };
        if other_wins {
            other.clone()
        } else {
            self.clone()
        }
    }
}

/// Errors produced by the fleet inventory.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FleetError {
 /// A provisioning payload exceeds the PV-11.3 64 KiB cap.
    #[error("provisioning payload is {size} bytes; the fleet limit is {max} bytes (PV-11.3)")]
    ProvisioningPayloadTooLarge { size: usize, max: usize },
 /// A provisioning record is structurally invalid.
    #[error("invalid provisioning record: {reason}")]
    InvalidProvisioning { reason: String },
 /// A revoked device cannot be re-provisioned.
    #[error("device {device_id} is revoked and cannot be re-provisioned")]
    DeviceRevoked { device_id: Did },
 /// An inbound update exceeds the entry-count bound.
    #[error("fleet update carries {count} entries; the maximum is {max}")]
    TooManyEntries { count: usize, max: usize },
 /// Serialisation failure.
    #[error("fleet inventory serialisation failed: {reason}")]
    Serialisation { reason: String },
}

/// Result of merging an inbound [`FleetInventoryDelta`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FleetMergeReport {
 /// Entries whose merged state changed locally.
    pub applied: usize,
 /// Entries already at or above the incoming state.
    pub unchanged: usize,
 /// Entries rejected as malformed or over the payload cap.
    pub rejected: usize,
 /// Device DIDs that became revoked as a result of this merge.
    pub newly_revoked: Vec<Did>,
}

impl FleetMergeReport {
 /// `true` when the merge changed any local state.
    pub fn changed(&self) -> bool {
        self.applied > 0
    }
}

/// Wire form of a fleet-inventory change set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetInventoryDelta {
 /// DID of the node that produced the update.
    pub origin_did: Did,
 /// Entries the origin wants its peers to merge.
    pub entries: Vec<FleetEntry>,
 /// Authenticated wall time the update was produced (UTC seconds).
    pub sent_at_est: i64,
}

impl FleetInventoryDelta {
 /// Build an update carrying the given device IDs from `inventory`.
    pub fn from_inventory(
        inventory: &FleetInventory,
        origin_did: impl Into<Did>,
        device_ids: &[Did],
        sent_at_est: i64,
    ) -> Self {
        let entries = device_ids
            .iter()
            .filter_map(|id| inventory.get(id).cloned())
            .collect();
        Self {
            origin_did: origin_did.into(),
            entries,
            sent_at_est,
        }
    }
}

/// The fleet inventory CRDT collection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetInventory {
    devices: BTreeMap<Did, FleetEntry>,
    lamport: u64,
}

impl FleetInventory {
 /// Create an empty inventory.
    pub fn new() -> Self {
        Self::default()
    }

 /// Number of known devices (provisioned and revoked).
    pub fn len(&self) -> usize {
        self.devices.len()
    }

 /// `true` when no device is known.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

 /// Current Lamport value of the collection.
    pub fn lamport(&self) -> u64 {
        self.lamport
    }

 /// Look up one device.
    pub fn get(&self, device_id: &str) -> Option<&FleetEntry> {
        self.devices.get(device_id)
    }

 /// `true` when the device is known and revoked.
    pub fn is_revoked(&self, device_id: &str) -> bool {
        self.devices
            .get(device_id)
            .map(FleetEntry::is_revoked)
            .unwrap_or(false)
    }

 /// DIDs of every revoked device, in deterministic order.
    pub fn revoked_device_ids(&self) -> Vec<Did> {
        self.devices
            .values()
            .filter(|entry| entry.is_revoked())
            .map(|entry| entry.device_id.clone())
            .collect()
    }

 /// All entries, in DID order.
    pub fn entries(&self) -> impl Iterator<Item = &FleetEntry> {
        self.devices.values()
    }

 /// Materialise a snapshot of all entries in DID order.
    pub fn snapshot(&self) -> Vec<FleetEntry> {
        self.devices.values().cloned().collect()
    }

 /// Provision (or re-provision) a device.
 ///
 /// The provisioning payload must not exceed [`MAX_PROVISIONING_PAYLOAD_BYTES`].
 /// A device that is already revoked cannot be re-provisioned.
    pub fn provision(
        &mut self,
        provisioning: DeviceProvisioning,
        updated_by: &str,
        updated_at_est: i64,
    ) -> Result<FleetEntry, FleetError> {
        provisioning.validate_size()?;
        if provisioning.device_id.trim().is_empty() {
            return Err(FleetError::InvalidProvisioning {
                reason: "device_id must not be empty".to_string(),
            });
        }
        if let Some(existing) = self.devices.get(&provisioning.device_id) {
            if existing.is_revoked() {
                return Err(FleetError::DeviceRevoked {
                    device_id: provisioning.device_id.clone(),
                });
            }
        }
        let version = self.next_version();
        let entry = FleetEntry {
            device_id: provisioning.device_id.clone(),
            lifecycle: DeviceLifecycle::Provisioned,
            version,
            updated_by: updated_by.to_string(),
            updated_at_est,
            provisioning: Some(provisioning),
            revocation_reason: None,
        };
        self.devices.insert(entry.device_id.clone(), entry.clone());
        Ok(entry)
    }

 /// Revoke a device.
 ///
 /// Revocation is terminal: revoking an already-revoked device is an
 /// idempotent no-op that returns `Ok(false)`. A device that was never
 /// provisioned is still revoked — the tombstone prevents a later
 /// provisioning record for that DID from being applied.
    pub fn revoke(
        &mut self,
        device_id: &str,
        reason: &str,
        updated_by: &str,
        updated_at_est: i64,
    ) -> Result<bool, FleetError> {
        if device_id.trim().is_empty() {
            return Err(FleetError::InvalidProvisioning {
                reason: "device_id must not be empty".to_string(),
            });
        }
        let existing = self.devices.get(device_id).cloned();
        if existing
            .as_ref()
            .map(FleetEntry::is_revoked)
            .unwrap_or(false)
        {
            return Ok(false);
        }
        let version = self.next_version();
        let entry = FleetEntry {
            device_id: device_id.to_string(),
            lifecycle: DeviceLifecycle::Revoked,
            version,
            updated_by: updated_by.to_string(),
            updated_at_est,
            provisioning: existing.and_then(|e| e.provisioning),
            revocation_reason: Some(reason.to_string()),
        };
        self.devices.insert(entry.device_id.clone(), entry);
        Ok(true)
    }

 /// Merge one untrusted remote entry.
    fn merge_entry(&mut self, incoming: FleetEntry) -> Result<bool, FleetError> {
        if incoming.device_id.trim().is_empty() {
            return Err(FleetError::InvalidProvisioning {
                reason: "inbound entry has an empty device_id".to_string(),
            });
        }
        if let Some(payload) = &incoming.provisioning {
            payload.validate_size()?;
        }
        self.lamport = self.lamport.max(incoming.version);

        match self.devices.get(&incoming.device_id) {
            None => {
                self.devices.insert(incoming.device_id.clone(), incoming);
                Ok(true)
            }
            Some(local) => {
                let merged = local.join(&incoming);
                if &merged == local {
                    Ok(false)
                } else {
                    self.devices.insert(merged.device_id.clone(), merged);
                    Ok(true)
                }
            }
        }
    }

 /// Merge a remote update into this inventory.
 ///
 /// Malformed or oversized entries are rejected without affecting the rest
 /// of the update, so one bad entry cannot poison a peer's whole delta.
    pub fn apply_update(&mut self, update: &FleetInventoryDelta) -> FleetMergeReport {
        let mut report = FleetMergeReport::default();
        if update.entries.len() > MAX_ENTRIES_PER_UPDATE {
            report.rejected = update.entries.len();
            return report;
        }
        for entry in &update.entries {
            let was_revoked = self.is_revoked(&entry.device_id);
            match self.merge_entry(entry.clone()) {
                Ok(true) => {
                    report.applied += 1;
                    if !was_revoked && self.is_revoked(&entry.device_id) {
                        report.newly_revoked.push(entry.device_id.clone());
                    }
                }
                Ok(false) => report.unchanged += 1,
                Err(_) => report.rejected += 1,
            }
        }
        report
    }

 /// Merge a whole inventory replica (state-based merge).
    pub fn merge(&mut self, other: &FleetInventory) -> FleetMergeReport {
        let update = FleetInventoryDelta {
            origin_did: "local-merge".to_string(),
            entries: other.snapshot(),
            sent_at_est: 0,
        };
        self.apply_update(&update)
    }

 /// Build a delta containing every entry (used to bring a newly connected
 /// peer up to date).
    pub fn full_update(&self, origin_did: impl Into<Did>, sent_at_est: i64) -> FleetInventoryDelta {
        FleetInventoryDelta {
            origin_did: origin_did.into(),
            entries: self.snapshot(),
            sent_at_est,
        }
    }

 /// SHA-256 over the canonical JSON snapshot of the inventory.
 ///
 /// Equal inventories (same entries in DID order) always produce the same
 /// hash on every replica and platform. This value is the fleet
 /// precondition hash a Contract migration can commit to ().
    pub fn snapshot_hash(&self) -> [u8; 32] {
        let canonical = serde_json::to_vec(&self.snapshot()).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(b"tirbase-fleet-inventory-v1:");
        hasher.update(&canonical);
        hasher.finalize().into()
    }

    fn next_version(&mut self) -> u64 {
        self.lamport = self.lamport.saturating_add(1);
        self.lamport
    }
}

/// Live [`FleetPreconditionVerifier`] backed by the CRDT inventory.
///
/// A Contract migration commits to a fleet precondition hash; this verifier
/// recomputes [`FleetInventory::snapshot_hash`] from the current inventory and
/// accepts the migration only when the two match. An empty inventory always
/// rejects: a Contract migration must never be approved over an unknown fleet.
#[derive(Debug)]
pub struct FleetInventoryVerifier {
    inventory: Arc<Mutex<FleetInventory>>,
}

impl FleetInventoryVerifier {
 /// Create a verifier over a shared inventory.
    pub fn new(inventory: Arc<Mutex<FleetInventory>>) -> Self {
        Self { inventory }
    }
}

impl FleetPreconditionVerifier for FleetInventoryVerifier {
    fn verify_contract(
        &self,
        migration_id: &MigrationId,
        fleet_precondition_hash: &[u8; 32],
    ) -> Result<(), TirBaseError> {
        let reject = || TirBaseError::FleetPreconditionMissing {
            migration_id: hex::encode(migration_id),
        };
        let inventory = self.inventory.lock().map_err(|_| reject())?;
        if inventory.is_empty() || inventory.snapshot_hash() != *fleet_precondition_hash {
            return Err(reject());
        }
        Ok(())
    }
}

/// Build the shared verifier handle for a `CoreHandle` migration engine.
pub fn dyn_verifier(inventory: Arc<Mutex<FleetInventory>>) -> DynFleetPreconditionVerifier {
    Arc::new(FleetInventoryVerifier::new(inventory))
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    fn provisioning(id: &str, label_bytes: usize) -> DeviceProvisioning {
        let mut p = DeviceProvisioning::new(
            id,
            "cold-room-gateway",
            [0x11; 16],
            [0x22; 32],
            1_700_000_000,
        );
        p.labels.insert("site".to_string(), "x".repeat(label_bytes));
        p
    }

    #[test]
    fn provisioning_payload_over_64_kib_is_rejected() {
        let mut inv = FleetInventory::new();
        let oversized = provisioning("did:key:zOversized", MAX_PROVISIONING_PAYLOAD_BYTES);
        let err = inv
            .provision(oversized, "did:key:zManager", 10)
            .expect_err("oversized provisioning must be rejected");
        assert!(matches!(
            err,
            FleetError::ProvisioningPayloadTooLarge { .. }
        ));
        assert!(inv.is_empty());

 // Just under the limit is accepted.
        let mut fits = provisioning("did:key:zFits", 0);
        fits.labels
            .insert("blob".to_string(), "x".repeat(48 * 1024));
        assert!(fits.validate_size().is_ok());
        inv.provision(fits, "did:key:zManager", 11)
            .expect("payload under 64 KiB must be accepted");
        assert_eq!(inv.len(), 1);
    }

    #[test]
    fn merge_is_commutative_associative_and_idempotent() {
        let mut a = FleetInventory::new();
        a.provision(provisioning("did:key:z1", 8), "did:key:zA", 100)
            .unwrap();
        a.provision(provisioning("did:key:z2", 8), "did:key:zA", 101)
            .unwrap();

        let mut b = FleetInventory::new();
        b.provision(provisioning("did:key:z2", 8), "did:key:zB", 200)
            .unwrap();
        b.revoke("did:key:z3", "decommissioned", "did:key:zB", 201)
            .unwrap();

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);
        assert_eq!(ab.snapshot(), ba.snapshot(), "merge must be commutative");
        assert_eq!(ab.snapshot_hash(), ba.snapshot_hash());

        let before = ab.clone();
        ab.merge(&b);
        assert_eq!(ab, before, "merge must be idempotent");
        assert!(ab.is_revoked("did:key:z3"));
    }

    #[test]
    fn revocation_dominates_any_provisioning_record() {
        let mut inv = FleetInventory::new();
        inv.revoke("did:key:z9", "stolen", "did:key:zA", 300)
            .unwrap();

 // A concurrent, higher-version provisioning record must not resurrect.
        let stale_provisioning = FleetEntry {
            device_id: "did:key:z9".to_string(),
            lifecycle: DeviceLifecycle::Provisioned,
            version: u64::MAX,
            updated_by: "did:key:zB".to_string(),
            updated_at_est: 400,
            provisioning: Some(provisioning("did:key:z9", 4)),
            revocation_reason: None,
        };
        let update = FleetInventoryDelta {
            origin_did: "did:key:zB".to_string(),
            entries: vec![stale_provisioning],
            sent_at_est: 401,
        };
        let report = inv.apply_update(&update);
        assert!(inv.is_revoked("did:key:z9"));
        assert!(!report.newly_revoked.contains(&"did:key:z9".to_string()));
    }

    #[test]
    fn equal_version_entries_converge_on_canonical_content() {
        let base = FleetEntry {
            device_id: "did:key:z1".to_string(),
            lifecycle: DeviceLifecycle::Provisioned,
            version: 7,
            updated_by: "did:key:zA".to_string(),
            updated_at_est: 10,
            provisioning: Some(provisioning("did:key:z1", 4)),
            revocation_reason: None,
        };
        let mut variant = base.clone();
        variant.updated_at_est = 11;

        let mut left = FleetInventory::new();
        left.apply_update(&FleetInventoryDelta {
            origin_did: "did:key:zA".to_string(),
            entries: vec![base.clone()],
            sent_at_est: 1,
        });
        let mut right = FleetInventory::new();
        right.apply_update(&FleetInventoryDelta {
            origin_did: "did:key:zB".to_string(),
            entries: vec![variant.clone()],
            sent_at_est: 1,
        });

        left.merge(&right);
        right.merge(&left);
        assert_eq!(
            left.snapshot_hash(),
            right.snapshot_hash(),
            "equal-version entries must still converge on both replicas"
        );
    }

    #[test]
    fn inbound_oversized_entry_is_rejected_but_update_still_merges_others() {
        let mut inv = FleetInventory::new();
        let oversized = FleetEntry {
            device_id: "did:key:zBig".to_string(),
            lifecycle: DeviceLifecycle::Provisioned,
            version: 5,
            updated_by: "did:key:zA".to_string(),
            updated_at_est: 10,
            provisioning: Some(provisioning("did:key:zBig", MAX_PROVISIONING_PAYLOAD_BYTES)),
            revocation_reason: None,
        };
        let good = FleetEntry {
            device_id: "did:key:zGood".to_string(),
            lifecycle: DeviceLifecycle::Provisioned,
            version: 6,
            updated_by: "did:key:zA".to_string(),
            updated_at_est: 11,
            provisioning: Some(provisioning("did:key:zGood", 4)),
            revocation_reason: None,
        };
        let update = FleetInventoryDelta {
            origin_did: "did:key:zA".to_string(),
            entries: vec![oversized, good],
            sent_at_est: 12,
        };
        let report = inv.apply_update(&update);
        assert_eq!(report.rejected, 1);
        assert_eq!(report.applied, 1);
        assert!(inv.get("did:key:zGood").is_some());
        assert!(inv.get("did:key:zBig").is_none());
    }

    #[test]
    fn snapshot_hash_matches_across_replicas_and_verifier_gate() {
        let mut inv = FleetInventory::new();
        inv.provision(provisioning("did:key:z1", 4), "did:key:zA", 1)
            .unwrap();
        let hash = inv.snapshot_hash();

        let mut replica = FleetInventory::new();
        replica
            .provision(provisioning("did:key:z1", 4), "did:key:zA", 1)
            .unwrap();
        assert_eq!(replica.snapshot_hash(), hash);

        let shared = Arc::new(Mutex::new(inv));
        let verifier = FleetInventoryVerifier::new(shared.clone());
        assert!(
            verifier.verify_contract(&[0xAA; 32], &hash).is_ok(),
            "a matching fleet precondition hash must be accepted"
        );
        assert!(
            verifier.verify_contract(&[0xAA; 32], &[0u8; 32]).is_err(),
            "a mismatched fleet precondition hash must be rejected"
        );

 // Empty inventory rejects even a hash that "matches" its empty state.
        let empty = FleetInventory::new();
        let empty_hash = empty.snapshot_hash();
        let empty_verifier =
            FleetInventoryVerifier::new(Arc::new(Mutex::new(FleetInventory::new())));
        assert!(
            empty_verifier
                .verify_contract(&[0xBB; 32], &empty_hash)
                .is_err(),
            "an empty inventory must never approve a Contract migration"
        );
    }
}
