// SPDX-License-Identifier: AGPL-3.0-only

//! F-05 — key domains, HSM custody, rotation, revocation, recovery, and
//! zeroization.
//!
//! ## Key domains
//!
//! Six independent domains exist ([`KeyDomain`]). Each domain owns its own key
//! records, validity windows, and revocation entries, and signatures are
//! domain-separated ([`KeyRegistry::signing_bytes`]): a signature produced for
//! `UpdateSigner` can never satisfy a `PolicyAuthority` check even if the same
//! bytes are presented.
//!
//! ## Custody
//!
//! Private key material lives behind [`custodian::KeyCustodian`]. The trait has
//! **no export operation**: callers can generate, sign, read the public key,
//! revoke, and zeroize. A hardware custodian (PKCS#11 / vendor SDK) implements
//! the same trait without ever releasing key bytes; [`custodian::SoftwareCustodian`]
//! is the in-process implementation used by tests and development ceremonies.
//!
//! ## Rotation
//!
//! [`KeyRegistry::rotate`] activates a new key and moves every previously
//! active key in the domain to [`KeyState::Retiring`] with a bounded overlap
//! window. During the overlap, artefacts signed by the old key still verify.
//! After the window closes the old key can neither sign a new artefact
//! ([`KeyError::NotActive`]) nor verify anything ([`KeyError::Expired`]).
//!
//! ## Revocation
//!
//! Revocation is per-key, not per-domain: [`KeyRegistry::revoke`] produces a
//! [`RevocationRecord`] and a distributable [`RevocationList`]. A peer that
//! applies the list ([`RevocationList::apply_to`]) rejects the revoked key
//! immediately without changing any other key domain, so a compromised
//! `UpdateSigner` is retired without re-keying devices or tenant wrapping keys.
//!
//! ## Recovery
//!
//! Destructive recovery operations require a quorum [`QuorumApproval`]
//! (distinct custodian approvals, a threshold, and an expiry). Disaster re-key
//! of the root domain additionally returns a bounded cross-sign [`BridgeWindow`]
//! so existing devices can accept the transition before the old root is
//! retired.
//!
//! ## Zeroization
//!
//! Decommission and compromised-device paths overwrite and destroy the key
//! through the custodian, mark the record [`KeyState::Destroyed`], and retain
//! the public bundle and revocation history so old artefacts fail closed. Both
//! return receipts. Private key material is never returned, printed, or
//! serialised: [`custodian::SoftwareCustodian`]'s `Debug` output redacts seeds.

pub mod custodian;

pub use custodian::{KeyCustodian, SoftwareCustodian};

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use tirbase_types::DeviceSignature;

use crate::crdt::delta::Ed25519Signature;
use crate::identity::keypair;

/// The six independent key domains (F-05 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyDomain {
    /// Offline trust anchor; authorises root rotation.
    RootCa,
    /// Signs policy manifests and capability grants.
    PolicyAuthority,
    /// Signs release / OTA update artefacts.
    UpdateSigner,
    /// Signs data and key export attestations.
    ExportSigner,
    /// Per-device identity credential.
    DeviceIdentity,
    /// Per-tenant envelope key-encryption keys.
    TenantWrapping,
}

impl KeyDomain {
    /// All domains, in a stable order (ceremony checklists iterate this).
    pub const ALL: [KeyDomain; 6] = [
        KeyDomain::RootCa,
        KeyDomain::PolicyAuthority,
        KeyDomain::UpdateSigner,
        KeyDomain::ExportSigner,
        KeyDomain::DeviceIdentity,
        KeyDomain::TenantWrapping,
    ];

    /// Canonical domain name, used in domain-separated signing bytes and audit
    /// records.
    pub fn as_str(self) -> &'static str {
        match self {
            KeyDomain::RootCa => "root-ca",
            KeyDomain::PolicyAuthority => "policy-authority",
            KeyDomain::UpdateSigner => "update-signer",
            KeyDomain::ExportSigner => "export-signer",
            KeyDomain::DeviceIdentity => "device-identity",
            KeyDomain::TenantWrapping => "tenant-wrapping",
        }
    }
}

impl fmt::Display for KeyDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle state of one key record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    /// Generated but not yet authorised to sign.
    Pending,
    /// The one key that may sign new artefacts in its domain.
    Active,
    /// Rotated out: verifies within its remaining window, never signs.
    Retiring,
    /// Explicitly revoked; verifies nothing after `effective_at`.
    Revoked,
    /// Key material zeroized; verifies nothing.
    Destroyed,
}

/// Why a key was revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// Replaced by a rotation.
    Superseded,
    /// Suspected or confirmed compromise.
    KeyCompromise,
    /// Retired by a ceremony.
    CeremonyRetirement,
    /// Device decommissioned.
    Decommissioned,
}

/// A public key record. Never contains private material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRecord {
    /// Domain this key belongs to.
    pub domain: KeyDomain,
    /// Stable key identifier (unique across the registry).
    pub key_id: String,
    /// Monotonic version within the domain.
    pub version: u32,
    /// Raw Ed25519 public key bytes.
    pub public_key: Vec<u8>,
    /// Validity window start (seconds, authenticated time).
    pub not_before: i64,
    /// Validity window end (seconds, authenticated time).
    pub not_after: i64,
    /// Lifecycle state.
    pub state: KeyState,
}

impl KeyRecord {
    /// Whether the record is within its validity window at `now`.
    pub fn window_contains(&self, now: i64) -> bool {
        now >= self.not_before && now <= self.not_after
    }

    /// Whether this record may sign new artefacts at `now`.
    pub fn can_sign_at(&self, now: i64) -> bool {
        self.state == KeyState::Active && self.window_contains(now)
    }
}

/// A distributable revocation entry (one per revoked key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRecord {
    /// Domain of the revoked key.
    pub domain: KeyDomain,
    /// Revoked key identifier.
    pub key_id: String,
    /// Version of the revoked key.
    pub version: u32,
    /// Reason for revocation.
    pub reason: RevocationReason,
    /// Time from which the key must be rejected.
    pub effective_at: i64,
}

/// A signed, domain-separated artefact produced by [`KeyRegistry::sign`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedArtefact {
    /// Domain of the signing key.
    pub domain: KeyDomain,
    /// Identifier of the signing key.
    pub key_id: String,
    /// Version of the signing key.
    pub version: u32,
    /// Ed25519 signature over [`KeyRegistry::signing_bytes`].
    pub signature: DeviceSignature,
}

impl SignedArtefact {
    /// Verify this artefact against `registry` at `now`.
    pub fn verify(
        &self,
        registry: &KeyRegistry,
        artefact: &[u8],
        now: i64,
    ) -> Result<(), KeyError> {
        registry.verify_artefact(self.domain, &self.key_id, artefact, &self.signature, now)
    }
}

/// Receipt proving a key was zeroized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroizeReceipt {
    /// Key whose material was destroyed.
    pub key_id: String,
    /// Time the destruction was requested.
    pub zeroized_at: i64,
    /// `true` when the key had already been destroyed (idempotent replay).
    pub already_destroyed: bool,
}

/// Receipt for a rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationReceipt {
    /// Domain rotated.
    pub domain: KeyDomain,
    /// Previously active key (now retiring), if any.
    pub previous_key_id: Option<String>,
    /// Newly active key.
    pub new_key_id: String,
    /// Version of the new key.
    pub new_version: u32,
    /// When the rotation happened.
    pub rotated_at: i64,
    /// When the retiring key's overlap window closes.
    pub overlap_ends_at: i64,
}

/// Quorum policy for a custodian set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumPolicy {
    /// Distinct approvals required.
    pub threshold: usize,
    /// Total custodians in the set.
    pub total: usize,
}

impl QuorumPolicy {
    /// Validate and construct a quorum policy (`threshold >= 1`,
    /// `threshold <= total`).
    pub fn new(threshold: usize, total: usize) -> Result<Self, KeyError> {
        if threshold == 0 || total == 0 || threshold > total {
            return Err(KeyError::ApprovalInvalid {
                reason: format!(
                    "quorum policy requires 1 <= threshold <= total (got {threshold}-of-{total})"
                ),
            });
        }
        Ok(QuorumPolicy { threshold, total })
    }
}

/// One custodian's contribution to a quorum approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodianApproval {
    /// Custodian identity (share holder).
    pub custodian_id: String,
    /// Commitment to the share used, for the ceremony transcript. Never the
    /// share itself.
    pub share_commitment: Vec<u8>,
    /// When the custodian approved.
    pub signed_at: i64,
}

/// Destructive operations that require quorum approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOperation {
    /// Reconstruct an existing domain key after custodian/HSM loss.
    Recover,
    /// Replace the root after root compromise or destruction.
    DisasterRekey,
}

/// A quorum approval object. Constructed during the ceremony and checked by
/// the registry before any destructive operation proceeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumApproval {
    /// Operation being approved.
    pub operation: RecoveryOperation,
    /// Domain the operation applies to.
    pub domain: KeyDomain,
    /// Existing key being recovered, when applicable.
    pub reference_key_id: Option<String>,
    /// Custodian approvals collected.
    pub approvals: Vec<CustodianApproval>,
    /// Distinct approvals required.
    pub threshold: usize,
    /// When the approval was opened.
    pub issued_at: i64,
    /// After this instant the approval is void.
    pub expires_at: i64,
}

impl QuorumApproval {
    /// Build an approval from collected custodian contributions.
    pub fn new(
        operation: RecoveryOperation,
        domain: KeyDomain,
        reference_key_id: Option<String>,
        policy: QuorumPolicy,
        approvals: Vec<CustodianApproval>,
        issued_at: i64,
        expires_at: i64,
    ) -> Self {
        QuorumApproval {
            operation,
            domain,
            reference_key_id,
            approvals,
            threshold: policy.threshold,
            issued_at,
            expires_at,
        }
    }

    /// Distinct custodian approvals received.
    pub fn distinct_approvals(&self) -> usize {
        let mut seen: Vec<&str> = Vec::new();
        for approval in &self.approvals {
            if !seen.contains(&approval.custodian_id.as_str()) {
                seen.push(&approval.custodian_id);
            }
        }
        seen.len()
    }

    /// Whether the approval is unexpired and meets its threshold at `now`.
    pub fn is_satisfied(&self, now: i64) -> bool {
        now <= self.expires_at
            && self.distinct_approvals() >= self.threshold
            && self.threshold > 0
    }
}

/// Bounded window during which the previous root still verifies after a
/// disaster re-key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeWindow {
    /// Old root key that remains acceptable.
    pub old_root_key_id: String,
    /// New root key.
    pub new_root_key_id: String,
    /// When the bridge closes (old root rejected after this).
    pub not_after: i64,
}

/// Result of the compromised-device path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompromiseRecord {
    /// Zeroized device identity key.
    pub key_id: String,
    /// Operator-supplied evidence reference (never secret material).
    pub evidence_ref: String,
    /// Time of revocation.
    pub revoked_at: i64,
    /// Zeroization receipt.
    pub zeroize: ZeroizeReceipt,
}

/// Key-management failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// No record with this key id.
    UnknownKey {
        /// Missing key id.
        key_id: String,
    },
    /// A record with this key id already exists.
    DuplicateKey {
        /// Duplicate key id.
        key_id: String,
    },
    /// The key belongs to another domain.
    DomainMismatch {
        /// Domain the caller asked for.
        expected: KeyDomain,
        /// Domain recorded for the key.
        actual: KeyDomain,
    },
    /// The key exists but is not permitted to sign.
    NotActive {
        /// Key id.
        key_id: String,
        /// Current state.
        state: KeyState,
    },
    /// The key's validity window has not started.
    NotYetValid {
        /// Key id.
        key_id: String,
        /// Window start.
        not_before: i64,
    },
    /// The key's validity window has ended.
    Expired {
        /// Key id.
        key_id: String,
        /// Window end.
        not_after: i64,
    },
    /// The key was revoked.
    Revoked {
        /// Key id.
        key_id: String,
    },
    /// The key material was zeroized.
    Destroyed {
        /// Key id.
        key_id: String,
    },
    /// No active key exists for the domain at this time.
    NoActiveKey {
        /// Domain.
        domain: KeyDomain,
    },
    /// Signature verification failed.
    SignatureInvalid {
        /// Key id.
        key_id: String,
    },
    /// The custodian does not hold the requested key.
    CustodianKeyMissing {
        /// Key id.
        key_id: String,
    },
    /// The quorum approval is missing, expired, or insufficient.
    ApprovalInvalid {
        /// Human-readable reason; never contains key material.
        reason: String,
    },
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::UnknownKey { key_id } => write!(f, "unknown key '{key_id}'"),
            KeyError::DuplicateKey { key_id } => write!(f, "duplicate key id '{key_id}'"),
            KeyError::DomainMismatch { expected, actual } => write!(
                f,
                "key domain mismatch: expected {expected}, record is {actual}"
            ),
            KeyError::NotActive { key_id, state } => {
                write!(f, "key '{key_id}' is {state:?} and may not sign")
            }
            KeyError::NotYetValid {
                key_id,
                not_before,
            } => write!(f, "key '{key_id}' is not valid before {not_before}"),
            KeyError::Expired { key_id, not_after } => {
                write!(f, "key '{key_id}' expired at {not_after}")
            }
            KeyError::Revoked { key_id } => write!(f, "key '{key_id}' is revoked"),
            KeyError::Destroyed { key_id } => write!(f, "key '{key_id}' was zeroized"),
            KeyError::NoActiveKey { domain } => {
                write!(f, "no active key in domain {domain}")
            }
            KeyError::SignatureInvalid { key_id } => {
                write!(f, "signature verification failed for '{key_id}'")
            }
            KeyError::CustodianKeyMissing { key_id } => {
                write!(f, "custodian does not hold key '{key_id}'")
            }
            KeyError::ApprovalInvalid { reason } => {
                write!(f, "quorum approval invalid: {reason}")
            }
        }
    }
}

impl std::error::Error for KeyError {}

/// The domain-scoped key registry.
///
/// Holds public records only; signing is delegated to a [`KeyCustodian`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRegistry {
    records: BTreeMap<String, KeyRecord>,
    revocations: Vec<RevocationRecord>,
}

impl KeyRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        KeyRegistry::default()
    }

    /// Register an initial key record (from a ceremony or the custodian).
    pub fn register(&mut self, record: KeyRecord) -> Result<(), KeyError> {
        if self.records.contains_key(&record.key_id) {
            return Err(KeyError::DuplicateKey {
                key_id: record.key_id,
            });
        }
        self.records.insert(record.key_id.clone(), record);
        Ok(())
    }

    /// Look up one record.
    pub fn record(&self, key_id: &str) -> Option<&KeyRecord> {
        self.records.get(key_id)
    }

    /// All records in a domain, ordered by key id.
    pub fn records_in(&self, domain: KeyDomain) -> Vec<&KeyRecord> {
        self.records
            .values()
            .filter(|record| record.domain == domain)
            .collect()
    }

    /// The key allowed to sign new artefacts in `domain` at `now`.
    pub fn active_key(&self, domain: KeyDomain, now: i64) -> Option<&KeyRecord> {
        self.records
            .values()
            .find(|record| record.domain == domain && record.can_sign_at(now))
    }

    /// All revocation entries.
    pub fn revocations(&self) -> &[RevocationRecord] {
        &self.revocations
    }

    /// Whether `key_id` is revoked as of `now`.
    pub fn is_revoked_at(&self, key_id: &str, now: i64) -> bool {
        self.revocations
            .iter()
            .any(|entry| entry.key_id == key_id && entry.effective_at <= now)
    }

    /// The distributable revocation list.
    pub fn revocation_list(&self) -> RevocationList {
        RevocationList {
            entries: self.revocations.clone(),
        }
    }

    /// Bytes signed for `artefact` in `domain`.
    ///
    /// Domain separation is part of the signed message, so a signature minted
    /// for one domain cannot be replayed in another.
    pub fn signing_bytes(domain: KeyDomain, artefact: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(24 + domain.as_str().len() + artefact.len());
        bytes.extend_from_slice(b"TirBase/v1/KeyDomain/");
        bytes.extend_from_slice(domain.as_str().as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(artefact);
        bytes
    }

    /// Sign a new artefact with the domain's active key.
    pub fn sign(
        &self,
        custodian: &dyn KeyCustodian,
        domain: KeyDomain,
        artefact: &[u8],
        now: i64,
    ) -> Result<SignedArtefact, KeyError> {
        let key_id = self
            .active_key(domain, now)
            .ok_or(KeyError::NoActiveKey { domain })?
            .key_id
            .clone();
        self.sign_with_key(custodian, domain, &key_id, artefact, now)
    }

    /// Sign with a specific key. Requires the key to be `Active` and inside
    /// its validity window, which is what stops a rotated-out key from
    /// producing new artefacts.
    pub fn sign_with_key(
        &self,
        custodian: &dyn KeyCustodian,
        domain: KeyDomain,
        key_id: &str,
        artefact: &[u8],
        now: i64,
    ) -> Result<SignedArtefact, KeyError> {
        let record = self
            .records
            .get(key_id)
            .ok_or_else(|| KeyError::UnknownKey {
                key_id: key_id.to_string(),
            })?;
        if record.domain != domain {
            return Err(KeyError::DomainMismatch {
                expected: domain,
                actual: record.domain,
            });
        }
        if record.state != KeyState::Active {
            return Err(KeyError::NotActive {
                key_id: key_id.to_string(),
                state: record.state,
            });
        }
        if !record.window_contains(now) {
            return Err(KeyError::Expired {
                key_id: key_id.to_string(),
                not_after: record.not_after,
            });
        }
        let message = Self::signing_bytes(domain, artefact);
        let signature = custodian.sign(domain, key_id, &message)?;
        Ok(SignedArtefact {
            domain,
            key_id: key_id.to_string(),
            version: record.version,
            signature,
        })
    }

    /// Verify `signature` over `artefact` under `key_id` at `now`.
    ///
    /// A `Retiring` key is accepted inside its overlap window and rejected
    /// afterwards; a `Revoked` or `Destroyed` key is always rejected.
    pub fn verify_artefact(
        &self,
        domain: KeyDomain,
        key_id: &str,
        artefact: &[u8],
        signature: &DeviceSignature,
        now: i64,
    ) -> Result<(), KeyError> {
        let record = self
            .records
            .get(key_id)
            .ok_or_else(|| KeyError::UnknownKey {
                key_id: key_id.to_string(),
            })?;
        if record.domain != domain {
            return Err(KeyError::DomainMismatch {
                expected: domain,
                actual: record.domain,
            });
        }
        if record.state == KeyState::Destroyed {
            return Err(KeyError::Destroyed {
                key_id: key_id.to_string(),
            });
        }
        if record.state == KeyState::Revoked || self.is_revoked_at(key_id, now) {
            return Err(KeyError::Revoked {
                key_id: key_id.to_string(),
            });
        }
        if record.state == KeyState::Pending {
            return Err(KeyError::NotActive {
                key_id: key_id.to_string(),
                state: record.state,
            });
        }
        if now < record.not_before {
            return Err(KeyError::NotYetValid {
                key_id: key_id.to_string(),
                not_before: record.not_before,
            });
        }
        if now > record.not_after {
            return Err(KeyError::Expired {
                key_id: key_id.to_string(),
                not_after: record.not_after,
            });
        }

        let message = Self::signing_bytes(domain, artefact);
        let public_key: [u8; 32] =
            record
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| KeyError::SignatureInvalid {
                    key_id: key_id.to_string(),
                })?;
        let DeviceSignature::Ed25519(bytes) = signature else {
            return Err(KeyError::SignatureInvalid {
                key_id: key_id.to_string(),
            });
        };
        keypair::verify(&public_key, &message, &Ed25519Signature::from_bytes(*bytes)).map_err(
            |_| KeyError::SignatureInvalid {
                key_id: key_id.to_string(),
            },
        )
    }

    /// Rotate a domain: activate `new_key_id` and retire the current active
    /// key with a bounded overlap window.
    ///
    /// The retiring key keeps verifying until `min(existing not_after,
    /// now + overlap_secs)` and can never sign a new artefact.
    pub fn rotate(
        &mut self,
        custodian: &dyn KeyCustodian,
        domain: KeyDomain,
        new_key_id: &str,
        now: i64,
        overlap_secs: i64,
        validity_secs: i64,
    ) -> Result<RotationReceipt, KeyError> {
        if self.records.contains_key(new_key_id) {
            return Err(KeyError::DuplicateKey {
                key_id: new_key_id.to_string(),
            });
        }

        let overlap_ends_at = now.saturating_add(overlap_secs);
        let previous_key_id = self
            .records
            .values()
            .find(|record| record.domain == domain && record.state == KeyState::Active)
            .map(|record| record.key_id.clone());

        for record in self.records.values_mut() {
            if record.domain == domain && record.state == KeyState::Active {
                record.state = KeyState::Retiring;
                record.not_after = record.not_after.min(overlap_ends_at);
            }
        }

        let next_version = self
            .records
            .values()
            .filter(|record| record.domain == domain)
            .map(|record| record.version)
            .max()
            .unwrap_or(0)
            .saturating_add(1);

        let not_after = now.saturating_add(validity_secs);
        let record = custodian.generate(domain, new_key_id, next_version, now, not_after)?;
        self.register(record)?;

        Ok(RotationReceipt {
            domain,
            previous_key_id,
            new_key_id: new_key_id.to_string(),
            new_version: next_version,
            rotated_at: now,
            overlap_ends_at,
        })
    }

    /// Revoke one key. Other domains and keys are untouched.
    pub fn revoke(
        &mut self,
        domain: KeyDomain,
        key_id: &str,
        reason: RevocationReason,
        now: i64,
    ) -> Result<RevocationRecord, KeyError> {
        let record = self
            .records
            .get_mut(key_id)
            .ok_or_else(|| KeyError::UnknownKey {
                key_id: key_id.to_string(),
            })?;
        if record.domain != domain {
            return Err(KeyError::DomainMismatch {
                expected: domain,
                actual: record.domain,
            });
        }

        if let Some(existing) = self
            .revocations
            .iter()
            .find(|entry| entry.key_id == key_id)
        {
            return Ok(existing.clone());
        }

        record.state = KeyState::Revoked;
        let entry = RevocationRecord {
            domain,
            key_id: key_id.to_string(),
            version: record.version,
            reason,
            effective_at: now,
        };
        self.revocations.push(entry.clone());
        Ok(entry)
    }

    /// Recover a domain key under a quorum approval.
    ///
    /// The approval must target [`RecoveryOperation::Recover`], name this
    /// domain, be unexpired, and carry the threshold of distinct custodians.
    pub fn recover(
        &mut self,
        custodian: &dyn KeyCustodian,
        approval: &QuorumApproval,
        domain: KeyDomain,
        new_key_id: &str,
        now: i64,
        validity_secs: i64,
    ) -> Result<RotationReceipt, KeyError> {
        self.check_approval(approval, RecoveryOperation::Recover, domain, now)?;
        if let Some(reference) = &approval.reference_key_id {
            if !self.records.contains_key(reference) {
                return Err(KeyError::UnknownKey {
                    key_id: reference.clone(),
                });
            }
        }
        // Recovery restores service immediately: no overlap window is needed
        // because the recovered key is the same logical authority.
        self.rotate(custodian, domain, new_key_id, now, 0, validity_secs)
    }

    /// Disaster re-key of the root domain under a quorum approval.
    ///
    /// Cross-signs the transition by keeping the old root valid for a bounded
    /// bridge window rather than immediately invalidating every device.
    pub fn disaster_rekey_root(
        &mut self,
        custodian: &dyn KeyCustodian,
        approval: &QuorumApproval,
        new_root_key_id: &str,
        now: i64,
        validity_secs: i64,
        bridge_secs: i64,
    ) -> Result<(RotationReceipt, BridgeWindow), KeyError> {
        self.check_approval(
            approval,
            RecoveryOperation::DisasterRekey,
            KeyDomain::RootCa,
            now,
        )?;
        let receipt = self.rotate(
            custodian,
            KeyDomain::RootCa,
            new_root_key_id,
            now,
            bridge_secs,
            validity_secs,
        )?;
        let old_root_key_id = receipt
            .previous_key_id
            .clone()
            .ok_or_else(|| KeyError::ApprovalInvalid {
                reason: "disaster re-key requires an existing root key to bridge from".to_string(),
            })?;
        let bridge = BridgeWindow {
            old_root_key_id,
            new_root_key_id: new_root_key_id.to_string(),
            not_after: receipt.overlap_ends_at,
        };
        Ok((receipt, bridge))
    }

    fn check_approval(
        &self,
        approval: &QuorumApproval,
        operation: RecoveryOperation,
        domain: KeyDomain,
        now: i64,
    ) -> Result<(), KeyError> {
        if approval.operation != operation {
            return Err(KeyError::ApprovalInvalid {
                reason: format!(
                    "approval is for {:?}, operation requires {operation:?}",
                    approval.operation
                ),
            });
        }
        if approval.domain != domain {
            return Err(KeyError::DomainMismatch {
                expected: domain,
                actual: approval.domain,
            });
        }
        if !approval.is_satisfied(now) {
            return Err(KeyError::ApprovalInvalid {
                reason: format!(
                    "{} distinct approval(s) of {} required, or approval expired at {}",
                    approval.distinct_approvals(),
                    approval.threshold,
                    approval.expires_at
                ),
            });
        }
        Ok(())
    }

    /// Decommission a key: zeroize the material and mark the record destroyed.
    ///
    /// The public record and revocation history are retained so artefacts
    /// signed by the key fail closed and remain auditable.
    pub fn decommission(
        &mut self,
        custodian: &dyn KeyCustodian,
        domain: KeyDomain,
        key_id: &str,
        now: i64,
    ) -> Result<ZeroizeReceipt, KeyError> {
        let record = self
            .records
            .get_mut(key_id)
            .ok_or_else(|| KeyError::UnknownKey {
                key_id: key_id.to_string(),
            })?;
        if record.domain != domain {
            return Err(KeyError::DomainMismatch {
                expected: domain,
                actual: record.domain,
            });
        }
        let receipt = custodian.zeroize(key_id, now)?;
        record.state = KeyState::Destroyed;
        Ok(receipt)
    }

    /// Compromised-device path: revoke the device identity key with reason
    /// `KeyCompromise` and zeroize it in the same operation.
    pub fn compromised_device(
        &mut self,
        custodian: &dyn KeyCustodian,
        key_id: &str,
        evidence_ref: &str,
        now: i64,
    ) -> Result<CompromiseRecord, KeyError> {
        self.revoke(
            KeyDomain::DeviceIdentity,
            key_id,
            RevocationReason::KeyCompromise,
            now,
        )?;
        let zeroize = self.decommission(custodian, KeyDomain::DeviceIdentity, key_id, now)?;
        Ok(CompromiseRecord {
            key_id: key_id.to_string(),
            evidence_ref: evidence_ref.to_string(),
            revoked_at: now,
            zeroize,
        })
    }
}

/// A distributable set of revocations.
///
/// Devices apply this list instead of re-keying: only the listed keys are
/// rejected.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationList {
    entries: Vec<RevocationRecord>,
}

impl RevocationList {
    /// Revocation entries in this list.
    pub fn entries(&self) -> &[RevocationRecord] {
        &self.entries
    }

    /// Whether `key_id` is revoked as of `now`.
    pub fn contains(&self, key_id: &str, now: i64) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.key_id == key_id && entry.effective_at <= now)
    }

    /// Apply every entry to `registry`, returning how many keys were newly
    /// revoked. Keys absent from this registry are ignored.
    pub fn apply_to(&self, registry: &mut KeyRegistry) -> usize {
        let mut applied = 0;
        for entry in &self.entries {
            let Some(record) = registry.records.get_mut(&entry.key_id) else {
                continue;
            };
            if record.state != KeyState::Revoked {
                record.state = KeyState::Revoked;
                applied += 1;
            }
            if !registry
                .revocations
                .iter()
                .any(|existing| existing.key_id == entry.key_id)
            {
                registry.revocations.push(entry.clone());
            }
        }
        applied
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    fn custodian_with_key(domain: KeyDomain, key_id: &str) -> (SoftwareCustodian, KeyRegistry) {
        let custodian = SoftwareCustodian::new();
        let mut registry = KeyRegistry::new();
        let record = custodian
            .generate(domain, key_id, 1, 1_000, 100_000)
            .expect("generate");
        registry.register(record).expect("register");
        (custodian, registry)
    }

    #[test]
    fn domains_are_independent_and_signatures_are_domain_separated() {
        let (custodian, registry) = custodian_with_key(KeyDomain::UpdateSigner, "update-1");
        let artefact = b"release-manifest";
        let signed = registry
            .sign(&custodian, KeyDomain::UpdateSigner, artefact, 2_000)
            .expect("sign");

        signed
            .verify(&registry, artefact, 2_000)
            .expect("active key verifies its own artefact");

        // Replaying the same bytes under another domain must fail, even
        // though the key exists and the signature is genuine.
        assert_eq!(
            registry.verify_artefact(
                KeyDomain::PolicyAuthority,
                "update-1",
                artefact,
                &signed.signature,
                2_000
            ),
            Err(KeyError::DomainMismatch {
                expected: KeyDomain::PolicyAuthority,
                actual: KeyDomain::UpdateSigner,
            })
        );
    }

    #[test]
    fn rotation_moves_the_old_key_to_retiring_with_an_overlap() {
        let (custodian, mut registry) = custodian_with_key(KeyDomain::UpdateSigner, "update-1");
        let receipt = registry
            .rotate(
                &custodian,
                KeyDomain::UpdateSigner,
                "update-2",
                1_500,
                100,
                10_000,
            )
            .expect("rotate");

        assert_eq!(receipt.previous_key_id.as_deref(), Some("update-1"));
        assert_eq!(receipt.overlap_ends_at, 1_600);
        assert_eq!(
            registry.record("update-1").unwrap().state,
            KeyState::Retiring
        );
        assert_eq!(registry.record("update-1").unwrap().not_after, 1_600);
        assert_eq!(registry.record("update-2").unwrap().state, KeyState::Active);
        assert_eq!(
            registry.active_key(KeyDomain::UpdateSigner, 1_500).unwrap().key_id,
            "update-2"
        );

        // A rotated-out key can never sign a new artefact, even during the
        // overlap window.
        assert_eq!(
            registry.sign_with_key(
                &custodian,
                KeyDomain::UpdateSigner,
                "update-1",
                b"new-artefact",
                1_550
            ),
            Err(KeyError::NotActive {
                key_id: "update-1".to_string(),
                state: KeyState::Retiring,
            })
        );
    }

    #[test]
    fn revocation_of_one_domain_leaves_other_domains_untouched() {
        let custodian = SoftwareCustodian::new();
        let mut registry = KeyRegistry::new();
        for (domain, key_id) in [
            (KeyDomain::UpdateSigner, "update-1"),
            (KeyDomain::DeviceIdentity, "device-1"),
            (KeyDomain::TenantWrapping, "tenant-1"),
        ] {
            let record = custodian
                .generate(domain, key_id, 1, 1_000, 100_000)
                .expect("generate");
            registry.register(record).expect("register");
        }

        let device_before = registry.record("device-1").unwrap().clone();
        let tenant_before = registry.record("tenant-1").unwrap().clone();

        registry
            .revoke(
                KeyDomain::UpdateSigner,
                "update-1",
                RevocationReason::KeyCompromise,
                2_000,
            )
            .expect("revoke");

        assert_eq!(registry.record("device-1").unwrap(), &device_before);
        assert_eq!(registry.record("tenant-1").unwrap(), &tenant_before);
        assert_eq!(
            registry.record("update-1").unwrap().state,
            KeyState::Revoked
        );
    }

    #[test]
    fn quorum_recovery_requires_the_threshold() {
        let (custodian, mut registry) = custodian_with_key(KeyDomain::RootCa, "root-1");
        let policy = QuorumPolicy::new(2, 3).expect("policy");
        let approval = |count: usize| {
            let approvals = (0..count)
                .map(|i| CustodianApproval {
                    custodian_id: format!("custodian-{i}"),
                    share_commitment: vec![i as u8; 32],
                    signed_at: 1_400,
                })
                .collect();
            QuorumApproval::new(
                RecoveryOperation::Recover,
                KeyDomain::RootCa,
                Some("root-1".to_string()),
                policy,
                approvals,
                1_400,
                9_999,
            )
        };

        assert!(matches!(
            registry.recover(
                &custodian,
                &approval(1),
                KeyDomain::RootCa,
                "root-2",
                1_500,
                100_000
            ),
            Err(KeyError::ApprovalInvalid { .. })
        ));

        registry
            .recover(
                &custodian,
                &approval(2),
                KeyDomain::RootCa,
                "root-2",
                1_500,
                100_000,
            )
            .expect("two distinct approvals satisfy 2-of-3");
    }

    #[test]
    fn decommission_zeroizes_and_fails_closed() {
        let (custodian, mut registry) =
            custodian_with_key(KeyDomain::TenantWrapping, "tenant-1");
        let signed = registry
            .sign(&custodian, KeyDomain::TenantWrapping, b"dek", 2_000)
            .expect("sign");

        let receipt = registry
            .decommission(&custodian, KeyDomain::TenantWrapping, "tenant-1", 2_100)
            .expect("decommission");
        assert!(!receipt.already_destroyed);

        assert_eq!(
            registry.verify_artefact(
                KeyDomain::TenantWrapping,
                "tenant-1",
                b"dek",
                &signed.signature,
                2_100
            ),
            Err(KeyError::Destroyed {
                key_id: "tenant-1".to_string()
            })
        );
        assert_eq!(
            custodian.sign(KeyDomain::TenantWrapping, "tenant-1", b"x"),
            Err(KeyError::Destroyed {
                key_id: "tenant-1".to_string()
            })
        );

        // Idempotent replay is reported, never panics.
        let replay = registry
            .decommission(&custodian, KeyDomain::TenantWrapping, "tenant-1", 2_200)
            .expect("replay");
        assert!(replay.already_destroyed);
    }
}
