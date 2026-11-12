//! Per-device enrollment epoch, enrollment nonce store, and the Stage 8 epoch
//! check (8.8 — CLAIM-8.5…CLAIM-8.8, PV-3.11, PV-3.13, PV-5.5,
//! PV-9.8, PV-9.8/RD-2).
//!
//! # Per-device epoch (PV-5.5, PV-9.8, RD-2)
//!
//! The epoch is keyed by **device**, not issuer. It starts at 0 on first
//! enrollment and is bumped only by a [`SignedOperation<EpochBump>`] carrying
//! PolicyAuthority **and** RevocationManager co-signatures. Every command
//! carries the `enrollment_epoch` observed at creation time; Stage 8 of
//! [`CommandGuard::admit`] rejects any command whose epoch is not the device's
//! current epoch. After a restore (S22) the operator bumps the epoch, and every
//! command produced from the restored snapshot is rejected as stale.
//!
//! # Epoch regression ()
//!
//! Peers and issuers remember the highest epoch they have witnessed for a
//! device. A report of a lower epoch is an [`EpochError::EpochRegression`] and
//! emits a [`ReasonCode::EpochRegression`] security event before the report is
//! rejected.
//!
//! # Enrollment nonce store (PV-3.13)
//!
//! The bootstrap message carries a one-time nonce. [`EnrollmentNonceStore`]
//! records nonces with a bounded retention (default 72 hours) and a background
//! purge removes expired entries. A reused nonce inside the retention window
//! is rejected as [`EpochError::NonceReused`].

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tirbase_core::crdt::delta::Ed25519Signature;
use tirbase_core::events::{emit, ReasonCode, SecurityEvent, SecurityEventCategory, Severity};
use tirbase_core::identity::keypair;
use tirbase_types::{CommandRole, DeviceSignature};

use crate::signed_operation::{SignedOperation, SignedOperationError, SignedOperationPayload};
use crate::trust_root::{TrustRootError, TrustRootRecord};

/// Default enrollment nonce retention: 72 hours (PV-3.13).
pub const DEFAULT_ENROLLMENT_NONCE_RETENTION_SECS: i64 = 72 * 60 * 60;

/// Default upper bound on retained enrollment nonces.
pub const DEFAULT_ENROLLMENT_NONCE_CAPACITY: usize = 100_000;

// ─── Errors ──────────────────────────────────────────────────────────────────

/// Enrollment, epoch, and nonce-store failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochError {
 /// The device has no epoch row yet.
    UnknownDevice(String),
 /// The command was produced under an older epoch (S22).
    StaleEpoch {
 /// Command epoch.
        command_epoch: u64,
 /// Device's current epoch.
        current_epoch: u64,
    },
 /// The command claims an epoch the device has not reached yet.
    FutureEpoch {
 /// Command epoch.
        command_epoch: u64,
 /// Device's current epoch.
        current_epoch: u64,
    },
 /// A peer/issuer observed a lower epoch than previously witnessed.
    EpochRegression {
 /// Device whose epoch regressed.
        device_id: String,
 /// Highest epoch previously witnessed.
        witnessed: u64,
 /// Lower epoch in the new report.
        reported: u64,
    },
 /// The bootstrap nonce was already recorded.
    NonceReused,
 /// The enrolling device's DID/public key/signature is invalid.
    InvalidIdentity(String),
 /// The scoped token could not be minted.
    TokenIssuance(String),
 /// The signer is not a RevocationManager.
    RevocationManagerRequired {
 /// Role presented by the caller.
        role: CommandRole,
    },
 /// A signed epoch bump does not match the current device state.
    EpochSequenceMismatch {
 /// Epoch in the signed operation.
        expected: u64,
 /// Current device epoch.
        current: u64,
    },
 /// The `SignedOperation` envelope failed verification.
    SignedOperation(SignedOperationError),
 /// Trust-root role/threshold verification failed.
    TrustRoot(TrustRootError),
 /// Durable store failure.
    Store(String),
}

impl fmt::Display for EpochError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EpochError::UnknownDevice(device) => write!(f, "unknown device: {device}"),
            EpochError::StaleEpoch {
                command_epoch,
                current_epoch,
            } => write!(
                f,
                "stale enrollment epoch: command epoch {command_epoch} < device epoch {current_epoch}"
            ),
            EpochError::FutureEpoch {
                command_epoch,
                current_epoch,
            } => write!(
                f,
                "future enrollment epoch: command epoch {command_epoch} > device epoch {current_epoch}"
            ),
            EpochError::EpochRegression {
                device_id,
                witnessed,
                reported,
            } => write!(
                f,
                "epoch regression for {device_id}: witnessed {witnessed}, reported {reported}"
            ),
            EpochError::NonceReused => {
                write!(f, "enrollment nonce reused inside its retention window")
            }
            EpochError::InvalidIdentity(reason) => {
                write!(f, "invalid enrollment identity: {reason}")
            }
            EpochError::TokenIssuance(reason) => {
                write!(f, "enrollment token issuance failed: {reason}")
            }
            EpochError::RevocationManagerRequired { role } => write!(
                f,
                "decommission requires a RevocationManager credential, got {}",
                role.as_str()
            ),
            EpochError::EpochSequenceMismatch { expected, current } => write!(
                f,
                "epoch bump sequence mismatch: operation expects current epoch {expected}, device is at {current}"
            ),
            EpochError::SignedOperation(error) => write!(f, "{error}"),
            EpochError::TrustRoot(error) => write!(f, "{error}"),
            EpochError::Store(reason) => write!(f, "epoch store error: {reason}"),
        }
    }
}

impl std::error::Error for EpochError {}

impl From<SignedOperationError> for EpochError {
    fn from(error: SignedOperationError) -> Self {
        EpochError::SignedOperation(error)
    }
}

impl From<TrustRootError> for EpochError {
    fn from(error: TrustRootError) -> Self {
        EpochError::TrustRoot(error)
    }
}

// ─── Device epoch record ─────────────────────────────────────────────────────

/// Durable per-device epoch row (`device_epoch` table).
///
/// `co_sig_pa` / `co_sig_rm` are `None` only for the epoch-0 row created at
/// first enrollment (design §4.13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEpoch {
 /// Device the epoch belongs to.
    pub device_id: String,
 /// Current epoch (starts at 0).
    pub epoch: u64,
 /// Authenticated-time timestamp of the last bump.
    pub bumped_at_est: i64,
 /// PolicyAuthority co-signature over the bump (None at epoch 0).
    pub co_sig_pa: Option<DeviceSignature>,
 /// RevocationManager co-signature over the bump (None at epoch 0).
    pub co_sig_rm: Option<DeviceSignature>,
}

/// Durable store for [`DeviceEpoch`] rows.
pub trait DeviceEpochStore: Send + Sync + fmt::Debug {
 /// Load the epoch row for `device_id`.
    fn load(&self, device_id: &str) -> Result<Option<DeviceEpoch>, EpochError>;
 /// Insert or update the epoch row.
    fn save(&self, record: &DeviceEpoch) -> Result<(), EpochError>;
}

/// In-memory [`DeviceEpochStore`] used by tests and single-process tooling.
#[derive(Debug, Default)]
pub struct InMemoryEpochStore {
    rows: Mutex<BTreeMap<String, DeviceEpoch>>,
}

impl DeviceEpochStore for InMemoryEpochStore {
    fn load(&self, device_id: &str) -> Result<Option<DeviceEpoch>, EpochError> {
        Ok(match self.rows.lock() {
            Ok(guard) => guard.get(device_id).cloned(),
            Err(poisoned) => poisoned.into_inner().get(device_id).cloned(),
        })
    }

    fn save(&self, record: &DeviceEpoch) -> Result<(), EpochError> {
        match self.rows.lock() {
            Ok(mut guard) => guard.insert(record.device_id.clone(), record.clone()),
            Err(poisoned) => poisoned
                .into_inner()
                .insert(record.device_id.clone(), record.clone()),
        };
        Ok(())
    }
}

// ─── Epoch bump payload ─────────────────────────────────────────────────────

/// Signed enrollment-epoch bump payload ().
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochBump {
 /// Device whose epoch is bumped.
    pub device_id: String,
 /// Epoch the bump expects to replace (must equal the current epoch).
    pub previous_epoch: u64,
 /// New epoch (must be `previous_epoch + 1`).
    pub new_epoch: u64,
 /// Human-readable reason (e.g. "snapshot restore").
    pub reason: String,
}

impl SignedOperationPayload for EpochBump {
    const CONTEXT: &'static str = crate::signed_operation::CONTEXT_EPOCH_BUMP;
}

// ─── Epoch registry ─────────────────────────────────────────────────────────

/// Per-device epoch manager with peer/issuer regression detection.
#[derive(Debug)]
pub struct EpochRegistry {
    store: Arc<dyn DeviceEpochStore>,
 /// Highest epoch witnessed per device (peers and issuers).
    witnessed: Mutex<BTreeMap<String, u64>>,
}

impl EpochRegistry {
 /// Construct a registry over `store`.
    pub fn new(store: Arc<dyn DeviceEpochStore>) -> Self {
        EpochRegistry {
            store,
            witnessed: Mutex::new(BTreeMap::new()),
        }
    }

 /// Create the epoch-0 row for a newly enrolled device, or return the
 /// existing row unchanged (first enrollment starts at 0).
    pub fn ensure_enrolled(
        &self,
        device_id: &str,
        now_est: i64,
    ) -> Result<DeviceEpoch, EpochError> {
        if let Some(record) = self.store.load(device_id)? {
            return Ok(record);
        }
        let record = DeviceEpoch {
            device_id: device_id.to_string(),
            epoch: 0,
            bumped_at_est: now_est,
            co_sig_pa: None,
            co_sig_rm: None,
        };
        self.store.save(&record)?;
        Ok(record)
    }

 /// Current epoch for `device_id`.
    pub fn current_epoch(&self, device_id: &str) -> Result<u64, EpochError> {
        self.store
            .load(device_id)?
            .map(|record| record.epoch)
            .ok_or_else(|| EpochError::UnknownDevice(device_id.to_string()))
    }

 /// Full epoch row for `device_id`.
    pub fn current_record(&self, device_id: &str) -> Result<Option<DeviceEpoch>, EpochError> {
        self.store.load(device_id)
    }

 /// Stage 8 epoch check: a command is admitted only when its
 /// `enrollment_epoch` equals the device's current epoch.
 ///
 /// Older epochs are rejected with [`EpochError::StaleEpoch`] (S22); epochs
 /// the device has not reached are rejected with [`EpochError::FutureEpoch`].
 /// This is called from [`CommandGuard::admit`].
    pub fn check_command_epoch(
        &self,
        device_id: &str,
        command_epoch: u64,
    ) -> Result<(), EpochError> {
        let current = self.current_epoch(device_id)?;
        if command_epoch < current {
            return Err(EpochError::StaleEpoch {
                command_epoch,
                current_epoch: current,
            });
        }
        if command_epoch > current {
            return Err(EpochError::FutureEpoch {
                command_epoch,
                current_epoch: current,
            });
        }
        Ok(())
    }

 /// Atomically advance the device epoch as part of an operator restore
 /// ( `POST /admin/restore`).
 ///
 /// The admin layer verifies the joint PolicyAuthority + RevocationManager
 /// restore operation before calling this; the epoch increment itself is a
 /// durability step (RD-2: restoring from backup increments the enrollment
 /// epoch so prior-epoch commands can never be replayed).
    pub fn restore_bump(
        &self,
        device_id: &str,
        reason: &str,
        now_est: i64,
    ) -> Result<DeviceEpoch, EpochError> {
        let current = self.store.load(device_id)?;
        let current_epoch = current.as_ref().map(|r| r.epoch).unwrap_or(0);
        let new_epoch = current_epoch
            .checked_add(1)
            .ok_or_else(|| EpochError::Store("epoch counter overflow".to_string()))?;
        let record = DeviceEpoch {
            device_id: device_id.to_string(),
            epoch: new_epoch,
            bumped_at_est: now_est,
            co_sig_pa: None,
            co_sig_rm: None,
        };
        self.store.save(&record)?;
        self.observe_epoch(device_id, new_epoch)?;
        emit(
            SecurityEvent::new(
                SecurityEventCategory::Enrollment,
                Severity::High,
                ReasonCode::EpochBumped,
            )
            .with_target(device_id.to_string())
            .with_detail(format!(
                "restore bumped device epoch {current_epoch} -> {new_epoch} ({reason}); \
                 prior-epoch commands are rejected"
            )),
        );
        Ok(record)
    }

 /// Apply a signed epoch bump ().
 ///
 /// Verification order:
 /// 1. bind the operation to the payload and context,
 /// 2. check the policy-authority co-signature against the role registry and
 /// threshold (role-registry lookup happens before signature checks),
 /// 3. check the revocation-manager co-signature the same way,
 /// 4. require `previous_epoch == current` and `new_epoch == current + 1`,
 /// 5. durably commit the new row, then update the witnessed epoch.
    pub fn apply_bump(
        &self,
        operation: &SignedOperation<EpochBump>,
        payload: &EpochBump,
        trust_root: &TrustRootRecord,
        now_est: i64,
    ) -> Result<DeviceEpoch, EpochError> {
        operation.verify_payload(payload)?;

        let policy_authority: Vec<_> = operation
            .signatures
            .iter()
            .filter(|entry| entry.role == CommandRole::PolicyAuthority)
            .cloned()
            .collect();
        trust_root.verify_role_signatures(
            CommandRole::PolicyAuthority,
            &operation.signing_bytes(),
            &policy_authority,
        )?;

        let revocation_manager: Vec<_> = operation
            .signatures
            .iter()
            .filter(|entry| entry.role == CommandRole::RevocationManager)
            .cloned()
            .collect();
        trust_root.verify_role_signatures(
            CommandRole::RevocationManager,
            &operation.signing_bytes(),
            &revocation_manager,
        )?;

        let current = self
            .store
            .load(&payload.device_id)?
            .ok_or_else(|| EpochError::UnknownDevice(payload.device_id.clone()))?;
        if payload.previous_epoch != current.epoch {
            return Err(EpochError::EpochSequenceMismatch {
                expected: payload.previous_epoch,
                current: current.epoch,
            });
        }
        let expected_new = current
            .epoch
            .checked_add(1)
            .ok_or_else(|| EpochError::Store("epoch counter overflow".to_string()))?;
        if payload.new_epoch != expected_new {
            return Err(EpochError::EpochSequenceMismatch {
                expected: expected_new,
                current: current.epoch,
            });
        }

 // The epoch may not move backwards even if the payload claims it does.
        self.observe_epoch(&payload.device_id, payload.new_epoch)?;

        let co_sig_pa = policy_authority
            .first()
            .map(|entry| entry.signature.clone());
        let co_sig_rm = revocation_manager
            .first()
            .map(|entry| entry.signature.clone());
        let record = DeviceEpoch {
            device_id: payload.device_id.clone(),
            epoch: payload.new_epoch,
            bumped_at_est: now_est,
            co_sig_pa,
            co_sig_rm,
        };
        self.store.save(&record)?;

        emit(
            SecurityEvent::new(
                SecurityEventCategory::Enrollment,
                Severity::High,
                ReasonCode::EpochBumped,
            )
            .with_target(payload.device_id.clone())
            .with_detail(format!(
                "device epoch bumped {} -> {} ({}); prior-epoch commands are now rejected",
                payload.previous_epoch, payload.new_epoch, payload.reason
            )),
        );

        Ok(record)
    }

 /// Observe a device's reported epoch (peer/issuer path).
 ///
 /// A report lower than the highest previously witnessed value emits an
 /// [`ReasonCode::EpochRegression`] event and is rejected; a higher value
 /// advances the witnessed watermark.
    pub fn observe_epoch(&self, device_id: &str, reported: u64) -> Result<(), EpochError> {
        let mut witnessed = match self.witnessed.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let previous = witnessed.get(device_id).copied();
        if let Some(previous) = previous {
            if reported < previous {
                drop(witnessed);
                emit(
                    SecurityEvent::new(
                        SecurityEventCategory::Enrollment,
                        Severity::High,
                        ReasonCode::EpochRegression,
                    )
                    .with_target(device_id.to_string())
                    .with_detail(format!(
                        "device reported epoch {reported} after previously witnessing {previous}"
                    )),
                );
                return Err(EpochError::EpochRegression {
                    device_id: device_id.to_string(),
                    witnessed: previous,
                    reported,
                });
            }
        }
        witnessed.insert(device_id.to_string(), reported);
        Ok(())
    }

 /// Highest epoch this process has witnessed for `device_id`.
    pub fn witnessed_epoch(&self, device_id: &str) -> Option<u64> {
        match self.witnessed.lock() {
            Ok(guard) => guard.get(device_id).copied(),
            Err(poisoned) => poisoned.into_inner().get(device_id).copied(),
        }
    }
}

// ─── Stage 8 guard ──────────────────────────────────────────────────────────

/// Minimal command envelope consumed by the Stage 8 epoch check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandEnvelope {
 /// Device the command targets (the local device identity).
    pub device_id: String,
 /// Issuer DID.
    pub issuer_did: String,
 /// Enrollment epoch stamped at command creation.
    pub enrollment_epoch: u64,
}

/// Command guard.
///
/// wires **Stage 8** — the enrollment-epoch check — into
/// [`CommandGuard::admit`]. The remaining pipeline stages (authentication,
/// token scope, envelope, replay, effects) are added by their own tasks; this
/// type deliberately contains only what owns so the epoch check is
/// unmistakably a production path rather than dead scaffolding.
#[derive(Debug)]
pub struct EpochCommandGuard {
    epochs: Arc<EpochRegistry>,
}

impl EpochCommandGuard {
 /// Construct a guard over `epochs`.
    pub fn new(epochs: Arc<EpochRegistry>) -> Self {
        EpochCommandGuard { epochs }
    }

 /// Admit `command`, applying Stage 8 (PV-5.5, PV-9.8).
 ///
 /// A prior-epoch command is rejected with [`EpochError::StaleEpoch`] after
 /// a signed epoch bump (scenario S22). Removing this check would let a
 /// restored snapshot's commands through; `prior_epoch_command_is_rejected_
 /// after_bump` is the wiring-mutation test.
    pub fn admit(&self, command: &CommandEnvelope) -> Result<(), EpochError> {
 // ── Stage 8: enrollment epoch (PV-5.5, PV-9.8) ─────────────────────
        self.epochs
            .check_command_epoch(&command.device_id, command.enrollment_epoch)?;
        Ok(())
    }

 /// Borrow the epoch registry (used by the admin epoch-bump endpoint).
    pub fn epochs(&self) -> &Arc<EpochRegistry> {
        &self.epochs
    }
}

// ─── Enrollment nonce store ─────────────────────────────────────────────────

/// Durable/in-memory one-time nonce store for bootstrap replay protection.
pub trait EnrollmentNonceStore: Send + Sync + fmt::Debug {
 /// Record `nonce` and return `true` when it was fresh, `false` when it was
 /// already present inside the retention window.
    fn record(&self, nonce: [u8; 32], now_est: i64) -> Result<bool, EpochError>;
 /// Delete expired nonces, returning the number removed.
    fn purge_expired(&self, now_est: i64) -> Result<usize, EpochError>;
 /// Whether `nonce` is currently recorded.
    fn contains(&self, nonce: &[u8; 32]) -> Result<bool, EpochError>;
 /// Number of currently retained nonces.
    fn len(&self) -> Result<usize, EpochError>;
 /// Whether no nonces are currently retained.
    fn is_empty(&self) -> Result<bool, EpochError> {
        Ok(self.len()? == 0)
    }
}

/// In-memory bounded nonce store used by tests and small deployments.
#[derive(Debug)]
pub struct InMemoryNonceStore {
    retention_secs: i64,
    capacity: usize,
 /// nonce → expires_at_est
    inner: Mutex<BTreeMap<[u8; 32], i64>>,
}

impl InMemoryNonceStore {
 /// Construct with the default 72-hour retention.
    pub fn new() -> Self {
        Self::with_retention(DEFAULT_ENROLLMENT_NONCE_RETENTION_SECS)
    }

 /// Construct with a custom retention window.
    pub fn with_retention(retention_secs: i64) -> Self {
        InMemoryNonceStore {
            retention_secs: retention_secs.max(0),
            capacity: DEFAULT_ENROLLMENT_NONCE_CAPACITY,
            inner: Mutex::new(BTreeMap::new()),
        }
    }

 /// Configure the maximum number of retained nonces.
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity.max(1);
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<[u8; 32], i64>> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl Default for InMemoryNonceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl EnrollmentNonceStore for InMemoryNonceStore {
    fn record(&self, nonce: [u8; 32], now_est: i64) -> Result<bool, EpochError> {
        let mut inner = self.lock();
        inner.retain(|_, expires| *expires >= now_est);
        if inner.contains_key(&nonce) {
            return Ok(false);
        }
        if inner.len() >= self.capacity {
 // Evict the nonce closest to expiry (deterministic).
            if let Some(key) = inner
                .iter()
                .min_by_key(|(_, expires)| **expires)
                .map(|(key, _)| *key)
            {
                inner.remove(&key);
            }
        }
        inner.insert(nonce, now_est.saturating_add(self.retention_secs));
        Ok(true)
    }

    fn purge_expired(&self, now_est: i64) -> Result<usize, EpochError> {
        let mut inner = self.lock();
        let before = inner.len();
        inner.retain(|_, expires| *expires >= now_est);
        Ok(before - inner.len())
    }

    fn contains(&self, nonce: &[u8; 32]) -> Result<bool, EpochError> {
        Ok(self.lock().contains_key(nonce))
    }

    fn len(&self) -> Result<usize, EpochError> {
        Ok(self.lock().len())
    }
}

// ─── Decommission credential ────────────────────────────────────────────────

/// Credential required to decommission a device (PV-3.13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecommissionCredential {
 /// Credential holder's DID.
    pub signer_did: String,
 /// Role claimed by the holder.
    pub role: CommandRole,
 /// Signature over the decommission statement.
    pub signature: DeviceSignature,
}

/// The bytes signed by a decommission credential.
pub fn decommission_message(device_id: &str) -> Vec<u8> {
    let mut bytes = b"TirBase/v1/Decommission".to_vec();
    bytes.push(0);
    bytes.extend_from_slice(device_id.as_bytes());
    bytes
}

/// Verify that a decommission credential is a valid RevocationManager credential
/// registered in the trust root.
///
/// A credential from any other role — even with a valid signature — is
/// rejected with [`EpochError::RevocationManagerRequired`].
pub fn verify_decommission_credential(
    trust_root: &TrustRootRecord,
    device_id: &str,
    credential: &DecommissionCredential,
) -> Result<(), EpochError> {
 // : decommission authorization is decided by the capability
 // matrix, not by an ad-hoc role comparison. Any role the matrix denies for
 // `DecommissionDevice` is rejected identically.
    if crate::auth_matrix::check_role_authorization(
        crate::auth_matrix::AuthOperation::DecommissionDevice,
        credential.role,
    )
    .is_err()
    {
        return Err(EpochError::RevocationManagerRequired {
            role: credential.role,
        });
    }
    let message = decommission_message(device_id);
    trust_root
        .verify_role_cosignature(
            CommandRole::RevocationManager,
            &credential.signer_did,
            &message,
            &credential.signature,
        )
        .map_err(EpochError::TrustRoot)
}

/// Verify a raw Ed25519 signature over `message` (helper for callers that hold
/// a public key rather than a trust root).
pub fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &DeviceSignature) -> bool {
    let Ok(key) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };
    match signature {
        DeviceSignature::Ed25519(bytes) => {
            keypair::verify(&key, message, &Ed25519Signature::from_bytes(*bytes)).is_ok()
        }
        DeviceSignature::P256(_) => false,
    }
}

/// Test-support counters shared with the trust-root tests.
#[cfg(test)]
pub(crate) mod tests_support {
    use std::sync::atomic::{AtomicU64, Ordering};

    use tirbase_core::errors::TirBaseError;
    use tirbase_core::traits::{AssuranceLevel, MonotonicCounterTrait};

 /// In-memory monotonic counter for unit tests.
    #[derive(Debug)]
    pub struct MemoryCounter {
        value: AtomicU64,
    }

    impl MemoryCounter {
 /// Construct at `initial`.
        pub fn new(initial: u64) -> Self {
            MemoryCounter {
                value: AtomicU64::new(initial),
            }
        }
    }

    impl MonotonicCounterTrait for MemoryCounter {
        fn read(&self) -> Result<u64, TirBaseError> {
            Ok(self.value.load(Ordering::SeqCst))
        }

        fn increment(&self) -> Result<u64, TirBaseError> {
            Ok(self.value.fetch_add(1, Ordering::SeqCst) + 1)
        }

        fn set_if_greater(&self, value: u64) -> Result<u64, TirBaseError> {
            let mut current = self.value.load(Ordering::SeqCst);
            loop {
                if value <= current {
                    return Ok(current);
                }
                match self.value.compare_exchange(
                    current,
                    value,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => return Ok(value),
                    Err(observed) => current = observed,
                }
            }
        }

        fn assurance_level(&self) -> AssuranceLevel {
            AssuranceLevel::Level1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::MemoryCounter;
    use super::*;
    use std::collections::BTreeMap;

    use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
    use tirbase_core::traits::KeyProvider;
    use tirbase_types::{FixedPointValue, UNIT_DEG_C};

    #[derive(Debug, Default)]
    struct MemoryEpochStore {
        rows: Mutex<BTreeMap<String, DeviceEpoch>>,
    }

    impl DeviceEpochStore for MemoryEpochStore {
        fn load(&self, device_id: &str) -> Result<Option<DeviceEpoch>, EpochError> {
            Ok(self.rows.lock().unwrap().get(device_id).cloned())
        }

        fn save(&self, record: &DeviceEpoch) -> Result<(), EpochError> {
            self.rows
                .lock()
                .unwrap()
                .insert(record.device_id.clone(), record.clone());
            Ok(())
        }
    }

    fn trust_root_with(pa: &InMemoryKeyProvider, rm: &InMemoryKeyProvider) -> TrustRootRecord {
        let mut roles = BTreeMap::new();
        roles.insert(
            CommandRole::PolicyAuthority,
            crate::trust_root::RolePolicy::new(
                1,
                vec![crate::trust_root::AuthorizedRoleSigner {
                    did: pa.did().to_string(),
                    public_key: pa.public_key_bytes(),
                }],
            ),
        );
        roles.insert(
            CommandRole::RevocationManager,
            crate::trust_root::RolePolicy::new(
                1,
                vec![crate::trust_root::AuthorizedRoleSigner {
                    did: rm.did().to_string(),
                    public_key: rm.public_key_bytes(),
                }],
            ),
        );
        TrustRootRecord {
            version: 1,
            root_ca_public_keys: vec![vec![9u8; 32]],
            threshold_k: 1,
            role_thresholds: roles,
            device_class_floors: BTreeMap::from([(
                "cold_room".to_string(),
                vec![crate::trust_root::ParamFloor {
                    param_name: "temperature".to_string(),
                    min_floor: FixedPointValue::new(-400, -1, UNIT_DEG_C),
                    max_ceiling: FixedPointValue::new(100, -1, UNIT_DEG_C),
                }],
            )]),
            expiry_est: 4_000_000_000,
            revoked_root_ca_keys: Vec::new(),
            signatures: Vec::new(),
        }
    }

    fn signed_bump(
        pa: &InMemoryKeyProvider,
        rm: &InMemoryKeyProvider,
        payload: &EpochBump,
    ) -> SignedOperation<EpochBump> {
        let mut operation = SignedOperation::new(payload, 1_000, None).unwrap();
        operation
            .sign_with(pa, CommandRole::PolicyAuthority)
            .unwrap();
        operation
            .sign_with(rm, CommandRole::RevocationManager)
            .unwrap();
        operation
    }

    fn registry() -> (EpochRegistry, Arc<MemoryEpochStore>) {
        let store = Arc::new(MemoryEpochStore::default());
        (EpochRegistry::new(store.clone()), store)
    }

    #[test]
    fn epoch_starts_at_zero_on_first_enrollment() {
        let (registry, _) = registry();
        let record = registry.ensure_enrolled("did:key:zDevice", 500).unwrap();
        assert_eq!(record.epoch, 0);
        assert!(record.co_sig_pa.is_none());
        assert!(record.co_sig_rm.is_none());
 // Re-enrolling is idempotent and does not reset the epoch.
        registry.observe_epoch("did:key:zDevice", 0).unwrap();
        assert_eq!(
            registry
                .ensure_enrolled("did:key:zDevice", 999)
                .unwrap()
                .epoch,
            0
        );
    }

    #[test]
    fn prior_epoch_command_is_rejected_after_bump() {
        let (registry, _) = registry();
        let registry = Arc::new(registry);
        let pa = InMemoryKeyProvider::generate().unwrap();
        let rm = InMemoryKeyProvider::generate().unwrap();
        let trust_root = trust_root_with(&pa, &rm);

        registry.ensure_enrolled("did:key:zDevice", 100).unwrap();
        let guard = EpochCommandGuard::new(registry.clone());
        let command = CommandEnvelope {
            device_id: "did:key:zDevice".to_string(),
            issuer_did: "did:key:zIssuer".to_string(),
            enrollment_epoch: 0,
        };
        guard.admit(&command).expect("epoch 0 command is current");

        let payload = EpochBump {
            device_id: "did:key:zDevice".to_string(),
            previous_epoch: 0,
            new_epoch: 1,
            reason: "snapshot restore".to_string(),
        };
        let operation = signed_bump(&pa, &rm, &payload);
        registry
            .apply_bump(&operation, &payload, &trust_root, 200)
            .expect("bump applies");

        assert_eq!(
            guard.admit(&command),
            Err(EpochError::StaleEpoch {
                command_epoch: 0,
                current_epoch: 1
            }),
            "removing the Stage 8 check would admit this prior-epoch command"
        );

        let mut next = command.clone();
        next.enrollment_epoch = 1;
        guard.admit(&next).expect("new-epoch command is admitted");
    }

    #[test]
    fn bump_without_both_role_cosignatures_is_rejected() {
        let (registry, _) = registry();
        let pa = InMemoryKeyProvider::generate().unwrap();
        let rm = InMemoryKeyProvider::generate().unwrap();
        let trust_root = trust_root_with(&pa, &rm);
        registry.ensure_enrolled("did:key:zDevice", 100).unwrap();

        let payload = EpochBump {
            device_id: "did:key:zDevice".to_string(),
            previous_epoch: 0,
            new_epoch: 1,
            reason: "restore".to_string(),
        };
        let mut operation = SignedOperation::new(&payload, 1_000, None).unwrap();
        operation
            .sign_with(&pa, CommandRole::PolicyAuthority)
            .unwrap();

        assert!(matches!(
            registry.apply_bump(&operation, &payload, &trust_root, 200),
            Err(EpochError::TrustRoot(TrustRootError::ThresholdNotMet {
                got: 0,
                ..
            }))
        ));
    }

    #[test]
    fn epoch_regression_emits_event_and_is_rejected() {
        use std::sync::Mutex;
        use tirbase_core::events::install_security_event_sink;
        use tirbase_core::traits::SecurityEventSink;

        #[derive(Debug, Default)]
        struct RecordingSink {
            events: Mutex<Vec<SecurityEvent>>,
        }
        impl SecurityEventSink for RecordingSink {
            fn emit(&self, event: SecurityEvent) {
                self.events.lock().unwrap().push(event);
            }
        }

        let (registry, _) = registry();
        registry.observe_epoch("did:key:zDevice", 5).unwrap();

        let sink = Arc::new(RecordingSink::default());
        let _previous = install_security_event_sink(sink.clone());

        let error = registry.observe_epoch("did:key:zDevice", 4).unwrap_err();
        assert_eq!(
            error,
            EpochError::EpochRegression {
                device_id: "did:key:zDevice".to_string(),
                witnessed: 5,
                reported: 4,
            }
        );
        let events = sink.events.lock().unwrap();
        assert!(events
            .iter()
            .any(|event| event.reason_code == ReasonCode::EpochRegression));
    }

    #[test]
    fn nonce_reuse_inside_retention_is_rejected() {
        let store = InMemoryNonceStore::new();
        let nonce = [7u8; 32];
        assert!(store.record(nonce, 1_000).unwrap());
        assert!(!store.record(nonce, 1_000).unwrap(), "reuse rejected");
        assert!(store.contains(&nonce).unwrap());
    }

    #[test]
    fn expired_nonces_are_purged() {
        let store = InMemoryNonceStore::with_retention(100).with_capacity(10);
        assert!(store.record([1u8; 32], 1_000).unwrap());
        assert!(store.record([2u8; 32], 1_050).unwrap());
        assert_eq!(store.len().unwrap(), 2);
 // expiry is `recorded_at + retention`: at 1_151 both are expired.
        assert_eq!(store.purge_expired(1_151).unwrap(), 2);
        assert_eq!(store.len().unwrap(), 0);
 // After expiry the nonce can be recorded again (outside retention).
        assert!(store.record([1u8; 32], 1_200).unwrap());
    }

    #[test]
    fn decommission_requires_a_revocation_manager_credential() {
        let pa = InMemoryKeyProvider::generate().unwrap();
        let rm = InMemoryKeyProvider::generate().unwrap();
        let trust_root = trust_root_with(&pa, &rm);
        let message = decommission_message("did:key:zDevice");

        let wrong_role = DecommissionCredential {
            signer_did: pa.did().to_string(),
            role: CommandRole::PolicyAuthority,
            signature: pa.sign(&message).unwrap(),
        };
        assert_eq!(
            verify_decommission_credential(&trust_root, "did:key:zDevice", &wrong_role),
            Err(EpochError::RevocationManagerRequired {
                role: CommandRole::PolicyAuthority
            })
        );

        let good = DecommissionCredential {
            signer_did: rm.did().to_string(),
            role: CommandRole::RevocationManager,
            signature: rm.sign(&message).unwrap(),
        };
        verify_decommission_credential(&trust_root, "did:key:zDevice", &good)
            .expect("RevocationManager credential accepted");
    }

    #[test]
    fn memory_counter_is_used_by_trust_root_tests() {
 // Keeps the shared test counter exercised from this module too.
        use tirbase_core::traits::MonotonicCounterTrait;
        let counter = MemoryCounter::new(3);
        assert_eq!(counter.read().unwrap(), 3);
    }
}
