// SPDX-License-Identifier: AGPL-3.0-only

//! F-04 — Device provisioning and lifecycle.
//!
//! This module implements the provisioning and lifecycle control plane for
//! devices:
//!
//! 1. **Enrolment**: operator-issued claim codes bind a device identity and a
//!    signed provisioning payload to a tenant (and optional site).
//! 2. **Credential lifecycle**: issue, rotate, revoke, replace, and
//!    decommission device credentials with an append-only audit trail.
//! 3. **Ownership transfer**: move a device between tenants with explicit audit
//!    and re-keying; tenant-scoped runtime material is cleared so old-tenant
//!    data does not leak.
//! 4. **Version reporting and drift detection**: record reported firmware/config
//!    versions and compare them to the expected versions in the bound payload.
//! 5. **Offline provisioning**: bounded, signed payloads with replay protection
//!    and idempotent application.
//! 6. **Device registry**: query devices by tenant, site, type, and state.
//!
//! # Security properties
//!
//! * Claim codes are single-use and time-bounded.
//! * A signed provisioning payload is verified before any state transition.
//! * Offline provisioning records a payload identifier and rejects replays, but
//!   applying the same payload again is idempotent.
//! * Revoked or decommissioned devices cannot re-enrol on their previous
//!   identity; re-enrolment requires revocation closure and an explicit
//!   re-issue path that provisions a fresh identity.
//! * Ownership transfer rotates credentials and clears tenant-scoped cached
//!   material before the new tenant is attached.

use std::collections::BTreeMap;
use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tirbase_types::identity::TenantPath;

/// Maximum accepted offline provisioning payload size (bytes).
pub const MAX_OFFLINE_PROVISIONING_PAYLOAD_BYTES: usize = 64 * 1024;

/// Domain separator for claim-code derivation.
const CLAIM_CODE_DOMAIN: &[u8] = b"TirBase/v1/ClaimCode";
/// Domain separator for provisioning payload signatures.
const PROVISIONING_PAYLOAD_DOMAIN: &[u8] = b"TirBase/v1/ProvisioningPayload";
/// Domain separator for device credential material derivation.
const CREDENTIAL_DOMAIN: &[u8] = b"TirBase/v1/DeviceCredential";

/// Provisioning/lifecycle errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProvisioningError {
    /// Claim code is unknown.
    #[error("claim code not found")]
    ClaimCodeNotFound,
    /// Claim code has expired.
    #[error("claim code expired")]
    ClaimCodeExpired,
    /// Claim code was already consumed.
    #[error("claim code already used")]
    ClaimCodeAlreadyUsed,
    /// Claim code does not match the enrolment request.
    #[error("claim code does not match request: {reason}")]
    ClaimCodeMismatch { reason: String },
    /// Device is unknown.
    #[error("device not found: {device_id}")]
    DeviceNotFound { device_id: String },
    /// Device already exists.
    #[error("device already exists: {device_id}")]
    DeviceAlreadyExists { device_id: String },
    /// Device state does not permit the requested transition.
    #[error("invalid device state {state:?} for operation {operation}")]
    InvalidState { state: DeviceState, operation: String },
    /// Provisioning payload failed validation.
    #[error("invalid provisioning payload: {reason}")]
    InvalidPayload { reason: String },
    /// Provisioning payload is too large for offline transport.
    #[error("provisioning payload is {size} bytes; maximum is {max}")]
    PayloadTooLarge { size: usize, max: usize },
    /// Provisioning payload signature is invalid.
    #[error("invalid provisioning payload signature")]
    InvalidPayloadSignature,
    /// Device identity does not match the payload/request.
    #[error("device identity mismatch: {reason}")]
    IdentityMismatch { reason: String },
    /// A revoked/stolen device cannot re-enrol without revocation and re-issue.
    #[error("device {device_id} cannot re-enrol without revocation and re-issue")]
    ReenrolmentBlocked { device_id: String },
    /// Offline payload replay was detected.
    #[error("offline provisioning payload replay detected: {payload_id}")]
    ReplayDetected { payload_id: String },
    /// Credential not found.
    #[error("credential not found: {credential_id}")]
    CredentialNotFound { credential_id: String },
    /// Credential is not active.
    #[error("credential is not active: {credential_id}")]
    CredentialInactive { credential_id: String },
    /// Re-issue requires a new device identity.
    #[error("re-issue requires a new device identity; old identity remains revoked")]
    ReissueRequiresNewIdentity,
    /// Serialisation or internal encoding failure.
    #[error("serialisation error: {reason}")]
    Serialisation { reason: String },
    /// Signature/key material error.
    #[error("cryptographic error: {reason}")]
    Crypto { reason: String },
}

/// Lifecycle state of a device in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DeviceState {
    /// A claim has been issued but the device has not completed enrolment.
    PendingEnrolment,
    /// Device is enrolled and operational.
    Active,
    /// Device credentials have been revoked; operational access is blocked.
    Revoked,
    /// Device has been decommissioned and removed from active service.
    Decommissioned,
    /// Device has been transferred out of a tenant and must be re-keyed/re-bound.
    Transferred,
}

/// Audit event kinds recorded by the lifecycle service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEventKind {
    ClaimIssued,
    Enrolled,
    CredentialIssued,
    CredentialRotated,
    CredentialRevoked,
    CredentialReplaced,
    DeviceRevoked,
    DeviceDecommissioned,
    ReissuePrepared,
    OwnershipTransferred,
    VersionReported,
    DriftDetected,
    DriftCleared,
    OfflineProvisionApplied,
}

/// Append-only audit record for provisioning and lifecycle operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Monotonic sequence within the registry.
    pub seq: u64,
    /// Authenticated/recorded wall time in UTC seconds.
    pub at_est: i64,
    /// Device identifier, when applicable.
    pub device_id: Option<String>,
    /// Tenant scope, when applicable.
    pub tenant: Option<TenantPath>,
    /// Actor that performed or requested the action.
    pub actor: String,
    /// Event kind.
    pub kind: AuditEventKind,
    /// Human/machine-readable detail.
    pub detail: String,
}

/// Operator-issued enrolment claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimCode {
    /// Opaque claim identifier (derived code).
    pub code: String,
    /// Tenant the device will be bound to.
    pub tenant: TenantPath,
    /// Optional site identifier within the tenant.
    pub site: Option<String>,
    /// Optional required device type/class.
    pub device_type: Option<String>,
    /// Issuing actor.
    pub issued_by: String,
    /// Issuance time (UTC seconds).
    pub issued_at_est: i64,
    /// Expiry time (UTC seconds).
    pub expires_at_est: i64,
    /// Consumption time (UTC seconds), if used.
    pub used_at_est: Option<i64>,
    /// Device identity that consumed the claim, if used.
    pub used_by_device_id: Option<String>,
}

impl ClaimCode {
    /// Returns `true` when the claim is expired at `now_est`.
    pub fn is_expired(&self, now_est: i64) -> bool {
        now_est > self.expires_at_est
    }

    /// Returns `true` when the claim has been consumed.
    pub fn is_used(&self) -> bool {
        self.used_at_est.is_some()
    }
}

/// Expected firmware/config versions carried by a provisioning payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VersionSet {
    /// Expected firmware version string.
    pub firmware_version: Option<String>,
    /// Expected configuration version string.
    pub config_version: Option<String>,
}

/// Signed provisioning payload bound to a tenant and device identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningPayload {
    /// Unique payload identifier (used for offline replay protection/idempotency).
    pub payload_id: String,
    /// Device identity (DID or stable device identifier).
    pub device_id: String,
    /// Device public key bytes (Ed25519).
    pub device_public_key: Vec<u8>,
    /// Tenant binding.
    pub tenant: TenantPath,
    /// Optional site identifier.
    pub site: Option<String>,
    /// Device type/class.
    pub device_type: String,
    /// Claim code authorizing enrolment (None for some controlled re-issue flows).
    pub claim_code: Option<String>,
    /// Expected firmware/config versions.
    pub expected_versions: VersionSet,
    /// Issuance time (UTC seconds).
    pub issued_at_est: i64,
    /// Expiry time (UTC seconds), if any.
    pub expires_at_est: Option<i64>,
    /// Issuing authority identifier.
    pub issued_by: String,
    /// Ed25519 signature by the provisioning authority over canonical bytes.
    pub signature: Vec<u8>,
}

impl ProvisioningPayload {
    /// Canonical bytes covered by [`Self::signature`].
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ProvisioningError> {
        #[derive(Serialize)]
        struct Body<'a> {
            payload_id: &'a str,
            device_id: &'a str,
            device_public_key: &'a [u8],
            tenant: &'a TenantPath,
            site: &'a Option<String>,
            device_type: &'a str,
            claim_code: &'a Option<String>,
            expected_versions: &'a VersionSet,
            issued_at_est: i64,
            expires_at_est: Option<i64>,
            issued_by: &'a str,
        }
        let body = Body {
            payload_id: &self.payload_id,
            device_id: &self.device_id,
            device_public_key: &self.device_public_key,
            tenant: &self.tenant,
            site: &self.site,
            device_type: &self.device_type,
            claim_code: &self.claim_code,
            expected_versions: &self.expected_versions,
            issued_at_est: self.issued_at_est,
            expires_at_est: self.expires_at_est,
            issued_by: &self.issued_by,
        };
        let canonical = serde_json::to_vec(&body)
            .map_err(|e| ProvisioningError::Serialisation { reason: e.to_string() })?;
        let mut out = Vec::with_capacity(PROVISIONING_PAYLOAD_DOMAIN.len() + canonical.len());
        out.extend_from_slice(PROVISIONING_PAYLOAD_DOMAIN);
        out.extend_from_slice(&canonical);
        Ok(out)
    }

    /// Verify the payload signature against an authority public key.
    pub fn verify(&self, authority_public_key: &[u8; 32]) -> Result<(), ProvisioningError> {
        let verifying_key = VerifyingKey::from_bytes(authority_public_key)
            .map_err(|e| ProvisioningError::Crypto { reason: e.to_string() })?;
        let sig_bytes: [u8; 64] = self.signature.as_slice().try_into().map_err(|_| {
            ProvisioningError::InvalidPayload {
                reason: "signature must be 64 bytes".to_string(),
            }
        })?;
        let signature = Signature::from_bytes(&sig_bytes);
        let bytes = self.signing_bytes()?;
        verifying_key
            .verify(&bytes, &signature)
            .map_err(|_| ProvisioningError::InvalidPayloadSignature)
    }

    /// Sign the payload in place with an authority signing key.
    pub fn sign(&mut self, authority: &SigningKey) -> Result<(), ProvisioningError> {
        self.signature.clear();
        let bytes = self.signing_bytes()?;
        let signature = authority.sign(&bytes);
        self.signature = signature.to_bytes().to_vec();
        Ok(())
    }

    /// Serialised size in bytes (for offline bounded-payload enforcement).
    pub fn encoded_len(&self) -> Result<usize, ProvisioningError> {
        serde_json::to_vec(self)
            .map(|b| b.len())
            .map_err(|e| ProvisioningError::Serialisation { reason: e.to_string() })
    }

    /// Validate structural and bound constraints.
    pub fn validate(&self, now_est: i64) -> Result<(), ProvisioningError> {
        if self.payload_id.trim().is_empty() {
            return Err(ProvisioningError::InvalidPayload {
                reason: "payload_id must not be empty".to_string(),
            });
        }
        if self.device_id.trim().is_empty() {
            return Err(ProvisioningError::InvalidPayload {
                reason: "device_id must not be empty".to_string(),
            });
        }
        if self.device_public_key.len() != 32 {
            return Err(ProvisioningError::InvalidPayload {
                reason: "device_public_key must be 32 bytes".to_string(),
            });
        }
        if self.device_type.trim().is_empty() {
            return Err(ProvisioningError::InvalidPayload {
                reason: "device_type must not be empty".to_string(),
            });
        }
        if let Some(exp) = self.expires_at_est {
            if now_est > exp {
                return Err(ProvisioningError::InvalidPayload {
                    reason: "payload has expired".to_string(),
                });
            }
        }
        let size = self.encoded_len()?;
        if size > MAX_OFFLINE_PROVISIONING_PAYLOAD_BYTES {
            return Err(ProvisioningError::PayloadTooLarge {
                size,
                max: MAX_OFFLINE_PROVISIONING_PAYLOAD_BYTES,
            });
        }
        Ok(())
    }
}

/// State of an issued credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialState {
    Active,
    Revoked,
    Replaced,
    Decommissioned,
}

/// Credential record tracked by the lifecycle service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRecord {
    /// Stable credential identifier.
    pub credential_id: String,
    /// Owning device.
    pub device_id: String,
    /// Tenant binding at issuance time.
    pub tenant: TenantPath,
    /// Derived/opaque credential material fingerprint (never the raw secret in audit).
    pub material_fingerprint: String,
    /// Current state.
    pub state: CredentialState,
    /// Issuance time.
    pub issued_at_est: i64,
    /// State-change time.
    pub updated_at_est: i64,
    /// Credential this one replaced, if any.
    pub replaces: Option<String>,
}

/// Reported runtime versions from a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ReportedVersions {
    pub firmware_version: Option<String>,
    pub config_version: Option<String>,
    pub reported_at_est: Option<i64>,
}

/// Drift status derived from expected vs reported versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftStatus {
    pub firmware_drifted: bool,
    pub config_drifted: bool,
    pub expected: VersionSet,
    pub reported: ReportedVersions,
}

impl DriftStatus {
    /// Returns `true` if any tracked component is drifted.
    pub fn is_drifted(&self) -> bool {
        self.firmware_drifted || self.config_drifted
    }
}

/// Device record stored in the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// Stable device identity.
    pub device_id: String,
    /// Current public key bytes.
    pub device_public_key: Vec<u8>,
    /// Current tenant binding.
    pub tenant: TenantPath,
    /// Optional site identifier.
    pub site: Option<String>,
    /// Device type/class.
    pub device_type: String,
    /// Lifecycle state.
    pub state: DeviceState,
    /// Expected versions from the active provisioning payload.
    pub expected_versions: VersionSet,
    /// Last reported versions.
    pub reported_versions: ReportedVersions,
    /// Active credential identifier, if any.
    pub active_credential_id: Option<String>,
    /// Bound provisioning payload identifier.
    pub provisioning_payload_id: Option<String>,
    /// Creation/enrolment time.
    pub created_at_est: i64,
    /// Last update time.
    pub updated_at_est: i64,
    /// Tenant-scoped runtime cache marker; cleared on ownership transfer and
    /// decommission to prevent old-tenant data leakage.
    pub tenant_data_cleared_at_est: Option<i64>,
    /// Previous tenants observed for this device identity (audit visibility).
    pub previous_tenants: Vec<TenantPath>,
}

/// Query filter for the device registry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceQuery {
    pub tenant: Option<TenantPath>,
    pub site: Option<String>,
    pub device_type: Option<String>,
    pub state: Option<DeviceState>,
}

impl DeviceQuery {
    /// Returns `true` if `record` matches all specified filters.
    pub fn matches(&self, record: &DeviceRecord) -> bool {
        if let Some(t) = &self.tenant {
            if &record.tenant != t {
                return false;
            }
        }
        if let Some(site) = &self.site {
            if record.site.as_ref() != Some(site) {
                return false;
            }
        }
        if let Some(ty) = &self.device_type {
            if &record.device_type != ty {
                return false;
            }
        }
        if let Some(state) = self.state {
            if record.state != state {
                return false;
            }
        }
        true
    }
}

/// Result of applying an offline provisioning payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineProvisionResult {
    /// Device record after application.
    pub record: DeviceRecord,
    /// `true` when this call was a replay/idempotent no-op for the same payload.
    pub idempotent_replay: bool,
}

/// In-memory device registry and lifecycle service.
///
/// This implementation is deterministic and suitable for tests, simulations, and
/// single-process control-plane use. A durable store can implement the same
/// semantics behind a trait boundary.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DeviceLifecycleRegistry {
    claim_codes: BTreeMap<String, ClaimCode>,
    devices: BTreeMap<String, DeviceRecord>,
    credentials: BTreeMap<String, CredentialRecord>,
    /// payload_id -> device_id for replay protection.
    offline_applied_payloads: BTreeMap<String, String>,
    /// device identities that were revoked/decommissioned/transferred and must
    /// not re-enrol without explicit re-issue to a new identity.
    reenrolment_blocked: BTreeMap<String, ReenrolmentBlock>,
    audit: Vec<AuditRecord>,
    next_audit_seq: u64,
    next_credential_seq: u64,
}

/// Reason a previous device identity cannot re-enrol directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReenrolmentBlock {
    pub device_id: String,
    pub reason: String,
    pub blocked_at_est: i64,
    /// `true` once a re-issue flow has been explicitly authorised. Even when
    /// re-issue is authorised, the original identity remains blocked and a fresh
    /// identity must be provisioned.
    pub reissue_authorised: bool,
}

impl DeviceLifecycleRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a new single-use claim code bound to a tenant (and optional site/type).
    pub fn issue_claim_code(
        &mut self,
        tenant: TenantPath,
        site: Option<String>,
        device_type: Option<String>,
        issued_by: impl Into<String>,
        now_est: i64,
        ttl_secs: i64,
        nonce: &[u8],
    ) -> ClaimCode {
        let issued_by = issued_by.into();
        let expires_at_est = now_est.saturating_add(ttl_secs.max(1));
        let code = derive_claim_code(&tenant, site.as_deref(), device_type.as_deref(), nonce, now_est);
        let claim = ClaimCode {
            code: code.clone(),
            tenant: tenant.clone(),
            site: site.clone(),
            device_type,
            issued_by: issued_by.clone(),
            issued_at_est: now_est,
            expires_at_est,
            used_at_est: None,
            used_by_device_id: None,
        };
        self.claim_codes.insert(code.clone(), claim.clone());
        self.push_audit(
            now_est,
            None,
            Some(tenant),
            issued_by,
            AuditEventKind::ClaimIssued,
            format!(
                "claim {code} issued{}",
                site.map(|s| format!(" for site {s}")).unwrap_or_default()
            ),
        );
        claim
    }

    /// Enrol a device using a claim code and a signed provisioning payload.
    pub fn enrol(
        &mut self,
        payload: &ProvisioningPayload,
        authority_public_key: &[u8; 32],
        actor: impl Into<String>,
        now_est: i64,
    ) -> Result<DeviceRecord, ProvisioningError> {
        self.enrol_inner(payload, authority_public_key, actor.into(), now_est, false)
    }

    /// Apply an offline provisioning payload with replay protection and idempotency.
    pub fn apply_offline_provisioning(
        &mut self,
        payload: &ProvisioningPayload,
        authority_public_key: &[u8; 32],
        actor: impl Into<String>,
        now_est: i64,
    ) -> Result<OfflineProvisionResult, ProvisioningError> {
        let actor = actor.into();
        if let Some(existing_device_id) = self.offline_applied_payloads.get(&payload.payload_id) {
            if existing_device_id == &payload.device_id {
                if let Some(record) = self.devices.get(existing_device_id).cloned() {
                    return Ok(OfflineProvisionResult {
                        record,
                        idempotent_replay: true,
                    });
                }
            }
            return Err(ProvisioningError::ReplayDetected {
                payload_id: payload.payload_id.clone(),
            });
        }
        // Record intent before applying to prevent replay windows in concurrent
        // environments; in-memory single-threaded use makes this sufficient.
        self.offline_applied_payloads
            .insert(payload.payload_id.clone(), payload.device_id.clone());
        match self.enrol_inner(payload, authority_public_key, actor.clone(), now_est, true) {
            Ok(record) => {
                self.push_audit(
                    now_est,
                    Some(record.device_id.clone()),
                    Some(record.tenant.clone()),
                    actor,
                    AuditEventKind::OfflineProvisionApplied,
                    format!("offline payload {} applied", payload.payload_id),
                );
                Ok(OfflineProvisionResult {
                    record,
                    idempotent_replay: false,
                })
            }
            Err(e) => {
                // Keep the payload recorded if it was a replay/idempotent-equivalent
                // state error is not possible here; remove only on validation
                // failures before state mutation? enrol_inner mutates on success.
                // On error, remove mapping so a corrected retry of a different flow
                // is not blocked, except replay detection is handled above.
                self.offline_applied_payloads.remove(&payload.payload_id);
                Err(e)
            }
        }
    }

    fn enrol_inner(
        &mut self,
        payload: &ProvisioningPayload,
        authority_public_key: &[u8; 32],
        actor: String,
        now_est: i64,
        offline: bool,
    ) -> Result<DeviceRecord, ProvisioningError> {
        payload.validate(now_est)?;
        payload.verify(authority_public_key)?;

        if let Some(block) = self.reenrolment_blocked.get(&payload.device_id) {
            // A previously revoked/decommissioned/transferred identity can never be
            // reused. Re-issue must provision a fresh identity.
            let _ = block;
            return Err(ProvisioningError::ReenrolmentBlocked {
                device_id: payload.device_id.clone(),
            });
        }
        if self.devices.contains_key(&payload.device_id) {
            return Err(ProvisioningError::DeviceAlreadyExists {
                device_id: payload.device_id.clone(),
            });
        }

        if !offline {
            let claim_code = payload.claim_code.as_ref().ok_or_else(|| {
                ProvisioningError::ClaimCodeMismatch {
                    reason: "online enrolment requires a claim code".to_string(),
                }
            })?;
            self.consume_claim_code(claim_code, payload, now_est)?;
        } else if let Some(claim_code) = &payload.claim_code {
            // Offline payloads may carry a claim code; if present it must be valid
            // and is consumed idempotently by payload replay protection above.
            self.consume_claim_code(claim_code, payload, now_est)?;
        }

        let credential = self.issue_credential_internal(
            &payload.device_id,
            &payload.tenant,
            now_est,
            None,
            CredentialState::Active,
        );
        let record = DeviceRecord {
            device_id: payload.device_id.clone(),
            device_public_key: payload.device_public_key.clone(),
            tenant: payload.tenant.clone(),
            site: payload.site.clone(),
            device_type: payload.device_type.clone(),
            state: DeviceState::Active,
            expected_versions: payload.expected_versions.clone(),
            reported_versions: ReportedVersions::default(),
            active_credential_id: Some(credential.credential_id.clone()),
            provisioning_payload_id: Some(payload.payload_id.clone()),
            created_at_est: now_est,
            updated_at_est: now_est,
            tenant_data_cleared_at_est: Some(now_est),
            previous_tenants: Vec::new(),
        };
        self.devices.insert(record.device_id.clone(), record.clone());
        self.credentials
            .insert(credential.credential_id.clone(), credential.clone());
        self.push_audit(
            now_est,
            Some(record.device_id.clone()),
            Some(record.tenant.clone()),
            actor.clone(),
            AuditEventKind::Enrolled,
            format!(
                "device enrolled with payload {}",
                payload.payload_id
            ),
        );
        self.push_audit(
            now_est,
            Some(record.device_id.clone()),
            Some(record.tenant.clone()),
            actor,
            AuditEventKind::CredentialIssued,
            format!("credential {} issued", credential.credential_id),
        );
        Ok(record)
    }

    fn consume_claim_code(
        &mut self,
        code: &str,
        payload: &ProvisioningPayload,
        now_est: i64,
    ) -> Result<(), ProvisioningError> {
        let claim = self
            .claim_codes
            .get_mut(code)
            .ok_or(ProvisioningError::ClaimCodeNotFound)?;
        if claim.is_expired(now_est) {
            return Err(ProvisioningError::ClaimCodeExpired);
        }
        if claim.is_used() {
            return Err(ProvisioningError::ClaimCodeAlreadyUsed);
        }
        if claim.tenant != payload.tenant {
            return Err(ProvisioningError::ClaimCodeMismatch {
                reason: "tenant binding mismatch".to_string(),
            });
        }
        if let Some(site) = &claim.site {
            if payload.site.as_ref() != Some(site) {
                return Err(ProvisioningError::ClaimCodeMismatch {
                    reason: "site binding mismatch".to_string(),
                });
            }
        }
        if let Some(device_type) = &claim.device_type {
            if &payload.device_type != device_type {
                return Err(ProvisioningError::ClaimCodeMismatch {
                    reason: "device type mismatch".to_string(),
                });
            }
        }
        claim.used_at_est = Some(now_est);
        claim.used_by_device_id = Some(payload.device_id.clone());
        Ok(())
    }

    fn issue_credential_internal(
        &mut self,
        device_id: &str,
        tenant: &TenantPath,
        now_est: i64,
        replaces: Option<String>,
        state: CredentialState,
    ) -> CredentialRecord {
        self.next_credential_seq = self.next_credential_seq.saturating_add(1);
        let credential_id = format!("cred-{}-{}", device_id, self.next_credential_seq);
        let material_fingerprint = fingerprint_credential(device_id, tenant, self.next_credential_seq, now_est);
        CredentialRecord {
            credential_id,
            device_id: device_id.to_string(),
            tenant: tenant.clone(),
            material_fingerprint,
            state,
            issued_at_est: now_est,
            updated_at_est: now_est,
            replaces,
        }
    }

    /// Rotate the active credential for a device.
    pub fn rotate_credential(
        &mut self,
        device_id: &str,
        actor: impl Into<String>,
        now_est: i64,
    ) -> Result<CredentialRecord, ProvisioningError> {
        let actor = actor.into();
        let (tenant, old_id) = {
            let record = self.device_mut_active(device_id, "rotate_credential")?;
            (record.tenant.clone(), record.active_credential_id.clone())
        };
        if let Some(old) = old_id.as_ref() {
            self.set_credential_state(old, CredentialState::Replaced, now_est)?;
        }
        let new = self.issue_credential_internal(device_id, &tenant, now_est, old_id.clone(), CredentialState::Active);
        self.credentials.insert(new.credential_id.clone(), new.clone());
        let record = self.devices.get_mut(device_id).expect("checked above");
        record.active_credential_id = Some(new.credential_id.clone());
        record.updated_at_est = now_est;
        self.push_audit(
            now_est,
            Some(device_id.to_string()),
            Some(tenant),
            actor,
            AuditEventKind::CredentialRotated,
            format!(
                "credential rotated from {:?} to {}",
                old_id, new.credential_id
            ),
        );
        Ok(new)
    }

    /// Revoke the active credential (or a specific credential) without decommissioning the device.
    pub fn revoke_credential(
        &mut self,
        device_id: &str,
        credential_id: Option<&str>,
        actor: impl Into<String>,
        now_est: i64,
    ) -> Result<(), ProvisioningError> {
        let actor = actor.into();
        let target = {
            let record = self.device_mut(device_id)?;
            if record.state == DeviceState::Decommissioned {
                return Err(ProvisioningError::InvalidState {
                    state: record.state,
                    operation: "revoke_credential".to_string(),
                });
            }
            credential_id
                .map(|s| s.to_string())
                .or_else(|| record.active_credential_id.clone())
                .ok_or_else(|| ProvisioningError::CredentialNotFound {
                    credential_id: "<active>".to_string(),
                })?
        };
        self.set_credential_state(&target, CredentialState::Revoked, now_est)?;
        let record = self.devices.get_mut(device_id).expect("checked");
        if record.active_credential_id.as_deref() == Some(target.as_str()) {
            record.active_credential_id = None;
        }
        record.state = DeviceState::Revoked;
        record.updated_at_est = now_est;
        self.reenrolment_blocked.insert(
            device_id.to_string(),
            ReenrolmentBlock {
                device_id: device_id.to_string(),
                reason: "credential revoked".to_string(),
                blocked_at_est: now_est,
                reissue_authorised: false,
            },
        );
        let tenant = record.tenant.clone();
        self.push_audit(
            now_est,
            Some(device_id.to_string()),
            Some(tenant),
            actor,
            AuditEventKind::CredentialRevoked,
            format!("credential {target} revoked"),
        );
        Ok(())
    }

    /// Replace a credential (revoke old, issue new) as an atomic lifecycle action.
    pub fn replace_credential(
        &mut self,
        device_id: &str,
        actor: impl Into<String>,
        now_est: i64,
    ) -> Result<CredentialRecord, ProvisioningError> {
        let actor = actor.into();
        let (tenant, old_id) = {
            let record = self.device_mut_active(device_id, "replace_credential")?;
            (record.tenant.clone(), record.active_credential_id.clone())
        };
        if let Some(old) = old_id.as_ref() {
            self.set_credential_state(old, CredentialState::Revoked, now_est)?;
        }
        let new = self.issue_credential_internal(device_id, &tenant, now_est, old_id.clone(), CredentialState::Active);
        self.credentials.insert(new.credential_id.clone(), new.clone());
        let record = self.devices.get_mut(device_id).expect("checked");
        record.active_credential_id = Some(new.credential_id.clone());
        record.updated_at_est = now_est;
        self.push_audit(
            now_est,
            Some(device_id.to_string()),
            Some(tenant),
            actor,
            AuditEventKind::CredentialReplaced,
            format!(
                "credential replaced from {:?} to {}",
                old_id, new.credential_id
            ),
        );
        Ok(new)
    }

    /// Decommission a device and all its credentials.
    pub fn decommission_device(
        &mut self,
        device_id: &str,
        actor: impl Into<String>,
        now_est: i64,
    ) -> Result<(), ProvisioningError> {
        let actor = actor.into();
        let (tenant, creds): (TenantPath, Vec<String>) = {
            let record = self.device_mut(device_id)?;
            if record.state == DeviceState::Decommissioned {
                return Ok(());
            }
            (record.tenant.clone(), self.credentials_for_device(device_id))
        };
        for cred_id in creds {
            if let Some(cred) = self.credentials.get_mut(&cred_id) {
                if cred.state == CredentialState::Active || cred.state == CredentialState::Replaced {
                    cred.state = CredentialState::Decommissioned;
                    cred.updated_at_est = now_est;
                }
            }
        }
        let record = self.devices.get_mut(device_id).expect("checked");
        record.state = DeviceState::Decommissioned;
        record.active_credential_id = None;
        record.updated_at_est = now_est;
        record.tenant_data_cleared_at_est = Some(now_est);
        self.reenrolment_blocked.insert(
            device_id.to_string(),
            ReenrolmentBlock {
                device_id: device_id.to_string(),
                reason: "device decommissioned".to_string(),
                blocked_at_est: now_est,
                reissue_authorised: false,
            },
        );
        self.push_audit(
            now_est,
            Some(device_id.to_string()),
            Some(tenant),
            actor,
            AuditEventKind::DeviceDecommissioned,
            "device decommissioned and tenant-scoped material cleared".to_string(),
        );
        Ok(())
    }

    /// Explicitly authorise re-issue for a revoked/decommissioned device identity.
    ///
    /// The original identity remains blocked from re-enrolment; a fresh identity
    /// must be provisioned via a new signed payload and claim code.
    pub fn authorise_reissue(
        &mut self,
        device_id: &str,
        actor: impl Into<String>,
        now_est: i64,
    ) -> Result<(), ProvisioningError> {
        let actor = actor.into();
        let block = self.reenrolment_blocked.get_mut(device_id).ok_or_else(|| {
            ProvisioningError::InvalidState {
                state: self
                    .devices
                    .get(device_id)
                    .map(|d| d.state)
                    .unwrap_or(DeviceState::PendingEnrolment),
                operation: "authorise_reissue".to_string(),
            }
        })?;
        block.reissue_authorised = true;
        let tenant = self.devices.get(device_id).map(|d| d.tenant.clone());
        self.push_audit(
            now_est,
            Some(device_id.to_string()),
            tenant,
            actor,
            AuditEventKind::ReissuePrepared,
            "re-issue authorised; original identity remains blocked and a new identity is required"
                .to_string(),
        );
        Ok(())
    }

    /// Transfer device ownership to a new tenant with audit and re-keying.
    ///
    /// Tenant-scoped runtime material is cleared before the new binding is
    /// attached so no old-tenant data leaks across the boundary.
    pub fn transfer_ownership(
        &mut self,
        device_id: &str,
        new_tenant: TenantPath,
        new_site: Option<String>,
        actor: impl Into<String>,
        now_est: i64,
    ) -> Result<CredentialRecord, ProvisioningError> {
        let actor = actor.into();
        let (old_tenant, old_cred) = {
            let record = self.device_mut(device_id)?;
            if matches!(record.state, DeviceState::Decommissioned | DeviceState::Revoked) {
                return Err(ProvisioningError::InvalidState {
                    state: record.state,
                    operation: "transfer_ownership".to_string(),
                });
            }
            (record.tenant.clone(), record.active_credential_id.clone())
        };

        // 1) Re-key: revoke/replace old tenant credential.
        if let Some(old) = old_cred.as_ref() {
            self.set_credential_state(old, CredentialState::Revoked, now_est)?;
        }
        // 2) Clear tenant-scoped material before attaching new tenant.
        let record = self.devices.get_mut(device_id).expect("checked");
        record.previous_tenants.push(old_tenant.clone());
        record.tenant_data_cleared_at_est = Some(now_est);
        record.reported_versions = ReportedVersions::default(); // tenant-scoped runtime state reset
        record.active_credential_id = None;
        record.state = DeviceState::Transferred;
        record.updated_at_est = now_est;

        // 3) Bind to new tenant and issue fresh credential.
        let new_cred = self.issue_credential_internal(
            device_id,
            &new_tenant,
            now_est,
            old_cred.clone(),
            CredentialState::Active,
        );
        self.credentials.insert(new_cred.credential_id.clone(), new_cred.clone());
        let record = self.devices.get_mut(device_id).expect("checked");
        record.tenant = new_tenant.clone();
        record.site = new_site;
        record.active_credential_id = Some(new_cred.credential_id.clone());
        record.state = DeviceState::Active;
        record.updated_at_est = now_est;

        self.push_audit(
            now_est,
            Some(device_id.to_string()),
            Some(new_tenant.clone()),
            actor,
            AuditEventKind::OwnershipTransferred,
            format!(
                "ownership transferred from {} to {} with re-keying and tenant data cleared",
                old_tenant, new_tenant
            ),
        );
        Ok(new_cred)
    }

    /// Record reported firmware/config versions and detect drift.
    pub fn report_versions(
        &mut self,
        device_id: &str,
        reported: ReportedVersions,
        actor: impl Into<String>,
        now_est: i64,
    ) -> Result<DriftStatus, ProvisioningError> {
        let actor = actor.into();
        let (drift, was_drifted, tenant, reported_fw, reported_cfg) = {
            let record = self.device_mut(device_id)?;
            if record.state != DeviceState::Active {
                return Err(ProvisioningError::InvalidState {
                    state: record.state,
                    operation: "report_versions".to_string(),
                });
            }
            let expected = record.expected_versions.clone();
            let mut reported = reported;
            if reported.reported_at_est.is_none() {
                reported.reported_at_est = Some(now_est);
            }
            let drift = compute_drift(&expected, &reported);
            let was_drifted = compute_drift(&expected, &record.reported_versions).is_drifted();
            record.reported_versions = reported;
            record.updated_at_est = now_est;
            let tenant = record.tenant.clone();
            let reported_fw = record.reported_versions.firmware_version.clone();
            let reported_cfg = record.reported_versions.config_version.clone();
            (drift, was_drifted, tenant, reported_fw, reported_cfg)
        };
        self.push_audit(
            now_est,
            Some(device_id.to_string()),
            Some(tenant.clone()),
            actor.clone(),
            AuditEventKind::VersionReported,
            format!("versions reported (firmware={reported_fw:?}, config={reported_cfg:?})"),
        );
        if drift.is_drifted() {
            self.push_audit(
                now_est,
                Some(device_id.to_string()),
                Some(tenant),
                actor,
                AuditEventKind::DriftDetected,
                format!(
                    "drift detected (firmware={}, config={})",
                    drift.firmware_drifted, drift.config_drifted
                ),
            );
        } else if was_drifted {
            self.push_audit(
                now_est,
                Some(device_id.to_string()),
                Some(tenant),
                actor,
                AuditEventKind::DriftCleared,
                "version drift cleared".to_string(),
            );
        }
        Ok(drift)
    }

    /// Compute current drift status for a device.
    pub fn drift_status(&self, device_id: &str) -> Result<DriftStatus, ProvisioningError> {
        let record = self
            .devices
            .get(device_id)
            .ok_or_else(|| ProvisioningError::DeviceNotFound {
                device_id: device_id.to_string(),
            })?;
        Ok(compute_drift(&record.expected_versions, &record.reported_versions))
    }

    /// Query devices by tenant, site, type, and/or state.
    pub fn query(&self, filter: &DeviceQuery) -> Vec<DeviceRecord> {
        self.devices
            .values()
            .filter(|r| filter.matches(r))
            .cloned()
            .collect()
    }

    /// Look up a device record.
    pub fn get(&self, device_id: &str) -> Option<&DeviceRecord> {
        self.devices.get(device_id)
    }

    /// Look up a credential record.
    pub fn credential(&self, credential_id: &str) -> Option<&CredentialRecord> {
        self.credentials.get(credential_id)
    }

    /// Return the append-only audit trail.
    pub fn audit_log(&self) -> &[AuditRecord] {
        &self.audit
    }

    /// Return the reenrolment block for a device identity, if any.
    pub fn reenrolment_block(&self, device_id: &str) -> Option<&ReenrolmentBlock> {
        self.reenrolment_blocked.get(device_id)
    }

    fn device_mut(&mut self, device_id: &str) -> Result<&mut DeviceRecord, ProvisioningError> {
        self.devices.get_mut(device_id).ok_or_else(|| ProvisioningError::DeviceNotFound {
            device_id: device_id.to_string(),
        })
    }

    fn device_mut_active(
        &mut self,
        device_id: &str,
        operation: &str,
    ) -> Result<&mut DeviceRecord, ProvisioningError> {
        let state = self
            .devices
            .get(device_id)
            .ok_or_else(|| ProvisioningError::DeviceNotFound {
                device_id: device_id.to_string(),
            })?
            .state;
        if state != DeviceState::Active {
            return Err(ProvisioningError::InvalidState {
                state,
                operation: operation.to_string(),
            });
        }
        Ok(self.devices.get_mut(device_id).expect("checked"))
    }

    fn set_credential_state(
        &mut self,
        credential_id: &str,
        state: CredentialState,
        now_est: i64,
    ) -> Result<(), ProvisioningError> {
        let cred = self.credentials.get_mut(credential_id).ok_or_else(|| {
            ProvisioningError::CredentialNotFound {
                credential_id: credential_id.to_string(),
            }
        })?;
        cred.state = state;
        cred.updated_at_est = now_est;
        Ok(())
    }

    fn credentials_for_device(&self, device_id: &str) -> Vec<String> {
        self.credentials
            .values()
            .filter(|c| c.device_id == device_id)
            .map(|c| c.credential_id.clone())
            .collect()
    }

    fn push_audit(
        &mut self,
        at_est: i64,
        device_id: Option<String>,
        tenant: Option<TenantPath>,
        actor: String,
        kind: AuditEventKind,
        detail: String,
    ) {
        self.next_audit_seq = self.next_audit_seq.saturating_add(1);
        self.audit.push(AuditRecord {
            seq: self.next_audit_seq,
            at_est,
            device_id,
            tenant,
            actor,
            kind,
            detail,
        });
    }
}

/// Compute drift between expected and reported version sets.
pub fn compute_drift(expected: &VersionSet, reported: &ReportedVersions) -> DriftStatus {
    let firmware_drifted = match (&expected.firmware_version, &reported.firmware_version) {
        (Some(expected), Some(reported)) => expected != reported,
        (Some(_), None) => true,
        _ => false,
    };
    let config_drifted = match (&expected.config_version, &reported.config_version) {
        (Some(expected), Some(reported)) => expected != reported,
        (Some(_), None) => true,
        _ => false,
    };
    DriftStatus {
        firmware_drifted,
        config_drifted,
        expected: expected.clone(),
        reported: reported.clone(),
    }
}

/// Derive a deterministic, opaque claim code.
pub fn derive_claim_code(
    tenant: &TenantPath,
    site: Option<&str>,
    device_type: Option<&str>,
    nonce: &[u8],
    issued_at_est: i64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CLAIM_CODE_DOMAIN);
    hasher.update(tenant.as_fact_string().as_bytes());
    hasher.update([0]);
    hasher.update(site.unwrap_or("").as_bytes());
    hasher.update([0]);
    hasher.update(device_type.unwrap_or("").as_bytes());
    hasher.update([0]);
    hasher.update(nonce);
    hasher.update([0]);
    hasher.update(issued_at_est.to_le_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..16])
}

fn fingerprint_credential(
    device_id: &str,
    tenant: &TenantPath,
    seq: u64,
    now_est: i64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CREDENTIAL_DOMAIN);
    hasher.update(device_id.as_bytes());
    hasher.update([0]);
    hasher.update(tenant.as_fact_string().as_bytes());
    hasher.update([0]);
    hasher.update(seq.to_le_bytes());
    hasher.update(now_est.to_le_bytes());
    hex::encode(&hasher.finalize()[..16])
}

/// Helper to build and sign a provisioning payload.
pub fn build_signed_payload(
    payload_id: impl Into<String>,
    device_id: impl Into<String>,
    device_public_key: [u8; 32],
    tenant: TenantPath,
    site: Option<String>,
    device_type: impl Into<String>,
    claim_code: Option<String>,
    expected_versions: VersionSet,
    issued_at_est: i64,
    expires_at_est: Option<i64>,
    issued_by: impl Into<String>,
    authority: &SigningKey,
) -> Result<ProvisioningPayload, ProvisioningError> {
    let mut payload = ProvisioningPayload {
        payload_id: payload_id.into(),
        device_id: device_id.into(),
        device_public_key: device_public_key.to_vec(),
        tenant,
        site,
        device_type: device_type.into(),
        claim_code,
        expected_versions,
        issued_at_est,
        expires_at_est,
        issued_by: issued_by.into(),
        signature: Vec::new(),
    };
    payload.sign(authority)?;
    Ok(payload)
}

impl fmt::Display for DeviceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DeviceState::PendingEnrolment => "PendingEnrolment",
            DeviceState::Active => "Active",
            DeviceState::Revoked => "Revoked",
            DeviceState::Decommissioned => "Decommissioned",
            DeviceState::Transferred => "Transferred",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirbase_types::identity::{TenantLevel, TenantSegment};

    fn tenant(org: &str, site: &str) -> TenantPath {
        TenantPath::new(vec![
            TenantSegment::new(TenantLevel::Organisation, org),
            TenantSegment::new(TenantLevel::Site, site),
        ])
    }

    fn signing_key_from_seed_material(label: &[u8]) -> SigningKey {
        let mut hasher = Sha256::new();
        hasher.update(b"TirBase/F04/test-seed");
        hasher.update(label);
        let digest = hasher.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest);
        SigningKey::from_bytes(&seed)
    }

    fn authority() -> (SigningKey, [u8; 32]) {
        let key = signing_key_from_seed_material(b"authority");
        let public = key.verifying_key().to_bytes();
        (key, public)
    }

    fn sample_payload(
        authority: &SigningKey,
        tenant: TenantPath,
        site: Option<String>,
        claim_code: Option<String>,
        device_id: &str,
        payload_id: &str,
        now: i64,
    ) -> ProvisioningPayload {
        // Deterministic per-test device key based on device_id for stable identity.
        let pk = signing_key_from_seed_material(device_id.as_bytes())
            .verifying_key()
            .to_bytes();
        build_signed_payload(
            payload_id,
            device_id,
            pk,
            tenant,
            site,
            "cold-room-gateway",
            claim_code,
            VersionSet {
                firmware_version: Some("1.0.0".to_string()),
                config_version: Some("cfg-1".to_string()),
            },
            now,
            Some(now + 3600),
            "operator-1",
            authority,
        )
        .unwrap()
    }

    #[test]
    fn claim_code_signed_payload_and_tenant_binding_enrols_device() {
        let (auth, auth_pub) = authority();
        let t = tenant("acme", "site-1");
        let mut reg = DeviceLifecycleRegistry::new();
        let claim = reg.issue_claim_code(
            t.clone(),
            Some("site-1".to_string()),
            Some("cold-room-gateway".to_string()),
            "op",
            1000,
            600,
            b"nonce-1",
        );
        let payload = sample_payload(
            &auth,
            t.clone(),
            Some("site-1".to_string()),
            Some(claim.code.clone()),
            "did:key:zDevice1",
            "payload-1",
            1000,
        );
        let record = reg.enrol(&payload, &auth_pub, "op", 1000).unwrap();
        assert_eq!(record.state, DeviceState::Active);
        assert_eq!(record.tenant, t);
        assert_eq!(record.site.as_deref(), Some("site-1"));
        assert!(record.active_credential_id.is_some());
        assert!(reg.claim_codes.get(&claim.code).unwrap().is_used());
    }

    #[test]
    fn stolen_device_cannot_reenrol_without_revocation_and_reissue() {
        let (auth, auth_pub) = authority();
        let t = tenant("acme", "site-1");
        let mut reg = DeviceLifecycleRegistry::new();
        let claim = reg.issue_claim_code(t.clone(), None, None, "op", 1000, 600, b"n1");
        let payload = sample_payload(&auth, t.clone(), None, Some(claim.code), "did:key:zStolen", "p1", 1000);
        reg.enrol(&payload, &auth_pub, "op", 1000).unwrap();

        reg.revoke_credential("did:key:zStolen", None, "secops", 1100).unwrap();

        // Even with a fresh valid claim/payload for the same stolen identity, re-enrolment is blocked.
        let claim2 = reg.issue_claim_code(t.clone(), None, None, "op", 1200, 600, b"n2");
        let payload2 = sample_payload(&auth, t.clone(), None, Some(claim2.code), "did:key:zStolen", "p2", 1200);
        let err = reg.enrol(&payload2, &auth_pub, "attacker-or-op", 1200).unwrap_err();
        assert_eq!(
            err,
            ProvisioningError::ReenrolmentBlocked {
                device_id: "did:key:zStolen".to_string()
            }
        );

        // Explicit re-issue authorisation still does NOT allow the old identity back.
        reg.authorise_reissue("did:key:zStolen", "secops", 1300).unwrap();
        let claim3 = reg.issue_claim_code(t.clone(), None, None, "op", 1301, 600, b"n3");
        let payload3 = sample_payload(&auth, t, None, Some(claim3.code), "did:key:zStolen", "p3", 1301);
        assert!(matches!(
            reg.enrol(&payload3, &auth_pub, "op", 1301),
            Err(ProvisioningError::ReenrolmentBlocked { .. })
        ));
    }

    #[test]
    fn ownership_transfer_rekeys_clears_old_tenant_data_and_audits() {
        let (auth, auth_pub) = authority();
        let t1 = tenant("acme", "site-1");
        let t2 = tenant("globex", "site-9");
        let mut reg = DeviceLifecycleRegistry::new();
        let claim = reg.issue_claim_code(t1.clone(), None, None, "op", 1000, 600, b"n1");
        let payload = sample_payload(&auth, t1.clone(), None, Some(claim.code), "did:key:zMove", "p1", 1000);
        reg.enrol(&payload, &auth_pub, "op", 1000).unwrap();
        let old_cred = reg.get("did:key:zMove").unwrap().active_credential_id.clone().unwrap();
        reg.report_versions(
            "did:key:zMove",
            ReportedVersions {
                firmware_version: Some("1.0.0".to_string()),
                config_version: Some("cfg-1".to_string()),
                reported_at_est: Some(1050),
            },
            "device",
            1050,
        )
        .unwrap();

        let new_cred = reg
            .transfer_ownership(
                "did:key:zMove",
                t2.clone(),
                Some("site-9".to_string()),
                "admin",
                2000,
            )
            .unwrap();
        let record = reg.get("did:key:zMove").unwrap().clone();
        assert_eq!(record.tenant, t2);
        assert_eq!(record.site.as_deref(), Some("site-9"));
        assert_ne!(record.active_credential_id.as_deref(), Some(old_cred.as_str()));
        assert_eq!(record.active_credential_id.as_deref(), Some(new_cred.credential_id.as_str()));
        // Old tenant runtime material cleared (reported versions reset) and clearance recorded.
        assert_eq!(record.reported_versions, ReportedVersions::default());
        assert_eq!(record.tenant_data_cleared_at_est, Some(2000));
        assert_eq!(record.previous_tenants, vec![t1.clone()]);
        assert_eq!(reg.credential(&old_cred).unwrap().state, CredentialState::Revoked);
        assert_ne!(reg.credential(&old_cred).unwrap().tenant, t2);
        assert!(reg.audit_log().iter().any(|a| {
            a.kind == AuditEventKind::OwnershipTransferred
                && a.detail.contains("acme")
                && a.detail.contains("globex")
                && a.detail.contains("re-keying")
        }));

        // Registry queries must not leak the device into old-tenant results.
        assert!(reg
            .query(&DeviceQuery {
                tenant: Some(t1),
                ..Default::default()
            })
            .is_empty());
        assert_eq!(
            reg.query(&DeviceQuery {
                tenant: Some(t2),
                ..Default::default()
            })
            .len(),
            1
        );
    }

    #[test]
    fn offline_provisioning_is_bounded_replay_protected_and_idempotent() {
        let (auth, auth_pub) = authority();
        let t = tenant("acme", "site-1");
        let mut reg = DeviceLifecycleRegistry::new();
        let claim = reg.issue_claim_code(t.clone(), None, None, "op", 1000, 600, b"n1");
        let payload = sample_payload(&auth, t.clone(), None, Some(claim.code), "did:key:zOffline", "payload-offline", 1000);
        assert!(payload.encoded_len().unwrap() <= MAX_OFFLINE_PROVISIONING_PAYLOAD_BYTES);

        let first = reg
            .apply_offline_provisioning(&payload, &auth_pub, "field-tech", 1000)
            .unwrap();
        assert!(!first.idempotent_replay);
        assert_eq!(first.record.state, DeviceState::Active);

        // Same payload again is idempotent (safe retry).
        let second = reg
            .apply_offline_provisioning(&payload, &auth_pub, "field-tech", 1001)
            .unwrap();
        assert!(second.idempotent_replay);
        assert_eq!(second.record.device_id, "did:key:zOffline");
        assert_eq!(reg.devices.len(), 1);

        // Different payload id targeting the same identity is a replay/tamper-style reuse attempt
        // blocked by the one-time identity enrolment and prior application state.
        let claim2 = reg.issue_claim_code(t.clone(), None, None, "op", 1002, 600, b"n2");
        let payload2 = sample_payload(&auth, t, None, Some(claim2.code), "did:key:zOffline", "payload-offline-2", 1002);
        assert!(reg
            .apply_offline_provisioning(&payload2, &auth_pub, "field-tech", 1002)
            .is_err());
    }

    #[test]
    fn credential_lifecycle_issue_rotate_revoke_replace_decommission() {
        let (auth, auth_pub) = authority();
        let t = tenant("acme", "site-1");
        let mut reg = DeviceLifecycleRegistry::new();
        let claim = reg.issue_claim_code(t.clone(), None, None, "op", 1000, 600, b"n1");
        let payload = sample_payload(&auth, t, None, Some(claim.code), "did:key:zCred", "p1", 1000);
        reg.enrol(&payload, &auth_pub, "op", 1000).unwrap();
        let issued = reg.get("did:key:zCred").unwrap().active_credential_id.clone().unwrap();

        let rotated = reg.rotate_credential("did:key:zCred", "op", 1100).unwrap();
        assert_ne!(rotated.credential_id, issued);
        assert_eq!(reg.credential(&issued).unwrap().state, CredentialState::Replaced);

        let replaced = reg.replace_credential("did:key:zCred", "op", 1200).unwrap();
        assert_eq!(reg.credential(&rotated.credential_id).unwrap().state, CredentialState::Revoked);
        assert_eq!(reg.get("did:key:zCred").unwrap().active_credential_id.as_deref(), Some(replaced.credential_id.as_str()));

        reg.decommission_device("did:key:zCred", "op", 1300).unwrap();
        let record = reg.get("did:key:zCred").unwrap();
        assert_eq!(record.state, DeviceState::Decommissioned);
        assert!(record.active_credential_id.is_none());
        assert_eq!(record.tenant_data_cleared_at_est, Some(1300));
        assert!(reg.credential(&replaced.credential_id).unwrap().state == CredentialState::Decommissioned
            || reg.credential(&replaced.credential_id).unwrap().state == CredentialState::Revoked);
    }

    #[test]
    fn version_reporting_and_drift_detection() {
        let (auth, auth_pub) = authority();
        let t = tenant("acme", "site-1");
        let mut reg = DeviceLifecycleRegistry::new();
        let claim = reg.issue_claim_code(t.clone(), None, None, "op", 1000, 600, b"n1");
        let payload = sample_payload(&auth, t, None, Some(claim.code), "did:key:zDrift", "p1", 1000);
        reg.enrol(&payload, &auth_pub, "op", 1000).unwrap();

        let drift = reg
            .report_versions(
                "did:key:zDrift",
                ReportedVersions {
                    firmware_version: Some("0.9.0".to_string()),
                    config_version: Some("cfg-1".to_string()),
                    reported_at_est: Some(1100),
                },
                "device",
                1100,
            )
            .unwrap();
        assert!(drift.firmware_drifted);
        assert!(!drift.config_drifted);
        assert!(drift.is_drifted());

        let cleared = reg
            .report_versions(
                "did:key:zDrift",
                ReportedVersions {
                    firmware_version: Some("1.0.0".to_string()),
                    config_version: Some("cfg-1".to_string()),
                    reported_at_est: Some(1200),
                },
                "device",
                1200,
            )
            .unwrap();
        assert!(!cleared.is_drifted());
        assert!(reg.audit_log().iter().any(|a| a.kind == AuditEventKind::DriftDetected));
        assert!(reg.audit_log().iter().any(|a| a.kind == AuditEventKind::DriftCleared));
    }

    #[test]
    fn registry_queries_by_tenant_site_type_and_state() {
        let (auth, auth_pub) = authority();
        let t1 = tenant("acme", "site-1");
        let t2 = tenant("acme", "site-2");
        let mut reg = DeviceLifecycleRegistry::new();
        for (i, (t, site, ty, did)) in [
            (t1.clone(), "site-1", "sensor", "did:key:z1"),
            (t1.clone(), "site-1", "camera", "did:key:z2"),
            (t2.clone(), "site-2", "sensor", "did:key:z3"),
        ]
        .into_iter()
        .enumerate()
        {
            let claim = reg.issue_claim_code(t.clone(), Some(site.to_string()), Some(ty.to_string()), "op", 1000 + i as i64, 600, format!("n{i}").as_bytes());
            let mut payload = sample_payload(&auth, t, Some(site.to_string()), Some(claim.code), did, &format!("p{i}"), 1000);
            payload.device_type = ty.to_string();
            payload.sign(&auth).unwrap();
            reg.enrol(&payload, &auth_pub, "op", 1000).unwrap();
        }
        reg.revoke_credential("did:key:z2", None, "op", 2000).unwrap();

        assert_eq!(reg.query(&DeviceQuery { tenant: Some(t1.clone()), ..Default::default() }).len(), 2);
        assert_eq!(reg.query(&DeviceQuery { site: Some("site-1".to_string()), ..Default::default() }).len(), 2);
        assert_eq!(reg.query(&DeviceQuery { device_type: Some("sensor".to_string()), ..Default::default() }).len(), 2);
        assert_eq!(reg.query(&DeviceQuery { state: Some(DeviceState::Active), ..Default::default() }).len(), 2);
        assert_eq!(reg.query(&DeviceQuery { state: Some(DeviceState::Revoked), ..Default::default() }).len(), 1);
        assert_eq!(
            reg.query(&DeviceQuery {
                tenant: Some(t1),
                site: Some("site-1".to_string()),
                device_type: Some("sensor".to_string()),
                state: Some(DeviceState::Active),
            })
            .len(),
            1
        );
    }
}
