// SPDX-License-Identifier: AGPL-3.0-only

//! F-04 provisioning/lifecycle control plane for the gateway admin surface.
//!
//! [`ProvisioningService`] wraps the durable [`SqliteProvisioningStore`] and
//! delegates domain logic to [`tirbase_core::provisioning::DeviceLifecycleRegistry`].
//! Every mutation loads the registry, applies the core transition, and
//! transactionally writes the snapshot back, so operations are durable and a
//! failed call leaves the previous state intact.

use std::fmt;
use std::path::Path;
use std::sync::Mutex;

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use tirbase_core::provisioning::{
    build_signed_payload, DeviceLifecycleRegistry, DeviceQuery, DeviceRecord, DeviceState,
    DriftStatus, ProvisioningError, ProvisioningPayload, ReportedVersions, VersionSet,
};
use tirbase_types::identity::TenantPath;

use crate::db::provisioning::{ProvisioningStoreError, SqliteProvisioningStore};

/// Admin-surface error with the HTTP status the gateway should return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisioningServiceError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl ProvisioningServiceError {
    fn new(status: u16, code: &str, message: impl Into<String>) -> Self {
        ProvisioningServiceError {
            status,
            code: code.to_string(),
            message: message.into(),
        }
    }

    /// Machine-readable JSON body.
    pub fn to_json(&self) -> Value {
        json!({
            "status": self.status,
            "code": self.code,
            "error": self.message,
            "endpoint": "provisioning",
        })
    }
}

impl fmt::Display for ProvisioningServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ProvisioningServiceError {}

impl From<ProvisioningError> for ProvisioningServiceError {
    fn from(error: ProvisioningError) -> Self {
        let status = match &error {
            ProvisioningError::DeviceNotFound { .. }
            | ProvisioningError::CredentialNotFound { .. } => 404,
            ProvisioningError::ClaimCodeNotFound => 404,
            ProvisioningError::DeviceAlreadyExists { .. }
            | ProvisioningError::ClaimCodeAlreadyUsed
            | ProvisioningError::ClaimCodeExpired
            | ProvisioningError::ReenrolmentBlocked { .. }
            | ProvisioningError::ReplayDetected { .. }
            | ProvisioningError::InvalidState { .. } => 409,
            _ => 400,
        };
        let code = match &error {
            ProvisioningError::ClaimCodeNotFound => "CLAIM_CODE_NOT_FOUND",
            ProvisioningError::ClaimCodeExpired => "CLAIM_CODE_EXPIRED",
            ProvisioningError::ClaimCodeAlreadyUsed => "CLAIM_CODE_ALREADY_USED",
            ProvisioningError::ClaimCodeMismatch { .. } => "CLAIM_CODE_MISMATCH",
            ProvisioningError::DeviceNotFound { .. } => "DEVICE_NOT_FOUND",
            ProvisioningError::DeviceAlreadyExists { .. } => "DEVICE_ALREADY_EXISTS",
            ProvisioningError::InvalidState { .. } => "INVALID_DEVICE_STATE",
            ProvisioningError::InvalidPayload { .. } => "INVALID_PROVISIONING_PAYLOAD",
            ProvisioningError::PayloadTooLarge { .. } => "PROVISIONING_PAYLOAD_TOO_LARGE",
            ProvisioningError::InvalidPayloadSignature => "PROVISIONING_SIGNATURE_INVALID",
            ProvisioningError::IdentityMismatch { .. } => "DEVICE_IDENTITY_MISMATCH",
            ProvisioningError::ReenrolmentBlocked { .. } => "REENROLMENT_BLOCKED",
            ProvisioningError::ReplayDetected { .. } => "OFFLINE_PAYLOAD_REPLAY",
            ProvisioningError::CredentialNotFound { .. } => "CREDENTIAL_NOT_FOUND",
            ProvisioningError::CredentialInactive { .. } => "CREDENTIAL_INACTIVE",
            ProvisioningError::ReissueRequiresNewIdentity => "REISSUE_REQUIRES_NEW_IDENTITY",
            ProvisioningError::Crypto { .. } | ProvisioningError::Serialisation { .. } => {
                "PROVISIONING_CRYPTO_ERROR"
            }
        };
        ProvisioningServiceError::new(status, code, error.to_string())
    }
}

impl From<ProvisioningStoreError> for ProvisioningServiceError {
    fn from(error: ProvisioningStoreError) -> Self {
        ProvisioningServiceError::new(500, "PROVISIONING_STORE_ERROR", error.to_string())
    }
}

/// Durable provisioning lifecycle service.
pub struct ProvisioningService {
    store: Mutex<SqliteProvisioningStore>,
    authority_public_key: [u8; 32],
    authority_signer: Option<SigningKey>,
}

impl fmt::Debug for ProvisioningService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProvisioningService")
            .field(
                "authority_public_key_hex",
                &hex::encode(self.authority_public_key),
            )
            .field("can_sign_payloads", &self.authority_signer.is_some())
            .finish()
    }
}

impl ProvisioningService {
    /// Open the durable registry in `db_path`.
    ///
    /// `authority_public_key` verifies signed provisioning payloads. When
    /// `authority_signer` is supplied the service can also mint signed payloads
    /// (`build_payload`), which backs the CLI and operational admin flows.
    pub fn open(
        db_path: impl AsRef<Path>,
        authority_public_key: [u8; 32],
        authority_signer: Option<SigningKey>,
    ) -> Result<Self, ProvisioningServiceError> {
        if let Some(signer) = &authority_signer {
            if signer.verifying_key().to_bytes() != authority_public_key {
                return Err(ProvisioningServiceError::new(
                    503,
                    "PROVISIONING_AUTHORITY_KEY_MISMATCH",
                    "the configured authority signing key does not match the verification key",
                ));
            }
        }
        let store = SqliteProvisioningStore::open(db_path)?;
        Ok(ProvisioningService {
            store: Mutex::new(store),
            authority_public_key,
            authority_signer,
        })
    }

    /// Verification-only service (no payload minting).
    pub fn open_verifying(
        db_path: impl AsRef<Path>,
        authority_public_key: [u8; 32],
    ) -> Result<Self, ProvisioningServiceError> {
        Self::open(db_path, authority_public_key, None)
    }

    /// The configured payload-verification key.
    pub fn authority_public_key(&self) -> [u8; 32] {
        self.authority_public_key
    }

    /// `true` when this service can mint signed provisioning payloads.
    pub fn can_sign_payloads(&self) -> bool {
        self.authority_signer.is_some()
    }

    /// Build and sign a provisioning payload.
    #[allow(clippy::too_many_arguments)]
    pub fn build_payload(
        &self,
        payload_id: String,
        device_id: String,
        device_public_key: [u8; 32],
        tenant: TenantPath,
        site: Option<String>,
        device_type: String,
        claim_code: Option<String>,
        expected_versions: VersionSet,
        issued_at_est: i64,
        expires_at_est: Option<i64>,
        issued_by: String,
    ) -> Result<ProvisioningPayload, ProvisioningServiceError> {
        let signer = self.authority_signer.as_ref().ok_or_else(|| {
            ProvisioningServiceError::new(
                503,
                "PROVISIONING_SIGNER_UNCONFIGURED",
                "this gateway has no provisioning authority signing key",
            )
        })?;
        build_signed_payload(
            payload_id,
            device_id,
            device_public_key,
            tenant,
            site,
            device_type,
            claim_code,
            expected_versions,
            issued_at_est,
            expires_at_est,
            issued_by,
            signer,
        )
        .map_err(Into::into)
    }

    fn with_registry<T>(
        &self,
        now_est: i64,
        operation: impl FnOnce(&mut DeviceLifecycleRegistry) -> Result<T, ProvisioningServiceError>,
    ) -> Result<T, ProvisioningServiceError> {
        let store = match self.store.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut registry = store.load()?.ok_or_else(|| {
            ProvisioningServiceError::new(
                500,
                "PROVISIONING_STORE_ERROR",
                "provisioning registry row is missing",
            )
        })?;
        let result = operation(&mut registry)?;
        store.save(&registry, now_est)?;
        Ok(result)
    }

    /// Read-only registry access.
    pub fn with_view<T>(
        &self,
        operation: impl FnOnce(&DeviceLifecycleRegistry) -> T,
    ) -> Result<T, ProvisioningServiceError> {
        let store = match self.store.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let registry = store.load()?.ok_or_else(|| {
            ProvisioningServiceError::new(
                500,
                "PROVISIONING_STORE_ERROR",
                "provisioning registry row is missing",
            )
        })?;
        Ok(operation(&registry))
    }

    /// Issue a single-use claim code.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_claim_code(
        &self,
        tenant: TenantPath,
        site: Option<String>,
        device_type: Option<String>,
        issued_by: String,
        ttl_secs: i64,
        nonce: &[u8],
        now_est: i64,
    ) -> Result<Value, ProvisioningServiceError> {
        self.with_registry(now_est, |registry| {
            let claim = registry.issue_claim_code(
                tenant,
                site,
                device_type,
                issued_by,
                now_est,
                ttl_secs,
                nonce,
            );
            Ok(json!({"status": 200, "claim_code": claim}))
        })
    }

    /// Enrol a device from a signed provisioning payload.
    pub fn enrol(
        &self,
        payload: &ProvisioningPayload,
        actor: String,
        now_est: i64,
    ) -> Result<Value, ProvisioningServiceError> {
        let record = self.with_registry(now_est, |registry| {
            registry
                .enrol(payload, &self.authority_public_key, actor, now_est)
                .map_err(Into::into)
        })?;
        Ok(json!({"status": 200, "outcome": "device_enrolled", "device": record}))
    }

    /// Apply a bounded offline provisioning payload (idempotent replay-safe).
    pub fn apply_offline(
        &self,
        payload: &ProvisioningPayload,
        actor: String,
        now_est: i64,
    ) -> Result<Value, ProvisioningServiceError> {
        let result = self.with_registry(now_est, |registry| {
            registry
                .apply_offline_provisioning(payload, &self.authority_public_key, actor, now_est)
                .map_err(Into::into)
        })?;
        Ok(json!({
            "status": 200,
            "outcome": if result.idempotent_replay { "offline_provisioning_replayed" } else { "offline_provisioning_applied" },
            "idempotent_replay": result.idempotent_replay,
            "device": result.record,
        }))
    }

    pub fn rotate(
        &self,
        device_id: &str,
        actor: String,
        now_est: i64,
    ) -> Result<Value, ProvisioningServiceError> {
        let credential = self.with_registry(now_est, |registry| {
            registry
                .rotate_credential(device_id, actor, now_est)
                .map_err(Into::into)
        })?;
        Ok(json!({"status": 200, "outcome": "credential_rotated", "credential": credential}))
    }

    pub fn revoke(
        &self,
        device_id: &str,
        credential_id: Option<&str>,
        actor: String,
        now_est: i64,
    ) -> Result<Value, ProvisioningServiceError> {
        self.with_registry(now_est, |registry| {
            registry
                .revoke_credential(device_id, credential_id, actor, now_est)
                .map_err(Into::into)
        })?;
        Ok(json!({"status": 200, "outcome": "credential_revoked"}))
    }

    pub fn replace(
        &self,
        device_id: &str,
        actor: String,
        now_est: i64,
    ) -> Result<Value, ProvisioningServiceError> {
        let credential = self.with_registry(now_est, |registry| {
            registry
                .replace_credential(device_id, actor, now_est)
                .map_err(Into::into)
        })?;
        Ok(json!({"status": 200, "outcome": "credential_replaced", "credential": credential}))
    }

    pub fn decommission(
        &self,
        device_id: &str,
        actor: String,
        now_est: i64,
    ) -> Result<Value, ProvisioningServiceError> {
        self.with_registry(now_est, |registry| {
            registry
                .decommission_device(device_id, actor, now_est)
                .map_err(Into::into)
        })?;
        Ok(json!({"status": 200, "outcome": "device_decommissioned"}))
    }

    pub fn authorise_reissue(
        &self,
        device_id: &str,
        actor: String,
        now_est: i64,
    ) -> Result<Value, ProvisioningServiceError> {
        self.with_registry(now_est, |registry| {
            registry
                .authorise_reissue(device_id, actor, now_est)
                .map_err(Into::into)
        })?;
        Ok(json!({"status": 200, "outcome": "reissue_authorised", "device_id": device_id}))
    }

    pub fn transfer(
        &self,
        device_id: &str,
        new_tenant: TenantPath,
        new_site: Option<String>,
        actor: String,
        now_est: i64,
    ) -> Result<Value, ProvisioningServiceError> {
        let credential = self.with_registry(now_est, |registry| {
            registry
                .transfer_ownership(device_id, new_tenant, new_site, actor, now_est)
                .map_err(Into::into)
        })?;
        Ok(json!({"status": 200, "outcome": "ownership_transferred", "credential": credential}))
    }

    pub fn report_versions(
        &self,
        device_id: &str,
        reported: ReportedVersions,
        actor: String,
        now_est: i64,
    ) -> Result<Value, ProvisioningServiceError> {
        let drift = self.with_registry(now_est, |registry| {
            registry
                .report_versions(device_id, reported, actor, now_est)
                .map_err(Into::into)
        })?;
        Ok(json!({"status": 200, "outcome": "versions_reported", "drift": drift}))
    }

    pub fn drift(&self, device_id: &str) -> Result<Value, ProvisioningServiceError> {
        let drift: DriftStatus = self.with_view(|registry| registry.drift_status(device_id))??;
        Ok(json!({"status": 200, "drift": drift}))
    }

    pub fn query(&self, filter: &DeviceQuery) -> Result<Value, ProvisioningServiceError> {
        let devices: Vec<DeviceRecord> = self.with_view(|registry| registry.query(filter))?;
        Ok(json!({"status": 200, "count": devices.len(), "devices": devices}))
    }

    pub fn audit(&self, device_id: Option<&str>) -> Result<Value, ProvisioningServiceError> {
        let records = self.with_view(|registry| {
            registry
                .audit_log()
                .iter()
                .filter(|record| {
                    device_id
                        .map(|id| record.device_id.as_deref() == Some(id))
                        .unwrap_or(true)
                })
                .cloned()
                .collect::<Vec<_>>()
        })?;
        Ok(json!({"status": 200, "count": records.len(), "audit": records}))
    }
}

/// Parse a `DeviceState` from its canonical name.
pub fn parse_device_state(value: &str) -> Option<DeviceState> {
    match value {
        "PendingEnrolment" | "pending" | "pending_enrolment" => Some(DeviceState::PendingEnrolment),
        "Active" | "active" => Some(DeviceState::Active),
        "Revoked" | "revoked" => Some(DeviceState::Revoked),
        "Decommissioned" | "decommissioned" => Some(DeviceState::Decommissioned),
        "Transferred" | "transferred" => Some(DeviceState::Transferred),
        _ => None,
    }
}

/// Parse a tenant path string rendered by `TenantPath` (`/Organisation:acme/Site:s1`).
pub fn parse_tenant_path_string(value: &str) -> Result<TenantPath, ProvisioningServiceError> {
    if value.trim().is_empty() || value == "/" {
        return Ok(TenantPath::root());
    }
    let mut segments = Vec::new();
    for part in value.trim().trim_start_matches('/').split('/') {
        let (level, id) = part.split_once(':').ok_or_else(|| {
            ProvisioningServiceError::new(
                400,
                "INVALID_TENANT",
                format!("tenant segment {part:?} must be level:id"),
            )
        })?;
        let level = level.parse().map_err(|_| {
            ProvisioningServiceError::new(400, "INVALID_TENANT", format!("unknown level {level:?}"))
        })?;
        segments.push(tirbase_types::identity::TenantSegment::new(level, id));
    }
    Ok(TenantPath::new(segments))
}

/// Parse a 32-byte hex public key.
pub fn parse_public_key_hex(value: &str) -> Result<[u8; 32], ProvisioningServiceError> {
    let bytes = hex::decode(value.trim()).map_err(|error| {
        ProvisioningServiceError::new(400, "INVALID_PUBLIC_KEY", format!("hex: {error}"))
    })?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        ProvisioningServiceError::new(400, "INVALID_PUBLIC_KEY", "key must be 32 bytes")
    })
}

/// Parse a 32-byte hex Ed25519 seed into a signing key.
pub fn parse_signing_key_hex(value: &str) -> Result<SigningKey, ProvisioningServiceError> {
    let seed = parse_public_key_hex(value)?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Public key bytes for a signing key.
pub fn signing_key_public(signer: &SigningKey) -> [u8; 32] {
    signer.verifying_key().to_bytes()
}
