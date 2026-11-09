//! Gateway self-update and config rollback (Task 30.9, PV-11.6).
//!
//! **BLOCKED: awaiting RFC-tuf.md merge per RD-6.** This module provides the
//! scaffolding/interfaces required by Task 30.9 but MUST NOT be wired as an
//! active production update path until `docs/RFC-tuf.md` is approved and the
//! update trust root/manifest format is finalized.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfUpdateError {
    /// BLOCKED: awaiting RFC-tuf.md merge per RD-6 (Task 30.9).
    BlockedPendingRfcTuf,
    InvalidManifest(String),
    ApplyFailed(String),
    RollbackFailed(String),
}

impl std::fmt::Display for SelfUpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BlockedPendingRfcTuf => write!(f, "BLOCKED: gateway self-update/config rollback awaiting RFC-tuf.md merge per RD-6 (Task 30.9)"),
            Self::InvalidManifest(s) => write!(f, "invalid signed firmware manifest: {s}"),
            Self::ApplyFailed(s) => write!(f, "update apply failed: {s}"),
            Self::RollbackFailed(s) => write!(f, "config rollback failed: {s}"),
        }
    }
}
impl std::error::Error for SelfUpdateError {}

/// Signed firmware-manifest delta (UpdateSigner credential). Placeholder until RD-6.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedFirmwareManifest {
    pub version: String,
    pub artifact_hash_sha256_hex: String,
    pub update_signer_did: String,
    pub signature_hex: String,
}

/// PolicyAuthority-signed config rollback operation. Placeholder until RD-6.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedConfigRollback {
    pub target_config_version: String,
    pub policy_authority_did: String,
    pub signature_hex: String,
}

#[derive(Debug, Default)]
pub struct SelfUpdateController {
    last_good_config_version: Option<String>,
}

impl SelfUpdateController {
    pub fn new(last_good_config_version: Option<String>) -> Self {
        Self {
            last_good_config_version,
        }
    }

    /// Accept a signed firmware-manifest delta. **BLOCKED pending RFC-tuf.md (RD-6).**
    pub fn apply_signed_firmware_manifest(
        &mut self,
        _manifest: &SignedFirmwareManifest,
    ) -> Result<(), SelfUpdateError> {
        Err(SelfUpdateError::BlockedPendingRfcTuf)
    }

    /// PolicyAuthority-signed config rollback. **BLOCKED pending RFC-tuf.md (RD-6).**
    pub fn rollback_config_signed(
        &mut self,
        _rollback: &SignedConfigRollback,
    ) -> Result<(), SelfUpdateError> {
        Err(SelfUpdateError::BlockedPendingRfcTuf)
    }

    /// Automatic rollback to last-good config on failed update (Task 30.9 intent).
    pub fn rollback_to_last_good(&mut self) -> Result<String, SelfUpdateError> {
        self.last_good_config_version.clone().ok_or_else(|| {
            SelfUpdateError::RollbackFailed("no last-good config version recorded".into())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_30_9_self_update_blocked_pending_rfc_tuf() {
        let mut c = SelfUpdateController::default();
        let m = SignedFirmwareManifest {
            version: "v0".into(),
            artifact_hash_sha256_hex: "00".into(),
            update_signer_did: "did:key:z".into(),
            signature_hex: "00".into(),
        };
        assert!(matches!(
            c.apply_signed_firmware_manifest(&m),
            Err(SelfUpdateError::BlockedPendingRfcTuf)
        ));
    }

    #[test]
    fn task_30_9_auto_rollback_uses_last_good() {
        let mut c = SelfUpdateController::new(Some("cfg-1".into()));
        assert_eq!(c.rollback_to_last_good().unwrap(), "cfg-1");
    }
}
