//! Gateway self-update and config rollback (PV-11.6).
//!
//! The *mechanics* are implemented here: an `UpdateSigner`-signed firmware
//! manifest is verified over domain-separated canonical bytes, the new config is
//! applied atomically (temp file + rename), and a failed apply restores the
//! last-good config. `PolicyAuthority`-signed config rollback is verified and
//! applied the same way.
//!
//! **Owner decision still open (RD-6):** `docs/RFC-tuf.md` proposes a TUF-style
//! manifest/trust-root format. This module deliberately implements the update
//! and rollback *semantics* without committing to that wire format, so the
//! format decision does not have to be re-litigated in code. The module is not
//! yet exposed through an admin endpoint; enabling the active update path needs
//! both that wiring and the RD-6 decision, so stays open.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

const MANIFEST_CONTEXT: &str = "TirBase/v1/FirmwareManifest";
const ROLLBACK_CONTEXT: &str = "TirBase/v1/ConfigRollback";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfUpdateError {
 /// The manifest/rollback contains malformed fields.
    InvalidManifest(String),
 /// Signature did not verify against the configured role key.
    SignatureInvalid(String),
 /// No key is configured for the role that must sign this operation.
    MissingRoleKey(&'static str),
    ApplyFailed(String),
    RollbackFailed(String),
}

impl std::fmt::Display for SelfUpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidManifest(s) => write!(f, "invalid signed manifest: {s}"),
            Self::SignatureInvalid(s) => write!(f, "signature verification failed: {s}"),
            Self::MissingRoleKey(role) => write!(f, "no {role} public key configured"),
            Self::ApplyFailed(s) => write!(f, "update apply failed: {s}"),
            Self::RollbackFailed(s) => write!(f, "config rollback failed: {s}"),
        }
    }
}
impl std::error::Error for SelfUpdateError {}

/// Signed firmware-manifest delta (UpdateSigner credential).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedFirmwareManifest {
    pub version: String,
    pub artifact_hash_sha256_hex: String,
    pub update_signer_did: String,
 /// Ed25519 signature (hex) over [`Self::canonical_bytes`].
    pub signature_hex: String,
}

impl SignedFirmwareManifest {
 /// Domain-separated canonical bytes covered by the UpdateSigner signature.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MANIFEST_CONTEXT.as_bytes());
        out.push(0);
        out.extend_from_slice(self.version.as_bytes());
        out.push(0);
        out.extend_from_slice(self.artifact_hash_sha256_hex.as_bytes());
        out
    }
}

/// PolicyAuthority-signed config rollback operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedConfigRollback {
    pub target_config_version: String,
    pub policy_authority_did: String,
    pub signature_hex: String,
}

impl SignedConfigRollback {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(ROLLBACK_CONTEXT.as_bytes());
        out.push(0);
        out.extend_from_slice(self.target_config_version.as_bytes());
        out
    }
}

#[derive(Debug, Default)]
pub struct SelfUpdateController {
    last_good_config_version: Option<String>,
    last_good_config_contents: Option<Vec<u8>>,
    config_path: Option<PathBuf>,
    update_signer_public_key: Option<[u8; 32]>,
    policy_authority_public_key: Option<[u8; 32]>,
}

impl SelfUpdateController {
    pub fn new(last_good_config_version: Option<String>) -> Self {
        Self {
            last_good_config_version,
            ..Self::default()
        }
    }

    pub fn with_config_path(mut self, path: PathBuf) -> Self {
        self.config_path = Some(path);
        self
    }

    pub fn with_update_signer(mut self, public_key: [u8; 32]) -> Self {
        self.update_signer_public_key = Some(public_key);
        self
    }

    pub fn with_policy_authority(mut self, public_key: [u8; 32]) -> Self {
        self.policy_authority_public_key = Some(public_key);
        self
    }

    pub fn last_good_config_version(&self) -> Option<&str> {
        self.last_good_config_version.as_deref()
    }

 /// Verify an UpdateSigner-signed manifest and apply `new_config` atomically.
 ///
 /// On any write failure the previous config contents are restored, so a
 /// partially-written config never becomes the live one.
    pub fn apply_signed_firmware_manifest(
        &mut self,
        manifest: &SignedFirmwareManifest,
        new_config: &str,
    ) -> Result<(), SelfUpdateError> {
        let key = self
            .update_signer_public_key
            .ok_or(SelfUpdateError::MissingRoleKey("UpdateSigner"))?;
        verify_hex_signature(&key, &manifest.canonical_bytes(), &manifest.signature_hex)?;

        if let Some(path) = self.config_path.clone() {
            let previous = std::fs::read(&path).ok();
            if let Err(error) = write_atomic(&path, new_config.as_bytes()) {
                if let Some(prev) = previous.as_ref() {
                    let _ = write_atomic(&path, prev);
                }
                return Err(SelfUpdateError::ApplyFailed(error));
            }
            if previous.is_none() {
 // First successful apply becomes the last-good baseline.
                self.last_good_config_contents = None;
            }
        }

        self.last_good_config_version = Some(manifest.version.clone());
        Ok(())
    }

 /// Verify a PolicyAuthority-signed rollback and restore the last-good config.
    pub fn rollback_config_signed(
        &mut self,
        rollback: &SignedConfigRollback,
    ) -> Result<String, SelfUpdateError> {
        let key = self
            .policy_authority_public_key
            .ok_or(SelfUpdateError::MissingRoleKey("PolicyAuthority"))?;
        verify_hex_signature(&key, &rollback.canonical_bytes(), &rollback.signature_hex)?;
        if let Some(current) = self.last_good_config_version.as_deref() {
            if current != rollback.target_config_version {
                return Err(SelfUpdateError::RollbackFailed(format!(
                    "rollback target {} does not match last-good {}",
                    rollback.target_config_version, current
                )));
            }
        }
        self.rollback_to_last_good()
    }

 /// Restore the last-good config contents (if a config path is configured)
 /// and return the restored version.
    pub fn rollback_to_last_good(&mut self) -> Result<String, SelfUpdateError> {
        let version = self.last_good_config_version.clone().ok_or_else(|| {
            SelfUpdateError::RollbackFailed("no last-good config version recorded".into())
        })?;
        if let (Some(path), Some(contents)) = (&self.config_path, &self.last_good_config_contents) {
            write_atomic(path, contents).map_err(SelfUpdateError::RollbackFailed)?;
        }
        Ok(version)
    }

 /// Snapshot the current config as last-good before an update attempt.
    pub fn checkpoint_current_config(&mut self) -> Result<(), SelfUpdateError> {
        let Some(path) = &self.config_path else {
            return Ok(());
        };
        let contents = std::fs::read(path)
            .map_err(|e| SelfUpdateError::RollbackFailed(format!("read config: {e}")))?;
        self.last_good_config_contents = Some(contents);
        Ok(())
    }
}

/// Write `contents` to `path` atomically (same-directory temp file + rename).
fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), String> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("config"),
        std::process::id()
    ));
    std::fs::write(&tmp, contents).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("rename to {}: {e}", path.display())
    })
}

fn verify_hex_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature_hex: &str,
) -> Result<(), SelfUpdateError> {
    let sig_bytes: [u8; 64] = hex_to_vec(signature_hex)
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| SelfUpdateError::InvalidManifest("signature is not 64 hex bytes".into()))?;
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|e| SelfUpdateError::SignatureInvalid(format!("invalid public key: {e}")))?;
    key.verify_strict(message, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| SelfUpdateError::SignatureInvalid("Ed25519 verification failed".into()))
}

fn hex_to_vec(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sign(key: &SigningKey, message: &[u8]) -> String {
        let sig = key.sign(message);
        sig.to_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    fn manifest(key: &SigningKey, version: &str) -> SignedFirmwareManifest {
        let mut m = SignedFirmwareManifest {
            version: version.into(),
            artifact_hash_sha256_hex: "ab".repeat(32),
            update_signer_did: "did:key:zUpdate".into(),
            signature_hex: String::new(),
        };
        m.signature_hex = sign(key, &m.canonical_bytes());
        m
    }

    fn temp_config(tag: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "tirbase-selfupdate-{tag}-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn manifest_requires_configured_update_signer() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut c = SelfUpdateController::default();
        let err = c
            .apply_signed_firmware_manifest(&manifest(&key, "v2"), "x = 1\n")
            .unwrap_err();
        assert_eq!(err, SelfUpdateError::MissingRoleKey("UpdateSigner"));
    }

    #[test]
    fn tampered_manifest_is_rejected() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut m = manifest(&key, "v2");
        m.artifact_hash_sha256_hex = "cd".repeat(32); // mutate after signing
        let mut c = SelfUpdateController::default().with_update_signer(key.verifying_key().to_bytes());
        let err = c.apply_signed_firmware_manifest(&m, "x = 1\n").unwrap_err();
        assert!(matches!(err, SelfUpdateError::SignatureInvalid(_)), "{err:?}");
    }

    #[test]
    fn auto_rollback_uses_last_good() {
        let mut c = SelfUpdateController::new(Some("cfg-1".into()));
        assert_eq!(c.rollback_to_last_good().unwrap(), "cfg-1");
        assert_eq!(c.last_good_config_version(), Some("cfg-1"));
    }

    #[test]
    fn valid_manifest_applies_and_rolls_back_config() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let path = temp_config("apply", "mode = \"old\"\n");
        let mut c = SelfUpdateController::default()
            .with_config_path(path.clone())
            .with_update_signer(key.verifying_key().to_bytes())
            .with_policy_authority(key.verifying_key().to_bytes());
        c.checkpoint_current_config().unwrap();

        c.apply_signed_firmware_manifest(&manifest(&key, "v2"), "mode = \"new\"\n")
            .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "mode = \"new\"\n");
        assert_eq!(c.last_good_config_version(), Some("v2"));

 // A rollback signed by the PolicyAuthority restores the checkpointed config.
        let mut rollback = SignedConfigRollback {
            target_config_version: "v2".into(),
            policy_authority_did: "did:key:zPA".into(),
            signature_hex: String::new(),
        };
        rollback.signature_hex = sign(&key, &rollback.canonical_bytes());
        assert_eq!(c.rollback_config_signed(&rollback).unwrap(), "v2");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "mode = \"old\"\n");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unsigned_rollback_is_rejected() {
        let pa = SigningKey::from_bytes(&[3u8; 32]);
        let attacker = SigningKey::from_bytes(&[4u8; 32]);
        let mut rollback = SignedConfigRollback {
            target_config_version: "v2".into(),
            policy_authority_did: "did:key:zPA".into(),
            signature_hex: String::new(),
        };
        rollback.signature_hex = sign(&attacker, &rollback.canonical_bytes());
        let mut c = SelfUpdateController::default()
            .with_policy_authority(pa.verifying_key().to_bytes());
        let err = c.rollback_config_signed(&rollback).unwrap_err();
        assert!(matches!(err, SelfUpdateError::SignatureInvalid(_)), "{err:?}");
    }
}
