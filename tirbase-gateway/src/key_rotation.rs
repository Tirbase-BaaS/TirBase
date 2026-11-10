//! Device key rotation (task 36.3c, PV-11.2).
//!
//! The gateway loads a static device [`KeyProvider`](tirbase_core::traits::KeyProvider)
//! at boot.  The admin `rotate` endpoint delegates to a [`KeyRotator`]: it
//! generates a fresh Ed25519 identity, backs up the previous identity file, and
//! writes the new identity so the next boot (or an explicit reload in a future
//! revision) picks it up.  The running process keeps serving with the identity
//! it loaded; rotation never silently changes signing behaviour mid-flight.
//!
//! The file format matches `tirbase-admin rotate` so both entry points are
//! interchangeable.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;

/// Result of a successful key rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationOutcome {
    /// DID of the identity that was replaced, if a key file existed.
    pub old_did: Option<String>,
    /// DID of the newly generated identity.
    pub new_did: String,
    /// Hex-encoded Ed25519 public key of the new identity.
    pub new_public_key_hex: String,
    /// Path where the new identity was written.
    pub key_path: String,
    /// Path of the backup of the previous identity, if one was made.
    pub backup_path: Option<String>,
}

/// Rotation backend used by the admin dispatcher.
pub trait KeyRotator: Send + Sync + fmt::Debug {
    /// Rotate the active device identity.  Implementations must not return
    /// `Ok` unless the new identity is durably written.
    fn rotate(&self) -> Result<RotationOutcome, String>;
}

/// File-backed rotation matching `tirbase-admin rotate`.
#[derive(Debug, Clone)]
pub struct FileKeyRotator {
    key_path: PathBuf,
    backup_path: PathBuf,
}

impl FileKeyRotator {
    /// Create a rotator for `key_path`, backing up to `<key_path>.bak`.
    pub fn new(key_path: impl Into<PathBuf>) -> Self {
        let key_path = key_path.into();
        let backup_path = PathBuf::from(format!("{}.bak", key_path.display()));
        Self {
            key_path,
            backup_path,
        }
    }

    /// Create a rotator with an explicit backup path.
    pub fn with_backup(key_path: impl Into<PathBuf>, backup_path: impl Into<PathBuf>) -> Self {
        Self {
            key_path: key_path.into(),
            backup_path: backup_path.into(),
        }
    }

    fn write_identity(path: &Path, provider: &InMemoryKeyProvider) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| format!("create {parent:?}: {e}"))?;
            }
        }
        let body = serde_json::json!({
            "did": provider.did(),
            "secret_key_hex": hex::encode(provider.secret_seed()),
            "public_key_hex": hex::encode(provider.public_key_bytes()),
        });
        let encoded =
            serde_json::to_string_pretty(&body).map_err(|e| format!("encode identity: {e}"))?;
        std::fs::write(path, encoded).map_err(|e| format!("write {}: {e}", path.display()))
    }
}

impl KeyRotator for FileKeyRotator {
    fn rotate(&self) -> Result<RotationOutcome, String> {
        let (old_did, backup_path) = if self.key_path.exists() {
            let body = std::fs::read_to_string(&self.key_path)
                .map_err(|e| format!("read {}: {e}", self.key_path.display()))?;
            let value: serde_json::Value =
                serde_json::from_str(&body).map_err(|e| format!("parse identity: {e}"))?;
            let old_did = value
                .get("did")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned);
            std::fs::write(&self.backup_path, &body)
                .map_err(|e| format!("write backup {}: {e}", self.backup_path.display()))?;
            (old_did, Some(self.backup_path.display().to_string()))
        } else {
            (None, None)
        };

        let provider =
            InMemoryKeyProvider::generate().map_err(|e| format!("generate identity: {e}"))?;
        let new_did = provider.did().to_string();
        let new_public_key_hex = hex::encode(provider.public_key_bytes());
        Self::write_identity(&self.key_path, &provider)?;

        Ok(RotationOutcome {
            old_did,
            new_did,
            new_public_key_hex,
            key_path: self.key_path.display().to_string(),
            backup_path,
        })
    }
}

/// Shared trait-object alias used by [`crate::admin::AdminState`].
pub type SharedKeyRotator = Arc<dyn KeyRotator>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_backs_up_previous_identity_and_writes_new_key() {
        let dir = std::env::temp_dir().join(format!("tb-rotate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("device-key.json");
        let first = InMemoryKeyProvider::generate().unwrap();
        std::fs::write(
            &key_path,
            serde_json::json!({
                "did": first.did(),
                "secret_key_hex": hex::encode(first.secret_seed()),
                "public_key_hex": hex::encode(first.public_key_bytes()),
            })
            .to_string(),
        )
        .unwrap();

        let outcome = FileKeyRotator::new(&key_path).rotate().unwrap();
        assert_eq!(outcome.old_did.as_deref(), Some(first.did()));
        assert_ne!(outcome.new_did, first.did());
        assert!(key_path.exists());
        let backup = outcome.backup_path.expect("backup path");
        assert!(Path::new(&backup).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
