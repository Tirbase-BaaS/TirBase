//! `tirbase-admin rotate` — local device identity key rotation (task 9.4 —
//! CLAIM-9.4, PV-3.10).
//!
//! Rotation generates a fresh Ed25519 device identity, backs up the existing
//! key file (if present), and writes the new identity.  The operator receives
//! the old and new DIDs/public keys so dependent enrollment/trust records can
//! be updated through the appropriate signed ceremony.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;

/// Arguments for `tirbase-admin rotate`.
#[derive(Debug, Clone)]
pub struct RotateArgs {
    /// Path to the device identity JSON file to rotate.
    pub key_path: PathBuf,
    /// Where to write a backup of the previous key file.  Defaults to
    /// `<key_path>.bak`.
    pub backup_path: Option<PathBuf>,
}

/// Result of a key rotation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RotateResult {
    /// DID of the previous identity, if the key file existed.
    pub old_did: Option<String>,
    /// Public key (hex) of the previous identity, if present.
    pub old_public_key_hex: Option<String>,
    /// DID of the new identity.
    pub new_did: String,
    /// Public key (hex) of the new identity.
    pub new_public_key_hex: String,
    /// Path where the new identity was written.
    pub key_path: String,
    /// Path where the previous identity was backed up, if any.
    pub backup_path: Option<String>,
}

/// Rotate the device identity at `key_path`.
///
/// This is the production caller; removing the rotation/generation call must
/// fail the integration test.
pub fn run(args: &RotateArgs) -> Result<RotateResult> {
    let backup_path = args
        .backup_path
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("{}.bak", args.key_path.display())));

    let (old_did, old_public_key_hex, backed_up) = if args.key_path.exists() {
        let body = std::fs::read_to_string(&args.key_path)
            .with_context(|| format!("read {}", args.key_path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&body).context("parse identity")?;
        let old_did = value
            .get("did")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let old_pk = value
            .get("public_key_hex")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        std::fs::write(&backup_path, &body)
            .with_context(|| format!("write backup {}", backup_path.display()))?;
        (old_did, old_pk, Some(backup_path.display().to_string()))
    } else {
        (None, None, None)
    };

    let provider = InMemoryKeyProvider::generate().context("generate new identity")?;
    let new_did = provider.did().to_string();
    let new_public_key_hex = hex::encode(provider.public_key_bytes());
    write_identity(&args.key_path, &provider)?;

    Ok(RotateResult {
        old_did,
        old_public_key_hex,
        new_did,
        new_public_key_hex,
        key_path: args.key_path.display().to_string(),
        backup_path: backed_up,
    })
}

fn write_identity(path: &Path, provider: &InMemoryKeyProvider) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let body = serde_json::json!({
        "did": provider.did(),
        "secret_key_hex": hex::encode(provider.secret_seed()),
        "public_key_hex": hex::encode(provider.public_key_bytes()),
    });
    std::fs::write(path, serde_json::to_string_pretty(&body)?)?;
    Ok(())
}

/// Print the rotation result as JSON.
pub fn print_result(result: &RotateResult) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(result)?);
    Ok(())
}
