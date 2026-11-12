//! `tirbase-admin rollout` — staged rollout primitives (PV-8.9, RD-1).
//!
//! Operator procedure (not automated halt): canary ring assignment, per-device
//! migration state reporting, and signed rollback command generation.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct RolloutStatusArgs {
 /// Rollout identifier (stable string).
    pub rollout_id: String,
 /// Optional state file: JSON object { "device_id": { "migration_state": "...", ... } }
    pub state_path: Option<PathBuf>,
 /// Device IDs to report (repeatable).
    pub device_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeviceRolloutState {
    #[serde(default)]
    pub migration_state: String,
    #[serde(default)]
    pub schema_hash: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RolloutStatusRow {
    pub device_id: String,
    pub rollout_id: String,
 /// Canary ring 0-99 assigned by `H(device_id || rollout_id) mod 100`.
    pub canary_ring: u8,
    pub migration_state: String,
    pub schema_hash: Option<String>,
    pub last_error: Option<String>,
}

/// Canary ring assignment (1-100 devices conceptually via ring 0-99): `H(device_id || rollout_id) mod 100`.
pub fn canary_ring(device_id: &str, rollout_id: &str) -> u8 {
    let mut h = Sha256::new();
    h.update(device_id.as_bytes());
    h.update(b"||");
    h.update(rollout_id.as_bytes());
    let digest = h.finalize();
    let val = u64::from_le_bytes(digest[0..8].try_into().expect("slice"));
    (val % 100) as u8
}

pub fn run_status(args: &RolloutStatusArgs) -> Result<Vec<RolloutStatusRow>> {
    let mut state: BTreeMap<String, DeviceRolloutState> = BTreeMap::new();
    if let Some(path) = &args.state_path {
        if path.exists() {
            let body = std::fs::read_to_string(path)
                .with_context(|| format!("read {}", path.display()))?;
            state = serde_json::from_str(&body).context("parse rollout state JSON")?;
        }
    }
    let mut out = Vec::new();
    for device_id in &args.device_ids {
        let ds = state.get(device_id).cloned().unwrap_or(DeviceRolloutState {
            migration_state: "unknown".to_string(),
            ..Default::default()
        });
        out.push(RolloutStatusRow {
            device_id: device_id.clone(),
            rollout_id: args.rollout_id.clone(),
            canary_ring: canary_ring(device_id, &args.rollout_id),
            migration_state: ds.migration_state,
            schema_hash: ds.schema_hash,
            last_error: ds.last_error,
        });
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct SignedRollbackArgs {
    pub rollout_id: String,
    pub target_migration_id_hex: String,
 /// Hex-encoded 32-byte Ed25519 seed for PolicyAuthority/rollback signer (operator-held).
    pub signer_seed_hex: String,
    pub output: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRollbackCommand {
    pub version: u8,
    pub rollout_id: String,
    pub target_migration_id_hex: String,
    pub signer_public_key_hex: String,
    pub signature_hex: String,
    pub signed_at_hint_secs: i64,
}

pub fn run_signed_rollback(args: &SignedRollbackArgs) -> Result<SignedRollbackCommand> {
    use ed25519_dalek::{Signer, SigningKey};
    let seed = hex::decode(args.signer_seed_hex.trim()).context("signer_seed_hex")?;
    if seed.len() != 32 {
        bail!("signer seed must be 32 bytes");
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(&seed);
    let sk = SigningKey::from_bytes(&s);
    let vk = sk.verifying_key();
    let msg = canonical_rollback_bytes(&args.rollout_id, &args.target_migration_id_hex);
    let sig = sk.sign(&msg);
    let cmd = SignedRollbackCommand {
        version: 1,
        rollout_id: args.rollout_id.clone(),
        target_migration_id_hex: args.target_migration_id_hex.clone(),
        signer_public_key_hex: hex::encode(vk.to_bytes()),
        signature_hex: hex::encode(sig.to_bytes()),
        signed_at_hint_secs: tirbase_core::traits::wall_hint_secs().unwrap_or_default(),
    };
    let body = serde_json::to_vec_pretty(&cmd)?;
    if let Some(p) = args.output.parent() {
        if !p.as_os_str().is_empty() {
            std::fs::create_dir_all(p)?;
        }
    }
    std::fs::write(&args.output, body)?;
    Ok(cmd)
}

pub fn canonical_rollback_bytes(rollout_id: &str, target_migration_id_hex: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"tirbase/v1/rollback\0");
    h.update(rollout_id.as_bytes());
    h.update(b"\0");
    h.update(target_migration_id_hex.as_bytes());
    h.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canary_ring_is_deterministic_mod_100() {
        let a = canary_ring("did:key:dev1", "rollout-2026-11");
        let b = canary_ring("did:key:dev1", "rollout-2026-11");
        assert_eq!(a, b);
        assert!(a < 100);
        let c = canary_ring("did:key:dev2", "rollout-2026-11");
        assert!(c < 100);
    }
}
