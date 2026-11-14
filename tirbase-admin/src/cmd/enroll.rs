// SPDX-License-Identifier: AGPL-3.0-only

//! `tirbase-admin enroll` — first-boot identity generation, replay-safe
//! bootstrap, and scoped token issuance (CLAIM-9.2, PV-3.10).
//!
//! The CLI drives the same [`EnrollmentService`] / [`EpochRegistry`] /
//! [`CoreHandle`] verification path as the gateway admin endpoint and the
//! integration tests.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tirbase_core::auth::biscuit;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_guard::enrollment::{DeviceIdentity, EnrolledDevice, EnrollmentService};
use tirbase_guard::epoch::{EpochRegistry, InMemoryEpochStore, InMemoryNonceStore};
use tirbase_guard::trust_root::{AuthorizedRoleSigner, RolePolicy, TrustRootRecord};
use tirbase_types::CommandRole;

/// Arguments for `tirbase-admin enroll`.
#[derive(Debug, Clone)]
pub struct EnrollArgs {
 /// Hex-encoded 32-byte Ed25519 root CA private seed used to mint the
 /// scoped Biscuit token. Never logged.
    pub root_ca_seed_hex: String,
 /// Role carried by the scoped token.
    pub role: String,
 /// Token TTL in seconds (clamped to the Biscuit window by the service).
    pub ttl_secs: u64,
 /// Optional path to persist the device identity. When omitted the
 /// identity is ephemeral and only the enrollment result is printed.
    pub device_key_path: Option<PathBuf>,
 /// Optional 64-character hex nonce. When omitted a random nonce is used.
    pub nonce_hex: Option<String>,
}

/// Run enrollment and return the issued device record.
///
/// This is the production entry point behind the CLI subcommand; removing the
/// enrollment call from it must fail the integration test (CLAIM-9.2 wiring
/// mutation intent).
pub fn run(args: &EnrollArgs) -> Result<EnrolledDevice> {
    let role = args
        .role
        .parse::<CommandRole>()
        .map_err(|_| anyhow::anyhow!("unknown role {:?}", args.role))?;
    let seed = decode_hex_32(&args.root_ca_seed_hex).context("root_ca_seed_hex")?;
    let root_public = public_from_seed(&seed)?;

    let rm = InMemoryKeyProvider::generate().context("generate RevocationManager placeholder")?;
    let trust_root = trust_root_for_enrollment(&rm, root_public);

    let nonces = Arc::new(InMemoryNonceStore::new());
    let epochs = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
    let service = EnrollmentService::new(
        nonces,
        epochs,
        Arc::new(trust_root),
        seed.to_vec(),
        args.ttl_secs,
    );

    let device = match &args.device_key_path {
        Some(path) => load_or_generate_device(path)?,
        None => DeviceIdentity::generate().context("generate device identity")?,
    };

    let nonce = match &args.nonce_hex {
        Some(hex_nonce) => decode_hex_32(hex_nonce).context("nonce_hex")?,
        None => random_nonce(),
    };
    let request = device
        .bootstrap(nonce, role)
        .context("build replay-safe bootstrap request")?;
    let now_est = tirbase_core::traits::wall_hint_secs().unwrap_or_default();
    let enrolled = service
        .enroll(&request, now_est)
        .context("enrollment rejected")?;

 // Sanity-check the issued token before reporting success.
    let _claims = biscuit::verify_token(&enrolled.token, &root_public, 0)
        .context("issued token failed post-enrollment verification")?;

    Ok(enrolled)
}

/// Print a JSON enrollment result to stdout.
pub fn print_result(result: &EnrolledDevice) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "device_id": result.device_id,
            "epoch": result.epoch,
            "token_hex": hex::encode(&result.token),
            "token_ttl_secs": result.token_ttl_secs,
        }))?
    );
    Ok(())
}

fn trust_root_for_enrollment(rm: &InMemoryKeyProvider, root_public: [u8; 32]) -> TrustRootRecord {
    let mut roles = std::collections::BTreeMap::new();
    roles.insert(
        CommandRole::RevocationManager,
        RolePolicy::new(
            1,
            vec![AuthorizedRoleSigner {
                did: rm.did().to_string(),
                public_key: rm.public_key_bytes(),
            }],
        ),
    );
    TrustRootRecord {
        version: 1,
        root_ca_public_keys: vec![root_public.to_vec()],
        threshold_k: 1,
        role_thresholds: roles,
        device_class_floors: std::collections::BTreeMap::new(),
        expiry_est: i64::MAX,
        revoked_root_ca_keys: Vec::new(),
        signatures: Vec::new(),
    }
}

fn load_or_generate_device(path: &Path) -> Result<DeviceIdentity> {
    if path.exists() {
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("read device key {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&body).context("parse device key")?;
        let seed_hex = value
            .get("secret_key_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("device key missing secret_key_hex"))?;
        let seed = decode_hex_32(seed_hex)?;
        Ok(DeviceIdentity::from_seed(seed))
    } else {
        let device = DeviceIdentity::generate().context("generate device identity")?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let body = serde_json::json!({
            "did": device.device_id(),
            "secret_key_hex": hex::encode(device.seed()),
            "public_key_hex": hex::encode(device.public_key()),
        });
        std::fs::write(path, serde_json::to_string_pretty(&body)?)?;
        Ok(device)
    }
}

fn decode_hex_32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value.trim())?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("expected 32 bytes, got {}", v.len()))
}

fn public_from_seed(seed: &[u8; 32]) -> Result<[u8; 32]> {
    let kp = InMemoryKeyProvider::from_seed(*seed);
    let public: [u8; 32] = kp
        .public_key_bytes()
        .try_into()
        .map_err(|_| anyhow::anyhow!("seed produced non-32-byte public key"))?;
    Ok(public)
}

fn random_nonce() -> [u8; 32] {
    let provider = InMemoryKeyProvider::generate()
        .unwrap_or_else(|_| InMemoryKeyProvider::from_seed([0u8; 32]));
    provider.secret_seed()
}
