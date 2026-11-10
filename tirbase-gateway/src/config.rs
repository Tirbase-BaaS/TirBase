//! Gateway TOML configuration and signed config-bundle validation
//! (CLAIM-35.2, PV-11.1).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tirbase_guard::signed_operation::SignedOperation;
use tirbase_guard::trust_root::{AuthorizedRoleSigner, RolePolicy, TrustRootRecord};
use tirbase_types::CommandRole;

/// Which [`KeyProvider`](tirbase_core::traits::KeyProvider) backend to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyBackend {
    /// File-backed Ed25519 key (development and software deployments).
    #[default]
    File,
    /// TPM2-sealed key (requires `--features tpm2`; CLAIM-6.3).
    Tpm2,
    /// PKCS#11 hardware token (requires `--features pkcs11`; CLAIM-6.4).
    Pkcs11,
}

/// Top-level gateway configuration deserialized from a TOML file.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// Path to the device key file (PEM or raw bytes).
    pub key_path: PathBuf,

    /// Key provider backend (defaults to `file`).
    #[serde(default)]
    pub key_backend: KeyBackend,

    /// Address to listen on for admin Unix socket.
    #[serde(default = "default_admin_sock")]
    pub admin_socket: PathBuf,

    /// Address for the health HTTP endpoint.
    #[serde(default = "default_health_addr")]
    pub health_addr: std::net::SocketAddr,

    /// Address for Prometheus metrics endpoint.
    #[serde(default = "default_metrics_addr")]
    pub metrics_addr: std::net::SocketAddr,

    /// Optional log level override (e.g. `"debug"`, `"info"`).
    #[serde(default)]
    pub log_level: Option<String>,

    /// SQLite database holding the Level 1 monotonic counter and the
    /// hardware-counter binding state (`monotonic_counters`).
    /// Defaults to `primary.db` (PrimaryLedger, synchronous=FULL).
    #[serde(default = "default_counter_db")]
    pub counter_db_path: PathBuf,

    /// DerivedLedger database (synchronous=NORMAL).  Created/opened at boot via
    /// the migration framework (task 18.2, CLAIM-18.2).
    #[serde(default = "default_derived_db")]
    pub derived_db_path: PathBuf,

    /// Security event log on-disk retention: archive/delete oldest signed segment
    /// when age exceeds this many days (PV-7.13, CLAIM-28.2). 0 disables age limit.
    #[serde(default = "default_security_event_retention_days")]
    pub security_event_retention_days: i64,

    /// Security event log on-disk retention: archive/delete oldest signed segment
    /// when total security_events payload exceeds this many bytes (PV-7.13, CLAIM-28.2).
    /// 0 disables size limit. Default 1 GiB.
    #[serde(default = "default_security_event_retention_bytes")]
    pub security_event_retention_bytes: i64,

    /// Directory where rotated signed security-event segments are archived before
    /// deletion (PV-7.13, CLAIM-28.2). Defaults next to primary.db.
    #[serde(default)]
    pub security_event_archive_dir: Option<PathBuf>,

    /// Retention/rotation background job cadence in seconds (PV-7.13, CLAIM-28.2).
    #[serde(default = "default_security_event_rotation_interval_secs")]
    pub security_event_rotation_interval_secs: u64,

    /// How often the checkpoint loop binds the software counter to the
    /// hardware counter (PV-7.3 cadence; CLAIM-6.7a).  Defaults to 60 seconds.
    #[serde(default = "default_checkpoint_interval_secs")]
    pub checkpoint_interval_secs: u64,

    /// Largest forward jump a single TimeBeacon may make without an M-of-N
    /// `TimeAnchor` quorum (PV-22.5; default 86,400 s).
    #[serde(default = "default_max_forward_jump_secs")]
    pub time_max_forward_jump_secs: i64,

    /// M in the M-of-N `TimeAnchor` quorum required for large ratchet jumps
    /// (PV-22.5; default 2).
    #[serde(default = "default_required_anchor_signatures")]
    pub time_required_anchor_signatures: usize,

    /// Staleness window after which `FreshnessState` becomes `Unverified`
    /// (PV-22.3; default 3,600 s).
    #[serde(default = "default_staleness_window_secs")]
    pub time_staleness_window_secs: i64,

    /// Validity window of the gateway boot attestation, measured from the
    /// ratchet floor in authenticated time (seconds; default 300).
    #[serde(default = "default_boot_attestation_ttl_secs")]
    pub boot_attestation_ttl_secs: i64,

    /// Optional signed `TimeBeacon` envelope consumed at boot (task 7.4).
    #[serde(default)]
    pub time_beacon_path: Option<PathBuf>,

    /// Trusted `TimeAnchor` public keys (JSON `did` → hex Ed25519 key).
    /// Required when `time_beacon_path` is set.
    #[serde(default)]
    pub time_anchor_keys_path: Option<PathBuf>,

    /// TPM2 NV index holding the sealed Ed25519 seed (CLAIM-6.3).
    #[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
    #[serde(default = "default_tpm2_nv_handle")]
    pub tpm2_nv_handle: u32,

    /// Optional PCR policy digest file for the TPM2-sealed seed.  The digest
    /// is read from this path; it is not inlined in the config file.
    #[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
    #[serde(default)]
    pub tpm2_pcr_policy_path: Option<PathBuf>,

    /// PKCS#11 slot / token identifier (CLAIM-6.4).
    #[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
    #[serde(default)]
    pub pkcs11_slot: u64,

    /// Path to a file holding the PKCS#11 PIN.  The PIN is never inlined in
    /// `gateway.toml` (CLAIM-6.4, PV-3.6).
    #[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
    #[serde(default)]
    pub pkcs11_pin_path: Option<PathBuf>,

    /// Offline-ceremony `TrustRootRecord` (JSON).  When present the gateway
    /// verifies its threshold signatures and installs it under rollback
    /// protection (tasks 8.2/8.3 — CLAIM-8.2, CLAIM-8.3).
    #[serde(default)]
    pub trust_root_path: Option<PathBuf>,

    /// Optional signed rotation record applied at boot.  A record whose
    /// version is not strictly greater than the committed trust-root version
    /// is rejected with `TrustRootRollbackRejected` (task 8.2).
    #[serde(default)]
    pub trust_root_rotation_path: Option<PathBuf>,

    /// Optional Biscuit token (hex) used at boot to prove the token path fails
    /// before root CA registration and succeeds after (task 8.1, CLAIM-8.1).
    #[serde(default)]
    pub root_ca_self_test_token_path: Option<PathBuf>,

    /// Root CA Ed25519 private key (hex, 32-byte seed) used to mint scoped
    /// enrollment tokens (task 8.6).  Never inlined in `gateway.toml`.
    #[serde(default)]
    pub enrollment_root_ca_private_key_path: Option<PathBuf>,

    /// Scoped enrollment-token TTL in seconds.  Clamped to the Biscuit window
    /// `[3600, 86400]` (default 86,400 — the admin API maximum; PV-3.11).
    #[serde(default = "default_enrollment_token_ttl_secs")]
    pub enrollment_token_ttl_secs: u64,

    /// Enrollment nonce retention window in seconds (PV-3.13; default 72h).
    #[serde(default = "default_enrollment_nonce_retention_secs")]
    pub enrollment_nonce_retention_secs: i64,

    /// Maximum number of retained enrollment nonces.
    #[serde(default = "default_enrollment_nonce_capacity")]
    pub enrollment_nonce_capacity: usize,

    /// Background nonce-purge cadence in seconds (PV-3.13).
    #[serde(default = "default_enrollment_nonce_purge_interval_secs")]
    pub enrollment_nonce_purge_interval_secs: u64,

    /// Optional signed `SignedOperation<EpochBump>` (JSON) applied at boot.
    #[serde(default)]
    pub epoch_bump_path: Option<PathBuf>,

    /// Whether to start the local admin listener (Linux only).
    #[serde(default = "default_admin_enabled")]
    pub admin_enabled: bool,

    /// Optional signed gateway config bundle (PolicyAuthority) instead of a plain
    /// TOML file. When present, the bundle payload is validated and used.
    #[serde(default)]
    pub config_bundle_path: Option<PathBuf>,
}

impl GatewayConfig {
    /// Returns a derived DB path that lives alongside `counter_db_path` when the
    /// derived path is not explicitly configured to a different location.
    pub fn effective_derived_db_path(&self) -> PathBuf {
        let default = default_derived_db();
        if self.derived_db_path != default {
            return self.derived_db_path.clone();
        }
        if self.counter_db_path != default_counter_db() {
            if let Some(parent) = self.counter_db_path.parent() {
                return parent.join("derived.db");
            }
        }
        self.derived_db_path.clone()
    }

    /// Strict semantic validation of the parsed configuration (CLAIM-35.2).
    pub fn validate(&self) -> Result<()> {
        if self.key_path.as_os_str().is_empty() {
            bail!("gateway config schema validation failed: key_path must not be empty");
        }
        if self.health_addr.ip().to_string() != "127.0.0.1" {
            bail!(
                "gateway config schema validation failed: health_addr must bind 127.0.0.1 (got {})",
                self.health_addr
            );
        }
        if self.metrics_addr.ip().to_string() != "127.0.0.1" {
            bail!(
                "gateway config schema validation failed: metrics_addr must bind 127.0.0.1 (got {})",
                self.metrics_addr
            );
        }
        if self.checkpoint_interval_secs == 0 {
            bail!("gateway config schema validation failed: checkpoint_interval_secs must be >= 1");
        }
        if self.security_event_rotation_interval_secs == 0 {
            bail!("gateway config schema validation failed: security_event_rotation_interval_secs must be >= 1");
        }
        if self.time_required_anchor_signatures == 0 {
            bail!("gateway config schema validation failed: time_required_anchor_signatures must be >= 1");
        }
        if self.time_max_forward_jump_secs <= 0 {
            bail!(
                "gateway config schema validation failed: time_max_forward_jump_secs must be > 0"
            );
        }
        if self.time_staleness_window_secs <= 0 {
            bail!(
                "gateway config schema validation failed: time_staleness_window_secs must be > 0"
            );
        }
        if self.enrollment_nonce_capacity == 0 {
            bail!(
                "gateway config schema validation failed: enrollment_nonce_capacity must be >= 1"
            );
        }
        if self.enrollment_nonce_retention_secs <= 0 {
            bail!("gateway config schema validation failed: enrollment_nonce_retention_secs must be > 0");
        }
        if let Some(level) = &self.log_level {
            let ok = matches!(
                level.to_ascii_lowercase().as_str(),
                "trace" | "debug" | "info" | "warn" | "error"
            );
            if !ok {
                bail!("gateway config schema validation failed: log_level '{level}' is invalid");
            }
        }
        Ok(())
    }
}

/// Domain-separated payload for a PolicyAuthority-signed gateway config bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayConfigBundlePayload {
    /// TOML content of the gateway configuration.
    pub config_toml: String,
    /// Monotonic bundle/config version for operator auditability.
    #[serde(default)]
    pub config_version: u64,
}

impl tirbase_guard::signed_operation::SignedOperationPayload for GatewayConfigBundlePayload {
    const CONTEXT: &'static str = "TirBase/v1/GatewayConfigBundle";
}

/// Signed config bundle: payload + SignedOperation verified by PolicyAuthority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedGatewayConfigBundle {
    pub payload: GatewayConfigBundlePayload,
    pub operation: SignedOperation<GatewayConfigBundlePayload>,
}

/// Minimal PolicyAuthority trust root fixture format for config bundle verification.
#[derive(Debug, Deserialize)]
struct PaTrustFixture {
    did: String,
    public_key_hex: String,
}

fn load_pa_trust_root(path: &Path) -> Result<TrustRootRecord> {
    let body = std::fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read PolicyAuthority trust root: {}",
            path.display()
        )
    })?;
    // Accept either full TrustRootRecord JSON or the compact PA fixture used by task34.
    if let Ok(record) = serde_json::from_str::<TrustRootRecord>(&body) {
        return Ok(record);
    }
    let fx: PaTrustFixture = serde_json::from_str(&body)
        .context("failed to parse PolicyAuthority trust root as TrustRootRecord or PA fixture")?;
    let pk =
        hex::decode(fx.public_key_hex.trim()).context("invalid PolicyAuthority public_key_hex")?;
    if pk.len() != 32 {
        bail!("PolicyAuthority public_key_hex must decode to 32-byte Ed25519 key");
    }
    let mut roles = BTreeMap::new();
    roles.insert(
        CommandRole::PolicyAuthority,
        RolePolicy::new(
            1,
            vec![AuthorizedRoleSigner {
                did: fx.did,
                public_key: pk,
            }],
        ),
    );
    Ok(TrustRootRecord {
        version: 1,
        root_ca_public_keys: vec![vec![1u8; 32]],
        threshold_k: 1,
        role_thresholds: roles,
        device_class_floors: BTreeMap::new(),
        expiry_est: i64::MAX,
        revoked_root_ca_keys: Vec::new(),
        signatures: Vec::new(),
    })
}

fn verify_config_bundle(
    bundle: &SignedGatewayConfigBundle,
    trust: &TrustRootRecord,
    now_est: i64,
) -> Result<()> {
    bundle
        .operation
        .verify(&bundle.payload, |did| {
            trust
                .role_policy(CommandRole::PolicyAuthority)
                .and_then(|p| p.public_key_for(did).map(|k| k.to_vec()))
        })
        .map_err(|e| {
            anyhow::anyhow!("signed config bundle PolicyAuthority verification failed: {e}")
        })?;
    // Require at least one PolicyAuthority role signature.
    let ok = bundle
        .operation
        .signatures
        .iter()
        .any(|s| s.role == CommandRole::PolicyAuthority);
    if !ok {
        bail!("signed config bundle rejected: missing PolicyAuthority role signature");
    }
    // Expiry gate if present.
    if let Some(exp) = bundle.operation.expires_est {
        if now_est > exp {
            bail!("signed config bundle rejected: expired at now_est={now_est} expires_est={exp}");
        }
    }
    Ok(())
}

/// Load and validate a gateway config from a plain TOML file.
pub fn load_config_from_toml_path(path: &Path) -> Result<GatewayConfig> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read gateway config: {}", path.display()))?;
    let cfg: GatewayConfig = toml::from_str(&body).with_context(|| {
        format!(
            "gateway config schema validation failed: {}",
            path.display()
        )
    })?;
    cfg.validate()?;
    Ok(cfg)
}

/// Load and validate a signed gateway config bundle (PolicyAuthority-verified).
pub fn load_config_from_bundle_path(
    bundle_path: &Path,
    trust_root_path: &Path,
) -> Result<GatewayConfig> {
    let body = std::fs::read_to_string(bundle_path).with_context(|| {
        format!(
            "failed to read signed config bundle: {}",
            bundle_path.display()
        )
    })?;
    let bundle: SignedGatewayConfigBundle = serde_json::from_str(&body).with_context(|| {
        format!(
            "failed to parse signed config bundle: {}",
            bundle_path.display()
        )
    })?;
    let trust = load_pa_trust_root(trust_root_path)?;
    let now_est = tirbase_core::traits::wall_hint_secs().unwrap_or_default();
    verify_config_bundle(&bundle, &trust, now_est)?;
    let cfg: GatewayConfig = toml::from_str(&bundle.payload.config_toml)
        .context("signed config bundle payload is not a valid GatewayConfig TOML schema")?;
    cfg.validate()?;
    Ok(cfg)
}

/// Load config: if `trust_root_path` is provided alongside `--config-bundle` use
/// signed bundle validation, otherwise load plain TOML. Unsigned bundles are rejected.
pub fn load_gateway_config(
    config_path: &Path,
    config_bundle_path: Option<&Path>,
    bundle_trust_root_path: Option<&Path>,
) -> Result<GatewayConfig> {
    if let Some(bundle_path) = config_bundle_path {
        let trust = bundle_trust_root_path.context(
            "signed config bundle requires PolicyAuthority trust root (--config-bundle-trust-root); unsigned config bundles are rejected",
        )?;
        return load_config_from_bundle_path(bundle_path, trust);
    }
    load_config_from_toml_path(config_path)
}

fn default_admin_sock() -> PathBuf {
    PathBuf::from("/run/tirbase/admin.sock")
}
fn default_health_addr() -> std::net::SocketAddr {
    "127.0.0.1:8080".parse().unwrap()
}
fn default_metrics_addr() -> std::net::SocketAddr {
    "127.0.0.1:9090".parse().unwrap()
}
fn default_counter_db() -> PathBuf {
    PathBuf::from("/var/lib/tirbase/primary.db")
}
fn default_derived_db() -> PathBuf {
    PathBuf::from("/var/lib/tirbase/derived.db")
}
fn default_checkpoint_interval_secs() -> u64 {
    60
}
fn default_max_forward_jump_secs() -> i64 {
    86_400
}
fn default_required_anchor_signatures() -> usize {
    2
}
fn default_staleness_window_secs() -> i64 {
    3_600
}
fn default_boot_attestation_ttl_secs() -> i64 {
    300
}
fn default_tpm2_nv_handle() -> u32 {
    0x0150_0001
}
fn default_enrollment_token_ttl_secs() -> u64 {
    86_400
}
fn default_enrollment_nonce_retention_secs() -> i64 {
    72 * 60 * 60
}
fn default_enrollment_nonce_capacity() -> usize {
    100_000
}
fn default_enrollment_nonce_purge_interval_secs() -> u64 {
    300
}
fn default_admin_enabled() -> bool {
    true
}
fn default_security_event_retention_days() -> i64 {
    90
}
fn default_security_event_retention_bytes() -> i64 {
    1_073_741_824
}
fn default_security_event_rotation_interval_secs() -> u64 {
    300
}
