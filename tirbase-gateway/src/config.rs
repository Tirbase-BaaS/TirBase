//! Gateway TOML configuration (task 4.9.1 — PV-30.1).

use serde::Deserialize;

/// Which [`KeyProvider`](tirbase_core::traits::KeyProvider) backend to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
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
#[derive(Debug, Deserialize)]
pub struct GatewayConfig {
    /// Path to the device key file (PEM or raw bytes).
    pub key_path: std::path::PathBuf,

    /// Key provider backend (defaults to `file`).
    #[serde(default)]
    pub key_backend: KeyBackend,

    /// Address to listen on for admin Unix socket.
    #[serde(default = "default_admin_sock")]
    pub admin_socket: std::path::PathBuf,

    /// Address for the health HTTP endpoint.
    #[serde(default = "default_health_addr")]
    pub health_addr: std::net::SocketAddr,

    /// Optional log level override (e.g. `"debug"`, `"info"`).
    #[serde(default)]
    pub log_level: Option<String>,

    /// SQLite database holding the Level 1 monotonic counter and the
    /// hardware-counter binding state (`monotonic_counters`).
    #[serde(default = "default_counter_db")]
    pub counter_db_path: std::path::PathBuf,

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
    pub time_beacon_path: Option<std::path::PathBuf>,

    /// Trusted `TimeAnchor` public keys (JSON `did` → hex Ed25519 key).
    /// Required when `time_beacon_path` is set.
    #[serde(default)]
    pub time_anchor_keys_path: Option<std::path::PathBuf>,

    /// TPM2 NV index holding the sealed Ed25519 seed (CLAIM-6.3).
    #[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
    #[serde(default = "default_tpm2_nv_handle")]
    pub tpm2_nv_handle: u32,

    /// Optional PCR policy digest file for the TPM2-sealed seed.  The digest
    /// is read from this path; it is not inlined in the config file.
    #[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
    #[serde(default)]
    pub tpm2_pcr_policy_path: Option<std::path::PathBuf>,

    /// PKCS#11 slot / token identifier (CLAIM-6.4).
    #[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
    #[serde(default)]
    pub pkcs11_slot: u64,

    /// Path to a file holding the PKCS#11 PIN.  The PIN is never inlined in
    /// `gateway.toml` (CLAIM-6.4, PV-3.6).
    #[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
    #[serde(default)]
    pub pkcs11_pin_path: Option<std::path::PathBuf>,

    /// Offline-ceremony `TrustRootRecord` (JSON).  When present the gateway
    /// verifies its threshold signatures and installs it under rollback
    /// protection (tasks 8.2/8.3 — CLAIM-8.2, CLAIM-8.3).
    #[serde(default)]
    pub trust_root_path: Option<std::path::PathBuf>,

    /// Optional signed rotation record applied at boot.  A record whose
    /// version is not strictly greater than the committed trust-root version
    /// is rejected with `TrustRootRollbackRejected` (task 8.2).
    #[serde(default)]
    pub trust_root_rotation_path: Option<std::path::PathBuf>,

    /// Optional Biscuit token (hex) used at boot to prove the token path fails
    /// before root CA registration and succeeds after (task 8.1, CLAIM-8.1).
    #[serde(default)]
    pub root_ca_self_test_token_path: Option<std::path::PathBuf>,

    /// Root CA Ed25519 private key (hex, 32-byte seed) used to mint scoped
    /// enrollment tokens (task 8.6).  Never inlined in `gateway.toml`.
    #[serde(default)]
    pub enrollment_root_ca_private_key_path: Option<std::path::PathBuf>,

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
    /// This is the operator path used after restoring a snapshot (task 8.8,
    /// scenario S22); the admin endpoint uses the same `EpochRegistry`.
    #[serde(default)]
    pub epoch_bump_path: Option<std::path::PathBuf>,

    /// Whether to start the local admin listener (Linux only).
    #[serde(default = "default_admin_enabled")]
    pub admin_enabled: bool,
}

fn default_admin_sock() -> std::path::PathBuf {
    std::path::PathBuf::from("/run/tirbase/admin.sock")
}

fn default_health_addr() -> std::net::SocketAddr {
    "127.0.0.1:8080".parse().unwrap()
}

fn default_counter_db() -> std::path::PathBuf {
    // The monotonic counters are PrimaryLedger state and live in `primary.db`
    // alongside the other anti-rollback tables (task 18.1).
    std::path::PathBuf::from("/var/lib/tirbase/primary.db")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_to_file_backend_and_counter_paths() {
        let config: GatewayConfig = toml::from_str("key_path = \"/tmp/key.json\"").unwrap();
        assert_eq!(config.key_backend, KeyBackend::File);
        assert_eq!(
            config.counter_db_path,
            std::path::PathBuf::from("/var/lib/tirbase/primary.db")
        );
        assert_eq!(config.checkpoint_interval_secs, 60);
        assert_eq!(config.time_max_forward_jump_secs, 86_400);
        assert_eq!(config.time_required_anchor_signatures, 2);
        assert_eq!(config.time_staleness_window_secs, 3_600);
        assert_eq!(config.boot_attestation_ttl_secs, 300);
        assert!(config.time_beacon_path.is_none());
        assert!(config.trust_root_path.is_none());
        assert!(config.trust_root_rotation_path.is_none());
        assert!(config.root_ca_self_test_token_path.is_none());
        assert!(config.enrollment_root_ca_private_key_path.is_none());
        assert_eq!(config.enrollment_token_ttl_secs, 86_400);
        assert_eq!(config.enrollment_nonce_retention_secs, 72 * 60 * 60);
        assert_eq!(config.enrollment_nonce_capacity, 100_000);
        assert_eq!(config.enrollment_nonce_purge_interval_secs, 300);
        assert!(config.epoch_bump_path.is_none());
        assert!(config.admin_enabled);
    }
}
