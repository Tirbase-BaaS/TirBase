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

fn default_tpm2_nv_handle() -> u32 {
    0x0150_0001
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
    }
}
