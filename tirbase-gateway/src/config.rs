//! Gateway TOML configuration (task 4.9.1 — PV-30.1).

use serde::Deserialize;

/// Top-level gateway configuration deserialized from a TOML file.
#[derive(Debug, Deserialize)]
pub struct GatewayConfig {
    /// Path to the device key file (PEM or raw bytes).
    pub key_path: std::path::PathBuf,

    /// Address to listen on for admin Unix socket.
    #[serde(default = "default_admin_sock")]
    pub admin_socket: std::path::PathBuf,

    /// Address for the health HTTP endpoint.
    #[serde(default = "default_health_addr")]
    pub health_addr: std::net::SocketAddr,

    /// Optional log level override (e.g. `"debug"`, `"info"`).
    #[serde(default)]
    pub log_level: Option<String>,
}

fn default_admin_sock() -> std::path::PathBuf {
    std::path::PathBuf::from("/run/tirbase/admin.sock")
}

fn default_health_addr() -> std::net::SocketAddr {
    "127.0.0.1:8080".parse().unwrap()
}
