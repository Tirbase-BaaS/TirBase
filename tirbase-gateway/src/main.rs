//! TirBase gateway binary entry point (task 4.9.1 — PV-30.1, CLAIM-4.9.1).
//!
//! This skeleton:
//!   - Parses [`GatewayConfig`] from a TOML file (first CLI argument or the
//!     default `/etc/tirbase/gateway.toml`).
//!   - Wires the three primary trait implementations:
//!     - [`SystemTimeSource`]  — CLOCK_BOOTTIME-backed time (CLAIM-7.1)
//!     - [`FileKeyProvider`]   — disk-resident device key (CLAIM-6.1)
//!     - [`SoftwareMonotonicCounter`] — Level-1 counter (CLAIM-6.5)
//!
//! No guard pipeline is wired yet; that comes in tasks 4.9.2 and 4.9.3.

// Warn on dead private code across this crate. `pub` items are naturally exempt
// (the Rust dead_code lint does not fire on reachable public items).
#![warn(dead_code)]

/// Admin Unix-socket listener with SO_PEERCRED authentication (task 4.9.2).
pub mod admin;

/// Health endpoint: GET /health → 200 OK (task 4.9.3, PV-30.3, CLAIM-4.9.3).
pub mod health;

mod config;
mod key_provider;
mod monotonic_counter;
mod time_source;

use anyhow::{Context, Result};
use config::GatewayConfig;
use key_provider::FileKeyProvider;
use monotonic_counter::SoftwareMonotonicCounter;
use time_source::SystemTimeSource;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialise tracing subscriber, respecting RUST_LOG / config log_level.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // ── Load configuration ─────────────────────────────────────────────────
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/tirbase/gateway.toml".to_string());

    let config_str = std::fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read config: {config_path}"))?;
    let config: GatewayConfig =
        toml::from_str(&config_str).context("failed to parse GatewayConfig")?;

    // ── Wire trait implementations ─────────────────────────────────────────
    // (No guard pipeline yet — task 4.9.2 / 4.9.3.)
    let _time_source = SystemTimeSource::new();
    let _key_provider = FileKeyProvider::new(config.key_path.clone());
    let _counter = SoftwareMonotonicCounter::new(0);

    tracing::info!("tirbase-gateway starting (skeleton — guard pipeline pending)");
    tracing::info!(
        admin_socket = %config.admin_socket.display(),
        health_addr  = %config.health_addr,
        "configuration loaded",
    );

    // Placeholder — guard pipeline and admin / health listeners wired in
    // subsequent tasks (4.9.2, 4.9.3).
    std::future::pending::<()>().await;
    Ok(())
}
