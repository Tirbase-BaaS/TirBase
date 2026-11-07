//! TirBase gateway binary entry point (task 4.9.1 — PV-30.1, CLAIM-4.9.1).
//!
//! This skeleton:
//!   - Parses [`GatewayConfig`] from a TOML file (first CLI argument or the
//!     default `/etc/tirbase/gateway.toml`).
//!   - Wires the four primary trait implementations from
//!     `tirbase-core::traits` (tasks 5.1–5.4):
//!     - [`SystemTimeSource`] — `CLOCK_BOOTTIME`-domain time (CLAIM-5.1, 7.1)
//!     - [`FileKeyProvider`] — disk-resident device key (CLAIM-5.2, 6.1)
//!     - [`SoftwareMonotonicCounter`] — Level-1 counter (CLAIM-5.3, 6.5)
//!     - [`GatewaySecurityEventLog`] — typed security event sink (CLAIM-5.4)
//!
//! The guard pipeline and admin/health listeners are wired in subsequent
//! tasks (4.9.2, 4.9.3).

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
mod security_sink;
mod time_source;

use anyhow::{bail, Context, Result};
use config::GatewayConfig;
use key_provider::FileKeyProvider;
use monotonic_counter::SoftwareMonotonicCounter;
use security_sink::GatewaySecurityEventLog;
use time_source::SystemTimeSource;

use tirbase_core::events::{ReasonCode, SecurityEvent, SecurityEventCategory, Severity};
use tirbase_core::traits::{KeyProvider, MonotonicCounterTrait};
use tirbase_types::DeviceSignature;

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

    // ── TimeSource (CLAIM-5.1) ─────────────────────────────────────────────
    // Installing the gateway's source routes every core subsystem (delta
    // timestamps, token issuance, transport bookkeeping) through it.
    let time_source = SystemTimeSource::new().install();
    tracing::info!(
        boot_id = time_source.boot_id(),
        monotonic_now_us = time_source.monotonic_now(),
        "TimeSource installed for all core subsystems",
    );

    // ── SecurityEventSink (CLAIM-5.4) ──────────────────────────────────────
    // Install before anything else can emit, so boot events are recorded too.
    let event_log = GatewaySecurityEventLog::new().install();

    // ── MonotonicCounterTrait (CLAIM-5.3) ──────────────────────────────────
    // Read/increment at boot and report the assurance level (PV-9.8).
    let counter = SoftwareMonotonicCounter::new(0);
    let boot_counter = counter
        .increment()
        .context("monotonic counter increment at boot")?;
    tracing::info!(
        assurance_level = counter.assurance_level().as_str(),
        boot_counter,
        "monotonic counter initialised",
    );

    // ── KeyProvider (CLAIM-5.2) ────────────────────────────────────────────
    // Load (or first-boot generate) the device key, then sign and verify a
    // boot attestation through the KeyProvider trait.  This proves every
    // gateway signing operation goes through the provider; no raw key bytes
    // are available to the binary.
    let key_provider = FileKeyProvider::load_or_generate(&config.key_path).with_context(|| {
        format!(
            "failed to load device key at {}",
            config.key_path.display()
        )
    })?;
    let attestation = b"tirbase-gateway-boot-attestation";
    verify_boot_attestation(&key_provider, attestation)?;
    tracing::info!(
        did = key_provider.did(),
        key_type = key_provider.key_type().as_str(),
        key_path = %key_provider.key_path.display(),
        "device key provider ready",
    );

    // ── Startup security event ─────────────────────────────────────────────
    tirbase_core::events::emit(
        SecurityEvent::new(
            SecurityEventCategory::Startup,
            Severity::Low,
            ReasonCode::BootCompleted,
        )
        .with_actor(key_provider.did())
        .with_detail(format!(
            "gateway booted (counter={boot_counter}, events={})",
            event_log.len()
        )),
    );

    tracing::info!(
        admin_socket = %config.admin_socket.display(),
        health_addr  = %config.health_addr,
        "tirbase-gateway starting (skeleton — guard pipeline pending)",
    );

    // Placeholder — guard pipeline and admin / health listeners wired in
    // subsequent tasks (4.9.2, 4.9.3).
    std::future::pending::<()>().await;
    Ok(())
}

/// Sign and verify a boot attestation through the [`KeyProvider`] trait.
fn verify_boot_attestation(provider: &FileKeyProvider, payload: &[u8]) -> Result<()> {
    let signature = provider
        .sign(payload)
        .context("signing boot attestation via KeyProvider")?;

    let public_key: [u8; 32] = provider.public_key_bytes().try_into().map_err(|_| {
        anyhow::anyhow!("device public key is not 32 bytes")
    })?;

    let signature_bytes = match signature {
        DeviceSignature::Ed25519(bytes) => bytes,
        DeviceSignature::P256(_) => {
            bail!("device key provider returned a P-256 signature; expected Ed25519")
        }
    };

    tirbase_core::identity::keypair::verify(
        &public_key,
        payload,
        &tirbase_core::crdt::delta::Ed25519Signature::from_bytes(signature_bytes),
    )
    .context("boot attestation signature did not verify")?;

    Ok(())
}
