//! TirBase gateway binary entry point (task 4.9.1 — PV-30.1, CLAIM-4.9.1).
//!
//! Boot sequence:
//!   1. Parse [`GatewayConfig`] from a TOML file (first CLI argument or the
//!      default `/etc/tirbase/gateway.toml`).
//!   2. Install the process-wide [`TimeSource`] (CLAIM-5.1) and
//!      [`SecurityEventSink`] (CLAIM-5.4).
//!   3. Open the durable Level 1 [`SoftwareMonotonicCounter`] (CLAIM-6.5),
//!      increment it, and check the hardware-counter binding for rollback
//!      (CLAIM-6.7a).  A regression persists LOCKDOWN and emits
//!      `MonotonicCounterRegression`.
//!   4. Select the key provider: file-backed [`FileKeyProvider`] (CLAIM-6.1)
//!      or a feature-gated TPM2 / PKCS#11 stub (CLAIM-6.3 / CLAIM-6.4).
//!   5. Sign and verify a domain-separated [`SignedOperation`] boot record
//!      (CLAIM-6.7).
//!   6. Enter the checkpoint loop, binding software to hardware counters at
//!      the configured cadence.
//!
//! The guard pipeline and admin/health listeners are wired in subsequent tasks.

// Warn on dead private code across this crate. `pub` items are naturally exempt
// (the Rust dead_code lint does not fire on reachable public items).
#![warn(dead_code)]

/// Admin Unix-socket listener with SO_PEERCRED authentication (task 4.9.2).
pub mod admin;

/// Health endpoint: GET /health → 200 OK (task 4.9.3, PV-30.3, CLAIM-4.9.3).
pub mod health;

mod config;
mod hw_counter_binding;
mod key_provider;
mod monotonic_counter;
mod security_sink;
mod time_source;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use config::{GatewayConfig, KeyBackend};
use hw_counter_binding::{BootCheck, HardwareCounterBinding, DEFAULT_SW_INCREMENT_PER_HW_WRITE};
use key_provider::FileKeyProvider;
use monotonic_counter::{
    default_hardware_counter, SoftwareMonotonicCounter,
};
use security_sink::GatewaySecurityEventLog;
use time_source::SystemTimeSource;

use serde::{Deserialize, Serialize};
use tirbase_core::events::{ReasonCode, SecurityEvent, SecurityEventCategory, Severity};
use tirbase_core::traits::{KeyProvider, MonotonicCounterTrait};
use tirbase_guard::signed_operation::{SignedOperation, SignedOperationPayload};
use tirbase_types::{CommandRole, DeviceSignature};

/// Serialises tests that own the process-wide security event sink.
#[cfg(test)]
pub(crate) static EVENT_SINK_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Payload signed at boot to exercise the domain-separated multi-party wrapper
/// (CLAIM-6.7).  Future policy-bundle / lockdown-exit / epoch-bump paths reuse
/// the same wrapper with their own context string.
#[derive(Debug, Serialize, Deserialize)]
struct GatewayBootRecord {
    boot_id: u64,
    counter: u64,
    did: String,
}

impl SignedOperationPayload for GatewayBootRecord {
    const CONTEXT: &'static str = "TirBase/v1/GatewayBootRecord";
}

#[tokio::main]
async fn main() -> Result<()> {
    // ── Load configuration ─────────────────────────────────────────────────
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/tirbase/gateway.toml".to_string());

    let config_str = std::fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read config: {config_path}"))?;
    let config: GatewayConfig =
        toml::from_str(&config_str).context("failed to parse GatewayConfig")?;

    // ── Tracing (config log_level, overridable by RUST_LOG) ────────────────
    let filter = std::env::var("RUST_LOG")
        .ok()
        .or_else(|| config.log_level.clone())
        .unwrap_or_else(|| "info".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .init();

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

    // ── MonotonicCounterTrait — Level 1 SQLite counter (CLAIM-5.3, 6.5) ────
    // WAL + synchronous=FULL; an increment is durable before it returns.
    let counter = SoftwareMonotonicCounter::open(&config.counter_db_path, 0)
        .with_context(|| {
            format!(
                "failed to open monotonic counter at {}",
                config.counter_db_path.display()
            )
        })?;
    let boot_counter = counter
        .increment()
        .context("monotonic counter increment at boot")?;
    tracing::info!(
        assurance_level = counter.assurance_level().as_str(),
        boot_counter,
        db = %config.counter_db_path.display(),
        "monotonic counter initialised at Level1 assurance",
    );

    // ── Hardware-counter DB-generation binding (CLAIM-6.7a) ────────────────
    // At boot, compare the hardware NV counter with the software value
    // recorded at the last hardware write.  hw > sw_at_last_write means the
    // software counter was rolled back; enter persisted LOCKDOWN.
    let hardware = default_hardware_counter();
    let binding = HardwareCounterBinding::open(
        &config.counter_db_path,
        hardware,
        DEFAULT_SW_INCREMENT_PER_HW_WRITE,
    )
    .context("failed to open hardware-counter binding")?;
    tracing::info!(
        hardware_assurance = binding.hardware().assurance_level().as_str(),
        "hardware-counter binding opened"
    );

    if binding.is_lockdown()? {
        tracing::warn!(
            "persisted LOCKDOWN state found at boot; device remains in LOCKDOWN until \
             an M-of-N lockdown-exit operation is presented"
        );
    }

    match binding.check_at_boot()? {
        BootCheck::Consistent => {
            tracing::info!("hardware/software monotonic counters are consistent");
        }
        BootCheck::Regression {
            hw_counter,
            sw_counter_at_last_hw_write,
        } => {
            tracing::error!(
                hw_counter,
                sw_counter_at_last_hw_write,
                "monotonic counter regression detected — device has been rolled back; \
                 persisted LOCKDOWN and emitted MonotonicCounterRegression"
            );
        }
    }

    // ── KeyProvider (CLAIM-5.2, 6.1, 6.3, 6.4) ─────────────────────────────
    let key_provider = build_key_provider(&config)?;
    tracing::info!(
        did = key_provider.did(),
        key_type = key_provider.key_type().as_str(),
        backend = ?config.key_backend,
        "device key provider ready",
    );

    // Prove the gateway signing path goes through the provider trait and that
    // a domain-separated SignedOperation verifies end-to-end (CLAIM-6.7).
    let created_est = time_source
        .wall_hint()
        .map(|micros| micros.div_euclid(1_000_000))
        .unwrap_or(0);
    let boot_record = GatewayBootRecord {
        boot_id: time_source.boot_id(),
        counter: boot_counter,
        did: key_provider.did().to_string(),
    };
    match sign_and_verify_boot_record(key_provider.as_ref(), &boot_record, created_est) {
        Ok(signature_count) => tracing::info!(
            signature_count,
            context = GatewayBootRecord::CONTEXT,
            "SignedOperation boot record verified"
        ),
        Err(error) => {
            // Hardware provider stubs cannot sign yet; the file provider must.
            match config.key_backend {
                KeyBackend::File => return Err(error).context("boot attestation failed"),
                _ => tracing::warn!(
                    %error,
                    "key provider backend is a stub; SignedOperation boot attestation skipped"
                ),
            }
        }
    }

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

    // ── Checkpoint loop: bind SW counter to HW counter (CLAIM-6.7a) ────────
    let checkpoint_interval = Duration::from_secs(config.checkpoint_interval_secs.max(1));
    tracing::info!(
        checkpoint_interval_secs = config.checkpoint_interval_secs,
        "entering checkpoint loop (hardware counter writes only at cadence)"
    );
    let mut ticker = tokio::time::interval(checkpoint_interval);
    loop {
        ticker.tick().await;
        let sw_value = counter.read()?;
        match binding.record_checkpoint(sw_value) {
            Ok(true) => tracing::debug!(
                sw_value,
                "wrote software counter to hardware NV counter at checkpoint cadence"
            ),
            Ok(false) => tracing::trace!(
                sw_value,
                "checkpoint within wear-leveling window; no hardware write"
            ),
            Err(error) => tracing::error!(%error, "hardware counter checkpoint write failed"),
        }
    }
}

/// Build the configured key provider (CLAIM-6.1 / 6.3 / 6.4).
fn build_key_provider(config: &GatewayConfig) -> Result<Arc<dyn KeyProvider>> {
    match config.key_backend {
        KeyBackend::File => {
            let provider = FileKeyProvider::load_or_generate(&config.key_path).with_context(|| {
                format!("failed to load device key at {}", config.key_path.display())
            })?;
            Ok(Arc::new(provider))
        }
        KeyBackend::Tpm2 => build_tpm2_provider(config),
        KeyBackend::Pkcs11 => build_pkcs11_provider(config),
    }
}

#[cfg(feature = "tpm2")]
fn build_tpm2_provider(config: &GatewayConfig) -> Result<Arc<dyn KeyProvider>> {
    use key_provider::Tpm2KeyProvider;

    let pcr_policy = match &config.tpm2_pcr_policy_path {
        Some(path) => std::fs::read(path).with_context(|| {
            format!("failed to read TPM2 PCR policy at {}", path.display())
        })?,
        None => Vec::new(),
    };
    let provider = Tpm2KeyProvider::ed25519_sealed_seed(config.tpm2_nv_handle, pcr_policy);
    Ok(Arc::new(provider))
}

#[cfg(not(feature = "tpm2"))]
fn build_tpm2_provider(_config: &GatewayConfig) -> Result<Arc<dyn KeyProvider>> {
    bail!("key_backend = \"tpm2\" requires building tirbase-gateway with --features tpm2")
}

#[cfg(feature = "pkcs11")]
fn build_pkcs11_provider(config: &GatewayConfig) -> Result<Arc<dyn KeyProvider>> {
    use key_provider::Pkcs11KeyProvider;
    use secrecy::SecretString;

    let pin_path = config
        .pkcs11_pin_path
        .as_ref()
        .context("key_backend = \"pkcs11\" requires pkcs11_pin_path")?;
    // The PIN is read from its own file and wrapped in a zeroizing secret; it is
    // never inlined in gateway.toml.
    let pin = std::fs::read_to_string(pin_path)
        .with_context(|| format!("failed to read PKCS#11 PIN file at {}", pin_path.display()))?
        .trim()
        .to_string();
    Ok(Arc::new(Pkcs11KeyProvider::new(
        config.pkcs11_slot,
        SecretString::from(pin),
    )))
}

#[cfg(not(feature = "pkcs11"))]
fn build_pkcs11_provider(_config: &GatewayConfig) -> Result<Arc<dyn KeyProvider>> {
    bail!("key_backend = \"pkcs11\" requires building tirbase-gateway with --features pkcs11")
}

/// Sign and verify a domain-separated [`SignedOperation`] boot record.
///
/// Returns the number of verified signatures.  The signature covers
/// `context_string || 0x00 || SHA-256(CBOR(record))`, so a signature produced
/// for a different context can never verify here (CLAIM-6.7).
fn sign_and_verify_boot_record(
    provider: &dyn KeyProvider,
    record: &GatewayBootRecord,
    created_est: i64,
) -> Result<usize> {
    let mut operation = SignedOperation::<GatewayBootRecord>::new(record, created_est, None)?;
    operation.sign_with(provider, CommandRole::UpdateSigner)?;

    let public_key: [u8; 32] = provider.public_key_bytes().try_into().map_err(|_| {
        anyhow::anyhow!("device public key is not a 32-byte Ed25519 key")
    })?;
    let did = provider.did().to_string();

    operation.verify(record, |candidate| {
        (candidate == did).then(|| public_key.to_vec())
    })?;

    // The boot attestation also flows through the raw verification path so a
    // malformed provider signature is caught independently of the wrapper.
    let signature = provider
        .sign(b"tirbase-gateway-boot-attestation")
        .context("signing boot attestation via KeyProvider")?;
    let signature_bytes = match signature {
        DeviceSignature::Ed25519(bytes) => bytes,
        DeviceSignature::P256(_) => {
            bail!("device key provider returned a P-256 signature; expected Ed25519")
        }
    };
    tirbase_core::identity::keypair::verify(
        &public_key,
        b"tirbase-gateway-boot-attestation",
        &tirbase_core::crdt::delta::Ed25519Signature::from_bytes(signature_bytes),
    )
    .context("boot attestation signature did not verify")?;

    Ok(operation.signatures.len())
}
