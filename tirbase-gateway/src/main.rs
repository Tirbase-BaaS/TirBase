//! TirBase gateway binary entry point (CLAIM-35.1, 35.2, 35.4, 35.5, 35.6,
//! PV-11.1, PV-7.1).

#![warn(dead_code)]

use tirbase_gateway::*;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use config::{GatewayConfig, KeyBackend};
use db::device_epoch::SqliteDeviceEpochStore;
use db::enrollment_nonce::SqliteEnrollmentNonceStore;
use db::time_ratchet::SqliteTimeRatchetStore;
use hw_counter_binding::{BootCheck, HardwareCounterBinding, DEFAULT_SW_INCREMENT_PER_HW_WRITE};
use key_provider::FileKeyProvider;
use monotonic_counter::{
    default_hardware_counter, NamedMonotonicCounter, SoftwareMonotonicCounter,
};
use security_log::SecurityEventLog;
use time_source::SystemTimeSource;

use serde::{Deserialize, Serialize};
use tirbase_core::auth::root_ca::RootCaRegistry;
use tirbase_core::events::{ReasonCode, SecurityEvent, SecurityEventCategory, Severity};
use tirbase_core::traits::{KeyProvider, MonotonicCounterTrait};
use tirbase_guard::enrollment::EnrollmentService;
use tirbase_guard::epoch::{EnrollmentNonceStore, EpochBump, EpochRegistry};
use tirbase_guard::signed_operation::{SignedOperation, SignedOperationPayload};
use tirbase_guard::time::{FreshnessState, TimeRatchet, TimeRatchetConfig};
use tirbase_guard::trust_root::{TrustRootError, TrustRootManager, TrustRootRecord};
use tirbase_types::{CommandRole, DeviceSignature};

#[cfg(test)]
pub(crate) static EVENT_SINK_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Payload signed at boot to exercise the domain-separated multi-party wrapper.
#[derive(Debug, Serialize, Deserialize)]
struct GatewayBootRecord {
    boot_id: u64,
    counter: u64,
    did: String,
}

impl SignedOperationPayload for GatewayBootRecord {
    const CONTEXT: &'static str = "TirBase/v1/GatewayBootRecord";
}

#[derive(Debug, Parser)]
#[command(
    name = "tirbase-gateway",
    version,
    about = "TirBase hardened edge gateway"
)]
struct Cli {
    /// Gateway config TOML path (plain, schema-validated)
    #[arg(value_name = "CONFIG", default_value = "/etc/tirbase/gateway.toml")]
    config: PathBuf,

    /// PolicyAuthority-signed config bundle (JSON). Requires --config-bundle-trust-root.
    #[arg(long)]
    config_bundle: Option<PathBuf>,

    /// Trust root used to verify a signed config bundle.
    #[arg(long)]
    config_bundle_trust_root: Option<PathBuf>,

    /// Task 34+ utility subcommands (compat).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    passthrough: Vec<String>,
}

fn try_task34_cli(args: &[String]) -> Option<Result<()>> {
    if args.is_empty() {
        return None;
    }
    match args[0].as_str() {
        "profile-install" => {
            if args.len() < 3 {
                return Some(Err(anyhow::anyhow!(
                    "usage: tirbase-gateway profile-install <profile.toml> <pa-trust-root.json>"
                )));
            }
            Some(tirbase_gateway::task34_cli::run_profile_install(
                &PathBuf::from(&args[1]),
                &PathBuf::from(&args[2]),
            ))
        }
        "modbus-smoke" => {
            if args.len() < 4 {
                return Some(Err(anyhow::anyhow!(
                    "usage: tirbase-gateway modbus-smoke <addr> <read-holding|read-input|write-single|write-multiple> <register> [values...]"
                )));
            }
            let reg: u16 = match args[3].parse() {
                Ok(v) => v,
                Err(e) => return Some(Err(anyhow::anyhow!("register: {e}"))),
            };
            let vals: Result<Vec<u16>> = args[4..]
                .iter()
                .map(|v| v.parse::<u16>().context("value"))
                .collect();
            let vals = match vals {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };
            Some(tirbase_gateway::task34_cli::run_modbus_smoke(
                &args[1], &args[2], reg, &vals,
            ))
        }
        "mqtt-smoke" => {
            if args.len() < 5 {
                return Some(Err(anyhow::anyhow!(
                    "usage: tirbase-gateway mqtt-smoke <mqtts://uri> <ca-cert.pem> <topic> <payload>"
                )));
            }
            Some(tirbase_gateway::task34_cli::run_mqtt_smoke(
                &args[1],
                &PathBuf::from(&args[2]),
                &args[3],
                &args[4],
            ))
        }
        "cold-room-sim" => {
            let seed: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(42);
            let steps: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(256);
            Some(tirbase_gateway::task34_cli::run_cold_room_step(seed, steps))
        }
        _ => None,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if let Some(res) = try_task34_cli(&raw) {
        return res;
    }
    let cli = Cli::parse();

    let config: GatewayConfig = config::load_gateway_config(
        &cli.config,
        cli.config_bundle.as_deref(),
        cli.config_bundle_trust_root.as_deref(),
    )?;

    let filter = std::env::var("RUST_LOG")
        .ok()
        .or_else(|| config.log_level.clone())
        .unwrap_or_else(|| "info".to_string());
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .init();

    // Prometheus metrics (CLAIM-35.5)
    let metrics = tirbase_gateway::metrics::global_metrics();
    let metrics_addr = config.metrics_addr;
    let metrics_for_server = metrics.clone();
    tokio::spawn(async move {
        if let Err(error) =
            tirbase_gateway::metrics::run_metrics_server(metrics_addr, metrics_for_server).await
        {
            tracing::warn!(%error, "metrics server unavailable");
        }
    });

    let time_source = SystemTimeSource::new().install();
    tracing::info!(
        boot_id = time_source.boot_id(),
        monotonic_now_us = time_source.monotonic_now(),
        "TimeSource installed for all core subsystems",
    );

    let _security_log_early = std::sync::Arc::new(SecurityEventLog::new_memory()).install();

    let key_provider = build_key_provider(&config)?;
    tracing::info!(
        did = key_provider.did(),
        key_type = key_provider.key_type().as_str(),
        backend = ?config.key_backend,
        "device key provider ready",
    );

    let node_mode =
        tirbase_guard::node_mode::NodeModeState::new(tirbase_guard::node_mode::NodeMode::Starting);
    let primary_db_path = config.counter_db_path.clone();
    let derived_db_path = config.effective_derived_db_path();
    {
        let _primary = match db::open_primary_with_key(
            &primary_db_path,
            Some(key_provider.as_ref()),
        ) {
            Ok(conn) => conn,
            Err(action) => {
                let action = if matches!(
                    action,
                    db::SqliteErrorAction::EnterRestrictedCorrupt {
                        kind: db::DbKind::Primary,
                        ..
                    }
                ) {
                    tracing::error!(
                        action = %action,
                        "primary.db corrupt at boot; attempting logical dump/export (CLAIM-31.5)"
                    );
                    if let Err(export_action) =
                        db::logical_dump::export_primary_corruption_snapshot(&primary_db_path)
                    {
                        tracing::error!(export_action = %export_action, "primary.db logical dump/export failed");
                    }
                    action
                } else {
                    action
                };
                action.apply(Some(node_mode.as_ref()));
                tracing::error!(
                    node_mode = %node_mode.get().as_str(),
                    action = %action,
                    "primary.db open failed; SQLite error mapping applied (CLAIM-18.4)"
                );
                return Err(anyhow::anyhow!(action.to_string())).context("open primary.db");
            }
        };
        match db::open_derived_with_key(&derived_db_path, Some(key_provider.as_ref())) {
            Ok(_conn) => {}
            Err(action) => {
                if matches!(
                    action,
                    db::SqliteErrorAction::EnterRestrictedCorrupt {
                        kind: db::DbKind::Derived,
                        ..
                    }
                ) {
                    tracing::warn!(action = %action, "derived.db corrupt; attempting signed-delta-log rebuild (CLAIM-31.5)");
                    match db::ledger_recovery::recover_derived_on_corruption(
                        &derived_db_path,
                        None,
                        Some(node_mode.as_ref()),
                    ) {
                        Ok(_conn) => {}
                        Err(rebuild_action) => {
                            tracing::error!(action = %rebuild_action, "derived.db rebuild failed; Restricted/operator intervention required (CLAIM-31.5)");
                            return Err(anyhow::anyhow!(rebuild_action.to_string()))
                                .context("rebuild derived.db");
                        }
                    }
                } else {
                    action.apply(Some(node_mode.as_ref()));
                    tracing::error!(
                        node_mode = %node_mode.get().as_str(),
                        action = %action,
                        "derived.db open failed; SQLite error mapping applied (CLAIM-18.4)"
                    );
                    return Err(anyhow::anyhow!(action.to_string())).context("open derived.db");
                }
            }
        };
    }

    let ratchet_store =
        SqliteTimeRatchetStore::open(&config.counter_db_path).with_context(|| {
            format!(
                "failed to open time_ratchet store at {}",
                config.counter_db_path.display()
            )
        })?;
    let mut ratchet = TimeRatchet::open(
        Arc::new(ratchet_store),
        TimeRatchetConfig {
            max_forward_jump_secs: config.time_max_forward_jump_secs,
            required_anchor_signatures: config.time_required_anchor_signatures,
            staleness_window_secs: config.time_staleness_window_secs,
        },
    )
    .context("failed to load the TimeRatchet from primary.db")?;

    let freshness_before_beacon = ratchet.freshness(time_source.as_ref());
    tracing::info!(
        persisted_floor = ratchet.persisted_floor(),
        freshness = freshness_before_beacon.as_str(),
        "TimeRatchet loaded"
    );

    if freshness_before_beacon == FreshnessState::Unverified {
        tirbase_core::events::emit(
            SecurityEvent::new(
                SecurityEventCategory::TimeRatchet,
                Severity::Medium,
                ReasonCode::FreshnessUnverified,
            )
            .with_detail("authenticated time is UNVERIFIED at boot"),
        );
    }

    if let Some(beacon_path) = &config.time_beacon_path {
        let anchors_path = config
            .time_anchor_keys_path
            .as_ref()
            .context("time_beacon_path requires time_anchor_keys_path")?;
        let anchors = time_beacon::load_trust_anchors(anchors_path)?;
        time_beacon::ingest_time_beacon_file(
            beacon_path,
            &anchors,
            &mut ratchet,
            time_source.as_ref(),
        )
        .context("time beacon was rejected at boot")?;
    }

    let now_est = ratchet.now_est(time_source.as_ref());
    let expires_est = ratchet
        .persisted_floor()
        .saturating_add(config.boot_attestation_ttl_secs);
    if ratchet.is_expired(expires_est, time_source.as_ref()) {
        bail!("boot attestation expired: now_est {now_est} > expires_est {expires_est}");
    }

    let counter =
        SoftwareMonotonicCounter::open(&config.counter_db_path, 0).with_context(|| {
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
        "monotonic counter initialised at Level1 assurance",
    );

    let hardware = default_hardware_counter();
    let binding = HardwareCounterBinding::open(
        &config.counter_db_path,
        hardware,
        DEFAULT_SW_INCREMENT_PER_HW_WRITE,
    )
    .context("failed to open hardware-counter binding")?;

    if let BootCheck::Regression {
        hw_counter,
        sw_counter_at_last_hw_write,
    } = binding.check_at_boot()?
    {
        tracing::error!(
            hw_counter,
            sw_counter_at_last_hw_write,
            "monotonic counter regression detected — device has been rolled back; persisted LOCKDOWN and emitted MonotonicCounterRegression"
        );
    }

    let created_est = ratchet.now_est(time_source.as_ref());
    let boot_record = GatewayBootRecord {
        boot_id: time_source.boot_id(),
        counter: boot_counter,
        did: key_provider.did().to_string(),
    };
    match sign_and_verify_boot_record(
        key_provider.as_ref(),
        &boot_record,
        created_est,
        expires_est,
    ) {
        Ok(signature_count) => tracing::info!(
            signature_count,
            context = GatewayBootRecord::CONTEXT,
            "SignedOperation boot record verified"
        ),
        Err(error) => match config.key_backend {
            KeyBackend::File => return Err(error).context("boot attestation failed"),
            _ => tracing::warn!(%error, "key provider backend is a stub; boot attestation skipped"),
        },
    }

    let security_log = SecurityEventLog::new_persistent_with_mode(
        &primary_db_path,
        Some(key_provider.clone()),
        false,
        Some(node_mode.clone()),
    );
    security_log.set_rate_limit_enabled(true);
    security_log.set_retention(
        tirbase_gateway::security_log::SecurityLogRetentionConfig::from_gateway_config(&config),
    );
    let _ = security_log.verify_hash_chain();
    security_log.install();
    let _checkpoint_handle = security_log.spawn_checkpoint_loop();
    let _retention_handle = security_log.spawn_retention_rotation_loop();

    let trust_root = install_trust_root(&config, &mut ratchet, time_source.as_ref())?;
    let root_ca_registry = build_root_ca_registry(trust_root.as_deref())?;
    if let (Some(registry), Some(token_path)) =
        (&root_ca_registry, &config.root_ca_self_test_token_path)
    {
        run_root_ca_self_test(token_path, registry, ratchet.now_est(time_source.as_ref()))?;
    }

    let epoch_store = SqliteDeviceEpochStore::open(&config.counter_db_path)
        .context("failed to open device_epoch store")?;
    let epochs = Arc::new(EpochRegistry::new(Arc::new(epoch_store)));

    if let Some(path) = &config.epoch_bump_path {
        let record = trust_root
            .as_deref()
            .context("epoch_bump_path requires trust_root_path")?;
        let file = std::fs::read_to_string(path)?;
        let request: EpochBumpFile = serde_json::from_str(&file)?;
        let _ = epochs.apply_bump(
            &request.operation,
            &request.payload,
            record,
            ratchet.now_est(time_source.as_ref()),
        )?;
    }

    let enrollment_service = build_enrollment_service(
        &config,
        trust_root.as_ref(),
        epochs.clone(),
        ratchet.now_est(time_source.as_ref()),
    )?;

    let admin_state = match (&enrollment_service, trust_root.as_ref()) {
        (Some(service), Some(record)) => {
            let mut st =
                admin::AdminState::new(service.clone(), epochs.clone(), Arc::clone(record));
            st.primary_db_path = Some(primary_db_path.clone());
            st.security_log = Some(security_log.clone());
            st.key_provider = Some(key_provider.clone());
            Some(Arc::new(st))
        }
        _ => {
            let mut st = admin::AdminState::default();
            st.primary_db_path = Some(primary_db_path.clone());
            st.security_log = Some(security_log.clone());
            st.key_provider = Some(key_provider.clone());
            Some(Arc::new(st))
        }
    };

    if config.admin_enabled {
        let admin_socket = config.admin_socket.clone();
        tokio::spawn(async move {
            if let Err(error) = admin::run_admin_listener(&admin_socket, admin_state).await {
                tracing::warn!(%error, "admin listener unavailable");
            }
        });
    }

    // Health endpoint (CLAIM-35.4)
    let health_addr = config.health_addr;
    tokio::spawn(async move {
        if let Err(error) = tirbase_gateway::health::run_health_server(health_addr).await {
            tracing::warn!(%error, "health server unavailable");
        }
    });

    // Health loop / watchdog forward progress (CLAIM-13.7)
    let health_state = tirbase_gateway::health::HealthLoopState::new();
    let watchdog: Arc<dyn tirbase_gateway::health::WatchdogNotifier> =
        Arc::new(tirbase_gateway::health::SdNotifyWatchdogNotifier);
    let shutdown = Arc::new(tokio::sync::Notify::new());
    tokio::spawn(tirbase_gateway::health::run_health_loop(
        health_state,
        watchdog,
        Duration::from_secs(10),
        shutdown,
    ));

    tirbase_core::events::emit(
        SecurityEvent::new(
            SecurityEventCategory::Startup,
            Severity::Low,
            ReasonCode::BootCompleted,
        )
        .with_actor(key_provider.did())
        .with_detail(format!("gateway booted (counter={boot_counter})")),
    );
    metrics.inc_security_event("low");

    tracing::info!(
        admin_socket = %config.admin_socket.display(),
        health_addr = %config.health_addr,
        metrics_addr = %config.metrics_addr,
        mode = node_mode.get().as_str(),
        "tirbase-gateway started",
    );

    let checkpoint_interval = Duration::from_secs(config.checkpoint_interval_secs.max(1));
    let mut ticker = tokio::time::interval(checkpoint_interval);
    loop {
        ticker.tick().await;
        let sw_value = counter.read()?;
        if let Err(error) = binding.record_checkpoint(sw_value) {
            tracing::error!(%error, "hardware counter checkpoint write failed");
        }
    }
}

#[derive(Debug, Deserialize)]
struct EpochBumpFile {
    operation: SignedOperation<EpochBump>,
    payload: EpochBump,
}

fn install_trust_root(
    config: &GatewayConfig,
    ratchet: &mut TimeRatchet,
    time_source: &dyn tirbase_core::traits::TimeSource,
) -> Result<Option<Arc<TrustRootRecord>>> {
    let Some(path) = &config.trust_root_path else {
        return Ok(None);
    };
    let record = read_trust_root(path)?;
    record
        .verify_threshold_signatures()
        .map_err(|error| anyhow::anyhow!("trust root threshold signatures invalid: {error}"))?;

    let counter = NamedMonotonicCounter::open(&config.counter_db_path, "trust_root_version", 0)
        .context("failed to open the trust-root version counter")?;
    let now_est = ratchet.now_est(time_source);
    let mut manager = match TrustRootManager::install(record, Arc::new(counter), now_est) {
        Ok(manager) => manager,
        Err(error) => return Err(trust_root_failure("install", error)),
    };
    if let Some(rotation_path) = &config.trust_root_rotation_path {
        let rotated = read_trust_root(rotation_path)?;
        rotated
            .verify_threshold_signatures()
            .map_err(|error| anyhow::anyhow!("rotation threshold signatures invalid: {error}"))?;
        if let Err(error) = manager.rotate(rotated, now_est) {
            return Err(trust_root_failure("rotation", error));
        }
    }
    Ok(Some(Arc::new(manager.record().clone())))
}

fn read_trust_root(path: &std::path::Path) -> Result<TrustRootRecord> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read trust root at {}", path.display()))?;
    serde_json::from_str(&body)
        .with_context(|| format!("failed to parse trust root at {}", path.display()))
}

fn trust_root_failure(stage: &str, error: TrustRootError) -> anyhow::Error {
    if let TrustRootError::Rollback { incoming, current } = &error {
        tirbase_core::events::emit(
            SecurityEvent::new(
                SecurityEventCategory::Enrollment,
                Severity::High,
                ReasonCode::TrustRootRollbackRejected,
            )
            .with_detail(format!(
                "trust-root {stage} rejected: incoming version {incoming} is not greater than committed version {current}"
            )),
        );
    }
    anyhow::anyhow!("trust root {stage} rejected: {error}")
}

fn build_root_ca_registry(record: Option<&TrustRootRecord>) -> Result<Option<RootCaRegistry>> {
    let Some(record) = record else {
        return Ok(None);
    };
    let mut keys = Vec::new();
    for key in record.active_root_ca_keys() {
        let key: [u8; 32] = key.try_into().map_err(|_| {
            anyhow::anyhow!("trust root contains a root CA key that is not 32 bytes")
        })?;
        keys.push(key);
    }
    let registry = RootCaRegistry::with_threshold(keys, usize::from(record.threshold_k))
        .context("trust root root-key threshold is not usable")?;
    Ok(Some(registry))
}

fn run_root_ca_self_test(
    token_path: &std::path::Path,
    registered: &RootCaRegistry,
    now_est: i64,
) -> Result<()> {
    let body = std::fs::read_to_string(token_path)?;
    let token = hex::decode(body.trim()).context("root CA self-test token is not hex")?;
    let mut registry = RootCaRegistry::new(Vec::new());
    let before = registry.verify_against_first(|key| {
        tirbase_core::auth::biscuit::verify_token(&token, key, now_est)
    });
    if before.is_ok() {
        bail!("root CA self-test failed: token verified before root CA registration");
    }
    for key in registered.active_keys() {
        registry.register(key);
    }
    registry
        .verify_against_first(|key| tirbase_core::auth::biscuit::verify_token(&token, key, now_est))
        .context("root CA self-test failed: token rejected after CA registration")?;
    Ok(())
}

fn build_enrollment_service(
    config: &GatewayConfig,
    trust_root: Option<&Arc<TrustRootRecord>>,
    epochs: Arc<EpochRegistry>,
    _now_est: i64,
) -> Result<Option<Arc<EnrollmentService>>> {
    let Some(key_path) = &config.enrollment_root_ca_private_key_path else {
        return Ok(None);
    };
    let record = trust_root
        .context("enrollment_root_ca_private_key_path requires trust_root_path")?
        .clone();
    let seed = read_hex_key(key_path)?;
    let nonces = Arc::new(
        SqliteEnrollmentNonceStore::open(
            &config.counter_db_path,
            config.enrollment_nonce_retention_secs,
            config.enrollment_nonce_capacity,
        )
        .context("failed to open the enrollment nonce store")?,
    );
    let service = Arc::new(EnrollmentService::new(
        nonces.clone(),
        epochs,
        record,
        seed,
        config.enrollment_token_ttl_secs,
    ));
    let purge_interval_secs = config.enrollment_nonce_purge_interval_secs.max(1);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(purge_interval_secs));
        loop {
            ticker.tick().await;
            let now = tirbase_core::traits::wall_hint_secs().unwrap_or_default();
            let _ = nonces.purge_expired(now);
        }
    });
    Ok(Some(service))
}

fn read_hex_key(path: &std::path::Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read key material at {}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim().strip_prefix("0x").unwrap_or(text.trim());
    let decoded = match hex::decode(trimmed) {
        Ok(decoded) => decoded,
        Err(_) if bytes.len() == 32 => bytes.clone(),
        Err(error) => bail!(
            "key material at {} is not hex/32-byte seed: {error}",
            path.display()
        ),
    };
    if decoded.len() != 32 {
        bail!(
            "key material at {} must be 32-byte Ed25519 seed",
            path.display()
        );
    }
    Ok(decoded)
}

fn build_key_provider(config: &GatewayConfig) -> Result<Arc<dyn KeyProvider>> {
    match config.key_backend {
        KeyBackend::File => {
            let provider =
                FileKeyProvider::load_or_generate(&config.key_path).with_context(|| {
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
        Some(path) => std::fs::read(path)?,
        None => Vec::new(),
    };
    Ok(Arc::new(Tpm2KeyProvider::ed25519_sealed_seed(
        config.tpm2_nv_handle,
        pcr_policy,
    )))
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
    let pin = std::fs::read_to_string(pin_path)?.trim().to_string();
    Ok(Arc::new(Pkcs11KeyProvider::new(
        config.pkcs11_slot,
        SecretString::from(pin),
    )))
}

#[cfg(not(feature = "pkcs11"))]
fn build_pkcs11_provider(_config: &GatewayConfig) -> Result<Arc<dyn KeyProvider>> {
    bail!("key_backend = \"pkcs11\" requires building tirbase-gateway with --features pkcs11")
}

fn sign_and_verify_boot_record(
    provider: &dyn KeyProvider,
    record: &GatewayBootRecord,
    created_est: i64,
    expires_est: i64,
) -> Result<usize> {
    let mut operation =
        SignedOperation::<GatewayBootRecord>::new(record, created_est, Some(expires_est))?;
    operation.sign_with(provider, CommandRole::UpdateSigner)?;
    let public_key: [u8; 32] = provider
        .public_key_bytes()
        .try_into()
        .map_err(|_| anyhow::anyhow!("device public key is not a 32-byte Ed25519 key"))?;
    let did = provider.did().to_string();
    operation.verify(record, |candidate| {
        (candidate == did).then(|| public_key.to_vec())
    })?;
    let signature = provider.sign(b"tirbase-gateway-boot-attestation")?;
    let signature_bytes = match signature {
        DeviceSignature::Ed25519(bytes) => bytes,
        DeviceSignature::P256(_) => bail!("expected Ed25519 boot attestation"),
    };
    tirbase_core::identity::keypair::verify(
        &public_key,
        b"tirbase-gateway-boot-attestation",
        &tirbase_core::crdt::delta::Ed25519Signature::from_bytes(signature_bytes),
    )?;
    Ok(operation.signatures.len())
}
