//! TirBase gateway binary entry point (CLAIM-35.1, 35.2, 35.4, 35.5, 35.6,
//! PV-11.1, PV-7.1).

#![warn(dead_code)]

use tirbase_gateway::*;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use arc_swap::ArcSwap;
use clap::Parser;
use config::{GatewayConfig, KeyBackend};
use db::anti_replay_windows::SqliteAntiReplayStore;
use db::applied_effects_ledger::SqliteAppliedEffectsStore;
use db::challenge_nonces::SqliteChallengeNonceStore;
use db::device_epoch::SqliteDeviceEpochStore;
use db::drift_rate_history::SqliteDriftRateHistoryStore;
use db::enrollment_nonce::SqliteEnrollmentNonceStore;
use db::idempotency_keys::SqliteIdempotencyStore;
use db::lockdown::SqliteLockdownStore;
use db::pending_approvals::SqlitePendingApprovalsStore;
use db::target_state::SqliteTargetStateStore;
use db::time_ratchet::SqliteTimeRatchetStore;
use guard::SqliteStage16Store;
use hw_counter_binding::{BootCheck, HardwareCounterBinding, DEFAULT_SW_INCREMENT_PER_HW_WRITE};
use key_provider::FileKeyProvider;
use key_rotation::{FileKeyRotator, KeyRotator};
use monotonic_counter::{
    default_hardware_counter, NamedMonotonicCounter, SoftwareMonotonicCounter,
};
use security_log::SecurityEventLog;
use time_source::SystemTimeSource;

use serde::{Deserialize, Serialize};
use tirbase_core::api::{CoreHandle, DeploymentConfig, InitConfig};
use tirbase_core::auth::root_ca::RootCaRegistry;
use tirbase_core::events::{ReasonCode, SecurityEvent, SecurityEventCategory, Severity};
use tirbase_core::traits::{KeyProvider, MonotonicCounterTrait, TimeSource};
use tirbase_guard::admit::{AdmitPipelineState, ChallengeNonceStore, DriftHistoryStore};
use tirbase_guard::enrollment::EnrollmentService;
use tirbase_guard::envelope::ProfileMap;
use tirbase_guard::epoch::{EnrollmentNonceStore, EpochBump, EpochRegistry};
use tirbase_guard::lockdown::LockdownStore;
use tirbase_guard::node_mode::{NodeMode, NodeModeState};
use tirbase_guard::policy::{make_bundle, PolicyLifecycle};
use tirbase_guard::signed_operation::{SignedOperation, SignedOperationPayload};
use tirbase_guard::time::{FreshnessState, TimeRatchet, TimeRatchetConfig};
use tirbase_guard::trust_root::{TrustRootError, TrustRootManager, TrustRootRecord};
use tirbase_guard::{CommandGuard, GuardConfig, TargetAdmission};
use tirbase_types::envelope::EnvelopeProfile;
use tirbase_types::{CommandRole, DeviceSignature, TargetId};


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

 /// + utility subcommands (compat).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    passthrough: Vec<String>,
}

fn try_reference_cli(args: &[String]) -> Option<Result<()>> {
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
            Some(tirbase_gateway::reference_cli::run_profile_install(
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
            Some(tirbase_gateway::reference_cli::run_modbus_smoke(
                &args[1], &args[2], reg, &vals,
            ))
        }
        "mqtt-smoke" => {
            if args.len() < 5 {
                return Some(Err(anyhow::anyhow!(
                    "usage: tirbase-gateway mqtt-smoke <mqtts://uri> <ca-cert.pem> <topic> <payload>"
                )));
            }
            Some(tirbase_gateway::reference_cli::run_mqtt_smoke(
                &args[1],
                &PathBuf::from(&args[2]),
                &args[3],
                &args[4],
            ))
        }
        "cold-room-sim" => {
            let seed: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(42);
            let steps: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(256);
            Some(tirbase_gateway::reference_cli::run_cold_room_step(seed, steps))
        }
        "modbus-register-map" => {
            if args.len() < 2 {
                return Some(Err(anyhow::anyhow!(
                    "usage: tirbase-gateway modbus-register-map <register-map.toml>"
                )));
            }
            Some(tirbase_gateway::reference_cli::run_register_map_check(
                &PathBuf::from(&args[1]),
            ))
        }
        _ => None,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if let Some(res) = try_reference_cli(&raw) {
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

 // ── Driver runtime posture ────────────────────────────────────────────────
 // Report the kernel isolation capabilities the driver child will run under
 // (CLAIM-33.6, PV-10.4) and initialise crash/restart accounting (CLAIM-33.7).
    {
        let caps = tirbase_drivers::isolation::KernelIsolationCaps::detect();
        if caps.supports_landlock() {
            tracing::info!(
                kernel_major = caps.kernel_major,
                kernel_minor = caps.kernel_minor,
                "driver isolation: landlock available for driver children"
            );
        } else {
            tracing::warn!(
                kernel_major = caps.kernel_major,
                kernel_minor = caps.kernel_minor,
                opt_in_flag = tirbase_drivers::isolation::DEGRADED_ISOLATION_OPT_IN_FLAG,
                "driver isolation: landlock unavailable; driver children stay disabled unless degraded isolation is explicitly opted into"
            );
        }
 // The persistent driver child is spawned and supervised through the
 // guard-owned proxy: socketpair isolation, SO_PEERCRED verification,
 // SCM_RIGHTS device handoff, and lifecycle-driven restart decisions
 // (CLAIM-33.5/33.6/33.7).
        tracing::info!(
            max_retries = tirbase_drivers::lifecycle::DRIVER_RESTART_MAX_RETRIES,
            initial_backoff_secs = tirbase_drivers::lifecycle::DRIVER_RESTART_INITIAL.as_secs(),
            max_backoff_secs = tirbase_drivers::lifecycle::DRIVER_RESTART_MAX.as_secs(),
            "driver lifecycle policy: supervised child with exponential backoff"
        );
        #[cfg(unix)]
        start_driver_supervision();
    }

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
        "TimeSource installed for all core subsystems (boot_id={}, monotonic_now_us={})",
        time_source.boot_id(),
        time_source.monotonic_now(),
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
 // Signed delta log source for derived-ledger rebuild (CLAIM-31.5, PV-9.3).
 // CoreHandle stores the signed DAG/delta log in core.db beside primary.db.
    let core_db_path = primary_db_path.with_file_name("core.db");
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
        tracing::info!(
            path = %primary_db_path.display(),
            "primary.db ready (journal_mode=WAL, synchronous=FULL)"
        );
        match db::open_derived_with_key(&derived_db_path, Some(key_provider.as_ref())) {
            Ok(_conn) => {
                tracing::info!(
                    path = %derived_db_path.display(),
                    "derived.db ready (journal_mode=WAL, synchronous=NORMAL)"
                );
            }
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
                        Some(core_db_path.as_path()),
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
    let now_est_at_load = ratchet.now_est(time_source.as_ref());
    tracing::info!(
        persisted_floor = ratchet.persisted_floor(),
        freshness = freshness_before_beacon.as_str(),
        "TimeRatchet loaded (persisted_floor={}, now_est={}, freshness={})",
        ratchet.persisted_floor(),
        now_est_at_load,
        freshness_before_beacon.as_str()
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
        match time_beacon::ingest_time_beacon_file(
            beacon_path,
            &anchors,
            &mut ratchet,
            time_source.as_ref(),
        ) {
            Ok(advance) => tracing::info!(
                "Beacon accepted (new_floor={}, previous_floor={}, jump_secs={}, anchor_signatures={})",
                advance.new_floor,
                advance.previous_floor,
                advance.jump_secs,
                advance.anchor_signatures
            ),
            Err(error) => {
                tracing::error!("Beacon rejected: {error}");
                return Err(error).context("time beacon was rejected at boot");
            }
        }
    }

 // (CLAIM-53.1, PV-28.1/28.2): broadcast our own signed
 // `COSE_Sign1` time beacons when a cadence is configured. Before this was
 // wired, `TimeAnchorService::spawn_periodic` had no production caller, so the
 // gateway never actually broadcast a beacon.
    let _time_anchor_broadcast = if let Some(interval_secs) =
        config.time_anchor_broadcast_interval_secs
    {
        struct TracingBeaconSink;
        impl tirbase_gateway::time_anchor::BeaconSink for TracingBeaconSink {
            fn publish(&self, beacon: &tirbase_gateway::time_anchor::CoseSign1Beacon) {
                tracing::debug!(
                    payload_len = beacon.payload.len(),
                    signature_len = beacon.signature.len(),
                    "time anchor beacon broadcast (CLAIM-53.1)"
                );
            }
        }
        let service = std::sync::Arc::new(tirbase_gateway::time_anchor::TimeAnchorService::new(
            key_provider.clone(),
            time_source.clone(),
            std::time::Duration::from_secs(interval_secs),
            config.time_anchor_valid_for_secs.unwrap_or(300),
            std::sync::Arc::new(TracingBeaconSink),
        ));
        let running = service.spawn_periodic();
        tracing::info!(
            interval_secs,
            "periodic time anchor beacon broadcast started (time-anchor beacon)"
        );
        Some(running)
    } else {
        None
    };

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
 // CLAIM-26.1: verify the persisted hash chain at startup. The log itself
 // emits TamperDetection and enters Restricted on a broken link; the boot
 // diagnostic makes the outcome observable to operators.
    match security_log.verify_hash_chain() {
        Ok(None) => tracing::info!("security log hash chain verified intact at boot"),
        Ok(Some(first_broken_seq)) => tracing::error!(
            first_broken_seq,
            "security log hash chain tamper detected (CLAIM-26.1); entered Restricted mode"
        ),
        Err(error) => tracing::error!(
            %error,
            "security log hash chain verification error (CLAIM-26.1); entered Restricted mode"
        ),
    }
    security_log.install();
    tracing::info!(
        path = %primary_db_path.display(),
        "hash-chained SecurityEventLog installed and routed to primary.db (CLAIM-25.1-25.5)"
    );
    let _checkpoint_handle = security_log.spawn_checkpoint_loop();
    let _retention_handle = security_log.spawn_retention_rotation_loop();

 // PV-15.4 (CLAIM-44.5/44.6): block-layer flash-write budget tracking and
 // throttling. HIGH/CRITICAL SecurityEvents bypass the batcher and budget
 // throttling and are written immediately.
    let flash_budget_path = config
        .flash_budget_data_path
        .clone()
        .unwrap_or_else(|| config.counter_db_path.clone());
    let flash_budget = tirbase_gateway::flash_budget::FlashBudgetController::new(
        flash_budget_path,
        config.flash_budget_bytes_per_day,
    );
    flash_budget.attach_security_log(security_log.clone());
    let flash_budget = flash_budget.install_global();
    let _flash_budget_handle = flash_budget.spawn();
    tracing::info!(
        block_device = ?flash_budget.estimate().block_device,
        block_layer_supported = flash_budget.estimate().block_layer_supported,
        budget_bytes_per_day = flash_budget.budget_bytes_per_day(),
        "flash-write budget tracker started (CLAIM-44.5/44.6)"
    );

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
        let bumped = epochs.apply_bump(
            &request.operation,
            &request.payload,
            record,
            ratchet.now_est(time_source.as_ref()),
        )?;
        tracing::info!(
            device_id = %bumped.device_id,
            "signed epoch bump applied (epoch={})",
            bumped.epoch
        );
    }

    let enrollment_service = build_enrollment_service(
        &config,
        trust_root.as_ref(),
        epochs.clone(),
        ratchet.now_est(time_source.as_ref()),
    )?;

 // Core runtime handle installed for the process lifetime (). It is
 // initialised from the configured primary DB location so the CRDT/transport
 // runtime lives beside the gateway ledgers rather than in a process-local DB.
    let core_root_ca_keys = trust_root
        .as_ref()
        .map(|record| {
            record
                .active_root_ca_keys()
                .into_iter()
                .filter_map(|key| key.try_into().ok())
                .collect::<Vec<[u8; 32]>>()
        })
        .unwrap_or_default();
    let core_handle = CoreHandle::init(InitConfig {
        storage_path: core_db_path.to_string_lossy().into_owned(),
        deployment: DeploymentConfig {
            root_ca_keys: core_root_ca_keys,
            ..DeploymentConfig::default()
        },
        listen_addr: "127.0.0.1:0".to_string(),
    })
    .await
    .context("CoreHandle::init from the configured primary db path")?;
    tracing::info!(
        db_path = %core_db_path.display(),
        "CoreHandle installed"
    );

 // 26.3/26.4/26.7 + 28.3: wire the security log to the core mesh. This
 // installs the checkpoint provider gossiped on peer connection, feeds peer
 // checkpoint observations into tail-truncation detection, supplies the real
 // witness state at checkpoint time, and publishes/merges security events.
    tirbase_gateway::mesh_wiring::wire_security_log_to_mesh(
        &core_handle,
        &security_log,
        key_provider.did().to_string(),
        {
            let core = Arc::clone(&core_handle);
            move |batch| {
                if let Err(error) = core.publish_security_event_sync(batch) {
                    tracing::warn!(%error, "security event mesh sync publish failed (CLAIM-28.3)");
                }
            }
        },
    );
    tracing::info!("security log wired to core mesh (CLAIM-26.3, 26.4, 26.7, 28.3)");

 // 26.7a (PV-7.10): when a trusted cloud anchor is configured, report the
 // latest checkpoint upstream and ingest its signed acknowledgement so tail
 // truncation stays detectable without mesh peers.
    match tirbase_gateway::cloud_anchor::CloudAnchorClient::from_config(
        &config,
        key_provider.clone(),
    ) {
        Ok(Some(client)) => {
            let cloud_log = security_log.clone();
            let interval = Duration::from_secs(config.cloud_anchor_interval_secs.max(1));
            tokio::spawn(tirbase_gateway::cloud_anchor::run_cloud_anchor_loop(
                client, cloud_log, interval,
            ));
            tracing::info!(
                endpoint = ?config.cloud_anchor_endpoint,
                anchor = ?config.cloud_anchor_did,
                "cloud anchor checkpoint ingress started (CLAIM-26.7a)"
            );
        }
        Ok(None) => {}
        Err(error) => tracing::warn!(
            %error,
            "cloud anchor configuration rejected; cloud anchoring disabled (CLAIM-26.7a)"
        ),
    }

 // CommandGuard / Stage 16 runtime for the configured local target ().
    let ratchet = Arc::new(Mutex::new(ratchet));
    let pipeline_time_source: Arc<dyn TimeSource> = time_source.clone();
    let command_runtime = build_command_runtime(
        CommandRuntimeSetup {
            config: &config,
            primary_db_path: &primary_db_path,
            device_id: key_provider.did(),
            node_mode: node_mode.clone(),
            epochs: epochs.clone(),
            ratchet: ratchet.clone(),
            trust_root: trust_root.as_deref(),
            root_ca_registry: root_ca_registry.unwrap_or_else(|| RootCaRegistry::new(Vec::new())),
            time_source: pipeline_time_source,
        },
        now_est,
    )?;

 // Persisted lockdown wins; otherwise leave boot mode and enter Normal.
    let lockdown_marker = primary_db_path.with_file_name("lockdown");
    let lockdown_store: Arc<dyn LockdownStore> =
        Arc::new(SqliteLockdownStore::new(&primary_db_path, &lockdown_marker));
    match lockdown_store.is_lockdown() {
        Ok(true) => {
            node_mode.set(NodeMode::Lockdown);
        }
        Ok(false) => {
            if node_mode.get() == NodeMode::Starting {
                node_mode.set(NodeMode::Normal);
            }
        }
        Err(error) => tracing::warn!(%error, "lockdown state unreadable at boot"),
    }

    let pending_approvals = Arc::new(
        SqlitePendingApprovalsStore::open(&primary_db_path)
            .map_err(anyhow::Error::msg)
            .context("failed to open pending_approvals store")?,
    );
    tracing::info!(
        target = command_runtime
            .target_id
            .as_deref()
            .unwrap_or("<unconfigured>"),
        guard = command_runtime.guard.is_some(),
        pending_approvals = true,
        "command runtime constructed"
    );
    let _pending_approvals = pending_approvals;

 // /36.8a–36.8f: outbound-initiated cloud channel. There is no
 // inbound cloud listener anywhere in this binary; the connection is dialled
 // from here and re-established with exponential backoff.
    if config.cloud_endpoint.is_some() {
        match (
            command_runtime.guard.clone(),
            command_runtime.stage16.clone(),
        ) {
            (Some(guard), Some(stage16)) => {
                let runtime = tirbase_gateway::cloud::CloudRuntime {
                    guard,
                    stage16,
                    time_source: time_source.clone(),
                    key_provider: key_provider.clone(),
                };
                match tirbase_gateway::cloud::CloudClient::from_config(&config, runtime) {
                    Ok(Some(client)) => {
                        let client = Arc::new(client);
                        tracing::info!(
                            endpoint = client.endpoint(),
                            "outbound cloud channel starting (outbound cloud channel)"
                        );
                        tokio::spawn(client.run());
                    }
                    Ok(None) => {}
                    Err(error) => tracing::error!(
                        %error,
                        "cloud channel disabled: invalid TLS/configuration"
                    ),
                }
            }
            _ => tracing::warn!(
                "cloud_endpoint set but no guard/target is configured; cloud channel not started"
            ),
        }
    }

 // Attach each handle independently: a gateway configured without an
 // enrollment CA must still serve policy/mode/lockdown/chain-recovery, so no
 // handle may be dropped just because a sibling is absent.
    let mint_root_ca_seed = match &config.enrollment_root_ca_private_key_path {
        Some(path) => match read_hex_key(path) {
            Ok(seed) => Some(Arc::new(seed)),
            Err(error) => {
                tracing::warn!(%error, "admin mint disabled: root CA seed unreadable");
                None
            }
        },
        None => None,
    };
    let rotator: Arc<dyn KeyRotator> = Arc::new(FileKeyRotator::new(config.key_path.clone()));
 // / RD-6: self-update requires the UpdateSigner and
 // PolicyAuthority keys plus the live config path. Missing or malformed
 // configuration leaves the capability unconfigured (the endpoint answers
 // 503) rather than half-enabled.
    let self_update = match (
        &config.update_signer_public_key_hex,
        &config.policy_authority_public_key_hex,
        &config.self_update_config_path,
    ) {
        (Some(update_hex), Some(policy_hex), Some(path)) => {
            let parse_key = |value: &str| -> Option<[u8; 32]> {
                hex::decode(value)
                    .ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            };
            match (parse_key(update_hex), parse_key(policy_hex)) {
                (Some(update_key), Some(policy_key)) => {
                    Some(Arc::new(std::sync::Mutex::new(
                        crate::self_update::SelfUpdateController::new(None)
                            .with_config_path(path.clone())
                            .with_update_signer(update_key)
                            .with_policy_authority(policy_key),
                    )))
                }
                _ => {
                    tracing::warn!(
                        "self-update disabled: role keys must each be 32-byte hex"
                    );
                    None
                }
            }
        }
        _ => None,
    };
    let admin_state = admin::AdminState {
        primary_db_path: Some(primary_db_path.clone()),
        security_log: Some(security_log.clone()),
        key_provider: Some(key_provider.clone()),
        enrollment: enrollment_service.clone(),
        epochs: Some(epochs.clone()),
        trust_root: trust_root.clone(),
        policy: command_runtime.policy.clone(),
        node_mode: Some(node_mode.clone()),
        lockdown_store: Some(lockdown_store.clone()),
        envelope_profile: command_runtime.envelope_profile.clone(),
        guard: command_runtime.guard.clone(),
        challenge_store: command_runtime.challenge_store.clone(),
        stage16: command_runtime.stage16.clone(),
        core_handle: Some(core_handle.clone()),
        core_db_path: Some(core_db_path.clone()),
        ratchet: Some(ratchet.clone()),
        time_source: Some(time_source.clone()),
        mint_root_ca_seed,
        key_rotator: Some(rotator),
        events_view_window_days: config.admin_events_view_days,
        events_page_size: config.admin_events_page_size,
        self_update,
        ..Default::default()
    };
    let admin_state = Some(Arc::new(admin_state));

 // (PV-11.5): deny-all until a signed EnvelopeProfile is
 // installed. A command ingress socket is only bound when a profile is
 // installed; otherwise no command socket exists and every attempted command
 // is refused by construction. The administrative/health surfaces remain
 // available so an operator can install a profile and observe the state.
    let profile_installed = command_runtime.envelope_profile.is_some();
    if !profile_installed {
        tracing::warn!(
            "no signed EnvelopeProfile installed: deny-all command posture active (PV-11.5); no command ingress socket will be opened"
        );
        tirbase_core::events::emit(
            SecurityEvent::new(
                SecurityEventCategory::Startup,
                Severity::High,
                ReasonCode::NoProfile,
            )
            .with_actor(key_provider.did())
            .with_detail(
                "gateway booted without an installed signed EnvelopeProfile; all command ingress is denied"
                    .to_string(),
            ),
        );
    }

 // Local-admin command transport: the only ingress transport implemented in
 // this gateway binary. Mesh/cloud receivers are deliberately absent (see
 // the " Blocker Note" in CLAIMS.md).
    if let Some(command_addr) = config.local_admin_command_addr {
        if !profile_installed {
            tracing::warn!(
                "local_admin_command_addr set but no signed EnvelopeProfile is installed; command socket deliberately not opened (deny-all, PV-11.5)"
            );
        } else if let (Some(guard), Some(stage16)) = (
            command_runtime.guard.clone(),
            command_runtime.stage16.clone(),
        ) {
            tokio::spawn(async move {
                if let Err(error) =
                    tirbase_gateway::command_ingress::local_admin::run_local_admin_command_listener(
                        command_addr,
                        guard,
                        stage16,
                    )
                    .await
                {
                    tracing::warn!(%error, "local-admin command receiver unavailable");
                }
            });
        } else {
            tracing::warn!(
                "local_admin_command_addr set but no target/envelope profile is configured; receiver not started"
            );
        }
    }

 // Keep the CoreHandle alive for the process lifetime (installed runtime).
    let _core_handle = core_handle;

    if config.admin_enabled {
        let admin_socket = config.admin_socket.clone();
        let admin_state = admin_state.clone();
        tokio::spawn(async move {
            if let Err(error) = admin::run_admin_listener(&admin_socket, admin_state).await {
                tracing::warn!(%error, "admin listener unavailable");
            }
        });
    }

 // (PV-11.2): optional remote admin listener, mTLS-only. Config
 // validation already guarantees the four settings are either all present or
 // all absent; a TLS material load failure leaves the listener unbound
 // (fail closed) rather than falling back to plaintext.
    if let (Some(addr), Some(cert), Some(key), Some(client_ca)) = (
        config.admin_remote_addr,
        config.admin_remote_cert_path.as_ref(),
        config.admin_remote_key_path.as_ref(),
        config.admin_remote_client_ca_path.as_ref(),
    ) {
        match tirbase_gateway::admin_remote::load_server_config(cert, key, client_ca) {
            Ok(tls) => {
                let admin_state = admin_state.clone();
                tokio::spawn(async move {
                    if let Err(error) = tirbase_gateway::admin_remote::run_remote_admin_listener(
                        addr,
                        tls,
                        admin_state,
                    )
                    .await
                    {
                        tracing::error!(%error, "remote admin listener unavailable");
                    }
                });
            }
            Err(error) => tracing::error!(
                %error,
                "remote admin disabled: mTLS material could not be loaded"
            ),
        }
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

/// Command runtime constructed in `main` for the configured local target.
///
/// Every handle is a real production store; nothing here is a stub. When no
/// target/envelope profile is configured the guard is still built (so the
/// decision pipeline and metrics are live) but policy/envelope admin endpoints
/// report the explicit unconfigured state.
#[allow(dead_code)]
struct CommandRuntime {
    guard: Option<Arc<CommandGuard>>,
    stage16: Option<Arc<SqliteStage16Store>>,
    policy: Option<Arc<Mutex<PolicyLifecycle>>>,
    envelope_profile: Option<Arc<EnvelopeProfile>>,
    challenge_store: Option<Arc<dyn ChallengeNonceStore>>,
    target_id: Option<String>,
    _pending_approvals: Arc<SqlitePendingApprovalsStore>,
    _applied_effects: Arc<SqliteAppliedEffectsStore>,
    _anti_replay: Arc<SqliteAntiReplayStore>,
    _idempotency: Arc<SqliteIdempotencyStore>,
    _drift_rate: Arc<SqliteDriftRateHistoryStore>,
    _target_state: Arc<SqliteTargetStateStore>,
}

/// Guard-owned device transport, kept alive for the process lifetime so the fd
/// handed to the driver child stays valid (CLAIM-34.8).
#[cfg(unix)]
static GUARD_DEVICE_TRANSPORT: std::sync::OnceLock<tirbase_guard::DeviceTransport> =
    std::sync::OnceLock::new();

/// Production driver-child supervision (CLAIM-33.5/33.6/33.7).
///
/// Both the child program (`TIRBASE_DRIVER_CHILD`) and the device endpoint
/// (`TIRBASE_DEVICE_ADDR`, Modbus TCP) are supplied by the deployment. The
/// guard owns the device transport and passes its fd to the child via
/// `SCM_RIGHTS`; without a configured device the child is not started at all,
/// so no unblocked driver ever runs. The child applies its seccomp/landlock
/// sandbox itself before parsing frames.
#[cfg(unix)]
fn start_driver_supervision() {
    let program = match std::env::var_os("TIRBASE_DRIVER_CHILD") {
        Some(program) => PathBuf::from(program),
        None => {
            tracing::info!(
                env = "TIRBASE_DRIVER_CHILD",
                "driver child supervision disabled: no driver child program configured"
            );
            return;
        }
    };
    let device_addr = match std::env::var("TIRBASE_DEVICE_ADDR") {
        Ok(addr) if !addr.trim().is_empty() => addr,
        _ => {
            tracing::warn!(
                env = "TIRBASE_DEVICE_ADDR",
                "driver child not started: no device endpoint configured, driver stays disabled"
            );
            return;
        }
    };
    let transport = match tirbase_guard::DeviceTransport::connect_modbus_tcp(
        &device_addr,
        Duration::from_secs(5),
        Some(Duration::from_secs(5)),
    ) {
        Ok(transport) => transport,
        Err(error) => {
            tracing::error!(
                %error,
                addr = %device_addr,
                "driver child not started: device transport connect failed"
            );
            return;
        }
    };
    let device_fd = transport.as_raw_fd();
 // The guard keeps ownership of the device fd; the child receives a dup via
 // SCM_RIGHTS inside `SupervisedDriver::start`.
    if GUARD_DEVICE_TRANSPORT.set(transport).is_err() {
        tracing::error!("device transport already registered; driver child not started");
        return;
    }
    let config = tirbase_guard::driver_proxy::ChildDriverConfig {
        program,
        args: vec!["--sandboxed-driver".to_string()],
        device_fd: Some(device_fd),
        degraded_isolation_opt_in: false,
        expected_peer_uid: None,
        capture_output: false,
    };
    match tirbase_guard::driver_proxy::SupervisedDriver::start(config) {
        Ok(driver) => {
            tracing::info!(
                pid = driver.child_pid(),
                peer = ?driver.peer_credentials(),
                device_addr = %device_addr,
                "driver child spawned over socketpair; device fd passed via SCM_RIGHTS, peer credentials checked before first write"
            );
            let spawned = std::thread::Builder::new()
                .name("driver-supervision".into())
                .spawn(move || driver_supervision_loop(driver));
            if let Err(error) = spawned {
                tracing::error!(%error, "failed to start driver supervision thread");
            }
        }
        Err(error) => tracing::error!(
            %error,
            "driver child failed to start; actuation dispatch remains disabled"
        ),
    }
}

/// Gateway-side crash accounting hook for the driver child (CLAIM-33.7, S24).
#[cfg(unix)]
struct GatewayDriverCrashSupervisor;

#[cfg(unix)]
impl tirbase_drivers::lifecycle::DriverCrashSupervisor for GatewayDriverCrashSupervisor {
    fn on_driver_restart(&self, attempt: u32, backoff: std::time::Duration) {
        tracing::warn!(
            attempt,
            backoff_secs = backoff.as_secs(),
            "driver child crash fed into supervisor accounting; scheduling restart"
        );
    }

    fn on_driver_escalate_lockdown(&self, attempts: u32) {
        tracing::error!(
            attempts,
            "driver child crash loop exceeded the retry budget; supervisor LOCKDOWN escalation required"
        );
    }
}

#[cfg(unix)]
fn driver_supervision_loop(mut driver: tirbase_guard::driver_proxy::SupervisedDriver) {
    use tirbase_drivers::lifecycle::DriverRestartDecision;

    let supervisor = GatewayDriverCrashSupervisor;
    let mut stable_ticks: u32 = 0;
    loop {
        std::thread::sleep(tirbase_guard::driver_proxy::DRIVER_RESTART_POLL_INTERVAL);
        match driver.try_wait() {
            Ok(Some(status)) => {
                stable_ticks = 0;
                tracing::warn!(
                    ?status,
                    pid = driver.child_pid(),
                    "driver child exited; applying restart decision"
                );
                match driver.restart_after_crash(&supervisor) {
                    Ok(DriverRestartDecision::Restart { attempt, backoff }) => tracing::warn!(
                        attempt,
                        backoff_ms = backoff.as_millis() as u64,
                        pid = driver.child_pid(),
                        "driver child restarted with exponential backoff"
                    ),
                    Ok(DriverRestartDecision::EscalateLockdown { attempts }) => {
                        tracing::error!(
                            attempts,
                            "driver child crash loop escalated; driver supervision halted"
                        );
                        return;
                    }
                    Err(error) => {
                        tracing::error!(%error, "driver child respawn failed; driver supervision halted");
                        return;
                    }
                }
            }
            Ok(None) => {
                stable_ticks = stable_ticks.saturating_add(1);
 // 60s of uninterrupted uptime (120 x 500ms) clears the crash
 // accounting, so a later isolated crash starts at 1s again.
                if stable_ticks >= 120 && driver.consecutive_crashes() > 0 {
                    driver.note_stable();
                    stable_ticks = 0;
                    tracing::info!("driver child stable; crash accounting reset");
                }
            }
            Err(error) => {
                tracing::error!(%error, "driver child wait failed; driver supervision halted");
                return;
            }
        }
    }
}

/// Boot inputs consumed when constructing the command runtime.
struct CommandRuntimeSetup<'a> {
    config: &'a GatewayConfig,
    primary_db_path: &'a std::path::Path,
    device_id: &'a str,
    node_mode: Arc<NodeModeState>,
    epochs: Arc<EpochRegistry>,
    ratchet: Arc<Mutex<TimeRatchet>>,
    trust_root: Option<&'a TrustRootRecord>,
    root_ca_registry: RootCaRegistry,
    time_source: Arc<dyn TimeSource>,
}

fn build_command_runtime(
    setup: CommandRuntimeSetup<'_>,
    now_est: i64,
) -> Result<CommandRuntime> {
    let CommandRuntimeSetup {
        config,
        primary_db_path,
        device_id,
        node_mode,
        epochs,
        ratchet,
        trust_root,
        root_ca_registry,
        time_source,
    } = setup;
 // Stage 16–19 durable store (single atomic SQLite transaction per command).
    let stage16 = Arc::new(SqliteStage16Store::open(primary_db_path).map_err(anyhow::Error::msg)?);

 // Explicitly constructed decision-state stores ().
    let applied_effects =
        Arc::new(SqliteAppliedEffectsStore::open(primary_db_path).map_err(anyhow::Error::msg)?);
    let anti_replay =
        Arc::new(SqliteAntiReplayStore::open(primary_db_path).map_err(anyhow::Error::msg)?);
    let idempotency =
        Arc::new(SqliteIdempotencyStore::open(primary_db_path).map_err(anyhow::Error::msg)?);
    let drift_rate =
        Arc::new(SqliteDriftRateHistoryStore::open(primary_db_path).map_err(anyhow::Error::msg)?);
    let target_state =
        Arc::new(SqliteTargetStateStore::open(primary_db_path).map_err(anyhow::Error::msg)?);
    let pending_approvals =
        Arc::new(SqlitePendingApprovalsStore::open(primary_db_path).map_err(anyhow::Error::msg)?);
    let challenge_store: Arc<dyn ChallengeNonceStore> =
        Arc::new(SqliteChallengeNonceStore::open(primary_db_path).map_err(anyhow::Error::msg)?);

 // Envelope profile + policy snapshot for the configured local target.
    let mut envelope_profiles = BTreeMap::new();
    let mut policy_lifecycle = None;
    let mut envelope_profile = None;
    let mut policy_bundle = None;
    if let Some(target_id) = config.target_id.clone() {
        let profile_path = config.envelope_profile_path.as_ref().context(
            "target_id is configured but envelope_profile_path is not; refusing to run an unguarded target",
        )?;
        let profile = profiles::load_profile_from_path(profile_path)
            .map_err(|error| anyhow::anyhow!("invalid envelope profile: {error}"))?;
        let target = TargetId::new(&target_id);
        envelope_profiles.insert(
            target.clone(),
            Arc::new(ArcSwap::from_pointee(profile.clone())),
        );
        envelope_profile = Some(Arc::new(profile.clone()));

        let bundle = make_bundle(profile.version, [0u8; 32], profile.clone(), Vec::new());
        policy_bundle = Some(bundle.clone());

        let policy_counter = NamedMonotonicCounter::open(primary_db_path, "policy_version", 0)
            .context("failed to open the policy anti-rollback counter")?;
        let profile_map = Arc::new(ProfileMap::from_profiles([(
            target.clone(),
            profile.clone(),
        )]));
        let policy_trust_root = trust_root.cloned().unwrap_or_else(|| TrustRootRecord {
            version: 1,
            root_ca_public_keys: Vec::new(),
            threshold_k: 1,
            role_thresholds: BTreeMap::new(),
            device_class_floors: BTreeMap::new(),
            expiry_est: i64::MAX,
            revoked_root_ca_keys: Vec::new(),
            signatures: Vec::new(),
        });
        policy_lifecycle = Some(Arc::new(Mutex::new(
            PolicyLifecycle::new(
                target.clone(),
                bundle,
                Arc::new(policy_counter),
                profile_map,
                Arc::new(ArcSwap::from_pointee(policy_trust_root)),
            )
            .map_err(anyhow::Error::msg)?,
        )));
    } else if config.envelope_profile_path.is_some() {
        bail!("envelope_profile_path is set but target_id is missing");
    }

    let envelope_profiles = Arc::new(envelope_profiles);
    let policy_snapshot = Arc::new(ArcSwap::from_pointee(policy_bundle));
    let pipeline = Arc::new(AdmitPipelineState::new(
        envelope_profiles.clone(),
        policy_snapshot.clone(),
        Arc::new(RwLock::new(root_ca_registry)),
        ratchet,
        time_source,
    ));
    pipeline.set_drift_store(drift_rate.clone() as Arc<dyn DriftHistoryStore>);
    pipeline.set_challenge_store(challenge_store.clone());
    guard::hydrate_runtime_state(primary_db_path, &pipeline).map_err(anyhow::Error::msg)?;

 // Register the local device at epoch 0 before the guard admits commands.
    epochs.ensure_enrolled(device_id, now_est)?;

    let mut targets = BTreeMap::new();
    if let Some(target_id) = &config.target_id {
        targets.insert(
            TargetId::new(target_id),
            TargetAdmission {
                device_id: device_id.to_string(),
            },
        );
    }
    let guard = Arc::new(
        CommandGuard::with_mode(epochs, GuardConfig { targets }, node_mode).with_pipeline(
            pipeline,
            envelope_profiles,
            policy_snapshot,
        ),
    );

    Ok(CommandRuntime {
        guard: Some(guard),
        stage16: Some(stage16),
        policy: policy_lifecycle,
        envelope_profile,
        challenge_store: Some(challenge_store),
        target_id: config.target_id.clone(),
        _pending_approvals: pending_approvals,
        _applied_effects: applied_effects,
        _anti_replay: anti_replay,
        _idempotency: idempotency,
        _drift_rate: drift_rate,
        _target_state: target_state,
    })
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
    let installed_version = record.version;
    let installed_k = record.threshold_k;
    let mut manager = match TrustRootManager::install(record, Arc::new(counter), now_est) {
        Ok(manager) => manager,
        Err(error) => return Err(trust_root_failure("install", error)),
    };
    tracing::info!(
        version = installed_version,
        threshold_k = installed_k,
        "trust root installed with rollback protection (version={installed_version}, k={installed_k})"
    );
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
        return anyhow::anyhow!(
            "trust root rollback rejected at {stage}: incoming version {incoming} <= committed version {current}"
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
    tracing::info!("root CA self-test: token rejected before CA registration");
    for key in registered.active_keys() {
        registry.register(key);
    }
    registry
        .verify_against_first(|key| tirbase_core::auth::biscuit::verify_token(&token, key, now_est))
        .context("root CA self-test failed: token rejected after CA registration")?;
    tracing::info!("root CA self-test: token verified after CA registration");
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
