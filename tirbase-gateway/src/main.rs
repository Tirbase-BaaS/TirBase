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

#![warn(dead_code)]

use tirbase_gateway::*;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
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

    // ── SecurityEventSink (CLAIM-5.4, 25.1–25.3) ──────────────────────────
    // Install before anything else can emit, so boot events are recorded too.
    // Replaced with persistent/key-backed log after key provider init.
    let _security_log_early = std::sync::Arc::new(SecurityEventLog::new_memory()).install();

    // ── KeyProvider (CLAIM-5.2, 6.1, 6.3, 6.4, 32.5) ───────────────────────
    // Built before DB opens so SQLCipher builds can derive key material via
    // KeyProvider and refuse to open on KeyProvider error (PV-9.6).
    let key_provider = build_key_provider(&config)?;
    tracing::info!(
        did = key_provider.did(),
        key_type = key_provider.key_type().as_str(),
        backend = ?config.key_backend,
        "device key provider ready",
    );

    // ── SQLite database split (CLAIM-18.1–18.4, PV-9.3, 32.5) ─────────────
    // Open primary.db (PrimaryLedger, WAL+synchronous=FULL) and derived.db
    // (DerivedLedger, WAL+synchronous=NORMAL) through the migration framework
    // (task 32.1) before any reads/writes. Hardening pragmas are applied by
    // the open helpers.
    // STATE-INVENTORY: RECONSTRUCTIBLE node mode (CLAIM-31.1)
    let node_mode =
        tirbase_guard::node_mode::NodeModeState::new(tirbase_guard::node_mode::NodeMode::Starting);
    let primary_db_path = config.counter_db_path.clone();
    let derived_db_path = config.effective_derived_db_path();
    {
        let primary = match db::open_primary_with_key(&primary_db_path, Some(key_provider.as_ref()))
        {
            Ok(conn) => conn,
            Err(action) => {
                let action = if matches!(
                    action,
                    db::SqliteErrorAction::EnterRestrictedCorrupt {
                        kind: db::DbKind::Primary,
                        ..
                    }
                ) {
                    db::ledger_recovery::handle_primary_corruption(action, Some(node_mode.as_ref()))
                } else {
                    action
                };
                action.apply(Some(node_mode.as_ref()));
                tracing::error!(
                    node_mode = %node_mode.get().as_str(),
                    action = %action,
                    "primary.db open failed; Restricted/operator intervention required if corrupt (CLAIM-18.4/31.5)"
                );
                return Err(anyhow::anyhow!(action.to_string())).context("open primary.db");
            }
        };
        let primary_ver = db::schema_version(&primary, db::DbKind::Primary)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        tracing::info!(path = %primary_db_path.display(), schema_version = primary_ver, "primary.db ready (synchronous=FULL, WAL, PrimaryLedger)");

        // ── Applied effects ledger boot reconciliation (19.2/19.3, PV-5.3) ──
        // Runs before accepting commands. Scans pre-Actuating legacy entries
        // (Failed/OLD_SCHEMA_ENTRY) and resolves Actuating entries via driver
        // read-back (30s timeout) => Complete/Failed/Unknown, emitting
        // ReconciliationComplete or ReconciliationTimeout.
        let reconcile_ts = tirbase_core::traits::wall_hint_secs().unwrap_or(0);
        match db::ledger_reconciliation::reconcile_on_boot(
            &primary,
            &db::ledger_reconciliation::NoDriverReadBack,
            reconcile_ts,
        ) {
            Ok(summary) => tracing::info!(
                ?summary,
                "applied_effects_ledger boot reconciliation complete (CLAIM-19.2/19.3)"
            ),
            Err(error) => tracing::error!(
                %error,
                "applied_effects_ledger boot reconciliation failed (CLAIM-19.2/19.3)"
            ),
        }

        // Task 21.5: release all SingleWriterLease rows at boot (stale leases
        // must not block targets after restart). Production caller: gateway.
        match db::single_writer_leases::release_all_at_boot(&primary) {
            Ok(deleted) => tracing::info!(
                deleted,
                "released all single_writer_leases at boot (CLAIM-21.5)"
            ),
            Err(error) => tracing::error!(%error, "single_writer_leases boot release failed"),
        }

        // ── WAL PASSIVE checkpoint cadence (32.4, CLAIM-32.4, PV-9) ───────
        // Production caller: background task in tirbase-gateway.
        db::wal_checkpoint::spawn_wal_checkpoint_loop(
            primary_db_path.clone(),
            derived_db_path.clone(),
        );

        // ── Ledger pruning background job (19.5, PV-5.12) ──────────────────
        // Production caller: background task in tirbase-gateway.
        {
            let prune_path = primary_db_path.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(6 * 60 * 60));
                loop {
                    ticker.tick().await;
                    let now_est = tirbase_core::traits::wall_hint_secs().unwrap_or_default();
                    let path = prune_path.clone();
                    let res = tokio::task::spawn_blocking(move || {
                        let conn = rusqlite::Connection::open(&path)
                            .map_err(|e| format!("prune open: {e}"))?;
                        conn.pragma_update(None, "journal_mode", "WAL")
                            .map_err(|e| format!("prune wal: {e}"))?;
                        conn.pragma_update(None, "synchronous", "FULL")
                            .map_err(|e| format!("prune sync: {e}"))?;
                        db::applied_effects_ledger::prune_retention(
                            &conn,
                            now_est,
                            db::applied_effects_ledger::PRUNE_MAX_AGE_SECS,
                            db::applied_effects_ledger::PRUNE_MAX_ENTRIES,
                        )
                    })
                    .await;
                    match res {
                        Ok(Ok(deleted)) if deleted > 0 => {
                            tirbase_core::events::emit(
                                tirbase_core::events::SecurityEvent::new(
                                    tirbase_core::events::SecurityEventCategory::EffectsLedger,
                                    tirbase_core::events::Severity::Low,
                                    tirbase_core::events::ReasonCode::LedgerPruned,
                                )
                                .with_detail(format!(
                                    "pruned {deleted} applied_effects_ledger entries"
                                )),
                            );
                        }
                        Ok(Err(error)) => tracing::warn!(%error, "ledger pruning failed (19.5)"),
                        Err(error) => {
                            tracing::warn!(%error, "ledger pruning task join failed (19.5)")
                        }
                        _ => {}
                    }
                }
            });
        }

        let derived = match db::open_derived_with_key(&derived_db_path, Some(key_provider.as_ref()))
        {
            Ok(conn) => conn,
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
                        None, // signed delta log source (core DAG) when configured; rebuild is safe without it
                        Some(node_mode.as_ref()),
                    ) {
                        Ok(conn) => conn,
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
        let derived_ver = db::schema_version(&derived, db::DbKind::Derived)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        tracing::info!(path = %derived_db_path.display(), schema_version = derived_ver, "derived.db ready (synchronous=NORMAL, WAL, DerivedLedger)");
    }

    // ── TimeRatchet (CLAIM-7.2, 7.3, 7.5, 7.6) ─────────────────────────────
    // The ratchet lives in `primary.db` next to the monotonic counters.  Opening
    // it creates/reads the `time_ratchet` table (with `beacon_boot_id`) and
    // recovers `persisted_floor` from the previous run.
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
        last_beacon_time = ratchet.last_beacon_time(),
        beacon_boot_id = ratchet.beacon_boot_id(),
        now_est = ratchet.now_est(time_source.as_ref()),
        freshness = freshness_before_beacon.as_str(),
        max_forward_jump_secs = ratchet.max_forward_jump_secs(),
        required_anchor_signatures = ratchet.required_anchor_signatures(),
        "TimeRatchet loaded"
    );

    if freshness_before_beacon == FreshnessState::Unverified {
        tirbase_core::events::emit(
            SecurityEvent::new(
                SecurityEventCategory::TimeRatchet,
                Severity::Medium,
                ReasonCode::FreshnessUnverified,
            )
            .with_detail(format!(
                "authenticated time is UNVERIFIED (persisted_floor={}, beacon_boot_id={}); \
                 critical parameters require a challenge nonce",
                ratchet.persisted_floor(),
                ratchet.beacon_boot_id()
            )),
        );
    }

    // Time-beacon ingress: a signed TimeAnchor beacon is admitted through
    // `TimeRatchet::advance`, which enforces the max-forward-jump and M-of-N
    // quorum rules (CLAIM-7.4, scenario S23).
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
                previous_floor = advance.previous_floor,
                new_floor = advance.new_floor,
                jump_secs = advance.jump_secs,
                anchor_signatures = advance.anchor_signatures,
                "Beacon accepted"
            ),
            Err(error) => {
                tracing::warn!(%error, "Beacon rejected");
                if config.key_backend == KeyBackend::File {
                    return Err(error).context("time beacon was rejected at boot");
                }
            }
        }

        if freshness_before_beacon == FreshnessState::Unverified
            && ratchet.freshness(time_source.as_ref()) == FreshnessState::Verified
        {
            tirbase_core::events::emit(
                SecurityEvent::new(
                    SecurityEventCategory::TimeRatchet,
                    Severity::Low,
                    ReasonCode::FreshnessRestored,
                )
                .with_detail(format!(
                    "fresh beacon restored VERIFIED freshness (now_est={})",
                    ratchet.now_est(time_source.as_ref())
                )),
            );
        }
    }

    // Authenticated-time expiry gate: the boot attestation is issued with its
    // expiry anchored to the ratchet floor and is checked with `now_est`, never
    // the wall clock (CLAIM-7.3).  Time spent waiting for a beacon therefore
    // expires it, which is precisely the behaviour Stage 9 applies to commands.
    let now_est = ratchet.now_est(time_source.as_ref());
    let expires_est = ratchet
        .persisted_floor()
        .saturating_add(config.boot_attestation_ttl_secs);
    if ratchet.is_expired(expires_est, time_source.as_ref()) {
        bail!(
            "boot attestation expired: now_est {now_est} > expires_est {expires_est} \
             (authenticated time advanced past the attestation window)"
        );
    }

    // ── MonotonicCounterTrait — Level 1 SQLite counter (CLAIM-5.3, 6.5) ────
    // WAL + synchronous=FULL; an increment is durable before it returns.
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

    // Prove the gateway signing path goes through the provider trait and that
    // a domain-separated SignedOperation verifies end-to-end (CLAIM-6.7).
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

    // ── SecurityEventLog (25.1–25.5, 26.1, PV-7, INV-4) ─────────────────────────
    let security_log = SecurityEventLog::new_persistent_with_mode(
        &primary_db_path,
        Some(key_provider.clone()),
        false,
        Some(node_mode.clone()),
    );
    security_log.set_rate_limit_enabled(true); // S14/PV-7.6 production rate limiting
                                               // 28.2 (PV-7.13): on-disk retention rotation (90 days or 1 GiB, configurable).
    security_log.set_retention(
        tirbase_gateway::security_log::SecurityLogRetentionConfig::from_gateway_config(&config),
    );
    match security_log.verify_hash_chain() {
        Ok(Some(first_broken_seq)) => {
            tracing::error!(
                first_broken_seq,
                mode = %node_mode.get().as_str(),
                "tamper detected in security log hash chain; entered Restricted (CLAIM-26.1, INV-4)"
            );
        }
        Ok(None) => {
            tracing::info!("security log hash chain verified intact at boot (CLAIM-26.1, INV-4)");
        }
        Err(e) => {
            tracing::error!(error = %e, "security log hash chain verification failed at boot");
            node_mode.set(tirbase_guard::node_mode::NodeMode::Restricted);
        }
    }
    security_log.install();
    let _checkpoint_handle = security_log.spawn_checkpoint_loop();
    let _retention_handle = security_log.spawn_retention_rotation_loop(); // 28.2
    tracing::info!(
        primary_db = %primary_db_path.display(),
        "hash-chained SecurityEventLog installed (CLAIM-25.1-26.1,28.2)"
    );

    // ── Trust root, root CA registry, rollback protection (tasks 8.1–8.3) ──
    // The trust-root version is committed to a named `MonotonicCounter` row in
    // primary.db.  Restoring an older `trust-root.json` therefore fails the
    // version check before its revoked root keys can be re-admitted.
    let trust_root = install_trust_root(&config, &mut ratchet, time_source.as_ref())?;
    let root_ca_registry = build_root_ca_registry(trust_root.as_deref())?;
    if let Some(registry) = &root_ca_registry {
        tracing::info!(
            active_keys = registry.active_keys().len(),
            threshold_k = registry.threshold_k(),
            "root CA registry initialised"
        );
        if let Some(warning) = registry.threshold_warning() {
            tracing::warn!("{warning}");
        }
    }
    if let Some(record) = trust_root.as_deref() {
        if let Some(warning) = record.threshold_warning() {
            tracing::warn!("{warning}");
        }
        tracing::info!(
            version = record.version,
            threshold_k = record.threshold_k,
            roles = record.role_thresholds.len(),
            device_classes = record.device_class_floors.len(),
            "trust root record loaded for all role-threshold lookups"
        );
    }
    if let Some(token_path) = &config.root_ca_self_test_token_path {
        let registry = root_ca_registry
            .as_ref()
            .context("root_ca_self_test_token_path requires trust_root_path")?;
        run_root_ca_self_test(token_path, registry, ratchet.now_est(time_source.as_ref()))?;
    }

    // ── Per-device epoch store (task 8.7) ──────────────────────────────────
    let epoch_store = SqliteDeviceEpochStore::open(&config.counter_db_path)
        .context("failed to open device_epoch store")?;
    let epochs = Arc::new(EpochRegistry::new(Arc::new(epoch_store)));
    tracing::info!(
        db = %config.counter_db_path.display(),
        "device_epoch store opened (epoch starts at 0 on first enrollment)"
    );

    // Signed epoch bump applied at boot (task 8.8).  This is the operator path
    // after restoring a snapshot (S22); the admin endpoint reuses `epochs`.
    if let Some(path) = &config.epoch_bump_path {
        let record = trust_root
            .as_deref()
            .context("epoch_bump_path requires trust_root_path")?;
        let file = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read epoch bump at {}", path.display()))?;
        let request: EpochBumpFile = serde_json::from_str(&file)
            .with_context(|| format!("failed to parse epoch bump at {}", path.display()))?;
        let bumped = epochs
            .apply_bump(
                &request.operation,
                &request.payload,
                record,
                ratchet.now_est(time_source.as_ref()),
            )
            .context("signed epoch bump was rejected")?;
        tracing::info!(
            device_id = %bumped.device_id,
            epoch = bumped.epoch,
            "signed epoch bump applied; prior-epoch commands are now rejected"
        );
    }

    // ── Enrollment service + bounded nonce store (tasks 8.5/8.6) ───────────
    let enrollment_service = build_enrollment_service(
        &config,
        trust_root.as_ref(),
        epochs.clone(),
        ratchet.now_est(time_source.as_ref()),
    )?;

    // ── Admin listener with enrollment / epoch-bump state (tasks 8.5–8.8) ──
    let admin_state = match (&enrollment_service, trust_root.as_ref()) {
        (Some(service), Some(record)) => {
            let mut st =
                admin::AdminState::new(service.clone(), epochs.clone(), Arc::clone(record));
            st.primary_db_path = Some(primary_db_path.clone());
            Some(Arc::new(st))
        }
        _ => None,
    };
    if config.admin_enabled {
        let admin_socket = config.admin_socket.clone();
        tokio::spawn(async move {
            if let Err(error) = admin::run_admin_listener(&admin_socket, admin_state).await {
                tracing::warn!(%error, "admin listener unavailable");
            }
        });
    }

    // ── Startup security event ─────────────────────────────────────────────
    tirbase_core::events::emit(
        SecurityEvent::new(
            SecurityEventCategory::Startup,
            Severity::Low,
            ReasonCode::BootCompleted,
        )
        .with_actor(key_provider.did())
        .with_detail(format!("gateway booted (counter={boot_counter})")),
    );

    tracing::info!(
        admin_socket = %config.admin_socket.display(),
        health_addr  = %config.health_addr,
        mode = node_mode.get().as_str(),
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

/// JSON envelope for a signed epoch bump applied at boot.
#[derive(Debug, Deserialize)]
struct EpochBumpFile {
    operation: SignedOperation<EpochBump>,
    payload: EpochBump,
}

/// Load, verify, install, and optionally rotate the offline trust root.
///
/// Returns `None` when the deployment has no `trust_root_path` (the skeleton
/// still boots; enrollment/epoch administration is disabled).
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
    tracing::info!(
        version = manager.record().version,
        committed_version = manager.committed_version().unwrap_or_default(),
        threshold_k = manager.record().threshold_k,
        "trust root installed with rollback protection"
    );

    if let Some(rotation_path) = &config.trust_root_rotation_path {
        let rotated = read_trust_root(rotation_path)?;
        rotated
            .verify_threshold_signatures()
            .map_err(|error| anyhow::anyhow!("rotation threshold signatures invalid: {error}"))?;
        if let Err(error) = manager.rotate(rotated, now_est) {
            return Err(trust_root_failure("rotation", error));
        }
        tracing::info!(
            version = manager.record().version,
            committed_version = manager.committed_version().unwrap_or_default(),
            revoked_root_keys = manager.record().revoked_root_ca_keys.len(),
            "trust root rotated; revoked root keys are no longer accepted"
        );
    }

    Ok(Some(Arc::new(manager.record().clone())))
}

fn read_trust_root(path: &std::path::Path) -> Result<TrustRootRecord> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read trust root at {}", path.display()))?;
    serde_json::from_str(&body)
        .with_context(|| format!("failed to parse trust root at {}", path.display()))
}

/// Emit `TrustRootRollbackRejected` and build the boot error for a rejected
/// trust-root install/rotation.
fn trust_root_failure(stage: &str, error: TrustRootError) -> anyhow::Error {
    if let TrustRootError::Rollback { incoming, current } = &error {
        tirbase_core::events::emit(
            SecurityEvent::new(
                SecurityEventCategory::Enrollment,
                Severity::High,
                ReasonCode::TrustRootRollbackRejected,
            )
            .with_detail(format!(
                "trust-root {stage} rejected: incoming version {incoming} \
                 is not greater than committed version {current}"
            )),
        );
        tracing::error!(incoming, current, stage, "trust root rollback rejected");
    }
    anyhow::anyhow!("trust root {stage} rejected: {error}")
}

/// Build the token-verification registry from the installed trust root.
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

/// Prove the root CA registration path: the token must fail against an empty
/// registry and succeed after the trust-root keys are registered (CLAIM-8.1).
fn run_root_ca_self_test(
    token_path: &std::path::Path,
    registered: &RootCaRegistry,
    now_est: i64,
) -> Result<()> {
    let body = std::fs::read_to_string(token_path).with_context(|| {
        format!(
            "failed to read root CA self-test token at {}",
            token_path.display()
        )
    })?;
    let token = hex::decode(body.trim())
        .context("root CA self-test token is not hex-encoded Biscuit bytes")?;

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
    tracing::info!(
        registered_keys = registry.active_keys().len(),
        "root CA self-test: token verified after CA registration"
    );
    Ok(())
}

/// Build the enrollment service and its bounded nonce store, starting the
/// background purge task (tasks 8.5/8.6).
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
    tracing::info!(
        retention_secs = nonces.retention_secs(),
        capacity = nonces.capacity(),
        token_ttl_secs = service.token_ttl_secs(),
        "enrollment service ready (replay-safe bootstrap enabled)"
    );

    let purge_interval_secs = config.enrollment_nonce_purge_interval_secs.max(1);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(purge_interval_secs));
        loop {
            ticker.tick().await;
            let now = tirbase_core::traits::wall_hint_secs().unwrap_or_default();
            match nonces.purge_expired(now) {
                Ok(0) => {}
                Ok(purged) => {
                    tracing::debug!(purged, "expired enrollment nonces purged")
                }
                Err(error) => tracing::warn!(%error, "enrollment nonce purge failed"),
            }
        }
    });

    Ok(Some(service))
}

/// Read an Ed25519 private key seed: either 64 hex characters or 32 raw bytes.
fn read_hex_key(path: &std::path::Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read key material at {}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    let trimmed = trimmed.strip_prefix("0x").unwrap_or(trimmed);

    let decoded = match hex::decode(trimmed) {
        Ok(decoded) => decoded,
        Err(_) if bytes.len() == 32 => bytes.clone(),
        Err(error) => {
            bail!(
                "key material at {} is neither hex nor a 32-byte seed: {error}",
                path.display()
            )
        }
    };
    if decoded.len() != 32 {
        bail!(
            "key material at {} must be a 32-byte Ed25519 seed (got {} bytes)",
            path.display(),
            decoded.len()
        );
    }
    Ok(decoded)
}

/// Build the configured key provider (CLAIM-6.1 / 6.3 / 6.4).
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
        Some(path) => std::fs::read(path)
            .with_context(|| format!("failed to read TPM2 PCR policy at {}", path.display()))?,
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

// (note: full CommandGuard/AdmitPipeline production construction is pending
// gateway command-server wiring; Task 21 hydration/sync helpers are implemented
// and integration-tested in tirbase_gateway::guard and admin dispatch paths.)
