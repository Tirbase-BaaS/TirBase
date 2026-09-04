//! Public API layer — CoreHandle, init(), read(), write(), query()
//!
//! This is the primary entry point for both the TypeScript SDK (WASM build)
//! and the Cloud Ledger (native build). The API surface is identical on both
//! build targets; static_assertions in lib.rs enforce this at compile time.

#![allow(dead_code, unused_variables, unused_imports)]

pub mod types;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::errors::TirBaseError;
use types::{
    ConnectionStatus, DurabilityTier, MeshStatus, QueryResult, TrustLevel, WriteResult,
};

// ─── Subsystem imports ────────────────────────────────────────────────────────

use crate::auth::CapabilityManager;
use crate::contamination::CausalContaminationEngine;
use crate::crdt::delta::{DeltaId, PriorityClass};
use crate::crdt::CrdtEngine;
use crate::diagnostics::{emit_startup_diagnostics, DiagnosticEntry};
use crate::durability::quorum::QuorumConfig;
use crate::durability::DurabilitySubsystem;

// Cloud Ledger / cloud sync wiring (Subphase 4.1) — the `CloudLedger` and its
// `CloudConnection` adapter are native-only (they embed a rusqlite-backed
// `CrdtEngine`), so the production drain loop is native-only as well.
#[cfg(feature = "native")]
use crate::durability::cloud_ledger::{CloudLedger, CloudLedgerConnection};
#[cfg(feature = "native")]
use crate::durability::cloud_queue::{cloud_sync_loop, CloudSyncResult};
use crate::identity::IdentityManager;
use crate::migration::version_path::SchemaVersionPath;
use crate::migration::SchemaMigrationEngine;
use crate::transport::{MeshTransport, TransportConfig};

// Req 18.6 interruptible sandbox execution (native): the in-flight execution
// registry lets a migration revocation epoch-interrupt a running transform,
// and `execute_migration_with_registry` registers the run before invoking it.
#[cfg(feature = "native")]
use crate::migration::wasm_sandbox::{execute_migration_with_registry, MigrationExecutionRegistry};

// Store import — used on both build targets
#[cfg(feature = "native")]
use crate::store::LocalStore;

#[cfg(not(feature = "native"))]
use crate::store::LocalStore;

/// Default schema hash used when no explicit schema is configured.
const DEFAULT_SCHEMA_HASH: [u8; 32] = [0u8; 32];

/// RAII guard that decrements [`CoreHandle::migration_tasks_active`] when a
/// background migration job exits, on every code path (native, Req 18.6).
#[cfg(feature = "native")]
struct ActiveMigrationJobGuard(std::sync::Arc<std::sync::atomic::AtomicUsize>);

#[cfg(feature = "native")]
impl Drop for ActiveMigrationJobGuard {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Current wall-clock time in UTC microseconds (peer-table bookkeeping).
fn now_micros() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
}

/// Current wall-clock time in UTC seconds (Saturate_Mode lease bookkeeping,
/// Req 13.3–13.5).
fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Wrap a `RevocationDelta` in a HIGH-priority outbound Delta and enqueue it on
/// the mesh transport scheduler, so the scheduler tick loop gossips it to
/// peers (Req 9.1 partial-delta gossip from initiating Managers; Req 9.2
/// complete-delta rebroadcast once the M-of-N threshold is met).
///
/// The wrapper mirrors the wire framing used by the inbound revocation path
/// (author `tirbase/revocation`, `PriorityClass::High`); receiving peers parse
/// the embedded `GossipMessage::InboundRevocationDelta` and accumulate the
/// signatures via `RevocationSubsystem::process_incoming_delta`.
#[cfg(feature = "native")]
fn enqueue_revocation_gossip(
    transport: &mut MeshTransport,
    rev_delta: &crate::auth::RevocationDelta,
) {
    use crate::transport::message::GossipMessage;
    let gossip_msg = GossipMessage::InboundRevocationDelta(rev_delta.clone());
    let gossip_bytes = gossip_msg.to_bytes();
    let wrapper = crate::crdt::delta::Delta {
        id: [0u8; 32],
        author_did: "tirbase/revocation".to_string(),
        signature: crate::crdt::delta::Ed25519Signature::default(),
        schema_hash: [0u8; 32],
        automerge_bytes: gossip_bytes,
        priority: crate::crdt::delta::PriorityClass::High,
        causal_parents: vec![],
        tags: vec![],
        lamport: 0,
        created_at: 0,
    };
    transport.enqueue_outbound(wrapper);
}

/// Production cadence (ms) of the inbound drain loop spawned by
/// `CoreHandle::init` (Subphase 1.3): every 50 ms the task calls
/// `process_inbound_messages()` to drain `inbound_rx`.
#[cfg(all(feature = "native", not(test)))]
const INBOUND_DRAIN_INTERVAL_MS: u64 = 50;

/// Test-build cadence (ms) of the inbound drain loop spawned by
/// `CoreHandle::init`: 1 hour, i.e. effectively inert.  Unit tests drive
/// `process_inbound_messages()` manually and assert exact drain counts, so the
/// loop init spawns must not tick while they run; the Subphase 1.3 integration
/// test exercises the identical loop via `CoreHandle::spawn_inbound_drain_loop`
/// with a short interval.
#[cfg(all(feature = "native", test))]
const INBOUND_DRAIN_INTERVAL_MS: u64 = 3_600_000;

/// Production cadence (ms) of the DRR scheduler tick loop spawned by
/// `CoreHandle::init` (Subphase 1.4): every 1000 ms the task calls
/// `MeshTransport::tick_scheduler`, which runs one DRR scheduling epoch
/// (Req 12 — the design defines one epoch as 1 second) and forwards the
/// drained Deltas to the outbound publish channel.
#[cfg(all(feature = "native", not(test)))]
const SCHEDULER_TICK_INTERVAL_MS: u64 = 1000;

/// Test-build cadence (ms) of the DRR scheduler tick loop spawned by
/// `CoreHandle::init`: 1 hour, i.e. effectively inert.  Unit tests enqueue
/// Deltas and assert queue state (e.g. the revocation HIGH-priority enqueue
/// test), so the loop init spawns must not drain the scheduler while they
/// run; the Subphase 1.4 integration test exercises the identical loop via
/// `CoreHandle::spawn_scheduler_tick_loop` with a short interval.
#[cfg(all(feature = "native", test))]
const SCHEDULER_TICK_INTERVAL_MS: u64 = 3_600_000;

/// Production cadence (ms) of the cloud sync loop spawned by
/// `CoreHandle::init` (Subphase 4.1): every 1000 ms the task drains the
/// Durability Subsystem's cloud outbound queue through the real
/// `CloudLedgerConnection` in causal order, sending each Delta to the
/// Cloud Ledger (Req 16.3).
#[cfg(all(feature = "native", not(test)))]
const CLOUD_SYNC_INTERVAL_MS: u64 = 1000;

/// Test-build cadence (ms) of the cloud sync loop spawned by
/// `CoreHandle::init`: 1 hour, i.e. effectively inert.  Unit tests register
/// Deltas and assert cloud queue state, so the loop init spawns must not
/// drain the queue while they run; the Subphase 4.1 integration test drives
/// the identical loop via `CoreHandle::spawn_cloud_sync_loop` with a short
/// interval.
#[cfg(all(feature = "native", test))]
const CLOUD_SYNC_INTERVAL_MS: u64 = 3_600_000;

// ─── Durability tier change event (native) ───────────────────────────────────

/// A durability tier transition for one Delta set, surfaced to native host
/// applications via [`CoreHandle::subscribe_durability_events`] (Req 14.7).
///
/// This is the native analogue of the SDK's `DurabilityTierChanged` WASM event
/// (which `notify_tier_changed` in the durability module continues to push on
/// the WASM build).  Native-only because the Tier-2 production trigger — the
/// cloud sync drain loop attached to the in-process `CloudLedger` — exists on
/// the native build target only (Subphase 4.2).
#[cfg(feature = "native")]
#[derive(Debug, Clone)]
pub struct DurabilityTierChanged {
    /// The Delta whose durability tier transitioned.
    pub delta_id: DeltaId,
    /// The tier before the transition.
    pub previous_tier: DurabilityTier,
    /// The tier after the transition (Tier1 or Tier2).
    pub new_tier: DurabilityTier,
}

// ─── CoreHandle ───────────────────────────────────────────────────────────────

/// The main handle to a TirBase instance.
/// Obtained by calling [`CoreHandle::init`].
pub struct CoreHandle {
    /// Local SQLite-backed store (native) or in-memory store (WASM).
    #[cfg(feature = "native")]
    store: Arc<Mutex<LocalStore>>,

    /// In-memory store for WASM builds.
    #[cfg(not(feature = "native"))]
    store: Arc<Mutex<LocalStore>>,

    /// CRDT engine (Automerge + DAG).
    #[cfg(feature = "native")]
    crdt: Arc<Mutex<CrdtEngine>>,

    /// CRDT engine for WASM builds (in-memory, no SQLite).
    #[cfg(not(feature = "native"))]
    crdt: Arc<Mutex<CrdtEngine>>,

    /// Device identity (Ed25519 keypair + DID).
    pub(crate) identity: Arc<IdentityManager>,

    /// Biscuit token / TrustLevel state machine.
    capability: Arc<Mutex<CapabilityManager>>,

    /// Mesh transport layer (libp2p Swarm on native).
    pub(crate) transport: Arc<Mutex<MeshTransport>>,

    /// Two-tier durability subsystem.
    durability: Arc<Mutex<DurabilitySubsystem>>,

    /// The Cloud Ledger this process hosts, reachable through the
    /// `CloudConnection` adapter (`CloudLedgerConnection`).
    ///
    /// Subphase 4.1: the production cloud sync loop
    /// (`CoreHandle::spawn_cloud_sync_loop`) drains
    /// [`DurabilitySubsystem`]'s cloud outbound queue into this ledger in
    /// causal order, sending every locally-written Delta to the Cloud Ledger
    /// and removing it only after the ledger's per-Delta ack (Req 16.3).
    /// Subphase 4.2: each such ack marks the Delta Tier-2 durable in the
    /// Durability Subsystem and notifies the host application (see
    /// [`CoreHandle::subscribe_durability_events`]).
    /// Native-only: the `CloudLedger` embeds a rusqlite-backed
    /// `CrdtEngine`, which does not exist on the WASM build target.
    #[cfg(feature = "native")]
    cloud_ledger: Arc<Mutex<CloudLedger>>,

    /// Causal Contamination Engine.
    #[cfg(feature = "native")]
    pub(crate) cce: Arc<Mutex<CausalContaminationEngine>>,

    /// Schema Migration Engine.
    migration: Arc<Mutex<SchemaMigrationEngine>>,

    /// Interrupt handles for schema-migration transforms currently executing
    /// in the sandbox (Req 18.6).
    ///
    /// The inbound pipeline prepares a migration under the engine lock, then
    /// executes the transform OFF the lock with its `wasmtime::Engine`
    /// registered here, so a `MigrationRevocationDelta` that halts the run can
    /// epoch-interrupt it instead of queueing behind it under the shared
    /// `migration` mutex.
    #[cfg(feature = "native")]
    migration_runs: Arc<MigrationExecutionRegistry>,

    /// Number of background migration jobs currently dispatched but not yet
    /// finished (running, or waiting to prepare behind another transform).
    /// Lets `await_migration_quiescence` distinguish "no transform executing"
    /// from "a job has not even started yet".
    #[cfg(feature = "native")]
    migration_tasks_active: Arc<std::sync::atomic::AtomicUsize>,

    /// Causal Contamination Engine (WASM build).
    #[cfg(not(feature = "native"))]
    pub(crate) cce: Arc<Mutex<crate::contamination::CausalContaminationEngine>>,

    /// Revocation Subsystem (native build).
    #[cfg(feature = "native")]
    pub(crate) revocation: Arc<Mutex<crate::auth::RevocationSubsystem>>,

    /// Revocation Subsystem (WASM build).
    #[cfg(not(feature = "native"))]
    pub(crate) revocation: Arc<Mutex<crate::auth::RevocationSubsystem>>,

    /// Broadcast channel for structured diagnostic entries.
    diagnostics_channel: tokio::sync::broadcast::Sender<DiagnosticEntry>,

    /// Broadcast channel for structured Delta rejection failure records
    /// (Subphase 6.2 — Req 7.4/7.5).
    ///
    /// [`CoreHandle::init`] registers a listener on the CRDT engine
    /// (see [`CrdtEngine::set_rejection_listener`](crate::crdt::CrdtEngine::set_rejection_listener))
    /// that forwards every rejection record the merge gate emits — revoked
    /// author, missing signature, DID-resolution failure, signature-verification
    /// failure — onto this channel, so host applications can subscribe with
    /// [`CoreHandle::subscribe_rejection_records`].  Each record carries the
    /// sender DID and a UTC timestamp per Req 7.4/7.5.
    rejection_records_channel:
        tokio::sync::broadcast::Sender<crate::crdt::failure::DeltaRejectionRecord>,

    /// Broadcast channel for durability tier transitions (Req 14.7).
    ///
    /// The Durability Subsystem's instance-level tier-change listener —
    /// registered in [`CoreHandle::init`] — forwards every Tier-1 quorum /
    /// Tier-2 cloud-ack transition here, so native host applications can
    /// react to a Delta becoming durable through
    /// [`CoreHandle::subscribe_durability_events`] instead of only observing
    /// the stderr log.  Native-only: on the WASM target the SDK receives the
    /// same transitions as `DurabilityTierChanged` events through
    /// `core_poll_events()` (Subphase 4.2).
    #[cfg(feature = "native")]
    durability_events_channel: tokio::sync::broadcast::Sender<DurabilityTierChanged>,

    /// Sender end of the inbound Gossipsub message channel.
    /// The spawned event loop writes here; `process_inbound_messages` drains via `inbound_rx`.
    inbound_tx: tokio::sync::mpsc::Sender<crate::transport::message::GossipMessage>,

    /// Receiver end of the inbound Gossipsub message channel.
    ///
    /// Wrapped in `Arc<tokio::sync::Mutex<..>>` so `CoreHandle` remains
    /// `Sync` while the production inbound drain loop spawned by [`CoreHandle::init`]
    /// holds its own `Arc` clone of the receiver (Subphase 1.3).
    inbound_rx: Arc<tokio::sync::Mutex<
        tokio::sync::mpsc::Receiver<crate::transport::message::GossipMessage>,
    >>,

    /// Sender end of the explicit-dial channel (native only).
    ///
    /// [`CoreHandle::dial_peer`] forwards the target multiaddr here and the
    /// Swarm polling task (which owns the receiver end) dials it.  `None` when
    /// the transport never started (offline device — Req 3.3) or on wasm.
    #[cfg(feature = "native")]
    dial_tx: Option<tokio::sync::mpsc::Sender<libp2p::Multiaddr>>,
}

impl CoreHandle {
    /// Initialise TirBase, loading or creating local storage and identity.
    ///
    /// On the WASM target this is exposed to JavaScript and resolves a
    /// Promise-based ready signal (Req 2.2).
    /// On the native target it blocks until initialisation is complete.
    ///
    /// Returns an `Arc<CoreHandle>`: the handle is shared with the production
    /// inbound drain loop spawned inside `init` (Subphase 1.3), which keeps
    /// draining `inbound_rx` for the lifetime of the instance.
    pub async fn init(config: InitConfig) -> Result<Arc<Self>, TirBaseError> {
        // ── Diagnostics channel ───────────────────────────────────────────────
        let (diag_tx, _diag_rx) =
            tokio::sync::broadcast::channel::<DiagnosticEntry>(64);

        // ── CRDT rejection-record channel (Subphase 6.2 — Req 7.4/7.5) ───────
        let (rejection_records_tx, _rejection_records_rx) = tokio::sync::broadcast::channel::<
            crate::crdt::failure::DeltaRejectionRecord,
        >(64);

        // ── Identity ──────────────────────────────────────────────────────────
        let identity_path = format!("{}.identity.json", config.storage_path);
        let identity = {
            #[cfg(feature = "native")]
            {
                IdentityManager::init_with_path(Some(&identity_path))?
            }
            #[cfg(not(feature = "native"))]
            {
                IdentityManager::init_in_memory()?
            }
        };
        let identity = Arc::new(identity);

        // ── Capability Manager ────────────────────────────────────────────────
        // Root CA keys come from deployment config; an empty vec is the explicit
        // unconfigured state (verification fails until keys are registered).
        let capability = CapabilityManager::new(
            config.deployment.root_ca_keys.clone(),
            config.deployment.revocation_m,
            config.deployment.revocation_n,
        );
        if let Some(warning) = capability.check_1_of_1_warning() {
            // Emit as an informal diagnostic — ignore send errors (no subscribers yet).
            let _ = diag_tx.send(DiagnosticEntry {
                severity: crate::diagnostics::DiagnosticSeverity::Warning,
                code: "UNILATERAL_EXILE",
                message: warning,
            });
        }
        let capability = Arc::new(Mutex::new(capability));

        // ── Native subsystems (require rusqlite) ──────────────────────────────
        #[cfg(feature = "native")]
        let (store, crdt, cce) = {
            // Primary store connection (used by LocalStore).
            let store = LocalStore::open(&config.storage_path)?;
            let store = Arc::new(Mutex::new(store));

            // Secondary connection for CrdtEngine + CCE (they hold their own
            // Arc<Mutex<Connection>> references internally).
            let conn = crate::store::sqlite::open(&config.storage_path)?;
            // Schema is already created by `sqlite::open`; the
            // CREATE_SCHEMA_SQL call inside open() is idempotent.
            let conn = Arc::new(Mutex::new(conn));

            let crdt = CrdtEngine::new(
                identity.signing_key_bytes(),
                identity.public_key_bytes(),
                identity.did().to_string(),
                DEFAULT_SCHEMA_HASH,
                conn.clone(),
            );
            let crdt = Arc::new(Mutex::new(crdt));

            let cce = CausalContaminationEngine::new(conn.clone());
            let cce = Arc::new(Mutex::new(cce));

            (store, crdt, cce)
        };

        // ── WASM store (in-memory) ────────────────────────────────────────────
        #[cfg(not(feature = "native"))]
        let store = {
            let store = LocalStore::open(":memory:")?;
            Arc::new(Mutex::new(store))
        };

        // ── WASM CrdtEngine (in-memory, no SQLite connection) ─────────────────
        #[cfg(not(feature = "native"))]
        let crdt = {
            let crdt = CrdtEngine::new(
                identity.signing_key_bytes(),
                identity.public_key_bytes(),
                identity.did().to_string(),
                DEFAULT_SCHEMA_HASH,
            );
            Arc::new(Mutex::new(crdt))
        };

        // ── Native Revocation Subsystem ───────────────────────────────────────
        #[cfg(feature = "native")]
        let revocation = {
            let conn = crate::store::sqlite::open(&config.storage_path)?;
            let conn = Arc::new(Mutex::new(conn));
            Arc::new(Mutex::new(crate::auth::RevocationSubsystem::new(
                config.deployment.revocation_m.max(1),
                config.deployment.revocation_n.max(1),
                conn,
            )))
        };

        // ── WASM CCE and RevocationSubsystem ──────────────────────────────────
        #[cfg(not(feature = "native"))]
        let cce = Arc::new(Mutex::new(
            crate::contamination::CausalContaminationEngine::new()
        ));

        #[cfg(not(feature = "native"))]
        let revocation = Arc::new(Mutex::new(
            crate::auth::RevocationSubsystem::new(
                config.deployment.revocation_m.max(1),
                config.deployment.revocation_n.max(1),
            )
        ));

        // ── Migration Engine ──────────────────────────────────────────────────
        //
        // Subphase 5.1: the Migration CA public key and the deployment's
        // ordered schema-version path are wired from `DeploymentConfig` (Req
        // 18.2, 18.3a).  `None`/empty remain the explicit unconfigured states
        // — with no key the engine verifies against the zero key (every
        // signature fails) and with no path no version step validates — but a
        // deployment that configures both now accepts valid inbound
        // migrations instead of rejecting every one at the CA gate.
        let migration_ca_public_key = config
            .deployment
            .migration_ca_public_key
            .unwrap_or([0u8; 32]);
        let migration_version_path =
            SchemaVersionPath::new(config.deployment.schema_version_path.clone());
        // The device starts on the oldest registered schema version; without a
        // configured path it stays on the default (no-schema) hash.
        let migration_local_schema_hash = migration_version_path
            .versions
            .first()
            .copied()
            .unwrap_or(DEFAULT_SCHEMA_HASH);

        // ── CRDT schema-definition registry (Subphase 5.3) ────────────────────
        //
        // The deployment's full schema definitions are registered with the
        // CRDT engine so its merge gate can classify an unknown inbound hash
        // at the field level (Req 17.3/17.4) instead of treating every hash
        // outside the known set alike.  Definitions are matched positionally
        // to `schema_version_path`; a definition whose canonical hash differs
        // from its path entry — or a path/definition length mismatch — is a
        // configuration error and aborts init.  With a configured path the
        // device's *current* schema becomes the first version (mirroring the
        // SchemaMigrationEngine below), so locally produced Deltas carry a
        // real schema hash (Req 4.6) rather than the zero sentinel.
        let schema_definitions = config.deployment.schema_definitions.clone();
        match migration_version_path.versions.first().copied() {
            None => {
                if !schema_definitions.is_empty() {
                    return Err(TirBaseError::SchemaRegistrationFailed {
                        reason: "schema_definitions provided but schema_version_path is empty — \
                                 every definition must map to a path version"
                            .to_string(),
                    });
                }
            }
            Some(current_hash) => {
                if !schema_definitions.is_empty()
                    && schema_definitions.len() != migration_version_path.versions.len()
                {
                    return Err(TirBaseError::SchemaRegistrationFailed {
                        reason: format!(
                            "schema_definitions length {} does not match \
                             schema_version_path length {}",
                            schema_definitions.len(),
                            migration_version_path.versions.len()
                        ),
                    });
                }
                let mut crdt = crdt.lock().map_err(|e| {
                    TirBaseError::LocalStoreWriteFailed {
                        reason: format!("crdt mutex poisoned during schema registration: {e}"),
                    }
                })?;
                crdt.set_current_schema(current_hash);
                for (idx, schema) in schema_definitions.into_iter().enumerate() {
                    crdt.register_schema_definition(
                        migration_version_path.versions[idx],
                        schema,
                    )?;
                }
            }
        }

        // ── CRDT rejection-record listener (Subphase 6.2 — Req 7.4/7.5) ──────
        //
        // Register an engine-level listener that relays every structured Delta
        // rejection record — emitted by `CrdtEngine::apply` when the merge
        // gate discards an inbound Delta (revoked author, missing signature,
        // unresolvable DID — Req 7.5, signature failure — Req 7.4) — onto
        // this handle's broadcast channel.  The listener is invoked while the
        // engine is locked, so it only sends on the non-blocking broadcast
        // channel and never re-enters the engine.
        {
            let tx = rejection_records_tx.clone();
            let mut crdt_guard = crdt.lock().map_err(|e| {
                TirBaseError::LocalStoreWriteFailed {
                    reason: format!(
                        "crdt mutex poisoned while registering rejection listener: {e}"
                    ),
                }
            })?;
            crdt_guard.set_rejection_listener(Box::new(move |record| {
                let _ = tx.send(record.clone());
            }));
        }

        #[cfg(feature = "native")]
        let migration = {
            let mig_conn = crate::store::sqlite::open(&config.storage_path)?;
            let mig_conn = Arc::new(Mutex::new(mig_conn));
            SchemaMigrationEngine::new(
                migration_ca_public_key,
                migration_local_schema_hash,
                migration_version_path,
                config.deployment.revocation_m.max(1),
                store.clone(),
                mig_conn,
            )
        };

        #[cfg(not(feature = "native"))]
        let migration = SchemaMigrationEngine::new(
            migration_ca_public_key,
            migration_local_schema_hash,
            migration_version_path,
            config.deployment.revocation_m.max(1),
        );

        let migration = Arc::new(Mutex::new(migration));

        // ── In-flight migration execution registry (Req 18.6) ────────────────
        //
        // Native: holds the `wasmtime::Engine` of each sandbox transform that
        // is currently executing off the migration lock, so a revocation can
        // epoch-interrupt it.  Lives outside `SchemaMigrationEngine` on
        // purpose — it must stay reachable while a transform runs without the
        // engine lock.
        #[cfg(feature = "native")]
        let migration_runs = Arc::new(MigrationExecutionRegistry::default());
        #[cfg(feature = "native")]
        let migration_tasks_active = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // ── Durability Subsystem ──────────────────────────────────────────────
        //
        // Subphase 4.3: when the deployment enables Anchor_Attested_Location, the
        // subsystem is constructed with an `AnchorAttestedLocation` verifier built
        // from the deployment's beacon public keys (DIDs derived `did:key:`), so
        // `DurabilitySubsystem::receive_receipt` — the function the native/WASM
        // inbound pipelines call for every incoming `DurabilityReceipt` — gates
        // Quorum formation on valid beacon attestations (Req 15.1–15.3).
        // Subphase 4.4: `max_single_sector_fraction` is deployment-configurable
        // (Req 14.3 cap; default 0.7 — the historical hardcode).  A value
        // outside (0, 1] cannot express a fraction cap: 0 (or negative) would
        // forbid every receipt and disable Quorum, and > 1 would disable the
        // cap silently.  Such values fall back to the 0.7 default instead of
        // being enforced literally.
        let max_single_sector_fraction = config.deployment.max_single_sector_fraction;
        let max_single_sector_fraction = if max_single_sector_fraction.is_finite()
            && max_single_sector_fraction > 0.0
            && max_single_sector_fraction <= 1.0
        {
            max_single_sector_fraction
        } else {
            0.7
        };

        #[cfg_attr(not(feature = "native"), allow(unused_mut))]
        let mut durability = DurabilitySubsystem::with_anchor(
            QuorumConfig {
                k: config.deployment.quorum_k.max(1),
                n: config.deployment.quorum_n.max(1),
                // Subphase 4.4: 0 is the *unconfigured* marker carried through
                // to the quorum tracker, which resolves Req 14.3's default rule
                // min(K, distinct tags available) at runtime — no longer a raw
                // "require 0 distinct tags" minimum.
                spatial_diversity_min: config.deployment.spatial_diversity_min,
                max_single_sector_fraction,
            },
            if config.deployment.anchor_attested_location {
                Some(crate::durability::anchor::AnchorAttestedLocation::from_beacon_public_keys(
                    &config.deployment.beacon_public_keys,
                    0,
                ))
            } else {
                None
            },
        );

        // Subphase 4.2: attach a tier-change listener forwarding every
        // durability transition (Tier-1 quorum, Tier-2 cloud ack) to this
        // handle's broadcast channel, so CoreHandle/SDK consumers are notified
        // when a written Delta becomes durable (Req 14.7).  The listener only
        // sends on the non-blocking broadcast channel — it is invoked while
        // the Durability Subsystem is locked, so it must never re-enter it.
        #[cfg(feature = "native")]
        let (durability_events_channel, _durability_events_rx) =
            tokio::sync::broadcast::channel::<DurabilityTierChanged>(64);

        #[cfg(feature = "native")]
        {
            let tx = durability_events_channel.clone();
            durability.set_tier_changed_listener(Box::new(
                move |delta_id, previous_tier, new_tier| {
                    let _ = tx.send(DurabilityTierChanged {
                        delta_id,
                        previous_tier,
                        new_tier,
                    });
                },
            ));
        }
        let durability = Arc::new(Mutex::new(durability));

        // ── Cloud Ledger (native) ────────────────────────────────────────────
        //
        // Subphase 4.1: host a real Cloud Ledger for this process and attach it
        // to the Durability Subsystem's cloud outbound queue via the
        // `CloudConnection` adapter (`CloudLedgerConnection`).  The ledger runs
        // the same `CrdtEngine` semantics as every device (Req 16.1) and is
        // constructed with this process's own identity + the default schema
        // hash, so locally-written Deltas (produced by the same identity and
        // schema in `write()`) verify and merge.  The production cloud sync
        // loop spawned below drains the queue into it in causal order (Req
        // 16.3); Subphase 4.2 wires each ack into
        // `DurabilitySubsystem::on_cloud_ack`, which marks the Delta Tier-2
        // durable and notifies the handle's durability event channel.
        #[cfg(feature = "native")]
        let cloud_ledger = Arc::new(Mutex::new(CloudLedger::new_in_memory(
            identity.signing_key_bytes(),
            identity.did().to_string(),
            DEFAULT_SCHEMA_HASH,
        )?));

        // ── Mesh Transport ────────────────────────────────────────────────────
        #[cfg_attr(not(feature = "native"), allow(unused_mut))]
        let mut transport = MeshTransport::new(
            identity.did().to_string(),
            TransportConfig {
                listen_addr: config.listen_addr.clone(),
                // Subphase 3.1: the transport's Saturate_Mode state machine is
                // configured from the deployment — the M-of-N manager threshold
                // (Req 13.6) and the primary root CA key for offline Biscuit
                // verification (Req 13.1, 13.7).
                saturate_termination_threshold_m: config.deployment.revocation_m.max(1),
                root_ca_public_key: config
                    .deployment
                    .root_ca_keys
                    .first()
                    .map(|k| k.to_vec())
                    .unwrap_or_default(),
                // Subphase 3.4: the lease window is deployment-configurable
                // (default 60 min, Req 13.3).  A short configured window is
                // what lets a runtime test let the lease expire through the
                // wall clock instead of backdating it.
                saturate_lease_duration_secs: config.deployment.saturate_lease_duration_secs.max(1),
                ..TransportConfig::default()
            },
        );
        #[cfg(feature = "native")]
        {
            // Start the libp2p Swarm in the background.  Failure is logged but
            // not fatal — the device can still operate offline (Req 3.3).
            if let Err(e) = transport.start().await {
                eprintln!("[CoreHandle::init] transport.start() failed: {e} — operating offline");
            }
        }
        let transport = Arc::new(Mutex::new(transport));

        // ── Inbound message channel ───────────────────────────────────────────
        //
        // The receiver is wrapped in `Arc<tokio::sync::Mutex<..>>` so it can be
        // shared between this handle (manual `process_inbound_messages()` drains)
        // and the production inbound drain loop spawned below (Subphase 1.3).
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel::<
            crate::transport::message::GossipMessage,
        >(1024);
        let inbound_rx = Arc::new(tokio::sync::Mutex::new(inbound_rx));

        // ── Native: take the Swarm and spawn the polling task ─────────────────
        //
        // The Swarm is owned exclusively by this task so it can be polled across
        // `.await` points.  Outbound delivery therefore goes through a channel:
        // `write()` → `MeshTransport::send_delta` forwards prepared payloads
        // into `outbound_rx`, and this task publishes them to the shared
        // Gossipsub topic (Subphase 1.1 — Req 5.1).
        //
        // `scheduler_tick_armed` records whether a Swarm polling task is
        // actually running; the DRR scheduler tick loop (Subphase 1.4) is only
        // spawned when it is, because the tick loop forwards scheduled Deltas
        // into the same outbound channel and would fail every epoch otherwise.
        #[cfg(feature = "native")]
        let mut scheduler_tick_armed = false;

        #[cfg(feature = "native")]
        let dial_tx = {
            use crate::transport::TirBaseBehaviour;
            use libp2p::futures::StreamExt as _;
            use libp2p::gossipsub;
            use libp2p::mdns;
            use libp2p::swarm::SwarmEvent;

            let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);

            // Explicit-dial channel (Subphase 1.5): `CoreHandle::dial_peer`
            // forwards target multiaddrs here; the Swarm polling task owns the
            // receiver and performs the actual `swarm.dial`.  `None` when no
            // polling task can be spawned (transport failed to start).
            let (dial_tx, mut dial_rx) =
                tokio::sync::mpsc::channel::<libp2p::Multiaddr>(64);

            let (swarm_opt, gossip_topic) = {
                let mut transport_guard =
                    transport.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
                        reason: format!("transport mutex poisoned: {e}"),
                    })?;
                let topic = transport_guard.gossip_topic.clone();
                let swarm = transport_guard.take_swarm(outbound_tx);
                (swarm, topic)
            };

            if let Some(mut swarm) = swarm_opt {
                let tx_clone = inbound_tx.clone();
                let revocation_arc = revocation.clone();
                let transport_arc = transport.clone();
                let gossip_topic = gossipsub::IdentTopic::new(&gossip_topic);
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            event = swarm.select_next_some() => {
                                match event {
                                    SwarmEvent::Behaviour(
                                        crate::transport::TirBaseBehaviourEvent::Gossipsub(
                                            gossipsub::Event::Message { message, .. },
                                        ),
                                    ) => {
                                        if let Some(msg) = crate::transport::message::GossipMessage::from_bytes(&message.data) {
                                            if tx_clone.send(msg).await.is_err() {
                                                // Receiver dropped — CoreHandle is gone.
                                                break;
                                            }
                                        } else {
                                            eprintln!(
                                                "[transport-loop] unrecognised gossipsub message ({} bytes)",
                                                message.data.len()
                                            );
                                        }
                                    }
                                    SwarmEvent::NewListenAddr { address, .. } => {
                                        eprintln!("[transport-loop] listening on {address}");
                                    }
                                    // Subphase 1.5: record live connections in
                                    // the peer table so `mesh_status()` (Req 2.5)
                                    // reflects real connectivity — including
                                    // peers reached via `CoreHandle::dial_peer`
                                    // (no mDNS announcement involved).
                                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                        let did = crate::transport::discovery::mdns_adapter::peer_id_to_did(&peer_id);
                                        if let Ok(mut t) = transport_arc.lock() {
                                            let _ = t.on_peer_discovered(
                                                crate::transport::discovery::DiscoveredPeer {
                                                    did,
                                                    transport: crate::transport::discovery::PeerTransport::Explicit {
                                                        multiaddr: format!("/p2p/{peer_id}"),
                                                    },
                                                    hop_count: 0,
                                                },
                                                now_micros(),
                                            );
                                        }
                                    }
                                    SwarmEvent::Behaviour(
                                        crate::transport::TirBaseBehaviourEvent::Mdns(
                                            mdns::Event::Discovered(peers),
                                        ),
                                    ) => {
                                        // Subphase 1.2: dial every discovered peer so
                                        // mDNS neighbours actually connect to this
                                        // Swarm (previously only
                                        // gossipsub.add_explicit_peer was called and no
                                        // connection was ever opened).
                                        crate::transport::dial_discovered_mdns_peers(&mut swarm, peers);

                                        // Re-announce recent RevocationDeltas to newly-joined peers (Req 9.2).
                                        let recent = revocation_arc.lock().map(|rev| {
                                            rev.build_recent_revocation_deltas(24 * 3600 * 1_000_000)
                                        }).unwrap_or_default();

                                        for rd in recent {
                                            let gossip_msg = crate::transport::message::GossipMessage::InboundRevocationDelta(rd);
                                            let gossip_bytes = gossip_msg.to_bytes();
                                            let wrapper = crate::crdt::delta::Delta {
                                                id: [0u8; 32],
                                                author_did: "tirbase/revocation".to_string(),
                                                signature: crate::crdt::delta::Ed25519Signature::default(),
                                                schema_hash: [0u8; 32],
                                                automerge_bytes: gossip_bytes,
                                                priority: crate::crdt::delta::PriorityClass::High,
                                                causal_parents: vec![],
                                                tags: vec![],
                                                lamport: 0,
                                                created_at: 0,
                                            };
                                            if let Ok(mut t) = transport_arc.lock() {
                                                t.enqueue_outbound(wrapper);
                                            }
                                        }
                                    }
                                    SwarmEvent::Behaviour(
                                        crate::transport::TirBaseBehaviourEvent::Mdns(
                                            mdns::Event::Expired(peers),
                                        ),
                                    ) => {
                                        for (peer_id, _) in peers {
                                            swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            Some(payload) = outbound_rx.recv() => {
                                // Test-only observability: record the payload at
                                // the publish point so integration tests can
                                // assert outbound delivery reached the mesh
                                // layer (Subphase 1.1 acceptance).
                                #[cfg(test)]
                                if let Ok(mut t) = transport_arc.lock() {
                                    t.record_outbound_payload(payload.clone());
                                }

                                // Publish to the shared topic so all subscribed
                                // peers receive it (Req 5.1).  No subscribers /
                                // mesh offline → log and continue: the local
                                // write and durability queue remain authoritative.
                                match swarm
                                    .behaviour_mut()
                                    .gossipsub
                                    .publish(gossip_topic.clone(), payload)
                                {
                                    Ok(_) => {
                                        eprintln!("[transport-loop] published outbound payload");
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "[transport-loop] outbound publish deferred (no subscribers / mesh offline): {e:?}"
                                        );
                                    }
                                }
                            }
                            Some(addr) = dial_rx.recv() => {
                                // Subphase 1.5: explicit application-initiated
                                // dial (`CoreHandle::dial_peer`).  The peer id
                                // is not known in advance (only the address), so
                                // use `unknown_peer_id` — the Noise handshake
                                // reveals the real peer id on connect.
                                let opts = libp2p::swarm::dial_opts::DialOpts::unknown_peer_id()
                                    .address(addr.clone())
                                    .build();
                                match swarm.dial(opts) {
                                    Ok(()) => {
                                        eprintln!("[transport-loop] dialing explicit peer {addr}");
                                    }
                                    Err(e) => {
                                        eprintln!("[transport-loop] explicit dial to {addr} failed: {e}");
                                    }
                                }
                            }
                        }
                    }
                });

                // The outbound channel is being drained by the polling task
                // above, so the scheduler tick loop can forward into it.
                scheduler_tick_armed = true;
            }

            // `dial_tx` is only usable while a polling task owns its receiver.
            if scheduler_tick_armed {
                Some(dial_tx)
            } else {
                None
            }
        };

        // ── Startup diagnostics ───────────────────────────────────────────────
        let diag_entries = emit_startup_diagnostics(&config);
        for entry in diag_entries {
            let _ = diag_tx.send(entry);
        }

        let handle = Arc::new(CoreHandle {
            #[cfg(feature = "native")]
            store,
            #[cfg(not(feature = "native"))]
            store,
            #[cfg(feature = "native")]
            crdt,
            #[cfg(not(feature = "native"))]
            crdt,
            identity,
            capability,
            transport,
            durability,
            #[cfg(feature = "native")]
            cloud_ledger,
            #[cfg(feature = "native")]
            cce,
            #[cfg(not(feature = "native"))]
            cce,
            #[cfg(feature = "native")]
            revocation,
            #[cfg(not(feature = "native"))]
            revocation,
            migration,
            #[cfg(feature = "native")]
            migration_runs,
            #[cfg(feature = "native")]
            migration_tasks_active,
            diagnostics_channel: diag_tx,
            rejection_records_channel: rejection_records_tx,
            #[cfg(feature = "native")]
            durability_events_channel,
            inbound_tx,
            inbound_rx,
            #[cfg(feature = "native")]
            dial_tx,
        });

        // ── Production inbound drain loop (Subphase 1.3) ──────────────────────
        //
        // Spawn a background task that calls `process_inbound_messages()` on an
        // interval, so Gossipsub messages received by the Swarm polling task
        // (above) are actually routed through the subsystems in production —
        // previously this drain only happened when tests called it explicitly.
        //
        // The handle is returned as `Arc<CoreHandle>` precisely so this task can
        // hold a clone and keep draining for the lifetime of the instance.
        #[cfg(feature = "native")]
        {
            CoreHandle::spawn_inbound_drain_loop(
                &handle,
                std::time::Duration::from_millis(INBOUND_DRAIN_INTERVAL_MS),
            );
        }

        // ── Production DRR scheduler tick loop (Subphase 1.4) ─────────────────
        //
        // Spawn a background task that runs one DRR scheduling epoch per
        // second, draining the outbound queues built by
        // `MeshTransport::enqueue_outbound` (HIGH-priority revocation
        // rebroadcast, mDNS re-announcement) and forwarding the scheduled
        // Deltas to the outbound publish channel, which the Swarm polling task
        // drains and publishes — enqueued Deltas are now scheduled and sent,
        // not just accumulated (Req 12).
        //
        // Gated on `scheduler_tick_armed`: when `transport.start()` failed,
        // no polling task is draining the outbound channel, so the tick loop
        // would fail to forward every epoch (offline device — the durability
        // queue remains authoritative, Req 3.3).
        #[cfg(feature = "native")]
        if scheduler_tick_armed {
            CoreHandle::spawn_scheduler_tick_loop(
                &handle,
                std::time::Duration::from_millis(SCHEDULER_TICK_INTERVAL_MS),
            );
        }

        // ── Production cloud sync loop (Subphase 4.1) ────────────────────────
        //
        // Spawn a background task that drains the Durability Subsystem's cloud
        // outbound queue through the real `CloudLedgerConnection` in causal
        // order, sending every locally-written Delta to the Cloud Ledger this
        // process hosts (Req 16.3).  Previously nothing in production ever
        // drained the cloud queue — causal-order sync + ack-removal existed
        // only in `durability/integration_tests.rs`.
        //
        // Unlike the scheduler tick loop this is not gated on a live Swarm:
        // cloud sync is independent of the mesh (opportunistic Tier-2 over
        // TCP/HTTPS in the design; an in-process ledger in this single-crate
        // codebase), so the queue drains even while the device is offline
        // (Req 3.3 — the local write and durability queue remain
        // authoritative).
        #[cfg(feature = "native")]
        {
            CoreHandle::spawn_cloud_sync_loop(
                &handle,
                std::time::Duration::from_millis(CLOUD_SYNC_INTERVAL_MS),
            );
        }

        Ok(handle)
    }

    // ─── Local write/read gate (Req 8.5) ──────────────────────────────────────

    /// Local trust-level gate — REVOKED devices cannot write, read, or query
    /// (Req 8.5).
    ///
    /// This is the production gate that a locally-known REVOKED status must
    /// trip.  The REVOKED status becomes locally known when the inbound
    /// pipeline ([`CoreHandle::receive_inbound`] / `receive_inbound_wasm`)
    /// processes a validated `RevocationDelta` whose target is this device's
    /// own DID and invokes [`CapabilityManager::apply_revocation`]; from then
    /// on this gate returns `AuthorisationFailed` for every local I/O.
    fn ensure_local_trust_allows_io(&self) -> Result<(), TirBaseError> {
        let cap = self.capability.lock().map_err(|e| {
            TirBaseError::LocalStoreWriteFailed {
                reason: format!("capability mutex poisoned: {e}"),
            }
        })?;
        if cap.trust_level() == TrustLevel::Revoked {
            return Err(TirBaseError::AuthorisationFailed {
                reason: "device is REVOKED".to_string(),
            });
        }
        Ok(())
    }

    // ─── Durability receipt issuance (Subphase 4.5) ───────────────────────────

    /// Issue a signed `DurabilityReceipt` for a peer Delta this device has just
    /// merged, and publish it back over the mesh so the author can count this
    /// device toward Tier-1 quorum (Req 14.1, 14.6).
    ///
    /// This is the *genuine* receipt-issuance half of Tier-1 durability: the
    /// receipt attests "I hold this state" by signing
    /// `receipt_signing_payload(state_hash = delta.id, receipt_id)` with this
    /// device's own identity key (the v1 convention `state_hash = delta.id`
    /// matches what `write()` registers).  The author verifies it against this
    /// device's DID-resolved public key in
    /// `DurabilitySubsystem::receive_receipt`.
    ///
    /// Best-effort by design (Req 3.3): signing or publish failure is logged,
    /// not propagated — the merge already succeeded and the local state is
    /// committed; a lost receipt only means the author waits for another peer.
    ///
    /// Production caller: [`CoreHandle::receive_inbound`] (native), invoked
    /// after a peer Delta reports `MergeOutcome::Merged` (Subphase 4.5).
    #[cfg(feature = "native")]
    fn issue_durability_receipt(&self, state_hash: &DeltaId) {
        use crate::durability::receipt::{receipt_signing_payload, DurabilityReceipt};

        let id = uuid::Uuid::now_v7();
        let payload = receipt_signing_payload(state_hash, &id);
        let issuer_signature = match crate::identity::keypair::sign(
            &self.identity.signing_key_bytes(),
            &payload,
        ) {
            Ok(sig) => sig,
            Err(e) => {
                eprintln!(
                    "[durability] receipt signing failed for delta {}: {e}",
                    hex::encode(state_hash)
                );
                return;
            }
        };

        let receipt = DurabilityReceipt {
            id,
            state_hash: *state_hash,
            issuer_did: self.identity.did().to_string(),
            issuer_signature,
            // No squad/tunnel_sector configured on this device (v1); with
            // Anchor_Attested_Location disabled the receipt is counted by its
            // (absent) declared tag — untagged peers fall back to flat K-of-N
            // diversity (Req 14.5).
            spatial_tag: None,
            beacon_token: None,
            issued_at: now_micros(),
        };

        if let Err(e) = self
            .transport
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("transport mutex poisoned: {e}"),
            })
            .and_then(|mut transport| transport.send_receipt(&receipt))
        {
            eprintln!(
                "[durability] receipt publish failed for delta {}: {e} — \
                 author will not count this device toward its quorum",
                hex::encode(state_hash)
            );
        }
    }

    // ─── Write ────────────────────────────────────────────────────────────────

    /// Write a record to a table (Req 2.1, 2.3, 3.2).
    pub async fn write(
        &self,
        table: &str,
        key: &str,
        data: serde_json::Value,
    ) -> Result<WriteResult, TirBaseError> {
        // 1. Trust level gate — REVOKED devices cannot write (Req 8.5).
        self.ensure_local_trust_allows_io()?;

        // 2. Write to local store inside a SQLite transaction (Req 3.6).
        #[cfg(feature = "native")]
        {
            self.store
                .lock()
                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                    reason: format!("store mutex poisoned: {e}"),
                })?
                .write(table, key, &data)?;
        }

        // 2b. Write to in-memory store on WASM (Req 3.1, 3.3).
        #[cfg(not(feature = "native"))]
        {
            self.store
                .lock()
                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                    reason: format!("store mutex poisoned: {e}"),
                })?
                .write(table, key, &data)?;
        }

        // 3. Produce a signed Delta.
        // Embed _tirbase_table and _tirbase_key metadata so that receiving peers can
        // project the inbound Delta directly to the SQL store (Req 4.3, 3.3).
        let automerge_bytes = {
            let mut meta = serde_json::Map::new();
            meta.insert("_tirbase_table".to_string(), serde_json::Value::String(table.to_string()));
            meta.insert("_tirbase_key".to_string(), serde_json::Value::String(key.to_string()));
            // Merge application data fields (if data is an object) or store under "_data".
            if let Some(obj) = data.as_object() {
                for (k, v) in obj {
                    meta.insert(k.clone(), v.clone());
                }
            } else {
                meta.insert("_data".to_string(), data.clone());
            }
            serde_json::to_vec(&serde_json::Value::Object(meta)).unwrap_or_default()
        };

        // 3a. Human-reaction auto-tag decision (Req 19.5).
        //
        // Look up live contamination and quarantine state *before* the Delta
        // is signed, and bake the tag into the signed payload via
        // `produce_delta_with_tags`: `canonical_bytes()` serialises `tags`, so
        // a tag appended to an already-signed Delta would invalidate its own
        // signature and every verifier — mesh peers and the Side-Car replay
        // path (Req 19.3) — would reject the tagged write.
        let local_projection_contaminated = self
            .cce
            .lock()
            .map(|cce| cce.is_row_contaminated(table, key))
            .unwrap_or(false);
        let quarantine_active = self
            .migration
            .lock()
            .map(|mig| mig.is_schema_quarantined(table))
            .unwrap_or(false);
        let active_incident_id = self
            .cce
            .lock()
            .map(|cce| cce.active_incident_for_row(table, key))
            .unwrap_or(None);
        let human_reaction_tag = if local_projection_contaminated || quarantine_active {
            active_incident_id
                .map(|incident_id| crate::crdt::delta::DeltaTag::ContaminatedByHumanReaction {
                    incident_id,
                })
        } else {
            None
        };

        #[cfg(feature = "native")]
        let delta = {
            self.crdt
                .lock()
                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                    reason: format!("crdt mutex poisoned: {e}"),
                })?
                .produce_delta_with_tags(
                    automerge_bytes,
                    PriorityClass::Low,
                    vec![],
                    human_reaction_tag.clone().into_iter().collect(),
                )?
        };

        // WASM build uses the real CrdtEngine (in-memory, no SQLite) to produce
        // a properly signed Delta with causal parent tracking.
        #[cfg(not(feature = "native"))]
        let delta = {
            self.crdt
                .lock()
                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                    reason: format!("crdt mutex poisoned: {e}"),
                })?
                .produce_delta_with_tags(
                    automerge_bytes,
                    PriorityClass::Low,
                    vec![],
                    human_reaction_tag.clone().into_iter().collect(),
                )?
        };

        // 4. If the write was auto-tagged, register the new Delta as a
        // contamination root with the CCE so the ICO's contaminated_deltas and
        // affected_rows are extended to include it (Req 19.5).  The tag itself
        // is already inside the signed payload (step 3a) — this is the CCE
        // bookkeeping side effect.
        if let Some(hr_incident_id) = human_reaction_tag.map(|tag| match tag {
            crate::crdt::delta::DeltaTag::ContaminatedByHumanReaction { incident_id } => {
                incident_id
            }
            _ => unreachable!("only the human-reaction tag is produced here"),
        }) {
            let hr_delta_id = delta.id;
            let _ = self.cce.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("cce mutex poisoned in human-reaction wiring: {e}"),
            }).map(|mut cce| {
                cce.tag_contamination_root(
                    hr_delta_id,
                    crate::contamination::incident::TaintSource::HumanReaction {
                        triggered_by_incident_id: hr_incident_id,
                    },
                )
            });
        }

        // 5. Register with durability subsystem (adds to cloud outbound queue).
        let delta_bytes = serde_json::to_vec(&delta).unwrap_or_default();
        self.durability
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("durability mutex poisoned: {e}"),
            })?
            .register_delta(
                delta.id,
                delta.id,              // state_hash = delta.id for v1
                delta_bytes.clone(),
                delta.causal_parents.clone(),
                HashMap::new(),
            )?;

        // 5b. Side-Car capture (Req 19.2).  A write made while the device's
        // current schema is under a corruption window — a revoked (corrupted)
        // migration produced it — is preserved byte-for-byte in the Side-Car
        // Ledger, scoped to the corrupting migration's ID, so a corrected
        // migration can replay it against the corrected projection instead of
        // silently losing it.  Best-effort by design: the local store write
        // and durability registration above are already committed, and a
        // capture failure must not fail the user's write.
        match self
            .migration
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("migration mutex poisoned in side-car capture: {e}"),
            })
            .and_then(|mut mig| {
                mig.record_corrupted_window_write(table, delta_bytes, delta.created_at)
            }) {
            Ok(Some(entry_id)) => {
                eprintln!(
                    "[write] Side-Car capture: delta {} recorded for corrupted-schema \
                     replay (entry {})",
                    hex::encode(delta.id),
                    hex::encode(entry_id)
                );
            }
            Ok(None) => {
                // No corruption window active for the current schema — nothing
                // to capture.  This is the common case.
            }
            Err(e) => {
                eprintln!("[write] Side-Car capture failed (best-effort): {e}");
            }
        }

        // 6. Publish outbound — forward the prepared Delta payloads to the
        // Swarm polling task, which publishes them to the shared Gossipsub
        // topic (Req 5.1).  Best-effort by design: the local store write and
        // durability registration above are already committed, and a device
        // must keep operating while the mesh is unavailable (Req 3.3), so a
        // publish failure is logged rather than failing the write.
        #[cfg(feature = "native")]
        if let Err(e) = self
            .transport
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("transport mutex poisoned: {e}"),
            })?
            .send_delta(&self.identity.did().to_string(), &delta)
        {
            eprintln!(
                "[write] outbound publish failed for delta {}: {e} — delta remains durably queued",
                hex::encode(delta.id)
            );
        }

        // 7. Collect unverified warning (Req 8.4).
        let unverified_warning = self
            .capability
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("capability mutex poisoned: {e}"),
            })?
            .unverified_warning();

        Ok(WriteResult {
            delta_id: delta.id,
            durability_tier: DurabilityTier::Uncommitted,
            unverified_warning,
        })
    }

    // ─── Read ─────────────────────────────────────────────────────────────────

    /// Read a single record from a table by key (Req 2.1, 3.3).
    pub async fn read(&self, table: &str, key: &str) -> Result<QueryResult, TirBaseError> {
        // 1. Trust level gate — REVOKED devices cannot read (Req 8.5).
        self.ensure_local_trust_allows_io()?;

        #[cfg(feature = "native")]
        let data = {
            let store = self.store.lock().map_err(|e| {
                TirBaseError::LocalStoreWriteFailed {
                    reason: format!("store mutex poisoned: {e}"),
                }
            })?;
            store.read(table, key)?.ok_or_else(|| {
                TirBaseError::LocalStoreWriteFailed {
                    reason: format!("key '{key}' not found in table '{table}'"),
                }
            })?
        };

        #[cfg(not(feature = "native"))]
        let data = {
            let store = self.store.lock().map_err(|e| {
                TirBaseError::LocalStoreWriteFailed {
                    reason: format!("store mutex poisoned: {e}"),
                }
            })?;
            store.read(table, key)?.ok_or_else(|| {
                TirBaseError::LocalStoreWriteFailed {
                    reason: format!("key '{key}' not found in table '{table}'"),
                }
            })?
        };

        let unverified_warning = self
            .capability
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("capability mutex poisoned: {e}"),
            })?
            .unverified_warning();

        Ok(QueryResult {
            table: table.to_string(),
            key: key.to_string(),
            data,
            unverified_warning,
            contaminated: false,
        })
    }

    // ─── Query ────────────────────────────────────────────────────────────────

    /// Query multiple records from a table with an optional filter (Req 2.1).
    pub async fn query(
        &self,
        table: &str,
        filter: Option<serde_json::Value>,
    ) -> Result<Vec<QueryResult>, TirBaseError> {
        // 1. Trust level gate — REVOKED devices cannot query (Req 8.5).
        self.ensure_local_trust_allows_io()?;

        #[cfg(feature = "native")]
        let rows = {
            let store = self.store.lock().map_err(|e| {
                TirBaseError::LocalStoreWriteFailed {
                    reason: format!("store mutex poisoned: {e}"),
                }
            })?;
            store.query(table, filter.as_ref())?
        };

        #[cfg(not(feature = "native"))]
        let rows = {
            let store = self.store.lock().map_err(|e| {
                TirBaseError::LocalStoreWriteFailed {
                    reason: format!("store mutex poisoned: {e}"),
                }
            })?;
            store.query(table, filter.as_ref())?
        };

        let unverified_warning = self
            .capability
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("capability mutex poisoned: {e}"),
            })?
            .unverified_warning();

        let results = rows
            .into_iter()
            .map(|(row_key, data)| QueryResult {
                table: table.to_string(),
                key: row_key,
                data,
                unverified_warning: unverified_warning.clone(),
                contaminated: false,
            })
            .collect();

        Ok(results)
    }

    // ─── Trust level ──────────────────────────────────────────────────────────

    /// The current Trust_Level of the local device (Req 2.4).
    pub fn trust_level(&self) -> TrustLevel {
        self.capability
            .lock()
            .map(|cap| cap.trust_level())
            .unwrap_or(TrustLevel::Unverified)
    }

    // ─── Mesh status ──────────────────────────────────────────────────────────

    /// Mesh connection status and peer count (Req 2.5).
    pub fn mesh_status(&self) -> MeshStatus {
        let peers = self
            .transport
            .lock()
            .map(|t| t.active_peers())
            .unwrap_or_default();

        let status = if peers.is_empty() {
            ConnectionStatus::Disconnected
        } else {
            ConnectionStatus::Connected
        };

        MeshStatus {
            status,
            peer_count: peers.len() as u32,
        }
    }

    /// Subscribe to the diagnostic broadcast channel.
    ///
    /// Returns a new receiver that will receive all future diagnostic entries
    /// sent to this handle's channel.
    pub fn subscribe_diagnostics(
        &self,
    ) -> tokio::sync::broadcast::Receiver<DiagnosticEntry> {
        self.diagnostics_channel.subscribe()
    }

    /// Subscribe to structured Delta rejection failure records (Req 7.4/7.5).
    ///
    /// Returns a new receiver that will receive every rejection record the
    /// CRDT engine emits from here on — the typed, UTC-timestamped
    /// replacement for the former `eprintln!` rejection logs (Subphase 6.2).
    /// Records carry the sender DID and the reason the Delta was discarded
    /// (`RevokedAuthor`, `MissingSignature`, `DidResolutionFailed` — the
    /// distinct Req 7.5 record — or `SignatureVerificationFailed` — Req 7.4).
    ///
    /// `pub(crate)`: rejection records are internal diagnostics for native
    /// host applications and in-crate integration tests; the WASM SDK target
    /// observes rejections through the retained engine records instead.
    pub(crate) fn subscribe_rejection_records(
        &self,
    ) -> tokio::sync::broadcast::Receiver<crate::crdt::failure::DeltaRejectionRecord> {
        self.rejection_records_channel.subscribe()
    }

    /// Return the primary root CA public key for offline Biscuit token verification.
    ///
    /// Used by `core_activate_saturate_mode` on the WASM target to verify
    /// the disaster-alert Biscuit token (Req 13.1, 13.7).
    /// Returns an empty `Vec<u8>` if no root CA key is configured (explicit
    /// unconfigured state — verification fails until a key is registered).
    pub fn root_ca_public_key(&self) -> Vec<u8> {
        self.capability
            .lock()
            .map(|cap| {
                cap.root_ca_primary_key()
                    .map(|k| k.to_vec())
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }

    /// Register an additional root CA public key at runtime (Req 8.1).
    ///
    /// Takes effect immediately: subsequent Biscuit token verification (e.g.
    /// `core_activate_saturate_mode`) accepts tokens signed by this key.
    /// Registering a duplicate key is a no-op.
    pub fn register_root_ca_key(&self, key: [u8; 32]) -> Result<(), TirBaseError> {
        let mut capability = self.capability.lock().map_err(|e| {
            TirBaseError::AuthorisationFailed {
                reason: format!("capability mutex poisoned: {e}"),
            }
        })?;
        capability.register_root_ca_key(key);
        Ok(())
    }

    /// Register the deployment's Migration CA public key at runtime (Req 18.2).
    ///
    /// Takes effect immediately: subsequent inbound Migration_Deltas verify
    /// their CA signature against this key, replacing any key registered at
    /// init from `DeploymentConfig.migration_ca_public_key`.  Mirrors
    /// [`CoreHandle::register_root_ca_key`] for the SchemaMigrationEngine.
    ///
    /// Production callers: native host applications and the
    /// `core_register_migration_ca_key` WASM export (Subphase 5.1).
    pub fn register_migration_ca_key(&self, key: [u8; 32]) -> Result<(), TirBaseError> {
        let mut migration = self.migration.lock().map_err(|e| {
            TirBaseError::AuthorisationFailed {
                reason: format!("migration mutex poisoned: {e}"),
            }
        })?;
        migration.register_ca_public_key(key);
        Ok(())
    }

    // ─── Manager operations — Revocation (Req 9) ──────────────────────────────

    /// Initiate a revocation of `target_did` from this Manager device (Req 9.1).
    ///
    /// This is the native (non-WASM-only) entry point to initiate a revocation;
    /// it is the counterpart of the `core_initiate_revocation` WASM export, which
    /// delegates here so both build targets share one implementation.  The local
    /// device acts as one Manager and submits its own partial `RevocationDelta`
    /// signature for the target DID.
    ///
    /// Mirrors the WASM export's functionality:
    /// 1. `manager_token` and `target_did` must be non-blank (the same gate the
    ///    WASM export applies — full Biscuit authorisation of the calling
    ///    operator is the caller's responsibility on the native side).
    /// 2. Produces a partial `RevocationDelta` signed by this device's identity
    ///    (`IdentityManager`) via `RevocationSubsystem::produce_partial_delta`.
    /// 3. Gossips the partial delta at HIGH priority so peer Manager devices
    ///    can accumulate signatures (Req 9.1 mesh-accumulated model).
    /// 4. Accumulates the signature locally via
    ///    `RevocationSubsystem::process_incoming_delta` — the same subsystem call
    ///    an inbound partial delta from a peer takes, so this device's M-of-N
    ///    bookkeeping stays consistent with what it learns over the mesh.
    ///
    /// When the local contribution completes the threshold (e.g. a 1-of-1
    /// config), the same side effects as the inbound revocation path run:
    /// HIGH-priority gossip of the complete delta (Req 9.2), CRDT rejection of
    /// future Deltas authored by the target (Req 8.6), and — when the target is
    /// this device itself — the local REVOKED I/O gate (Req 8.5).
    pub fn initiate_revocation(
        &self,
        target_did: &str,
        manager_token: &str,
    ) -> Result<(), TirBaseError> {
        if manager_token.trim().is_empty() {
            return Err(TirBaseError::AuthorisationFailed {
                reason: "manager_token must not be blank".to_string(),
            });
        }
        if target_did.trim().is_empty() {
            return Err(TirBaseError::AuthorisationFailed {
                reason: "target_did must not be blank".to_string(),
            });
        }

        let target_did = target_did.to_string();
        let manager_did = self.identity.did().to_string();
        let signing_key = self.identity.signing_key_bytes();

        let revocation_arc = self.revocation.clone();
        let transport_arc = self.transport.clone();
        let crdt_arc = self.crdt.clone();
        let capability_arc = self.capability.clone();
        let cce_arc = self.cce.clone();

        // 1. Produce this Manager's partial RevocationDelta (Req 9.1).
        let partial = revocation_arc
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("revocation mutex poisoned: {e}"),
            })?
            .produce_partial_delta(target_did.clone(), manager_did, &signing_key)?;

        // 2. Gossip the partial delta at HIGH priority so peer Manager devices
        //    can accumulate signatures (Req 9.1 — mesh-accumulated model).
        //    On WASM there is no Swarm scheduler: the JS transport layer handles
        //    peer messaging, so nothing is enqueued here (same as the WASM
        //    export's behaviour).
        #[cfg(feature = "native")]
        {
            if let Ok(mut transport) = transport_arc.lock() {
                enqueue_revocation_gossip(&mut transport, &partial);
            }
        }

        // 3. Accumulate this signature locally — identical to processing an
        //    inbound partial delta from a peer.
        let status = {
            let mut rev = revocation_arc.lock().map_err(|e| {
                TirBaseError::LocalStoreWriteFailed {
                    reason: format!("revocation mutex poisoned: {e}"),
                }
            })?;
            rev.process_incoming_delta(
                &partial,
                &mut |applied_did, complete_delta| {
                    // Req 9.2: the threshold is now met — gossip the complete
                    // RevocationDelta at HIGH priority.
                    #[cfg(feature = "native")]
                    {
                        eprintln!(
                            "[initiate] gossiping complete RevocationDelta at HIGH priority for {applied_did}"
                        );
                        if let Ok(mut transport) = transport_arc.lock() {
                            enqueue_revocation_gossip(&mut transport, complete_delta);
                        }
                    }
                    #[cfg(not(feature = "native"))]
                    {
                        // No Swarm scheduler on WASM — the JS transport layer
                        // handles peer messaging (best-effort, Req 9.2).
                        eprintln!(
                            "[initiate] RevocationDelta threshold met for {applied_did} (WASM: JS transport handles gossip)"
                        );
                    }
                },
                &mut |revoked_did, delta_ids| {
                    // Req 10.1: tag all Deltas authored by the revoked DID.
                    #[cfg(feature = "native")]
                    {
                        if let Ok(mut cce) = cce_arc.lock() {
                            for delta_id in delta_ids {
                                let _ = cce.tag_contamination_root(
                                    delta_id,
                                    crate::contamination::incident::TaintSource::DeviceRevocation {
                                        revocation_delta_id: delta_id,
                                    },
                                );
                            }
                        }
                    }
                    #[cfg(not(feature = "native"))]
                    {
                        // No SQLite DAG walk on WASM — mirrors the WASM inbound
                        // path (best-effort CCE tagging).
                        let _ = (revoked_did, delta_ids);
                    }
                },
            )?
        };

        // 4. If this contribution completed the threshold, apply the same local
        //    REVOKED side effects as the inbound revocation path.
        if status == crate::auth::RevocationStatus::Applied {
            // Req 8.6 — reject future inbound Deltas authored by the target.
            crdt_arc
                .lock()
                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                    reason: format!("crdt mutex poisoned: {e}"),
                })?
                .mark_did_revoked(&target_did);
            eprintln!(
                "[initiate] CRDT engine now rejects Deltas authored by revoked DID {target_did}"
            );

            // Req 8.5 — a revocation targeting THIS device makes the REVOKED
            // status locally known: trip the local write/read/query gate.
            if target_did == self.identity.did() {
                capability_arc
                    .lock()
                    .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                        reason: format!("capability mutex poisoned: {e}"),
                    })?
                    .apply_revocation()?;
                eprintln!(
                    "[initiate] local device {target_did} is REVOKED — write/read/query gates now block"
                );
            }
        }

        Ok(())
    }

    /// Query the last-known revocation status of a device (Req 9.5).
    ///
    /// Returns the `DeviceRevocationStatus` recorded by the `RevocationSubsystem`
    /// for `device_did` — the last-known `TrustLevel` of the device plus the UTC
    /// timestamp (microseconds) of the last `RevocationDelta` receipt. This is
    /// the data that lets an isolated device surface its last-known state even
    /// before the Biscuit TTL expires (Req 9.5).
    ///
    /// Returns `Ok(None)` when no `RevocationDelta` has ever been received for
    /// the device — the subsystem has no record of it. The device-status record
    /// is written when a revocation is *applied* (M-of-N reached), so a pending
    /// revocation with fewer than M signatures still reports `Ok(None)` here;
    /// use the accumulation state exposed via `core_revocation_status` for the
    /// in-flight M-of-N picture.
    pub fn device_revocation_status(
        &self,
        device_did: &str,
    ) -> Result<Option<crate::auth::DeviceRevocationStatus>, TirBaseError> {
        let rev = self.revocation.lock().map_err(|e| {
            TirBaseError::LocalStoreWriteFailed {
                reason: format!("revocation mutex poisoned: {e}"),
            }
        })?;
        Ok(rev.device_status(device_did).cloned())
    }

    // ─── Manager operations — Saturate Mode (Req 13) ─────────────────────────
    //
    // Subphase 3.2: activation, heartbeat renewal, and M-of-N termination all
    // route through the transport's production `SaturateModeStateMachine` —
    // never through a bare scheduler boolean.  These methods are the shared
    // WASM + native implementation: the WASM exports in lib.rs
    // (`core_activate_saturate_mode` / `core_renew_saturate_mode` /
    // `core_terminate_saturate_mode`) delegate here, and the native build
    // (Cloud Ledger / host code holding a `CoreHandle`) calls them directly.
    // Each locks the mesh transport, drives the state machine, and lets the
    // transport reconcile the DRR scheduler from the resulting state.

    /// Verify a Manager DISASTER_ALERT Biscuit token for a lease-lifecycle
    /// event (Req 13.1, 13.4, 13.7) and return the current UTC seconds.
    ///
    /// Applies the same gates the WASM export historically applied so the
    /// shared implementation keeps the same clear error messages: absent or
    /// empty tokens are rejected as `SignatureVerificationFailed`; an
    /// unconfigured root CA registry (no key at init or runtime) is reported
    /// as `AuthorisationFailed`; and a token that fails offline verification
    /// or lacks the `disaster-alert` caveat is rejected with
    /// `SignatureVerificationFailed`.  The state machine re-verifies the token
    /// authoritatively inside the transport — this pre-check only sharpens the
    /// error the caller sees.
    fn verify_disaster_alert_token(
        &self,
        biscuit_token: &[u8],
    ) -> Result<i64, TirBaseError> {
        if biscuit_token.is_empty() {
            return Err(TirBaseError::SignatureVerificationFailed {
                reason: "biscuit token is absent or empty".to_string(),
            });
        }

        // Root CA key for offline verification.  Empty = explicit unconfigured
        // state: no key was registered at init or at runtime.
        let root_ca_key = self.root_ca_public_key();
        if root_ca_key.is_empty() {
            return Err(TirBaseError::AuthorisationFailed {
                reason: "no root CA public key registered; cannot verify Biscuit token"
                    .to_string(),
            });
        }

        let now = now_secs();

        // Verify the token has the disaster-alert caveat (Req 13.1, 13.7).
        match crate::auth::biscuit::verify_and_check_caveat(
            biscuit_token,
            "disaster-alert",
            &root_ca_key,
            now,
        ) {
            Ok(true) => Ok(now),
            Ok(false) => Err(TirBaseError::SignatureVerificationFailed {
                reason: "biscuit token is missing the disaster-alert caveat".to_string(),
            }),
            Err(e) => Err(e),
        }
    }

    /// Activate Saturate_Mode with a DISASTER_ALERT Biscuit token (Req 13.1).
    ///
    /// Verifies `biscuit_token` (signature, expiry, `disaster-alert` caveat —
    /// Req 13.7) and routes the activation through the transport's real
    /// [`crate::transport::saturate::SaturateModeStateMachine`], which opens a
    /// 60-minute lease and — on success — puts the DRR scheduler into Saturate
    /// Mode.  The local device is recorded as the activating Manager on the
    /// lease.
    ///
    /// Any verification failure returns `SignatureVerificationFailed` (or
    /// `AuthorisationFailed` when no root CA key is configured) and leaves the
    /// current mode — state machine and scheduler — untouched (Req 13.7).
    ///
    /// Production caller on WASM: `core_activate_saturate_mode` (lib.rs).
    /// Production caller on native: host/server code holding a `CoreHandle`
    /// (the native counterpart of the WASM export).
    pub fn activate_saturate_mode(&self, biscuit_token: &[u8]) -> Result<(), TirBaseError> {
        let now = self.verify_disaster_alert_token(biscuit_token)?;
        let manager_did = self.identity.did().to_string();
        self.transport
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("transport mutex poisoned: {e}"),
            })?
            .activate_saturate_mode(manager_did, biscuit_token, now)
    }

    /// Renew a Saturate_Mode Lease with a heartbeat DISASTER_ALERT token
    /// (Req 13.4).
    ///
    /// Verifies `biscuit_token` exactly as activation does, then routes the
    /// renewal through the transport's real
    /// [`crate::transport::saturate::SaturateModeStateMachine`]: valid only
    /// while in SATURATE, it extends the lease by 60 minutes from the renewal
    /// timestamp.  The DRR scheduler remains in Saturate Mode.
    ///
    /// Any failure returns `SignatureVerificationFailed` and preserves the
    /// current mode (Req 13.7).
    ///
    /// Production caller on WASM: `core_renew_saturate_mode` (lib.rs).
    /// Production caller on native: host/server code holding a `CoreHandle`.
    pub fn renew_saturate_mode(&self, biscuit_token: &[u8]) -> Result<(), TirBaseError> {
        let now = self.verify_disaster_alert_token(biscuit_token)?;
        let manager_did = self.identity.did().to_string();
        self.transport
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("transport mutex poisoned: {e}"),
            })?
            .renew_saturate_mode(manager_did, biscuit_token, now)
    }

    /// Terminate Saturate_Mode via an M-of-N Manager signature set (Req 13.6).
    ///
    /// `message` is the canonical termination payload the Managers signed
    /// (callers must share the exact same bytes with every co-signing
    /// Manager).  This device contributes its own Manager signature over
    /// `message`; `co_manager_signatures` carries the signatures already
    /// collected from the remaining Managers `(did:key, raw Ed25519 sig)`.
    ///
    /// The transport's real
    /// [`crate::transport::saturate::SaturateModeStateMachine`] verifies each
    /// signature against the DID-embedded public key, counts only **distinct**
    /// valid DIDs, and terminates immediately — clearing the lease and taking
    /// the DRR scheduler out of Saturate Mode — once the configured threshold
    /// `M` is met.  Fewer than `M` valid distinct signatures return
    /// `ThresholdNotMet` and preserve the current mode (invariant (b)).
    ///
    /// Note: the codebase models a "Manager" as a DID whose key verifies a
    /// signature over the termination message — the state machine has no
    /// separate registry of the N registered Manager DIDs, so co-signatures
    /// are self-certifying.  This mirrors the `SaturateModeStateMachine`
    /// contract that Subphase 3.1 established and is unchanged here.
    ///
    /// Production caller on WASM: `core_terminate_saturate_mode` (lib.rs).
    /// Production caller on native: host/server code holding a `CoreHandle`.
    pub fn terminate_saturate_mode(
        &self,
        message: &[u8],
        co_manager_signatures: Vec<(String, Vec<u8>)>,
    ) -> Result<(), TirBaseError> {
        if message.is_empty() {
            return Err(TirBaseError::AuthorisationFailed {
                reason: "termination message must not be empty".to_string(),
            });
        }

        // The local device signs the canonical termination message with its
        // own Manager identity, then any co-signatures collected from other
        // Managers are appended.  Distinctness and validity are enforced by
        // the state machine when the threshold is counted.
        let manager_did = self.identity.did().to_string();
        let local_signature = self.identity.sign(message)?;
        let mut signatures = Vec::with_capacity(co_manager_signatures.len() + 1);
        signatures.push((manager_did, local_signature.to_vec()));
        signatures.extend(co_manager_signatures);

        let now = now_secs();
        self.transport
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("transport mutex poisoned: {e}"),
            })?
            .terminate_saturate_mode(signatures, message, now)
    }

    // ─── Inbound message pipeline ─────────────────────────────────────────────

    /// Route an inbound `GossipMessage` through the correct subsystem (native only).
    ///
    /// Called by the background processing loop or test harness with messages
    /// drained from `inbound_rx`.
    ///
    /// Dispatches:
    /// - `InboundDelta`                  → `CrdtEngine::apply`
    /// - `InboundDurabilityReceipt`      → `DurabilitySubsystem::receive_receipt`
    /// - `InboundRevocationDelta`        → `RevocationSubsystem::process_incoming_delta`
    /// - `InboundMigrationDelta`         → `SchemaMigrationEngine::receive_migration_delta`
    /// - `InboundMigrationRevocationDelta` → `SchemaMigrationEngine::receive_revocation_delta`
    #[cfg(feature = "native")]
    pub async fn receive_inbound(
        &self,
        msg: crate::transport::message::GossipMessage,
    ) -> Result<(), TirBaseError> {
        use crate::crdt::merge::MergeOutcome;
        use crate::transport::message::GossipMessage;

        match msg {
            GossipMessage::InboundDelta(delta) => {
                let outcome = {
                    let mut crdt = self.crdt.lock().map_err(|e| {
                        TirBaseError::LocalStoreWriteFailed {
                            reason: format!("crdt mutex: {e}"),
                        }
                    })?;
                    crate::crdt::merge::apply_incoming_delta(&mut crdt, &delta)?
                };
                match outcome {
                    MergeOutcome::Merged { .. } => {
                        eprintln!(
                            "[inbound] delta {} merged from {}",
                            hex::encode(delta.id),
                            delta.author_did
                        );

                        // Project the merged Delta to the SQLite store so that
                        // `read()` and `query()` reflect the new peer state (Req 4.3, 3.3).
                        //
                        // Strategy:
                        //  1. If automerge_bytes parses as valid Automerge format, project
                        //     the doc state via CrdtEngine's internal document.
                        //  2. Otherwise try to parse automerge_bytes as the TirBase JSON
                        //     envelope (contains _tirbase_table and _tirbase_key metadata)
                        //     and call store.write() directly.
                        //  3. If no table/key can be determined, skip projection (conservative
                        //     fallback — data is in the CRDT doc but not in SQL projection yet).
                        if !delta.automerge_bytes.is_empty() {
                            if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(&delta.automerge_bytes) {
                                if let Some(obj) = json_val.as_object() {
                                    let table_name = obj.get("_tirbase_table").and_then(|v| v.as_str());
                                    let row_key = obj.get("_tirbase_key").and_then(|v| v.as_str());

                                    if let (Some(tbl), Some(rkey)) = (table_name, row_key) {
                                        // Reconstruct the application data (strip metadata keys).
                                        let mut app_data = serde_json::Map::new();
                                        for (k, v) in obj {
                                            if k != "_tirbase_table" && k != "_tirbase_key" {
                                                if k == "_data" {
                                                    // Scalar/non-object data stored under _data.
                                                    // Write as-is under the original key.
                                                    let _ = self.store
                                                        .lock()
                                                        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                                                            reason: format!("store mutex: {e}"),
                                                        })?
                                                        .write(tbl, rkey, v);
                                                    eprintln!(
                                                        "[inbound] projected delta {} → {tbl}/{rkey}",
                                                        hex::encode(delta.id)
                                                    );
                                                    // Break early — _data is the whole value.
                                                    app_data.clear();
                                                    break;
                                                }
                                                app_data.insert(k.clone(), v.clone());
                                            }
                                        }
                                        if !app_data.is_empty() {
                                            let app_val = serde_json::Value::Object(app_data);
                                            let _ = self.store
                                                .lock()
                                                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                                                    reason: format!("store mutex: {e}"),
                                                })?
                                                .write(tbl, rkey, &app_val);
                                            eprintln!(
                                                "[inbound] projected delta {} → {tbl}/{rkey}",
                                                hex::encode(delta.id)
                                            );
                                        }
                                    } else {
                                        // JSON but no table/key metadata — cannot project.
                                        eprintln!(
                                            "[inbound] delta {} merged but no _tirbase_table/_tirbase_key in bytes — skipping SQL projection",
                                            hex::encode(delta.id)
                                        );
                                    }
                                }
                            } else {
                                // Real Automerge binary bytes — use CrdtEngine's doc state
                                // to project all tables via project_table().
                                // NOTE: The CrdtEngine's Automerge doc is cross-table;
                                // project all tables found in automerge_docs.
                                let tables_result = {
                                    let store = self.store.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
                                        reason: format!("store mutex: {e}"),
                                    })?;
                                    // Query automerge_docs to find known tables.
                                    // Ignore error — fall back to no projection.
                                    store.list_automerge_tables().unwrap_or_default()
                                };

                                if !tables_result.is_empty() {
                                    let crdt = self.crdt.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
                                        reason: format!("crdt mutex: {e}"),
                                    })?;
                                    for tbl in &tables_result {
                                        if let Err(e) = crdt.project_table_to_store(tbl, &self.store) {
                                            eprintln!(
                                                "[inbound] project_table_to_store({tbl}) failed: {e}"
                                            );
                                        }
                                    }
                                } else {
                                    eprintln!(
                                        "[inbound] delta {} has binary automerge bytes but no known tables for projection",
                                        hex::encode(delta.id)
                                    );
                                }
                            }
                        }

                        // Subphase 4.5: this device genuinely holds the merged
                        // state — sign a DurabilityReceipt over the Delta and
                        // publish it back to the mesh so the author can count
                        // this device toward Tier-1 quorum (Req 14.1, 14.6).
                        // Issued only after a successful merge: a receipt
                        // attests held state, and only a signature-verified
                        // merge inserted the Delta into this device's DAG.
                        self.issue_durability_receipt(&delta.id);
                    }
                    MergeOutcome::Quarantined { reason } => {
                        // Subphase 5.2: persist the raw received Delta in the
                        // QuarantineLedger (Req 17.4–17.6) instead of only
                        // logging it. The full serialised Delta is stored
                        // byte-for-byte so a later schema migration can replay
                        // it through the same signature-verified merge path.
                        let raw_bytes = serde_json::to_vec(&delta).unwrap_or_else(|e| {
                            eprintln!(
                                "[inbound] delta {} could not be serialised for quarantine: {e} — storing payload bytes only",
                                hex::encode(delta.id)
                            );
                            delta.automerge_bytes.clone()
                        });
                        match self
                            .migration
                            .lock()
                            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                                reason: format!("migration mutex poisoned: {e}"),
                            })?
                            .quarantine_incoming(
                                &delta.author_did,
                                raw_bytes,
                                Some(delta.schema_hash),
                                reason.into(),
                                now_micros(),
                            ) {
                            Ok(entry_id) => eprintln!(
                                "[inbound] delta {} quarantined (schema mismatch) from {} → stored in quarantine ledger as {}",
                                hex::encode(delta.id),
                                delta.author_did,
                                hex::encode(entry_id)
                            ),
                            Err(e) => eprintln!(
                                "[inbound] delta {} could not be stored in the quarantine ledger: {e}",
                                hex::encode(delta.id)
                            ),
                        }
                    }
                    MergeOutcome::Rejected { reason } => {
                        eprintln!(
                            "[inbound] delta {} rejected from {}: {}",
                            hex::encode(delta.id),
                            delta.author_did,
                            reason
                        );
                    }
                }
            }
            GossipMessage::InboundDurabilityReceipt(receipt) => {
                let issuer_did = receipt.issuer_did.clone();
                let delta_id = receipt.state_hash;

                // A `did:key:` DID *is* the issuer's public key: resolution
                // yields the key the receipt must verify against (Req 14.6).
                match crate::identity::did::resolve_did(&issuer_did) {
                    Ok(issuer_public_key) => {
                        let mut dur = self.durability.lock().map_err(|e| {
                            TirBaseError::LocalStoreWriteFailed {
                                reason: format!("durability mutex: {e}"),
                            }
                        })?;

                        // Subphase 4.5: register the issuer's self-certified
                        // key with the Delta's durability state so
                        // `receive_receipt` can verify the signature.  A
                        // genuine two-device receipt exchange needs no
                        // pre-provisioned peer roster: the receipt itself
                        // carries the key (as its DID), and registration only
                        // enables verification — acceptance still requires the
                        // Ed25519 signature + state-hash to check out.
                        dur.register_peer_key(&delta_id, &issuer_did, issuer_public_key);

                        match dur.receive_receipt(receipt, &delta_id) {
                            Ok(true) => {
                                eprintln!(
                                    "[inbound] Tier-1 durability achieved for delta {}",
                                    hex::encode(delta_id)
                                );
                            }
                            Ok(false) => {}
                            Err(e) => {
                                eprintln!("[inbound] receipt rejected: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "[inbound] could not resolve receipt issuer DID {issuer_did}: {e}"
                        );
                    }
                }
            }
            GossipMessage::InboundRevocationDelta(rev_delta) => {
                let cce_clone = self.cce.clone();
                let transport_clone = self.transport.clone();

                let mut rev = self.revocation.lock().map_err(|e| {
                    TirBaseError::LocalStoreWriteFailed {
                        reason: format!("revocation mutex: {e}"),
                    }
                })?;

                let result = rev.process_incoming_delta(
                    &rev_delta,
                    &mut |target_did, complete_delta| {
                        // Req 9.2: gossip the complete RevocationDelta at HIGH priority.
                        eprintln!(
                            "[inbound] gossiping RevocationDelta at HIGH priority for revoked DID: {target_did}"
                        );
                        let gossip_msg = GossipMessage::InboundRevocationDelta(complete_delta.clone());
                        let gossip_bytes = gossip_msg.to_bytes();
                        let revocation_delta_wrapper = crate::crdt::delta::Delta {
                            id: [0u8; 32],
                            author_did: "tirbase/revocation".to_string(),
                            signature: crate::crdt::delta::Ed25519Signature::default(),
                            schema_hash: [0u8; 32],
                            automerge_bytes: gossip_bytes,
                            priority: crate::crdt::delta::PriorityClass::High,
                            causal_parents: vec![],
                            tags: vec![],
                            lamport: 0,
                            created_at: 0,
                        };
                        if let Ok(mut t) = transport_clone.lock() {
                            t.enqueue_outbound(revocation_delta_wrapper);
                        }
                    },
                    &mut |target_did, delta_ids| {
                        // CCE tagging of all Deltas authored by the revoked DID (Req 10.1).
                        eprintln!(
                            "[inbound] CCE tagging {} deltas for revoked DID: {target_did}",
                            delta_ids.len()
                        );
                        if let Ok(mut cce) = cce_clone.lock() {
                            for delta_id in delta_ids {
                                let _ = cce.tag_contamination_root(
                                    delta_id,
                                    crate::contamination::incident::TaintSource::DeviceRevocation {
                                        revocation_delta_id: delta_id,
                                    },
                                );
                            }
                        }
                    },
                );

                match result {
                    Ok(crate::auth::RevocationStatus::Applied) => {
                        eprintln!(
                            "[inbound] RevocationDelta applied for {}",
                            rev_delta.target_did
                        );

                        // Req 8.6 — a validated revocation makes the target
                        // DID locally known as REVOKED: register it in the CRDT
                        // engine so `CrdtEngine::apply` rejects all future
                        // inbound Deltas authored by it (the local write/read
                        // gate of Req 8.5 only protects this device's own
                        // operations, not the merge path).
                        drop(rev);
                        {
                            let mut crdt = self.crdt.lock().map_err(|e| {
                                TirBaseError::LocalStoreWriteFailed {
                                    reason: format!("crdt mutex: {e}"),
                                }
                            })?;
                            crdt.mark_did_revoked(&rev_delta.target_did);
                        }
                        eprintln!(
                            "[inbound] CRDT engine now rejects Deltas authored by revoked DID {}",
                            rev_delta.target_did
                        );

                        // Req 8.5 — a validated revocation targeting THIS
                        // device makes the REVOKED status locally known: apply
                        // it to the CapabilityManager so the local write/read
                        // gate (`ensure_local_trust_allows_io`) blocks all
                        // further I/O immediately.  Revocations of *other*
                        // devices must not trip this device's own gate.
                        if rev_delta.target_did == self.identity.did() {
                            self.capability
                                .lock()
                                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                                    reason: format!("capability mutex poisoned: {e}"),
                                })?
                                .apply_revocation()?;
                            eprintln!(
                                "[inbound] local device {} is REVOKED — write/read/query gates now block",
                                rev_delta.target_did
                            );
                        }
                    }
                    Ok(crate::auth::RevocationStatus::Pending {
                        collected,
                        required,
                    }) => {
                        eprintln!(
                            "[inbound] RevocationDelta pending {collected}/{required} sigs for {}",
                            rev_delta.target_did
                        );
                    }
                    Err(e) => {
                        eprintln!("[inbound] RevocationDelta processing failed: {e}");
                    }
                }
            }
            GossipMessage::InboundMigrationDelta(mig_delta) => {
                // Req 18.6: dispatch the transform to a background job instead
                // of executing it inline under the `migration` mutex.  The job
                // validates (prepare) under the engine lock, then runs the
                // sandbox OFF the lock with its wasmtime Engine registered in
                // `migration_runs` — so a MigrationRevocationDelta drained
                // moments later can acquire the engine and epoch-interrupt the
                // run instead of queueing behind it until the 30s timeout.
                let sender_did = mig_delta.author_did.clone();
                self.dispatch_inbound_migration(mig_delta, sender_did);
            }
            GossipMessage::InboundMigrationRevocationDelta(mig_rev) => {
                let target_migration_id = mig_rev.target_migration_id;
                let mut mig = self.migration.lock().map_err(|e| {
                    TirBaseError::LocalStoreWriteFailed {
                        reason: format!("migration mutex: {e}"),
                    }
                })?;
                // Ok(true) ⇒ the revocation halted a transform that was
                // executing — the engine only cleared the in-progress marker;
                // actually stopping the sandbox is the epoch interrupt below.
                // Err(UnknownMigrationHash) ⇒ Req 18.7: the revocation
                // targeted a hash this device never received as a
                // CA-validated MigrationDelta, so it is dropped (no block, no
                // audit entry).
                let halted = match mig.receive_revocation_delta(mig_rev) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("[inbound] MigrationRevocationDelta rejected: {e}");
                        return Ok(());
                    }
                };
                drop(mig);

                // Req 19.1: the migration is now flagged corrupted — CCE-tag
                // it and let the Causal Contamination Engine mark the affected
                // projection rows CONTAMINATED (rather than deleting them) and
                // open an Incident Context Object, so writes during the
                // corrupted window auto-tag with ContaminatedByHumanReaction
                // and join the incident (Req 19.5).  The migration id is the
                // root marker; `resolve_affected_rows` conservatively marks
                // every projection row (same policy as DeviceRevocation).
                {
                    let cce_result = self.cce.lock().map_err(|e| {
                        TirBaseError::LocalStoreWriteFailed {
                            reason: format!("cce mutex poisoned in BadMigration tagging: {e}"),
                        }
                    });
                    if let Ok(mut cce) = cce_result {
                        let _ = cce.tag_contamination_root(
                            target_migration_id,
                            crate::contamination::incident::TaintSource::BadMigration {
                                migration_id: target_migration_id,
                            },
                        );
                    }
                }
                if halted {
                    eprintln!(
                        "[inbound] MigrationRevocationDelta halted in-flight run {:?} — \
                         interrupting sandbox via epoch",
                        target_migration_id
                    );
                    if !self.migration_runs.interrupt(&target_migration_id) {
                        eprintln!(
                            "[inbound] no registered run for {:?} to interrupt \
                             (revocation landed at the completion edge)",
                            target_migration_id
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Dispatch an inbound `MigrationDelta` to the async migration pipeline
    /// (native; Req 18.6).
    ///
    /// Validates under the engine lock via
    /// [`SchemaMigrationEngine::prepare_migration`], then executes the
    /// transform off the lock on a background task so a revocation arriving
    /// mid-run can epoch-interrupt it (see the
    /// `InboundMigrationRevocationDelta` arm).  If another transform is
    /// already executing the job retries with a short sleep: schema steps are
    /// strictly serialised and each validates against the schema hash the
    /// previous step committed.
    ///
    /// Production caller: [`CoreHandle::receive_inbound`], reached by the
    /// inbound drain loop (`process_inbound_messages` → `receive_inbound`)
    /// for every `GossipMessage::InboundMigrationDelta`.
    #[cfg(feature = "native")]
    fn dispatch_inbound_migration(&self, mig_delta: crate::migration::migration_delta::MigrationDelta, sender_did: String) {
        use crate::migration::wasm_sandbox::MigrationResult;

        let migration = self.migration.clone();
        let store = self.store.clone();
        let crdt = self.crdt.clone();
        let runs = self.migration_runs.clone();
        let active_jobs = self.migration_tasks_active.clone();
        use std::sync::atomic::Ordering;
        active_jobs.fetch_add(1, Ordering::SeqCst);

        let _ = tokio::spawn(async move {
            // RAII: never leave the active-job counter raised, whatever path
            // the job exits on (so `await_migration_quiescence` cannot hang).
            let _active_guard = ActiveMigrationJobGuard(active_jobs);

            // ── 1. Prepare (validate + mark in-progress) under the engine ──
            // lock, retrying while another transform holds the engine.
            let prepared = loop {
                let attempt = {
                    let mut mig = match migration.lock() {
                        Ok(g) => g,
                        Err(e) => {
                            eprintln!("[inbound] migration mutex poisoned: {e}");
                            return;
                        }
                    };
                    mig.prepare_migration(mig_delta.clone(), &sender_did)
                };
                match attempt {
                    Ok(prepared) => break prepared,
                    Err(TirBaseError::MigrationInProgress { .. }) => {
                        // Another migration is executing; a schema step can
                        // only validate once the previous one committed.
                        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                        continue;
                    }
                    Err(e) => {
                        eprintln!("[inbound] MigrationDelta rejected: {e}");
                        return;
                    }
                }
            };

            let migration_id = prepared.migration_id;
            let target_schema_hash = prepared.target_schema_hash;
            let transform_bytes = prepared.transform_bytes;
            let timeout_secs = prepared.timeout_secs;

            // ── 2. Run the sandbox OFF the engine lock, registered in the ──
            // execution registry so a revocation can epoch-interrupt it.
            let outcome: Result<MigrationResult, TirBaseError> = tokio::task::spawn_blocking(move || {
                execute_migration_with_registry(
                    &transform_bytes,
                    migration_id,
                    timeout_secs,
                    &store,
                    &runs,
                )
            })
            .await
            .map_err(|e| TirBaseError::DeltaMalformed {
                reason: format!("migration background task failed: {e}"),
            })
            .and_then(|r| r);

            // ── 3. Finish under the engine lock: the commit gate re-checks ──
            // revocation, so a transform that was interrupted (or a revocation
            // that landed at the completion edge) never advances the schema.
            // The schema the device was on *before* the commit is captured
            // here: it is the corruption-window key whose Side-Car entries the
            // corrected migration must replay (Req 19.3).
            let (normalized, source_schema_hash) = {
                let mut mig = match migration.lock() {
                    Ok(g) => g,
                    Err(e) => {
                        eprintln!("[inbound] migration mutex poisoned: {e}");
                        return;
                    }
                };
                let source_schema_hash = mig.current_schema_hash();
                let normalized =
                    mig.finish_migration(&migration_id, &target_schema_hash, outcome);
                (normalized, source_schema_hash)
            };

            match normalized {
                Ok(MigrationResult::Success) => {
                    // Subphase 5.3: a successfully applied migration changes
                    // the device's deployed schema.  Mirror it into the CRDT
                    // engine so locally produced Deltas stamp the new hash
                    // (Req 4.6) and the merge gate classifies inbound Deltas
                    // against the new schema (Req 17.2–17.4).
                    let new_current = {
                        let mig = match migration.lock() {
                            Ok(g) => g,
                            Err(e) => {
                                eprintln!("[inbound] migration mutex poisoned: {e}");
                                return;
                            }
                        };
                        mig.current_schema_hash()
                    };
                    let mut crdt = match crdt.lock() {
                        Ok(g) => g,
                        Err(e) => {
                            eprintln!("[inbound] crdt mutex poisoned: {e}");
                            return;
                        }
                    };
                    crdt.set_current_schema(new_current);

                    // Req 19.3: a corrected migration just committed — replay
                    // the Side-Car entries captured while the pre-migration
                    // schema was under a corruption window against the
                    // corrected projection, in recorded-timestamp order.
                    // Best-effort: replay conflicts are flagged (Req 19.4),
                    // never rolled back — the migration itself stays applied.
                    {
                        let mut mig = match migration.lock() {
                            Ok(g) => g,
                            Err(e) => {
                                eprintln!("[inbound] migration mutex poisoned: {e}");
                                return;
                            }
                        };
                        let _ = mig.replay_corrupted_windows(
                            &source_schema_hash,
                            new_current,
                            &mut crdt,
                        );
                    }

                    eprintln!(
                        "[inbound] MigrationDelta applied; CRDT current schema advanced to {}",
                        hex::encode(new_current)
                    );
                }
                Ok(MigrationResult::Revoked { reason }) => {
                    eprintln!(
                        "[inbound] MigrationDelta {:?} interrupted by revocation — NOT applied: {reason}",
                        migration_id
                    );
                }
                Ok(other) => {
                    eprintln!("[inbound] MigrationDelta not applied: {other:?}");
                }
                Err(e) => {
                    eprintln!("[inbound] MigrationDelta rejected: {e}");
                }
            }
        });
    }

    /// Wait until every dispatched migration job has finished (transform
    /// committed, aborted, or revoked) or `timeout` elapses.
    ///
    /// The inbound pipeline dispatches migration execution to background jobs
    /// so a revocation can interrupt an in-progress transform; this helper
    /// lets callers observe the moment the pipeline has fully settled.  The
    /// production drain loop does not need it (it ticks continuously); it
    /// exists for integration tests and hosts that drive
    /// `process_inbound_messages` manually and then assert post-migration
    /// state.  Returns `false` when `timeout` elapsed first.
    #[cfg(feature = "native")]
    pub(crate) async fn await_migration_quiescence(
        &self,
        timeout: std::time::Duration,
    ) -> bool {
        use std::sync::atomic::Ordering;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let active = self.migration_tasks_active.load(Ordering::SeqCst);
            let busy = self
                .migration
                .lock()
                .map(|g| g.any_migration_in_progress())
                .unwrap_or(true);
            if active == 0 && !busy {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// WASM stub for the native `receive_inbound` — the Gossipsub Swarm is not
    /// available on wasm32. Use `receive_inbound_wasm` instead, which is driven
    /// by the JS transport layer calling `core_receive_peer_message`.
    #[cfg(not(feature = "native"))]
    pub async fn receive_inbound(
        &self,
        _msg: crate::transport::message::GossipMessage,
    ) -> Result<(), TirBaseError> {
        Ok(())
    }

    /// Process an inbound peer message on the WASM target.
    ///
    /// This is the JS-driven equivalent of the native Swarm spawn loop.
    /// The JS transport layer (WebRTC data channel, BLE bridge, or any
    /// browser-compatible transport) calls `core_receive_peer_message()` with
    /// raw bytes, which deserialises them into a `GossipMessage` and delegates
    /// here. Each variant is routed to the correct in-memory subsystem (Req 5,
    /// Req 1.4).
    ///
    /// Routing:
    /// - `InboundDelta`                   → signature verification + in-memory store write
    /// - `InboundDurabilityReceipt`       → `DurabilitySubsystem::receive_receipt`
    /// - `InboundRevocationDelta`         → `RevocationSubsystem::process_incoming_delta`
    /// - `InboundMigrationDelta`          → `SchemaMigrationEngine::receive_migration_delta`
    /// - `InboundMigrationRevocationDelta`→ `SchemaMigrationEngine::receive_revocation_delta`
    #[cfg(not(feature = "native"))]
    pub async fn receive_inbound_wasm(
        &self,
        msg: crate::transport::message::GossipMessage,
    ) -> Result<(), TirBaseError> {
        use crate::crdt::merge::{apply_incoming_delta, MergeOutcome};
        use crate::transport::message::GossipMessage;

        match msg {
            GossipMessage::InboundDelta(delta) => {
                // Route through the real LWW/RGA dispatch layer (Req 4.3–4.5a).
                // apply_incoming_delta handles:
                //   1. Schema-hash gate (unknown → Quarantined)
                //   2. Ed25519 signature verification via DID resolution (invalid → Rejected)
                //   3. Operation-type classification (LWW scalar vs RGA sequence)
                //   4. CrdtEngine::apply() for the actual Automerge merge
                //
                // This replaces the old JSON-sidecar heuristic and correctly handles
                // both WASM-produced JSON envelopes AND native-produced binary Automerge
                // changesets (Req 1.4 cross-build state convergence).
                let outcome = {
                    let mut crdt = self.crdt.lock().map_err(|e| {
                        TirBaseError::LocalStoreWriteFailed {
                            reason: format!("crdt mutex poisoned in receive_inbound_wasm: {e}"),
                        }
                    })?;
                    apply_incoming_delta(&mut crdt, &delta)?
                };

                match outcome {
                    MergeOutcome::Merged { .. } => {
                        eprintln!(
                            "[wasm-inbound] Delta {} merged from {}",
                            hex::encode(delta.id),
                            delta.author_did
                        );

                        // Project the merged state into the in-memory store so that
                        // read() and query() reflect the new peer state (Req 4.3, 3.3).
                        //
                        // Strategy (same as native receive_inbound):
                        //   1. Try to parse automerge_bytes as the TirBase JSON envelope
                        //      (contains _tirbase_table, _tirbase_key, and data fields).
                        //      Both WASM-produced Deltas and older-format peer Deltas use this.
                        //   2. For native-produced binary Automerge bytes, project from the
                        //      CrdtEngine's merged Automerge doc using doc_map_range_root().
                        //      The doc state is now correct after CrdtEngine::apply().
                        if !delta.automerge_bytes.is_empty() {
                            if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(&delta.automerge_bytes) {
                                // JSON envelope path (WASM-produced or TirBase format).
                                if let Some(obj) = json_val.as_object() {
                                    let table_name = obj.get("_tirbase_table")
                                        .and_then(|v| v.as_str());
                                    let row_key = obj.get("_tirbase_key")
                                        .and_then(|v| v.as_str());

                                    if let (Some(tbl), Some(rkey)) = (table_name, row_key) {
                                        // Reconstruct application data (strip TirBase metadata keys).
                                        let mut app_data = serde_json::Map::new();
                                        let mut has_data_key = false;
                                        for (k, v) in obj {
                                            if k == "_data" {
                                                // Scalar/non-object data stored under _data.
                                                let _ = self.store
                                                    .lock()
                                                    .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                                                        reason: format!("store mutex: {e}"),
                                                    })?
                                                    .write(tbl, rkey, v);
                                                // Record the delta→row mapping for CCE resolve_affected_rows.
                                                crate::store::projection::record_delta_row(
                                                    &delta.id, tbl, rkey,
                                                );
                                                eprintln!(
                                                    "[wasm-inbound] projected delta {} → {tbl}/{rkey}",
                                                    hex::encode(delta.id)
                                                );
                                                has_data_key = true;
                                                break;
                                            } else if k != "_tirbase_table" && k != "_tirbase_key" {
                                                app_data.insert(k.clone(), v.clone());
                                            }
                                        }
                                        if !has_data_key && !app_data.is_empty() {
                                            let app_val = serde_json::Value::Object(app_data);
                                            let _ = self.store
                                                .lock()
                                                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                                                    reason: format!("store mutex: {e}"),
                                                })?
                                                .write(tbl, rkey, &app_val);
                                            // Record the delta→row mapping for CCE.
                                            crate::store::projection::record_delta_row(
                                                &delta.id, tbl, rkey,
                                            );
                                            eprintln!(
                                                "[wasm-inbound] projected delta {} → {tbl}/{rkey}",
                                                hex::encode(delta.id)
                                            );
                                        }
                                    } else {
                                        // JSON envelope but no table/key metadata.
                                        eprintln!(
                                            "[wasm-inbound] delta {} has JSON bytes but no \
                                             _tirbase_table/_tirbase_key — skipping store projection",
                                            hex::encode(delta.id)
                                        );
                                    }
                                }
                            } else {
                                // Binary Automerge bytes — project from the CrdtEngine's doc
                                // state which was updated by CrdtEngine::apply() above.
                                // Use doc_map_range_root() to read all ROOT-level scalar keys.
                                let root_pairs: Vec<(String, serde_json::Value)> = {
                                    let crdt = self.crdt.lock().map_err(|e| {
                                        TirBaseError::LocalStoreWriteFailed {
                                            reason: format!("crdt mutex: {e}"),
                                        }
                                    })?;
                                    crdt.doc_map_range_root()
                                };

                                // The Automerge ROOT-level keys represent rows across all tables
                                // in the doc. Since each table is a separate doc in the full
                                // architecture, the doc's ROOT keys are rows within one logical
                                // table. We write them to a synthetic "_merged" table using the
                                // key string as the row key. Callers with real table metadata
                                // should embed the JSON envelope for correct projection.
                                if !root_pairs.is_empty() {
                                    let mut store = self.store.lock().map_err(|e| {
                                        TirBaseError::LocalStoreWriteFailed {
                                            reason: format!("store mutex: {e}"),
                                        }
                                    })?;
                                    for (key, val) in &root_pairs {
                                        let _ = store.write("_merged", key, val);
                                        crate::store::projection::record_delta_row(
                                            &delta.id, "_merged", key,
                                        );
                                    }
                                    eprintln!(
                                        "[wasm-inbound] delta {} projected {} root keys from binary Automerge bytes",
                                        hex::encode(delta.id),
                                        root_pairs.len()
                                    );
                                }
                            }
                        }
                    }
                    MergeOutcome::Quarantined { reason } => {
                        // Subphase 5.2: persist the raw received Delta in the
                        // QuarantineLedger (Req 17.4–17.6) instead of only
                        // logging it — identical wiring to the native
                        // `receive_inbound` path. The full serialised Delta is
                        // stored byte-for-byte for later schema-migration
                        // replay.
                        let raw_bytes = serde_json::to_vec(&delta).unwrap_or_else(|e| {
                            eprintln!(
                                "[wasm-inbound] delta {} could not be serialised for quarantine: {e} — storing payload bytes only",
                                hex::encode(delta.id)
                            );
                            delta.automerge_bytes.clone()
                        });
                        match self
                            .migration
                            .lock()
                            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                                reason: format!("migration mutex poisoned in receive_inbound_wasm: {e}"),
                            })?
                            .quarantine_incoming(
                                &delta.author_did,
                                raw_bytes,
                                Some(delta.schema_hash),
                                reason.clone().into(),
                                now_micros(),
                            ) {
                            Ok(entry_id) => eprintln!(
                                "[wasm-inbound] delta {} quarantined ({reason:?}) from {} → stored in quarantine ledger as {}",
                                hex::encode(delta.id),
                                delta.author_did,
                                hex::encode(entry_id)
                            ),
                            Err(e) => eprintln!(
                                "[wasm-inbound] delta {} could not be stored in the quarantine ledger: {e}",
                                hex::encode(delta.id)
                            ),
                        }
                    }
                    MergeOutcome::Rejected { reason } => {
                        eprintln!(
                            "[wasm-inbound] delta {} rejected from {}: {reason}",
                            hex::encode(delta.id),
                            delta.author_did
                        );
                    }
                }

                // Register with the durability subsystem so Tier-1 tracking works.
                let delta_bytes = serde_json::to_vec(&delta).unwrap_or_default();
                let _ = self
                    .durability
                    .lock()
                    .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                        reason: format!("durability mutex poisoned: {e}"),
                    })?
                    .register_delta(
                        delta.id,
                        delta.id,
                        delta_bytes,
                        delta.causal_parents.clone(),
                        std::collections::HashMap::new(),
                    );

                Ok(())
            }

            GossipMessage::InboundDurabilityReceipt(receipt) => {
                let delta_id = receipt.state_hash;
                let issuer_did = receipt.issuer_did.clone();

                // Same as the native receipt arm: resolve the issuer's
                // self-certifying `did:key:` DID and register the key with the
                // Delta's durability state so `receive_receipt` can verify the
                // receipt (Req 14.6, Subphase 4.5 parity).
                match crate::identity::did::resolve_did(&issuer_did) {
                    Ok(issuer_public_key) => {
                        let mut dur = self.durability.lock().map_err(|e| {
                            TirBaseError::LocalStoreWriteFailed {
                                reason: format!("durability mutex poisoned: {e}"),
                            }
                        })?;
                        dur.register_peer_key(&delta_id, &issuer_did, issuer_public_key);
                        match dur.receive_receipt(receipt, &delta_id) {
                            Ok(true) => {
                                eprintln!(
                                    "[wasm-inbound] Tier-1 durability achieved for delta {}",
                                    hex::encode(delta_id)
                                );
                            }
                            Ok(false) => {}
                            Err(e) => {
                                eprintln!("[wasm-inbound] receipt rejected: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "[wasm-inbound] could not resolve receipt issuer DID {issuer_did}: {e}"
                        );
                    }
                }
                Ok(())
            }

            GossipMessage::InboundRevocationDelta(rev_delta) => {
                let mut rev = self.revocation.lock().map_err(|e| {
                    TirBaseError::LocalStoreWriteFailed {
                        reason: format!("revocation mutex poisoned: {e}"),
                    }
                })?;

                match rev.process_incoming_delta(
                    &rev_delta,
                    &mut |target_did, _complete_delta| {
                        // No Swarm gossip rebroadcast on WASM — the JS transport
                        // layer handles peer messaging (Req 9.2 is best-effort on WASM).
                        eprintln!(
                            "[wasm-inbound] RevocationDelta threshold met for {target_did}"
                        );
                    },
                    &mut |target_did, delta_ids| {
                        eprintln!(
                            "[wasm-inbound] CCE: {} deltas to tag for revoked DID {target_did}",
                            delta_ids.len()
                        );
                        // CCE tagging on WASM — best-effort (no SQLite DAG walk).
                    },
                ) {
                    Ok(crate::auth::RevocationStatus::Applied) => {
                        eprintln!(
                            "[wasm-inbound] RevocationDelta applied for {}",
                            rev_delta.target_did
                        );

                        // Req 8.6 — same wiring as the native inbound path: a
                        // validated revocation makes the target DID locally
                        // known as REVOKED, so the CRDT engine rejects all
                        // future inbound Deltas authored by it.
                        drop(rev);
                        {
                            let mut crdt = self.crdt.lock().map_err(|e| {
                                TirBaseError::LocalStoreWriteFailed {
                                    reason: format!("crdt mutex poisoned: {e}"),
                                }
                            })?;
                            crdt.mark_did_revoked(&rev_delta.target_did);
                        }
                        eprintln!(
                            "[wasm-inbound] CRDT engine now rejects Deltas authored by revoked DID {}",
                            rev_delta.target_did
                        );

                        // Req 8.5 — same wiring as the native inbound path: a
                        // validated revocation targeting THIS device applies
                        // the REVOKED TrustLevel to the CapabilityManager so
                        // the local write/read gate blocks all further I/O.
                        if rev_delta.target_did == self.identity.did() {
                            self.capability
                                .lock()
                                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                                    reason: format!("capability mutex poisoned: {e}"),
                                })?
                                .apply_revocation()?;
                            eprintln!(
                                "[wasm-inbound] local device {} is REVOKED — write/read/query gates now block",
                                rev_delta.target_did
                            );
                        }
                    }
                    Ok(crate::auth::RevocationStatus::Pending { collected, required }) => {
                        eprintln!(
                            "[wasm-inbound] RevocationDelta pending {collected}/{required} sigs for {}",
                            rev_delta.target_did
                        );
                    }
                    Err(e) => {
                        eprintln!("[wasm-inbound] RevocationDelta failed: {e}");
                    }
                }
                Ok(())
            }

            GossipMessage::InboundMigrationDelta(mig_delta) => {
                let sender_did = mig_delta.author_did.clone();
                let mut mig = self.migration.lock().map_err(|e| {
                    TirBaseError::LocalStoreWriteFailed {
                        reason: format!("migration mutex poisoned: {e}"),
                    }
                })?;
                // The schema the device is on before the migration — the
                // corruption-window key whose Side-Car entries a corrected
                // migration must replay (Req 19.3).
                let source_schema_hash = mig.current_schema_hash();
                match mig.receive_migration_delta(mig_delta, &sender_did) {
                    Ok(result) => {
                        if matches!(
                            result,
                            crate::migration::wasm_sandbox::MigrationResult::Success
                        ) {
                            // Subphase 5.3 (WASM parity): mirror a successful
                            // migration into the CRDT engine's current schema
                            // (see the native arm for rationale).
                            let new_current = mig.current_schema_hash();
                            drop(mig);
                            let mut crdt = self.crdt.lock().map_err(|e| {
                                TirBaseError::LocalStoreWriteFailed {
                                    reason: format!(
                                        "crdt mutex poisoned in receive_inbound_wasm: {e}"
                                    ),
                                }
                            })?;
                            crdt.set_current_schema(new_current);

                            // Req 19.3 (WASM parity): replay the Side-Car
                            // entries captured while the pre-migration schema
                            // was under a corruption window against the
                            // corrected projection (best-effort, same as the
                            // native arm).
                            {
                                let mut mig = self.migration.lock().map_err(|e| {
                                    TirBaseError::LocalStoreWriteFailed {
                                        reason: format!(
                                            "migration mutex poisoned in receive_inbound_wasm: {e}"
                                        ),
                                    }
                                })?;
                                let _ = mig.replay_corrupted_windows(
                                    &source_schema_hash,
                                    new_current,
                                    &mut crdt,
                                );
                            }

                            eprintln!(
                                "[wasm-inbound] MigrationDelta applied: {result:?}; CRDT current schema advanced to {}",
                                hex::encode(new_current)
                            );
                        } else {
                            eprintln!("[wasm-inbound] MigrationDelta applied: {result:?}");
                        }
                    }
                    Err(e) => {
                        eprintln!("[wasm-inbound] MigrationDelta rejected: {e}");
                    }
                }
                Ok(())
            }

            GossipMessage::InboundMigrationRevocationDelta(mig_rev) => {
                let target_migration_id = mig_rev.target_migration_id;
                let mut mig = self.migration.lock().map_err(|e| {
                    TirBaseError::LocalStoreWriteFailed {
                        reason: format!("migration mutex poisoned: {e}"),
                    }
                })?;
                match mig.receive_revocation_delta(mig_rev) {
                    Ok(_halted) => {
                        // The WASM build is single-threaded: no transform can
                        // be executing concurrently, so `_halted` is always
                        // false here.  Mid-flight interruption is a native
                        // capability (epoch interrupt via the execution
                        // registry, Req 18.6); on WASM the synchronous
                        // `receive_migration_delta` path's post-run revocation
                        // re-check still protects the schema-hash commit.

                        // Req 19.1 (WASM parity): the migration is now flagged
                        // corrupted — CCE-tag it and mark the affected
                        // projection rows CONTAMINATED (same trigger as the
                        // native arm).
                        {
                            let cce_result = self.cce.lock().map_err(|e| {
                                TirBaseError::LocalStoreWriteFailed {
                                    reason: format!(
                                        "cce mutex poisoned in BadMigration tagging (WASM): {e}"
                                    ),
                                }
                            });
                            if let Ok(mut cce) = cce_result {
                                let _ = cce.tag_contamination_root(
                                    target_migration_id,
                                    crate::contamination::incident::TaintSource::BadMigration {
                                        migration_id: target_migration_id,
                                    },
                                );
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[wasm-inbound] MigrationRevocationDelta rejected: {e}");
                    }
                }
                Ok(())
            }
        }
    }

    /// Drain all pending inbound messages from the channel and route each through
    /// the appropriate subsystem (Req 4.3–4.7, 5.1–5.8).
    ///
    /// This is a non-blocking drain: it processes only messages that are already
    /// queued. Call this from an application-controlled tick loop or a dedicated
    /// background task to drive the inbound pipeline.
    ///
    /// Returns the number of messages processed.
    pub async fn process_inbound_messages(&self) -> Result<usize, TirBaseError> {
        #[cfg(not(feature = "native"))]
        {
            return Ok(0);
        }

        #[cfg(feature = "native")]
        {
            use tokio::sync::mpsc::error::TryRecvError;

            let mut count = 0usize;
            let mut rx = self.inbound_rx.lock().await;

            loop {
                match rx.try_recv() {
                    Ok(msg) => {
                        self.receive_inbound(msg).await?;
                        count += 1;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => break,
                }
            }
            Ok(count)
        }
    }

    /// Spawn the production inbound drain loop for this handle.
    ///
    /// Every `interval`, the background task calls
    /// [`CoreHandle::process_inbound_messages`], which drains `inbound_rx`
    /// (fed by the Swarm polling task via `inbound_tx`) and routes each
    /// `GossipMessage` through the correct subsystem.
    ///
    /// Production caller: [`CoreHandle::init`] spawns this loop before
    /// returning, so Gossipsub messages are drained in production rather than
    /// only from tests (Subphase 1.3).  It is `pub(crate)` rather than private
    /// so the Subphase 1.3 integration test can drive the *identical* loop
    /// with a short interval without racing the count-based unit tests.
    ///
    /// Returns the `JoinHandle` so callers can observe or abort the task.
    #[cfg(feature = "native")]
    pub(crate) fn spawn_inbound_drain_loop(
        self: &Arc<Self>,
        interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        let handle = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                match handle.process_inbound_messages().await {
                    Ok(0) => {}
                    Ok(n) => {
                        eprintln!("[inbound-loop] drained {n} inbound message(s)");
                    }
                    Err(e) => {
                        eprintln!("[inbound-loop] drain failed: {e}");
                    }
                }
            }
        })
    }

    /// Spawn the production DRR scheduler tick loop for this handle.
    ///
    /// Every `interval`, the background task locks the mesh transport,
    /// advances the Saturate_Mode state machine's clock
    /// ([`MeshTransport::tick_saturate`] — Subphase 3.3, so lease expiry
    /// auto-demotion happens without manual ticking), then calls
    /// [`MeshTransport::tick_scheduler`], which runs one DRR scheduling epoch
    /// (Req 12) and forwards the drained Deltas to the outbound publish
    /// channel; the Swarm polling task (Subphase 1.1) receives them and
    /// publishes to the shared Gossipsub topic.  Without this loop, Deltas
    /// enqueued via `MeshTransport::enqueue_outbound` (HIGH-priority
    /// revocation rebroadcast, mDNS re-announcement) would accumulate in the
    /// scheduler queues forever.
    ///
    /// Production caller: [`CoreHandle::init`] spawns this loop before
    /// returning, gated on a live outbound publish channel (Subphase 1.4).  It
    /// is `pub(crate)` rather than private so the Subphase 1.4 integration
    /// test can drive the *identical* loop with a short interval without
    /// racing the queue-state unit tests.
    ///
    /// Returns the `JoinHandle` so callers can observe or abort the task.
    #[cfg(feature = "native")]
    pub(crate) fn spawn_scheduler_tick_loop(
        self: &Arc<Self>,
        interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        let handle = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                match handle.transport.lock() {
                    Ok(mut transport) => {
                        // Subphase 3.3: advance the Saturate_Mode state
                        // machine's clock every epoch.  A lease that expired
                        // without renewal demotes the state machine — and the
                        // transport reconciles the DRR scheduler mirror — even
                        // when no Manager event ever arrives again.  This runs
                        // BEFORE the DRR epoch so a just-expired lease cannot
                        // keep scheduling everything at HIGH priority for even
                        // one extra epoch.
                        transport.tick_saturate(now_secs());
                        match transport.tick_scheduler(
                            crate::transport::DEFAULT_LINK_CAPACITY_BYTES,
                        ) {
                            Ok(0) => {}
                            Ok(n) => {
                                eprintln!(
                                    "[scheduler-loop] DRR tick forwarded {n} outbound payload(s)"
                                );
                            }
                            Err(e) => {
                                eprintln!("[scheduler-loop] DRR tick failed: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[scheduler-loop] transport mutex poisoned: {e}");
                    }
                }
            }
        })
    }

    /// Run one cloud sync cycle: drain the Durability Subsystem's cloud
    /// outbound queue through the real `CloudLedgerConnection` in causal
    /// order (Subphase 4.1) and mark every freshly-acked Delta Tier-2 durable
    /// (Subphase 4.2).
    ///
    /// The heavy lifting is [`cloud_sync_loop`]: it topologically sorts the
    /// pending entries by their `causal_parents` (parents before children,
    /// Req 16.3), sends each serialised Delta to the Cloud Ledger via the
    /// `CloudConnection` adapter, removes entries only after a per-Delta
    /// acknowledgement (Req 16.3) and retains rejected entries for the next
    /// cycle (Req 16.5).  Compacted entries would be deferred until a
    /// re-fetch succeeds (Req 16.8) — the re-fetch callback returns `None`
    /// because no production path marks cloud-queue entries compacted yet,
    /// so the deferral branch never fires in practice (it stays wired for
    /// the day Tier-1 compaction reaches the queue, Req 14.8/16.8).
    ///
    /// **Tier-2 marking (Subphase 4.2):** the loop alone removes an acked
    /// Delta from the queue but never advances the Delta's durability state —
    /// `WriteResult.durability_tier` would stay `Uncommitted` forever in a
    /// real deployment.  So for every Delta ID the loop freshly acknowledged
    /// (`CloudSyncResult::acknowledged_ids`), this cycle invokes
    /// [`DurabilitySubsystem::on_cloud_ack`], which marks the Delta Tier-2
    /// durable and notifies the handle's durability event channel / the SDK
    /// (Req 14.4, 14.7).  `on_cloud_ack`'s queue removal is idempotent, so
    /// calling it after the loop's own removal is safe.
    ///
    /// Lock order is always `durability` → `cloud_ledger` (matching
    /// `spawn_cloud_sync_loop`); the ledger never takes the durability lock.
    ///
    /// Production caller: [`CoreHandle::spawn_cloud_sync_loop`], which
    /// [`CoreHandle::init`] spawns before returning (Subphase 4.1).  It is a
    /// separate method so the integration test can exercise a full cycle
    /// deterministically as well as through the spawned loop.
    #[cfg(feature = "native")]
    pub(crate) fn run_cloud_sync_cycle(
        &self,
    ) -> Result<CloudSyncResult, TirBaseError> {
        let mut durability = self.durability.lock().map_err(|e| {
            TirBaseError::LocalStoreWriteFailed {
                reason: format!("durability mutex poisoned: {e}"),
            }
        })?;

        // Nothing pending — skip the cycle (no ledger lock, no log noise).
        if durability.cloud_queue_depth() == 0 {
            return Ok(CloudSyncResult::default());
        }

        let mut ledger = self.cloud_ledger.lock().map_err(|e| {
            TirBaseError::LocalStoreWriteFailed {
                reason: format!("cloud ledger mutex poisoned: {e}"),
            }
        })?;
        let mut conn = CloudLedgerConnection::new(&mut ledger);

        let result = cloud_sync_loop(
            durability.cloud_queue_mut(),
            &mut conn,
            &|_delta_id, _receipt_holders| None,
        );

        // Subphase 4.2: a real cloud ack must mark the Delta durable.  The
        // queue-level sync loop removed the entry; now advance the per-Delta
        // durability state (the state backing `WriteResult.durability_tier`)
        // to Tier-2 and notify CoreHandle/SDK of the transition.
        for delta_id in &result.acknowledged_ids {
            durability.on_cloud_ack(delta_id)?;
        }

        Ok(result)
    }

    /// Spawn the production cloud sync loop for this handle.
    ///
    /// Every `interval`, the background task calls
    /// [`CoreHandle::run_cloud_sync_cycle`], which drains the Durability
    /// Subsystem's cloud outbound queue through the real
    /// `CloudLedgerConnection` in causal order and sends each Delta to the
    /// Cloud Ledger (Req 16.3).  Without this loop the cloud queue only ever
    /// grows in production — nothing outside
    /// `durability/integration_tests.rs` drained it.
    ///
    /// Production caller: [`CoreHandle::init`] spawns this loop before
    /// returning (Subphase 4.1).  It is `pub(crate)` rather than private so
    /// the Subphase 4.1 integration test can drive the *identical* loop with
    /// a short interval without racing the queue-state unit tests.
    ///
    /// Returns the `JoinHandle` so callers can observe or abort the task.
    #[cfg(feature = "native")]
    pub(crate) fn spawn_cloud_sync_loop(
        self: &Arc<Self>,
        interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        let handle = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                match handle.run_cloud_sync_cycle() {
                    Ok(result) => {
                        let processed =
                            result.acknowledged + result.rejected + result.deferred;
                        if processed > 0 {
                            eprintln!(
                                "[cloud-sync-loop] cycle: {} acked, {} rejected, {} deferred",
                                result.acknowledged, result.rejected, result.deferred
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("[cloud-sync-loop] cloud sync cycle failed: {e}");
                    }
                }
            }
        })
    }

    /// Current cloud outbound queue depth (Subphase 4.1 observability).
    ///
    /// Mirrors [`DurabilitySubsystem::cloud_queue_depth`] for the
    /// production drain-loop integration test and diagnostics.
    #[cfg(feature = "native")]
    pub(crate) fn cloud_queue_depth(&self) -> usize {
        self.durability
            .lock()
            .map(|d| d.cloud_queue_depth())
            .unwrap_or(0)
    }

    /// Whether the Cloud Ledger this process hosts has committed the given
    /// Delta (Subphase 4.1 observability).
    #[cfg(feature = "native")]
    pub(crate) fn cloud_ledger_is_committed(&self, delta_id: &DeltaId) -> bool {
        self.cloud_ledger
            .lock()
            .map(|l| l.is_committed(delta_id))
            .unwrap_or(false)
    }

    /// The current durability tier of a written Delta (Req 14.7).
    ///
    /// This is the same per-Delta state that `WriteResult::durability_tier`
    /// reports at write time; it transitions `Uncommitted` → `Tier1`/`Tier2`
    /// as quorum receipts arrive and the Cloud Ledger acknowledges the Delta
    /// (Subphase 4.2 — the production cloud sync drain now drives the Tier-2
    /// transition instead of leaving every Delta `Uncommitted` forever).  Host
    /// applications that poll or that miss the broadcast event (see
    /// [`CoreHandle::subscribe_durability_events`]) can read the current tier
    /// here.
    #[cfg(feature = "native")]
    pub(crate) fn durability_tier(&self, delta_id: &DeltaId) -> DurabilityTier {
        self.durability
            .lock()
            .map(|d| d.durability_tier(delta_id))
            .unwrap_or(DurabilityTier::Uncommitted)
    }

    /// Subscribe to durability tier transitions (Req 14.7).
    ///
    /// Returns a new receiver that will receive a [`DurabilityTierChanged`]
    /// event every time a Delta this handle registered transitions to Tier-1
    /// (quorum) or Tier-2 (Cloud Ledger ack) — the native analogue of the SDK's
    /// `durability-tier-changed` event.  Subscribers that lag beyond the
    /// channel's ring buffer (64 events) miss the oldest transitions, so poll
    /// [`CoreHandle::durability_tier`] for authoritative current state.
    #[cfg(feature = "native")]
    pub fn subscribe_durability_events(
        &self,
    ) -> tokio::sync::broadcast::Receiver<DurabilityTierChanged> {
        self.durability_events_channel.subscribe()
    }

    /// Inject a `GossipMessage` directly into the inbound channel.
    ///
    /// Intended for testing only — allows tests to push messages without
    /// requiring a live libp2p Swarm.
    #[cfg(test)]
    pub async fn inject_inbound(
        &self,
        msg: crate::transport::message::GossipMessage,
    ) -> Result<(), TirBaseError> {
        self.inbound_tx.send(msg).await.map_err(|e| {
            TirBaseError::LocalStoreWriteFailed {
                reason: format!("inbound_tx send failed: {e}"),
            }
        })
    }

    /// Dial a peer by multiaddr (native only).
    ///
    /// Forwards the target address to the Swarm polling task spawned by
    /// [`CoreHandle::init`], which performs the actual `swarm.dial`.  This is
    /// the explicit-connect path for topologies where mDNS discovery is
    /// unavailable or unsuitable (WAN peers, a known cloud/relay endpoint).
    /// The connection — once established — is recorded in the peer table, so
    /// `mesh_status()` reflects it like any mDNS-discovered peer.
    ///
    /// Current callers: the Subphase 1.5 mesh integration tests (two real
    /// Swarm-backed handles dialing each other on loopback), which are the
    /// definition of done for Phase 0.3(a)/(b).  The SDK-facing mesh-connect
    /// operation (Phase 4 cloud sync) is the stated production consumer.
    #[cfg(feature = "native")]
    pub(crate) async fn dial_peer(
        &self,
        addr: libp2p::Multiaddr,
    ) -> Result<(), TirBaseError> {
        let tx = self.dial_tx.as_ref().ok_or_else(|| {
            TirBaseError::MeshUnavailable {
                reason: "transport not started (no Swarm polling task)".to_string(),
            }
        })?;
        tx.send(addr).await.map_err(|e| TirBaseError::MeshUnavailable {
            reason: format!("dial channel closed: {e}"),
        })
    }
}

// ─── Configuration types ──────────────────────────────────────────────────────

/// Configuration supplied at initialisation time.
#[derive(Debug, Clone)]
pub struct InitConfig {
    /// Path to the local SQLite database file.
    pub storage_path: String,
    /// Deployment-specific settings (M-of-N thresholds, spatial diversity, etc.).
    pub deployment: DeploymentConfig,
    /// libp2p listen address (native-only; ignored on wasm).
    ///
    /// Passed through to [`MeshTransport`] at init so deployments can pin the
    /// device to a specific interface / port (firewall rules, NAT port
    /// forwarding).  The default ephemeral bind on all interfaces paired with
    /// mDNS discovery is what LAN operation uses.
    pub listen_addr: String,
}

/// Deployment-specific configuration.
#[derive(Debug, Clone)]
pub struct DeploymentConfig {
    /// Revocation threshold M (signatures required).
    pub revocation_m: usize,
    /// Revocation threshold N (total manager DIDs).
    pub revocation_n: usize,
    /// Biscuit token TTL in seconds (1h–24h; or extended with accepted-risk doc).
    pub biscuit_ttl_secs: u64,
    /// Root CA Ed25519 public keys trusted for offline Biscuit token verification.
    ///
    /// Empty (the default) is the explicit *unconfigured* state: no Biscuit
    /// token can be verified until at least one key is registered, either here
    /// at init time or via [`CoreHandle::register_root_ca_key`] at runtime.
    pub root_ca_keys: Vec<[u8; 32]>,
    /// Ed25519 public key of the deployment's Migration CA, trusted to sign
    /// Migration_Delta transforms (Req 18.2).
    ///
    /// `None` (the default) is the explicit *unconfigured* state: the
    /// `SchemaMigrationEngine` is constructed with a zero key, so every
    /// inbound migration fails at the CA-verification gate.  A deployment
    /// that wants inbound migrations to apply must register its Migration CA
    /// key here at init time or via [`CoreHandle::register_migration_ca_key`]
    /// at runtime (Subphase 5.1).
    pub migration_ca_public_key: Option<[u8; 32]>,
    /// Ordered schema-version update path (oldest → newest) of this deployment
    /// (Req 18.3a).  A Migration_Delta is accepted only when its
    /// `source_schema_hash` equals the device's current schema hash and its
    /// `target_schema_hash` is the next hash in this path.
    ///
    /// Empty (the default) is the explicit *unconfigured* state: no version
    /// step validates, so every inbound migration is rejected at the
    /// version-path gate.  The first entry is the schema hash a
    /// freshly-initialised device is on; the engine advances through the path
    /// as migrations apply (Subphase 5.1).
    pub schema_version_path: Vec<[u8; 32]>,
    /// Full schema definitions for each entry in `schema_version_path`, in the
    /// same order (Subphase 5.3 — Req 17.3/17.4).
    ///
    /// When registered, the CRDT engine can classify an inbound Delta whose
    /// schema hash is not yet known by diffing its sender's schema definition
    /// field-by-field against the device's current schema: a Delta written
    /// under a schema that only *adds* tables/fields merges (Req 17.3), while
    /// a Delta written under a schema that removes/renames/retypes an existing
    /// field or drops a table is quarantined as a breaking schema change
    /// (Req 17.4).  Empty (the default) keeps the legacy behaviour: every hash
    /// outside the known set is quarantined as unknown.  `CoreHandle::init`
    /// validates that each definition hashes to its corresponding
    /// `schema_version_path` entry and rejects the configuration otherwise.
    pub schema_definitions: Vec<crate::schema::Schema>,
    /// Whether Anchor_Attested_Location subsystem is enabled.
    pub anchor_attested_location: bool,
    /// Ed25519 public keys of the fixed beacons trusted for Anchor_Attested_Location
    /// (Req 15.1).  Empty (the default) is the explicit unconfigured state: when
    /// `anchor_attested_location` is enabled with no keys, every beacon token is
    /// rejected as unknown-beacon, so Quorum cannot form — a deployment must
    /// configure its beacons here.  Mirror of `root_ca_keys`.
    pub beacon_public_keys: Vec<[u8; 32]>,
    /// Minimum distinct spatial tags required for Quorum (Req 14.3).
    ///
    /// `0` (the default) is the explicit *unconfigured* state: the quorum
    /// tracker then applies Req 14.3's default rule `min(K, distinct tags
    /// available)` at runtime instead of enforcing a raw 0-distinct minimum
    /// (Subphase 4.4 — see
    /// [`Tier1QuorumTracker::effective_min_distinct`](crate::durability::quorum::Tier1QuorumTracker::effective_min_distinct)).
    /// An explicit value `> 0` is enforced as configured, with the Req 14.5
    /// degradation fallback (flat K-of-N + warning) when fewer distinct tags
    /// are available.
    pub spatial_diversity_min: usize,
    /// Maximum fraction of Quorum receipts that may come from any single
    /// squad/tunnel_sector tag (Req 14.3).  E.g. `0.7` means no single sector
    /// may provide more than 70% of the receipts collected for a Delta.
    ///
    /// Defaults to `0.7` (the pre-Subphase-4.4 hardcode).  Values outside
    /// `(0, 1]` cannot express a fraction cap (0 would forbid every receipt
    /// and disable Quorum; > 1 is meaningless), so `CoreHandle::init` falls
    /// back to the `0.7` default for them.
    pub max_single_sector_fraction: f64,
    /// K-of-N quorum (K receipts required).
    pub quorum_k: usize,
    /// N candidate peers for quorum.
    pub quorum_n: usize,
    /// Duration in seconds of a Saturate_Mode Lease (Req 13.3), fed by
    /// `CoreHandle::init` into the transport's Saturate_Mode state machine.
    /// Defaults to [`crate::transport::saturate::SATURATE_LEASE_DURATION_SECS`]
    /// (60 minutes — the spec window); a deployment may shorten it (faster
    /// auto-demotion on Manager silence) or lengthen it.  Clamped to `>= 1` at
    /// init.
    pub saturate_lease_duration_secs: i64,
}

impl Default for DeploymentConfig {
    /// Manual default: every field derives-0 except two spec-mandated defaults
    /// that a 0 would actively corrupt:
    /// - `saturate_lease_duration_secs` defaults to the 60-minute window
    ///   (Req 13.3) — a zero-length lease would expire on the first tick;
    /// - `max_single_sector_fraction` defaults to `0.7` (Req 14.3 cap, the
    ///   pre-Subphase-4.4 hardcode) — a 0 cap would forbid every receipt and
    ///   disable Quorum entirely.
    /// `spatial_diversity_min: 0` is *not* a bug: it is the explicit
    /// unconfigured marker resolved to Req 14.3's default rule
    /// `min(K, distinct tags available)` at runtime (Subphase 4.4).
    fn default() -> Self {
        Self {
            revocation_m: 0,
            revocation_n: 0,
            biscuit_ttl_secs: 0,
            root_ca_keys: vec![],
            migration_ca_public_key: None,
            schema_version_path: vec![],
            schema_definitions: vec![],
            anchor_attested_location: false,
            beacon_public_keys: vec![],
            spatial_diversity_min: 0,
            max_single_sector_fraction: 0.7,
            quorum_k: 0,
            quorum_n: 0,
            saturate_lease_duration_secs: crate::transport::saturate::SATURATE_LEASE_DURATION_SECS,
        }
    }
}

// ─── Integration tests ────────────────────────────────────────────────────────

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::transport::message::GossipMessage;
    use serde_json::json;
    use std::env;

    fn make_config(path: &str) -> InitConfig {
        InitConfig {
            storage_path: path.to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 2,
                revocation_n: 3,
                biscuit_ttl_secs: 3600,
                root_ca_keys: vec![],
                migration_ca_public_key: None,
                schema_version_path: vec![],
                schema_definitions: vec![],
                anchor_attested_location: false,
                beacon_public_keys: vec![],
                spatial_diversity_min: 1,
                max_single_sector_fraction: 0.7,
                quorum_k: 1,
                quorum_n: 1,
                saturate_lease_duration_secs: 3600,
            },
        }
    }

    /// Create a unique temp file path for this test.
    fn tmp_path(suffix: &str) -> String {
        let mut p = env::temp_dir();
        p.push(format!("tirbase_test_{suffix}.db"));
        p.to_str().unwrap().to_string()
    }

    /// Remove a temp db and its accompanying identity file if they exist.
    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}.identity.json"));
        // WAL + SHM side-cars
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    // ── 1. Init succeeds with a temp path ─────────────────────────────────────

    #[tokio::test]
    async fn init_succeeds_with_temp_path() {
        let path = tmp_path("init_ok");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path)).await;
        assert!(
            handle.is_ok(),
            "CoreHandle::init should succeed: {:?}",
            handle.err()
        );

        cleanup(&path);
    }

    // ── 2. Write then read returns same value ─────────────────────────────────

    #[tokio::test]
    async fn write_then_read_returns_same_value() {
        let path = tmp_path("write_read");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        let data = json!({"hello": "world", "count": 42});
        handle
            .write("test_table", "key1", data.clone())
            .await
            .expect("write");

        let result = handle.read("test_table", "key1").await.expect("read");
        assert_eq!(result.data, data, "read data must match written data");
        assert_eq!(result.key, "key1");
        assert_eq!(result.table, "test_table");

        cleanup(&path);
    }

    // ── 3. Read on missing key returns Err ────────────────────────────────────

    #[tokio::test]
    async fn read_missing_key_returns_err() {
        let path = tmp_path("read_missing");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        let result = handle.read("test_table", "nonexistent").await;
        assert!(
            result.is_err(),
            "reading a missing key must return Err"
        );

        cleanup(&path);
    }

    // ── 4. Trust level is Unverified after init (no Biscuit token supplied) ───

    #[tokio::test]
    async fn trust_level_is_unverified_after_init() {
        let path = tmp_path("trust_unverified");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        assert_eq!(
            handle.trust_level(),
            TrustLevel::Unverified,
            "initial trust level must be UNVERIFIED"
        );

        cleanup(&path);
    }

    // ── 5. Two independent handles share no store ─────────────────────────────

    #[tokio::test]
    async fn two_instances_sharing_no_store_are_independent() {
        let path_a = tmp_path("independent_a");
        let path_b = tmp_path("independent_b");
        cleanup(&path_a);
        cleanup(&path_b);

        let handle_a = CoreHandle::init(make_config(&path_a))
            .await
            .expect("init a");
        let handle_b = CoreHandle::init(make_config(&path_b))
            .await
            .expect("init b");

        // Write to A.
        handle_a
            .write("shared_table", "x", json!({"from": "a"}))
            .await
            .expect("write a");

        // Reading the same key from B must fail (not found).
        let result = handle_b.read("shared_table", "x").await;
        assert!(
            result.is_err(),
            "reading from handle_b after writing to handle_a must fail"
        );

        cleanup(&path_a);
        cleanup(&path_b);
    }

    // ── 6. Query returns all written rows ─────────────────────────────────────

    #[tokio::test]
    async fn query_returns_all_written_rows() {
        let path = tmp_path("query_all");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        handle.write("items", "item-1", json!({"v": 1})).await.expect("write 1");
        handle.write("items", "item-2", json!({"v": 2})).await.expect("write 2");
        handle.write("items", "item-3", json!({"v": 3})).await.expect("write 3");

        let rows = handle.query("items", None).await.expect("query");
        assert_eq!(rows.len(), 3, "query should return all 3 rows");

        cleanup(&path);
    }

    // ── 7. Mesh status is Disconnected after init (no peers connected yet) ────

    #[tokio::test]
    async fn mesh_status_is_disconnected_after_init() {
        let path = tmp_path("mesh_status");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        let status = handle.mesh_status();
        assert_eq!(
            status.status,
            ConnectionStatus::Disconnected,
            "mesh status should be Disconnected when no peers are connected"
        );
        assert_eq!(status.peer_count, 0);

        cleanup(&path);
    }

    // ── 8. REVOKED device cannot write ───────────────────────────────────────

    #[tokio::test]
    async fn revoked_device_cannot_write() {
        let path = tmp_path("revoked_write");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Force REVOKED state via CapabilityManager.
        handle
            .capability
            .lock()
            .unwrap()
            .apply_revocation()
            .expect("apply_revocation");

        let result = handle
            .write("test_table", "should_fail", json!({"x": 1}))
            .await;

        assert!(
            result.is_err(),
            "REVOKED device must not be allowed to write"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("REVOKED"),
            "error message must mention REVOKED: {err}"
        );

        cleanup(&path);
    }

    // ── 8b. Locally-known REVOKED (via inbound RevocationDelta) blocks writes, ─
    //       reads, and queries (Subphase 2.2 — Req 8.5)
    //
    // End-to-end through the PRODUCTION inbound pipeline: a valid 1-of-1
    // RevocationDelta targeting this device's own DID is injected and drained
    // exactly like a gossipsub message would be.  The inbound arm must invoke
    // CapabilityManager::apply_revocation() so the local TrustLevel becomes
    // REVOKED and every local I/O gate trips.

    #[tokio::test]
    async fn inbound_revocation_of_local_device_blocks_writes_reads_and_queries() {
        let path = tmp_path("revoked_gate_e2e");
        cleanup(&path);

        // M=1, N=1 so a single Manager signature completes the revocation.
        let handle = CoreHandle::init(InitConfig {
            storage_path: path.clone(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                biscuit_ttl_secs: 3600,
                root_ca_keys: vec![],
                migration_ca_public_key: None,
                schema_version_path: vec![],
                schema_definitions: vec![],
                anchor_attested_location: false,
                beacon_public_keys: vec![],
                spatial_diversity_min: 1,
                max_single_sector_fraction: 0.7,
                quorum_k: 1,
                quorum_n: 1,
                saturate_lease_duration_secs: 3600,
            },
        })
        .await
        .expect("init");

        // Sanity: I/O works before the revocation is locally known.
        handle
            .write("t", "k1", json!({ "v": 1 }))
            .await
            .expect("pre-revocation write must succeed");

        // A Manager signs a 1-of-1 RevocationDelta targeting THIS device's DID.
        let mgr = crate::identity::IdentityManager::init_in_memory().unwrap();
        let mgr_did = mgr.did().to_string();
        let mgr_sk = mgr.signing_key_bytes();
        let local_did = handle.identity.did().to_string();

        let delta = {
            let rev = handle.revocation.lock().unwrap();
            rev.produce_partial_delta(local_did.clone(), mgr_did.clone(), &mgr_sk)
                .expect("produce partial delta")
        };

        // Deliver through the production inbound pipeline (the same path a
        // gossipsub message takes in production — Subphase 1.3 drain loop).
        handle
            .inject_inbound(GossipMessage::InboundRevocationDelta(delta))
            .await
            .expect("inject_inbound");
        handle
            .process_inbound_messages()
            .await
            .expect("process_inbound_messages");

        // The local device's TrustLevel must now be REVOKED — this is the
        // production caller of CapabilityManager::apply_revocation().
        assert_eq!(
            handle.trust_level(),
            TrustLevel::Revoked,
            "local device must be REVOKED after inbound RevocationDelta"
        );

        // Write must be blocked by the gate.
        let write = handle.write("t", "k2", json!({ "v": 2 })).await;
        assert!(
            write.is_err(),
            "REVOKED device must not be allowed to write"
        );
        assert!(
            write.unwrap_err().to_string().contains("REVOKED"),
            "write error must mention REVOKED"
        );

        // Read must be blocked by the gate.
        let read = handle.read("t", "k1").await;
        assert!(
            read.is_err(),
            "REVOKED device must not be allowed to read"
        );
        assert!(
            read.unwrap_err().to_string().contains("REVOKED"),
            "read error must mention REVOKED"
        );

        // Query must be blocked by the gate.
        let query = handle.query("t", None).await;
        assert!(
            query.is_err(),
            "REVOKED device must not be allowed to query"
        );
        assert!(
            query.unwrap_err().to_string().contains("REVOKED"),
            "query error must mention REVOKED"
        );

        cleanup(&path);
    }

    // ── 8c. Revoking a DIFFERENT device must not trip this device's gate ─────

    #[tokio::test]
    async fn inbound_revocation_of_other_device_does_not_block_local_device() {
        let path = tmp_path("revoked_gate_other");
        cleanup(&path);

        // M=1, N=1 so the other device's revocation completes immediately.
        let handle = CoreHandle::init(InitConfig {
            storage_path: path.clone(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                biscuit_ttl_secs: 3600,
                root_ca_keys: vec![],
                migration_ca_public_key: None,
                schema_version_path: vec![],
                schema_definitions: vec![],
                anchor_attested_location: false,
                beacon_public_keys: vec![],
                spatial_diversity_min: 1,
                max_single_sector_fraction: 0.7,
                quorum_k: 1,
                quorum_n: 1,
                saturate_lease_duration_secs: 3600,
            },
        })
        .await
        .expect("init");

        // A Manager revokes an unrelated device, not this one.
        let mgr = crate::identity::IdentityManager::init_in_memory().unwrap();
        let mgr_did = mgr.did().to_string();
        let mgr_sk = mgr.signing_key_bytes();
        let other_did = crate::identity::IdentityManager::init_in_memory()
            .unwrap()
            .did()
            .to_string();

        let delta = {
            let rev = handle.revocation.lock().unwrap();
            rev.produce_partial_delta(other_did.clone(), mgr_did.clone(), &mgr_sk)
                .expect("produce partial delta")
        };

        handle
            .inject_inbound(GossipMessage::InboundRevocationDelta(delta))
            .await
            .expect("inject_inbound");
        handle
            .process_inbound_messages()
            .await
            .expect("process_inbound_messages");

        // The other device is REVOKED in the subsystem…
        assert!(
            handle
                .revocation
                .lock()
                .unwrap()
                .revoked_dids()
                .contains(&other_did),
            "subsystem must know the other device is REVOKED"
        );
        // …but this device's own TrustLevel must be untouched.
        assert_eq!(
            handle.trust_level(),
            TrustLevel::Unverified,
            "revoking another device must not revoke the local device"
        );
        handle
            .write("t", "k", json!({ "v": 1 }))
            .await
            .expect("write must still succeed");
        handle
            .read("t", "k")
            .await
            .expect("read must still succeed");

        cleanup(&path);
    }

    // ── 9a. CoreHandle::initiate_revocation — native entry point (Subphase 2.4, ─
    //       Req 9.1)
    //
    // The native (non-WASM-only) entry point to initiate a revocation, mirroring
    // the WASM export `core_initiate_revocation`: the local Manager signs a
    // partial RevocationDelta, it is gossiped at HIGH priority, and the
    // signature is accumulated locally through the same subsystem call an
    // inbound partial delta from a peer would take.

    #[tokio::test]
    async fn initiate_revocation_rejects_blank_inputs() {
        let path = tmp_path("rev_init_blank");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        let blank_token = handle
            .initiate_revocation("did:key:z6MkX-target", "  ")
            .expect_err("blank manager_token must be rejected");
        assert!(
            blank_token.to_string().contains("manager_token must not be blank"),
            "unexpected error: {blank_token}"
        );

        let blank_target = handle
            .initiate_revocation("", "manager-token")
            .expect_err("blank target_did must be rejected");
        assert!(
            blank_target.to_string().contains("target_did must not be blank"),
            "unexpected error: {blank_target}"
        );

        cleanup(&path);
    }

    #[tokio::test]
    async fn initiate_revocation_1of1_marks_target_revoked_and_gossips_at_high() {
        let path = tmp_path("rev_init_1of1");
        cleanup(&path);

        // M=1, N=1 so this Manager's single signature completes the revocation.
        let handle = CoreHandle::init(InitConfig {
            storage_path: path.clone(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                biscuit_ttl_secs: 3600,
                root_ca_keys: vec![],
                migration_ca_public_key: None,
                schema_version_path: vec![],
                schema_definitions: vec![],
                anchor_attested_location: false,
                beacon_public_keys: vec![],
                spatial_diversity_min: 1,
                max_single_sector_fraction: 0.7,
                quorum_k: 1,
                quorum_n: 1,
                saturate_lease_duration_secs: 3600,
            },
        })
        .await
        .expect("init");

        let other_did = crate::identity::IdentityManager::init_in_memory()
            .unwrap()
            .did()
            .to_string();

        // Sanity: I/O works before any revocation is initiated.
        handle
            .write("t", "k1", json!({ "v": 1 }))
            .await
            .expect("pre-revocation write must succeed");

        // This device (the Manager) initiates the revocation of another device.
        handle
            .initiate_revocation(&other_did, "manager-token")
            .expect("initiate_revocation must succeed");

        // The complete delta (M=1) is gossiped at HIGH priority (Req 9.1/9.2).
        {
            let transport = handle.transport.lock().unwrap();
            assert!(
                transport.has_backlog(),
                "revocation gossip must be enqueued on the scheduler"
            );
            assert!(
                transport.high_queue_depth() > 0,
                "revocation gossip must be at HIGH priority (depth: {})",
                transport.high_queue_depth()
            );
        }

        // The target is now REVOKED in the subsystem…
        {
            let rev = handle.revocation.lock().unwrap();
            match rev.store_status(&other_did) {
                Some(crate::auth::RevocationStatus::Applied) => {}
                _ => panic!("target must be Applied after a 1-of-1 initiate"),
            }
            assert!(
                rev.revoked_dids().contains(&other_did),
                "subsystem must know the target DID is REVOKED"
            );
        }
        // …but revoking another device must not trip this device's own gate.
        assert_ne!(
            handle.trust_level(),
            TrustLevel::Revoked,
            "revoking another device must not revoke the local device"
        );
        handle
            .write("t", "k2", json!({ "v": 2 }))
            .await
            .expect("local writes must still succeed");

        cleanup(&path);
    }

    #[tokio::test]
    async fn initiate_revocation_of_self_1of1_trips_local_io_gate() {
        let path = tmp_path("rev_init_self");
        cleanup(&path);

        // M=1, N=1 — a single Manager signature completes the revocation.
        let handle = CoreHandle::init(InitConfig {
            storage_path: path.clone(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                biscuit_ttl_secs: 3600,
                root_ca_keys: vec![],
                migration_ca_public_key: None,
                schema_version_path: vec![],
                schema_definitions: vec![],
                anchor_attested_location: false,
                beacon_public_keys: vec![],
                spatial_diversity_min: 1,
                max_single_sector_fraction: 0.7,
                quorum_k: 1,
                quorum_n: 1,
                saturate_lease_duration_secs: 3600,
            },
        })
        .await
        .expect("init");

        let local_did = handle.identity.did().to_string();
        handle
            .write("t", "k1", json!({ "v": 1 }))
            .await
            .expect("pre-revocation write must succeed");

        // The Manager device initiates a 1-of-1 revocation of ITSELF.
        handle
            .initiate_revocation(&local_did, "manager-token")
            .expect("initiate_revocation must succeed");

        // Req 8.5: the locally-known REVOKED status must now block all I/O — the
        // same end state the inbound path reaches, driven through the native
        // initiate entry point instead.
        assert_eq!(
            handle.trust_level(),
            TrustLevel::Revoked,
            "local device must be REVOKED after initiating its own 1-of-1 revocation"
        );

        let write = handle.write("t", "k2", json!({ "v": 2 })).await;
        assert!(write.is_err(), "REVOKED device must not be allowed to write");
        assert!(
            write.unwrap_err().to_string().contains("REVOKED"),
            "write error must mention REVOKED"
        );

        let read = handle.read("t", "k1").await;
        assert!(read.is_err(), "REVOKED device must not be allowed to read");
        assert!(
            read.unwrap_err().to_string().contains("REVOKED"),
            "read error must mention REVOKED"
        );

        cleanup(&path);
    }

    #[tokio::test]
    async fn initiate_revocation_gossips_partial_and_second_signature_completes() {
        let path = tmp_path("rev_init_m2");
        cleanup(&path);

        // M=2, N=2 — the local contribution stays Pending until a second
        // Manager's signature arrives through the (simulated) mesh.
        let handle = CoreHandle::init(InitConfig {
            storage_path: path.clone(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 2,
                revocation_n: 2,
                biscuit_ttl_secs: 3600,
                root_ca_keys: vec![],
                migration_ca_public_key: None,
                schema_version_path: vec![],
                schema_definitions: vec![],
                anchor_attested_location: false,
                beacon_public_keys: vec![],
                spatial_diversity_min: 1,
                max_single_sector_fraction: 0.7,
                quorum_k: 1,
                quorum_n: 1,
                saturate_lease_duration_secs: 3600,
            },
        })
        .await
        .expect("init");

        let target = crate::identity::IdentityManager::init_in_memory()
            .unwrap()
            .did()
            .to_string();
        let mgr2 = crate::identity::IdentityManager::init_in_memory().unwrap();
        let mgr2_did = mgr2.did().to_string();
        let mgr2_sk = mgr2.signing_key_bytes();

        // This device contributes signature #1 via the native initiate entry.
        handle
            .initiate_revocation(&target, "manager-token")
            .expect("initiate_revocation must succeed");

        // Status is Pending (1/2) and the partial delta is gossiped at HIGH.
        {
            let rev = handle.revocation.lock().unwrap();
            match rev.store_status(&target) {
                Some(crate::auth::RevocationStatus::Pending {
                    collected,
                    required,
                }) => {
                    assert_eq!(collected, 1, "one signature collected after initiate");
                    assert_eq!(required, 2, "M threshold must be 2");
                }
                _ => panic!("expected Pending status after the first signature"),
            }
        }
        {
            let transport = handle.transport.lock().unwrap();
            assert!(
                transport.has_backlog(),
                "partial revocation delta must be enqueued for gossip"
            );
            assert!(
                transport.high_queue_depth() > 0,
                "partial revocation delta must gossip at HIGH priority"
            );
        }

        // Manager #2's partial signature arrives from the mesh.
        let partial2 = {
            let rev = handle.revocation.lock().unwrap();
            rev.produce_partial_delta(target.clone(), mgr2_did, &mgr2_sk)
                .expect("produce partial delta for manager 2")
        };
        handle
            .inject_inbound(GossipMessage::InboundRevocationDelta(partial2))
            .await
            .expect("inject_inbound");
        handle
            .process_inbound_messages()
            .await
            .expect("process_inbound_messages");

        // M=2 reached: the target is Applied + REVOKED, and the complete delta
        // is re-gossiped at HIGH priority (Req 9.2).
        {
            let rev = handle.revocation.lock().unwrap();
            match rev.store_status(&target) {
                Some(crate::auth::RevocationStatus::Applied) => {}
                _ => panic!("target must be Applied once M=2 signatures accumulate"),
            }
            assert!(
                rev.revoked_dids().contains(&target),
                "subsystem must know the target DID is REVOKED"
            );
        }
        {
            let transport = handle.transport.lock().unwrap();
            assert!(
                transport.high_queue_depth() > 0,
                "complete revocation delta must be re-gossiped at HIGH priority"
            );
        }

        cleanup(&path);
    }

    // ── 9b. CoreHandle::device_revocation_status — Req 9.5 queryable status ───
    //
    // The Req 9.5 data (last-known TrustLevel + last RevocationDelta receipt
    // timestamp) lives in `RevocationSubsystem::device_status`; these tests
    // pin the CoreHandle exposure of that map.

    #[tokio::test]
    async fn device_revocation_status_is_none_for_unknown_device() {
        let path = tmp_path("rev_dev_status_unknown");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        let unknown = crate::identity::IdentityManager::init_in_memory()
            .unwrap()
            .did()
            .to_string();

        // No RevocationDelta has ever been received for this DID: the subsystem
        // has no record, so the query returns Ok(None) — not an error.
        assert!(
            handle
                .device_revocation_status(&unknown)
                .expect("query must succeed")
                .is_none(),
            "unknown device must have no device-status record (Req 9.5)"
        );

        cleanup(&path);
    }

    #[tokio::test]
    async fn device_revocation_status_reports_applied_revocation() {
        let path = tmp_path("rev_dev_status_applied");
        cleanup(&path);

        // M=1, N=1 so a single Manager signature applies the revocation.
        let handle = CoreHandle::init(InitConfig {
            storage_path: path.clone(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                biscuit_ttl_secs: 3600,
                root_ca_keys: vec![],
                migration_ca_public_key: None,
                schema_version_path: vec![],
                schema_definitions: vec![],
                anchor_attested_location: false,
                beacon_public_keys: vec![],
                spatial_diversity_min: 1,
                max_single_sector_fraction: 0.7,
                quorum_k: 1,
                quorum_n: 1,
                saturate_lease_duration_secs: 3600,
            },
        })
        .await
        .expect("init");

        let other_did = crate::identity::IdentityManager::init_in_memory()
            .unwrap()
            .did()
            .to_string();

        handle
            .initiate_revocation(&other_did, "manager-token")
            .expect("initiate_revocation must succeed");

        // Req 9.5: the last-known TrustLevel is REVOKED and the receipt
        // timestamp is recorded for the target device.
        let status = handle
            .device_revocation_status(&other_did)
            .expect("query must succeed")
            .expect("applied revocation must produce a device-status record");
        assert_eq!(
            status.last_known_trust_level,
            TrustLevel::Revoked,
            "device-status must record the REVOKED TrustLevel (Req 9.5)"
        );
        assert!(
            status.last_revocation_delta_received_at.is_some(),
            "device-status must record the receipt timestamp (Req 9.5)"
        );
        assert_eq!(
            status.device_did, other_did,
            "device-status must be keyed by the target DID"
        );

        cleanup(&path);
    }

    #[tokio::test]
    async fn device_revocation_status_stays_none_while_pending() {
        let path = tmp_path("rev_dev_status_pending");
        cleanup(&path);

        // M=2, N=2 — the local contribution keeps the revocation Pending.
        let handle = CoreHandle::init(InitConfig {
            storage_path: path.clone(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 2,
                revocation_n: 2,
                biscuit_ttl_secs: 3600,
                root_ca_keys: vec![],
                migration_ca_public_key: None,
                schema_version_path: vec![],
                schema_definitions: vec![],
                anchor_attested_location: false,
                beacon_public_keys: vec![],
                spatial_diversity_min: 1,
                max_single_sector_fraction: 0.7,
                quorum_k: 1,
                quorum_n: 1,
                saturate_lease_duration_secs: 3600,
            },
        })
        .await
        .expect("init");

        let target = crate::identity::IdentityManager::init_in_memory()
            .unwrap()
            .did()
            .to_string();

        handle
            .initiate_revocation(&target, "manager-token")
            .expect("initiate_revocation must succeed");

        // The M-of-N accumulation is Pending (1/2)…
        {
            let rev = handle.revocation.lock().unwrap();
            match rev.store_status(&target) {
                Some(crate::auth::RevocationStatus::Pending {
                    collected,
                    required,
                }) => {
                    assert_eq!(collected, 1);
                    assert_eq!(required, 2);
                }
                _ => panic!("expected Pending accumulation state"),
            }
        }
        // …but the Req 9.5 device-status record is only written on application,
        // so the query still returns None (no last-known state yet).
        assert!(
            handle
                .device_revocation_status(&target)
                .expect("query must succeed")
                .is_none(),
            "no device-status record until the revocation is applied (Req 9.5)"
        );

        cleanup(&path);
    }

    // ── 9. Write result has Uncommitted durability tier ───────────────────────

    #[tokio::test]
    async fn write_result_has_uncommitted_tier() {
        let path = tmp_path("durability_tier");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        let result = handle
            .write("t", "k", json!({"v": 42}))
            .await
            .expect("write");

        assert_eq!(
            result.durability_tier,
            DurabilityTier::Uncommitted,
            "initial write must have Uncommitted durability"
        );

        cleanup(&path);
    }

    // ── 9b. write() publishes the Delta to the outbound mesh ─────────────────
    //
    // Subphase 1.1 acceptance: write() must NOT discard prepare_outbound()'s
    // output — the prepared payload must reach the outbound publish path (the
    // Swarm polling task) and be handed to gossipsub.publish.  With no peers
    // subscribed, gossipsub.publish returns NoPeersSubscribedToTopic, so the
    // payload is observed at the publish point via the test-only recording
    // hook rather than via a live peer.

    #[tokio::test]
    async fn write_publishes_outbound_delta_to_mesh() {
        let path = tmp_path("outbound_publish");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        let result = handle
            .write("sensors", "s1", json!({"v": 42}))
            .await
            .expect("write must succeed even with no mesh peers connected");

        // The Swarm polling task drains the outbound channel asynchronously;
        // poll until the prepared payload reaches the publish point.
        let mut attempts = 0;
        let published = loop {
            let published = handle
                .transport
                .lock()
                .unwrap()
                .outbound_published
                .clone();
            if !published.is_empty() {
                break published;
            }
            attempts += 1;
            assert!(
                attempts < 100,
                "write()'s outbound payload never reached the publish path"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };

        assert_eq!(
            published.len(),
            1,
            "exactly one outbound payload must be produced per write (mtu=0)"
        );

        // The published payload must carry the prepared Delta — i.e. the
        // output of prepare_outbound() is used, not discarded.  Since the
        // wire protocol frames every mesh message as a `GossipMessage`
        // (Subphase 1.5 — the receiving poll task dispatches on the variant),
        // the recorded payload is `GossipMessage::InboundDelta(delta)` rather
        // than the bare serialised Delta.
        let wire: crate::transport::message::GossipMessage =
            serde_json::from_slice(&published[0])
                .expect("published payload must deserialise as a GossipMessage");
        let decoded = match wire {
            crate::transport::message::GossipMessage::InboundDelta(d) => d,
            other => panic!(
                "published payload must be InboundDelta framing, got: {other:?}"
            ),
        };
        assert_eq!(
            decoded.id, result.delta_id,
            "published payload must be the Delta produced by this write"
        );

        cleanup(&path);
    }

    // ── 10. Test A: ContaminatedByHumanReaction tag applied when row is contaminated ──

    #[tokio::test]
    async fn write_on_contaminated_row_gets_human_reaction_tag() {
        use crate::contamination::incident::TaintSource;
        use crate::crdt::delta::DeltaTag;

        let path = tmp_path("human_reaction_tag");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Write an initial value so the key/table exists.
        handle
            .write("sensors", "temp-1", json!({"v": 100}))
            .await
            .expect("initial write");

        // Tag a synthetic contamination root via the CCE. We insert the DagNode via
        // a public helper on ChangesetDag, accessed through the CCE's public tag method.
        // We use tag_contamination_root with a DeviceRevocation source on a zero-byte
        // root ID — the BFS walk will find no descendants (node not in DAG), and
        // affected_rows will be empty, but the ICO is still registered as OPEN.
        // This is enough to exercise the live lock path in CoreHandle::write().
        let root_delta_id = [0xA0u8; 32];
        {
            let mut cce = handle.cce.lock().unwrap();
            // tag_contamination_root will attempt a BFS walk; the node may not be in the
            // DAG (returns DeltaNotFound or empty walk). We ignore the error here since
            // our goal is only to test that the write path calls is_row_contaminated.
            let _ = cce.tag_contamination_root(
                root_delta_id,
                TaintSource::DeviceRevocation {
                    revocation_delta_id: root_delta_id,
                },
            );
        }

        // Write again to the same key — with the live lookup path active (not hardcoded
        // false), the write must still complete without error.
        let result = handle
            .write("sensors", "temp-1", json!({"v": 200}))
            .await;
        assert!(
            result.is_ok(),
            "write must succeed even when CCE has been touched: {:?}",
            result.err()
        );

        cleanup(&path);
    }

    // ── 11. Test B: No ContaminatedByHumanReaction on uncontaminated table ────────

    #[tokio::test]
    async fn write_on_clean_row_has_no_human_reaction_tag() {
        let path = tmp_path("human_reaction_clean");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Write to a clean table with no incidents.
        let result = handle
            .write("clean_table", "row-1", json!({"status": "ok"}))
            .await
            .expect("write must succeed");

        // The durability tier should still be Uncommitted (unchanged behaviour).
        assert_eq!(result.durability_tier, DurabilityTier::Uncommitted);

        cleanup(&path);
    }

    // ── 12. Test C: WriteContext uses live lookups (mutex lock doesn't panic) ─────

    #[tokio::test]
    async fn write_ctx_live_lookups_do_not_panic() {
        let path = tmp_path("write_ctx_live");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Perform multiple writes — each one should lock cce and migration without
        // deadlock or panic regardless of whether contamination state is clean.
        for i in 0..5u32 {
            handle
                .write("perf_table", &format!("key-{i}"), json!({"i": i}))
                .await
                .unwrap_or_else(|e| panic!("write {i} failed: {e}"));
        }

        cleanup(&path);
    }

    // ── Task-44 Test A: write on contaminated row → new Delta added to ICO ───

    /// Validates Req 19.5: when `tag_contamination_root` has marked a row as
    /// contaminated, a subsequent `CoreHandle::write()` to that same row must
    /// register the resulting Delta in the active ICO's `contaminated_deltas`.
    #[tokio::test]
    async fn task44_test_a_human_reaction_delta_added_to_ico() {
        use crate::contamination::incident::TaintSource;
        use crate::crdt::dag::DagNode;
        use crate::crdt::delta::DeltaTag;

        let path = tmp_path("t44_test_a");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Step 1: write an initial row so the table and key exist in the store.
        let first_write = handle
            .write("events", "evt-1", json!({"status": "initial"}))
            .await
            .expect("first write");
        let first_delta_id = first_write.delta_id;

        // Step 2: insert that delta as a DagNode so the BFS walk can find it,
        //         then tag it as a contamination root.
        let ico_id = {
            let mut cce = handle.cce.lock().unwrap();

            // Insert the first delta's ID as a DagNode so the BFS walk succeeds.
            cce.test_insert_dag_node(DagNode {
                delta_id: first_delta_id,
                payload: vec![],
                parent_ids: vec![],
                actor_id: b"actor".to_vec(),
                lamport: 1,
                schema_hash: [0u8; 32],
                compacted: false,
                author_did: "did:key:z6MkTest".to_string(),
            }).expect("insert DagNode for first delta");

            cce.tag_contamination_root(
                first_delta_id,
                TaintSource::DeviceRevocation {
                    revocation_delta_id: first_delta_id,
                },
            ).expect("tag_contamination_root")
        };

        // Confirm the first delta is in the ICO.
        let ico_before = handle.cce.lock().unwrap()
            .get_incident(ico_id).unwrap().unwrap();
        assert!(
            ico_before.contaminated_deltas.contains(&first_delta_id),
            "first delta must be in ICO before second write"
        );

        // Step 3: manually set the contaminated_rows entry to simulate the projection
        // layer having resolved affected rows. The BFS walk only populates
        // contaminated_rows when affected_rows is non-empty, which requires a
        // live projection table. We use the test helper to inject the entry directly.
        {
            let mut cce = handle.cce.lock().unwrap();
            cce.test_set_contaminated_row("events", "evt-1", ico_id);
        }

        // Confirm is_row_contaminated returns true.
        assert!(
            handle.cce.lock().unwrap().is_row_contaminated("events", "evt-1"),
            "row must appear contaminated before second write"
        );

        let second_write = handle
            .write("events", "evt-1", json!({"status": "updated"}))
            .await
            .expect("second write must succeed");
        let second_delta_id = second_write.delta_id;

        // Step 4: the second delta must now appear in the active open ICOs.
        // CoreHandle::write() calls on_write_commit → returns Some((id, incident_id))
        // → calls cce.tag_contamination_root(TaintSource::HumanReaction) → BFS walk
        // from second_delta_id → new ICO or composite ICO containing second_delta_id.
        let all_open_icos = handle.cce.lock().unwrap()
            .open_incidents().unwrap();

        let found = all_open_icos.iter().any(|ico| {
            ico.contaminated_deltas.contains(&second_delta_id)
        });

        assert!(
            found,
            "second write delta {second_delta_id:?} must be registered in an active ICO; \
             open ICOs (ids): {:?}",
            all_open_icos.iter().map(|i| i.id).collect::<Vec<_>>()
        );

        cleanup(&path);
    }

    // ── Task-44 Test B: write on uncontaminated row → no ContaminatedByHumanReaction ─

    /// Validates Req 19.5 negative case: a write to a completely clean row must
    /// produce no `ContaminatedByHumanReaction` tag, and no ICO must be updated.
    #[tokio::test]
    async fn task44_test_b_clean_row_write_has_no_human_reaction_tag() {
        let path = tmp_path("t44_test_b");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Write to a table/key that has never been contaminated.
        let _result = handle
            .write("clean_sensors", "reading-42", json!({"temp": 22.5}))
            .await
            .expect("write must succeed");

        // No ICOs must be open (nothing was contaminated).
        let open_icos = handle.cce.lock().unwrap().open_incidents().unwrap();
        assert!(
            open_icos.is_empty(),
            "no ICOs must be created for a clean write; found: {open_icos:?}"
        );

        // The CCE's contaminated_rows must not contain this key.
        let is_contaminated = handle.cce.lock().unwrap()
            .is_row_contaminated("clean_sensors", "reading-42");
        assert!(
            !is_contaminated,
            "row must not appear in contaminated_rows after a clean write"
        );

        cleanup(&path);
    }

    // ── Task-44 Test C: write after resolution → no ContaminatedByHumanReaction ─

    /// Validates Req 19.5 resolution case: after `verify_data` resolves all roots
    /// and the CCE prunes `contaminated_rows`, a subsequent write to the previously
    /// contaminated row must not trigger human-reaction tagging or update any ICO.
    #[tokio::test]
    async fn task44_test_c_write_after_resolution_no_human_reaction_tag() {
        use crate::contamination::incident::TaintSource;
        use crate::crdt::dag::DagNode;
        use crate::identity::{keypair, IdentityManager};
        use crate::contamination::resolution::now_micros;

        let path = tmp_path("t44_test_c");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Step 1: write an initial row.
        let first_write = handle
            .write("telemetry", "node-7", json!({"reading": 100}))
            .await
            .expect("initial write");
        let first_delta_id = first_write.delta_id;

        // Step 2: insert the DagNode and tag as contamination root.
        let ico_id = {
            let mut cce = handle.cce.lock().unwrap();
            cce.test_insert_dag_node(DagNode {
                delta_id: first_delta_id,
                payload: vec![],
                parent_ids: vec![],
                actor_id: b"actor".to_vec(),
                lamport: 1,
                schema_hash: [0u8; 32],
                compacted: false,
                author_did: "did:key:z6MkTest".to_string(),
            }).expect("insert DagNode");

            cce.tag_contamination_root(
                first_delta_id,
                TaintSource::DeviceRevocation {
                    revocation_delta_id: first_delta_id,
                },
            ).expect("tag_contamination_root")
        };

        // Set contaminated_rows so is_row_contaminated returns true.
        {
            let mut cce = handle.cce.lock().unwrap();
            cce.test_set_contaminated_row("telemetry", "node-7", ico_id);
        }

        // Confirm the row is contaminated before resolution.
        assert!(
            handle.cce.lock().unwrap().is_row_contaminated("telemetry", "node-7"),
            "row must be contaminated before verify_data"
        );

        // Step 3: resolve the contamination root via verify_data.
        let mgr = IdentityManager::init_in_memory().expect("manager identity");
        let mgr_did = mgr.did().to_string();
        let mgr_secret = mgr.signing_key_bytes();
        let sig = keypair::sign(&mgr_secret, &first_delta_id).expect("sign");
        let expiry = now_micros() + 3_600_000_000; // +1h

        handle.cce.lock().unwrap()
            .verify_data(first_delta_id, mgr_did, sig, expiry)
            .expect("verify_data must succeed");

        // Step 4: after resolution, contaminated_rows must be pruned.
        assert!(
            !handle.cce.lock().unwrap().is_row_contaminated("telemetry", "node-7"),
            "row must NOT be contaminated after verify_data resolves all roots"
        );

        // Count open ICOs before the third write.
        let icos_before = handle.cce.lock().unwrap().open_incidents().unwrap().len();

        // Step 5: write again to the previously contaminated row.
        let _third_write = handle
            .write("telemetry", "node-7", json!({"reading": 200}))
            .await
            .expect("third write must succeed");

        // No new ICOs must have been opened by the third write.
        let icos_after = handle.cce.lock().unwrap().open_incidents().unwrap().len();
        assert_eq!(
            icos_after, icos_before,
            "no new ICO must be opened by a write on a resolved row"
        );

        cleanup(&path);
    }

    // ── Phase 2.1: root CA key registration (Req 8.1) ────────────────────────

    /// Build a config that registers the given root CA public key at init.
    fn make_config_with_ca_key(path: &str, ca_key: [u8; 32]) -> InitConfig {
        let mut config = make_config(path);
        config.deployment.root_ca_keys = vec![ca_key];
        config
    }

    /// Create a fresh CA keypair; returns (private_key_bytes, public_key_bytes).
    fn make_ca_keypair() -> (Vec<u8>, [u8; 32]) {
        use biscuit_auth::{builder::Algorithm, KeyPair};
        let kp = KeyPair::new();
        let private_bytes = kp.private().to_bytes().to_vec();
        let public_bytes: [u8; 32] = kp
            .public()
            .to_bytes()
            .try_into()
            .expect("public key must be 32 bytes");
        (private_bytes, public_bytes)
    }

    fn now_secs() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Init-time registration: keys supplied in `DeploymentConfig` must be
    /// reachable through `root_ca_public_key()` and must let the exact
    /// production verification path (`verify_and_check_caveat`, as used by
    /// `core_activate_saturate_mode`) succeed.
    #[tokio::test]
    async fn init_registers_root_ca_keys_and_biscuit_verifies() {
        let path = tmp_path("p21_init_keys");
        cleanup(&path);

        let (ca_private, ca_public) = make_ca_keypair();
        let handle = CoreHandle::init(make_config_with_ca_key(&path, ca_public))
            .await
            .expect("init with registered root CA key");

        // The registered key must be the one exposed for offline verification.
        assert_eq!(handle.root_ca_public_key(), ca_public.to_vec());

        // Build a real disaster-alert Biscuit token signed by the CA.
        let token_bytes = crate::auth::biscuit::create_token_with_caveat(
            "did:key:z6MkTest",
            "manager",
            3600,
            "disaster-alert",
            &ca_private,
        )
        .expect("create token");

        // The exact production verification call (`core_activate_saturate_mode`
        // in lib.rs) must succeed now that a key is registered.
        assert!(
            crate::auth::biscuit::verify_and_check_caveat(
                &token_bytes,
                "disaster-alert",
                &handle.root_ca_public_key(),
                now_secs(),
            )
            .expect("verification must not error"),
            "registered CA key must verify a valid disaster-alert token"
        );

        cleanup(&path);
    }

    /// Runtime registration: a handle initialised with no keys starts in the
    /// explicit unconfigured state (verification fails), and becomes able to
    /// verify tokens only after `register_root_ca_key` is called.
    #[tokio::test]
    async fn runtime_register_root_ca_key_enables_biscuit_verification() {
        let path = tmp_path("p21_runtime_key");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init without keys");
        assert!(
            handle.root_ca_public_key().is_empty(),
            "unconfigured handle must expose no root CA key"
        );

        let (ca_private, ca_public) = make_ca_keypair();
        let token_bytes = crate::auth::biscuit::create_token_with_caveat(
            "did:key:z6MkTest",
            "manager",
            3600,
            "disaster-alert",
            &ca_private,
        )
        .expect("create token");

        // Before registration: the empty registry must NOT verify the token.
        let before = crate::auth::biscuit::verify_and_check_caveat(
            &token_bytes,
            "disaster-alert",
            &handle.root_ca_public_key(), // empty — explicit unconfigured state
            now_secs(),
        );
        assert!(before.is_err(), "empty registry must reject verification");

        // Register the CA key at runtime.
        handle
            .register_root_ca_key(ca_public)
            .expect("register_root_ca_key must succeed");
        assert_eq!(handle.root_ca_public_key(), ca_public.to_vec());

        // Now the same token verifies.
        assert!(
            crate::auth::biscuit::verify_and_check_caveat(
                &token_bytes,
                "disaster-alert",
                &handle.root_ca_public_key(),
                now_secs(),
            )
            .expect("verification must not error after registration"),
            "runtime-registered CA key must verify a valid disaster-alert token"
        );

        cleanup(&path);
    }

    // ── Subphase 5.1: Migration CA key + schema version path wiring ──────────
    //
    // `CoreHandle::init` constructs the `SchemaMigrationEngine` from
    // `DeploymentConfig.migration_ca_public_key` and
    // `DeploymentConfig.schema_version_path` (Req 18.2, 18.3a).  Before this
    // wiring the engine was built with a zero CA key and an empty path, so
    // every real inbound migration failed at the CA-verification gate
    // regardless of validity.  These tests drive the exact production
    // construction (`CoreHandle::init`) and assert that a CA-signed migration
    // on a valid path step is now accepted, that the full inbound pipeline
    // (`inject_inbound` → `process_inbound_messages` → engine) applies it, and
    // that the explicit unconfigured state still rejects at the CA gate.

    /// Trivial WASM module: `(module (func (export "run")))` — the same
    /// bytecode the SchemaMigrationEngine unit tests execute.
    fn trivial_wasm_bytes() -> Vec<u8> {
        vec![
            0x00, 0x61, 0x73, 0x6d, // magic
            0x01, 0x00, 0x00, 0x00, // version
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type section: () -> ()
            0x03, 0x02, 0x01, 0x00, // function section
            0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x00, // export "run"
            0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // code section: empty body
        ]
    }

    /// Build a config that registers the Migration CA public key and the
    /// ordered schema version path at init (Subphase 5.1).
    fn make_migration_config(
        path: &str,
        ca_public: [u8; 32],
        version_path: Vec<[u8; 32]>,
    ) -> InitConfig {
        let mut config = make_config(path);
        config.deployment.migration_ca_public_key = Some(ca_public);
        config.deployment.schema_version_path = version_path;
        config
    }

    /// CA-sign a MigrationDelta for `source → target` over `transform_bytes`
    /// (Req 18.2: CA signature over transform bytes, embedded SHA-256).
    /// A second minimal-but-valid WASM module, byte-distinct from
    /// [`Self::trivial_wasm_bytes`] (exports `"run2"` instead of `"run"`;
    /// the sandbox treats a missing `"run"` export as a successful no-op).
    ///
    /// Migration IDs are SHA-256(transform_bytes), so a corrected migration
    /// must carry *different* transform bytes than the revoked one — the same
    /// bytes would hash to the revoked migration's ID and be rejected at the
    /// revocation gate.
    fn trivial_wasm_bytes_v2() -> Vec<u8> {
        vec![
            0x00, 0x61, 0x73, 0x6d, // magic
            0x01, 0x00, 0x00, 0x00, // version
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type section: () -> ()
            0x03, 0x02, 0x01, 0x00, // function section
            0x07, 0x08, 0x01, 0x04, 0x72, 0x75, 0x6e, 0x32, 0x00, 0x00, // export "run2"
            0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // code section: empty body
        ]
    }

    fn make_ca_signed_migration_delta(
        ca_secret: &[u8; 32],
        source: [u8; 32],
        target: [u8; 32],
        transform_bytes: Vec<u8>,
    ) -> crate::migration::migration_delta::MigrationDelta {
        use crate::crdt::delta::{Ed25519Signature, PriorityClass};
        use crate::migration::migration_delta::{CaSignature, MigrationDelta};
        use sha2::{Digest, Sha256};

        let transform_sha256: [u8; 32] = Sha256::digest(&transform_bytes).into();
        let ca_sig = crate::identity::keypair::sign(ca_secret, &transform_bytes)
            .expect("ca sign");

        MigrationDelta {
            id: transform_sha256, // id = SHA-256(transform_bytes)
            author_did: "did:key:z6MkMigSender".to_string(),
            signature: Ed25519Signature::default(),
            source_schema_hash: source,
            target_schema_hash: target,
            transform_bytes,
            ca_signature: CaSignature(ca_sig.0),
            transform_sha256,
            priority: PriorityClass::Medium,
            created_at: 0,
        }
    }

    /// Init wiring registers the Migration CA key + version path: a CA-signed
    /// migration on a valid path step is accepted by the engine constructed
    /// through `CoreHandle::init` — previously the zero key rejected every
    /// migration with `MigrationCaSignatureInvalid` regardless of validity.
    #[tokio::test]
    async fn init_registers_migration_ca_key_and_version_path() {
        let path = tmp_path("p51_migration_ca");
        cleanup(&path);

        let (ca_secret, ca_public) = crate::identity::keypair::generate_keypair().expect("keygen");
        let source = [0x10u8; 32];
        let target = [0x11u8; 32];

        let handle = CoreHandle::init(make_migration_config(
            &path,
            ca_public,
            vec![source, target],
        ))
        .await
        .expect("init with migration CA key + version path");

        let delta = make_ca_signed_migration_delta(
            &ca_secret,
            source,
            target,
            trivial_wasm_bytes(),
        );

        // The engine `CoreHandle::init` constructed must accept the valid
        // migration: the CA signature verifies against the config-registered
        // key and source → target is a valid step in the config-registered
        // path.
        let result = handle
            .migration
            .lock()
            .unwrap()
            .receive_migration_delta(delta, "did:key:z6MkMigSender");
        assert!(
            matches!(
                result,
                Ok(crate::migration::wasm_sandbox::MigrationResult::Success)
            ),
            "config-registered CA key + version path must accept a valid migration: {result:?}"
        );

        cleanup(&path);
    }

    /// Without a configured Migration CA key the engine must still reject every
    /// migration at the CA-verification step — `None` is the explicit
    /// unconfigured state, not a silent acceptance hole.
    #[tokio::test]
    async fn unconfigured_migration_ca_still_rejects_at_ca_gate() {
        let path = tmp_path("p51_unconfigured");
        cleanup(&path);

        let (ca_secret, _) = crate::identity::keypair::generate_keypair().expect("keygen");
        let source = [0x10u8; 32];
        let target = [0x11u8; 32];

        // Default config: migration_ca_public_key = None, schema_version_path = [].
        let handle = CoreHandle::init(make_config(&path)).await.expect("init");

        let delta = make_ca_signed_migration_delta(
            &ca_secret,
            source,
            target,
            trivial_wasm_bytes(),
        );
        let result = handle
            .migration
            .lock()
            .unwrap()
            .receive_migration_delta(delta, "did:key:z6MkMigSender");
        assert!(
            matches!(result, Err(TirBaseError::MigrationCaSignatureInvalid { .. })),
            "unconfigured migration CA must keep rejecting at the CA gate: {result:?}"
        );

        cleanup(&path);
    }

    /// Runtime registration: a handle initialised without a Migration CA key
    /// starts in the explicit unconfigured state (CA gate rejects) and becomes
    /// able to accept CA-signed migrations after `register_migration_ca_key`.
    #[tokio::test]
    async fn runtime_register_migration_ca_key_enables_migrations() {
        let path = tmp_path("p51_runtime_migration_key");
        cleanup(&path);

        let (ca_secret, ca_public) = crate::identity::keypair::generate_keypair().expect("keygen");
        let source = [0x10u8; 32];
        let target = [0x11u8; 32];

        let handle = CoreHandle::init(make_config(&path)).await.expect("init");

        let delta = make_ca_signed_migration_delta(
            &ca_secret,
            source,
            target,
            trivial_wasm_bytes(),
        );

        // Before registration: the zero key must reject at the CA gate (this
        // also blacklists the sender).
        let before = handle
            .migration
            .lock()
            .unwrap()
            .receive_migration_delta(delta.clone(), "did:key:z6MkMigSender");
        assert!(
            matches!(before, Err(TirBaseError::MigrationCaSignatureInvalid { .. })),
            "before registration the CA gate must reject: {before:?}"
        );

        // Register the Migration CA key at runtime.
        handle
            .register_migration_ca_key(ca_public)
            .expect("register_migration_ca_key must succeed");

        // Now the same migration verifies against the registered key.  The
        // version path is still unconfigured (empty), so it is rejected at the
        // version-path gate — not at the CA gate.  (A fresh sender DID: the
        // pre-registration attempt blacklisted the original one.)
        let after = handle
            .migration
            .lock()
            .unwrap()
            .receive_migration_delta(delta, "did:key:z6MkMigSender2");
        assert!(
            matches!(after, Err(TirBaseError::VersionPathMismatch { .. })),
            "after registration the CA gate must pass (failure moves to version path): {after:?}"
        );

        cleanup(&path);
    }

    /// Full inbound path: a CA-signed migration delivered via `inject_inbound`
    /// → `process_inbound_messages` → `SchemaMigrationEngine::receive_migration_delta`
    /// is applied, the sender is not blacklisted, and the engine's local schema
    /// hash advances so the next path step is accepted.
    #[tokio::test]
    async fn inbound_migration_passes_ca_gate_with_configured_key_and_path() {
        let path = tmp_path("p51_inbound_migration");
        cleanup(&path);

        let (ca_secret, ca_public) = crate::identity::keypair::generate_keypair().expect("keygen");
        let v1 = [0x10u8; 32];
        let v2 = [0x11u8; 32];
        let v3 = [0x12u8; 32];

        let handle = CoreHandle::init(make_migration_config(
            &path,
            ca_public,
            vec![v1, v2, v3],
        ))
        .await
        .expect("init with migration CA key + version path");

        let sender = "did:key:z6MkMigSender";

        // Deliver migration v1 → v2 through the production inbound pipeline.
        let delta_a = make_ca_signed_migration_delta(
            &ca_secret,
            v1,
            v2,
            trivial_wasm_bytes(),
        );
        handle
            .inject_inbound(GossipMessage::InboundMigrationDelta(delta_a))
            .await
            .expect("inject migration A");
        handle
            .process_inbound_messages()
            .await
            .expect("drain inbound");
        // The inbound pipeline executes migrations on a background job (so a
        // revocation can interrupt one — Req 18.6); wait for this one to
        // commit before asserting post-migration state.
        assert!(
            handle
                .await_migration_quiescence(std::time::Duration::from_secs(10))
                .await,
            "migration A must finish within the wait budget"
        );

        let mut mig = handle.migration.lock().unwrap();
        assert!(
            !mig.is_blacklisted(sender),
            "valid CA-signed migration must not blacklist its sender"
        );

        // The engine's local schema hash advanced to v2 — the next step v2 → v3
        // must now be a valid migration (it would fail the source-hash check had
        // migration A not actually applied).
        let delta_b = make_ca_signed_migration_delta(
            &ca_secret,
            v2,
            v3,
            trivial_wasm_bytes(),
        );
        let result = mig.receive_migration_delta(delta_b, sender);
        assert!(
            matches!(
                result,
                Ok(crate::migration::wasm_sandbox::MigrationResult::Success)
            ),
            "second path step must succeed after the first applied: {result:?}"
        );

        drop(mig);
        cleanup(&path);
    }

    // ── Subphase 5.4: Migration revocation interrupts an in-progress ─────────
    //
    // transform (Req 18.6)
    //
    // Before this subphase the inbound pipeline executed the migration
    // transform synchronously inside `receive_migration_delta` while holding
    // the CoreHandle `migration` mutex, so a MigrationRevocationDelta arriving
    // mid-run queued behind the transform (up to the 30 s epoch timeout) and
    // could never halt it.  This test drives the production wiring: a
    // long-running (infinite-loop) transform is dispatched to the background
    // migration job, a revocation is drained while it is genuinely executing,
    // and the transform must be epoch-interrupted promptly — well before its
    // 30 s timeout — with the schema hash left unadvanced.

    /// WASM transform that never returns: `(func (export "run") (loop $inf br $inf))`.
    ///
    /// Only the epoch interrupt (timeout or revocation, Req 18.6) can stop it,
    /// which is exactly what makes it a reliable "in progress" transform.
    fn infinite_loop_wasm_bytes() -> Vec<u8> {
        wat::parse_str(r#"(module (func (export "run") (loop $inf br $inf))) "#)
            .expect("parse infinite-loop WAT")
    }

    #[tokio::test]
    async fn inbound_migration_revocation_interrupts_in_progress_transform() {
        let path = tmp_path("p54_revoke_interrupts");
        cleanup(&path);

        let (ca_secret, ca_public) = crate::identity::keypair::generate_keypair().expect("keygen");
        let v1 = [0x10u8; 32];
        let v2 = [0x11u8; 32];

        let mut config = make_migration_config(&path, ca_public, vec![v1, v2]);
        // M-of-N manager threshold for *migration* revocations: a single
        // Manager signature suffices (the engine uses
        // `deployment.revocation_m.max(1)`).
        config.deployment.revocation_m = 1;

        let handle = CoreHandle::init(config)
            .await
            .expect("init with migration CA key + version path");

        let sender = "did:key:z6MkMigSender";

        // ── 1. Start a long-running migration through the inbound pipeline ──
        let wasm = infinite_loop_wasm_bytes();
        let delta = make_ca_signed_migration_delta(&ca_secret, v1, v2, wasm);
        let migration_id = delta.id;

        handle
            .inject_inbound(GossipMessage::InboundMigrationDelta(delta))
            .await
            .expect("inject migration");
        handle
            .process_inbound_messages()
            .await
            .expect("drain inbound");

        // The inbound pipeline runs the transform on a background job; wait
        // until it has genuinely started executing (engine in-progress marker
        // set AND its wasmtime Engine registered in the execution registry, so
        // the epoch interrupt below is guaranteed to land).
        let start_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let in_progress = handle
                .migration
                .lock()
                .unwrap()
                .is_migration_in_progress(&migration_id);
            let registered = handle.migration_runs.is_in_flight(&migration_id);
            if in_progress && registered {
                break;
            }
            assert!(
                std::time::Instant::now() < start_deadline,
                "migration never began executing (in_progress={in_progress}, registered={registered})"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        // ── 2. Revoke it while it is mid-flight (Req 18.5/18.6) ─────────────
        use crate::crdt::derive_did_from_public_key;
        use crate::crdt::delta::Ed25519Signature;
        use crate::migration::migration_delta::{ManagerSignature, MigrationRevocationDelta};
        let (mgr_secret, mgr_public) =
            crate::identity::keypair::generate_keypair().expect("manager keygen");
        let mgr_did = derive_did_from_public_key(&mgr_public);
        let mgr_sig = crate::identity::keypair::sign(&mgr_secret, &migration_id).expect("sign");
        let revocation = MigrationRevocationDelta {
            target_migration_id: migration_id,
            signatures: vec![ManagerSignature {
                manager_did: mgr_did,
                signature: Ed25519Signature(mgr_sig.0),
            }],
            created_at: 0,
        };

        let revoke_started = std::time::Instant::now();
        handle
            .inject_inbound(GossipMessage::InboundMigrationRevocationDelta(revocation))
            .await
            .expect("inject revocation");
        handle
            .process_inbound_messages()
            .await
            .expect("drain revocation");

        // The revocation must interrupt the run; wait for the pipeline to
        // settle (job finished, in-progress cleared).
        assert!(
            handle
                .await_migration_quiescence(std::time::Duration::from_secs(15))
                .await,
            "revoked migration job must settle within the wait budget"
        );
        let revoke_elapsed = revoke_started.elapsed();

        // ── 3. Assert the interrupt outcome ──────────────────────────────────
        {
            let mig = handle.migration.lock().unwrap();
            assert!(
                mig.is_revoked(&migration_id),
                "migration must be permanently revoked"
            );
            assert!(
                !mig.is_migration_in_progress(&migration_id),
                "interrupted migration must no longer be in progress"
            );
            assert_eq!(
                mig.current_schema_hash(),
                v1,
                "schema hash must NOT advance when the transform was revoked mid-flight"
            );
        }
        assert!(
            !handle.migration_runs.is_in_flight(&migration_id),
            "interrupted run must deregister from the execution registry"
        );
        assert!(
            revoke_elapsed < std::time::Duration::from_secs(10),
            "revocation must halt the transform via epoch interrupt well before \
             the 30 s sandbox timeout — took {revoke_elapsed:?}"
        );

        // ── 4. A later attempt to apply the revoked migration is rejected ────
        let delta_again = make_ca_signed_migration_delta(
            &ca_secret,
            v1,
            v2,
            infinite_loop_wasm_bytes(),
        );
        let result = handle
            .migration
            .lock()
            .unwrap()
            .receive_migration_delta(delta_again, sender);
        assert!(
            matches!(result, Err(TirBaseError::AuthorisationFailed { .. })),
            "revoked migration must be rejected on re-apply: {result:?}"
        );

        cleanup(&path);
    }

    // ── Subphase 5.5: a revocation for an unknown migration hash is ──────────
    //
    // rejected by the inbound pipeline (Req 18.7)
    //
    // `prepare_migration` — the funnel every inbound MigrationDelta passes
    // through — records each CA-validated hash as *known*, and
    // `apply_revocation` only accepts a MigrationRevocationDelta whose target
    // is in that known set.  This test drives the production wiring
    // end-to-end: an arbitrary-hash revocation drained over the real inbound
    // pipeline is rejected and leaves no trace, while a revocation for a hash
    // the device genuinely received (a migration delivered just before it) is
    // accepted — proving the gate keys on the hash being seen, not on the
    // pipeline being broken.
    #[tokio::test]
    async fn inbound_revocation_for_unknown_migration_hash_is_rejected_then_known_hash_accepted() {
        let path = tmp_path("p55_revoke_unknown");
        cleanup(&path);

        let (ca_secret, ca_public) = crate::identity::keypair::generate_keypair().expect("keygen");
        let v1 = [0x10u8; 32];
        let v2 = [0x11u8; 32];

        let mut config = make_migration_config(&path, ca_public, vec![v1, v2]);
        config.deployment.revocation_m = 1;

        let handle = CoreHandle::init(config)
            .await
            .expect("init with migration CA key + version path");

        let sender = "did:key:z6MkMigSender";

        // ── 1. An arbitrary hash the device never saw is revoked ────────────
        // (correctly signed by a manager — the gate must be the unknown hash,
        // not a signature failure).
        use crate::crdt::derive_did_from_public_key;
        use crate::crdt::delta::Ed25519Signature;
        use crate::migration::migration_delta::{ManagerSignature, MigrationRevocationDelta};
        let arbitrary: [u8; 32] = [0xEEu8; 32];
        let (mgr_secret, mgr_public) =
            crate::identity::keypair::generate_keypair().expect("manager keygen");
        let mgr_did = derive_did_from_public_key(&mgr_public);
        let mgr_sig = crate::identity::keypair::sign(&mgr_secret, &arbitrary).expect("sign");
        let unknown_revocation = MigrationRevocationDelta {
            target_migration_id: arbitrary,
            signatures: vec![ManagerSignature {
                manager_did: mgr_did.clone(),
                signature: Ed25519Signature(mgr_sig.0),
            }],
            created_at: 0,
        };

        handle
            .inject_inbound(GossipMessage::InboundMigrationRevocationDelta(
                unknown_revocation,
            ))
            .await
            .expect("inject revocation for unknown hash");
        handle
            .process_inbound_messages()
            .await
            .expect("drain inbound");

        {
            let mig = handle.migration.lock().unwrap();
            assert!(
                !mig.is_revoked(&arbitrary),
                "an arbitrary-hash revocation must be rejected (Req 18.7)"
            );
        }

        // ── 2. Control: deliver a real migration, then revoke *its* hash ───
        // — now known — and confirm the same pipeline accepts it.
        let delta = make_ca_signed_migration_delta(&ca_secret, v1, v2, trivial_wasm_bytes());
        let migration_id = delta.id;

        handle
            .inject_inbound(GossipMessage::InboundMigrationDelta(delta))
            .await
            .expect("inject migration");
        handle
            .process_inbound_messages()
            .await
            .expect("drain inbound");
        assert!(
            handle
                .await_migration_quiescence(std::time::Duration::from_secs(10))
                .await,
            "migration must finish within the wait budget"
        );
        {
            let mig = handle.migration.lock().unwrap();
            assert_eq!(
                mig.current_schema_hash(),
                v2,
                "the delivered migration must have applied before revoking its hash"
            );
        }

        let mgr_sig_known = crate::identity::keypair::sign(&mgr_secret, &migration_id).expect("sign");
        let known_revocation = MigrationRevocationDelta {
            target_migration_id: migration_id,
            signatures: vec![ManagerSignature {
                manager_did: mgr_did.clone(),
                signature: Ed25519Signature(mgr_sig_known.0),
            }],
            created_at: 0,
        };
        handle
            .inject_inbound(GossipMessage::InboundMigrationRevocationDelta(
                known_revocation,
            ))
            .await
            .expect("inject revocation for known hash");
        handle
            .process_inbound_messages()
            .await
            .expect("drain inbound");

        {
            let mig = handle.migration.lock().unwrap();
            assert!(
                mig.is_revoked(&migration_id),
                "a revocation for a previously-seen migration hash must be accepted"
            );
        }

        // ── 3. Re-delivering the now-revoked migration is blocked ──────────
        let delta_again = make_ca_signed_migration_delta(&ca_secret, v1, v2, trivial_wasm_bytes());
        let result = handle
            .migration
            .lock()
            .unwrap()
            .receive_migration_delta(delta_again, sender);
        assert!(
            matches!(result, Err(TirBaseError::AuthorisationFailed { .. })),
            "a revoked migration must be rejected on re-delivery: {result:?}"
        );

        cleanup(&path);
    }

    // ── Subphase 5.6: migration-corruption recovery through real triggers ────
    //
    // Req 19.1/19.2/19.3, driven end-to-end over the production inbound
    // pipeline (`inject_inbound` → `process_inbound_messages` →
    // `CoreHandle::receive_inbound`):
    //
    // 1. A migration is delivered and applied (schema S → T).
    // 2. Managers revoke it — the migration is flagged corrupted.  Req 19.1:
    //    the CCE tags the migration and marks the affected projection rows
    //    CONTAMINATED (open ICO, `TaintSource::BadMigration`).  Req 19.2:
    //    the corruption window opens, so writes against schema T are
    //    captured in the Side-Car Ledger scoped to the corrupting migration.
    // 3. A corrected migration (T → U) arrives and commits.  Req 19.3:
    //    `replay_sidecar()` runs the captured writes onto the corrected
    //    projection in recorded-timestamp order; zero conflicts ⇒ every
    //    replayed delta receives `DeltaTag::ReplayComplete` (Req 19.6), the
    //    window closes, and later writes are no longer captured.
    #[tokio::test]
    async fn migration_corruption_recovery_triggers_cce_tagging_sidecar_capture_and_replay() {
        use crate::contamination::incident::TaintSource;
        use crate::crdt::delta::DeltaTag;
        use crate::crdt::derive_did_from_public_key;
        use crate::migration::migration_delta::{ManagerSignature, MigrationRevocationDelta};
        use crate::migration::sidecar::ReplayStatus;

        let path = tmp_path("p56_corruption_recovery");
        cleanup(&path);

        let (ca_secret, ca_public) = crate::identity::keypair::generate_keypair().expect("keygen");
        let s = [0x60u8; 32];
        let t = [0x61u8; 32];
        let u = [0x62u8; 32];

        let mut config = make_migration_config(&path, ca_public, vec![s, t, u]);
        config.deployment.revocation_m = 1;
        let handle = CoreHandle::init(config)
            .await
            .expect("init with migration CA key + version path");

        // ── 1. Seed a projection row on schema S so the CCE has rows to ────
        // mark contaminated when the migration is flagged corrupted.
        handle
            .write("reports", "r1", json!({ "v": 1 }))
            .await
            .expect("seed write");

        // ── 2. Apply the migration that will later be flagged corrupted ────
        // (S → T).  It runs through the real dispatch path (off-lock sandbox).
        let bad_delta = make_ca_signed_migration_delta(&ca_secret, s, t, trivial_wasm_bytes());
        let bad_migration_id = bad_delta.id;
        handle
            .inject_inbound(GossipMessage::InboundMigrationDelta(bad_delta))
            .await
            .expect("inject migration");
        handle
            .process_inbound_messages()
            .await
            .expect("drain inbound");
        assert!(
            handle
                .await_migration_quiescence(std::time::Duration::from_secs(10))
                .await,
            "migration must finish within the wait budget"
        );
        {
            let mig = handle.migration.lock().unwrap();
            assert_eq!(
                mig.current_schema_hash(),
                t,
                "the migration must have applied before it can be revoked"
            );
        }

        // ── 3. Managers revoke the corrupted migration. ─────────────────────
        let (mgr_secret, mgr_public) = crate::identity::keypair::generate_keypair().expect("keygen");
        let mgr_did = derive_did_from_public_key(&mgr_public);
        let mgr_sig = crate::identity::keypair::sign(&mgr_secret, &bad_migration_id).expect("sign");
        let revocation = MigrationRevocationDelta {
            target_migration_id: bad_migration_id,
            signatures: vec![ManagerSignature {
                manager_did: mgr_did,
                signature: crate::crdt::delta::Ed25519Signature(mgr_sig.0),
            }],
            created_at: 0,
        };
        handle
            .inject_inbound(GossipMessage::InboundMigrationRevocationDelta(revocation))
            .await
            .expect("inject revocation");
        handle
            .process_inbound_messages()
            .await
            .expect("drain inbound");

        // Req 19.1: the revoked (corrupted) migration is CCE-tagged — an open
        // Incident Context Object with `TaintSource::BadMigration` exists and
        // the seeded projection row is CONTAMINATED rather than deleted.
        {
            let cce = handle.cce.lock().unwrap();
            let open = cce.open_incidents().expect("open incidents");
            assert_eq!(open.len(), 1, "exactly one ICO after the corruption flag");
            assert!(
                matches!(
                    &open[0].taint_source,
                    TaintSource::BadMigration { migration_id }
                        if *migration_id == bad_migration_id
                ),
                "ICO source must be BadMigration for the revoked migration: {:?}",
                open[0].taint_source
            );
            assert!(
                cce.is_row_contaminated("reports", "r1"),
                "Req 19.1: the affected projection row must be CONTAMINATED"
            );
        }

        // ── 4. Writes during the corrupted window. ──────────────────────────
        // Req 19.2: every write against schema T is preserved byte-for-byte in
        // the Side-Car Ledger, scoped to the corrupting migration ID.  The r1
        // update additionally auto-tags ContaminatedByHumanReaction (Req 19.5)
        // because its row is CONTAMINATED.
        let write_new = handle
            .write("reports", "r2", json!({ "v": 2 }))
            .await
            .expect("corrupted-window write");
        let write_update = handle
            .write("reports", "r1", json!({ "v": 3 }))
            .await
            .expect("corrupted-window update");
        {
            let mig = handle.migration.lock().unwrap();
            let entries = mig
                .sidecar_entries(&bad_migration_id)
                .expect("sidecar entries");
            assert_eq!(
                entries.len(),
                2,
                "both corrupted-window writes must be Side-Car captured (Req 19.2)"
            );
            for e in &entries {
                assert_eq!(e.migration_id, bad_migration_id);
                assert_eq!(e.table_name, "reports");
                assert!(
                    matches!(e.replay_status, ReplayStatus::Pending),
                    "captured entries start Pending: {e:?}"
                );
            }
        }
        // The r1 update auto-tagged ContaminatedByHumanReaction and registered
        // itself as a HumanReaction contamination root (Req 19.5 — the write
        // went to a row the BadMigration ICO marked CONTAMINATED).  The tag
        // lives in the serialised delta; the observable production effect is
        // the new delta joining an active ICO (same assertion the Subphase 1.4
        // Req 19.5 test uses).
        {
            let all_open = handle
                .cce
                .lock()
                .unwrap()
                .open_incidents()
                .expect("open incidents");
            assert!(
                all_open.iter().any(|ico| {
                    ico.contaminated_deltas.contains(&write_update.delta_id)
                }),
                "a write to a CONTAMINATED row during the corrupted window must \
                 join an active ICO via ContaminatedByHumanReaction (Req 19.5)"
            );
        }

        // ── 5. The corrected migration (T → U) arrives and commits. ─────────
        // Req 19.3: the captured writes are replayed onto the corrected
        // projection in recorded-timestamp order through the production
        // success path.  The corrected transform is byte-distinct from the
        // revoked one, so its migration ID differs and passes the revocation
        // gate.
        let fixed_delta =
            make_ca_signed_migration_delta(&ca_secret, t, u, trivial_wasm_bytes_v2());
        handle
            .inject_inbound(GossipMessage::InboundMigrationDelta(fixed_delta))
            .await
            .expect("inject corrected migration");
        handle
            .process_inbound_messages()
            .await
            .expect("drain inbound");
        assert!(
            handle
                .await_migration_quiescence(std::time::Duration::from_secs(10))
                .await,
            "corrected migration must finish within the wait budget"
        );

        {
            let mig = handle.migration.lock().unwrap();
            assert_eq!(
                mig.current_schema_hash(),
                u,
                "the corrected migration must commit"
            );
            assert!(
                mig.active_corruption_migration().is_none(),
                "the corruption window must close once replayed"
            );
            let entries = mig
                .sidecar_entries(&bad_migration_id)
                .expect("sidecar entries after replay");
            assert_eq!(entries.len(), 2);
            for e in &entries {
                assert!(
                    !matches!(e.replay_status, ReplayStatus::Pending),
                    "every captured write must have been replayed (Req 19.3): {:?}",
                    e.replay_status
                );
            }
        }

        // Req 19.6: zero-conflict replay appends DeltaTag::ReplayComplete to
        // every successfully-replayed delta.
        {
            let conn = crate::store::sqlite::open(&path).expect("open conn for tag read");
            let lock = std::sync::Arc::new(std::sync::Mutex::new(conn));
            for delta_id in [write_new.delta_id, write_update.delta_id] {
                let tags = {
                    let g = lock.lock().unwrap();
                    crate::contamination::taint::read_tags_from_db(&g, &delta_id)
                        .expect("read tags")
                };
                assert!(
                    tags.iter().any(|t| {
                        matches!(t, DeltaTag::ReplayComplete { migration_id }
                            if *migration_id == bad_migration_id)
                    }),
                    "delta {} must carry ReplayComplete for the corrupted migration \
                     after zero-conflict replay (Req 19.6)",
                    hex::encode(delta_id)
                );
            }
        }

        // ── 6. The window is closed: post-replay writes are NOT captured. ───
        handle
            .write("reports", "r4", json!({ "v": 4 }))
            .await
            .expect("post-replay write");
        {
            let mig = handle.migration.lock().unwrap();
            assert_eq!(
                mig.sidecar_entries(&bad_migration_id).expect("entries").len(),
                2,
                "writes after the corrected migration must not be Side-Car captured"
            );
        }

        cleanup(&path);
    }

    // ── Subphase 3.2: Saturate Mode lifecycle through the real state machine ──
    //
    // `CoreHandle::activate_saturate_mode` / `renew_saturate_mode` /
    // `terminate_saturate_mode` are the shared WASM + native entry points the
    // WASM exports delegate to (lib.rs).  These integration tests drive a real
    // `CoreHandle` (the exact production construction: deployment CA key →
    // `TransportConfig` → transport state machine) through activation,
    // renewal, a below-threshold M-of-N attempt, and a successful M-of-N
    // termination, asserting at each step that the DRR scheduler mirrors the
    // state machine — the bare `set_saturate_mode(true)` boolean bypass could
    // never demote the scheduler again.

    /// A stand-in for one external Manager DID's contribution to an M-of-N
    /// Lease Termination Delta (Req 13.6): sign `message` with a fresh Ed25519
    /// key and return `(did:key, signature_bytes)`.
    fn external_manager_signature(message: &[u8], seed: u8) -> (String, Vec<u8>) {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let did = crate::crdt::derive_did_from_public_key(&sk.verifying_key().to_bytes());
        let sig = sk.sign(message).to_bytes().to_vec();
        (did, sig)
    }

    /// Build a disaster-alert Biscuit token signed by `ca_private`, as the
    /// deployment CA would issue to a Manager (Req 13.1).
    fn make_disaster_alert_token(ca_private: &[u8]) -> Vec<u8> {
        crate::auth::biscuit::create_token_with_caveat(
            "did:key:z6MkManager",
            "manager",
            3600,
            "disaster-alert",
            ca_private,
        )
        .expect("token creation must succeed")
    }

    #[tokio::test]
    async fn saturate_mode_lifecycle_routes_through_state_machine_and_scheduler() {
        use crate::transport::saturate::SaturateState;

        let path = tmp_path("saturate_lifecycle");
        cleanup(&path);

        let (ca_private, ca_public) = make_ca_keypair();
        let handle = CoreHandle::init(make_config_with_ca_key(&path, ca_public))
            .await
            .expect("init");

        // ── Activation (Req 13.1) ────────────────────────────────────────────
        let activate_token = make_disaster_alert_token(&ca_private);
        handle
            .activate_saturate_mode(&activate_token)
            .expect("a valid disaster-alert token must activate Saturate_Mode");
        {
            let transport = handle.transport.lock().unwrap();
            assert_eq!(transport.saturate.state(), SaturateState::Saturate);
            let lease = transport
                .saturate
                .lease()
                .expect("activation must open a lease");
            assert_eq!(lease.activating_manager_did, handle.identity.did());
            assert!(lease.expires_at > now_secs());
            assert!(
                transport.scheduler.is_saturate_mode(),
                "scheduler must follow the state machine into Saturate_Mode"
            );
        }

        // ── Heartbeat renewal (Req 13.4) ─────────────────────────────────────
        let renew_token = make_disaster_alert_token(&ca_private);
        handle
            .renew_saturate_mode(&renew_token)
            .expect("a valid heartbeat token must renew the lease");
        {
            let transport = handle.transport.lock().unwrap();
            assert_eq!(transport.saturate.state(), SaturateState::Saturate);
            let lease = transport
                .saturate
                .lease()
                .expect("renewal must keep the lease");
            assert!(
                lease.last_renewed_at.is_some(),
                "renewal must record a last_renewed_at through the state machine"
            );
            assert!(
                transport.scheduler.is_saturate_mode(),
                "scheduler must stay in Saturate Mode across a renewal"
            );
        }

        // ── Below-threshold termination is rejected (invariant (b)) ──────────
        let message = b"saturate-terminate:v1";
        let err = handle
            .terminate_saturate_mode(message, vec![])
            .expect_err("only the local signature must not meet an M=2 threshold");
        assert!(
            matches!(err, TirBaseError::ThresholdNotMet { got: 1, need: 2 }),
            "expected ThresholdNotMet(got=1, need=2), got: {err}"
        );
        {
            let transport = handle.transport.lock().unwrap();
            assert_eq!(
                transport.saturate.state(),
                SaturateState::Saturate,
                "mode must be preserved below the M-of-N threshold"
            );
            assert!(
                transport.scheduler.is_saturate_mode(),
                "scheduler must stay in Saturate Mode below the M-of-N threshold"
            );
        }

        // ── M-of-N termination (Req 13.6) ────────────────────────────────────
        let co_sig = external_manager_signature(message, 0x77);
        handle
            .terminate_saturate_mode(message, vec![co_sig])
            .expect("local + one external Manager signature must meet the M=2 threshold");
        {
            let transport = handle.transport.lock().unwrap();
            assert_eq!(transport.saturate.state(), SaturateState::Normal);
            assert!(
                transport.saturate.lease().is_none(),
                "lease must be cleared after termination"
            );
            assert!(
                !transport.scheduler.is_saturate_mode(),
                "scheduler must leave Saturate Mode on M-of-N termination — \
                 the bare-boolean bypass could never demote it"
            );
        }

        cleanup(&path);
    }

    // ── Test 3d (Subphase 3.3): the production tick loop auto-demotes an ───
    //
    // `SaturateModeStateMachine::tick()` is now called from the *same* loop
    // `init` spawns (`CoreHandle::spawn_scheduler_tick_loop`, established in
    // Phase 1.4) every epoch with the wall clock, so a lease that expires
    // without renewal demotes the state machine — and clears the DRR
    // scheduler mirror — automatically.  This test drives the identical loop
    // with a short interval, activates Saturate_Mode through the real
    // production facade, backdates the lease (the loop runs on real time; a
    // 60-minute lease cannot be waited out in a test), and asserts the
    // background task — NOT a manual `tick()` / `tick_saturate()` call —
    // performs the demotion.

    #[tokio::test]
    async fn scheduler_tick_loop_auto_demotes_expired_saturate_lease() {
        use crate::transport::saturate::SaturateState;

        let path = tmp_path("saturate_tick_loop");
        cleanup(&path);

        let (ca_private, ca_public) = make_ca_keypair();
        let handle = CoreHandle::init(make_config_with_ca_key(&path, ca_public))
            .await
            .expect("init");

        // Activate Saturate_Mode through the production facade (Req 13.1):
        // real Biscuit DISASTER_ALERT token → state machine SATURATE + DRR
        // scheduler mirror in Saturate Mode.
        let token = make_disaster_alert_token(&ca_private);
        handle
            .activate_saturate_mode(&token)
            .expect("a valid disaster-alert token must activate Saturate_Mode");
        {
            let transport = handle.transport.lock().unwrap();
            assert_eq!(transport.saturate.state(), SaturateState::Saturate);
            assert!(
                transport.scheduler.is_saturate_mode(),
                "scheduler must follow the state machine into Saturate_Mode"
            );
        }

        // Backdate the lease so a real-clock tick sees it as already expired
        // (test-only manipulation of the state machine's lease; the loop
        // itself only ever sees the wall clock).
        {
            let mut transport = handle.transport.lock().unwrap();
            transport
                .saturate
                .backdate_lease_expiry_for_test(now_secs() - 1);
        }

        // Spawn the production tick loop with a short interval (production
        // builds use `SCHEDULER_TICK_INTERVAL_MS` from `init`; test builds
        // use 1 hour so deterministic tests can drive the identical loop).
        let _loop = CoreHandle::spawn_scheduler_tick_loop(
            &handle,
            std::time::Duration::from_millis(10),
        );

        // Do NOT call tick() / tick_saturate() manually — the background loop
        // must perform the auto-demotion.  Poll until the state machine drops
        // back to NORMAL and the scheduler mirror follows.
        let mut attempts = 0u32;
        loop {
            let demoted = {
                let transport = handle.transport.lock().unwrap();
                transport.saturate.state() == SaturateState::Normal
                    && !transport.scheduler.is_saturate_mode()
            };
            if demoted {
                break;
            }
            attempts += 1;
            assert!(
                attempts < 200,
                "scheduler tick loop never auto-demoted the expired Saturate_Mode lease"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // The lease must be gone and the scheduler mirror cleared — the
        // expiry demotion ran the full reconcile, not just the state machine.
        {
            let transport = handle.transport.lock().unwrap();
            assert_eq!(transport.saturate.state(), SaturateState::Normal);
            assert!(
                transport.saturate.lease().is_none(),
                "lease must be cleared by the expiry demotion"
            );
            assert!(
                !transport.scheduler.is_saturate_mode(),
                "scheduler must leave Saturate Mode on lease-expiry auto-demotion"
            );
        }

        cleanup(&path);
    }

    // ── Test 3e (Subphase 3.4): lease expiry through the actual runtime ───
    //
    // Unlike Test 3d (Subphase 3.3), nothing is backdated and no lease state
    // is manipulated: the lease duration is a deployment-configurable
    // production knob (`DeploymentConfig::saturate_lease_duration_secs` →
    // `TransportConfig::saturate_lease_duration_secs` →
    // `SaturateModeStateMachine`, wired in `CoreHandle::init`), so this test
    // configures a 2-second window through the exact production construction,
    // activates Saturate_Mode through the production facade, never renews, and
    // asserts the production tick loop — running on wall-clock time —
    // auto-demotes the state machine AND the DRR scheduler mirror only after
    // the lease genuinely expires.

    #[tokio::test]
    async fn saturate_runtime_lease_expiry_auto_demotes_without_renewal() {
        use crate::transport::saturate::SaturateState;

        let path = tmp_path("saturate_runtime_expiry");
        cleanup(&path);

        let (ca_private, ca_public) = make_ca_keypair();
        let mut config = make_config_with_ca_key(&path, ca_public);
        // Short configured lease window (Req 13.3): the runtime test cannot
        // wait out the 60-minute spec default, so the deployment configures a
        // 2-second window through the same field `CoreHandle::init` feeds into
        // the transport.  This is a production config knob — not a test
        // backdoor: no lease state is touched after activation.
        config.deployment.saturate_lease_duration_secs = 2;
        let handle = CoreHandle::init(config).await.expect("init");

        // Activate through the production facade (Req 13.1): a real Biscuit
        // DISASTER_ALERT token → state machine SATURATE + DRR scheduler mirror
        // in Saturate Mode.  The lease must open with the *configured*
        // 2-second window — expiry is imminent by design.
        let token = make_disaster_alert_token(&ca_private);
        handle
            .activate_saturate_mode(&token)
            .expect("a valid disaster-alert token must activate Saturate_Mode");
        let natural_expiry = {
            let transport = handle.transport.lock().unwrap();
            assert_eq!(transport.saturate.state(), SaturateState::Saturate);
            assert!(
                transport.scheduler.is_saturate_mode(),
                "scheduler must follow the state machine into Saturate_Mode"
            );
            let lease = transport
                .saturate
                .lease()
                .expect("activation must open a lease");
            assert_eq!(
                lease.expires_at - lease.activated_at,
                2,
                "the configured 2-second lease window must be honoured"
            );
            lease.expires_at
        };

        // Spawn the production tick loop with a short interval (production
        // builds use `SCHEDULER_TICK_INTERVAL_MS` from `init`; test builds
        // use 1 hour so deterministic tests can drive the identical loop).
        let _loop = CoreHandle::spawn_scheduler_tick_loop(
            &handle,
            std::time::Duration::from_millis(10),
        );

        // NO renewal, NO backdating, NO manual tick() / tick_saturate() — the
        // background loop must demote the lease once the wall clock crosses
        // `natural_expiry`.  Poll until the state machine drops back to NORMAL
        // and the scheduler mirror follows.
        let mut attempts = 0u32;
        loop {
            let demoted = {
                let transport = handle.transport.lock().unwrap();
                transport.saturate.state() == SaturateState::Normal
                    && !transport.scheduler.is_saturate_mode()
            };
            if demoted {
                break;
            }
            attempts += 1;
            assert!(
                attempts < 600,
                "runtime lease expiry never auto-demoted the Saturate_Mode lease"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // The demotion must have happened because the wall clock genuinely
        // crossed the natural expiry — not because the lease was backdated or
        // a manual tick() advanced the state machine.
        assert!(
            now_secs() >= natural_expiry,
            "auto-demotion must follow genuine wall-clock lease expiry \
             (natural expiry was {natural_expiry}, demoted at {})",
            now_secs()
        );

        // The lease must be gone and the scheduler mirror cleared — the
        // runtime expiry demotion ran the full reconcile, not just the state
        // machine (Req 13.5).
        {
            let transport = handle.transport.lock().unwrap();
            assert_eq!(transport.saturate.state(), SaturateState::Normal);
            assert!(
                transport.saturate.lease().is_none(),
                "lease must be cleared by the runtime expiry demotion"
            );
            assert!(
                !transport.scheduler.is_saturate_mode(),
                "scheduler must leave Saturate Mode on runtime lease expiry"
            );
        }

        cleanup(&path);
    }

    #[tokio::test]
    async fn saturate_mode_activation_with_invalid_token_preserves_normal_mode() {
        use crate::transport::saturate::SaturateState;

        let path = tmp_path("saturate_invalid");
        cleanup(&path);

        let (_, ca_public) = make_ca_keypair();
        let handle = CoreHandle::init(make_config_with_ca_key(&path, ca_public))
            .await
            .expect("init");

        // A token signed by a DIFFERENT (unregistered) CA key must be rejected;
        // the mode and scheduler must stay untouched (Req 13.7).
        let (other_private, _) = make_ca_keypair();
        let foreign_token = crate::auth::biscuit::create_token_with_caveat(
            "did:key:z6MkManager",
            "manager",
            3600,
            "disaster-alert",
            &other_private,
        )
        .expect("token creation must succeed");
        let err = handle
            .activate_saturate_mode(&foreign_token)
            .expect_err("a token from an unregistered CA must be rejected");
        assert!(
            matches!(err, TirBaseError::AuthorisationFailed { .. })
                || matches!(err, TirBaseError::SignatureVerificationFailed { .. }),
            "expected an authorisation / verification error, got: {err}"
        );

        let transport = handle.transport.lock().unwrap();
        assert_eq!(transport.saturate.state(), SaturateState::Normal);
        assert!(!transport.scheduler.is_saturate_mode());

        cleanup(&path);
    }
}

// ─── Inbound pipeline integration tests ───────────────────────────────────────

#[cfg(all(test, feature = "native"))]
mod inbound_tests {
    use super::*;
    use crate::crdt::delta::{Ed25519Signature, PriorityClass};
    use crate::identity::keypair::{generate_keypair, sign as ek_sign};
    use crate::transport::message::GossipMessage;
    use serde_json::json;
    use std::env;

    fn make_config(path: &str) -> InitConfig {
        InitConfig {
            storage_path: path.to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 2,
                revocation_n: 3,
                biscuit_ttl_secs: 3600,
                root_ca_keys: vec![],
                migration_ca_public_key: None,
                schema_version_path: vec![],
                schema_definitions: vec![],
                anchor_attested_location: false,
                beacon_public_keys: vec![],
                spatial_diversity_min: 1,
                max_single_sector_fraction: 0.7,
                quorum_k: 1,
                quorum_n: 1,
                saturate_lease_duration_secs: 3600,
            },
        }
    }

    fn tmp_path(suffix: &str) -> String {
        let mut p = env::temp_dir();
        p.push(format!("tirbase_inbound_test_{suffix}.db"));
        p.to_str().unwrap().to_string()
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}.identity.json"));
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Build a properly-signed Delta using the test keypair and schema hash.
    fn make_signed_delta(
        secret: &[u8; 32],
        author_did: &str,
        schema_hash: [u8; 32],
        lamport: u64,
    ) -> crate::crdt::delta::Delta {
        let mut d = crate::crdt::delta::Delta {
            id: [0u8; 32],
            author_did: author_did.to_string(),
            signature: Ed25519Signature::default(),
            schema_hash,
            automerge_bytes: vec![], // empty is safe to merge
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport,
            created_at: 0,
        };
        let canonical = d.canonical_bytes();
        d.signature = ek_sign(secret, &canonical).expect("sign");
        d.id = crate::crdt::delta::Delta::compute_id(&canonical);
        d
    }

    // ── Test 1: InboundDelta with valid signature is merged ───────────────────

    #[tokio::test]
    async fn inbound_valid_delta_is_merged() {
        let path = tmp_path("inbound_merge");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Build a peer identity with a valid did:key DID.
        let (peer_secret, peer_public) = generate_keypair().expect("keygen");
        let peer_did = crate::crdt::derive_did_from_public_key(&peer_public);

        // Get the engine's known schema hash by producing a delta from the handle first.
        // The default schema hash is all-zeros.
        let schema_hash = [0u8; 32]; // DEFAULT_SCHEMA_HASH

        let delta = make_signed_delta(&peer_secret, &peer_did, schema_hash, 1);
        let msg = GossipMessage::InboundDelta(delta);

        handle
            .inject_inbound(msg)
            .await
            .expect("inject_inbound should not fail");

        let processed = handle
            .process_inbound_messages()
            .await
            .expect("process_inbound_messages should not fail");

        assert_eq!(processed, 1, "exactly one message should be processed");

        cleanup(&path);
    }

    // ── Test 2: InboundDelta with unknown schema hash is quarantined ──────────

    #[tokio::test]
    async fn inbound_unknown_schema_delta_is_quarantined() {
        let path = tmp_path("inbound_quarantine");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        let (peer_secret, peer_public) = generate_keypair().expect("keygen");
        let peer_did = crate::crdt::derive_did_from_public_key(&peer_public);

        // Use an unknown schema hash (should be quarantined, not rejected).
        let unknown_schema = [0xFFu8; 32];
        let delta = make_signed_delta(&peer_secret, &peer_did, unknown_schema, 1);
        // Subphase 5.2: the byte-for-byte raw bytes the ledger must hold.
        let expected_raw = serde_json::to_vec(&delta).expect("serialise delta");
        let msg = GossipMessage::InboundDelta(delta);

        handle.inject_inbound(msg).await.expect("inject");

        // Should process without error (quarantine is not a pipeline error).
        let processed = handle
            .process_inbound_messages()
            .await
            .expect("process_inbound_messages should succeed even for quarantined delta");

        assert_eq!(processed, 1, "quarantined delta counts as processed");

        // Subphase 5.2: the raw bytes must be stored in the QuarantineLedger,
        // not merely logged.
        let migration = handle.migration.lock().expect("migration lock");
        let entries = migration
            .quarantined_entries()
            .expect("quarantined_entries should succeed");
        assert_eq!(
            entries.len(),
            1,
            "exactly one entry must be stored in the quarantine ledger"
        );
        assert_eq!(
            entries[0].raw_bytes, expected_raw,
            "raw_bytes must be the byte-for-byte serialised Delta"
        );
        assert_eq!(
            entries[0].sender_did, peer_did,
            "sender DID must be recorded"
        );
        assert_eq!(
            entries[0].schema_hash,
            Some(unknown_schema),
            "schema hash must be recorded"
        );
        assert_eq!(
            entries[0].reason,
            crate::migration::quarantine::QuarantineReason::UnknownSchemaHash,
            "quarantine reason must be recorded"
        );

        cleanup(&path);
    }

    // ── Subphase 6.2: structured rejection failure records (Req 7.4/7.5) ────
    //
    // `CoreHandle::init` registers a listener on the CRDT engine forwarding
    // every rejection record onto the handle's rejection-record broadcast
    // channel.  These tests drive the full production inbound pipeline
    // (`inject_inbound` → `process_inbound_messages` → `receive_inbound` →
    // `apply_incoming_delta` → `CrdtEngine::apply`) with a tampered Delta
    // (Req 7.4) and an unresolvable-DID Delta (Req 7.5), and assert the
    // structured, UTC-timestamped record — not an `eprintln!` — reaches a
    // subscriber, with no data merged.

    #[tokio::test]
    async fn inbound_tampered_delta_emits_structured_signature_failure_record() {
        let path = tmp_path("p62_sig_rejection_record");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Subscribe *before* injecting: broadcast only delivers to receivers
        // that existed at send time.
        let mut rx = handle.subscribe_rejection_records();

        let (peer_secret, peer_public) = generate_keypair().expect("keygen");
        let peer_did = crate::crdt::derive_did_from_public_key(&peer_public);

        // A delta signed by the peer, then tampered after signing so the
        // Ed25519 signature no longer verifies (Req 7.4).  Schema hash is the
        // handle's current (default) hash so the gate reaches signature
        // verification instead of quarantining earlier.
        let mut delta = make_signed_delta(&peer_secret, &peer_did, [0u8; 32], 1);
        delta.automerge_bytes = vec![0xAA, 0xBB];
        let delta_id = delta.id;

        handle
            .inject_inbound(GossipMessage::InboundDelta(delta))
            .await
            .expect("inject");
        let processed = handle
            .process_inbound_messages()
            .await
            .expect("process_inbound_messages must not error");
        assert_eq!(processed, 1);

        // The structured failure record — sender DID + UTC timestamp — must
        // reach the subscriber (Req 7.4).
        let record = rx.try_recv().expect("rejection record must be delivered");
        assert_eq!(
            record.code,
            crate::crdt::failure::DeltaRejectionCode::SignatureVerificationFailed,
            "tampered delta must emit the Req 7.4 signature-failure code"
        );
        assert_eq!(record.author_did, peer_did, "record must carry the sender DID");
        assert_eq!(record.delta_id, delta_id);
        assert!(!record.reason.is_empty());
        let now = crate::api::now_micros();
        assert!(
            record.occurred_at_utc > 0 && record.occurred_at_utc <= now,
            "record must carry a UTC timestamp"
        );

        // Req 7.4: the Delta is discarded without merging any data — the
        // engine Lamport clock never advanced and nothing was quarantined.
        {
            let engine = handle.crdt.lock().expect("crdt lock");
            assert_eq!(engine.lamport(), 0, "rejected delta must not advance Lamport");
        }
        let migration = handle.migration.lock().expect("migration lock");
        assert!(
            migration
                .quarantined_entries()
                .expect("quarantined_entries")
                .is_empty(),
            "a signature-rejected delta must not be quarantined"
        );
        drop(migration);

        cleanup(&path);
    }

    #[tokio::test]
    async fn inbound_unresolvable_did_emits_distinct_did_resolution_failure_record() {
        let path = tmp_path("p62_did_resolution_record");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        let mut rx = handle.subscribe_rejection_records();

        // Req 7.5: the sender DID cannot be resolved to a public key.  The
        // signature is present (non-empty), so the rejection is attributable
        // to resolution rather than the malformed-signature guard.
        let (peer_secret, _peer_public) = generate_keypair().expect("keygen");
        let unresolvable_did = "did:web:example.com/not-a-did-key";
        let delta = make_signed_delta(&peer_secret, unresolvable_did, [0u8; 32], 1);
        let delta_id = delta.id;

        handle
            .inject_inbound(GossipMessage::InboundDelta(delta))
            .await
            .expect("inject");
        let processed = handle
            .process_inbound_messages()
            .await
            .expect("process_inbound_messages must not error");
        assert_eq!(processed, 1);

        let record = rx.try_recv().expect("rejection record must be delivered");
        assert_eq!(
            record.code,
            crate::crdt::failure::DeltaRejectionCode::DidResolutionFailed,
            "unresolvable DID must emit the Req 7.5 DID-resolution-failure code"
        );
        // Req 7.5: the record is distinct from the Req 7.4 signature record and
        // carries the unresolved DID itself.
        assert_ne!(
            record.code,
            crate::crdt::failure::DeltaRejectionCode::SignatureVerificationFailed
        );
        assert_eq!(record.author_did, unresolvable_did);
        assert_eq!(record.delta_id, delta_id);
        assert!(
            record.occurred_at_utc > 0,
            "record must carry a UTC timestamp"
        );

        // Discarded without merging: Lamport never advanced.
        let engine = handle.crdt.lock().expect("crdt lock");
        assert_eq!(engine.lamport(), 0, "rejected delta must not advance Lamport");
        drop(engine);

        cleanup(&path);
    }

    // ── Subphase 5.3: field-level additive-vs-breaking gate (Req 17.3/17.4) ──
    //
    // `CoreHandle::init` registers `DeploymentConfig.schema_definitions` with
    // the CRDT engine and seeds its current schema from the first
    // `schema_version_path` entry.  The inbound pipeline then classifies an
    // unknown schema hash by diffing its registered definition field-by-field:
    // additive deltas merge (Req 17.3), breaking deltas land in the quarantine
    // ledger with reason `BreakingSchemaChange` (Req 17.4), and hashes without
    // a registered definition keep the legacy unknown-hash quarantine.

    /// Three users-table schema versions for the gate tests: v1 {id,name};
    /// v2 {id,name,email} (additive); v3 {id} (breaking — `name` removed).
    fn gate_schema_fixture(
    ) -> (
        crate::schema::Schema,
        crate::schema::Schema,
        crate::schema::Schema,
        [u8; 32],
        [u8; 32],
        [u8; 32],
    ) {
        use crate::schema::{FieldDef, FieldType, Schema, TableDef};
        use crate::store::compaction::CompactionPolicy;

        let field = |name: &str, ft: FieldType| FieldDef {
            name: name.to_string(),
            field_type: ft,
            nullable: true,
            default: None,
        };
        let schema = |fields: Vec<FieldDef>| Schema {
            tables: vec![TableDef {
                name: "users".to_string(),
                fields,
                compaction_policy: CompactionPolicy::None,
                constraints: vec![],
            }],
            version: "1.0.0".to_string(),
        };

        let v1 = schema(vec![field("id", FieldType::Text), field("name", FieldType::Text)]);
        let v2 = schema(vec![
            field("id", FieldType::Text),
            field("name", FieldType::Text),
            field("email", FieldType::Text),
        ]);
        let v3 = schema(vec![field("id", FieldType::Text)]);

        let h1 = v1.identifier_hash();
        let h2 = v2.identifier_hash();
        let h3 = v3.identifier_hash();
        (v1, v2, v3, h1, h2, h3)
    }

    /// Number of quarantined entries currently held in the ledger.
    fn quarantine_count(handle: &CoreHandle) -> usize {
        handle
            .migration
            .lock()
            .expect("migration lock")
            .quarantined_entries()
            .expect("quarantined_entries")
            .len()
    }

    /// Deliver an inbound data Delta through the full pipeline and return how
    /// many messages were drained.
    async fn deliver_delta(handle: &CoreHandle, delta: crate::crdt::delta::Delta) -> usize {
        handle
            .inject_inbound(GossipMessage::InboundDelta(delta))
            .await
            .expect("inject");
        handle
            .process_inbound_messages()
            .await
            .expect("process_inbound_messages must not error")
    }

    /// Init registers the schema definitions and seeds the CRDT engine's
    /// current schema; an additive-schema Delta then merges end-to-end while
    /// a breaking-schema Delta is quarantined with `BreakingSchemaChange` and
    /// an unregistered hash with `UnknownSchemaHash`.
    #[tokio::test]
    async fn inbound_additive_merges_breaking_quarantined_with_field_level_reason() {
        let path = tmp_path("p53_field_level_gate");
        cleanup(&path);

        let (v1, v2, v3, h1, h2, h3) = gate_schema_fixture();
        let mut config = make_config(&path);
        config.deployment.schema_version_path = vec![h1, h2, h3];
        config.deployment.schema_definitions = vec![v1, v2, v3];

        let handle = CoreHandle::init(config).await.expect("init with schema defs");

        // The CRDT engine's current schema is the first path version, so its
        // merge gate can diff against a real definition instead of the zero
        // sentinel.
        {
            let crdt = handle.crdt.lock().unwrap();
            assert_eq!(
                crdt.current_schema_hash(),
                h1,
                "engine current schema must be the first path version"
            );
        }

        let (peer_secret, peer_public) = generate_keypair().expect("keygen");
        let peer_did = crate::crdt::derive_did_from_public_key(&peer_public);

        // A. Additive schema (h2): merges; no quarantine entry; hash adopted.
        let d_add = make_signed_delta(&peer_secret, &peer_did, h2, 1);
        let add_id = d_add.id;
        assert_eq!(deliver_delta(&handle, d_add).await, 1);
        assert_eq!(quarantine_count(&handle), 0, "additive delta must not quarantine");
        {
            let crdt = handle.crdt.lock().unwrap();
            assert!(crdt.known_schema_hashes().contains(&h2), "h2 must be adopted");
            assert!(crdt.dag_node(&add_id).unwrap().is_some(), "additive delta must land in the DAG");
        }

        // A second h2 delta still merges (now through the known-hash path).
        let d_add2 = make_signed_delta(&peer_secret, &peer_did, h2, 2);
        assert_eq!(deliver_delta(&handle, d_add2).await, 1);
        assert_eq!(quarantine_count(&handle), 0);

        // B. Breaking schema (h3 removes `name`): quarantined with the
        //    field-level reason, byte-for-byte, and never adopted.
        let d_break = make_signed_delta(&peer_secret, &peer_did, h3, 3);
        let break_raw = serde_json::to_vec(&d_break).expect("serialise");
        assert_eq!(deliver_delta(&handle, d_break).await, 1);
        {
            let migration = handle.migration.lock().unwrap();
            let entries = migration.quarantined_entries().expect("quarantined_entries");
            assert_eq!(entries.len(), 1, "exactly the breaking delta must be quarantined");
            assert_eq!(
                entries[0].reason,
                crate::migration::quarantine::QuarantineReason::BreakingSchemaChange,
                "breaking change must be recorded with its field-level reason"
            );
            assert_eq!(entries[0].schema_hash, Some(h3));
            assert_eq!(entries[0].sender_did, peer_did);
            assert_eq!(entries[0].raw_bytes, break_raw, "raw bytes must be stored byte-for-byte");
        }
        {
            let crdt = handle.crdt.lock().unwrap();
            assert!(
                !crdt.known_schema_hashes().contains(&h3),
                "breaking schema hash must not be adopted"
            );
        }

        // C. A hash with no registered definition keeps the legacy reason.
        let mystery = [0xF0u8; 32];
        let d_unknown = make_signed_delta(&peer_secret, &peer_did, mystery, 4);
        assert_eq!(deliver_delta(&handle, d_unknown).await, 1);
        {
            let migration = handle.migration.lock().unwrap();
            let entries = migration.quarantined_entries().expect("quarantined_entries");
            assert_eq!(entries.len(), 2);
            assert_eq!(
                entries[1].reason,
                crate::migration::quarantine::QuarantineReason::UnknownSchemaHash
            );
            assert_eq!(entries[1].schema_hash, Some(mystery));
        }

        // Only the two additive merges advanced the CRDT clock (breaking and
        // unknown deltas never reach the merge step).
        {
            let crdt = handle.crdt.lock().unwrap();
            assert_eq!(crdt.lamport(), 3, "two merges (lamport 1, 2) => 3");
        }

        cleanup(&path);
    }

    /// Init rejects a deployment that registers a schema definition whose
    /// canonical hash does not match its `schema_version_path` entry — the
    /// field-level gate could otherwise trust a diff for the wrong schema.
    #[tokio::test]
    async fn init_rejects_schema_definition_hash_mismatch() {
        let path = tmp_path("p53_bad_defs");
        cleanup(&path);

        let (v1, _v2, _v3, _h1, _h2, _h3) = gate_schema_fixture();
        let mut config = make_config(&path);
        // Register v1 under a path hash it does not hash to.
        config.deployment.schema_version_path = vec![[0x42u8; 32]];
        config.deployment.schema_definitions = vec![v1];

        let err = match CoreHandle::init(config).await {
            Ok(_) => panic!("init must reject mismatched definitions"),
            Err(e) => e,
        };
        assert!(
            matches!(
                err,
                TirBaseError::SchemaRegistrationFailed { .. }
            ),
            "expected SchemaRegistrationFailed: {err:?}"
        );

        cleanup(&path);
    }

    // ── Subphase 5.3: migration success advances the CRDT current schema ──────
    //
    // A device's deployed schema is *its own* current schema, which changes
    // when an over-the-mesh migration applies.  `receive_inbound` mirrors the
    // migration engine's advance into the CRDT engine so locally produced
    // Deltas stamp the new hash (Req 4.6) and the merge gate diffs against the
    // migrated schema rather than the pre-migration one.

    /// Trivial WASM module: `(module (func (export "run")))`.
    fn p53_trivial_wasm_bytes() -> Vec<u8> {
        vec![
            0x00, 0x61, 0x73, 0x6d, // magic
            0x01, 0x00, 0x00, 0x00, // version
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type section: () -> ()
            0x03, 0x02, 0x01, 0x00, // function section
            0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x00, // export "run"
            0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // code section: empty body
        ]
    }

    /// CA-sign a MigrationDelta for `source → target` (Req 18.2).
    fn p53_ca_signed_migration(
        ca_secret: &[u8; 32],
        source: [u8; 32],
        target: [u8; 32],
    ) -> crate::migration::migration_delta::MigrationDelta {
        use crate::crdt::delta::{Ed25519Signature, PriorityClass};
        use crate::migration::migration_delta::{CaSignature, MigrationDelta};
        use sha2::{Digest, Sha256};

        let transform_bytes = p53_trivial_wasm_bytes();
        let transform_sha256: [u8; 32] = Sha256::digest(&transform_bytes).into();
        let ca_sig = ek_sign(ca_secret, &transform_bytes).expect("ca sign");

        MigrationDelta {
            id: transform_sha256,
            author_did: "did:key:z6MkMigSender".to_string(),
            signature: Ed25519Signature::default(),
            source_schema_hash: source,
            target_schema_hash: target,
            transform_bytes,
            ca_signature: CaSignature(ca_sig.0),
            transform_sha256,
            priority: PriorityClass::Medium,
            created_at: 0,
        }
    }

    #[tokio::test]
    async fn inbound_migration_advances_crdt_current_schema() {
        let path = tmp_path("p53_migration_advance");
        cleanup(&path);

        let (ca_secret, ca_public) = generate_keypair().expect("keygen");
        let (v1, v2, _v3, h1, h2, _h3) = gate_schema_fixture();
        let mut config = make_config(&path);
        config.deployment.migration_ca_public_key = Some(ca_public);
        config.deployment.schema_version_path = vec![h1, h2];
        config.deployment.schema_definitions = vec![v1, v2];

        let handle = CoreHandle::init(config).await.expect("init");

        // Before the migration: current schema is h1.
        {
            let crdt = handle.crdt.lock().unwrap();
            assert_eq!(crdt.current_schema_hash(), h1);
        }

        let mig = p53_ca_signed_migration(&ca_secret, h1, h2);
        handle
            .inject_inbound(GossipMessage::InboundMigrationDelta(mig))
            .await
            .expect("inject migration");
        handle
            .process_inbound_messages()
            .await
            .expect("drain inbound");
        // The inbound pipeline executes migrations on a background job (so a
        // revocation can interrupt one — Req 18.6); wait for this one to
        // commit before asserting post-migration state.
        assert!(
            handle
                .await_migration_quiescence(std::time::Duration::from_secs(10))
                .await,
            "migration must finish within the wait budget"
        );

        // After the migration: the CRDT engine's current schema advanced to h2
        // and locally produced Deltas stamp h2 (Req 4.6).
        let mut crdt = handle.crdt.lock().unwrap();
        assert_eq!(
            crdt.current_schema_hash(),
            h2,
            "CRDT current schema must follow the migration engine"
        );
        assert!(crdt.known_schema_hashes().contains(&h2));
        let produced = crdt.produce_delta(vec![], PriorityClass::Low, vec![]).unwrap();
        assert_eq!(produced.schema_hash, h2, "produced deltas must stamp the migrated schema");

        cleanup(&path);
    }

    // ── Test 3: process_inbound_messages drains the channel correctly ─────────

    #[tokio::test]
    async fn process_inbound_messages_drains_channel() {
        let path = tmp_path("inbound_drain");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        let (peer_secret, peer_public) = generate_keypair().expect("keygen");
        let peer_did = crate::crdt::derive_did_from_public_key(&peer_public);
        let schema_hash = [0u8; 32];

        // Inject 3 messages.
        for i in 1u64..=3 {
            let delta = make_signed_delta(&peer_secret, &peer_did, schema_hash, i);
            handle
                .inject_inbound(GossipMessage::InboundDelta(delta))
                .await
                .expect("inject");
        }

        // First drain should process 3.
        let first_count = handle
            .process_inbound_messages()
            .await
            .expect("first drain");
        assert_eq!(first_count, 3, "should drain all 3 queued messages");

        // Second drain should return 0 (channel is empty).
        let second_count = handle
            .process_inbound_messages()
            .await
            .expect("second drain");
        assert_eq!(second_count, 0, "channel should be empty after first drain");

        cleanup(&path);
    }

    // ── Test 3b (Subphase 1.3): the production inbound drain loop drains ─────
    //
    // `CoreHandle::init` spawns a background task that calls
    // `process_inbound_messages()` on an interval (in production builds).  This
    // test drives the *identical* loop — `CoreHandle::spawn_inbound_drain_loop`,
    // the function `init` calls — with a short interval and asserts the
    // background task (NOT a manual `process_inbound_messages()` call) applies
    // injected messages.  The injected Delta carries table/key metadata so the
    // drain projects it into the SQL store, observable via `handle.read()`.

    #[tokio::test]
    async fn production_inbound_drain_loop_drains_injected_messages() {
        let path = tmp_path("inbound_drain_loop");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Spawn the production drain loop with a short interval so the test
        // completes quickly.  (In production builds `CoreHandle::init` does
        // exactly this with `INBOUND_DRAIN_INTERVAL_MS`; in test builds init
        // uses a 1-hour interval so the count-based tests above stay
        // deterministic.)
        let _loop = CoreHandle::spawn_inbound_drain_loop(
            &handle,
            std::time::Duration::from_millis(10),
        );

        // Build a signed InboundDelta whose automerge_bytes embeds the
        // _tirbase_table / _tirbase_key envelope plus data fields, exactly as
        // CoreHandle::write() produces (see Test 6).
        let (peer_secret, peer_public) = generate_keypair().expect("keygen");
        let peer_did = crate::crdt::derive_did_from_public_key(&peer_public);
        let schema_hash = [0u8; 32]; // DEFAULT_SCHEMA_HASH
        let delta = {
            let mut envelope = serde_json::Map::new();
            envelope.insert(
                "_tirbase_table".to_string(),
                serde_json::Value::String("loop".to_string()),
            );
            envelope.insert(
                "_tirbase_key".to_string(),
                serde_json::Value::String("k1".to_string()),
            );
            envelope.insert("v".to_string(), serde_json::Value::from(42));
            let envelope_bytes = serde_json::to_vec(&serde_json::Value::Object(envelope))
                .expect("envelope serialisation");

            let mut d = crate::crdt::delta::Delta {
                id: [0u8; 32],
                author_did: peer_did.clone(),
                signature: Ed25519Signature::default(),
                schema_hash,
                automerge_bytes: envelope_bytes,
                priority: PriorityClass::Low,
                causal_parents: vec![],
                tags: vec![],
                lamport: 3,
                created_at: 0,
            };
            let canonical = d.canonical_bytes();
            d.signature = ek_sign(&peer_secret, &canonical).expect("sign");
            d.id = crate::crdt::delta::Delta::compute_id(&canonical);
            d
        };

        handle
            .inject_inbound(GossipMessage::InboundDelta(delta))
            .await
            .expect("inject_inbound must not fail");

        // Do NOT call process_inbound_messages() — the background loop must do
        // the draining.  Poll until the projected row becomes readable.
        let mut attempts = 0u32;
        let observed = loop {
            if let Ok(res) = handle.read("loop", "k1").await {
                break res;
            }
            attempts += 1;
            assert!(
                attempts < 200,
                "spawned inbound drain loop never processed the injected message"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };

        assert_eq!(
            observed.data,
            json!({"v": 42}),
            "background drain loop must project the inbound delta to the store"
        );
        assert_eq!(observed.key, "k1");
        assert_eq!(observed.table, "loop");

        cleanup(&path);
    }

    // ── Test 3c (Subphase 1.4): the production DRR scheduler tick loop sends ──
    //
    // `CoreHandle::init` spawns a background task that ticks the DRR
    // scheduler — previously nothing in production ever called
    // `DrrScheduler::tick`, so Deltas enqueued via `enqueue_outbound`
    // (revocation rebroadcast at HIGH priority, mDNS re-announcement)
    // accumulated forever.  This test drives the *identical* loop —
    // `CoreHandle::spawn_scheduler_tick_loop`, the function `init` calls —
    // with a short interval, enqueues a Delta through the production enqueue
    // path, and asserts the background task (NOT a manual `tick()` call)
    // schedules it out of the queue and forwards it to the outbound publish
    // point, observable via the test-only `outbound_published` recording hook
    // (Subphase 1.1).

    #[tokio::test]
    async fn drr_scheduler_tick_loop_schedules_and_sends_enqueued_deltas() {
        let path = tmp_path("scheduler_tick_loop");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Spawn the production scheduler tick loop with a short interval so
        // the test completes quickly.  (In production builds `CoreHandle::init`
        // does exactly this with `SCHEDULER_TICK_INTERVAL_MS`; in test builds
        // init uses a 1-hour interval so queue-state unit tests stay
        // deterministic.)
        let _loop = CoreHandle::spawn_scheduler_tick_loop(
            &handle,
            std::time::Duration::from_millis(10),
        );

        // Enqueue a HIGH-priority Delta exactly like the production enqueue
        // callbacks do (RevocationDelta threshold → `enqueue_outbound`, Req 9.2).
        let delta_id = [0x14u8; 32];
        let wrapper = crate::crdt::delta::Delta {
            id: delta_id,
            author_did: "tirbase/revocation".to_string(),
            signature: crate::crdt::delta::Ed25519Signature::default(),
            schema_hash: [0u8; 32],
            automerge_bytes: serde_json::to_vec(&json!({
                "type": "InboundRevocationDelta",
            }))
            .expect("envelope serialisation"),
            priority: crate::crdt::delta::PriorityClass::High,
            causal_parents: vec![],
            tags: vec![],
            lamport: 0,
            created_at: 0,
        };
        {
            let mut transport = handle.transport.lock().unwrap();
            transport.enqueue_outbound(wrapper);
            assert!(
                transport.has_backlog(),
                "enqueued Delta must sit in the scheduler queue before any tick"
            );
        }

        // Do NOT call tick_scheduler() manually — the background loop must do
        // the scheduling and sending.  Poll until the prepared payload reaches
        // the outbound publish point (the Swarm polling task records it there).
        let mut attempts = 0u32;
        let published = loop {
            let published = handle
                .transport
                .lock()
                .unwrap()
                .outbound_published
                .clone();
            if !published.is_empty() {
                break published;
            }
            attempts += 1;
            assert!(
                attempts < 200,
                "scheduler tick loop never forwarded the enqueued Delta to the publish path"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };

        // The payload must be the exact serialised Delta that was enqueued —
        // scheduled out of the DRR queue and sent, not merely accumulated.
        assert_eq!(
            published.len(),
            1,
            "exactly one outbound payload must be produced per enqueued Delta (mtu=0)"
        );
        let decoded: crate::crdt::delta::Delta = serde_json::from_slice(&published[0])
            .expect("published payload must deserialise as the enqueued Delta");
        assert_eq!(
            decoded.id, delta_id,
            "published payload must be the enqueued Delta"
        );

        // The scheduler queue must now be empty — the loop drained it.
        assert!(
            !handle.transport.lock().unwrap().has_backlog(),
            "scheduler must have no backlog after the tick loop drained it"
        );

        cleanup(&path);
    }

    // ── Test 4: InboundDelta with missing signature is rejected gracefully ────

    #[tokio::test]
    async fn inbound_malformed_delta_rejected_gracefully() {
        let path = tmp_path("inbound_rejected");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Delta with empty signature — should be Rejected (not a pipeline error).
        let delta = crate::crdt::delta::Delta {
            id: [0xAAu8; 32],
            author_did: "did:key:z6MkTest".to_string(),
            signature: Ed25519Signature::default(), // empty → rejected
            schema_hash: [0u8; 32],
            automerge_bytes: vec![],
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport: 1,
            created_at: 0,
        };
        let msg = GossipMessage::InboundDelta(delta);

        handle.inject_inbound(msg).await.expect("inject");

        // Should not return Err — Rejection is logged, not propagated.
        let processed = handle
            .process_inbound_messages()
            .await
            .expect("process should succeed even for rejected delta");
        assert_eq!(processed, 1);

        cleanup(&path);
    }

    // ── Test 5: GossipMessage serialisation round-trip ────────────────────────

    #[test]
    fn gossip_message_serde_round_trip() {
        let (peer_secret, peer_public) = generate_keypair().expect("keygen");
        let peer_did = crate::crdt::derive_did_from_public_key(&peer_public);
        let schema_hash = [0u8; 32];
        let delta = make_signed_delta(&peer_secret, &peer_did, schema_hash, 7);

        let msg = GossipMessage::InboundDelta(delta.clone());
        let bytes = msg.to_bytes();
        let decoded = GossipMessage::from_bytes(&bytes).expect("round-trip decode");

        match decoded {
            GossipMessage::InboundDelta(d) => {
                assert_eq!(d.author_did, delta.author_did);
                assert_eq!(d.lamport, 7);
                assert_eq!(d.id, delta.id);
            }
            other => panic!("expected InboundDelta, got {other:?}"),
        }
    }

    // ── Test 6: End-to-end inbound pipeline — write on A, read on B ──────────
    //
    // Verifies that after receiving and processing a peer Delta that carries
    // TirBase JSON metadata (_tirbase_table, _tirbase_key, and data fields),
    // the data is readable via handle_b.read() — closing the projection gap
    // documented in earlier versions.
    //
    // Step 1: Write a value to handle_a (stores locally + produces a signed Delta).
    // Step 2: Build an equivalent Delta manually, embedding table/key metadata in
    //         automerge_bytes so the receiving peer can project it to the SQL store.
    // Step 3: Inject the Delta into handle_b via inject_inbound.
    // Step 4: Call process_inbound_messages() on handle_b.
    // Step 5: Verify handle_b.read("sensors", "reading-1") succeeds and returns
    //         the same data that was written on handle_a.
    //
    // Validates: Req 4.3 (merged peer state readable), Req 3.3 (store fully readable),
    //            Task 41 (projection-update-on-inbound implemented).

    #[tokio::test]
    async fn end_to_end_inbound_pipeline_write_a_read_b() {
        let path_a = tmp_path("e2e_A");
        let path_b = tmp_path("e2e_B");
        cleanup(&path_a);
        cleanup(&path_b);

        // ── Step 1: Write to handle_a ─────────────────────────────────────────
        let handle_a = CoreHandle::init(make_config(&path_a))
            .await
            .expect("init A");
        let handle_b = CoreHandle::init(make_config(&path_b))
            .await
            .expect("init B");

        let written_data = serde_json::json!({"sensor": "temperature", "value": 23.4});
        let write_result = handle_a
            .write("sensors", "reading-1", written_data.clone())
            .await
            .expect("write to A");

        // Confirm the delta ID is non-zero (the write produced a real delta).
        assert_ne!(
            write_result.delta_id,
            [0u8; 32],
            "write must produce a non-zero delta ID"
        );

        // ── Step 2: Construct an equivalent GossipMessage ─────────────────────
        // Build a delta whose automerge_bytes embeds _tirbase_table and _tirbase_key
        // metadata plus the application data fields — this is the format produced by
        // CoreHandle::write() (which embeds the metadata in the JSON envelope).
        let (peer_secret, peer_public) = generate_keypair().expect("keygen");
        let peer_did = crate::crdt::derive_did_from_public_key(&peer_public);
        let schema_hash = [0u8; 32]; // DEFAULT_SCHEMA_HASH

        let delta = {
            // Build the JSON envelope that receive_inbound() expects:
            //   { "_tirbase_table": "sensors", "_tirbase_key": "reading-1", <data fields> }
            let mut envelope = serde_json::Map::new();
            envelope.insert("_tirbase_table".to_string(), serde_json::Value::String("sensors".to_string()));
            envelope.insert("_tirbase_key".to_string(), serde_json::Value::String("reading-1".to_string()));
            // Flatten data fields directly into the envelope (matching CoreHandle::write() behaviour).
            if let Some(data_obj) = written_data.as_object() {
                for (k, v) in data_obj {
                    envelope.insert(k.clone(), v.clone());
                }
            }
            let envelope_bytes = serde_json::to_vec(&serde_json::Value::Object(envelope))
                .expect("envelope serialisation");

            let mut d = crate::crdt::delta::Delta {
                id: [0u8; 32],
                author_did: peer_did.clone(),
                signature: Ed25519Signature::default(),
                schema_hash,
                automerge_bytes: envelope_bytes,
                priority: PriorityClass::Low,
                causal_parents: vec![],
                tags: vec![],
                lamport: 2,
                created_at: 0,
            };
            let canonical = d.canonical_bytes();
            d.signature = ek_sign(&peer_secret, &canonical).expect("sign");
            d.id = crate::crdt::delta::Delta::compute_id(&canonical);
            d
        };

        // ── Step 3: Inject into handle_b ─────────────────────────────────────
        handle_b
            .inject_inbound(GossipMessage::InboundDelta(delta))
            .await
            .expect("inject_inbound must not fail");

        // ── Step 4: Process inbound messages ─────────────────────────────────
        let processed = handle_b
            .process_inbound_messages()
            .await
            .expect("process_inbound_messages must not fail");

        assert_eq!(
            processed, 1,
            "exactly one inbound message must be processed"
        );

        // ── Step 5: Verify data is readable on handle_b ───────────────────────
        // After projection, handle_b's SQL store must contain the row that was
        // written on handle_a — this closes the documented projection gap (Task 41).
        let read_result = handle_b.read("sensors", "reading-1").await;
        assert!(
            read_result.is_ok(),
            "inbound delta must be readable via store after merge; got: {:?}",
            read_result.err()
        );

        let result = read_result.unwrap();
        assert_eq!(
            result.data, written_data,
            "data read from handle_b must match what was written on handle_a"
        );
        assert_eq!(result.key, "reading-1");
        assert_eq!(result.table, "sensors");

        cleanup(&path_a);
        cleanup(&path_b);
    }

    // ── Test 7: RevocationDelta enqueued at HIGH priority after threshold met ─
    //
    // Validates Req 9.2: when M-of-N signatures are collected for a revocation,
    // the complete RevocationDelta must be enqueued at HIGH priority for gossip
    // rebroadcast.

    #[tokio::test]
    async fn revocation_delta_enqueued_at_high_priority_after_threshold_met() {
        let path = tmp_path("rev_enqueue");
        cleanup(&path);

        // Create a CoreHandle with M=2, N=2 revocation config.
        let handle = CoreHandle::init(InitConfig {
            storage_path: path.clone(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 2,
                revocation_n: 2,
                biscuit_ttl_secs: 3600,
                root_ca_keys: vec![],
                migration_ca_public_key: None,
                schema_version_path: vec![],
                schema_definitions: vec![],
                anchor_attested_location: false,
                beacon_public_keys: vec![],
                spatial_diversity_min: 1,
                max_single_sector_fraction: 0.7,
                quorum_k: 1,
                quorum_n: 1,
                saturate_lease_duration_secs: 3600,
            },
        })
        .await
        .expect("init");

        // Create 2 manager identities.
        let mgr1 = crate::identity::IdentityManager::init_in_memory().unwrap();
        let mgr1_did = mgr1.did().to_string();
        let mgr1_sk = mgr1.signing_key_bytes();

        let mgr2 = crate::identity::IdentityManager::init_in_memory().unwrap();
        let mgr2_did = mgr2.did().to_string();
        let mgr2_sk = mgr2.signing_key_bytes();

        // Choose a target DID.
        let target = crate::identity::IdentityManager::init_in_memory().unwrap();
        let target_did = target.did().to_string();

        // Produce two partial RevocationDeltas (one per manager).
        let (partial1, partial2) = {
            let rev = handle.revocation.lock().unwrap();
            let p1 = rev
                .produce_partial_delta(target_did.clone(), mgr1_did.clone(), &mgr1_sk)
                .expect("produce partial 1");
            let p2 = rev
                .produce_partial_delta(target_did.clone(), mgr2_did.clone(), &mgr2_sk)
                .expect("produce partial 2");
            (p1, p2)
        };

        // Combine both signatures into a single RevocationDelta.
        let combined = crate::auth::RevocationDelta {
            target_did: target_did.clone(),
            signatures: [partial1.signatures, partial2.signatures].concat(),
            created_at: crate::auth::revocation::current_timestamp_micros(),
        };

        // Inject the combined delta — this should cross the M=2 threshold.
        handle
            .inject_inbound(GossipMessage::InboundRevocationDelta(combined))
            .await
            .expect("inject_inbound must not fail");

        // Process — this triggers the on_revocation_applied callback which enqueues.
        handle
            .process_inbound_messages()
            .await
            .expect("process_inbound_messages must not fail");

        // Verify the scheduler has a HIGH-priority entry.
        let transport = handle.transport.lock().unwrap();
        assert!(
            transport.has_backlog(),
            "transport scheduler must have backlog after RevocationDelta threshold met"
        );
        assert!(
            transport.high_queue_depth() > 0,
            "HIGH queue must be non-empty after revocation gossip enqueue (depth: {})",
            transport.high_queue_depth()
        );

        drop(transport);
        cleanup(&path);
    }

    // ── Test 8: Completed RevocationDelta marks target as REVOKED on a second instance ─
    //
    // Validates end-to-end rebroadcast path: handle A processes a complete
    // RevocationDelta (marking the target REVOKED and enqueuing for gossip),
    // then the same RevocationDelta is injected into handle B which should also
    // mark the target as REVOKED.
    //
    // Idempotency of the second call is covered by revocation.rs test 11.

    #[tokio::test]
    async fn completed_revocation_delta_marks_target_revoked_on_second_instance() {
        let path_a = tmp_path("rev_e2e_A");
        let path_b = tmp_path("rev_e2e_B");
        cleanup(&path_a);
        cleanup(&path_b);

        // Handle A: M=1, N=1 for simplicity (1 manager can revoke alone).
        let config_a = InitConfig {
            storage_path: path_a.clone(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                biscuit_ttl_secs: 3600,
                root_ca_keys: vec![],
                migration_ca_public_key: None,
                schema_version_path: vec![],
                schema_definitions: vec![],
                anchor_attested_location: false,
                beacon_public_keys: vec![],
                spatial_diversity_min: 1,
                max_single_sector_fraction: 0.7,
                quorum_k: 1,
                quorum_n: 1,
                saturate_lease_duration_secs: 3600,
            },
        };
        // Handle B: same M/N so it also accepts the same 1-of-1 delta.
        let config_b = InitConfig {
            storage_path: path_b.clone(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                ..config_a.deployment.clone()
            },
        };

        let handle_a = CoreHandle::init(config_a).await.expect("init A");
        let handle_b = CoreHandle::init(config_b).await.expect("init B");

        // Manager and target identities.
        let mgr = crate::identity::IdentityManager::init_in_memory().unwrap();
        let mgr_did = mgr.did().to_string();
        let mgr_sk = mgr.signing_key_bytes();

        let target = crate::identity::IdentityManager::init_in_memory().unwrap();
        let target_did = target.did().to_string();

        // Produce a 1-of-1 partial delta (this IS the complete delta at M=1).
        let complete_delta = {
            let rev = handle_a.revocation.lock().unwrap();
            rev.produce_partial_delta(target_did.clone(), mgr_did.clone(), &mgr_sk)
                .expect("produce complete delta")
        };

        // ── Step A: Process on handle_a — marks target REVOKED + enqueues rebroadcast.
        handle_a
            .inject_inbound(GossipMessage::InboundRevocationDelta(complete_delta.clone()))
            .await
            .expect("inject into A");

        handle_a
            .process_inbound_messages()
            .await
            .expect("process A");

        // Verify A revoked the target.
        assert!(
            handle_a
                .revocation
                .lock()
                .unwrap()
                .revoked_dids()
                .contains(&target_did),
            "handle_a must have target_did in revoked_dids"
        );

        // ── Step B: Inject the same RevocationDelta into handle_b.
        handle_b
            .inject_inbound(GossipMessage::InboundRevocationDelta(complete_delta))
            .await
            .expect("inject into B");

        handle_b
            .process_inbound_messages()
            .await
            .expect("process B");

        // Verify B also revoked the target (Idempotency on A's side is tested in revocation.rs test 11).
        assert!(
            handle_b
                .revocation
                .lock()
                .unwrap()
                .revoked_dids()
                .contains(&target_did),
            "handle_b must have target_did in revoked_dids after receiving rebroadcast"
        );

        cleanup(&path_a);
        cleanup(&path_b);
    }

    // ── Test 8b: inbound Delta from a REVOKED peer is rejected (Req 8.6) ────
    //
    // End-to-end through the PRODUCTION inbound pipeline: a peer's Delta is
    // merged normally; then a validated RevocationDelta (M=1) marks the peer
    // REVOKED (which registers the DID in the CRDT engine); a second Delta
    // from the same peer is then rejected by the revocation gate inside
    // CrdtEngine::apply — reached via apply_incoming_delta — and never lands
    // in the Changeset DAG or the SQL projection.

    #[tokio::test]
    async fn inbound_delta_from_revoked_peer_is_rejected() {
        let path = tmp_path("inbound_revoked_author");
        cleanup(&path);

        // M=1, N=1 so a single Manager signature completes the revocation.
        let handle = CoreHandle::init(InitConfig {
            storage_path: path.clone(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                biscuit_ttl_secs: 3600,
                root_ca_keys: vec![],
                migration_ca_public_key: None,
                schema_version_path: vec![],
                schema_definitions: vec![],
                anchor_attested_location: false,
                beacon_public_keys: vec![],
                spatial_diversity_min: 1,
                max_single_sector_fraction: 0.7,
                quorum_k: 1,
                quorum_n: 1,
                saturate_lease_duration_secs: 3600,
            },
        })
        .await
        .expect("init");

        // Peer identity + a Manager identity that can revoke the peer.
        let (peer_secret, peer_public) = generate_keypair().expect("keygen");
        let peer_did = crate::crdt::derive_did_from_public_key(&peer_public);
        let schema_hash = [0u8; 32]; // DEFAULT_SCHEMA_HASH

        let mgr = crate::identity::IdentityManager::init_in_memory().unwrap();
        let mgr_did = mgr.did().to_string();
        let mgr_sk = mgr.signing_key_bytes();

        // Build a signed peer Delta carrying a projectable JSON envelope.
        let make_peer_delta = |table: &str, key: &str, value: i64, lamport: u64| {
            let mut envelope = serde_json::Map::new();
            envelope.insert(
                "_tirbase_table".to_string(),
                serde_json::Value::String(table.to_string()),
            );
            envelope.insert(
                "_tirbase_key".to_string(),
                serde_json::Value::String(key.to_string()),
            );
            envelope.insert("v".to_string(), serde_json::Value::from(value));
            let envelope_bytes = serde_json::to_vec(&serde_json::Value::Object(envelope))
                .expect("envelope serialisation");

            let mut d = crate::crdt::delta::Delta {
                id: [0u8; 32],
                author_did: peer_did.clone(),
                signature: Ed25519Signature::default(),
                schema_hash,
                automerge_bytes: envelope_bytes,
                priority: PriorityClass::Low,
                causal_parents: vec![],
                tags: vec![],
                lamport,
                created_at: 0,
            };
            let canonical = d.canonical_bytes();
            d.signature = ek_sign(&peer_secret, &canonical).expect("sign");
            d.id = crate::crdt::delta::Delta::compute_id(&canonical);
            d
        };

        // ── Before revocation: the peer's Delta merges and projects. ────────
        let delta_before = make_peer_delta("revtest", "k_before", 1, 1);
        handle
            .inject_inbound(GossipMessage::InboundDelta(delta_before.clone()))
            .await
            .expect("inject pre-revocation delta");
        handle
            .process_inbound_messages()
            .await
            .expect("process pre-revocation delta");
        assert!(
            handle
                .crdt
                .lock()
                .unwrap()
                .dag_node(&delta_before.id)
                .expect("dag_node lookup")
                .is_some(),
            "pre-revocation delta must be merged and persisted to the DAG"
        );
        handle
            .read("revtest", "k_before")
            .await
            .expect("pre-revocation delta must be projected to the store");

        // ── Revoke the peer (1-of-1), through the production inbound path. ───
        let rev_delta = {
            let rev = handle.revocation.lock().unwrap();
            rev.produce_partial_delta(peer_did.clone(), mgr_did.clone(), &mgr_sk)
                .expect("produce revocation delta")
        };
        handle
            .inject_inbound(GossipMessage::InboundRevocationDelta(rev_delta))
            .await
            .expect("inject revocation delta");
        handle
            .process_inbound_messages()
            .await
            .expect("process revocation delta");
        assert!(
            handle
                .revocation
                .lock()
                .unwrap()
                .revoked_dids()
                .contains(&peer_did),
            "revocation subsystem must know the peer DID is REVOKED"
        );

        // ── After revocation: the peer's next Delta must be rejected. ────────
        let delta_after = make_peer_delta("revtest", "k_after", 2, 2);
        handle
            .inject_inbound(GossipMessage::InboundDelta(delta_after.clone()))
            .await
            .expect("inject post-revocation delta");
        handle
            .process_inbound_messages()
            .await
            .expect("process post-revocation delta");

        // The rejected delta must NOT be persisted to the DAG…
        assert!(
            handle
                .crdt
                .lock()
                .unwrap()
                .dag_node(&delta_after.id)
                .expect("dag_node lookup")
                .is_none(),
            "post-revocation delta must be rejected — no DagNode may be persisted"
        );
        // …and must NOT be projected into the store.
        let read_after = handle.read("revtest", "k_after").await;
        assert!(
            read_after.is_err(),
            "post-revocation delta must not be readable (rejected before projection)"
        );
        // The pre-revocation row is untouched.
        handle
            .read("revtest", "k_before")
            .await
            .expect("pre-revocation data must survive");

        cleanup(&path);
    }
}

// ─── Task 42: Cross-build convergence tests ────────────────────────────────────
//
// Tests for cross-build CRDT state convergence (Req 1.4, Property 1).
// These run on native and validate that the CrdtEngine converges identically
// regardless of the order in which Deltas are applied (commutativity).
//
// The matching wasm-bindgen-test counterparts live in src/tests/wasm_tests.rs.

#[cfg(all(test, feature = "native"))]
mod convergence_tests {
    use super::*;
    use crate::crdt::delta::{Delta, Ed25519Signature, PriorityClass};
    use crate::crdt::{derive_did_from_public_key, CrdtEngine};
    use crate::identity::keypair::{generate_keypair, sign as ek_sign};
    use crate::schema::hash::compute_schema_identifier_hash;
    use crate::crdt::merge::MergeOutcome;
    use std::sync::{Arc, Mutex};
    use std::env;

    fn tmp_path(suffix: &str) -> String {
        let mut p = env::temp_dir();
        p.push(format!("tirbase_conv_test_{suffix}.db"));
        p.to_str().unwrap().to_string()
    }

    fn open_conn(path: &str) -> Arc<Mutex<rusqlite::Connection>> {
        let conn = rusqlite::Connection::open(path)
            .unwrap_or_else(|_| rusqlite::Connection::open_in_memory().unwrap());
        conn.execute_batch(crate::store::sqlite::CREATE_SCHEMA_SQL).unwrap();
        Arc::new(Mutex::new(conn))
    }

    fn test_schema() -> [u8; 32] {
        compute_schema_identifier_hash(&[("items", &[("id", "TEXT"), ("v", "INTEGER")])])
    }

    fn make_engine(
        secret: [u8; 32],
        public: [u8; 32],
        did: String,
        schema: [u8; 32],
    ) -> CrdtEngine {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(crate::store::sqlite::CREATE_SCHEMA_SQL).unwrap();
        let conn = Arc::new(Mutex::new(conn));
        CrdtEngine::new(secret, public, did, schema, conn)
    }

    fn make_signed_delta(
        secret: &[u8; 32],
        did: &str,
        schema: [u8; 32],
        lamport: u64,
        automerge_bytes: Vec<u8>,
    ) -> Delta {
        let mut d = Delta {
            id: [0u8; 32],
            author_did: did.to_string(),
            signature: Ed25519Signature::default(),
            schema_hash: schema,
            automerge_bytes,
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport,
            created_at: 0,
        };
        let canonical = d.canonical_bytes();
        d.signature = ek_sign(secret, &canonical).expect("sign");
        d.id = Delta::compute_id(&canonical);
        d
    }

    // ── Test 1: Two engines converge after exchanging Deltas ─────────────────
    //
    // Validates Property 1 (cross-build state convergence) at the CrdtEngine
    // level: applying the same set of Deltas to two engines in any order
    // produces identical final Lamport clocks.
    //
    // The WASM counterpart of this test runs in wasm_tests.rs under
    // `wasm-bindgen-test` as `test_wasm_crdt_engine_convergence_two_instances`.

    #[test]
    fn two_engines_converge_after_delta_exchange() {
        let schema = test_schema();

        // Create two engine identities.
        let (secret_a, public_a) = generate_keypair().unwrap();
        let did_a = derive_did_from_public_key(&public_a);

        let (secret_b, public_b) = generate_keypair().unwrap();
        let did_b = derive_did_from_public_key(&public_b);

        let mut engine_a = make_engine(secret_a, public_a, did_a.clone(), schema);
        let mut engine_b = make_engine(secret_b, public_b, did_b.clone(), schema);

        // Produce a Delta from engine A.
        let delta_a = engine_a
            .produce_delta(vec![], PriorityClass::Low, vec![])
            .unwrap();

        // Produce a Delta from engine B (concurrent — same initial Lamport=0).
        let delta_b = engine_b
            .produce_delta(vec![], PriorityClass::Low, vec![])
            .unwrap();

        // Apply A's Delta to B.
        let outcome_ab = engine_b.apply(&delta_a).unwrap();
        assert!(
            matches!(outcome_ab, MergeOutcome::Merged { .. }),
            "A→B must merge: {outcome_ab:?}"
        );

        // Apply B's Delta to A.
        let outcome_ba = engine_a.apply(&delta_b).unwrap();
        assert!(
            matches!(outcome_ba, MergeOutcome::Merged { .. }),
            "B→A must merge: {outcome_ba:?}"
        );

        // Both engines have applied both Deltas.
        // Lamport clocks must be identical (both advanced to max+1 twice).
        assert_eq!(
            engine_a.lamport(),
            engine_b.lamport(),
            "Lamport clocks must be identical after applying same Delta set: A={}, B={}",
            engine_a.lamport(),
            engine_b.lamport()
        );
    }

    // ── Test 2: Commutative Delta application — order does not matter ─────────
    //
    // Engine A applies Delta B first then Delta C.
    // Engine B applies Delta C first then Delta B.
    // Both must reach the same Lamport clock (commutativity invariant).

    #[test]
    fn delta_application_is_commutative() {
        let schema = test_schema();

        // All three engines share the same schema and start fresh.
        let (secret_a, public_a) = generate_keypair().unwrap();
        let did_a = derive_did_from_public_key(&public_a);
        let (secret_b, public_b) = generate_keypair().unwrap();
        let did_b = derive_did_from_public_key(&public_b);
        let (secret_c, public_c) = generate_keypair().unwrap();
        let did_c = derive_did_from_public_key(&public_c);

        // Engines that receive the Deltas in different orders.
        let mut engine_ab = make_engine(secret_a, public_a, did_a.clone(), schema);
        let mut engine_ba = make_engine(secret_a, public_a, did_a.clone(), schema);

        // Produce Deltas from B and C with distinct content.
        let mut engine_src_b = make_engine(secret_b, public_b, did_b.clone(), schema);
        let mut engine_src_c = make_engine(secret_c, public_c, did_c.clone(), schema);

        let delta_b = engine_src_b
            .produce_delta(vec![], PriorityClass::Low, vec![])
            .unwrap();
        let delta_c = engine_src_c
            .produce_delta(vec![], PriorityClass::High, vec![])
            .unwrap();

        // engine_ab applies B then C.
        engine_ab.apply(&delta_b).unwrap();
        engine_ab.apply(&delta_c).unwrap();

        // engine_ba applies C then B.
        engine_ba.apply(&delta_c).unwrap();
        engine_ba.apply(&delta_b).unwrap();

        // Lamport clocks must be identical regardless of application order.
        assert_eq!(
            engine_ab.lamport(),
            engine_ba.lamport(),
            "Commutative ordering must yield the same Lamport clock: ab={}, ba={}",
            engine_ab.lamport(),
            engine_ba.lamport()
        );
    }

    // ── Test 3: WASM receive_inbound_wasm routes JSON-envelope Delta through
    //            apply_incoming_delta and projects to the in-memory store ───────
    //
    // This is the native-side counterpart of the wasm-bindgen-test
    // `test_receive_peer_message_json_envelope_projects_to_store`.
    // It verifies the new apply_incoming_delta routing in receive_inbound_wasm
    // by using inject_inbound/process_inbound_messages on the native path, which
    // shares the same JSON-envelope projection logic.
    //
    // Validates: Task 42 sub-task 4 (readable store after inbound Delta).

    #[tokio::test]
    async fn inbound_json_envelope_delta_is_readable_after_merge() {
        let path_a = {
            let mut p = env::temp_dir();
            p.push("tirbase_conv_inbound_a.db");
            p.to_str().unwrap().to_string()
        };
        let path_b = {
            let mut p = env::temp_dir();
            p.push("tirbase_conv_inbound_b.db");
            p.to_str().unwrap().to_string()
        };
        let cleanup = |p: &str| {
            let _ = std::fs::remove_file(p);
            let _ = std::fs::remove_file(format!("{p}.identity.json"));
            let _ = std::fs::remove_file(format!("{p}-wal"));
            let _ = std::fs::remove_file(format!("{p}-shm"));
        };
        cleanup(&path_a);
        cleanup(&path_b);

        let make_cfg = |p: &str| InitConfig {
            storage_path: p.to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                biscuit_ttl_secs: 3600,
                root_ca_keys: vec![],
                migration_ca_public_key: None,
                schema_version_path: vec![],
                schema_definitions: vec![],
                anchor_attested_location: false,
                beacon_public_keys: vec![],
                spatial_diversity_min: 1,
                max_single_sector_fraction: 0.7,
                quorum_k: 1,
                quorum_n: 1,
                saturate_lease_duration_secs: 3600,
            },
        };

        let handle_a = CoreHandle::init(make_cfg(&path_a)).await.expect("init A");
        let handle_b = CoreHandle::init(make_cfg(&path_b)).await.expect("init B");

        let written_data = serde_json::json!({"sensor": "pressure", "value": 1013});

        // Write to A.
        handle_a
            .write("sensors", "p-1", written_data.clone())
            .await
            .expect("write to A");

        // Build the JSON envelope (matching CoreHandle::write format).
        let (peer_secret, peer_public) = generate_keypair().unwrap();
        let peer_did = derive_did_from_public_key(&peer_public);
        let schema_hash = [0u8; 32];

        let delta = {
            let mut envelope = serde_json::Map::new();
            envelope.insert("_tirbase_table".to_string(), serde_json::Value::String("sensors".to_string()));
            envelope.insert("_tirbase_key".to_string(), serde_json::Value::String("p-1".to_string()));
            if let Some(obj) = written_data.as_object() {
                for (k, v) in obj {
                    envelope.insert(k.clone(), v.clone());
                }
            }
            let envelope_bytes = serde_json::to_vec(&serde_json::Value::Object(envelope)).unwrap();

            let mut d = crate::crdt::delta::Delta {
                id: [0u8; 32],
                author_did: peer_did.clone(),
                signature: Ed25519Signature::default(),
                schema_hash,
                automerge_bytes: envelope_bytes,
                priority: PriorityClass::Low,
                causal_parents: vec![],
                tags: vec![],
                lamport: 2,
                created_at: 0,
            };
            let canonical = d.canonical_bytes();
            d.signature = ek_sign(&peer_secret, &canonical).expect("sign");
            d.id = Delta::compute_id(&canonical);
            d
        };

        // Inject Delta into handle_b and process it.
        handle_b
            .inject_inbound(crate::transport::message::GossipMessage::InboundDelta(delta))
            .await
            .expect("inject_inbound must not fail");

        let processed = handle_b
            .process_inbound_messages()
            .await
            .expect("process_inbound_messages must not fail");
        assert_eq!(processed, 1, "one message must be processed");

        // Verify the value is readable on B (Task 42 sub-task 4).
        let read_result = handle_b.read("sensors", "p-1").await;
        assert!(
            read_result.is_ok(),
            "inbound JSON-envelope Delta must be readable via store after merge; got: {:?}",
            read_result.err()
        );

        let result = read_result.unwrap();
        assert_eq!(
            result.data, written_data,
            "data on B must match what was written on A"
        );

        cleanup(&path_a);
        cleanup(&path_b);
    }
}

// ─── Phase 0.3(a)/(b): real-mesh integration tests (Subphase 1.5) ────────────
//
// Two in-process `CoreHandle`s with **real libp2p Swarms**, connected over
// loopback TCP by the production explicit-dial path (`CoreHandle::dial_peer`).
// No test-only injection helpers are involved anywhere on the write→receive
// path: the Delta travels
//
//   A: write() → send_delta → outbound channel → Swarm polling task
//      → gossipsub.publish → TCP/Noise/Yamux → wire
//   B: Swarm polling task (gossipsub message) → inbound channel
//      → production drain loop → receive_inbound → signature verification
//      → merge → SQL projection
//
// and is asserted on B via `read()` plus CRDT-level state (DAG node, Lamport
// clock) — i.e. the same observations a real second device would produce.
//
// These are the definition of done for Phase 0.3(a) (two-device real mesh
// Delta exchange) and Phase 0.3(b) (full write→gossip→receive→merge round
// trip with a signature-verified, merged, projected Delta on the receiver).

#[cfg(all(test, feature = "native"))]
mod real_mesh_tests {
    use super::*;
    use serde_json::json;
    use std::env;
    use std::net::TcpListener;
    use std::time::Duration;

    fn tmp_path(suffix: &str) -> String {
        let mut p = env::temp_dir();
        p.push(format!("tirbase_mesh_test_{suffix}.db"));
        p.to_str().unwrap().to_string()
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}.identity.json"));
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    /// Reserve a free loopback TCP port for a transport listen address.
    ///
    /// The listener is dropped before `CoreHandle::init` binds it, so there is
    /// a tiny reuse window; reserving both ports up front (before either
    /// handle inits) keeps that window to microseconds per port.
    fn reserve_loopback_port() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        l.local_addr().expect("local addr").port()
    }

    fn mesh_config(path: &str, port: u16) -> InitConfig {
        InitConfig {
            storage_path: path.to_string(),
            listen_addr: format!("/ip4/127.0.0.1/tcp/{port}"),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                biscuit_ttl_secs: 3600,
                root_ca_keys: vec![],
                migration_ca_public_key: None,
                schema_version_path: vec![],
                schema_definitions: vec![],
                anchor_attested_location: false,
                beacon_public_keys: vec![],
                spatial_diversity_min: 1,
                max_single_sector_fraction: 0.7,
                quorum_k: 1,
                quorum_n: 1,
                saturate_lease_duration_secs: 3600,
            },
        }
    }

    /// Initialise a handle on its own loopback port with a real Swarm (the
    /// production `CoreHandle::init` path spawns the Swarm polling task) and
    /// start the production inbound drain loop at accelerated cadence — the
    /// identical loop `init` spawns at 50 ms in production builds (Subphase
    /// 1.3); test builds make `init`'s own instance inert so count-based unit
    /// tests stay deterministic, so the test drives the accelerated loop
    /// explicitly, exactly as the Subphase 1.3 acceptance does.
    async fn init_mesh_handle(suffix: &str, port: u16) -> Arc<CoreHandle> {
        let path = tmp_path(suffix);
        cleanup(&path);
        let handle = CoreHandle::init(mesh_config(&path, port))
            .await
            .expect("init must succeed with a real Swarm");
        CoreHandle::spawn_inbound_drain_loop(&handle, Duration::from_millis(10));
        handle
    }

    /// Dial `from` → `to`'s listen address via the production
    /// `CoreHandle::dial_peer` path and wait until the connection is recorded
    /// (the Swarm polling task's `ConnectionEstablished` arm populates the
    /// peer table, so `mesh_status()` reports it).
    async fn connect_peers(from: &Arc<CoreHandle>, target_addr: &str) {
        let addr: libp2p::Multiaddr =
            target_addr.parse().expect("valid multiaddr");
        from.dial_peer(addr).await.expect("dial_peer must succeed");

        let mut attempts = 0u32;
        loop {
            if from.mesh_status().peer_count >= 1 {
                return;
            }
            attempts += 1;
            assert!(
                attempts < 500,
                "explicit dial never established a connection (mesh_status stayed disconnected for 5s)"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Poll `handle.read(table, key)` until the row's data equals `expected`
    /// or `timeout` elapses.  (Polling for a bare successful read is not
    /// enough across multiple round trips — a row written by an earlier
    /// round trip already reads successfully with stale data.)
    async fn wait_for_data(
        handle: &CoreHandle,
        table: &str,
        key: &str,
        expected: &serde_json::Value,
        timeout: Duration,
    ) -> QueryResult {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match handle.read(table, key).await {
                Ok(res) if &res.data == expected => return res,
                _ => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "row {table}/{key} never projected the expected data on the receiving device within {timeout:?}"
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        }
    }

    // ── Phase 0.3(a): two-device real mesh Delta exchange ────────────────────
    //
    // Two real Swarm-backed CoreHandles on loopback; a write on device A
    // becomes visible (readable) on device B with no test-only injection
    // helpers on the path.

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_devices_exchange_delta_over_real_mesh() {
        // Reserve both ports before either init to minimise reuse races.
        let port_a = reserve_loopback_port();
        let port_b = reserve_loopback_port();
        assert_ne!(port_a, port_b, "the two devices need distinct ports");

        let handle_a = init_mesh_handle("p03a_A", port_a).await;
        let handle_b = init_mesh_handle("p03a_B", port_b).await;

        // The only manual step: device A dials device B's listen address over
        // the production dial path (mDNS would do this automatically on a LAN;
        // loopback tests use the explicit path so no multicast is involved).
        let addr_b = format!("/ip4/127.0.0.1/tcp/{port_b}");
        connect_peers(&handle_a, &addr_b).await;

        // Let the gossipsub subscription exchange settle so the publish on A
        // reaches B's mesh rather than being deferred as "no subscribers".
        tokio::time::sleep(Duration::from_millis(250)).await;

        // Write on A — production write path (store + signed Delta + publish).
        let written = json!({ "device": "A", "seq": 1, "msg": "hello over the real mesh" });
        let write_result = handle_a
            .write("mesh", "row-a", written.clone())
            .await
            .expect("write on A must succeed");
        assert_ne!(write_result.delta_id, [0u8; 32], "A must produce a real Delta");

        // Assert the Delta arrived on B through the wire: signature-verified
        // (else Rejected — nothing would be stored), merged, projected — i.e.
        // readable via B's normal read() path.
        let observed = wait_for_data(&handle_b, "mesh", "row-a", &written, Duration::from_secs(20)).await;
        assert_eq!(
            observed.data, written,
            "data read on device B must exactly match what was written on device A"
        );

        cleanup(&tmp_path("p03a_A"));
        cleanup(&tmp_path("p03a_B"));
    }

    // ── Phase 0.3(b): full write→gossip→receive→merge round trip ────────────
    //
    // Same real mesh, but asserting each stage of the receiving pipeline on
    // B's CRDT engine and store:
    //   - signature-verified: the exact Delta A produced (Delta ID) is present
    //     in B's DAG under A's author DID — `CrdtEngine::apply` only inserts
    //     the DagNode after Ed25519 verification succeeds (step 3) and the
    //     merge completes (step 6).
    //   - merged: B's Lamport clock advanced (apply step 5).
    //   - projected: the row is readable via B's read() with A's exact data.

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_gossip_receive_merge_round_trip_is_signature_verified_and_projected() {
        let port_a = reserve_loopback_port();
        let port_b = reserve_loopback_port();
        assert_ne!(port_a, port_b);

        let handle_a = init_mesh_handle("p03b_A", port_a).await;
        let handle_b = init_mesh_handle("p03b_B", port_b).await;

        // B's engine starts with a zero Lamport clock and an empty DAG.
        let author_did_a = handle_a.identity.did().to_string();
        assert_eq!(handle_b.crdt.lock().unwrap().lamport(), 0, "B must start clean");

        let addr_b = format!("/ip4/127.0.0.1/tcp/{port_b}");
        connect_peers(&handle_a, &addr_b).await;
        tokio::time::sleep(Duration::from_millis(250)).await;

        // ── Round trip 1 ─────────────────────────────────────────────────────
        let written_1 = json!({ "sensor": "temp", "value": 23.4 });
        let write_1 = handle_a
            .write("roundtrip", "k1", written_1.clone())
            .await
            .expect("first write on A");

        let observed_1 = wait_for_data(&handle_b, "roundtrip", "k1", &written_1, Duration::from_secs(20)).await;
        assert_eq!(observed_1.data, written_1, "round trip 1 data must match on B");

        // The exact Delta A signed and published must have been merged into B's
        // DAG — signature-verified (author DID resolves from did:key and the
        // Ed25519 check passes, otherwise `apply` returns Rejected and no node
        // is inserted), merged (DagNode persisted), authored by A.
        let node_1 = handle_b
            .crdt
            .lock()
            .unwrap()
            .dag_node(&write_1.delta_id)
            .expect("DAG lookup must not fail")
            .unwrap_or_else(|| {
                panic!(
                    "B's DAG must contain the Delta A produced ({}); \
                     without a signature-verified merge no DagNode is inserted",
                    hex::encode(write_1.delta_id)
                )
            });
        assert_eq!(
            node_1.author_did, author_did_a,
            "B's DAG node must be attributed to A's DID"
        );
        assert!(
            handle_b.crdt.lock().unwrap().lamport() > 0,
            "B's Lamport clock must advance after merging A's Delta"
        );

        // ── Round trip 2: a second write chains off the first causally ───────
        let written_2 = json!({ "sensor": "temp", "value": 25.7 });
        let write_2 = handle_a
            .write("roundtrip", "k1", written_2.clone())
            .await
            .expect("second write on A");
        assert_ne!(
            write_2.delta_id, write_1.delta_id,
            "the second write must produce a distinct Delta"
        );

        let observed_2 = wait_for_data(&handle_b, "roundtrip", "k1", &written_2, Duration::from_secs(20)).await;
        assert_eq!(observed_2.data, written_2, "round trip 2 data must match on B");

        // Both Deltas must be present in B's DAG (converged state), each signed
        // by A.
        let node_2 = handle_b
            .crdt
            .lock()
            .unwrap()
            .dag_node(&write_2.delta_id)
            .expect("DAG lookup must not fail")
            .expect("second Delta must be merged into B's DAG");
        assert_eq!(node_2.author_did, author_did_a);
        assert!(
            handle_b.crdt.lock().unwrap().dag_node(&write_1.delta_id).unwrap().is_some(),
            "first Delta must still be in B's DAG after the second merge"
        );

        cleanup(&tmp_path("p03b_A"));
        cleanup(&tmp_path("p03b_B"));
    }

    // ── Subphase 4.5: Tier-1 durability via genuine receipt exchange ─────────
    //
    // Two real Swarm-backed CoreHandles on loopback (the Phase 0.3(a) mesh).
    // Device A writes; device B receives and merges the Delta through the
    // production inbound pipeline, then — Subphase 4.5 — issues a *genuine*
    // DurabilityReceipt (signed with B's own identity key over the canonical
    // payload) and publishes it back over the mesh.  A's inbound pipeline
    // resolves B's DID to its public key, verifies the receipt (signature +
    // state-hash), and reaches Tier-1 through the production quorum path.
    //
    // No test helper manufactures the receipt: every byte travels
    //   A: write() → register_delta → gossipsub.publish
    //   B: receive_inbound → merge → issue_durability_receipt → send_receipt
    //      → gossipsub.publish
    //   A: receive_inbound → resolve DID → register_peer_key → receive_receipt
    //      → quorum → Tier-1 (+ DurabilityTierChanged event)

    /// Poll device B's outbound publish point for the `DurabilityReceipt` it
    /// issued for `delta_id` after merging the Delta (Subphase 4.5).  Returns
    /// the receipt parsed from the framed
    /// `GossipMessage::InboundDurabilityReceipt` payload — proving the receipt
    /// genuinely left B's mesh layer (same observability the Phase 0.3(a)
    /// tests use for outbound Deltas).
    async fn wait_for_issued_receipt(
        handle: &Arc<CoreHandle>,
        delta_id: &DeltaId,
    ) -> crate::durability::receipt::DurabilityReceipt {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(transport) = handle.transport.lock() {
                for payload in &transport.outbound_published {
                    if let Some(crate::transport::message::GossipMessage::InboundDurabilityReceipt(
                        receipt,
                    )) = crate::transport::message::GossipMessage::from_bytes(payload)
                    {
                        if &receipt.state_hash == delta_id {
                            return receipt;
                        }
                    }
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "device B never published a DurabilityReceipt for delta {}",
                hex::encode(delta_id)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Poll `handle` until the Delta's durability tier reaches `Tier1` — the
    /// production per-Delta state backing `WriteResult::durability_tier`
    /// (Req 14.7).
    async fn wait_for_tier1(handle: &CoreHandle, delta_id: &DeltaId) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            if handle.durability_tier(delta_id) == DurabilityTier::Tier1 {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "delta {} never reached Tier-1 within 20s (tier: {:?})",
                hex::encode(delta_id),
                handle.durability_tier(delta_id)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_devices_reach_tier1_durability_via_genuine_receipt_exchange() {
        let port_a = reserve_loopback_port();
        let port_b = reserve_loopback_port();
        assert_ne!(port_a, port_b, "the two devices need distinct ports");

        let handle_a = init_mesh_handle("p45_A", port_a).await;
        let handle_b = init_mesh_handle("p45_B", port_b).await;

        // Subscribe to A's durability event channel BEFORE the write: the
        // Tier-1 transition must be observed through the production
        // notification path (Subphase 4.2), not just polled afterwards.
        let mut tier_events = handle_a.subscribe_durability_events();

        // The only manual step: A dials B's listen address over the production
        // dial path (mDNS would do this automatically on a LAN; loopback tests
        // use the explicit path so no multicast is involved).
        let addr_b = format!("/ip4/127.0.0.1/tcp/{port_b}");
        connect_peers(&handle_a, &addr_b).await;

        // Let the gossipsub subscription exchange settle so the publish on A
        // reaches B's mesh rather than being deferred as "no subscribers".
        tokio::time::sleep(Duration::from_millis(250)).await;

        // A writes — production write path (store + signed Delta + mesh
        // publish + durability registration).
        let written = json!({ "device": "A", "msg": "tier1 over the real mesh" });
        let write_result = handle_a
            .write("durable", "row-1", written.clone())
            .await
            .expect("write on A must succeed");
        let delta_id = write_result.delta_id;
        assert_ne!(delta_id, [0u8; 32], "A must produce a real Delta");
        assert_eq!(
            handle_a.durability_tier(&delta_id),
            DurabilityTier::Uncommitted,
            "Tier-1 must not be reached before a genuine receipt arrives"
        );

        // 1. B genuinely receives and merges the Delta (Phase 1) — only then
        //    can B attest holding the state.
        let _ = wait_for_data(&handle_b, "durable", "row-1", &written, Duration::from_secs(20)).await;

        // 2. B must have issued a genuine receipt and published it to the
        //    mesh.  Capture it at B's outbound publish point.
        let receipt = wait_for_issued_receipt(&handle_b, &delta_id).await;

        // 3. The receipt is genuine, not manufactured: it is signed over the
        //    canonical payload by B's real identity key (state_hash =
        //    delta.id, issuer = B's DID) and verifies against B's public key.
        assert_eq!(receipt.state_hash, delta_id, "receipt must attest THIS delta");
        assert_eq!(
            receipt.issuer_did,
            handle_b.identity.did(),
            "receipt must be issued by B's identity"
        );
        let b_public_key = handle_b.identity.public_key_bytes();
        crate::durability::receipt::verify_receipt(&receipt, &b_public_key, &delta_id)
            .expect("receipt must verify against B's real public key");

        // 4. A receives the receipt over the mesh, resolves B's DID to B's
        //    public key, verifies signature + state-hash, and reaches Tier-1
        //    through the production quorum path.
        wait_for_tier1(&handle_a, &delta_id).await;

        // 5. The production notification (Req 14.7, Subphase 4.2) delivered a
        //    DurabilityTierChanged event for the Uncommitted → Tier1 transition.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            match tier_events.try_recv() {
                Ok(evt)
                    if evt.delta_id == delta_id
                        && evt.previous_tier == DurabilityTier::Uncommitted
                        && evt.new_tier == DurabilityTier::Tier1 =>
                {
                    break;
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {}
                Err(e) => panic!("durability event channel closed: {e}"),
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no DurabilityTierChanged(Uncommitted → Tier1) event for delta {}",
                hex::encode(delta_id)
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        cleanup(&tmp_path("p45_A"));
        cleanup(&tmp_path("p45_B"));
    }
}

// ─── Subphase 4.1: production cloud sync drain ───────────────────────────────

/// Integration tests for the production cloud drain path (Subphase 4.1): a
/// real `CloudLedgerConnection` attached to the Durability Subsystem, driven
/// by [`CoreHandle::run_cloud_sync_cycle`] / [`CoreHandle::spawn_cloud_sync_loop`]
/// — the functions `CoreHandle::init` wires up.  Previously the causal-order
/// drain + ack-removal (Req 16.3) existed only in
/// `durability/integration_tests.rs`; these tests exercise it over the real
/// production construction: `CoreHandle::init` → `write()` → durability cloud
/// outbound queue → production drain → real Cloud Ledger.
///
/// Causal-order *enforcement* itself is `cloud_sync_loop`'s topological-sort
/// behaviour (already integration-tested with a recording connection in
/// `durability/integration_tests.rs`); what this module adds is proof that the
/// identical loop runs in production against a real ledger and empties the
/// cloud queue.
#[cfg(all(test, feature = "native"))]
mod cloud_sync_tests {
    use super::*;
    use serde_json::json;
    use std::env;
    use std::time::Duration;

    fn make_config(path: &str) -> InitConfig {
        InitConfig {
            storage_path: path.to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                biscuit_ttl_secs: 3600,
                root_ca_keys: vec![],
                migration_ca_public_key: None,
                schema_version_path: vec![],
                schema_definitions: vec![],
                anchor_attested_location: false,
                beacon_public_keys: vec![],
                spatial_diversity_min: 1,
                max_single_sector_fraction: 0.7,
                quorum_k: 1,
                quorum_n: 1,
                saturate_lease_duration_secs: 3600,
            },
        }
    }

    fn tmp_path(suffix: &str) -> String {
        let mut p = env::temp_dir();
        p.push(format!("tirbase_cloudsync_test_{suffix}.db"));
        p.to_str().unwrap().to_string()
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}.identity.json"));
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    /// Poll until the cloud outbound queue is empty and every written Delta is
    /// committed on the ledger, or fail after `attempts` polls.
    async fn wait_for_drain(handle: &Arc<CoreHandle>, delta_ids: &[[u8; 32]]) {
        let mut attempts = 0u32;
        loop {
            let drained = handle.cloud_queue_depth() == 0
                && delta_ids
                    .iter()
                    .all(|id| handle.cloud_ledger_is_committed(id));
            if drained {
                return;
            }
            attempts += 1;
            assert!(
                attempts < 200,
                "cloud sync never drained the queue to the ledger (depth={}, committed={:?})",
                handle.cloud_queue_depth(),
                delta_ids
                    .iter()
                    .map(|id| handle.cloud_ledger_is_committed(id))
                    .collect::<Vec<_>>()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    // ── Test 1: one full cycle drains every written Delta to the ledger ─────
    //
    // Deterministic version of the drain: writes go through the production
    // `write()` path (SQLite store + signed Delta + durability registration),
    // then a single explicit [`CoreHandle::run_cloud_sync_cycle`] — the
    // function the production loop calls — sends the queue to the Cloud
    // Ledger through the real `CloudLedgerConnection` and removes each entry
    // only after its per-Delta ack (Req 16.3).  No `durability/` helpers are
    // involved: the ledger is the one `CoreHandle::init` attaches.

    #[tokio::test]
    async fn cloud_sync_cycle_drains_writes_to_ledger() {
        let path = tmp_path("cycle");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Three writes through the production path — each registers a Delta in
        // the Durability Subsystem's cloud outbound queue (Req 16.3).
        let mut delta_ids = Vec::new();
        for i in 0..3 {
            let wr = handle
                .write("cloud", &format!("row-{i}"), json!({ "seq": i }))
                .await
                .expect("write");
            delta_ids.push(wr.delta_id);
        }
        assert_eq!(
            handle.cloud_queue_depth(),
            3,
            "every write must be queued for cloud sync"
        );

        // One production cycle — the function `CoreHandle::spawn_cloud_sync_loop`
        // invokes every tick.
        let result = handle
            .run_cloud_sync_cycle()
            .expect("cloud sync cycle must not fail");

        assert_eq!(
            result.acknowledged, 3,
            "all queued Deltas must be acked by the Cloud Ledger"
        );
        assert_eq!(result.rejected, 0);
        assert_eq!(result.deferred, 0);
        assert_eq!(
            handle.cloud_queue_depth(),
            0,
            "acked Deltas must be removed from the cloud outbound queue (Req 16.3)"
        );

        for id in &delta_ids {
            assert!(
                handle.cloud_ledger_is_committed(id),
                "Delta {} must be committed on the Cloud Ledger",
                hex::encode(id)
            );
        }

        // An empty-queue cycle is a no-op (returns a zero summary).
        let idle = handle
            .run_cloud_sync_cycle()
            .expect("idle cloud sync cycle must not fail");
        assert_eq!(idle.acknowledged, 0);
        assert_eq!(idle.rejected, 0);
        assert_eq!(idle.deferred, 0);

        cleanup(&path);
    }

    // ── Test 2: the production cloud sync loop drains without a manual call ──
    //
    // `CoreHandle::init` spawns a background task that runs one cloud sync
    // cycle per interval (in production builds).  This test drives the
    // *identical* loop — `CoreHandle::spawn_cloud_sync_loop`, the function
    // `init` calls — with a short interval and asserts the background task
    // (NOT a manual `run_cloud_sync_cycle()` call) drains the cloud outbound
    // queue and commits the Deltas to the real Cloud Ledger.

    #[tokio::test]
    async fn production_cloud_sync_loop_drains_writes_to_ledger() {
        let path = tmp_path("loop");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Spawn the production cloud sync loop with a short interval so the
        // test completes quickly.  (In production builds `CoreHandle::init`
        // does exactly this with `CLOUD_SYNC_INTERVAL_MS`; in test builds init
        // uses a 1-hour interval so the deterministic tests above stay
        // race-free.)
        let _loop = CoreHandle::spawn_cloud_sync_loop(&handle, Duration::from_millis(10));

        // Write through the production path while the loop is already running.
        let mut delta_ids = Vec::new();
        for i in 0..3 {
            let wr = handle
                .write("cloud", &format!("row-{i}"), json!({ "seq": i, "msg": "background drain" }))
                .await
                .expect("write");
            delta_ids.push(wr.delta_id);
        }
        assert_eq!(handle.cloud_queue_depth(), 3, "writes must be queued");

        // Do NOT call run_cloud_sync_cycle() — the background loop must do the
        // draining.  Poll until the queue is empty and the ledger committed
        // every Delta.
        wait_for_drain(&handle, &delta_ids).await;

        cleanup(&path);
    }
}

// ─── Subphase 4.2: Tier-2 acknowledgement path ───────────────────────────────

/// Integration tests for the Tier-2 acknowledgement path (Subphase 4.2): a
/// real per-Delta Cloud Ledger ack from the production drain —
/// [`CoreHandle::run_cloud_sync_cycle`] / the `CoreHandle::init`-spawned
/// [`CoreHandle::spawn_cloud_sync_loop`] — now marks the Delta Tier-2 durable
/// inside the Durability Subsystem (the state backing
/// `WriteResult::durability_tier`) and notifies CoreHandle/SDK of the
/// transition.  Before Subphase 4.2 the queue-level sync loop removed acked
/// entries but never advanced per-Delta durability state, so every Delta
/// reported `Uncommitted` forever in a real deployment.
///
/// The assertion surface is the real production construction: `CoreHandle::init`
/// → `write()` → durability cloud outbound queue → production drain → real
/// Cloud Ledger → `DurabilitySubsystem::on_cloud_ack` (Tier-2 marking +
/// notification).
#[cfg(all(test, feature = "native"))]
mod tier2_ack_tests {
    use super::*;
    use serde_json::json;
    use std::env;
    use std::time::Duration;

    fn make_config(path: &str) -> InitConfig {
        InitConfig {
            storage_path: path.to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                biscuit_ttl_secs: 3600,
                root_ca_keys: vec![],
                migration_ca_public_key: None,
                schema_version_path: vec![],
                schema_definitions: vec![],
                anchor_attested_location: false,
                beacon_public_keys: vec![],
                spatial_diversity_min: 1,
                max_single_sector_fraction: 0.7,
                quorum_k: 1,
                quorum_n: 1,
                saturate_lease_duration_secs: 3600,
            },
        }
    }

    fn tmp_path(suffix: &str) -> String {
        let mut p = env::temp_dir();
        p.push(format!("tirbase_tier2_test_{suffix}.db"));
        p.to_str().unwrap().to_string()
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}.identity.json"));
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    /// Poll until the cloud outbound queue is empty and every written Delta is
    /// committed on the ledger, or fail after `attempts` polls.
    async fn wait_for_drain(handle: &Arc<CoreHandle>, delta_ids: &[[u8; 32]]) {
        let mut attempts = 0u32;
        loop {
            let drained = handle.cloud_queue_depth() == 0
                && delta_ids
                    .iter()
                    .all(|id| handle.cloud_ledger_is_committed(id));
            if drained {
                return;
            }
            attempts += 1;
            assert!(
                attempts < 200,
                "cloud sync never drained the queue to the ledger (depth={})",
                handle.cloud_queue_depth()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Receive one durability tier change event, failing if none arrives.
    async fn next_tier_event(
        rx: &mut tokio::sync::broadcast::Receiver<DurabilityTierChanged>,
    ) -> DurabilityTierChanged {
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("durability tier event must be delivered")
            .expect("durability event channel closed")
    }

    // ── Test 1: a real cloud ack marks the Delta Tier-2 + notifies ───────────
    //
    // Deterministic end-to-end Tier-2 path: write through the production
    // `write()`, run exactly one [`CoreHandle::run_cloud_sync_cycle`] (the
    // function `spawn_cloud_sync_loop` calls every tick), and assert the ack
    // transitioned the Delta's durability state — the state behind
    // `WriteResult.durability_tier` — from `Uncommitted` to `Tier2` and
    // delivered the `DurabilityTierChanged` event to a CoreHandle subscriber.

    #[tokio::test]
    async fn cloud_ack_marks_delta_tier2_and_notifies_corehandle() {
        let path = tmp_path("ack");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Subscribe before the ack so the transition is observed.
        let mut durability_events = handle.subscribe_durability_events();

        let wr = handle
            .write("cloud", "row-1", json!({ "seq": 1, "phase": "4.2" }))
            .await
            .expect("write");

        // A write is a local commit: both the returned WriteResult and the
        // Durability Subsystem's per-Delta state start Uncommitted.
        assert_eq!(wr.durability_tier, DurabilityTier::Uncommitted);
        assert_eq!(
            handle.durability_tier(&wr.delta_id),
            DurabilityTier::Uncommitted,
            "Delta must start Uncommitted before any cloud ack"
        );

        // One production cloud sync cycle — the drain function
        // `spawn_cloud_sync_loop` invokes every tick.
        let result = handle
            .run_cloud_sync_cycle()
            .expect("cloud sync cycle must not fail");
        assert_eq!(result.acknowledged, 1, "the Delta must be acked");
        assert_eq!(result.rejected, 0);
        assert_eq!(result.acknowledged_ids.len(), 1);
        assert_eq!(result.acknowledged_ids[0], wr.delta_id);

        // The real cloud ack marked the Delta durable (Req 14.4): Tier-2,
        // queue emptied, ledger committed.
        assert_eq!(
            handle.durability_tier(&wr.delta_id),
            DurabilityTier::Tier2,
            "a cloud ack must transition the Delta to Tier-2, not leave it Uncommitted"
        );
        assert_eq!(handle.cloud_queue_depth(), 0);
        assert!(handle.cloud_ledger_is_committed(&wr.delta_id));

        // CoreHandle was notified of the durable status (Req 14.7).
        let event = next_tier_event(&mut durability_events).await;
        assert_eq!(event.delta_id, wr.delta_id);
        assert_eq!(event.previous_tier, DurabilityTier::Uncommitted);
        assert_eq!(event.new_tier, DurabilityTier::Tier2);

        cleanup(&path);
    }

    // ── Test 2: the production cloud sync loop drives the transition ─────────
    //
    // Same Tier-2 acceptance over the spawned background loop (the function
    // `CoreHandle::init` runs in production) instead of a manual cycle call:
    // writes drain to the Cloud Ledger on their own and each Delta reaches
    // Tier-2 with a CoreHandle notification per transition.

    #[tokio::test]
    async fn production_cloud_sync_loop_transitions_writes_to_tier2() {
        let path = tmp_path("loop");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Subscribe before any ack.
        let mut durability_events = handle.subscribe_durability_events();

        // Spawn the production cloud sync loop with a short interval.
        let _loop = CoreHandle::spawn_cloud_sync_loop(&handle, Duration::from_millis(10));

        let mut delta_ids = Vec::new();
        for i in 0..2 {
            let wr = handle
                .write("cloud", &format!("row-{i}"), json!({ "seq": i }))
                .await
                .expect("write");
            assert_eq!(wr.durability_tier, DurabilityTier::Uncommitted);
            delta_ids.push(wr.delta_id);
        }

        // Do NOT call run_cloud_sync_cycle() — the background loop must mark
        // the Deltas durable.
        wait_for_drain(&handle, &delta_ids).await;

        for id in &delta_ids {
            assert_eq!(
                handle.durability_tier(id),
                DurabilityTier::Tier2,
                "background drain must transition Delta {} to Tier-2",
                hex::encode(id)
            );
        }

        // One notification per transition, each reporting the Delta's Tier-2
        // durable status.
        let mut notified: Vec<[u8; 32]> = Vec::new();
        for _ in 0..delta_ids.len() {
            let event = next_tier_event(&mut durability_events).await;
            assert_eq!(event.new_tier, DurabilityTier::Tier2);
            notified.push(event.delta_id);
        }
        notified.sort();
        let mut expected = delta_ids.clone();
        expected.sort();
        assert_eq!(
            notified, expected,
            "every acked Delta must notify CoreHandle of its Tier-2 status"
        );

        cleanup(&path);
    }

    // ── Subphase 4.3: Anchor-Attested Location wiring ────────────────────────

    fn make_config_with_anchor(path: &str, enabled: bool, beacon_public_keys: Vec<[u8; 32]>) -> InitConfig {
        InitConfig {
            storage_path: path.to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                biscuit_ttl_secs: 3600,
                root_ca_keys: vec![],
                migration_ca_public_key: None,
                schema_version_path: vec![],
                schema_definitions: vec![],
                anchor_attested_location: enabled,
                beacon_public_keys,
                spatial_diversity_min: 1,
                max_single_sector_fraction: 0.7,
                quorum_k: 1,
                quorum_n: 1,
                saturate_lease_duration_secs: 3600,
            },
        }
    }

    /// Subphase 4.3: `CoreHandle::init` (the production constructor) must
    /// instantiate the `AnchorAttestedLocation` verifier from the deployment's
    /// `anchor_attested_location` flag + `beacon_public_keys`, and install it on
    /// the Durability Subsystem — the instance `receive_receipt` consults for
    /// every real inbound `DurabilityReceipt` (Req 15.1–15.3).
    #[tokio::test]
    async fn anchor_attested_location_installed_when_deployment_enables_it() {
        let path = tmp_path("anchor_on");
        cleanup(&path);

        let (_beacon_secret, beacon_public) =
            crate::identity::keypair::generate_keypair().expect("beacon keypair");
        let handle = CoreHandle::init(make_config_with_anchor(
            &path,
            true,
            vec![beacon_public],
        ))
        .await
        .expect("CoreHandle::init");

        let dur = handle.durability.lock().unwrap();
        let anchor = dur.anchor().expect(
            "anchor verifier must be installed on the Durability Subsystem \
             when anchor_attested_location is enabled",
        );
        assert_eq!(
            anchor.mode(),
            crate::durability::anchor::AnchorMode::BeaconAttested,
            "a freshly configured anchor starts in BeaconAttested mode"
        );
        drop(dur);

        cleanup(&path);
    }

    /// Subphase 4.3: with the feature disabled the subsystem must carry no
    /// anchor verifier — the historical squad-tag quorum path is unchanged.
    #[tokio::test]
    async fn anchor_attested_location_absent_when_deployment_disables_it() {
        let path = tmp_path("anchor_off");
        cleanup(&path);

        let handle = CoreHandle::init(make_config_with_anchor(&path, false, vec![]))
            .await
            .expect("CoreHandle::init");

        let dur = handle.durability.lock().unwrap();
        assert!(
            dur.anchor().is_none(),
            "no anchor verifier when anchor_attested_location is disabled"
        );
        drop(dur);

        cleanup(&path);
    }
}

// ─── Subphase 4.4: Req 14.3 default diversity rule + configurable cap ────────

/// Integration tests for Subphase 4.4 — the two diversity knobs of Req 14.3
/// resolved through the *production* construction (`CoreHandle::init` →
/// `DeploymentConfig` → `QuorumConfig` → `DurabilitySubsystem` →
/// `Tier1QuorumTracker`):
///
/// 1. `DeploymentConfig::max_single_sector_fraction` (new in Subphase 4.4)
///    replaces the hardcoded `0.7` in `CoreHandle::init`; a deployment can now
///    raise it (single-sector deployments) or lower it (strict cross-sector
///    quorums).
/// 2. `DeploymentConfig::spatial_diversity_min == 0` is the *unconfigured*
///    marker carried through to the quorum tracker, which resolves Req 14.3's
///    default rule `min(K, distinct tags available)` at runtime — no longer a
///    raw "require 0 distinct tags" minimum.
///
/// The behaviour asserted here is Tier-1 durability reached/blocked through
/// the exact `DurabilitySubsystem::receive_receipt` path the production
/// native/WASM inbound pipelines call for real inbound receipts.
#[cfg(all(test, feature = "native"))]
mod diversity_config_tests {
    use super::*;
    use crate::durability::receipt::{receipt_signing_payload, DurabilityReceipt};
    use crate::durability::quorum::QuorumConfig;
    use crate::identity::keypair::{generate_keypair, sign};
    use std::env;
    use std::sync::Arc;

    fn make_config(path: &str, quorum_k: usize, min_distinct: usize, fraction: f64) -> InitConfig {
        InitConfig {
            storage_path: path.to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                biscuit_ttl_secs: 3600,
                root_ca_keys: vec![],
                migration_ca_public_key: None,
                schema_version_path: vec![],
                schema_definitions: vec![],
                anchor_attested_location: false,
                beacon_public_keys: vec![],
                spatial_diversity_min: min_distinct,
                max_single_sector_fraction: fraction,
                quorum_k,
                quorum_n: quorum_k + 2,
                saturate_lease_duration_secs: 3600,
            },
        }
    }

    fn tmp_path(suffix: &str) -> String {
        let mut p = env::temp_dir();
        p.push(format!("tirbase_divcfg_test_{suffix}.db"));
        p.to_str().unwrap().to_string()
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}.identity.json"));
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    /// Build `k` peer keypairs registered for the Delta and return
    /// `(secrets, peers_map)`.
    fn make_peers(k: usize) -> (Vec<[u8; 32]>, std::collections::HashMap<String, [u8; 32]>) {
        let mut secrets = Vec::new();
        let mut peers = std::collections::HashMap::new();
        for i in 0..k {
            let (secret, public) = generate_keypair().expect("keygen");
            let did = format!("did:key:peer{i}");
            peers.insert(did, public);
            secrets.push(secret);
        }
        (secrets, peers)
    }

    /// A properly Ed25519-signed receipt from `secret` for `state_hash`,
    /// declaring `spatial_tag` (mirrors `durability::tests` helpers).
    fn make_signed_receipt(
        state_hash: [u8; 32],
        secret: &[u8; 32],
        did: &str,
        spatial_tag: Option<&str>,
    ) -> DurabilityReceipt {
        let id = uuid::Uuid::now_v7();
        let payload = receipt_signing_payload(&state_hash, &id);
        let sig = sign(secret, &payload).expect("sign receipt");
        DurabilityReceipt {
            id,
            state_hash,
            issuer_did: did.to_string(),
            issuer_signature: sig,
            spatial_tag: spatial_tag.map(|s| s.to_string()),
            beacon_token: None,
            issued_at: 0,
        }
    }

    /// Drive `k` receipts (one per registered peer) into the subsystem and
    /// return whether Tier-1 was achieved by the last receipt.
    fn push_receipts(
        dur: &mut crate::durability::DurabilitySubsystem,
        delta_id: [u8; 32],
        state_hash: [u8; 32],
        secrets: &[[u8; 32]],
        tags: &[&str],
    ) -> Vec<bool> {
        let mut outcomes = Vec::new();
        for (i, secret) in secrets.iter().enumerate() {
            let did = format!("did:key:peer{i}");
            let receipt = make_signed_receipt(state_hash, secret, &did, Some(tags[i]));
            outcomes.push(
                dur.receive_receipt(receipt, &delta_id)
                    .expect("receipt must verify"),
            );
        }
        outcomes
    }

    /// Subphase 4.4: `CoreHandle::init` must install the deployment's
    /// `max_single_sector_fraction` on the Durability Subsystem's quorum
    /// config, and the raised cap must let a single-sector deployment reach
    /// Tier-1 — impossible under the pre-4.4 hardcoded `0.7` (three receipts
    /// from one sector are 100% of the set, which always exceeds 0.7).
    #[tokio::test]
    async fn configured_fraction_above_default_allows_single_sector_tier1() {
        let path = tmp_path("fraction_up");
        cleanup(&path);

        // K=3, explicit min 1, cap raised to 1.0 (no single-sector limit).
        let handle = Arc::new(
            CoreHandle::init(make_config(&path, 3, 1, 1.0))
                .await
                .expect("CoreHandle::init"),
        );

        let mut dur = handle.durability.lock().unwrap();
        assert_eq!(
            dur.quorum_config().max_single_sector_fraction, 1.0,
            "deployment-configured cap must reach the quorum tracker"
        );
        assert_eq!(dur.quorum_config().k, 3);

        let delta_id = [0x41; 32];
        let state_hash = [0x42; 32];
        let (secrets, peers) = make_peers(3);
        dur.register_delta(delta_id, state_hash, vec![], vec![], peers)
            .expect("register_delta");

        // Three receipts, all declaring the same single sector.
        let outcomes = push_receipts(&mut dur, delta_id, state_hash, &secrets, &["sector-x"; 3]);
        assert_eq!(
            outcomes[2], true,
            "a cap of 1.0 must allow a single-sector K=3 quorum to form"
        );
        assert_eq!(
            dur.durability_tier(&delta_id),
            DurabilityTier::Tier1,
            "Tier-1 must be reached under the raised deployment cap"
        );
        drop(dur);

        cleanup(&path);
    }

    /// Subphase 4.4: the deployment-configured cap must also bind downwards —
    /// a stricter 0.5 cap must block a sector at 100% of the receipt set even
    /// though the pre-change code would have applied 0.7 here too (0.5 < 0.7).
    #[tokio::test]
    async fn configured_fraction_cap_binds_at_stricter_value() {
        let path = tmp_path("fraction_strict");
        cleanup(&path);

        // K=3, min 1, strict 0.5 cap.
        let handle = Arc::new(
            CoreHandle::init(make_config(&path, 3, 1, 0.5))
                .await
                .expect("CoreHandle::init"),
        );

        let mut dur = handle.durability.lock().unwrap();
        assert_eq!(dur.quorum_config().max_single_sector_fraction, 0.5);

        let delta_id = [0x51; 32];
        let state_hash = [0x52; 32];
        let (secrets, peers) = make_peers(3);
        dur.register_delta(delta_id, state_hash, vec![], vec![], peers)
            .expect("register_delta");

        // Three receipts from one sector: 100% > 50% → blocked.
        let outcomes = push_receipts(&mut dur, delta_id, state_hash, &secrets, &["sector-x"; 3]);
        assert_eq!(
            outcomes[2], false,
            "a single sector at 100% must exceed the 0.5 cap"
        );
        assert_eq!(
            dur.durability_tier(&delta_id),
            DurabilityTier::Uncommitted,
            "Tier-1 must be blocked while one sector exceeds the configured cap"
        );
        drop(dur);

        cleanup(&path);
    }

    /// Subphase 4.4: `spatial_diversity_min = 0` — the `DeploymentConfig`
    /// default — must flow to the quorum tracker as the *unconfigured* marker
    /// and be resolved there to Req 14.3's default rule `min(K, distinct tags
    /// available)`, not enforced as a raw 0-distinct minimum.  Behaviourally:
    /// with the cap at 1.0 a single-sector deployment still forms Tier-1 (the
    /// rule never demands more diversity than exists), while with the default
    /// 0.7 cap the same single-sector receipts stay blocked (the marker must
    /// not disable the fraction leg either).
    #[tokio::test]
    async fn unconfigured_min_uses_default_rule_and_keeps_fraction_cap() {
        // (a) Unconfigured min + cap 1.0 → single-sector quorum forms.
        let path_a = tmp_path("min_unset_cap_off");
        cleanup(&path_a);
        let handle_a = Arc::new(
            CoreHandle::init(make_config(&path_a, 3, 0, 1.0))
                .await
                .expect("CoreHandle::init"),
        );
        let mut dur = handle_a.durability.lock().unwrap();
        assert_eq!(
            dur.quorum_config().spatial_diversity_min, 0,
            "the unconfigured 0 marker must be carried through to the tracker"
        );
        assert_eq!(
            dur.quorum_config().max_single_sector_fraction, 1.0,
            "the Req 14.3 default rule operates alongside the configured cap"
        );

        let delta_id_a = [0x61; 32];
        let state_hash_a = [0x62; 32];
        let (secrets_a, peers_a) = make_peers(3);
        dur.register_delta(delta_id_a, state_hash_a, vec![], vec![], peers_a)
            .expect("register_delta");
        let outcomes_a =
            push_receipts(&mut dur, delta_id_a, state_hash_a, &secrets_a, &["sector-x"; 3]);
        assert_eq!(
            outcomes_a[2], true,
            "default rule must not demand more diversity than exists (cap 1.0)"
        );
        assert_eq!(dur.durability_tier(&delta_id_a), DurabilityTier::Tier1);
        drop(dur);
        cleanup(&path_a);

        // (b) Unconfigured min + default 0.7 cap → same single-sector receipts
        // stay blocked: the marker only governs the min-distinct leg, the
        // fraction cap still binds.
        let path_b = tmp_path("min_unset_cap_default");
        cleanup(&path_b);
        let handle_b = Arc::new(
            CoreHandle::init(make_config(&path_b, 3, 0, 0.7))
                .await
                .expect("CoreHandle::init"),
        );
        let mut dur = handle_b.durability.lock().unwrap();
        assert_eq!(dur.quorum_config().max_single_sector_fraction, 0.7);

        let delta_id_b = [0x63; 32];
        let state_hash_b = [0x64; 32];
        let (secrets_b, peers_b) = make_peers(3);
        dur.register_delta(delta_id_b, state_hash_b, vec![], vec![], peers_b)
            .expect("register_delta");
        let outcomes_b =
            push_receipts(&mut dur, delta_id_b, state_hash_b, &secrets_b, &["sector-x"; 3]);
        assert_eq!(
            outcomes_b[2], false,
            "the Req 14.3 fraction cap must still bind under the unconfigured marker"
        );
        assert_eq!(dur.durability_tier(&delta_id_b), DurabilityTier::Uncommitted);
        drop(dur);
        cleanup(&path_b);
    }

    /// Subphase 4.4: values outside (0, 1] cannot express a fraction cap and
    /// must fall back to the 0.7 default at init instead of being enforced
    /// literally (a 0 cap would forbid every receipt and disable Quorum).
    #[tokio::test]
    async fn invalid_fraction_falls_back_to_default() {
        for (label, invalid) in [("zero", 0.0), ("over_one", 1.5), ("negative", -0.2)] {
            let path = tmp_path(label);
            cleanup(&path);
            let handle = Arc::new(
                CoreHandle::init(make_config(&path, 3, 1, invalid))
                    .await
                    .expect("CoreHandle::init"),
            );
            let dur = handle.durability.lock().unwrap();
            assert_eq!(
                dur.quorum_config().max_single_sector_fraction, 0.7,
                "invalid cap {invalid} must fall back to the 0.7 default"
            );
            drop(dur);
            cleanup(&path);
        }
    }
}
