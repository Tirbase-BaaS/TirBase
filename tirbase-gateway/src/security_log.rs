//! Hash-chained security event log (PV-7.1–PV-7.6, INV-4, task 25).
//!
//! Production callers:
//! - [`SecurityEventLog`] implements [`SecurityEventSink`] and is installed as the
//!   process-wide sink so every `tirbase-core`/`tirbase-guard` `emit()` call site
//!   produces a chained, persisted record (CLAIM-25.1).
//! - Checkpoint loop: [`SecurityEventLog::spawn_checkpoint_loop`] (CLAIM-25.3).
//! - DB segment tracking helpers live alongside the log (CLAIM-25.5).
//!
//! Design notes:
//! - Per-event device signatures are NOT stored (checkpoints only, PV-7.3).
//! - `prev_hash = SHA-256(canonical_cbor(prev_chained_event_body))` (PV-7.2).
//! - In-memory ring bounded to 10,000; on overflow retains oldest checkpoint
//!   anchors and the most recent events (CLAIM-25.2, PV-7.6).
//! - High/Critical events flush immediately through the 19.4 group-commit
//!   batcher path; checkpoints are signed rows written to `security_events`.

#![allow(dead_code)] // APIs wired incrementally by 25.3 loop/admin paths.

use std::collections::HashMap;
use std::fs;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tirbase_core::events::{
    ReasonCode, SecurityEvent as SecurityEventPayload, SecurityEventCategory, Severity,
    TimeSourceFlag,
};
use tirbase_core::traits::{KeyProvider, SecurityEventSink};
use tirbase_core::transport::security_event_sync::{
    SecurityEventSyncBatch, SecurityEventSyncRecord,
};
use tirbase_guard::node_mode::{NodeMode, NodeModeState};
use tirbase_types::DeviceSignature;

use crate::db::peer_checkpoint_witnesses::{
    latest_local_checkpoint, list_peer_checkpoint_witnesses, upsert_peer_checkpoint_witness,
};
use crate::event_batcher::{EventBatchBackend, GroupCommitBatcher, DEFAULT_BATCH_WINDOW};
use crate::security_sink::MAX_EVENTS;

/// 25.1: chained security event record (PV-7.1, PV-7.2).
/// No per-event device signature; checkpoints carry `checkpoint_signature`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecurityEvent {
    pub seq: u64,
    pub segment_id: u64,
    pub category: SecurityEventCategory,
    pub severity: Severity,
    pub actor_did: Option<String>,
    pub target: Option<String>,
    pub reason_code: ReasonCode,
    pub best_effort_wall_time: i64,
    pub time_source_flag: TimeSourceFlag,
    pub prev_hash: [u8; 32],
    /// Present only on signed checkpoint rows (PV-7.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_signature: Option<DeviceSignature>,
    /// Present only on checkpoint rows: SHA-256 of canonical checkpoint body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_hash: Option<[u8; 32]>,
    /// GDPR salted commitments entering the hash chain (CLAIM-27.1, PV-7.7, RD-3).
    /// Each is `(field_name, SHA-256(random_salt ‖ value_plaintext))`.
    /// Empty for events without personal fields.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub personal_commitments: Vec<PersonalFieldCommitment>,
}

/// GDPR personal-field commitment entering the hash chain (CLAIM-27.1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersonalFieldCommitment {
    pub field_name: String,
    /// `SHA-256(random_salt ‖ value_plaintext)` — the salted form in the chain.
    pub commitment: [u8; 32],
}

/// Canonical body hashed into `prev_hash` / checkpoint hash (deterministic CBOR).
#[derive(Debug, Clone, Serialize)]
pub struct ChainHashBody<'a> {
    pub seq: u64,
    pub segment_id: u64,
    pub category: &'a str,
    pub severity: &'a str,
    pub actor_did: Option<&'a str>,
    pub target: Option<&'a str>,
    pub reason_code: &'a str,
    pub best_effort_wall_time: i64,
    pub time_source_flag: &'a str,
    pub prev_hash: &'a [u8; 32],
    pub is_checkpoint: bool,
    /// GDPR salted commitments (CLAIM-27.1); always included (empty vec = no personal fields).
    pub personal_commitments: &'a [PersonalFieldCommitment],
}

/// GDPR (CLAIM-27.1, PV-7.7, RD-3): salted commitment = SHA-256(random_salt || value_plaintext).
pub fn gdpr_salted_commitment(salt: &[u8; 32], value_plaintext: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(value_plaintext.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn random_salt_32() -> Result<[u8; 32], String> {
    let mut salt = [0u8; 32];
    getrandom::getrandom(&mut salt).map_err(|e| format!("salt rng: {e}"))?;
    Ok(salt)
}

fn persist_personal_fields(
    conn: &Connection,
    seq: u64,
    fields: &[(String, [u8; 32], String)],
) -> rusqlite::Result<()> {
    for (field_name, salt, plaintext) in fields {
        conn.execute(
            "INSERT OR REPLACE INTO security_event_personal_fields(seq, field_name, salt, plaintext) VALUES (?1, ?2, ?3, ?4)",
            params![seq as i64, field_name, salt.as_slice(), plaintext.as_bytes()],
        )?;
    }
    Ok(())
}

pub fn read_personal_fields_for_seq(
    conn: &Connection,
    seq: u64,
) -> rusqlite::Result<Vec<(String, [u8; 32], Vec<u8>)>> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS security_event_personal_fields (seq INTEGER NOT NULL, field_name TEXT NOT NULL, salt BLOB NOT NULL, plaintext BLOB NOT NULL, PRIMARY KEY (seq, field_name));",
    )?;
    let mut stmt = conn.prepare(
        "SELECT field_name, salt, plaintext FROM security_event_personal_fields WHERE seq=?1 ORDER BY field_name ASC",
    )?;
    let rows = stmt.query_map(params![seq as i64], |r| {
        let salt_blob: Vec<u8> = r.get(1)?;
        let mut salt = [0u8; 32];
        if salt_blob.len() == 32 {
            salt.copy_from_slice(&salt_blob);
        }
        Ok((r.get::<_, String>(0)?, salt, r.get::<_, Vec<u8>>(2)?))
    })?;
    rows.collect()
}

pub fn canonical_hash_bytes(body: &ChainHashBody<'_>) -> [u8; 32] {
    let mut buf = Vec::with_capacity(256);
    // ciborium produces deterministic CBOR for canonical map key ordering in
    // struct fields as declared; body field order is fixed.
    let _ = ciborium::ser::into_writer(body, &mut buf);
    let digest = Sha256::digest(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn event_hash(record: &SecurityEvent, is_checkpoint: bool) -> [u8; 32] {
    let body = ChainHashBody {
        seq: record.seq,
        segment_id: record.segment_id,
        category: record.category.as_str(),
        severity: record.severity.as_str(),
        actor_did: record.actor_did.as_deref(),
        target: record.target.as_deref(),
        reason_code: record.reason_code.as_str(),
        best_effort_wall_time: record.best_effort_wall_time,
        time_source_flag: record.time_source_flag.as_str(),
        prev_hash: &record.prev_hash,
        is_checkpoint,
        personal_commitments: &record.personal_commitments,
    };
    canonical_hash_bytes(&body)
}

/// S14 (PV-7.6): per-category rate limit.
pub const SECURITY_LOG_RATE_LIMIT_PER_CATEGORY_PER_SEC: u32 = 100;
/// PV-7.6/S14: ring cap (anchors + recent).
pub const SECURITY_LOG_RING_CAP: usize = 10_000;

/// 28.3 (PV-7.12): max local records per outbound sync batch. The mesh sync
/// ingress accepts 500 events/minute per peer; flushing one batch per second
/// at this size stays below that limit.
pub const SECURITY_EVENT_SYNC_BATCH_MAX: usize = 8;
/// 28.3: outbound sync flush period.
pub const SECURITY_EVENT_SYNC_FLUSH: Duration = Duration::from_secs(1);
/// 28.3: bounded outbound sync backlog (oldest records dropped on overflow).
pub const SECURITY_EVENT_SYNC_OUTBOX_CAP: usize = 4_096;

/// 28.3 production publisher installed by [`crate::mesh_wiring`].
struct SyncPublisher {
    sender_did: String,
    publish: Arc<dyn Fn(SecurityEventSyncBatch) + Send + Sync>,
}

#[derive(Debug, Clone)]
struct RateLimitState {
    tokens: f64,
    last_refill: Instant,
    suppressed_in_window: u64,
    window_started: Instant,
    window_last_emitted: Option<Instant>,
}

impl RateLimitState {
    fn new(now: Instant) -> Self {
        Self {
            tokens: SECURITY_LOG_RATE_LIMIT_PER_CATEGORY_PER_SEC as f64,
            last_refill: now,
            suppressed_in_window: 0,
            window_started: now,
            window_last_emitted: None,
        }
    }
}

#[derive(Debug, Default)]
struct CategoryRateLimiter {
    by_category: HashMap<String, RateLimitState>,
}

impl CategoryRateLimiter {
    fn allow_or_suppress(
        &mut self,
        category: &str,
        severity: Severity,
        now: Instant,
    ) -> (bool, Option<u64>) {
        // S14: HIGH/CRITICAL bypass the rate limiter.
        if matches!(severity, Severity::High | Severity::Critical) {
            return (true, None);
        }
        let cap = SECURITY_LOG_RATE_LIMIT_PER_CATEGORY_PER_SEC as f64;
        let state = self
            .by_category
            .entry(category.to_string())
            .or_insert_with(|| RateLimitState::new(now));
        let elapsed = now.duration_since(state.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            state.tokens = (state.tokens + elapsed * cap).min(cap);
            state.last_refill = now;
        }
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            let summary = if state.suppressed_in_window > 0
                && state
                    .window_last_emitted
                    .map(|t| now.duration_since(t) >= Duration::from_secs(1))
                    .unwrap_or(true)
            {
                let n = state.suppressed_in_window;
                state.suppressed_in_window = 0;
                state.window_last_emitted = Some(now);
                Some(n)
            } else {
                None
            };
            return (true, summary);
        }
        state.suppressed_in_window = state.suppressed_in_window.saturating_add(1);
        // Emit a suppression summary once per window if not already emitted recently.
        let summary = if state.suppressed_in_window == 1
            || state
                .window_last_emitted
                .map(|t| now.duration_since(t) >= Duration::from_secs(1))
                .unwrap_or(true)
        {
            state.window_last_emitted = Some(now);
            // summary count reported separately; keep accumulating.
            Some(state.suppressed_in_window)
        } else {
            None
        };
        (false, summary)
    }
}

/// 25.2: in-memory ring retaining oldest checkpoint anchors + most recent events.
#[derive(Debug)]
struct SecurityEventRing {
    anchors: Vec<SecurityEvent>,
    recent: std::collections::VecDeque<SecurityEvent>,
    cap: usize,
}

impl SecurityEventRing {
    fn new(cap: usize) -> Self {
        Self {
            anchors: Vec::new(),
            recent: std::collections::VecDeque::with_capacity(cap.min(4096)),
            cap,
        }
    }

    fn push(&mut self, event: SecurityEvent) {
        let is_anchor = event.checkpoint_signature.is_some()
            || matches!(
                event.reason_code,
                ReasonCode::CheckpointWritten
                    | ReasonCode::ChainRecovery
                    | ReasonCode::TamperDetection
                    | ReasonCode::TailTruncation
            );
        if is_anchor {
            self.anchors.push(event.clone());
        }
        self.recent.push_back(event);
        self.evict_to_cap();
    }

    fn evict_to_cap(&mut self) {
        let total = self.anchors.len() + self.recent.len();
        if total <= self.cap {
            return;
        }
        // Keep all anchors (bounded in practice by checkpoints) and trim oldest
        // non-anchor recent events first. If anchors alone exceed cap (pathological),
        // retain the oldest anchors (first) and newest anchors to fit.
        while self.anchors.len() + self.recent.len() > self.cap {
            if let Some(front) = self.recent.front() {
                let front_anchor = front.checkpoint_signature.is_some()
                    || matches!(
                        front.reason_code,
                        ReasonCode::CheckpointWritten
                            | ReasonCode::ChainRecovery
                            | ReasonCode::TamperDetection
                            | ReasonCode::TailTruncation
                    );
                if front_anchor {
                    // Don't drop anchors from recent; drop oldest non-anchor by scanning.
                    if let Some(pos) = self.recent.iter().position(|e| {
                        !(e.checkpoint_signature.is_some()
                            || matches!(
                                e.reason_code,
                                ReasonCode::CheckpointWritten
                                    | ReasonCode::ChainRecovery
                                    | ReasonCode::TamperDetection
                                    | ReasonCode::TailTruncation
                            ))
                    }) {
                        self.recent.remove(pos);
                        continue;
                    }
                    // Only anchors remain in recent; trim middle anchors from anchors vec if over cap.
                    if self.anchors.len() > 2 && self.anchors.len() + self.recent.len() > self.cap {
                        let mid = self.anchors.len() / 2;
                        self.anchors.remove(mid);
                        continue;
                    }
                    self.recent.pop_front();
                } else {
                    self.recent.pop_front();
                }
            } else {
                if self.anchors.len() > 2 {
                    let mid = self.anchors.len() / 2;
                    self.anchors.remove(mid);
                } else {
                    break;
                }
            }
        }
    }

    fn len(&self) -> usize {
        // anchors may duplicate recent; count unique by seq for diagnostics.
        self.recent.len()
    }

    fn snapshot(&self) -> Vec<SecurityEvent> {
        let mut out: Vec<SecurityEvent> = self.anchors.clone();
        for e in &self.recent {
            if !out.iter().any(|a| a.seq == e.seq) {
                out.push(e.clone());
            }
        }
        out.sort_by_key(|e| e.seq);
        out
    }
}

/// Configuration for checkpointing (25.3).
#[derive(Debug, Clone, Copy)]
pub struct CheckpointConfig {
    pub every_events: u64,
    pub every_secs: u64,
}

impl Default for CheckpointConfig {
    fn default() -> Self {
        Self {
            every_events: 100,
            every_secs: 60,
        }
    }
}

/// SQLite backend used by [`SecurityEventLog`] when persistence is enabled.
#[derive(Debug)]
pub struct SqliteEventBackend {
    path: PathBuf,
}

impl SqliteEventBackend {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn open(&self) -> Result<Connection, String> {
        let conn =
            Connection::open(&self.path).map_err(|e| format!("open security log db: {e}"))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| format!("wal: {e}"))?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|e| format!("sync: {e}"))?;
        ensure_security_log_schema(&conn).map_err(|e| format!("schema: {e}"))?;
        Ok(conn)
    }
}

impl EventBatchBackend for SqliteEventBackend {
    fn flush(&self, batch: Vec<SecurityEventPayload>) {
        // Payload-only flush path: real chaining/persistence happens in
        // SecurityEventLog::emit() which writes chained rows. This backend is a
        // compatibility hook for the batcher; no-op to avoid double-writing.
        let _ = batch;
    }
}

/// Ensure security_events/checkpoint_hash and segment table exist (25.4/25.5).
pub fn ensure_security_log_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS security_event_segments (
            segment_id     INTEGER PRIMARY KEY,
            started_at_seq INTEGER NOT NULL,
            ended_at_seq   INTEGER,
            start_hash     BLOB NOT NULL,
            reason         TEXT NOT NULL
        );",
    )?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS peer_checkpoint_witnesses (
            peer_did        TEXT PRIMARY KEY,
            seq             INTEGER NOT NULL,
            checkpoint_hash BLOB NOT NULL,
            observed_at     INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS security_events (
            seq                  INTEGER PRIMARY KEY,
            segment_id           INTEGER NOT NULL DEFAULT 1,
            category             TEXT NOT NULL,
            severity             TEXT NOT NULL,
            actor_did            TEXT,
            target               TEXT,
            reason_code          TEXT NOT NULL,
            best_effort_wall_ts  INTEGER NOT NULL,
            time_source_flag     TEXT NOT NULL,
            prev_hash            BLOB NOT NULL,
            is_checkpoint        INTEGER NOT NULL DEFAULT 0,
            checkpoint_signature BLOB,
            checkpoint_hash      BLOB
        );
        CREATE TABLE IF NOT EXISTS security_event_personal_fields (
            seq        INTEGER NOT NULL,
            field_name TEXT    NOT NULL,
            salt       BLOB    NOT NULL,
            plaintext  BLOB    NOT NULL,
            PRIMARY KEY (seq, field_name),
            FOREIGN KEY (seq) REFERENCES security_events(seq)
        );",
    )?;
    // 26.7a (PV-7.10): cloud-anchor checkpoint acknowledgements, one row per
    // anchor, recording the chain position the anchor has witnessed.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS cloud_anchor_witness (
            anchor_did      TEXT PRIMARY KEY,
            seq             INTEGER NOT NULL,
            checkpoint_hash BLOB NOT NULL,
            observed_at     INTEGER NOT NULL
        );",
    )?;
    // 28.3 (PV-7.9): received mesh security-event records are merged into an
    // append-only table keyed by their origin chain position.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS synced_security_events (
            origin_did         TEXT    NOT NULL,
            segment_id         INTEGER NOT NULL,
            seq                INTEGER NOT NULL,
            category           TEXT    NOT NULL,
            severity           TEXT    NOT NULL,
            actor_did          TEXT,
            target             TEXT,
            reason_code        TEXT    NOT NULL,
            best_effort_wall_ts INTEGER NOT NULL,
            time_source_flag   TEXT    NOT NULL,
            prev_hash          BLOB    NOT NULL,
            is_checkpoint      INTEGER NOT NULL,
            received_at        INTEGER NOT NULL,
            PRIMARY KEY (origin_did, segment_id, seq)
        );",
    )?;
    let has_col: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('security_events') WHERE name='checkpoint_hash'",
        [],
        |r| r.get(0),
    )?;
    if has_col == 0 {
        conn.execute_batch("ALTER TABLE security_events ADD COLUMN checkpoint_hash BLOB;")?;
    }
    Ok(())
}

#[derive(Debug)]
struct LogState {
    ring: SecurityEventRing,
    next_seq: u64,
    prev_hash: [u8; 32],
    segment_id: u64,
    events_since_checkpoint: u64,
    last_checkpoint_mono: Instant,
    rate_limiter: CategoryRateLimiter,
    restricted_by_tamper: bool,
    last_witness_check_mono: Instant,
}

/// 28.2 (PV-7.13): on-disk rolling retention and archive-then-delete rotation.
#[derive(Debug, Clone)]
pub struct SecurityLogRetentionConfig {
    /// 0 disables age-based retention.
    pub max_age_secs: i64,
    /// 0 disables size-based retention.
    pub max_bytes: i64,
    pub archive_dir: PathBuf,
    pub check_interval: Duration,
}

impl SecurityLogRetentionConfig {
    pub fn from_gateway_config(cfg: &crate::config::GatewayConfig) -> Self {
        let archive_dir = cfg.security_event_archive_dir.clone().unwrap_or_else(|| {
            cfg.counter_db_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("/var/lib/tirbase"))
                .join("security-log-archive")
        });
        Self {
            max_age_secs: cfg
                .security_event_retention_days
                .saturating_mul(24 * 60 * 60),
            max_bytes: cfg.security_event_retention_bytes,
            archive_dir,
            check_interval: Duration::from_secs(cfg.security_event_rotation_interval_secs.max(1)),
        }
    }
}

fn rot_sig_hex(sig: &DeviceSignature) -> String {
    match sig {
        DeviceSignature::Ed25519(b) => hex::encode(b),
        DeviceSignature::P256(b) => hex::encode(b),
    }
}

/// Hash-chained, checkpoint-capable security event log (25.1–25.5).
pub struct SecurityEventLog {
    state: Mutex<LogState>,
    primary_db: Option<PathBuf>,
    key_provider: RwLock<Option<Arc<dyn KeyProvider>>>,
    checkpoint: CheckpointConfig,
    batcher: Option<Arc<GroupCommitBatcher>>,
    checkpoint_stop: AtomicBool,
    /// Retained for diagnostics; checkpoint timing uses state.last_checkpoint_mono.
    _checkpoint_every_secs: AtomicU64,
    last_emit_wall: AtomicI64,
    node_mode: RwLock<Option<Arc<NodeModeState>>>,
    rate_limit_enabled: AtomicBool,
    retention: RwLock<Option<SecurityLogRetentionConfig>>,
    rotation_stop: AtomicBool,
    /// 26.7: real mesh-peer witness source (`true` when a mesh peer is connected).
    witness_source: RwLock<Option<Arc<dyn Fn() -> bool + Send + Sync>>>,
    /// 26.7a: set once a verified cloud-anchor acknowledgement has been
    /// ingested, so checkpoints stop reporting `NoWitnessAvailable`.
    cloud_anchor_seen: AtomicBool,
    /// 28.3: production publisher for local security-event sync batches.
    sync_publisher: RwLock<Option<SyncPublisher>>,
    /// 28.3: bounded outbound backlog drained by `spawn_security_event_sync_loop`.
    sync_outbox: Mutex<Vec<SecurityEventSyncRecord>>,
}

impl std::fmt::Debug for SecurityEventLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityEventLog")
            .field("primary_db", &self.primary_db)
            .field("checkpoint", &self.checkpoint)
            .finish()
    }
}

impl Default for SecurityEventLog {
    fn default() -> Self {
        Self::new_memory()
    }
}

impl SecurityEventLog {
    /// In-memory log (tests/compat). No DB persistence, no key signing.
    pub fn new_memory() -> Self {
        Self::with_options_inner(None, None, CheckpointConfig::default(), false, false)
    }

    /// Compatibility: batched in-memory constructor used by legacy wrappers.
    pub(crate) fn with_options_compat(batched: bool) -> Self {
        Self::with_options_inner(None, None, CheckpointConfig::default(), batched, false)
    }

    /// Production constructor: persists to `primary_db` and uses `key_provider`
    /// for checkpoint signatures when available.
    pub fn new_persistent(
        primary_db: impl Into<PathBuf>,
        key_provider: Option<Arc<dyn KeyProvider>>,
        batched: bool,
    ) -> Arc<Self> {
        Self::new_persistent_with_mode(primary_db, key_provider, batched, None)
    }

    /// Production constructor with node-mode integration (26.1/26.4/26.7).
    pub fn new_persistent_with_mode(
        primary_db: impl Into<PathBuf>,
        key_provider: Option<Arc<dyn KeyProvider>>,
        batched: bool,
        node_mode: Option<Arc<NodeModeState>>,
    ) -> Arc<Self> {
        let log = Arc::new(Self::with_options(
            Some(primary_db.into()),
            key_provider,
            CheckpointConfig::default(),
            batched,
        ));
        if let Some(mode) = node_mode {
            log.set_node_mode(mode);
        }
        if let Err(e) = log.init_from_db() {
            tracing::warn!(error = %e, "security event log init from db failed; starting fresh chain state");
        }
        log
    }

    fn with_options(
        primary_db: Option<PathBuf>,
        key_provider: Option<Arc<dyn KeyProvider>>,
        checkpoint: CheckpointConfig,
        batched: bool,
    ) -> Self {
        Self::with_options_inner(primary_db, key_provider, checkpoint, batched, false)
    }

    fn with_options_inner(
        primary_db: Option<PathBuf>,
        key_provider: Option<Arc<dyn KeyProvider>>,
        checkpoint: CheckpointConfig,
        batched: bool,
        rate_limit_enabled: bool,
    ) -> Self {
        let batcher = if batched {
            let backend = Arc::new(crate::event_batcher::RecordingBatchBackend::default());
            Some(GroupCommitBatcher::with_window(
                backend,
                DEFAULT_BATCH_WINDOW,
            ))
        } else {
            None
        };
        Self {
            state: Mutex::new(LogState {
                ring: SecurityEventRing::new(SECURITY_LOG_RING_CAP),
                next_seq: 1,
                prev_hash: [0u8; 32],
                segment_id: 1,
                events_since_checkpoint: 0,
                last_checkpoint_mono: Instant::now(),
                rate_limiter: CategoryRateLimiter::default(),
                restricted_by_tamper: false,
                last_witness_check_mono: Instant::now(),
            }),
            primary_db,
            key_provider: RwLock::new(key_provider),
            checkpoint,
            batcher,
            checkpoint_stop: AtomicBool::new(false),
            _checkpoint_every_secs: AtomicU64::new(checkpoint.every_secs),
            last_emit_wall: AtomicI64::new(0),
            node_mode: RwLock::new(None),
            rate_limit_enabled: AtomicBool::new(rate_limit_enabled),
            retention: RwLock::new(None),
            rotation_stop: AtomicBool::new(false),
            witness_source: RwLock::new(None),
            cloud_anchor_seen: AtomicBool::new(false),
            sync_publisher: RwLock::new(None),
            sync_outbox: Mutex::new(Vec::new()),
        }
    }

    pub fn set_rate_limit_enabled(&self, enabled: bool) {
        self.rate_limit_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Install as process-wide sink.
    pub fn install(self: &Arc<Self>) -> Arc<Self> {
        tirbase_core::events::install_security_event_sink(self.clone());
        self.clone()
    }

    pub fn set_key_provider(&self, kp: Arc<dyn KeyProvider>) {
        *self.key_provider.write().unwrap_or_else(|p| p.into_inner()) = Some(kp);
    }

    pub fn set_node_mode(&self, mode: Arc<NodeModeState>) {
        *self.node_mode.write().unwrap_or_else(|p| p.into_inner()) = Some(mode);
    }

    fn node_mode(&self) -> Option<Arc<NodeModeState>> {
        self.node_mode
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn enter_restricted(&self, reason: &str) {
        if let Some(mode) = self.node_mode() {
            mode.set(NodeMode::Restricted);
            tracing::error!(reason, mode = %mode.get().as_str(), "security log entered Restricted mode (INV-4/26.x)");
        }
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        st.restricted_by_tamper = true;
    }

    pub fn is_restricted_by_tamper(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .restricted_by_tamper
    }

    /// 26.1 compatibility name.
    pub fn verify_hash_chain(&self) -> Result<Option<u64>, String> {
        self.verify_hash_chain_at_startup()
    }

    /// 26.1: verify persisted hash chain at startup. On broken link, emit
    /// `TamperDetection` identifying the first broken sequence number, enter
    /// `Restricted` mode, and open a new chain segment from the next valid
    /// event boundary (next seq). Returns `Ok(None)` when intact, or the first
    /// broken sequence number when tamper was detected/handled.
    pub fn verify_hash_chain_at_startup(&self) -> Result<Option<u64>, String> {
        let Some(conn) = self.open_db()? else {
            return Ok(None);
        };
        let mut stmt = conn
            .prepare(
                "SELECT seq, segment_id, category, severity, actor_did, target, reason_code,                         best_effort_wall_ts, time_source_flag, prev_hash, is_checkpoint                  FROM security_events ORDER BY seq ASC",
            )
            .map_err(|e| format!("prepare verify: {e}"))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u64,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, i64>(7)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, Vec<u8>>(9)?,
                    r.get::<_, i64>(10)? != 0,
                ))
            })
            .map_err(|e| format!("query verify: {e}"))?;

        let mut expected_prev = [0u8; 32];
        let mut tip_hash = [0u8; 32];
        let mut max_seq: u64 = 0;
        let mut max_seg: u64 = 1;
        let mut first_broken: Option<u64> = None;

        for row in rows {
            let row = row.map_err(|e| format!("row verify: {e}"))?;
            let seq = row.0;
            max_seq = max_seq.max(seq);
            max_seg = max_seg.max(row.1);
            let mut stored_prev = [0u8; 32];
            if row.9.len() == 32 {
                stored_prev.copy_from_slice(&row.9);
            }
            let personal_commitments: Vec<PersonalFieldCommitment> =
                read_personal_fields_for_seq(&conn, row.0)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(field_name, salt, plaintext_bytes)| {
                        let plaintext = String::from_utf8_lossy(&plaintext_bytes);
                        PersonalFieldCommitment {
                            field_name,
                            commitment: gdpr_salted_commitment(&salt, &plaintext),
                        }
                    })
                    .collect();
            let body = ChainHashBody {
                seq: row.0,
                segment_id: row.1,
                category: &row.2,
                severity: &row.3,
                actor_did: row.4.as_deref(),
                target: row.5.as_deref(),
                reason_code: &row.6,
                best_effort_wall_time: row.7,
                time_source_flag: &row.8,
                prev_hash: &stored_prev,
                is_checkpoint: row.10,
                personal_commitments: &personal_commitments,
            };
            let computed = canonical_hash_bytes(&body);
            if stored_prev != expected_prev {
                first_broken = Some(seq);
                break;
            }
            expected_prev = computed;
            tip_hash = computed;
        }

        if let Some(broken_seq) = first_broken {
            // Ensure state continues after the known tail/chain and open a new segment.
            {
                let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
                st.next_seq = max_seq.saturating_add(1).max(st.next_seq);
                st.segment_id = max_seg.max(st.segment_id);
                st.prev_hash = tip_hash;
                st.events_since_checkpoint = 0;
            }
            let detail = format!(
                "hash-chain break detected at startup: first_broken_seq={broken_seq} (CLAIM-26.1, PV-7.4, INV-4)"
            );
            self.enter_restricted(&detail);
            // Emit tamper detection as a fresh, verifiable record in the new segment.
            let _ = self.start_new_segment("tamper-detection-recovery");
            self.append_payload_internal(
                SecurityEventPayload::new(
                    SecurityEventCategory::SecurityLog,
                    Severity::Critical,
                    ReasonCode::TamperDetection,
                )
                .with_detail(detail.clone())
                .with_target(broken_seq.to_string()),
                true,
            );
            return Ok(Some(broken_seq));
        }

        // Intact: set tip/next from DB if needed.
        if max_seq > 0 {
            let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            st.next_seq = max_seq.saturating_add(1).max(st.next_seq);
            st.prev_hash = tip_hash;
            st.segment_id = max_seg.max(st.segment_id);
        }
        Ok(None)
    }

    fn emit_suppression_summary(&self, category: &str, suppressed_count: u64) {
        if suppressed_count == 0 {
            return;
        }
        let payload = SecurityEventPayload::new(
            SecurityEventCategory::SecurityLog,
            Severity::Medium,
            ReasonCode::SuppressionSummary,
        )
        .with_target(category.to_string())
        .with_detail(format!(
            "suppressed {suppressed_count} security events in category {category} (S14, PV-7.6)"
        ));
        self.append_payload_internal(payload, true);
    }

    fn key_provider(&self) -> Option<Arc<dyn KeyProvider>> {
        self.key_provider
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn open_db(&self) -> Result<Option<Connection>, String> {
        let Some(path) = &self.primary_db else {
            return Ok(None);
        };
        let conn = Connection::open(path).map_err(|e| format!("open primary.db: {e}"))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| format!("wal: {e}"))?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|e| format!("sync: {e}"))?;
        ensure_security_log_schema(&conn).map_err(|e| format!("schema: {e}"))?;
        Ok(Some(conn))
    }

    fn init_from_db(&self) -> Result<(), String> {
        let Some(conn) = self.open_db()? else {
            return Ok(());
        };
        let row: Option<(u64, u64, Vec<u8>)> = conn
            .query_row(
                "SELECT seq, segment_id, prev_hash FROM security_events ORDER BY seq DESC LIMIT 1",
                [],
                |r| {
                    let seq: i64 = r.get(0)?;
                    let seg: i64 = r.get(1)?;
                    let prev: Vec<u8> = r.get(2)?;
                    Ok((seq as u64, seg as u64, prev))
                },
            )
            .optional()
            .map_err(|e| format!("query last security event: {e}"))?;
        if let Some((seq, segment_id, prev_hash)) = row {
            let mut hash = [0u8; 32];
            if prev_hash.len() == 32 {
                hash.copy_from_slice(&prev_hash);
            }
            // prev_hash stored on the row is prev of that row; chain tip hash is hash(row).
            // Reload last row as full record hash approximation: compute from stored fields.
            let tip_hash = self.compute_stored_row_hash(&conn, seq).unwrap_or(hash);
            let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            st.next_seq = seq.saturating_add(1);
            st.prev_hash = tip_hash;
            st.segment_id = segment_id.max(1);
            st.events_since_checkpoint = 0;
        }
        self.ensure_segment_row(&conn, 1, 1, [0u8; 32], "boot")
            .map_err(|e| format!("ensure segment: {e}"))?;
        Ok(())
    }

    fn compute_stored_row_hash(&self, conn: &Connection, seq: u64) -> Option<[u8; 32]> {
        let row = conn
            .query_row(
                "SELECT seq, segment_id, category, severity, actor_did, target, reason_code, \
                        best_effort_wall_ts, time_source_flag, prev_hash, is_checkpoint \
                 FROM security_events WHERE seq=?1",
                params![seq as i64],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)? as u64,
                        r.get::<_, i64>(1)? as u64,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, i64>(7)?,
                        r.get::<_, String>(8)?,
                        r.get::<_, Vec<u8>>(9)?,
                        r.get::<_, i64>(10)? != 0,
                    ))
                },
            )
            .optional()
            .ok()
            .flatten()?;
        let mut prev = [0u8; 32];
        if row.9.len() == 32 {
            prev.copy_from_slice(&row.9);
        }
        // GDPR (CLAIM-27.1): reconstruct commitments from stored plaintext+salt so
        // chain verification/hashing matches the committed form that entered the chain.
        let personal_commitments: Vec<PersonalFieldCommitment> =
            read_personal_fields_for_seq(conn, seq)
                .unwrap_or_default()
                .into_iter()
                .map(|(field_name, salt, plaintext_bytes)| {
                    let plaintext = String::from_utf8_lossy(&plaintext_bytes);
                    PersonalFieldCommitment {
                        field_name,
                        commitment: gdpr_salted_commitment(&salt, &plaintext),
                    }
                })
                .collect();
        let body = ChainHashBody {
            seq: row.0,
            segment_id: row.1,
            category: &row.2,
            severity: &row.3,
            actor_did: row.4.as_deref(),
            target: row.5.as_deref(),
            reason_code: &row.6,
            best_effort_wall_time: row.7,
            time_source_flag: &row.8,
            prev_hash: &prev,
            is_checkpoint: row.10,
            personal_commitments: &personal_commitments,
        };
        Some(canonical_hash_bytes(&body))
    }

    fn ensure_segment_row(
        &self,
        conn: &Connection,
        segment_id: u64,
        started_at_seq: u64,
        start_hash: [u8; 32],
        reason: &str,
    ) -> rusqlite::Result<()> {
        conn.execute(
            "INSERT OR IGNORE INTO security_event_segments(segment_id, started_at_seq, ended_at_seq, start_hash, reason) \
             VALUES (?1, ?2, NULL, ?3, ?4)",
            params![segment_id as i64, started_at_seq as i64, start_hash.as_slice(), reason],
        )?;
        Ok(())
    }

    /// Open/start a new chain segment (25.5). Production caller for recovery paths.
    pub fn start_new_segment(&self, reason: &str) -> Result<u64, String> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let old_seg = st.segment_id;
        let new_seg = old_seg.saturating_add(1);
        let started_at = st.next_seq;
        let start_hash = st.prev_hash;
        st.segment_id = new_seg;
        st.events_since_checkpoint = 0;
        drop(st);
        if let Some(conn) = self.open_db()? {
            conn.execute(
                "UPDATE security_event_segments SET ended_at_seq=?1 WHERE segment_id=?2 AND ended_at_seq IS NULL",
                params![started_at.saturating_sub(1) as i64, old_seg as i64],
            )
            .map_err(|e| format!("close segment: {e}"))?;
            self.ensure_segment_row(&conn, new_seg, started_at, start_hash, reason)
                .map_err(|e| format!("insert segment: {e}"))?;
        }
        Ok(new_seg)
    }

    fn persist_record(&self, conn: &Connection, rec: &SecurityEvent) -> rusqlite::Result<()> {
        tirbase_core::fail_crate::fail_point!("fp_security_log_persist_record", |_| Err(
            rusqlite::Error::InvalidQuery
        ));
        let is_checkpoint = rec.checkpoint_signature.is_some();
        conn.execute(
            "INSERT INTO security_events(
                seq, segment_id, category, severity, actor_did, target, reason_code,
                best_effort_wall_ts, time_source_flag, prev_hash, is_checkpoint,
                checkpoint_signature, checkpoint_hash
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                rec.seq as i64,
                rec.segment_id as i64,
                rec.category.as_str(),
                rec.severity.as_str(),
                rec.actor_did.as_deref(),
                rec.target.as_deref(),
                rec.reason_code.as_str(),
                rec.best_effort_wall_time,
                rec.time_source_flag.as_str(),
                rec.prev_hash.as_slice(),
                if is_checkpoint { 1i64 } else { 0i64 },
                rec.checkpoint_signature.as_ref().and_then(sig_to_bytes),
                rec.checkpoint_hash.as_ref().map(|h| h.as_slice()),
            ],
        )?;
        Ok(())
    }

    fn wall_time_now(&self) -> i64 {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.last_emit_wall.store(secs, Ordering::Relaxed);
        secs
    }

    fn time_flag(&self) -> TimeSourceFlag {
        // Monotonic/boot-time is always available; wall clock is a hint.
        TimeSourceFlag::LogicalFallback
    }

    /// Emit a security event with GDPR personal fields (CLAIM-27.1, PV-7.7, RD-3).
    /// Production caller for personal-field events: salted commitments enter the
    /// hash chain; plaintext is stored in `security_event_personal_fields`.
    pub fn append_payload_with_personal_fields(
        &self,
        mut payload: SecurityEventPayload,
        personal_fields: Vec<tirbase_core::events::PersonalField>,
    ) -> SecurityEvent {
        payload.personal_fields = personal_fields;
        self.append_payload(payload)
    }

    /// Append payload as a chained record (25.1). Returns the chained record.
    /// Applies S14 per-category rate limiting (100/sec, HIGH/CRITICAL bypass).
    pub fn append_payload(&self, payload: SecurityEventPayload) -> SecurityEvent {
        self.append_payload_internal(payload, false)
    }

    fn append_payload_internal(
        &self,
        payload: SecurityEventPayload,
        bypass_rate_limit: bool,
    ) -> SecurityEvent {
        let now = Instant::now();
        let (suppress_summary_count, suppressed) = if !self
            .rate_limit_enabled
            .load(Ordering::Relaxed)
            || bypass_rate_limit
            || matches!(payload.reason_code, ReasonCode::SuppressionSummary)
        {
            (None, false)
        } else {
            let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            let (allow, summary) =
                st.rate_limiter
                    .allow_or_suppress(payload.category.as_str(), payload.severity, now);
            (summary, !allow)
        };

        if let Some(count) = suppress_summary_count {
            if suppressed || count > 0 {
                // Avoid recursion by emitting summary via direct append with bypass.
                let summary_payload = SecurityEventPayload::new(
                    SecurityEventCategory::SecurityLog,
                    Severity::Medium,
                    ReasonCode::SuppressionSummary,
                )
                .with_target(payload.category.as_str().to_string())
                .with_detail(format!(
                    "suppressed security events in category {} count={} (S14, PV-7.6)",
                    payload.category.as_str(),
                    count
                ));
                // Only emit when first suppressed or periodic marker.
                if suppressed || count == 1 {
                    let _ = self.append_payload_internal(summary_payload, true);
                }
            }
        }

        if suppressed {
            // Return a synthetic non-persisted view is not possible; persist a minimal marker-less
            // path by returning current chain tip view is unsafe. Instead, record suppression above
            // and return a synthetic event (not persisted as the dropped payload).
            let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            return SecurityEvent {
                seq: st.next_seq.saturating_sub(1),
                segment_id: st.segment_id,
                category: payload.category,
                severity: payload.severity,
                actor_did: payload.actor_did,
                target: payload.target,
                reason_code: ReasonCode::SuppressionSummary,
                best_effort_wall_time: self.wall_time_now(),
                time_source_flag: self.time_flag(),
                prev_hash: st.prev_hash,
                checkpoint_signature: None,
                checkpoint_hash: None,
                personal_commitments: Vec::new(),
            };
        }

        let (rec, should_checkpoint, personal_rows) = {
            let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            let seq = st.next_seq;
            st.next_seq = st.next_seq.saturating_add(1);
            // GDPR (CLAIM-27.1, PV-7.7, RD-3): compute salted commitments for personal fields.
            // Plaintext is stored separately in security_event_personal_fields; only commitments
            // enter the hash chain. Wiring mutation: storing plaintext in the chain must fail tests.
            let mut personal_commitments: Vec<PersonalFieldCommitment> = Vec::new();
            let mut personal_rows: Vec<(String, [u8; 32], String)> = Vec::new();
            for pf in &payload.personal_fields {
                if let Ok(salt) = random_salt_32() {
                    let commitment = gdpr_salted_commitment(&salt, &pf.value_plaintext);
                    personal_commitments.push(PersonalFieldCommitment {
                        field_name: pf.field_name.clone(),
                        commitment,
                    });
                    personal_rows.push((pf.field_name.clone(), salt, pf.value_plaintext.clone()));
                }
            }
            let rec = SecurityEvent {
                seq,
                segment_id: st.segment_id,
                category: payload.category,
                severity: payload.severity,
                actor_did: payload.actor_did.clone(),
                target: payload.target.clone(),
                reason_code: payload.reason_code,
                best_effort_wall_time: self.wall_time_now(),
                time_source_flag: self.time_flag(),
                prev_hash: st.prev_hash,
                checkpoint_signature: None,
                checkpoint_hash: None,
                personal_commitments,
            };
            let h = event_hash(&rec, false);
            st.prev_hash = h;
            st.events_since_checkpoint = st.events_since_checkpoint.saturating_add(1);
            let elapsed = st.last_checkpoint_mono.elapsed().as_secs();
            let should = st.events_since_checkpoint >= self.checkpoint.every_events
                || elapsed >= self.checkpoint.every_secs;
            st.ring.push(rec.clone());
            (rec, should, personal_rows)
        };

        if let Ok(Some(conn)) = self.open_db() {
            let _ = self.persist_record(&conn, &rec);
            if !personal_rows.is_empty() {
                let _ = persist_personal_fields(&conn, rec.seq, &personal_rows);
            }
            let _ = self.ensure_segment_row(&conn, rec.segment_id, 1, [0u8; 32], "boot");
        }

        // 28.3 (PV-7.9): every appended record is offered to the mesh sync
        // publisher so peers receive the security-event stream.
        self.enqueue_security_event_sync(&rec);

        if let Some(batcher) = &self.batcher {
            batcher.emit(payload);
        }

        if should_checkpoint {
            let _ = self.try_checkpoint();
        }
        rec
    }

    /// 25.3: create a signed checkpoint row if a key provider is available.
    /// Checkpoint is stored as a security_events row with is_checkpoint=1.
    pub fn try_checkpoint(&self) -> Result<Option<u64>, String> {
        let kp = match self.key_provider() {
            Some(k) => k,
            None => return Ok(None),
        };
        let (mut checkpoint_rec, conn_opt) = {
            let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            let seq = st.next_seq;
            st.next_seq = st.next_seq.saturating_add(1);
            let mut rec = SecurityEvent {
                seq,
                segment_id: st.segment_id,
                category: SecurityEventCategory::SecurityLog,
                severity: Severity::Low,
                actor_did: Some(kp.did().to_string()),
                target: None,
                reason_code: ReasonCode::CheckpointWritten,
                best_effort_wall_time: self.wall_time_now(),
                time_source_flag: self.time_flag(),
                prev_hash: st.prev_hash,
                checkpoint_signature: None,
                checkpoint_hash: None,
                personal_commitments: Vec::new(),
            };
            let chash = event_hash(&rec, true);
            rec.checkpoint_hash = Some(chash);
            let sig = kp
                .sign(&chash)
                .map_err(|e| format!("checkpoint sign: {e}"))?;
            rec.checkpoint_signature = Some(sig);
            let row_hash = event_hash(&rec, true);
            st.prev_hash = row_hash;
            st.events_since_checkpoint = 0;
            st.last_checkpoint_mono = Instant::now();
            st.ring.push(rec.clone());
            (rec, self.open_db()?)
        };
        if let Some(conn) = conn_opt {
            self.persist_record(&conn, &checkpoint_rec)
                .map_err(|e| format!("persist checkpoint: {e}"))?;
        }
        // 28.3 (PV-7.9): checkpoint rows propagate to peers like any other record.
        self.enqueue_security_event_sync(&checkpoint_rec);
        // 26.7: record the real observed witness state; the source is wired
        // from the live mesh peer table in `CoreHandle` startup
        // (`set_witness_source`). Cloud-anchor gossip (task 36.8) is absent.
        let (has_mesh_peers, has_cloud_anchor) = self.witness_state();
        let _ = self.record_checkpoint_witness_status(has_mesh_peers, has_cloud_anchor);
        let _ = &mut checkpoint_rec;
        Ok(Some(checkpoint_rec.seq))
    }

    /// 25.3 production caller: background checkpoint loop (100 events or 60s).
    pub fn spawn_checkpoint_loop(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                if this.checkpoint_stop.load(Ordering::Relaxed) {
                    break;
                }
                let should = {
                    let st = this.state.lock().unwrap_or_else(|p| p.into_inner());
                    st.events_since_checkpoint >= this.checkpoint.every_events
                        || st.last_checkpoint_mono.elapsed().as_secs() >= this.checkpoint.every_secs
                };
                if should {
                    let _ = this.try_checkpoint();
                }
            }
        })
    }

    pub fn stop_checkpoint_loop(&self) {
        self.checkpoint_stop.store(true, Ordering::Relaxed);
    }

    /// 28.2 (PV-7.13, CLAIM-28.2): configure rolling retention/rotation.
    pub fn set_retention(&self, cfg: SecurityLogRetentionConfig) {
        *self.retention.write().unwrap_or_else(|p| p.into_inner()) = Some(cfg);
    }

    pub fn stop_retention_rotation_loop(&self) {
        self.rotation_stop.store(true, Ordering::Relaxed);
    }

    /// 28.2 production caller: background rotation job (PV-7.13).
    pub fn spawn_retention_rotation_loop(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let interval = this
                .retention
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .as_ref()
                .map(|c| c.check_interval)
                .unwrap_or(Duration::from_secs(300));
            let mut tick = tokio::time::interval(interval);
            loop {
                tick.tick().await;
                if this.rotation_stop.load(Ordering::Relaxed) {
                    break;
                }
                if let Err(e) = this.rotate_retention_if_needed() {
                    tracing::warn!(error = %e, "security log retention rotation failed (CLAIM-28.2)");
                }
            }
        })
    }

    fn retention_cfg(&self) -> Option<SecurityLogRetentionConfig> {
        self.retention
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn archive_signed_segment(
        &self,
        conn: &Connection,
        segment_id: u64,
        archive_dir: &Path,
    ) -> Result<(), String> {
        fs::create_dir_all(archive_dir).map_err(|e| format!("archive dir: {e}"))?;
        let mut stmt = conn
            .prepare(
                "SELECT seq, segment_id, category, severity, actor_did, target, reason_code,
                        best_effort_wall_ts, time_source_flag, prev_hash, is_checkpoint,
                        checkpoint_signature, checkpoint_hash
                 FROM security_events WHERE segment_id=?1 ORDER BY seq ASC",
            )
            .map_err(|e| format!("archive query: {e}"))?;
        let rows = stmt
            .query_map(params![segment_id as i64], |r| {
                let prev: Vec<u8> = r.get(9)?;
                let sig: Option<Vec<u8>> = r.get(11)?;
                let ch: Option<Vec<u8>> = r.get(12)?;
                Ok(serde_json::json!({
                    "seq": r.get::<_, i64>(0)?,
                    "segment_id": r.get::<_, i64>(1)?,
                    "category": r.get::<_, String>(2)?,
                    "severity": r.get::<_, String>(3)?,
                    "actor_did": r.get::<_, Option<String>>(4)?,
                    "target": r.get::<_, Option<String>>(5)?,
                    "reason_code": r.get::<_, String>(6)?,
                    "best_effort_wall_ts": r.get::<_, i64>(7)?,
                    "time_source_flag": r.get::<_, String>(8)?,
                    "prev_hash_hex": hex::encode(prev),
                    "is_checkpoint": r.get::<_, i64>(10)? != 0,
                    "checkpoint_signature_hex": sig.map(hex::encode),
                    "checkpoint_hash_hex": ch.map(hex::encode),
                }))
            })
            .map_err(|e| format!("archive rows: {e}"))?;
        let events: Vec<serde_json::Value> = rows.filter_map(|r| r.ok()).collect();
        let seg_meta: Option<(i64, Option<i64>, String)> = conn
            .query_row(
                "SELECT started_at_seq, ended_at_seq, reason FROM security_event_segments WHERE segment_id=?1",
                params![segment_id as i64],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| format!("segment meta: {e}"))?;
        let manifest = serde_json::json!({
            "format": "tirbase-security-segment-v1",
            "segment_id": segment_id,
            "started_at_seq": seg_meta.as_ref().map(|m| m.0),
            "ended_at_seq": seg_meta.as_ref().and_then(|m| m.1),
            "reason": seg_meta.as_ref().map(|m| m.2.clone()),
            "archived_at_unix": self.wall_time_now(),
            "events": events,
        });
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&manifest, &mut bytes)
            .map_err(|e| format!("archive cbor: {e}"))?;
        let hash = Sha256::digest(&bytes);
        let sig_hex = if let Some(kp) = self.key_provider() {
            kp.sign(&hash).ok().map(|s| rot_sig_hex(&s))
        } else {
            None
        };
        let archive = serde_json::json!({
            "manifest_cbor_hex": hex::encode(&bytes),
            "manifest_sha256_hex": hex::encode(hash),
            "device_signature_hex": sig_hex,
        });
        let out_path = archive_dir.join(format!("segment-{segment_id:016}.signed.json"));
        let mut f = fs::File::create(&out_path).map_err(|e| format!("archive create: {e}"))?;
        f.write_all(
            serde_json::to_vec_pretty(&archive)
                .map_err(|e| e.to_string())?
                .as_slice(),
        )
        .map_err(|e| format!("archive write: {e}"))?;
        f.sync_all().ok();
        Ok(())
    }

    /// 28.2 (PV-7.13): rotate/archive oldest signed/closed segment(s) when retention
    /// limits are exceeded (90 days or 1 GB, whichever first; configurable).
    pub fn rotate_retention_if_needed(&self) -> Result<u64, String> {
        let Some(cfg) = self.retention_cfg() else {
            return Ok(0);
        };
        if cfg.max_age_secs <= 0 && cfg.max_bytes <= 0 {
            return Ok(0);
        }
        let Some(mut conn) = self.open_db()? else {
            return Ok(0);
        };
        let total_bytes: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(LENGTH(COALESCE(category,''))+LENGTH(COALESCE(severity,''))+LENGTH(COALESCE(actor_did,''))+LENGTH(COALESCE(target,''))+LENGTH(COALESCE(reason_code,''))+64),0) FROM security_events",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let oldest_ts: Option<i64> = conn
            .query_row(
                "SELECT MIN(best_effort_wall_ts) FROM security_events",
                [],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None)
            .flatten();
        let now = self.wall_time_now();
        let too_old = cfg.max_age_secs > 0
            && oldest_ts
                .map(|t| now.saturating_sub(t) > cfg.max_age_secs)
                .unwrap_or(false);
        let too_big = cfg.max_bytes > 0 && total_bytes > cfg.max_bytes;
        if !too_old && !too_big {
            return Ok(0);
        }
        let mut rotated = 0u64;
        // Rotate one oldest closed segment at a time; keep current active segment.
        loop {
            let total_bytes_now: i64 = conn
                .query_row(
                    "SELECT COALESCE(SUM(LENGTH(COALESCE(category,''))+LENGTH(COALESCE(severity,''))+LENGTH(COALESCE(actor_did,''))+LENGTH(COALESCE(target,''))+LENGTH(COALESCE(reason_code,''))+64),0) FROM security_events",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            let oldest_ts_now: Option<i64> = conn
                .query_row(
                    "SELECT MIN(best_effort_wall_ts) FROM security_events",
                    [],
                    |r| r.get(0),
                )
                .optional()
                .unwrap_or(None)
                .flatten();
            let now2 = self.wall_time_now();
            let need = (cfg.max_age_secs > 0
                && oldest_ts_now
                    .map(|t| now2.saturating_sub(t) > cfg.max_age_secs)
                    .unwrap_or(false))
                || (cfg.max_bytes > 0 && total_bytes_now > cfg.max_bytes);
            if !need {
                break;
            }
            let candidate: Option<(i64, i64)> = conn
                .query_row(
                    "SELECT s.segment_id, COALESCE(s.ended_at_seq, (SELECT MAX(seq) FROM security_events e WHERE e.segment_id=s.segment_id))
                     FROM security_event_segments s
                     WHERE s.segment_id < (SELECT COALESCE(MAX(segment_id),1) FROM security_event_segments)
                     ORDER BY s.segment_id ASC LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(|e| format!("candidate segment: {e}"))?;
            let Some((seg_id, max_seq)) = candidate else {
                break;
            };
            self.archive_signed_segment(&conn, seg_id as u64, &cfg.archive_dir)?;
            conn.execute(
                "DELETE FROM security_event_personal_fields WHERE seq IN (SELECT seq FROM security_events WHERE segment_id=?1)",
                params![seg_id],
            )
            .map_err(|e| format!("delete personal fields: {e}"))?;
            conn.execute(
                "DELETE FROM security_events WHERE segment_id=?1",
                params![seg_id],
            )
            .map_err(|e| format!("delete segment events: {e}"))?;
            conn.execute(
                "DELETE FROM security_event_segments WHERE segment_id=?1",
                params![seg_id],
            )
            .map_err(|e| format!("delete segment meta: {e}"))?;
            self.append_payload_internal(
                SecurityEventPayload::new(
                    SecurityEventCategory::SecurityLog,
                    Severity::Low,
                    ReasonCode::LogRotated,
                )
                .with_target(seg_id.to_string())
                .with_detail(format!(
                    "archived and removed security_event segment {seg_id} (through seq {max_seq}) (CLAIM-28.2, PV-7.13)"
                )),
                true,
            );
            rotated += 1;
            if rotated >= 64 {
                break;
            }
        }
        Ok(rotated)
    }

    pub fn len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .ring
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot of chained records (ring view).
    pub fn chained_events(&self) -> Vec<SecurityEvent> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .ring
            .snapshot()
    }

    /// Compatibility view for code expecting payload events.
    pub fn events(&self) -> Vec<SecurityEventPayload> {
        self.chained_events()
            .into_iter()
            .map(|r| SecurityEventPayload {
                category: r.category,
                severity: r.severity,
                actor_did: r.actor_did,
                target: r.target,
                reason_code: r.reason_code,
                detail: None,
                personal_fields: Vec::new(),
            })
            .collect()
    }

    pub fn batcher(&self) -> Option<&Arc<GroupCommitBatcher>> {
        self.batcher.as_ref()
    }

    pub fn flush(&self) {
        if let Some(b) = &self.batcher {
            b.stop();
        }
    }

    /// 26.4 production caller hook: compare peer-observed checkpoint hash.
    /// PV-7.10 discrepancy => emit `TailTruncation` and enter Restricted.
    pub fn observe_peer_checkpoint(
        &self,
        peer_did: &str,
        peer_seq: u64,
        peer_checkpoint_hash: [u8; 32],
        observed_at: i64,
    ) -> Result<bool, String> {
        let Some(conn) = self.open_db()? else {
            return Ok(false);
        };
        upsert_peer_checkpoint_witness(
            &conn,
            peer_did,
            peer_seq,
            &peer_checkpoint_hash,
            observed_at,
        )
        .map_err(|e| format!("upsert peer checkpoint witness: {e}"))?;

        self.detect_checkpoint_discrepancy(&conn, peer_did, peer_seq, peer_checkpoint_hash)
    }

    /// 26.4/26.7a: shared PV-7.10 discrepancy check against the local tail.
    /// A witness that has seen a higher sequence number, or a different hash at
    /// the same sequence number, means the local log was truncated or forked.
    fn detect_checkpoint_discrepancy(
        &self,
        conn: &Connection,
        witness_id: &str,
        witness_seq: u64,
        witness_hash: [u8; 32],
    ) -> Result<bool, String> {
        let local = latest_local_checkpoint(conn).map_err(|e| format!("latest checkpoint: {e}"))?;
        let discrepant = match local {
            Some((local_seq, local_hash)) => {
                (witness_seq > local_seq)
                    || (witness_seq == local_seq && witness_hash != local_hash)
            }
            None => false,
        };
        if discrepant {
            let detail = format!(
                "tail truncation/checkpoint discrepancy: witness={} witness_seq={} local_seq={} (CLAIM-26.4, PV-7.10, INV-4)",
                witness_id,
                witness_seq,
                local.map(|x| x.0).unwrap_or(0)
            );
            self.enter_restricted(&detail);
            self.append_payload_internal(
                SecurityEventPayload::new(
                    SecurityEventCategory::SecurityLog,
                    Severity::Critical,
                    ReasonCode::TailTruncation,
                )
                .with_actor(witness_id.to_string())
                .with_detail(detail)
                .with_target(witness_seq.to_string()),
                true,
            );
            return Ok(true);
        }
        Ok(false)
    }

    /// 26.7a (PV-7.10) production caller: ingest a verified cloud-anchor
    /// acknowledgement. `acknowledged` is the `(seq, checkpoint_hash)` the
    /// anchor has now witnessed; `previously_witnessed` is the anchor's prior
    /// view of this device's chain, which is compared against the local tail so
    /// a single gateway can detect tail truncation without mesh peers.
    ///
    /// Returns `true` when truncation was detected.
    pub fn note_cloud_anchor_witness(
        &self,
        anchor_did: &str,
        acknowledged: (u64, [u8; 32]),
        previously_witnessed: Option<(u64, [u8; 32])>,
        observed_at: i64,
    ) -> Result<bool, String> {
        self.cloud_anchor_seen.store(true, Ordering::Relaxed);
        let Some(conn) = self.open_db()? else {
            return Ok(false);
        };
        conn.execute(
            "INSERT INTO cloud_anchor_witness(anchor_did, seq, checkpoint_hash, observed_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(anchor_did) DO UPDATE SET
               seq=excluded.seq,
               checkpoint_hash=excluded.checkpoint_hash,
               observed_at=excluded.observed_at",
            params![
                anchor_did,
                acknowledged.0 as i64,
                acknowledged.1.as_slice(),
                observed_at
            ],
        )
        .map_err(|e| format!("upsert cloud anchor witness: {e}"))?;
        match previously_witnessed {
            Some((seq, hash)) => self.detect_checkpoint_discrepancy(&conn, anchor_did, seq, hash),
            None => Ok(false),
        }
    }

    /// 26.7: single-gateway witness fallback at checkpoint time.
    /// `has_mesh_peers` / `has_cloud_anchor` come from production callers.
    pub fn record_checkpoint_witness_status(
        &self,
        has_mesh_peers: bool,
        has_cloud_anchor: bool,
    ) -> Result<(), String> {
        if has_mesh_peers || has_cloud_anchor {
            return Ok(());
        }
        self.append_payload_internal(
            SecurityEventPayload::new(
                SecurityEventCategory::SecurityLog,
                Severity::Low,
                ReasonCode::NoWitnessAvailable,
            )
            .with_detail(
                "no mesh peers and no cloud anchor; tail-truncation detection degraded until a peer connects (CLAIM-26.7, PV-7.10)"
                    .to_string(),
            ),
            true,
        );
        Ok(())
    }

    /// 26.7 production caller hook: install the real mesh-peer witness source.
    /// The closure returns `true` when a mesh peer is connected; the gateway
    /// wires it from the live mesh peer table (see [`crate::mesh_wiring`]).
    /// The cloud-anchor half of the witness state is maintained by
    /// [`Self::note_cloud_anchor_witness`].
    pub fn set_witness_source<F>(&self, source: F)
    where
        F: Fn() -> bool + Send + Sync + 'static,
    {
        *self
            .witness_source
            .write()
            .unwrap_or_else(|p| p.into_inner()) = Some(Arc::new(source));
    }

    /// 26.7: observed witness state at checkpoint time. Without a wired source
    /// the device is assumed isolated (degraded detection, not bricked).
    fn witness_state(&self) -> (bool, bool) {
        let has_mesh_peers = self
            .witness_source
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|source| source())
            .unwrap_or(false);
        let has_cloud_anchor = self.cloud_anchor_seen.load(Ordering::Relaxed);
        (has_mesh_peers, has_cloud_anchor)
    }

    /// 28.3 production caller hook: install the mesh publisher for local
    /// security-event sync batches (the gateway wires
    /// `CoreHandle::publish_security_event_sync`).
    pub fn set_security_event_sync_publisher<F>(&self, sender_did: impl Into<String>, publisher: F)
    where
        F: Fn(SecurityEventSyncBatch) + Send + Sync + 'static,
    {
        *self
            .sync_publisher
            .write()
            .unwrap_or_else(|p| p.into_inner()) = Some(SyncPublisher {
            sender_did: sender_did.into(),
            publish: Arc::new(publisher),
        });
    }

    /// 28.3: queue an appended local record for mesh sync (no-op until a
    /// publisher is installed). The outbox is bounded; oldest records are
    /// dropped on overflow so a slow link cannot grow memory without limit.
    fn enqueue_security_event_sync(&self, rec: &SecurityEvent) {
        let publisher_installed = self
            .sync_publisher
            .read()
            .map(|guard| guard.is_some())
            .unwrap_or(false);
        if !publisher_installed {
            return;
        }
        let origin_did = self
            .key_provider()
            .map(|kp| kp.did().to_string())
            .unwrap_or_else(|| "did:unknown".to_string());
        let record = SecurityEventSyncRecord {
            origin_did,
            seq: rec.seq,
            segment_id: rec.segment_id,
            category: rec.category.as_str().to_string(),
            severity: rec.severity.as_str().to_string(),
            actor_did: rec.actor_did.clone(),
            target: rec.target.clone(),
            reason_code: rec.reason_code.as_str().to_string(),
            best_effort_wall_time: rec.best_effort_wall_time,
            time_source_flag: rec.time_source_flag.as_str().to_string(),
            prev_hash: rec.prev_hash,
            is_checkpoint: rec.checkpoint_signature.is_some(),
            personal_commitments: rec
                .personal_commitments
                .iter()
                .map(|c| (c.field_name.clone(), c.commitment))
                .collect(),
        };
        let mut outbox = self.sync_outbox.lock().unwrap_or_else(|p| p.into_inner());
        if outbox.len() >= SECURITY_EVENT_SYNC_OUTBOX_CAP {
            outbox.remove(0);
        }
        outbox.push(record);
    }

    /// 28.3 receive-path merge: persist a synced peer record append-only.
    /// Returns `true` when the record was new (dedupe key is the origin
    /// chain position), matching the core collection's `compaction=none`
    /// semantics.
    pub fn persist_synced_event(&self, record: &SecurityEventSyncRecord) -> Result<bool, String> {
        let Some(conn) = self.open_db()? else {
            return Ok(false);
        };
        let inserted = conn
            .execute(
                "INSERT OR IGNORE INTO synced_security_events(
                    origin_did, segment_id, seq, category, severity, actor_did, target,
                    reason_code, best_effort_wall_ts, time_source_flag, prev_hash,
                    is_checkpoint, received_at
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![
                    record.origin_did,
                    record.segment_id as i64,
                    record.seq as i64,
                    record.category,
                    record.severity,
                    record.actor_did.as_deref(),
                    record.target.as_deref(),
                    record.reason_code,
                    record.best_effort_wall_time,
                    record.time_source_flag,
                    record.prev_hash.as_slice(),
                    if record.is_checkpoint { 1i64 } else { 0i64 },
                    self.wall_time_now(),
                ],
            )
            .map_err(|e| format!("persist synced security event: {e}"))?;
        Ok(inserted > 0)
    }

    /// 28.3: drain up to [`SECURITY_EVENT_SYNC_BATCH_MAX`] queued records to
    /// the installed publisher. Returns the number of records published.
    pub fn flush_security_event_sync(&self) -> usize {
        let Some((sender_did, publish)) = self
            .sync_publisher
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|p| (p.sender_did.clone(), p.publish.clone()))
        else {
            return 0;
        };
        let records = {
            let mut outbox = self.sync_outbox.lock().unwrap_or_else(|p| p.into_inner());
            if outbox.is_empty() {
                return 0;
            }
            let take = outbox.len().min(SECURITY_EVENT_SYNC_BATCH_MAX);
            outbox.drain(..take).collect::<Vec<_>>()
        };
        let published = records.len();
        publish(SecurityEventSyncBatch {
            sender_did,
            records,
        });
        published
    }

    /// 28.3 production caller: background mesh sync publisher for appended
    /// security events.
    pub fn spawn_security_event_sync_loop(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SECURITY_EVENT_SYNC_FLUSH);
            loop {
                tick.tick().await;
                this.flush_security_event_sync();
            }
        })
    }

    pub fn latest_checkpoint_hash(&self) -> Result<Option<(u64, [u8; 32])>, String> {
        let Some(conn) = self.open_db()? else {
            return Ok(None);
        };
        latest_local_checkpoint(&conn).map_err(|e| format!("latest checkpoint: {e}"))
    }

    pub fn peer_checkpoint_witnesses(
        &self,
    ) -> Result<Vec<crate::db::peer_checkpoint_witnesses::PeerCheckpointWitness>, String> {
        let Some(conn) = self.open_db()? else {
            return Ok(vec![]);
        };
        list_peer_checkpoint_witnesses(&conn).map_err(|e| format!("list witnesses: {e}"))
    }
}

impl SecurityEventSink for SecurityEventLog {
    fn emit(&self, event: SecurityEventPayload) {
        // Real decision-point metrics (CLAIM-35.5): every security event that
        // reaches the gateway sink increments its severity counter, and Delta
        // quarantine events increment the quarantine-entry counter.
        let metrics = crate::metrics::global_metrics();
        metrics.inc_security_event(event.severity.as_str());
        if matches!(event.reason_code, ReasonCode::DeltaQuarantined) {
            metrics.inc_quarantine_entry("delta");
        }
        let _ = self.append_payload(event);
    }
}

fn sig_to_bytes(sig: &DeviceSignature) -> Option<Vec<u8>> {
    Some(match sig {
        DeviceSignature::Ed25519(b) => b.to_vec(),
        DeviceSignature::P256(b) => b.clone(),
    })
}

/// Read security_events rows for inspection/tests (25.4).
pub fn read_security_events(
    conn: &Connection,
) -> rusqlite::Result<Vec<(u64, u64, i64, Option<Vec<u8>>)>> {
    let mut stmt = conn.prepare(
        "SELECT seq, segment_id, is_checkpoint, checkpoint_hash FROM security_events ORDER BY seq ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)? as u64,
            r.get::<_, i64>(1)? as u64,
            r.get::<_, i64>(2)?,
            r.get::<_, Option<Vec<u8>>>(3)?,
        ))
    })?;
    rows.collect()
}

pub fn read_security_event_segments(
    conn: &Connection,
) -> rusqlite::Result<Vec<(u64, u64, String)>> {
    let mut stmt = conn.prepare(
        "SELECT segment_id, started_at_seq, reason FROM security_event_segments ORDER BY segment_id ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)? as u64,
            r.get::<_, i64>(1)? as u64,
            r.get::<_, String>(2)?,
        ))
    })?;
    rows.collect()
}

/// Re-export for compatibility with older imports.
pub use crate::security_sink::MAX_EVENTS as LOG_MAX_EVENTS;

#[cfg(test)]
mod tests {
    use super::*;
    use tirbase_core::events::{ReasonCode, SecurityEventCategory, Severity};

    fn payload(n: u64) -> SecurityEventPayload {
        SecurityEventPayload::new(
            SecurityEventCategory::CommandDecision,
            Severity::Low,
            ReasonCode::CommandAccepted,
        )
        .with_target(format!("t{n}"))
    }

    #[test]
    fn chained_event_has_required_fields_and_no_per_event_signature() {
        let log = SecurityEventLog::new_memory();
        let rec = log.append_payload(payload(1));
        assert_eq!(rec.seq, 1);
        assert_eq!(rec.segment_id, 1);
        assert_eq!(rec.prev_hash, [0u8; 32]);
        assert!(rec.checkpoint_signature.is_none());
        assert!(matches!(
            rec.time_source_flag,
            TimeSourceFlag::TrustedClock | TimeSourceFlag::LogicalFallback
        ));
        let rec2 = log.append_payload(payload(2));
        assert_eq!(rec2.seq, 2);
        assert_ne!(rec2.prev_hash, [0u8; 32]);
        assert!(rec2.checkpoint_signature.is_none());
    }

    #[test]
    fn ring_overflow_retains_anchors_and_recent() {
        let mut ring = SecurityEventRing::new(32);
        for i in 1..=120u64 {
            let e = SecurityEvent {
                seq: i,
                segment_id: 1,
                category: SecurityEventCategory::SecurityLog,
                severity: Severity::Low,
                actor_did: None,
                target: None,
                reason_code: if i % 20 == 0 {
                    ReasonCode::CheckpointWritten
                } else {
                    ReasonCode::CommandAccepted
                },
                best_effort_wall_time: 0,
                time_source_flag: TimeSourceFlag::LogicalFallback,
                prev_hash: [0u8; 32],
                checkpoint_signature: if i % 20 == 0 {
                    Some(DeviceSignature::Ed25519([7u8; 64]))
                } else {
                    None
                },
                checkpoint_hash: None,
                personal_commitments: Vec::new(),
            };
            ring.push(e);
        }
        let snap = ring.snapshot();
        assert!(snap.len() <= 40, "ring bounded: {}", snap.len());
        assert!(snap.iter().any(|e| e.seq == 120), "retains recent");
        assert!(
            snap.iter()
                .any(|e| matches!(e.reason_code, ReasonCode::CheckpointWritten)),
            "retains anchor checkpoints"
        );
        let first_anchor = snap
            .iter()
            .find(|e| matches!(e.reason_code, ReasonCode::CheckpointWritten))
            .unwrap()
            .seq;
        assert!(first_anchor <= 40, "retains oldest anchors");
    }

    mod p18_hash_chain_tamper {
        use super::*;
        use proptest::prelude::*;

        fn verify_chain_records(records: &[SecurityEvent]) -> Option<u64> {
            let mut expected_prev = [0u8; 32];
            for rec in records {
                let body = ChainHashBody {
                    seq: rec.seq,
                    segment_id: rec.segment_id,
                    category: rec.category.as_str(),
                    severity: rec.severity.as_str(),
                    actor_did: rec.actor_did.as_deref(),
                    target: rec.target.as_deref(),
                    reason_code: rec.reason_code.as_str(),
                    best_effort_wall_time: rec.best_effort_wall_time,
                    time_source_flag: rec.time_source_flag.as_str(),
                    prev_hash: &rec.prev_hash,
                    is_checkpoint: rec.checkpoint_signature.is_some(),
                    personal_commitments: &rec.personal_commitments,
                };
                let computed = canonical_hash_bytes(&body);
                if rec.prev_hash != expected_prev {
                    return Some(rec.seq);
                }
                expected_prev = computed;
            }
            None
        }

        proptest! {
            /// P18 (CLAIM-26.6, PV-7.4, INV-4): any interior modification of a
            /// committed event at any position is detected by hash-chain verification.
            #[test]
            fn any_interior_modification_detected(
                n in 3usize..20usize,
                modify_idx in 0usize..18usize,
                mutation in 0u8..4u8,
            ) {
                let mut records = Vec::new();
                let mut prev = [0u8; 32];
                for i in 0..n {
                    let mut rec = SecurityEvent {
                        seq: (i as u64) + 1,
                        segment_id: 1,
                        category: SecurityEventCategory::CommandDecision,
                        severity: Severity::Low,
                        actor_did: Some(format!("did:test:{i}")),
                        target: Some(format!("t{i}")),
                        reason_code: ReasonCode::CommandAccepted,
                        best_effort_wall_time: 1000 + i as i64,
                        time_source_flag: TimeSourceFlag::LogicalFallback,
                        prev_hash: prev,
                        checkpoint_signature: None,
                        checkpoint_hash: None,
                        personal_commitments: Vec::new(),
                    };
                    let h = event_hash(&rec, false);
                    prev = h;
                    records.push(rec);
                }
                prop_assert!(verify_chain_records(&records).is_none());

                let idx = (modify_idx % n.max(1)).min(n.saturating_sub(2));
                match mutation % 4 {
                    0 => records[idx].target = Some("tampered".into()),
                    1 => records[idx].actor_did = Some("did:evil:x".into()),
                    2 => records[idx].best_effort_wall_time += 999,
                    _ => records[idx].reason_code = ReasonCode::SequenceRejected,
                }
                let broken = verify_chain_records(&records);
                prop_assert!(broken.is_some(), "interior modification at idx={} must be detected", idx);
                // first broken is at idx (if prev_hash link broken there) or idx+1 (successor sees wrong prev)
                let b = broken.unwrap();
                prop_assert!(b == records[idx].seq || b == records[idx+1].seq,
                    "broken seq {} must identify modified position {} or successor {}", b, records[idx].seq, records[idx+1].seq);
            }
        }

        /// Wiring mutation guard: skipping interior hash checks must fail.
        #[test]
        fn skipping_interior_hash_check_fails() {
            let mut records = Vec::new();
            let mut prev = [0u8; 32];
            for i in 0..5u64 {
                let rec = SecurityEvent {
                    seq: i + 1,
                    segment_id: 1,
                    category: SecurityEventCategory::CommandDecision,
                    severity: Severity::Low,
                    actor_did: None,
                    target: None,
                    reason_code: ReasonCode::CommandAccepted,
                    best_effort_wall_time: 1,
                    time_source_flag: TimeSourceFlag::LogicalFallback,
                    prev_hash: prev,
                    checkpoint_signature: None,
                    checkpoint_hash: None,
                    personal_commitments: Vec::new(),
                };
                prev = event_hash(&rec, false);
                records.push(rec);
            }
            records[2].target = Some("evil".into()); // interior
            assert!(
                verify_chain_records(&records).is_some(),
                "must detect interior modification"
            );
        }
    }
}
