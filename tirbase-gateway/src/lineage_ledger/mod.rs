// SPDX-License-Identifier: AGPL-3.0-only

//! Hash-chained lineage ledger and signed export (CC-14).
//!
//! The ledger is the tamper-evident record of what happened to physical product:
//! lot registration, splits, merges, repacks, excursion detection, dispositions
//! and signed resolutions. It complements the CC-12 traceability graph (which
//! answers *what is related to what*) with an append-only history (which answers
//! *what happened, in what order, attested by whom*).
//!
//! # Entry
//!
//! Each [`LedgerEntry`] carries a contiguous `seq`, the `prev_hash` of its
//! predecessor, its own domain-separated `entry_hash`, the recording timestamp,
//! the actor DID, the device and lot it concerns, the event type and the hash of
//! its payload. The payload itself is stored so the ledger is reconstructable;
//! the hash is what the chain commits to.
//!
//! ```text
//! entry_hash = SHA-256("TirBase/v1/LineageLedgerEntry" || 0x00 ||
//!                      canonical JSON{seq, prev_hash, recorded_est, actor_did,
//!                                     device_id, lot_id, event_type, payload_hash})
//! ```
//!
//! # Appends
//!
//! [`LineageLedger::append`] is idempotent on the caller-supplied `entry_id`: a
//! retried append (after a crash, a timeout, or a duplicate queue delivery)
//! returns [`AppendOutcome::Duplicate`] and writes nothing, so the same event can
//! never be recorded twice. Reusing an `entry_id` for a *different* payload is
//! [`LedgerError::Conflict`]. The row is inserted in one statement and the next
//! sequence is derived from the stored head, so a restart continues the chain at
//! the correct link.
//!
//! # Checkpoints
//!
//! [`LineageLedger::checkpoint`] signs the current head with a `KeyProvider` and
//! stores the signature. A checkpoint commits to `(seq, count, head_hash)`, so a
//! verifier can detect a ledger truncated below a signed head even when every
//! remaining entry is individually well formed.
//!
//! # Verification
//!
//! [`LineageLedger::verify`] recomputes every entry hash, checks sequence
//! contiguity and `prev_hash` links, rejects duplicates and reordering, and
//! verifies each checkpoint signature against a caller-supplied trusted signer
//! set and key resolver. Tampering with a stored payload, deleting the tail under
//! a checkpoint, or re-signing with an untrusted key all produce typed
//! [`LedgerViolation`]s with a human-readable reason.
//!
//! Signed export bundles live in [`export`].

pub mod export;
pub mod sink;

pub use sink::LedgerSink;

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tirbase_core::traits::KeyProvider;
use tirbase_types::DeviceSignature;

/// Domain-separation context for an entry hash.
pub const CONTEXT_LEDGER_ENTRY: &str = "TirBase/v1/LineageLedgerEntry";

/// Domain-separation context for a payload hash.
pub const CONTEXT_LEDGER_PAYLOAD: &str = "TirBase/v1/LineageLedgerPayload";

/// Domain-separation context for a checkpoint hash.
pub const CONTEXT_LEDGER_CHECKPOINT: &str = "TirBase/v1/LineageLedgerCheckpoint";

/// The all-zero hash that precedes the first entry.
pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Event type: a lot identity was registered.
pub const EVENT_LOT_REGISTERED: &str = "lot_registered";
/// Event type: a lot was split.
pub const EVENT_LOT_SPLIT: &str = "lot_split";
/// Event type: lots were merged.
pub const EVENT_LOT_MERGED: &str = "lot_merged";
/// Event type: a lot was repacked.
pub const EVENT_LOT_REPACKED: &str = "lot_repacked";
/// Event type: a lot was relocated.
pub const EVENT_LOT_RELOCATED: &str = "lot_relocated";
/// Event type: an excursion was detected (CC-11).
pub const EVENT_EXCURSION_DETECTED: &str = "excursion_detected";
/// Event type: an operator disposition was recorded (CC-11).
pub const EVENT_EXCURSION_DISPOSITIONED: &str = "excursion_dispositioned";
/// Event type: a signed resolution closed the disposition (CC-11).
pub const EVENT_EXCURSION_RESOLVED: &str = "excursion_resolved";

/// Longest accepted entry id.
pub const MAX_ENTRY_ID_LEN: usize = 128;

/// Longest accepted event type.
pub const MAX_EVENT_TYPE_LEN: usize = 64;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS lineage_ledger (
    seq          INTEGER PRIMARY KEY,
    entry_id     TEXT NOT NULL UNIQUE,
    prev_hash    TEXT NOT NULL,
    entry_hash   TEXT NOT NULL,
    recorded_est INTEGER NOT NULL,
    actor_did    TEXT NOT NULL,
    device_id    TEXT,
    lot_id       TEXT,
    event_type   TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lineage_ledger_lot ON lineage_ledger(lot_id, seq);
CREATE INDEX IF NOT EXISTS idx_lineage_ledger_device ON lineage_ledger(device_id, seq);

CREATE TABLE IF NOT EXISTS lineage_ledger_checkpoints (
    seq             INTEGER PRIMARY KEY,
    count           INTEGER NOT NULL,
    head_hash       TEXT NOT NULL,
    checkpoint_hash TEXT NOT NULL,
    signer_did      TEXT NOT NULL,
    signature_json  TEXT NOT NULL,
    created_est     INTEGER NOT NULL
);
"#;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// One committed ledger entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Contiguous position in the chain, starting at 1.
    pub seq: u64,
    /// Caller-supplied idempotency key.
    pub entry_id: String,
    /// Hash of the previous entry, or [`ZERO_HASH`] for seq 1.
    pub prev_hash: String,
    /// Domain-separated hash of this entry.
    pub entry_hash: String,
    /// Recording time (authenticated-time estimate, seconds).
    pub recorded_est: i64,
    /// Actor that caused the event.
    pub actor_did: String,
    /// Device the event concerns, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Lot the event concerns, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lot_id: Option<String>,
    /// Event type (snake case, e.g. [`EVENT_LOT_SPLIT`]).
    pub event_type: String,
    /// SHA-256 over the canonical payload.
    pub payload_hash: String,
    /// The payload itself.
    pub payload: serde_json::Value,
}

/// A request to append one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendRequest {
    /// Idempotency key; a retry with the same key and payload is a no-op.
    pub entry_id: String,
    /// Actor that caused the event.
    pub actor_did: String,
    /// Device the event concerns.
    pub device_id: Option<String>,
    /// Lot the event concerns.
    pub lot_id: Option<String>,
    /// Event type.
    pub event_type: String,
    /// Payload committed by hash.
    pub payload: serde_json::Value,
    /// Recording time.
    pub recorded_est: i64,
}

impl AppendRequest {
    /// Build an append request.
    pub fn new(
        entry_id: impl Into<String>,
        actor_did: impl Into<String>,
        event_type: impl Into<String>,
        payload: serde_json::Value,
        recorded_est: i64,
    ) -> Self {
        Self {
            entry_id: entry_id.into(),
            actor_did: actor_did.into(),
            device_id: None,
            lot_id: None,
            event_type: event_type.into(),
            payload,
            recorded_est,
        }
    }

    /// Bind the request to a lot.
    pub fn with_lot(mut self, lot_id: impl Into<String>) -> Self {
        self.lot_id = Some(lot_id.into());
        self
    }

    /// Bind the request to a device.
    pub fn with_device(mut self, device_id: impl Into<String>) -> Self {
        self.device_id = Some(device_id.into());
        self
    }
}

/// Result of an append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendOutcome {
    /// A new entry was written.
    Appended(LedgerEntry),
    /// An identical entry with this `entry_id` already existed; nothing was
    /// written.
    Duplicate(LedgerEntry),
}

impl AppendOutcome {
    /// The entry, appended or already present.
    pub fn entry(&self) -> &LedgerEntry {
        match self {
            AppendOutcome::Appended(entry) => entry,
            AppendOutcome::Duplicate(entry) => entry,
        }
    }

    /// Whether this call wrote anything.
    pub fn appended(&self) -> bool {
        matches!(self, AppendOutcome::Appended(_))
    }
}

/// Result of importing a bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportReport {
    /// Entries written.
    pub imported: usize,
    /// Entries already present with the same hash.
    pub skipped: usize,
}

/// One signed checkpoint over the prefix `1..=seq`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerCheckpoint {
    /// Last sequence covered.
    pub seq: u64,
    /// Number of entries covered (`seq` when the chain starts at 1).
    pub count: u64,
    /// Entry hash at `seq`.
    pub head_hash: String,
    /// Domain-separated hash over `(seq, count, head_hash, created_est)`.
    pub checkpoint_hash: String,
    /// DID of the signing key.
    pub signer_did: String,
    /// Signature over [`LedgerCheckpoint::checkpoint_hash`] bytes.
    pub signature: DeviceSignature,
    /// When the checkpoint was created.
    pub created_est: i64,
}

/// Kind of verification violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    /// Entries are not contiguous from the expected start.
    SequenceGap,
    /// Two entries claim the same position.
    Duplicate,
    /// Entries are out of order.
    Reorder,
    /// An entry's `prev_hash` does not match its predecessor.
    PreviousHashMismatch,
    /// An entry's stored hash does not match the recomputed hash.
    EntryHashMismatch,
    /// The stored payload does not match the committed payload hash.
    PayloadHashMismatch,
    /// A checkpoint commits to more entries than are present.
    Truncation,
    /// A checkpoint hash does not match its content.
    CheckpointForgery,
    /// A checkpoint signature does not verify.
    CheckpointSignature,
    /// A checkpoint was signed by a key the verifier does not trust.
    WrongSigner,
}

impl ViolationKind {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            ViolationKind::SequenceGap => "sequence_gap",
            ViolationKind::Duplicate => "duplicate",
            ViolationKind::Reorder => "reorder",
            ViolationKind::PreviousHashMismatch => "previous_hash_mismatch",
            ViolationKind::EntryHashMismatch => "entry_hash_mismatch",
            ViolationKind::PayloadHashMismatch => "payload_hash_mismatch",
            ViolationKind::Truncation => "truncation",
            ViolationKind::CheckpointForgery => "checkpoint_forgery",
            ViolationKind::CheckpointSignature => "checkpoint_signature",
            ViolationKind::WrongSigner => "wrong_signer",
        }
    }
}

/// One verification violation with a human-readable reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerViolation {
    /// Sequence the violation refers to (`0` for a whole-ledger problem).
    pub seq: u64,
    /// Kind of violation.
    pub kind: ViolationKind,
    /// Why it was reported.
    pub detail: String,
}

impl LedgerViolation {
    /// Build a violation.
    pub fn new(seq: u64, kind: ViolationKind, detail: impl Into<String>) -> Self {
        Self {
            seq,
            kind,
            detail: detail.into(),
        }
    }
}

/// Result of verifying a ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerReport {
    /// `true` when nothing was reported.
    pub ok: bool,
    /// Entries examined.
    pub checked: usize,
    /// Highest sequence present.
    pub head_seq: u64,
    /// Checkpoints examined.
    pub checkpoints: usize,
    /// Violations, in sequence order.
    pub violations: Vec<LedgerViolation>,
    /// One-line summary.
    pub message: String,
}

impl LedgerReport {
    /// Reasons this ledger failed, one string each.
    pub fn reasons(&self) -> Vec<String> {
        self.violations
            .iter()
            .map(|violation| {
                format!(
                    "seq {}: {} ({})",
                    violation.seq,
                    violation.kind.as_str(),
                    violation.detail
                )
            })
            .collect()
    }
}

/// Why a ledger operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// Storage failure.
    Store(String),
    /// The request is malformed.
    InvalidRequest(String),
    /// An idempotency key was reused with different content.
    Conflict(String),
    /// A checkpoint already covers this head, signed by another key.
    CheckpointConflict(String),
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerError::Store(detail) => write!(f, "ledger store: {detail}"),
            LedgerError::InvalidRequest(detail) => write!(f, "invalid request: {detail}"),
            LedgerError::Conflict(detail) => write!(f, "ledger conflict: {detail}"),
            LedgerError::CheckpointConflict(detail) => {
                write!(f, "checkpoint conflict: {detail}")
            }
        }
    }
}

impl std::error::Error for LedgerError {}

fn store_error(error: impl fmt::Display) -> LedgerError {
    LedgerError::Store(error.to_string())
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct EntryHashBody<'a> {
    seq: u64,
    prev_hash: &'a str,
    recorded_est: i64,
    actor_did: &'a str,
    device_id: Option<&'a str>,
    lot_id: Option<&'a str>,
    event_type: &'a str,
    payload_hash: &'a str,
}

#[derive(Serialize)]
struct CheckpointHashBody<'a> {
    seq: u64,
    count: u64,
    head_hash: &'a str,
    created_est: i64,
}

fn hex_digest(context: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(context.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// SHA-256 over the canonical payload, domain separated.
pub fn payload_hash(payload: &serde_json::Value) -> Result<String, LedgerError> {
    let bytes = serde_json::to_vec(payload).map_err(store_error)?;
    Ok(hex_digest(CONTEXT_LEDGER_PAYLOAD, &bytes))
}

/// Recompute an entry's hash from its fields.
// The hash commits to eight independent entry fields; grouping them into a
// struct would only move the same list one level down.
#[allow(clippy::too_many_arguments)]
pub fn entry_hash(
    seq: u64,
    prev_hash: &str,
    recorded_est: i64,
    actor_did: &str,
    device_id: Option<&str>,
    lot_id: Option<&str>,
    event_type: &str,
    payload_hash: &str,
) -> Result<String, LedgerError> {
    let body = EntryHashBody {
        seq,
        prev_hash,
        recorded_est,
        actor_did,
        device_id,
        lot_id,
        event_type,
        payload_hash,
    };
    let bytes = serde_json::to_vec(&body).map_err(store_error)?;
    Ok(hex_digest(CONTEXT_LEDGER_ENTRY, &bytes))
}

fn recompute_entry_hash(entry: &LedgerEntry) -> Result<String, LedgerError> {
    entry_hash(
        entry.seq,
        &entry.prev_hash,
        entry.recorded_est,
        &entry.actor_did,
        entry.device_id.as_deref(),
        entry.lot_id.as_deref(),
        &entry.event_type,
        &entry.payload_hash,
    )
}

fn checkpoint_hash(
    seq: u64,
    count: u64,
    head_hash: &str,
    created_est: i64,
) -> Result<String, LedgerError> {
    let body = CheckpointHashBody {
        seq,
        count,
        head_hash,
        created_est,
    };
    let bytes = serde_json::to_vec(&body).map_err(store_error)?;
    Ok(hex_digest(CONTEXT_LEDGER_CHECKPOINT, &bytes))
}

/// Decode a 64-character hex hash.
pub fn decode_hash(value: &str) -> Result<[u8; 32], LedgerError> {
    let bytes = hex::decode(value)
        .map_err(|error| LedgerError::InvalidRequest(format!("hash is not hex: {error}")))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| LedgerError::InvalidRequest(format!("hash is not 32 bytes: {value:?}")))
}

/// Verify an Ed25519 signature over `bytes`.
pub(crate) fn verify_ed25519(
    public_key: &[u8],
    bytes: &[u8],
    signature: &DeviceSignature,
) -> Result<(), LedgerError> {
    let key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| LedgerError::InvalidRequest("public key is not 32 bytes".to_string()))?;
    let DeviceSignature::Ed25519(raw) = signature else {
        return Err(LedgerError::InvalidRequest(
            "only Ed25519 signatures are supported".to_string(),
        ));
    };
    tirbase_core::identity::keypair::verify(
        &key,
        bytes,
        &tirbase_core::crdt::delta::Ed25519Signature::from_bytes(*raw),
    )
    .map_err(|error| LedgerError::InvalidRequest(format!("signature did not verify: {error}")))
}

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

/// The persisted append-only ledger.
#[derive(Debug)]
pub struct LineageLedger {
    conn: Connection,
}

impl LineageLedger {
    /// Open (or create) a ledger database at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let conn = crate::db::open_primary(path)
            .map_err(|error| LedgerError::Store(format!("open primary db: {error:?}")))?;
        Self::from_connection(conn)
    }

    /// Open an in-memory ledger (tests and ephemeral deployments).
    pub fn open_in_memory() -> Result<Self, LedgerError> {
        let conn = Connection::open_in_memory().map_err(store_error)?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self, LedgerError> {
        conn.execute_batch(SCHEMA)
            .map_err(|error| LedgerError::Store(format!("create ledger schema: {error}")))?;
        Ok(Self { conn })
    }

    // -----------------------------------------------------------------------
    // Append
    // -----------------------------------------------------------------------

    /// Append one entry, idempotently.
    ///
    /// A retry with the same `entry_id` and payload returns
    /// [`AppendOutcome::Duplicate`] without writing; the same id with a different
    /// payload is [`LedgerError::Conflict`].
    pub fn append(&self, request: AppendRequest) -> Result<AppendOutcome, LedgerError> {
        validate_request(&request)?;
        let hash = payload_hash(&request.payload)?;

        if let Some(existing) = self.load_by_entry_id(&request.entry_id)? {
            if existing.payload_hash == hash {
                return Ok(AppendOutcome::Duplicate(existing));
            }
            return Err(LedgerError::Conflict(format!(
                "entry {} was already recorded with payload {}",
                request.entry_id, existing.payload_hash
            )));
        }

        // Derive the next link from the stored head so a restart continues the
        // chain rather than guessing from memory.
        let head = self.head()?;
        let seq = head.as_ref().map(|entry| entry.seq + 1).unwrap_or(1);
        let prev_hash = head
            .as_ref()
            .map(|entry| entry.entry_hash.clone())
            .unwrap_or_else(|| ZERO_HASH.to_string());
        let entry_hash = entry_hash(
            seq,
            &prev_hash,
            request.recorded_est,
            &request.actor_did,
            request.device_id.as_deref(),
            request.lot_id.as_deref(),
            &request.event_type,
            &hash,
        )?;
        let entry = LedgerEntry {
            seq,
            entry_id: request.entry_id,
            prev_hash,
            entry_hash,
            recorded_est: request.recorded_est,
            actor_did: request.actor_did,
            device_id: request.device_id,
            lot_id: request.lot_id,
            event_type: request.event_type,
            payload_hash: hash,
            payload: request.payload,
        };
        self.insert(&entry)?;
        Ok(AppendOutcome::Appended(entry))
    }

    fn insert(&self, entry: &LedgerEntry) -> Result<(), LedgerError> {
        let payload = serde_json::to_string(&entry.payload).map_err(store_error)?;
        self.conn
            .execute(
                "INSERT INTO lineage_ledger (seq, entry_id, prev_hash, entry_hash, \
                 recorded_est, actor_did, device_id, lot_id, event_type, payload_hash, \
                 payload_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    i64::try_from(entry.seq)
                        .map_err(|_| LedgerError::InvalidRequest("seq overflow".into()))?,
                    entry.entry_id,
                    entry.prev_hash,
                    entry.entry_hash,
                    entry.recorded_est,
                    entry.actor_did,
                    entry.device_id,
                    entry.lot_id,
                    entry.event_type,
                    entry.payload_hash,
                    payload,
                ],
            )
            .map_err(|error| LedgerError::Store(format!("insert ledger entry: {error}")))?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Reads
    // -----------------------------------------------------------------------

    /// Load an entry by its idempotency key.
    pub fn load_by_entry_id(&self, entry_id: &str) -> Result<Option<LedgerEntry>, LedgerError> {
        self.conn
            .query_row(
                "SELECT seq, entry_id, prev_hash, entry_hash, recorded_est, actor_did, \
                 device_id, lot_id, event_type, payload_hash, payload_json \
                 FROM lineage_ledger WHERE entry_id=?1",
                params![entry_id],
                row_to_entry,
            )
            .optional()
            .map_err(store_error)
    }

    /// Load one entry by sequence.
    pub fn get(&self, seq: u64) -> Result<Option<LedgerEntry>, LedgerError> {
        self.conn
            .query_row(
                "SELECT seq, entry_id, prev_hash, entry_hash, recorded_est, actor_did, \
                 device_id, lot_id, event_type, payload_hash, payload_json \
                 FROM lineage_ledger WHERE seq=?1",
                params![seq as i64],
                row_to_entry,
            )
            .optional()
            .map_err(store_error)
    }

    /// The newest entry, if any.
    pub fn head(&self) -> Result<Option<LedgerEntry>, LedgerError> {
        self.conn
            .query_row(
                "SELECT seq, entry_id, prev_hash, entry_hash, recorded_est, actor_did, \
                 device_id, lot_id, event_type, payload_hash, payload_json \
                 FROM lineage_ledger ORDER BY seq DESC LIMIT 1",
                [],
                row_to_entry,
            )
            .optional()
            .map_err(store_error)
    }

    /// Number of entries.
    pub fn len(&self) -> Result<u64, LedgerError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM lineage_ledger", [], |row| row.get(0))
            .map_err(store_error)?;
        Ok(count.max(0) as u64)
    }

    /// Whether the ledger has no entries.
    pub fn is_empty(&self) -> Result<bool, LedgerError> {
        Ok(self.len()? == 0)
    }

    /// Entries in `[start, end]`, in sequence order.
    pub fn range(&self, start: u64, end: u64) -> Result<Vec<LedgerEntry>, LedgerError> {
        if start == 0 || end < start {
            return Err(LedgerError::InvalidRequest(format!(
                "invalid range {start}..={end}"
            )));
        }
        let mut stmt = self
            .conn
            .prepare(
                "SELECT seq, entry_id, prev_hash, entry_hash, recorded_est, actor_did, \
                 device_id, lot_id, event_type, payload_hash, payload_json \
                 FROM lineage_ledger WHERE seq BETWEEN ?1 AND ?2 ORDER BY seq ASC",
            )
            .map_err(store_error)?;
        let rows = stmt
            .query_map(params![start as i64, end as i64], row_to_entry)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    /// Every entry, in sequence order.
    pub fn entries(&self) -> Result<Vec<LedgerEntry>, LedgerError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT seq, entry_id, prev_hash, entry_hash, recorded_est, actor_did, \
                 device_id, lot_id, event_type, payload_hash, payload_json \
                 FROM lineage_ledger ORDER BY seq ASC",
            )
            .map_err(store_error)?;
        let rows = stmt.query_map([], row_to_entry).map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    /// Entries for one lot, in sequence order.
    pub fn entries_for_lot(&self, lot_id: &str) -> Result<Vec<LedgerEntry>, LedgerError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT seq, entry_id, prev_hash, entry_hash, recorded_est, actor_did, \
                 device_id, lot_id, event_type, payload_hash, payload_json \
                 FROM lineage_ledger WHERE lot_id=?1 ORDER BY seq ASC",
            )
            .map_err(store_error)?;
        let rows = stmt
            .query_map(params![lot_id], row_to_entry)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    // -----------------------------------------------------------------------
    // Checkpoints
    // -----------------------------------------------------------------------

    /// Sign the current head and store the checkpoint.
    ///
    /// Checkpointing an unchanged head is idempotent for the same signer; a
    /// different signer at the same sequence is refused.
    pub fn checkpoint(
        &self,
        key: &dyn KeyProvider,
        created_est: i64,
    ) -> Result<LedgerCheckpoint, LedgerError> {
        let head = self
            .head()?
            .ok_or_else(|| LedgerError::InvalidRequest("ledger is empty".to_string()))?;
        if let Some(existing) = self.load_checkpoint(head.seq)? {
            if existing.head_hash == head.entry_hash {
                if existing.signer_did == key.did() {
                    return Ok(existing);
                }
                return Err(LedgerError::CheckpointConflict(format!(
                    "sequence {} is already checkpointed by {}",
                    head.seq, existing.signer_did
                )));
            }
        }
        let count = head.seq;
        let hash = checkpoint_hash(head.seq, count, &head.entry_hash, created_est)?;
        let signature = key
            .sign(&decode_hash(&hash)?)
            .map_err(|error| LedgerError::Store(format!("sign checkpoint: {error:?}")))?;
        let checkpoint = LedgerCheckpoint {
            seq: head.seq,
            count,
            head_hash: head.entry_hash,
            checkpoint_hash: hash,
            signer_did: key.did().to_string(),
            signature,
            created_est,
        };
        self.insert_checkpoint(&checkpoint)?;
        Ok(checkpoint)
    }

    fn insert_checkpoint(&self, checkpoint: &LedgerCheckpoint) -> Result<(), LedgerError> {
        let signature = serde_json::to_string(&checkpoint.signature).map_err(store_error)?;
        self.conn
            .execute(
                "INSERT INTO lineage_ledger_checkpoints \
                 (seq, count, head_hash, checkpoint_hash, signer_did, signature_json, created_est) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    checkpoint.seq as i64,
                    checkpoint.count as i64,
                    checkpoint.head_hash,
                    checkpoint.checkpoint_hash,
                    checkpoint.signer_did,
                    signature,
                    checkpoint.created_est,
                ],
            )
            .map_err(|error| LedgerError::Store(format!("insert checkpoint: {error}")))?;
        Ok(())
    }

    /// Load the checkpoint at `seq`, if one exists.
    pub fn load_checkpoint(&self, seq: u64) -> Result<Option<LedgerCheckpoint>, LedgerError> {
        self.conn
            .query_row(
                "SELECT seq, count, head_hash, checkpoint_hash, signer_did, signature_json, \
                 created_est FROM lineage_ledger_checkpoints WHERE seq=?1",
                params![seq as i64],
                row_to_checkpoint,
            )
            .optional()
            .map_err(store_error)
    }

    /// Every checkpoint, oldest first.
    pub fn checkpoints(&self) -> Result<Vec<LedgerCheckpoint>, LedgerError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT seq, count, head_hash, checkpoint_hash, signer_did, signature_json, \
                 created_est FROM lineage_ledger_checkpoints ORDER BY seq ASC",
            )
            .map_err(store_error)?;
        let rows = stmt.query_map([], row_to_checkpoint).map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    // -----------------------------------------------------------------------
    // Verification
    // -----------------------------------------------------------------------

    /// Import a verified bundle into this ledger.
    ///
    /// The bundle's chain is re-verified before anything is written, and every
    /// entry is matched by `entry_id` and sequence, so importing the same bundle
    /// twice imports nothing the second time. A local entry at the same sequence
    /// with a different hash is a conflict rather than an overwrite.
    pub fn import_bundle(
        &self,
        bundle: &export::LedgerBundle,
    ) -> Result<ImportReport, LedgerError> {
        let violations = verify_chain(
            &bundle.entries,
            bundle.manifest.range_start,
            &bundle.manifest.range_prev_hash,
        );
        if let Some(first) = violations.first() {
            return Err(LedgerError::InvalidRequest(format!(
                "bundle chain is invalid at seq {}: {} ({})",
                first.seq,
                first.kind.as_str(),
                first.detail
            )));
        }
        let mut report = ImportReport {
            imported: 0,
            skipped: 0,
        };
        for entry in &bundle.entries {
            if let Some(existing) = self.get(entry.seq)? {
                if existing.entry_hash == entry.entry_hash {
                    report.skipped += 1;
                    continue;
                }
                return Err(LedgerError::Conflict(format!(
                    "sequence {} already holds {}, bundle carries {}",
                    entry.seq, existing.entry_hash, entry.entry_hash
                )));
            }
            if let Some(existing) = self.load_by_entry_id(&entry.entry_id)? {
                if existing.entry_hash == entry.entry_hash {
                    report.skipped += 1;
                    continue;
                }
                return Err(LedgerError::Conflict(format!(
                    "entry {} already recorded differently",
                    entry.entry_id
                )));
            }
            self.insert(entry)?;
            report.imported += 1;
        }
        for checkpoint in &bundle.manifest.checkpoints {
            if self.load_checkpoint(checkpoint.seq)?.is_none() {
                self.insert_checkpoint(checkpoint)?;
            }
        }
        Ok(report)
    }

    /// Verify the stored chain and every checkpoint.
    ///
    /// `trusted_signers` are the DIDs allowed to checkpoint; `resolve_key` maps a
    /// DID to its raw public key. Entries alone are checked when neither is
    /// supplied.
    pub fn verify(
        &self,
        trusted_signers: &BTreeSet<String>,
        resolve_key: &dyn Fn(&str) -> Option<Vec<u8>>,
    ) -> Result<LedgerReport, LedgerError> {
        let entries = self.entries()?;
        let head_seq = entries.last().map(|entry| entry.seq).unwrap_or(0);
        let mut violations = verify_chain(&entries, 1, ZERO_HASH);
        let checkpoints = self.checkpoints()?;
        violations.extend(verify_checkpoints(
            &entries,
            &checkpoints,
            trusted_signers,
            resolve_key,
        ));
        let checked = entries.len();
        let ok = violations.is_empty();
        Ok(LedgerReport {
            ok,
            checked,
            head_seq,
            checkpoints: checkpoints.len(),
            message: if ok {
                format!(
                    "chain intact ({checked} entries, {} checkpoints)",
                    checkpoints.len()
                )
            } else {
                format!("{} violation(s) across {checked} entries", violations.len())
            },
            violations,
        })
    }
}

fn validate_request(request: &AppendRequest) -> Result<(), LedgerError> {
    if request.entry_id.trim().is_empty() || request.entry_id.len() > MAX_ENTRY_ID_LEN {
        return Err(LedgerError::InvalidRequest(format!(
            "entry_id must be 1..={MAX_ENTRY_ID_LEN} characters"
        )));
    }
    if request.actor_did.trim().is_empty() {
        return Err(LedgerError::InvalidRequest(
            "actor_did must be non-empty".to_string(),
        ));
    }
    let event = request.event_type.as_bytes();
    if event.is_empty()
        || event.len() > MAX_EVENT_TYPE_LEN
        || !event[0].is_ascii_lowercase()
        || !event
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Err(LedgerError::InvalidRequest(format!(
            "event_type {:?} must be lowercase snake_case",
            request.event_type
        )));
    }
    Ok(())
}

/// Verify a chain segment: numbering, links and recomputed hashes.
///
/// `expected_start` is the first sequence the segment must contain (1 for a full
/// ledger); `expected_prev` is the hash the first entry must link to.
pub fn verify_chain(
    entries: &[LedgerEntry],
    expected_start: u64,
    expected_prev: &str,
) -> Vec<LedgerViolation> {
    let mut violations = Vec::new();
    let mut expected_seq = expected_start;
    let mut prev_hash = expected_prev.to_string();
    let mut last_seq: Option<u64> = None;

    for entry in entries {
        if let Some(previous) = last_seq {
            if entry.seq < previous {
                violations.push(LedgerViolation::new(
                    entry.seq,
                    ViolationKind::Reorder,
                    format!("sequence {} follows {previous}", entry.seq),
                ));
                expected_seq = entry.seq;
            } else if entry.seq == previous {
                violations.push(LedgerViolation::new(
                    entry.seq,
                    ViolationKind::Duplicate,
                    format!("sequence {} appears more than once", entry.seq),
                ));
            }
        }
        if entry.seq != expected_seq {
            violations.push(LedgerViolation::new(
                entry.seq,
                ViolationKind::SequenceGap,
                format!("expected sequence {expected_seq}, found {}", entry.seq),
            ));
        }
        if entry.prev_hash != prev_hash {
            violations.push(LedgerViolation::new(
                entry.seq,
                ViolationKind::PreviousHashMismatch,
                format!(
                    "prev_hash {} does not link to {}",
                    entry.prev_hash, prev_hash
                ),
            ));
        }
        match payload_hash(&entry.payload) {
            Ok(hash) if hash == entry.payload_hash => {}
            Ok(hash) => violations.push(LedgerViolation::new(
                entry.seq,
                ViolationKind::PayloadHashMismatch,
                format!(
                    "payload hashes to {hash}, entry commits to {}",
                    entry.payload_hash
                ),
            )),
            Err(error) => violations.push(LedgerViolation::new(
                entry.seq,
                ViolationKind::PayloadHashMismatch,
                format!("payload cannot be canonicalised: {error}"),
            )),
        }
        match recompute_entry_hash(entry) {
            Ok(hash) if hash == entry.entry_hash => {}
            Ok(hash) => violations.push(LedgerViolation::new(
                entry.seq,
                ViolationKind::EntryHashMismatch,
                format!("entry hashes to {hash}, stored {}", entry.entry_hash),
            )),
            Err(error) => violations.push(LedgerViolation::new(
                entry.seq,
                ViolationKind::EntryHashMismatch,
                format!("entry cannot be hashed: {error}"),
            )),
        }
        prev_hash = entry.entry_hash.clone();
        expected_seq = entry.seq.saturating_add(1);
        last_seq = Some(entry.seq);
    }
    violations
}

/// Verify checkpoint content and signatures.
pub fn verify_checkpoints(
    entries: &[LedgerEntry],
    checkpoints: &[LedgerCheckpoint],
    trusted_signers: &BTreeSet<String>,
    resolve_key: &dyn Fn(&str) -> Option<Vec<u8>>,
) -> Vec<LedgerViolation> {
    let mut violations = Vec::new();
    let head_seq = entries.last().map(|entry| entry.seq).unwrap_or(0);
    for checkpoint in checkpoints {
        let recomputed = checkpoint_hash(
            checkpoint.seq,
            checkpoint.count,
            &checkpoint.head_hash,
            checkpoint.created_est,
        );
        match recomputed {
            Ok(hash) if hash == checkpoint.checkpoint_hash => {}
            Ok(hash) => violations.push(LedgerViolation::new(
                checkpoint.seq,
                ViolationKind::CheckpointForgery,
                format!(
                    "checkpoint hashes to {hash}, stored {}",
                    checkpoint.checkpoint_hash
                ),
            )),
            Err(error) => violations.push(LedgerViolation::new(
                checkpoint.seq,
                ViolationKind::CheckpointForgery,
                format!("checkpoint cannot be hashed: {error}"),
            )),
        }
        if checkpoint.seq > head_seq {
            violations.push(LedgerViolation::new(
                checkpoint.seq,
                ViolationKind::Truncation,
                format!(
                    "checkpoint covers {} entries but the ledger ends at {head_seq}",
                    checkpoint.seq
                ),
            ));
            continue;
        }
        if let Some(entry) = entries.iter().find(|entry| entry.seq == checkpoint.seq) {
            if entry.entry_hash != checkpoint.head_hash {
                violations.push(LedgerViolation::new(
                    checkpoint.seq,
                    ViolationKind::CheckpointForgery,
                    format!(
                        "checkpoint commits to {} but entry hashes to {}",
                        checkpoint.head_hash, entry.entry_hash
                    ),
                ));
            }
        }
        if !trusted_signers.is_empty() && !trusted_signers.contains(&checkpoint.signer_did) {
            violations.push(LedgerViolation::new(
                checkpoint.seq,
                ViolationKind::WrongSigner,
                format!("checkpoint signed by untrusted {}", checkpoint.signer_did),
            ));
            continue;
        }
        let Some(public_key) = resolve_key(&checkpoint.signer_did) else {
            violations.push(LedgerViolation::new(
                checkpoint.seq,
                ViolationKind::CheckpointSignature,
                format!("no public key for signer {}", checkpoint.signer_did),
            ));
            continue;
        };
        match decode_hash(&checkpoint.checkpoint_hash)
            .and_then(|hash| verify_ed25519(&public_key, &hash, &checkpoint.signature))
        {
            Ok(()) => {}
            Err(error) => violations.push(LedgerViolation::new(
                checkpoint.seq,
                ViolationKind::CheckpointSignature,
                format!("signature does not verify: {error}"),
            )),
        }
    }
    violations
}

fn row_to_entry(row: &Row<'_>) -> rusqlite::Result<LedgerEntry> {
    let payload_json: String = row.get(10)?;
    let payload: serde_json::Value = serde_json::from_str(&payload_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(10, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(LedgerEntry {
        seq: row.get::<_, i64>(0)? as u64,
        entry_id: row.get(1)?,
        prev_hash: row.get(2)?,
        entry_hash: row.get(3)?,
        recorded_est: row.get(4)?,
        actor_did: row.get(5)?,
        device_id: row.get(6)?,
        lot_id: row.get(7)?,
        event_type: row.get(8)?,
        payload_hash: row.get(9)?,
        payload,
    })
}

fn row_to_checkpoint(row: &Row<'_>) -> rusqlite::Result<LedgerCheckpoint> {
    let signature_json: String = row.get(5)?;
    let signature: DeviceSignature = serde_json::from_str(&signature_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(LedgerCheckpoint {
        seq: row.get::<_, i64>(0)? as u64,
        count: row.get::<_, i64>(1)? as u64,
        head_hash: row.get(2)?,
        checkpoint_hash: row.get(3)?,
        signer_did: row.get(4)?,
        signature,
        created_est: row.get(6)?,
    })
}
