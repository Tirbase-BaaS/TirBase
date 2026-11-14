// SPDX-License-Identifier: AGPL-3.0-only

//! SQLite schema and stores for gateway state.
//!
//! (CLAIM-18.1–18.4, PV-9.3, PV-9) splits the durable state into:
//! - `primary.db` (WAL, `synchronous=FULL`) — PrimaryLedger tables.
//! - `derived.db` (WAL, `synchronous=NORMAL`) — DerivedLedger tables.
//!
//! Both are opened through the migration framework (CLAIM-32.1)
//! before reads/writes, and receive hardening pragmas after creation.
//! SQLite errors are mapped to `NodeMode`/`SecurityEvent` ().
//!
//! Per-subsystem `create_table` helpers remain available for compatibility
//! with existing stores; the migration framework is the authoritative schema
//! owner for `primary.db`/`derived.db` boot.

pub mod anti_replay_windows;
pub mod applied_effects_ledger;
pub mod challenge_nonces;
pub mod decided_outcomes;
pub mod device_epoch;
pub mod drift_rate_history;
pub mod enrollment_nonce;
pub mod idempotency_keys;
pub mod ledger_reconciliation;
pub mod ledger_recovery;
pub mod lockdown;
pub mod logical_dump;
pub mod migrations;
pub mod peer_checkpoint_witnesses;
pub mod pending_approvals;
pub mod security_events;
pub mod single_writer_leases;
pub mod sqlite_errors;
pub mod target_state;
pub mod time_ratchet;
pub mod wal_checkpoint;

pub use migrations::{
    maintenance_integrity_check, open_derived, open_derived_with_key, open_primary,
    open_primary_with_key, schema_version, MigrationReport,
};
pub use sqlite_errors::{DbKind, SqliteErrorAction, HARDENING_PRAGMAS};
pub mod sqlcipher;
