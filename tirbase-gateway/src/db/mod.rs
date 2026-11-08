//! SQLite schema and stores for gateway state.
//!
//! Task 18 (CLAIM-18.1–18.4, PV-9.3, PV-9) splits the durable state into:
//! - `primary.db` (WAL, `synchronous=FULL`) — PrimaryLedger tables.
//! - `derived.db` (WAL, `synchronous=NORMAL`) — DerivedLedger tables.
//!
//! Both are opened through the migration framework (task 32.1, CLAIM-32.1)
//! before reads/writes, and receive hardening pragmas after creation.
//! SQLite errors are mapped to `NodeMode`/`SecurityEvent` (task 18.4).
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
pub mod lockdown;
pub mod migrations;
pub mod pending_approvals;
pub mod single_writer_leases;
pub mod sqlite_errors;
pub mod time_ratchet;

pub use migrations::{open_derived, open_primary, schema_version, MigrationReport};
pub use sqlite_errors::{DbKind, SqliteErrorAction, HARDENING_PRAGMAS};
