//! SQLite schema and stores for gateway state living in `primary.db`
//! (task 7.6 — CLAIM-7.6, PV-22.2).
//!
//! The gateway owns the durable PrimaryLedger tables.  Task 32.1 introduces the
//! general migration framework; until then each table-owning subsystem creates
//! its own table idempotently (`CREATE TABLE IF NOT EXISTS`) at boot.  The
//! definitions mirror design.md §4.13 so the later migration framework can adopt
//! them unchanged.

pub mod device_epoch;
pub mod enrollment_nonce;
pub mod lockdown;
pub mod pending_approvals;
pub mod time_ratchet;
pub mod challenge_nonces;
pub mod decided_outcomes;
pub mod drift_rate_history;
