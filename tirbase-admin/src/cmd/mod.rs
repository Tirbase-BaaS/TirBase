//! `tirbase-admin` subcommands (task 9 — CLAIM-9.1..9.5, PV-3.10).
//!
//! Each command is a small, testable unit; the clap entry point in
//! `main.rs` is the production caller.

pub mod enroll;
pub mod inspect_identities;
pub mod mint;
pub mod rotate;
