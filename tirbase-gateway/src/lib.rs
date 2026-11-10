//! `tirbase-gateway` library surface.
//!
//! The production entry point is the `tirbase-gateway` binary (`main.rs`).  This
//! library exists so integration tests and tooling can exercise gateway modules
//! (admin dispatch, DB stores) without spawning the full binary for every case.
//! Binary-only concerns (arg parsing, full boot loop) remain in `main.rs`.

#![warn(dead_code)]

/// Serialises tests that own the process-wide security event sink.
pub static EVENT_SINK_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub mod admin;
pub mod command_ingress;
pub mod config;
pub mod db;
pub mod event_batcher;
pub mod guard;
pub mod health;
pub mod hw_counter_binding;
pub mod key_provider;
pub mod metrics;
pub mod monotonic_counter;
pub mod profiles;
pub mod security_log;
pub mod security_log_export;
pub mod security_sink;
pub mod self_update;
pub mod task34_cli;
pub mod time_beacon;
pub mod time_source;
