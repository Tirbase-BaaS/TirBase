// SPDX-License-Identifier: AGPL-3.0-only

//! `tirbase-gateway` library surface.
//!
//! The production entry point is the `tirbase-gateway` binary (`main.rs`). This
//! library exists so integration tests and tooling can exercise gateway modules
//! (admin dispatch, DB stores) without spawning the full binary for every case.
//! Binary-only concerns (arg parsing, full boot loop) remain in `main.rs`.

#![warn(dead_code)]

/// Serialises tests that own the process-wide security event sink.
pub static EVENT_SINK_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub mod admin;
pub mod admin_remote;
pub mod alerts;
pub mod asset_registry;
pub mod audit_time;
pub mod backup;
pub mod cloud;
pub mod cloud_anchor;
pub mod command_ingress;
pub mod config;
pub mod db;
pub mod event_batcher;
pub mod excursion;
pub mod flash_budget;
pub mod fleet;
pub mod guard;
pub mod health;
pub mod hw_counter_binding;
pub mod key_provider;
pub mod key_rotation;
pub mod lineage_ledger;
pub mod lot;
pub mod master_data;
pub mod mesh_wiring;
pub mod metrics;
pub mod monotonic_counter;
pub mod operator_identity;
pub mod ota;
pub mod profiles;
pub mod provisioning;
pub mod reference_cli;
pub mod reporting;
pub mod retention;
pub mod security_log;
pub mod security_log_export;
pub mod security_sink;
pub mod self_update;
pub mod storage_budget;
pub mod telemetry;
pub mod time_anchor;
pub mod time_beacon;
pub mod time_source;
pub mod vertical_api;
pub mod webhooks;
