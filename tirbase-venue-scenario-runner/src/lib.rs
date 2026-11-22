// SPDX-License-Identifier: AGPL-3.0-only

//! # tirbase-venue-scenario-runner — AGPL integration runner (ST-09)
//!
//! Interprets the Apache-2.0 data pack in `tirbase-venue-scenarios` against the
//! real venue engines:
//!
//! * ST-05 signed tickets and the issuer key ring;
//! * ST-06 capacity envelopes, idempotent counting and reconciliation;
//! * ST-07 gate admission (cross-gate replay, revocation deltas);
//! * ST-08 lockdown, M-of-N commands and break-glass;
//! * ST-04 gate fail modes for the power-loss scenario.
//!
//! Every run is deterministic: fixed keys, fixed timestamps from the scenario,
//! no clock and no randomness. Expectations are compared, and each scenario's
//! safety invariant is evaluated over the observed trace, so a violated
//! invariant fails the run rather than being logged.

#![forbid(unsafe_code)]

pub mod runner;

pub use runner::{
    run_scenario, FinalState, InvariantObservation, Observation, RunError, StepObservation,
};
