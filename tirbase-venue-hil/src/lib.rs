// SPDX-License-Identifier: AGPL-3.0-only

//! # tirbase-venue-hil — gate HIL bench and safety evidence (ST-12)
//!
//! This crate is the software half of the venue gate HIL programme. It composes
//! the production ST-04 [`GateController`] with the ST-03 access controller, a
//! reader link, a physical turnstile model and a scriptable power supply, then
//! exercises power cuts, brownouts, network loss and clock jumps against the
//! configured fail-safe/fail-secure safe state.
//!
//! The physical lab still needs a real controller, reader, turnstile and smart
//! PDU. The bench is deterministic and produces a hash-sealed evidence document
//! that the lab procedure re-runs against the same case list.
//!
//! ## Safety boundary
//!
//! This is test evidence, not a safety certification. A physical safety
//! assessment (risk assessment, SIL/PL determination, actuator and fire-panel
//! verification) is a separate commercial engagement by a competent assessor.
//! No SIL/ASIL claim is made here. The emergency egress path is simulated; the
//! fire system remains external and authoritative.

#![forbid(unsafe_code)]

pub mod bench;
pub mod campaign;

pub use bench::{
    bench_config, cards, HilBench, LossStage, PowerLossRecord, SafetyClock, Turnstile,
    CONTROLLER_BROWNOUT_MV, NOMINAL_MV,
};
pub use campaign::{run_campaign, CampaignReport, CaseKind, CaseOutcome, REFERENCE_SEED};
