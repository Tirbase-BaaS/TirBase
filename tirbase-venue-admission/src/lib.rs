// SPDX-License-Identifier: AGPL-3.0-only

//! # tirbase-venue-admission — Gate anti-replay and ticket revocation (ST-07)
//!
//! Builds on ST-05's signed tickets and ST-06's counting layer with the
//! gate-side guard that makes one ticket one passage:
//!
//! * **gate + epoch replay keys** — `ticket id + nonce + gate id + epoch` —
//!   plus a ticket-level claim that remembers the first gate, so a ticket
//!   cannot be used at two gates and reuse after the window is refused;
//! * **signed revocation deltas** chained on a version, each with an expiry and
//!   an M-of-N approval threshold, where emergency revocations need the
//!   stricter policy threshold and a bounded lifetime;
//! * **offline accumulation** — deltas that arrive out of order wait in a
//!   bounded queue and apply as soon as the chain closes, so gateways that have
//!   been offline converge;
//! * a **bounded replay store** with expiry cleanup, capacity eviction,
//!   eviction accounting and JSON persistence.
//!
//! A missing or expired revocation list never admits a ticket; the `Alarm`
//! stale policy refuses *and* records an operator alarm.

#![forbid(unsafe_code)]

pub mod admission;
pub mod error;
pub mod replay;
pub mod revocation;

pub use admission::{
    GateAdmission, GateDecision, GateDeny, RevocationAlarm, StalePolicy, StaleReason,
};
pub use error::{ReplayError, RevocationError};
pub use replay::{
    EpochPolicy, GateReplayGuard, ReplayKey, ReplayVerdict, DEFAULT_EPOCH_LEN_US,
    DEFAULT_REPLAY_CAPACITY, MAX_EPOCH_LEN_US, MAX_REPLAY_CAPACITY, MIN_EPOCH_LEN_US,
};
pub use revocation::{
    ApplyOutcome, DeltaPolicy, DeltaSignature, RevocationAccumulator, RevocationDelta,
    RevocationLedger, SignedRevocationDelta, SubmitOutcome, DELTA_DOMAIN, MAX_DELTA_IDS,
    MAX_PENDING_DELTAS,
};
