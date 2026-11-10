//! `TimeRatchet`, authenticated-time estimate, and freshness state
//! (tasks 7.2–7.5 — CLAIM-7.2…7.5, PV-22).
//!
//! # Authenticated-time model (PV-22.1)
//!
//! Command and token expiry is evaluated against `now_est`, never against the
//! wall clock:
//!
//! ```text
//! now_est = last_beacon_time + (mono_now − mono_at_beacon)
//! ```
//!
//! `last_beacon_time` is the wall-clock value of the most recent accepted
//! [`TimeBeacon`], `mono_at_beacon` is the `TimeSource::monotonic_now()` value
//! at the moment that beacon was received.  Because the difference uses the
//! monotonic (`CLOCK_BOOTTIME`) domain, adjusting the system clock cannot
//! extend the validity of an expired command (scenario S04).
//!
//! # Reboot handling (PV-22.4, INV-13)
//!
//! `mono_now − mono_at_beacon` is meaningless after a reboot, so the ratchet
//! records the `boot_id` at which the beacon was accepted.  If the current
//! `boot_id` differs, [`TimeRatchet::now_est`] returns `persisted_floor`
//! directly and freshness is [`FreshnessState::Unverified`] until a new beacon
//! arrives.
//!
//! # Ratchet (PV-22.2, S23)
//!
//! `persisted_floor` is the highest beacon wall time ever committed.  It only
//! ever moves forward: a beacon below the floor is a replay and is rejected, and
//! a beacon may only jump forward by `max_forward_jump_secs` unless it carries
//! the configured M-of-N `TimeAnchor` quorum (default M = 2).  The new record is
//! written to the [`TimeRatchetStore`] **before** the in-memory ratchet is
//! updated, so a crash can never leave the process accepting time it did not
//! durably commit.
//!
//! # Freshness (PV-22.3)
//!
//! [`FreshnessState`] is `Verified` only while a beacon has been accepted in the
//! current boot and no more than `staleness_window_secs` (default 1 hour) of
//! monotonic time has elapsed since.  Critical parameters command a
//! challenge nonce when freshness is `Unverified`
//! ([`FreshnessState::requires_challenge`]); the guard pipeline Stage 10 calls
//! this before evaluating a command.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tirbase_core::events::{ReasonCode, SecurityEvent, SecurityEventCategory, Severity};
use tirbase_core::traits::TimeSource;
use tirbase_types::CommandRole;

use crate::signed_operation::{SignedOperation, SignedOperationError, SignedOperationPayload};

// ═════════════════════════════════════════════════════════════════════════════
// Constants and configuration
// ═════════════════════════════════════════════════════════════════════════════

/// Domain-separation context string for `TimeBeacon` signatures.
pub const CONTEXT_TIME_BEACON: &str = "TirBase/v1/TimeBeacon";

/// Domain-separation context string for operator time-reset operations
/// (`POST /admin/time-reset`, task 36.3l).
pub const CONTEXT_TIME_RESET: &str = "TirBase/v1/TimeReset";

/// Max forward jump accepted from a single beacon without an anchor quorum
/// (PV-22.5): 24 hours.
pub const DEFAULT_MAX_FORWARD_JUMP_SECS: i64 = 86_400;

/// Default M in the M-of-N `TimeAnchor` quorum for large jumps (PV-22.5).
pub const DEFAULT_REQUIRED_ANCHOR_SIGNATURES: usize = 2;

/// Default staleness window after which freshness becomes `Unverified`
/// (PV-22.3): 1 hour.
pub const DEFAULT_STALENESS_WINDOW_SECS: i64 = 3_600;

/// Tunables for the ratchet.  Every field has a documented production default;
/// deployments override them from `gateway.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeRatchetConfig {
    /// Largest forward jump a single beacon may make on its own (PV-22.5).
    pub max_forward_jump_secs: i64,
    /// How many distinct `TimeAnchor` signatures a larger jump requires.
    pub required_anchor_signatures: usize,
    /// Elapsed monotonic time after which freshness is `Unverified`.
    pub staleness_window_secs: i64,
}

impl Default for TimeRatchetConfig {
    fn default() -> Self {
        TimeRatchetConfig {
            max_forward_jump_secs: DEFAULT_MAX_FORWARD_JUMP_SECS,
            required_anchor_signatures: DEFAULT_REQUIRED_ANCHOR_SIGNATURES,
            staleness_window_secs: DEFAULT_STALENESS_WINDOW_SECS,
        }
    }
}

impl TimeRatchetConfig {
    /// Clamp the configuration into a sane shape: a non-negative jump limit,
    /// at least one required signature, and a non-negative staleness window.
    pub fn sanitised(mut self) -> Self {
        self.max_forward_jump_secs = self.max_forward_jump_secs.max(0);
        self.required_anchor_signatures = self.required_anchor_signatures.max(1);
        self.staleness_window_secs = self.staleness_window_secs.max(0);
        self
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// TimeBeacon (PV-22.5, PV-28.2)
// ═════════════════════════════════════════════════════════════════════════════

/// A signed time beacon from a `TimeAnchor` peer (PV-28.2).
///
/// The beacon is always carried inside a [`SignedOperation<TimeBeacon>`], whose
/// signatures cover `CONTEXT_TIME_BEACON || 0x00 || SHA-256(CBOR(beacon))`.
/// Signing through the domain-separated wrapper means a time-anchor signature
/// can never be replayed as a command or policy signature (CLAIM-6.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeBeacon {
    /// Wall-clock time claimed by the anchor, seconds since the Unix epoch.
    pub wall_time_secs: i64,
    /// DID of the anchor that originated the beacon.
    pub issuer_did: String,
    /// Monotonically increasing per-anchor sequence number.
    pub mono_seq: u64,
    /// How long the anchor considers the beacon valid, in seconds.
    pub valid_for_secs: u32,
}

impl SignedOperationPayload for TimeBeacon {
    const CONTEXT: &'static str = CONTEXT_TIME_BEACON;
}

/// Operator time-reset payload (task 36.3l, PV-22).
///
/// A reset is the only operation that may move the ratchet floor backwards: it
/// exists for recovery from a corrupted clock and therefore requires an M-of-N
/// `TimeAnchor` quorum.  Every other path (`advance`) keeps the ratchet
/// monotonic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeResetPayload {
    /// Authoritative wall-clock value to install as the new ratchet floor.
    pub new_floor_secs: i64,
    /// Operator-visible reason for the reset.
    pub reason: String,
    /// Unique reset identifier for audit correlation.
    pub reset_id: [u8; 16],
}

impl SignedOperationPayload for TimeResetPayload {
    const CONTEXT: &'static str = CONTEXT_TIME_RESET;
}

// ═════════════════════════════════════════════════════════════════════════════
// Persistence
// ═════════════════════════════════════════════════════════════════════════════

/// The persisted row of the `time_ratchet` table (PV-22.2, task 7.6).
///
/// The `id = 1` single-row convention matches the schema in design.md §4.13;
/// storage implementations are responsible for mapping this record onto that
/// table (including the `beacon_boot_id` column).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TimeRatchetRecord {
    /// Wall-clock time of the most recently accepted beacon.
    pub last_beacon_time: i64,
    /// Monotonic value at the moment that beacon was accepted.
    pub mono_at_beacon: u64,
    /// Highest beacon wall time ever committed; only moves forward.
    pub persisted_floor: i64,
    /// `boot_id` at which the last beacon was accepted (`0` = never).
    pub beacon_boot_id: u64,
    /// Monotonic timestamp of the last ratchet update.
    pub updated_at_mono: u64,
}

/// Durable storage for the ratchet's persisted floor (PV-22.2).
///
/// The guard crate is storage-agnostic: the gateway supplies a SQLite-backed
/// implementation over `primary.db` (`tirbase-gateway/src/db/time_ratchet.rs`),
/// while simulation and tests may use an in-memory one.  A storage failure is
/// surfaced, never swallowed: an advance that cannot be persisted must not take
/// effect.
pub trait TimeRatchetStore: Send + Sync + fmt::Debug {
    /// Load the persisted record, or `None` before the first beacon.
    fn load(&self) -> Result<Option<TimeRatchetRecord>, TimeRatchetError>;

    /// Persist the record.  Must be durable before returning `Ok`.
    fn save(&self, record: &TimeRatchetRecord) -> Result<(), TimeRatchetError>;
}

// ═════════════════════════════════════════════════════════════════════════════
// FreshnessState (PV-22.3)
// ═════════════════════════════════════════════════════════════════════════════

/// Freshness of the authenticated-time estimate (PV-22.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FreshnessState {
    /// A beacon was accepted in this boot and is within the staleness window.
    Verified,
    /// No beacon yet (including after a reboot), or the last beacon is older
    /// than the staleness window.  Critical parameters require a challenge
    /// nonce in this state.
    Unverified,
}

impl FreshnessState {
    /// Canonical name used in boot diagnostics and event details.
    pub fn as_str(&self) -> &'static str {
        match self {
            FreshnessState::Verified => "Verified",
            FreshnessState::Unverified => "Unverified",
        }
    }

    /// True only for [`FreshnessState::Verified`].
    pub fn is_verified(&self) -> bool {
        matches!(self, FreshnessState::Verified)
    }

    /// Stage 10 decision: a `critical: true` parameter may only be actuated
    /// below `Unverified` freshness after a single-use challenge nonce signed by
    /// the issuer (PV-22.3).
    pub fn requires_challenge(&self, critical_parameter: bool) -> bool {
        critical_parameter && !self.is_verified()
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Errors
// ═════════════════════════════════════════════════════════════════════════════

/// Failure modes of the ratchet and beacon admission (all fail closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeRatchetError {
    /// The durable store rejected the operation.
    Store(String),
    /// The wrapper's context string is not the time-beacon domain.
    WrongDomain {
        /// Domain expected for a `TimeBeacon`.
        expected: &'static str,
        /// Context string embedded in the wrapper.
        actual: String,
    },
    /// The wrapper does not bind the supplied beacon payload.
    PayloadMismatch,
    /// The beacon carried no signature at all.
    EmptySignatures,
    /// A signature did not verify over the beacon's signing bytes.
    SignatureInvalid {
        /// DID of the entry that failed.
        signer_did: String,
    },
    /// A signer could not be resolved to a public key.
    UnknownSigner {
        /// DID of the entry that could not be resolved.
        signer_did: String,
    },
    /// A signature was presented under a role other than `TimeAnchor`.
    NonAnchorSignature {
        /// DID of the offending signer.
        signer_did: String,
        /// Role the signer claimed.
        role: CommandRole,
    },
    /// The beacon is older than the persisted floor (replay) and would move the
    /// ratchet backwards.
    BeaconNotAdvancing {
        /// Wall time claimed by the beacon.
        wall_time: i64,
        /// Current persisted floor.
        persisted_floor: i64,
    },
    /// A jump larger than `max_forward_jump_secs` arrived without enough
    /// distinct `TimeAnchor` signatures (S23).
    InsufficientAnchorQuorum {
        /// Distinct verified `TimeAnchor` signatures presented.
        verified: usize,
        /// M required by configuration.
        required: usize,
        /// Size of the rejected jump, in seconds.
        jump_secs: i64,
    },
    /// A signature wrapper error that is not covered above.
    MalformedBeacon(String),
}

impl fmt::Display for TimeRatchetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeRatchetError::Store(reason) => write!(f, "time ratchet store failure: {reason}"),
            TimeRatchetError::WrongDomain { expected, actual } => write!(
                f,
                "time beacon domain separation failure: expected {expected:?}, got {actual:?}"
            ),
            TimeRatchetError::PayloadMismatch => {
                write!(f, "time beacon wrapper does not bind the supplied beacon payload")
            }
            TimeRatchetError::EmptySignatures => {
                write!(f, "time beacon carries no TimeAnchor signature")
            }
            TimeRatchetError::SignatureInvalid { signer_did } => {
                write!(f, "time beacon signature did not verify for {signer_did}")
            }
            TimeRatchetError::UnknownSigner { signer_did } => {
                write!(f, "time beacon signer {signer_did} is not a trusted TimeAnchor")
            }
            TimeRatchetError::NonAnchorSignature { signer_did, role } => write!(
                f,
                "time beacon signed by {signer_did} under role {role:?}; only TimeAnchor may submit beacons"
            ),
            TimeRatchetError::BeaconNotAdvancing {
                wall_time,
                persisted_floor,
            } => write!(
                f,
                "time beacon wall_time {wall_time} is behind the persisted floor {persisted_floor}"
            ),
            TimeRatchetError::InsufficientAnchorQuorum {
                verified,
                required,
                jump_secs,
            } => write!(
                f,
                "time beacon jump of {jump_secs}s exceeds max_forward_jump_secs with only \
                 {verified} of {required} required TimeAnchor signature(s)"
            ),
            TimeRatchetError::MalformedBeacon(reason) => {
                write!(f, "malformed time beacon: {reason}")
            }
        }
    }
}

impl std::error::Error for TimeRatchetError {}

fn map_signed_operation_error(error: SignedOperationError) -> TimeRatchetError {
    match error {
        SignedOperationError::ContextMismatch { expected, actual } => {
            TimeRatchetError::WrongDomain { expected, actual }
        }
        SignedOperationError::PayloadHashMismatch => TimeRatchetError::PayloadMismatch,
        SignedOperationError::EmptySignatures => TimeRatchetError::EmptySignatures,
        other => TimeRatchetError::MalformedBeacon(other.to_string()),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Advance outcome
// ═════════════════════════════════════════════════════════════════════════════

/// Result of applying an accepted beacon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RatchetAdvance {
    /// Floor before the beacon was applied.
    pub previous_floor: i64,
    /// Floor after the beacon was applied (`>= previous_floor`).
    pub new_floor: i64,
    /// Forward jump the beacon requested, in seconds.
    pub jump_secs: i64,
    /// Distinct verified `TimeAnchor` signatures on the beacon.
    pub anchor_signatures: usize,
}

// ═════════════════════════════════════════════════════════════════════════════
// TimeRatchet
// ═════════════════════════════════════════════════════════════════════════════

/// Persisted monotonic ratchet for the authenticated-time estimate (PV-22.1,
/// PV-22.2).
///
/// Field names follow design.md §4.3 exactly.  `store` and the tunables are
/// additional machinery; the ratchet value itself is one of the five documented
/// fields.
#[derive(Debug)]
pub struct TimeRatchet {
    store: Arc<dyn TimeRatchetStore>,
    last_beacon_time: i64,
    mono_at_beacon: u64,
    persisted_floor: i64,
    beacon_boot_id: u64,
    updated_at_mono: u64,
    max_forward_jump_secs: i64,
    required_anchor_signatures: usize,
    staleness_window_secs: i64,
}

impl TimeRatchet {
    /// Open the ratchet from `store`: this is the production boot path, which is
    /// how the gateway recovers `persisted_floor` across restarts (CLAIM-7.2).
    pub fn open(
        store: Arc<dyn TimeRatchetStore>,
        config: TimeRatchetConfig,
    ) -> Result<Self, TimeRatchetError> {
        let config = config.sanitised();
        let record = store.load()?.unwrap_or_default();
        Ok(TimeRatchet {
            store,
            last_beacon_time: record.last_beacon_time,
            mono_at_beacon: record.mono_at_beacon,
            persisted_floor: record.persisted_floor,
            beacon_boot_id: record.beacon_boot_id,
            updated_at_mono: record.updated_at_mono,
            max_forward_jump_secs: config.max_forward_jump_secs,
            required_anchor_signatures: config.required_anchor_signatures,
            staleness_window_secs: config.staleness_window_secs,
        })
    }

    /// The record as it is persisted in `time_ratchet`.
    pub fn record(&self) -> TimeRatchetRecord {
        TimeRatchetRecord {
            last_beacon_time: self.last_beacon_time,
            mono_at_beacon: self.mono_at_beacon,
            persisted_floor: self.persisted_floor,
            beacon_boot_id: self.beacon_boot_id,
            updated_at_mono: self.updated_at_mono,
        }
    }

    /// Wall-clock time of the most recently accepted beacon.
    pub fn last_beacon_time(&self) -> i64 {
        self.last_beacon_time
    }

    /// Monotonic value at which the last beacon was accepted.
    pub fn mono_at_beacon(&self) -> u64 {
        self.mono_at_beacon
    }

    /// Highest beacon wall time ever committed (the ratchet value).
    pub fn persisted_floor(&self) -> i64 {
        self.persisted_floor
    }

    /// `boot_id` at which the last beacon was accepted (`0` = never).
    pub fn beacon_boot_id(&self) -> u64 {
        self.beacon_boot_id
    }

    /// Monotonic timestamp of the last ratchet update.
    pub fn updated_at_mono(&self) -> u64 {
        self.updated_at_mono
    }

    /// Max forward jump a single beacon may make without a quorum.
    pub fn max_forward_jump_secs(&self) -> i64 {
        self.max_forward_jump_secs
    }

    /// M in the M-of-N `TimeAnchor` quorum for large jumps.
    pub fn required_anchor_signatures(&self) -> usize {
        self.required_anchor_signatures
    }

    /// Staleness window after which freshness becomes `Unverified`.
    pub fn staleness_window_secs(&self) -> i64 {
        self.staleness_window_secs
    }

    /// Authenticated-time estimate (PV-22.1, PV-22.4).
    ///
    /// Returns `persisted_floor` when the device rebooted since the last beacon
    /// (the monotonic subtraction would be meaningless).  Otherwise evaluates
    /// `last_beacon_time + (mono_now − mono_at_beacon)` in whole seconds and
    /// floors the result at `persisted_floor`, so the estimate never runs behind
    /// the ratchet.
    pub fn now_est(&self, ts: &dyn TimeSource) -> i64 {
        if ts.boot_id() != self.beacon_boot_id {
            return self.persisted_floor;
        }

        let elapsed_micros = i128::from(ts.monotonic_now()) - i128::from(self.mono_at_beacon);
        let elapsed_secs = elapsed_micros.div_euclid(1_000_000);
        let estimate = i128::from(self.last_beacon_time) + elapsed_secs;
        saturating_i64(estimate).max(self.persisted_floor)
    }

    /// Freshness of the authenticated-time estimate (PV-22.3).
    ///
    /// `Unverified` when no beacon has ever been accepted, when the device has
    /// rebooted since the last beacon, or when more than
    /// `staleness_window_secs` of monotonic time has elapsed since it.
    pub fn freshness(&self, ts: &dyn TimeSource) -> FreshnessState {
        if self.beacon_boot_id == 0 || ts.boot_id() != self.beacon_boot_id {
            return FreshnessState::Unverified;
        }

        let elapsed_micros = ts.monotonic_now().saturating_sub(self.mono_at_beacon);
        let elapsed_secs = i64::try_from(elapsed_micros / 1_000_000).unwrap_or(i64::MAX);
        if elapsed_secs > self.staleness_window_secs {
            FreshnessState::Unverified
        } else {
            FreshnessState::Verified
        }
    }

    /// Stage 9 expiry check: an artefact is expired when
    /// `now_est > expiry_est` (PV-22.1).  Deliberately takes the authenticated
    /// estimate, not the wall clock — replacing this with a wall-clock
    /// comparison reintroduces the S19/S04 failure modes.
    pub fn is_expired(&self, expiry_est: i64, ts: &dyn TimeSource) -> bool {
        self.now_est(ts) > expiry_est
    }

    /// Apply an M-of-N `TimeAnchor`-signed operator time reset (task 36.3l).
    ///
    /// Unlike [`TimeRatchet::advance`], a reset may move the floor backwards; it
    /// is the explicit recovery path for a corrupted clock and is accepted only
    /// when at least `required_m` distinct trusted `TimeAnchor` signatures are
    /// presented.  The new record is durably persisted before it is applied.
    pub fn force_reset(
        &mut self,
        operation: &SignedOperation<TimeResetPayload>,
        payload: &TimeResetPayload,
        ts: &dyn TimeSource,
        resolve: impl Fn(&str) -> Option<Vec<u8>>,
        required_m: usize,
    ) -> Result<TimeRatchetRecord, TimeRatchetError> {
        operation
            .verify_payload(payload)
            .map_err(map_signed_operation_error)?;
        let required_m = required_m.max(1);
        let mut verified: BTreeSet<String> = BTreeSet::new();
        for entry in &operation.signatures {
            if entry.role != CommandRole::TimeAnchor {
                return Err(TimeRatchetError::NonAnchorSignature {
                    signer_did: entry.signer_did.clone(),
                    role: entry.role,
                });
            }
            let Some(public_key) = resolve(&entry.signer_did) else {
                return Err(TimeRatchetError::UnknownSigner {
                    signer_did: entry.signer_did.clone(),
                });
            };
            operation.verify_entry(entry, &public_key).map_err(|_| {
                TimeRatchetError::SignatureInvalid {
                    signer_did: entry.signer_did.clone(),
                }
            })?;
            verified.insert(entry.signer_did.clone());
        }
        if verified.len() < required_m {
            return Err(TimeRatchetError::InsufficientAnchorQuorum {
                verified: verified.len(),
                required: required_m,
                jump_secs: 0,
            });
        }

        let now_mono = ts.monotonic_now();
        let record = TimeRatchetRecord {
            last_beacon_time: payload.new_floor_secs,
            mono_at_beacon: now_mono,
            persisted_floor: payload.new_floor_secs,
            beacon_boot_id: ts.boot_id(),
            updated_at_mono: now_mono,
        };
        self.store.save(&record)?;
        self.last_beacon_time = record.last_beacon_time;
        self.mono_at_beacon = record.mono_at_beacon;
        self.persisted_floor = record.persisted_floor;
        self.beacon_boot_id = record.beacon_boot_id;
        self.updated_at_mono = record.updated_at_mono;
        self.emit(
            Severity::High,
            ReasonCode::BeaconAccepted,
            format!(
                "operator time reset installed floor {} ({} anchor signature(s), reason: {})",
                record.persisted_floor,
                verified.len(),
                payload.reason
            ),
        );
        Ok(record)
    }

    /// Apply a signed beacon (PV-22.5, S23).
    ///
    /// Admission order matters:
    ///
    /// 1. the wrapper must bind this exact payload and use the time-beacon
    ///    domain (domain separation);
    /// 2. every signature must be presented by a `TimeAnchor` and verify;
    /// 3. at least one anchor must have signed;
    /// 4. a beacon older than `persisted_floor` is rejected as a replay — the
    ///    ratchet never moves backwards;
    /// 5. a jump larger than `max_forward_jump_secs` requires the configured
    ///    M-of-N quorum of distinct `TimeAnchor` signers;
    /// 6. the new record is persisted *before* it is applied in memory.
    ///
    /// `resolve` maps a signer DID to its Ed25519 public key.
    pub fn advance(
        &mut self,
        operation: &SignedOperation<TimeBeacon>,
        beacon: &TimeBeacon,
        ts: &dyn TimeSource,
        resolve: impl Fn(&str) -> Option<Vec<u8>>,
    ) -> Result<RatchetAdvance, TimeRatchetError> {
        operation
            .verify_payload(beacon)
            .map_err(map_signed_operation_error)?;

        let mut verified: BTreeSet<String> = BTreeSet::new();
        for entry in &operation.signatures {
            if entry.role != CommandRole::TimeAnchor {
                self.emit(
                    Severity::High,
                    ReasonCode::BeaconRejected,
                    format!(
                        "beacon signature from {} presented under role {:?}; \
                         only TimeAnchor may submit time beacons",
                        entry.signer_did, entry.role
                    ),
                );
                return Err(TimeRatchetError::NonAnchorSignature {
                    signer_did: entry.signer_did.clone(),
                    role: entry.role,
                });
            }
            let Some(public_key) = resolve(&entry.signer_did) else {
                self.emit(
                    Severity::High,
                    ReasonCode::BeaconRejected,
                    format!(
                        "beacon signer {} is not a trusted TimeAnchor",
                        entry.signer_did
                    ),
                );
                return Err(TimeRatchetError::UnknownSigner {
                    signer_did: entry.signer_did.clone(),
                });
            };
            if operation.verify_entry(entry, &public_key).is_err() {
                self.emit(
                    Severity::High,
                    ReasonCode::BeaconSignatureInvalid,
                    format!(
                        "beacon signature did not verify for TimeAnchor {}",
                        entry.signer_did
                    ),
                );
                return Err(TimeRatchetError::SignatureInvalid {
                    signer_did: entry.signer_did.clone(),
                });
            }
            verified.insert(entry.signer_did.clone());
        }

        if verified.is_empty() {
            self.emit(
                Severity::High,
                ReasonCode::BeaconRejected,
                "beacon carried no TimeAnchor signature".to_string(),
            );
            return Err(TimeRatchetError::EmptySignatures);
        }

        let jump = i128::from(beacon.wall_time_secs) - i128::from(self.persisted_floor);
        if jump < 0 {
            self.emit(
                Severity::High,
                ReasonCode::BeaconRejected,
                format!(
                    "beacon wall_time {} is behind the persisted floor {}; \
                     a replayed beacon cannot move the ratchet backwards",
                    beacon.wall_time_secs, self.persisted_floor
                ),
            );
            return Err(TimeRatchetError::BeaconNotAdvancing {
                wall_time: beacon.wall_time_secs,
                persisted_floor: self.persisted_floor,
            });
        }

        if jump > i128::from(self.max_forward_jump_secs)
            && verified.len() < self.required_anchor_signatures
        {
            self.emit(
                Severity::High,
                ReasonCode::BeaconJumpTooLarge,
                format!(
                    "beacon jump of {}s exceeds max_forward_jump_secs {} with only {} of {} \
                     required TimeAnchor signature(s)",
                    saturating_i64(jump),
                    self.max_forward_jump_secs,
                    verified.len(),
                    self.required_anchor_signatures
                ),
            );
            return Err(TimeRatchetError::InsufficientAnchorQuorum {
                verified: verified.len(),
                required: self.required_anchor_signatures,
                jump_secs: saturating_i64(jump),
            });
        }

        let now_mono = ts.monotonic_now();
        let previous_floor = self.persisted_floor;
        let new_floor = self.persisted_floor.max(beacon.wall_time_secs);
        let record = TimeRatchetRecord {
            last_beacon_time: beacon.wall_time_secs,
            mono_at_beacon: now_mono,
            persisted_floor: new_floor,
            beacon_boot_id: ts.boot_id(),
            updated_at_mono: now_mono,
        };

        // Durable before accepted: a ratchet that cannot be persisted is not
        // advanced (the wiring mutation for CLAIM-7.2 removes this save).
        self.store.save(&record)?;
        self.last_beacon_time = record.last_beacon_time;
        self.mono_at_beacon = record.mono_at_beacon;
        self.persisted_floor = record.persisted_floor;
        self.beacon_boot_id = record.beacon_boot_id;
        self.updated_at_mono = record.updated_at_mono;

        self.emit(
            Severity::Low,
            ReasonCode::BeaconAccepted,
            format!(
                "beacon from {} advanced the ratchet floor {} -> {} (jump {}s, {} anchor signature(s))",
                beacon.issuer_did,
                previous_floor,
                new_floor,
                saturating_i64(jump),
                verified.len()
            ),
        );

        Ok(RatchetAdvance {
            previous_floor,
            new_floor,
            jump_secs: saturating_i64(jump),
            anchor_signatures: verified.len(),
        })
    }

    fn emit(&self, severity: Severity, reason: ReasonCode, detail: String) {
        tirbase_core::events::emit(
            SecurityEvent::new(SecurityEventCategory::TimeRatchet, severity, reason)
                .with_detail(detail),
        );
    }
}

/// Clamp an `i128` into `i64` without wrapping.
fn saturating_i64(value: i128) -> i64 {
    if value > i128::from(i64::MAX) {
        i64::MAX
    } else if value < i128::from(i64::MIN) {
        i64::MIN
    } else {
        value as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_documented_policy() {
        let config = TimeRatchetConfig::default();
        assert_eq!(config.max_forward_jump_secs, 86_400);
        assert_eq!(config.required_anchor_signatures, 2);
        assert_eq!(config.staleness_window_secs, 3_600);
    }

    #[test]
    fn config_sanitisation_keeps_m_at_least_one() {
        let config = TimeRatchetConfig {
            max_forward_jump_secs: -5,
            required_anchor_signatures: 0,
            staleness_window_secs: -1,
        }
        .sanitised();
        assert_eq!(config.max_forward_jump_secs, 0);
        assert_eq!(config.required_anchor_signatures, 1);
        assert_eq!(config.staleness_window_secs, 0);
    }

    #[test]
    fn unverified_freshness_requires_a_challenge_for_critical_parameters_only() {
        assert!(FreshnessState::Unverified.requires_challenge(true));
        assert!(!FreshnessState::Unverified.requires_challenge(false));
        assert!(!FreshnessState::Verified.requires_challenge(true));
        assert_eq!(FreshnessState::Verified.as_str(), "Verified");
        assert_eq!(FreshnessState::Unverified.as_str(), "Unverified");
    }

    #[test]
    fn saturating_conversion_clamps_both_ends() {
        assert_eq!(saturating_i64(i128::from(i64::MAX) + 1), i64::MAX);
        assert_eq!(saturating_i64(i128::from(i64::MIN) - 1), i64::MIN);
        assert_eq!(saturating_i64(-7), -7);
    }
}
