//! Typed security events and the process-wide emission sink (PV-7.1).
//!
//! Every security-relevant decision in the core (CRDT rejection, revocation,
//! handshake result, migration outcome) is emitted as a [`SecurityEvent`]
//! through [`emit`], which forwards to the installed
//! [`SecurityEventSink`](crate::traits::SecurityEventSink).  Ad-hoc
//! `eprintln!` diagnostics in those paths are replaced by typed events so the
//! gateway can route them into a single, structured event log.
//!
//! # Relationship to the full log (task 25.1)
//!
//! This module defines the *event payload* and the emission plumbing used by
//! task 5.4 / 5.8.  The hash-chained, device-signed security event log
//! (sequence numbers, `prev_hash`, checkpoints, retention, [`TimeSourceFlag`])
//! is implemented in task 25.1; it subscribes as a [`SecurityEventSink`].
//!
//! The allowed category and reason-code names are governed by
//! `docs/security-event-catalog.md`; `scripts/check-security-event-catalog.sh`
//! fails CI if production code references a variant that is not catalogued.

use std::sync::{Arc, RwLock};

use crate::traits::SecurityEventSink;

// ─── Severity ─────────────────────────────────────────────────────────────────

/// Severity attached to a [`SecurityEvent`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Severity {
    /// Informational; no operator action required.
    Low,
    /// Worth investigating in aggregate.
    Medium,
    /// A security decision went against the caller.
    High,
    /// The node's security posture is compromised or must change mode.
    Critical,
}

impl Severity {
    /// Canonical uppercase string used in exports and logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

// ─── Time source flag (PV-7.1, CLAIM-25.1) ───────────────────────────────────

/// Indicates whether a security-event timestamp came from a trusted clock or a
/// logical fallback (PV-7.1). Carried by chained log records (task 25.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TimeSourceFlag {
    /// Timestamp derived from an authenticated/trusted time source.
    TrustedClock,
    /// Best-effort local/monotonic fallback; not authenticated.
    LogicalFallback,
}

impl TimeSourceFlag {
    /// Canonical string stored in `security_events.time_source_flag`.
    pub fn as_str(&self) -> &'static str {
        match self {
            TimeSourceFlag::TrustedClock => "TrustedClock",
            TimeSourceFlag::LogicalFallback => "LogicalFallback",
        }
    }
}

impl std::str::FromStr for TimeSourceFlag {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "TrustedClock" => Ok(TimeSourceFlag::TrustedClock),
            "LogicalFallback" => Ok(TimeSourceFlag::LogicalFallback),
            _ => Err(()),
        }
    }
}

// ─── Category ────────────────────────────────────────────────────────────────

/// Category of a [`SecurityEvent`] — matches the headings in
/// `docs/security-event-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SecurityEventCategory {
    /// Command Guard accept/reject decisions (Stage 17).
    CommandDecision,
    /// Applied Effects Ledger state transitions.
    EffectsLedger,
    /// Policy lifecycle transitions.
    PolicyLifecycle,
    /// Operational mode transitions.
    ModeTransition,
    /// Revocation subsystem.
    Revocation,
    /// Device enrollment and epoch handling.
    Enrollment,
    /// Security event log integrity.
    SecurityLog,
    /// Anti-replay window.
    AntiReplay,
    /// Monotonic counter / anti-rollback.
    MonotonicCounter,
    /// Authenticated time and TimeRatchet.
    TimeRatchet,
    /// Mesh transport (libp2p / Noise / BLE).
    MeshTransport,
    /// CRDT inbound hardening and quarantine.
    CrdtHardening,
    /// Schema migration engine.
    Migration,
    /// Driver proxy and process lifecycle.
    Driver,
    /// Cloud synchronisation path.
    CloudSync,
    /// Gateway boot and initialisation.
    Startup,
    /// Non-security informational diagnostics.
    Diagnostic,
}

impl SecurityEventCategory {
    /// Canonical string name, matching the catalog heading.
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityEventCategory::CommandDecision => "CommandDecision",
            SecurityEventCategory::EffectsLedger => "EffectsLedger",
            SecurityEventCategory::PolicyLifecycle => "PolicyLifecycle",
            SecurityEventCategory::ModeTransition => "ModeTransition",
            SecurityEventCategory::Revocation => "Revocation",
            SecurityEventCategory::Enrollment => "Enrollment",
            SecurityEventCategory::SecurityLog => "SecurityLog",
            SecurityEventCategory::AntiReplay => "AntiReplay",
            SecurityEventCategory::MonotonicCounter => "MonotonicCounter",
            SecurityEventCategory::TimeRatchet => "TimeRatchet",
            SecurityEventCategory::MeshTransport => "MeshTransport",
            SecurityEventCategory::CrdtHardening => "CrdtHardening",
            SecurityEventCategory::Migration => "Migration",
            SecurityEventCategory::Driver => "Driver",
            SecurityEventCategory::CloudSync => "CloudSync",
            SecurityEventCategory::Startup => "Startup",
            SecurityEventCategory::Diagnostic => "Diagnostic",
        }
    }
}

// ─── Reason code ─────────────────────────────────────────────────────────────

/// Reason code attached to a [`SecurityEvent`].
///
/// The variants implemented here are the ones emitted by the core paths wired
/// in tasks 5.4 and 5.8.  Task 25.1 extends this enum to the full catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ReasonCode {
    // CrdtHardening
    /// Inbound delta quarantined; `detail` carries the specific violation.
    DeltaQuarantined,
    /// `start_op` validation failed.
    ClockJump,
    UnknownSchemaHash,
    /// Delta depends on operations not yet received.
    MissingDependency,
    /// Pending delta timed out waiting for dependencies.
    MissingDependencyTimeout,
    /// Pending queue byte cap exceeded.
    PendingQueueOverflow,
    /// Per-sender rate cap exceeded.
    RateExceeded,
    /// Delta exceeded the maximum size.
    Oversize,
    /// Delta exceeded the maximum operation count.
    OpCountExceeded,
    /// Batch exceeded the maximum change count.
    BatchExceeded,
    /// DAG heads exceeded the maximum.
    HeadCountExceeded,
    /// Change has too many dependencies.
    DepCountExceeded,
    /// DAG traversal budget exceeded.
    TraversalBudgetExceeded,
    /// Inbound mesh peer count exceeded the configured connection cap.
    ConnectionCapExceeded,
    /// Delta accepted for merge and routed via the LWW or RGA path.
    DeltaRouted,
    /// An additive schema change was accepted and merged.
    SchemaAdditiveAccepted,
    /// Post-merge LWW/RGA verification completed.
    MergeVerified,
    /// A payload was not in Automerge format; the Automerge merge was skipped.
    NonAutomergePayload,

    // CommandDecision
    /// Pre-auth per-source token bucket exceeded before any crypto (Stage 0).
    PreAuthRateLimit,
    /// Node is in Lockdown or Restricted mode; command rejected at Stage 1.
    ModeLockdown,
    /// A Biscuit token was invalid, expired, or from an unknown CA (Stage 3).
    TokenInvalid,
    /// A command signature failed verification (Stage 2).
    CommandSignatureInvalid,
    /// Command passed the task-11 admission core and was dispatched.
    CommandAccepted,
    /// Token does not authorise requested target/parameter/role binding (Stage 4).
    ScopeViolation,
    /// Issuer DID is revoked (Stage 5).
    IssuerRevoked,
    /// Command enrollment epoch is stale (Stage 6).
    StaleEpoch,
    /// Target has an Unknown ledger entry (Stage 6.5).
    TargetBusy,
    /// Command expiry exceeded using `now_est` (Stage 8).
    Expired,
    /// Critical parameter in UNVERIFIED freshness requires challenge nonce (Stage 9).
    ChallengeMissing,
    /// FixedPointValue invalid or non-canonical exponent (Stage 10).
    ValueInvalid,
    /// Value outside envelope bounds (Stage 11).
    EnvelopeViolation,
    /// Cross-parameter linear constraint failed (Stage 12).
    ConstraintViolation,
    /// Rate-of-change or cumulative drift window exceeded (Stage 13).
    DriftExceeded,
    /// Dwell timing violation (Stage 13, PV-4.7).
    DwellViolation,
    /// Min-off timing violation (Stage 13, PV-4.7).
    MinOffViolation,
    /// Per-issuer rate limit exceeded (Stage 14).
    RateLimit,
    /// Critical parameter requires M-of-N co-signatures (Stage 15).
    QuorumRequired,
    /// Atomic commit/sequence conflict (Stage 16).
    CommitConflict,
    /// Anti-replay sequence rejected: replay or outside window (PV-5.5).
    SequenceRejected,
    /// Anti-replay window baseline reset by PolicyAuthority (PV-5.5).
    WindowReset,
    /// Another issuer holds the SingleWriterLease (Stage 16).
    LeaseHeld,
    /// No EnvelopeProfile installed for target.
    NoProfile,
    /// Operation unsupported in this mode/version.
    Unsupported,

    // Revocation
    /// A DID was added to the revocation set.
    DidRevoked,
    /// One M-of-N co-signature was received.
    RevocationSignatureReceived,
    /// A lease held by a revoked DID was released.
    RevocationLeaseReleased,
    /// A migration author was revoked after execution.
    RevocationPostExecution,
    /// A revocation signature or revocation delta failed verification.
    RevocationVerificationFailed,

    // MeshTransport
    /// A mesh peer connected.
    PeerConnected,
    /// A mesh peer disconnected.
    PeerDisconnected,
    /// Noise IK handshake succeeded.
    HandshakeSuccess,
    /// Noise IK handshake failed.
    HandshakeFailed,
    /// A delta was routed through a relay peer because the destination is not
    /// a direct neighbour.
    RelaySelected,
    /// Fragment reassembly failed or produced an unparsable payload.
    FragmentReassemblyFailed,
    /// Latest checkpoint hash gossiped to peer during sync (PV-7.10, CLAIM-26.3).
    CheckpointGossiped,

    // Migration
    /// A migration transform was applied.
    MigrationApplied,
    /// A migration postcondition failed.
    PostconditionFailed,
    /// The WASM sandbox ran out of fuel.
    FuelExhausted,
    /// An in-progress migration was cancelled.
    MigrationCancelled,
    /// The module's fuel-cost table does not match the active profile.
    EngineVersionMismatch,
    /// PV-8.2 / S8: migration WASM violated the deterministic execution profile.
    DeterministicProfileViolation,
    /// The module contains non-deterministic instructions.
    NonDeterministicModule,
    /// A contract migration violated the expand/contract rule.
    ExpandContractViolation,
    /// A contract migration omitted the fleet precondition hash.
    FleetPreconditionMissing,

    // MonotonicCounter (PV-9.8, CLAIM-6.7a)
    /// Hardware counter ahead of the software counter at boot; device rollback
    /// detected.
    MonotonicCounterRegression,

    // Driver isolation (PV-10.4, S35, CLAIM-34.8)
    /// Driver child exited abnormally or failed seccomp/landlock init.
    IsolationFailure,
    /// Driver child attempted or was blocked from passing an fd via SCM_RIGHTS (S35).
    SCMRightsAttempt,
    /// Seccomp/landlock/no_new_privs sandbox violation in driver child.
    SandboxViolation,

    // PolicyLifecycle (PV-4.8–4.12, CLAIM-12.1–12.11)
    /// Tightening policy bundle applied after signature verification (PV-4.9).
    TighteningApplied,
    /// Loosening co-signature collected; operation still pending.
    LooseningSignatureCollected,
    /// Loosening policy applied after M-of-N threshold and time-lock.
    LooseningApplied,
    /// Pending loosening operation cancelled by PolicyAuthority.
    LooseningCancelled,
    /// Bundle rejected: version not strictly greater than committed counter.
    PolicyRollbackBlocked,
    /// Bundle rejected: tightening would violate device-class tightening floor.
    TighteningFloorViolation,
    /// Bundle rejected: classification, signature, or governance check failed.
    PolicyRejected,
    /// M=1 loosening governance accepted with a startup/operational warning (RD-9).
    PolicyLooseningM1Warning,

    // TimeRatchet (PV-22, CLAIM-7.2–7.5)
    /// A TimeAnchor beacon advanced the ratchet's persisted floor.
    BeaconAccepted,
    /// A time beacon was rejected before the ratchet was updated.
    BeaconRejected,
    /// Beacon wall time exceeded `max_forward_jump_secs` without an anchor
    /// quorum (S23).
    BeaconJumpTooLarge,
    /// A beacon signature did not verify against a trusted TimeAnchor key.
    BeaconSignatureInvalid,
    /// The authenticated-time estimate is stale or unknown after a reboot.
    FreshnessUnverified,
    /// A fresh beacon restored VERIFIED freshness.
    FreshnessRestored,

    // Enrollment (PV-3.11, PV-3.13, PV-5.5)
    /// A device completed enrollment and received a scoped token.
    DeviceEnrolled,
    /// A signed enrollment-epoch bump was committed.
    EpochBumped,
    /// A peer or issuer reported a lower epoch than previously witnessed.
    EpochRegression,
    /// A bootstrap enrollment nonce was reused inside its retention window.
    NonceReused,

    // SecurityLog (PV-7, task 25/26/28)
    /// Signed checkpoint record written to the security event log (PV-7.3).
    CheckpointWritten,
    /// Hash-chain broken; entering Restricted mode (PV-7.4).
    TamperDetection,
    /// Signed chain-recovery command accepted; new segment opened (PV-7.4).
    ChainRecovery,
    /// Peer observed a higher checkpoint hash than local log (PV-7.10).
    TailTruncation,
    /// Per-category rate limit (100/s) hit; N events suppressed (PV-7.6, S14).
    SuppressionSummary,
    /// No mesh peers or cloud connection; checkpoint cannot be externally witnessed (PV-7.10).
    NoWitnessAvailable,
    /// Security event mesh sync failed; retry scheduled (PV-7.9, CLAIM-28.3).
    SyncFailure,
    /// Peer security-event sync rate limit (500 events/min) exceeded (PV-7.12, CLAIM-28.3).
    SyncRateLimitReached,
    /// Oldest signed segment archived/removed by retention rotation (PV-7.13, CLAIM-28.2).
    LogRotated,

    // Flash budget / storage wear (PV-15.4, CLAIM-44.5/44.6)
    /// Non-critical write throttling activated because projected daily block writes exceed budget.
    FlashBudgetThrottlingActivated,
    /// Flash-wear throttling deactivated (within budget).
    FlashBudgetThrottlingDeactivated,

    // Startup / Diagnostic
    /// Gateway startup completed.
    BootCompleted,
    /// A persisted lockdown flag was found at boot.
    LockdownFlagFound,
    /// PRAGMA quick_check detected database corruption at boot (PV-9.3).
    QuickCheckFailed,
    /// `SQLITE_FULL` (ENOSPC): High severity; continue with reduced logging (PV-9, CLAIM-18.4).
    StorageFull,
    /// `SQLITE_IOERR`: PrimaryLedger/DB I/O failure; enter Restricted mode (PV-9, CLAIM-18.4).
    StorageError,
    /// `SQLITE_CORRUPT`: enter Restricted mode; operator intervention required (PV-9, CLAIM-18.4).
    StorageCorrupt,
    /// Derived ledger rebuilt from signed delta log after corruption.
    LedgerRebuilt,
    /// Boot-time reconciliation of Actuating effects-ledger entries finished (PV-5.3).
    ReconciliationComplete,
    /// One or more Actuating entries could not be reconciled within timeout (PV-5.3).
    ReconciliationTimeout,
    /// Pre-Actuating ledger entry from an older schema marked Failed at boot (PV-5.3, 19.3).
    OldSchemaEntry,
    /// Effects-ledger pruning job removed old Complete/Failed entries (PV-5.12).
    LedgerPruned,
    /// A trust-root record with a stale version was rejected at boot/rotation.
    TrustRootRollbackRejected,

    // ModeTransition / lockdown (PV-4.13, PV-1.11, CLAIM-13.1–13.6)
    /// Node entered LOCKDOWN.
    EnteredLockdown,
    /// Node exited LOCKDOWN after M-of-N authorization.
    ExitedLockdown,
    /// Node entered Restricted mode.
    EnteredRestricted,
    /// Crash-loop threshold exceeded; LOCKDOWN escalation triggered.
    CrashLoopEscalation,
    /// A valid M-of-N lockdown-exit command was applied.
    LockdownExitApplied,
    /// A lockdown-exit command was rejected (signature/quorum/profile).
    LockdownExitRejected,
    // CommandDecision (Stage 1 mode gate, CLAIM-13.1)
}

impl ReasonCode {
    /// Canonical string name, matching the catalog row.
    pub fn as_str(&self) -> &'static str {
        match self {
            ReasonCode::DeltaQuarantined => "DeltaQuarantined",
            ReasonCode::ClockJump => "ClockJump",
            ReasonCode::UnknownSchemaHash => "UnknownSchemaHash",
            ReasonCode::MissingDependency => "MissingDependency",
            ReasonCode::MissingDependencyTimeout => "MissingDependencyTimeout",
            ReasonCode::PendingQueueOverflow => "PendingQueueOverflow",
            ReasonCode::RateExceeded => "RateExceeded",
            ReasonCode::PreAuthRateLimit => "PreAuthRateLimit",
            ReasonCode::Oversize => "Oversize",
            ReasonCode::OpCountExceeded => "OpCountExceeded",
            ReasonCode::BatchExceeded => "BatchExceeded",
            ReasonCode::HeadCountExceeded => "HeadCountExceeded",
            ReasonCode::DepCountExceeded => "DepCountExceeded",
            ReasonCode::TraversalBudgetExceeded => "TraversalBudgetExceeded",
            ReasonCode::ConnectionCapExceeded => "ConnectionCapExceeded",
            ReasonCode::DeltaRouted => "DeltaRouted",
            ReasonCode::SchemaAdditiveAccepted => "SchemaAdditiveAccepted",
            ReasonCode::MergeVerified => "MergeVerified",
            ReasonCode::NonAutomergePayload => "NonAutomergePayload",
            ReasonCode::TokenInvalid => "TokenInvalid",
            ReasonCode::CommandSignatureInvalid => "CommandSignatureInvalid",
            ReasonCode::CommandAccepted => "CommandAccepted",
            ReasonCode::ScopeViolation => "ScopeViolation",
            ReasonCode::IssuerRevoked => "IssuerRevoked",
            ReasonCode::StaleEpoch => "StaleEpoch",
            ReasonCode::TargetBusy => "TargetBusy",
            ReasonCode::Expired => "Expired",
            ReasonCode::ChallengeMissing => "ChallengeMissing",
            ReasonCode::ValueInvalid => "ValueInvalid",
            ReasonCode::EnvelopeViolation => "EnvelopeViolation",
            ReasonCode::ConstraintViolation => "ConstraintViolation",
            ReasonCode::DriftExceeded => "DriftExceeded",
            ReasonCode::DwellViolation => "DwellViolation",
            ReasonCode::MinOffViolation => "MinOffViolation",
            ReasonCode::RateLimit => "RateLimit",
            ReasonCode::QuorumRequired => "QuorumRequired",
            ReasonCode::CommitConflict => "CommitConflict",
            ReasonCode::SequenceRejected => "SequenceRejected",
            ReasonCode::WindowReset => "WindowReset",
            ReasonCode::LeaseHeld => "LeaseHeld",
            ReasonCode::NoProfile => "NoProfile",
            ReasonCode::Unsupported => "Unsupported",
            ReasonCode::DidRevoked => "DidRevoked",
            ReasonCode::RevocationSignatureReceived => "RevocationSignatureReceived",
            ReasonCode::RevocationLeaseReleased => "RevocationLeaseReleased",
            ReasonCode::RevocationPostExecution => "RevocationPostExecution",
            ReasonCode::RevocationVerificationFailed => "RevocationVerificationFailed",
            ReasonCode::PeerConnected => "PeerConnected",
            ReasonCode::PeerDisconnected => "PeerDisconnected",
            ReasonCode::HandshakeSuccess => "HandshakeSuccess",
            ReasonCode::HandshakeFailed => "HandshakeFailed",
            ReasonCode::RelaySelected => "RelaySelected",
            ReasonCode::FragmentReassemblyFailed => "FragmentReassemblyFailed",
            ReasonCode::CheckpointGossiped => "CheckpointGossiped",
            ReasonCode::MigrationApplied => "MigrationApplied",
            ReasonCode::PostconditionFailed => "PostconditionFailed",
            ReasonCode::FuelExhausted => "FuelExhausted",
            ReasonCode::MigrationCancelled => "MigrationCancelled",
            ReasonCode::EngineVersionMismatch => "EngineVersionMismatch",
            ReasonCode::DeterministicProfileViolation => "DeterministicProfileViolation",
            ReasonCode::NonDeterministicModule => "NonDeterministicModule",
            ReasonCode::ExpandContractViolation => "ExpandContractViolation",
            ReasonCode::FleetPreconditionMissing => "FleetPreconditionMissing",
            ReasonCode::MonotonicCounterRegression => "MonotonicCounterRegression",
            ReasonCode::IsolationFailure => "IsolationFailure",
            ReasonCode::SCMRightsAttempt => "SCMRightsAttempt",
            ReasonCode::SandboxViolation => "SandboxViolation",
            ReasonCode::TighteningApplied => "TighteningApplied",
            ReasonCode::LooseningSignatureCollected => "LooseningSignatureCollected",
            ReasonCode::LooseningApplied => "LooseningApplied",
            ReasonCode::LooseningCancelled => "LooseningCancelled",
            ReasonCode::PolicyRollbackBlocked => "PolicyRollbackBlocked",
            ReasonCode::TighteningFloorViolation => "TighteningFloorViolation",
            ReasonCode::PolicyRejected => "PolicyRejected",
            ReasonCode::PolicyLooseningM1Warning => "PolicyLooseningM1Warning",
            ReasonCode::BeaconAccepted => "BeaconAccepted",
            ReasonCode::BeaconRejected => "BeaconRejected",
            ReasonCode::BeaconJumpTooLarge => "BeaconJumpTooLarge",
            ReasonCode::BeaconSignatureInvalid => "BeaconSignatureInvalid",
            ReasonCode::FreshnessUnverified => "FreshnessUnverified",
            ReasonCode::FreshnessRestored => "FreshnessRestored",
            ReasonCode::DeviceEnrolled => "DeviceEnrolled",
            ReasonCode::EpochBumped => "EpochBumped",
            ReasonCode::EpochRegression => "EpochRegression",
            ReasonCode::NonceReused => "NonceReused",
            ReasonCode::CheckpointWritten => "CheckpointWritten",
            ReasonCode::TamperDetection => "TamperDetection",
            ReasonCode::ChainRecovery => "ChainRecovery",
            ReasonCode::TailTruncation => "TailTruncation",
            ReasonCode::SuppressionSummary => "SuppressionSummary",
            ReasonCode::NoWitnessAvailable => "NoWitnessAvailable",
            ReasonCode::SyncFailure => "SyncFailure",
            ReasonCode::SyncRateLimitReached => "SyncRateLimitReached",
            ReasonCode::LogRotated => "LogRotated",
            ReasonCode::FlashBudgetThrottlingActivated => "FlashBudgetThrottlingActivated",
            ReasonCode::FlashBudgetThrottlingDeactivated => "FlashBudgetThrottlingDeactivated",

            ReasonCode::BootCompleted => "BootCompleted",
            ReasonCode::LockdownFlagFound => "LockdownFlagFound",
            ReasonCode::QuickCheckFailed => "QuickCheckFailed",
            ReasonCode::StorageFull => "StorageFull",
            ReasonCode::StorageError => "StorageError",
            ReasonCode::StorageCorrupt => "StorageCorrupt",
            ReasonCode::LedgerRebuilt => "LedgerRebuilt",
            ReasonCode::ReconciliationComplete => "ReconciliationComplete",
            ReasonCode::ReconciliationTimeout => "ReconciliationTimeout",
            ReasonCode::OldSchemaEntry => "OldSchemaEntry",
            ReasonCode::LedgerPruned => "LedgerPruned",
            ReasonCode::TrustRootRollbackRejected => "TrustRootRollbackRejected",
            ReasonCode::EnteredLockdown => "EnteredLockdown",
            ReasonCode::ExitedLockdown => "ExitedLockdown",
            ReasonCode::EnteredRestricted => "EnteredRestricted",
            ReasonCode::CrashLoopEscalation => "CrashLoopEscalation",
            ReasonCode::LockdownExitApplied => "LockdownExitApplied",
            ReasonCode::LockdownExitRejected => "LockdownExitRejected",
            ReasonCode::ModeLockdown => "ModeLockdown",
        }
    }
}

// ─── Event ───────────────────────────────────────────────────────────────────

/// A typed, structured security-relevant record (PV-7.1).
///
/// Fields are deliberately plain data: the hash-chain fields (`seq`,
/// `prev_hash`, `best_effort_wall_time`, `time_source_flag`) are attached by
/// the [`SecurityEventLog`](crate::traits::SecurityEventSink) implementation in
/// task 25.1, so emission sites never have to know about chain state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEvent {
    /// Category this event belongs to.
    pub category: SecurityEventCategory,
    /// Severity of the event.
    pub severity: Severity,
    /// DID of the actor that caused the event, when known.
    pub actor_did: Option<String>,
    /// Target identifier (device, parameter, peer, delta id), when known.
    pub target: Option<String>,
    /// Typed reason code.
    pub reason_code: ReasonCode,
    /// Human-readable detail (never parsed by machine consumers).
    pub detail: Option<String>,
    /// GDPR personal fields (CLAIM-27.1, PV-7.7, RD-3). Plaintext is stored
    /// in `security_event_personal_fields`; only salted commitments
    /// `SHA-256(random_salt ‖ value)` enter the hash chain. Empty by default.
    pub personal_fields: Vec<PersonalField>,
}

/// A personal field carried by a security event (GDPR, PV-7.7, RD-3).
/// `value_plaintext` is never persisted in the hash-chained event row; it is
/// stored separately in `security_event_personal_fields` alongside a random salt.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersonalField {
    pub field_name: String,
    pub value_plaintext: String,
}

impl PersonalField {
    pub fn new(field_name: impl Into<String>, value_plaintext: impl Into<String>) -> Self {
        Self {
            field_name: field_name.into(),
            value_plaintext: value_plaintext.into(),
        }
    }
}

impl SecurityEvent {
    /// Construct an event with the required fields and no actor/target/detail.
    pub fn new(
        category: SecurityEventCategory,
        severity: Severity,
        reason_code: ReasonCode,
    ) -> Self {
        SecurityEvent {
            category,
            severity,
            actor_did: None,
            target: None,
            reason_code,
            detail: None,
            personal_fields: Vec::new(),
        }
    }

    /// Attach the actor DID.
    pub fn with_actor(mut self, actor_did: impl Into<String>) -> Self {
        self.actor_did = Some(actor_did.into());
        self
    }

    /// Attach the target identifier.
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Attach free-form detail.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Attach a GDPR personal field (CLAIM-27.1, PV-7.7, RD-3). The plaintext
    /// is stored in `security_event_personal_fields`; the salted commitment
    /// enters the hash chain.
    pub fn with_personal_field(
        mut self,
        field_name: impl Into<String>,
        value_plaintext: impl Into<String>,
    ) -> Self {
        self.personal_fields
            .push(PersonalField::new(field_name, value_plaintext));
        self
    }
}

// ─── Process-wide sink ───────────────────────────────────────────────────────

/// The installed sink, if any.  A process-global slot keeps every core
/// subsystem on one event log without threading a sink handle through every
/// constructor.
static SECURITY_EVENT_SINK: RwLock<Option<Arc<dyn SecurityEventSink>>> = RwLock::new(None);

/// Install the process-wide [`SecurityEventSink`], returning the previously
/// installed sink (if any).
///
/// The gateway installs its event log once at boot; tests install a
/// recording sink to assert wiring.
pub fn install_security_event_sink(
    sink: Arc<dyn SecurityEventSink>,
) -> Option<Arc<dyn SecurityEventSink>> {
    match SECURITY_EVENT_SINK.write() {
        Ok(mut slot) => slot.replace(sink),
        Err(poisoned) => poisoned.into_inner().replace(sink),
    }
}

/// The currently installed sink, if one has been installed.
pub fn security_event_sink() -> Option<Arc<dyn SecurityEventSink>> {
    match SECURITY_EVENT_SINK.read() {
        Ok(slot) => slot.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

/// Emit `event` through the installed [`SecurityEventSink`] (PV-7.1).
///
/// A missing sink is a deliberate no-op: the core library stays usable in
/// environments that have not wired an event log yet (for example the WASM
/// build before the SDK installs one).  The sink handle is cloned out of the
/// registry before `emit` is called, so a re-entrant emit from inside the sink
/// cannot deadlock on the registry lock.
pub fn emit(event: SecurityEvent) {
    if let Some(sink) = security_event_sink() {
        sink.emit(event);
    }
}

/// Emit an event with all optional fields.
pub(crate) fn emit_security(
    category: SecurityEventCategory,
    severity: Severity,
    reason_code: ReasonCode,
    actor_did: Option<&str>,
    target: Option<String>,
    detail: impl Into<String>,
) {
    let mut event = SecurityEvent::new(category, severity, reason_code).with_detail(detail);
    if let Some(actor_did) = actor_did {
        event = event.with_actor(actor_did);
    }
    if let Some(target) = target {
        event = event.with_target(target);
    }
    emit(event);
}

/// Convenience: emit a `CrdtHardening` event.
pub(crate) fn emit_crdt(
    severity: Severity,
    reason_code: ReasonCode,
    target: Option<String>,
    detail: impl Into<String>,
) {
    emit_security(
        SecurityEventCategory::CrdtHardening,
        severity,
        reason_code,
        None,
        target,
        detail,
    );
}

/// Convenience: emit a `MeshTransport` event.
pub(crate) fn emit_transport(
    severity: Severity,
    reason_code: ReasonCode,
    target: Option<String>,
    detail: impl Into<String>,
) {
    emit_security(
        SecurityEventCategory::MeshTransport,
        severity,
        reason_code,
        None,
        target,
        detail,
    );
}

/// Convenience: emit an auth/token `CommandDecision` event.
pub(crate) fn emit_auth(
    severity: Severity,
    reason_code: ReasonCode,
    actor_did: Option<&str>,
    detail: impl Into<String>,
) {
    emit_security(
        SecurityEventCategory::CommandDecision,
        severity,
        reason_code,
        actor_did,
        None,
        detail,
    );
}

/// Convenience: emit a `Revocation` event.
pub(crate) fn emit_revocation(
    severity: Severity,
    reason_code: ReasonCode,
    target: Option<String>,
    detail: impl Into<String>,
) {
    emit_security(
        SecurityEventCategory::Revocation,
        severity,
        reason_code,
        None,
        target,
        detail,
    );
}

/// Convenience: emit a `Migration` event.
pub(crate) fn emit_migration(
    severity: Severity,
    reason_code: ReasonCode,
    target: Option<String>,
    detail: impl Into<String>,
) {
    emit_security(
        SecurityEventCategory::Migration,
        severity,
        reason_code,
        None,
        target,
        detail,
    );
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::traits::SecurityEventSink;
    use std::sync::Mutex;

    /// Serialises tests that replace the process-wide sink so parallel test
    /// threads cannot observe each other's sinks.
    pub(crate) static SINK_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Debug, Default)]
    struct RecordingSink {
        events: Mutex<Vec<SecurityEvent>>,
    }

    impl SecurityEventSink for RecordingSink {
        fn emit(&self, event: SecurityEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    #[test]
    fn emit_routes_through_installed_sink() {
        let _guard = SINK_TEST_LOCK.lock().unwrap();
        let sink = Arc::new(RecordingSink::default());
        let previous = install_security_event_sink(sink.clone());

        emit(
            SecurityEvent::new(
                SecurityEventCategory::MeshTransport,
                Severity::Medium,
                ReasonCode::HandshakeFailed,
            )
            .with_target("peer-1")
            .with_detail("noise handshake failed"),
        );

        // Restore before asserting so a panic cannot leave the test sink
        // installed for other tests.
        install_security_event_sink(previous.unwrap_or_else(|| Arc::new(RecordingSink::default())));

        let events = sink.events.lock().unwrap();
        // Other parallel tests may emit into the same sink while it is
        // installed, so match on this event instead of asserting a count.
        let event = events
            .iter()
            .find(|event| event.target.as_deref() == Some("peer-1"))
            .expect("emitted event routed to installed sink");
        assert_eq!(event.category, SecurityEventCategory::MeshTransport);
        assert_eq!(event.reason_code, ReasonCode::HandshakeFailed);
        assert_eq!(event.severity, Severity::Medium);
    }

    #[test]
    fn category_and_reason_names_match_catalog() {
        assert_eq!(
            SecurityEventCategory::CrdtHardening.as_str(),
            "CrdtHardening"
        );
        assert_eq!(ReasonCode::DeltaQuarantined.as_str(), "DeltaQuarantined");
        assert_eq!(Severity::High.as_str(), "HIGH");
    }
}

// Additional reason codes used by flash-wear budget/throttle (PV-15.4, CLAIM-44.5/44.6).
// NOTE: variants appended via source edit below in separate patch; keep marker.
