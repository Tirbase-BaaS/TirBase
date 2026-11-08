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
//! task 5.4 / 5.8.  The hash-chained, device-signed [`SecurityEventLog`]
//! (sequence numbers, `prev_hash`, checkpoints, retention) is implemented in
//! task 25.1; it subscribes as a [`SecurityEventSink`].
//!
//! The allowed category and reason-code names are governed by
//! `docs/security-event-catalog.md`; `scripts/check-security-event-catalog.sh`
//! fails CI if production code references a variant that is not catalogued.

use std::sync::{Arc, RwLock};

use crate::traits::SecurityEventSink;

// ─── Severity ─────────────────────────────────────────────────────────────────

/// Severity attached to a [`SecurityEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

// ─── Category ────────────────────────────────────────────────────────────────

/// Category of a [`SecurityEvent`] — matches the headings in
/// `docs/security-event-catalog.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReasonCode {
    // CrdtHardening
    /// Inbound delta quarantined; `detail` carries the specific violation.
    DeltaQuarantined,
    /// `start_op` validation failed.
    ClockJump,
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
    /// Delta accepted for merge and routed via the LWW or RGA path.
    DeltaRouted,
    /// An additive schema change was accepted and merged.
    SchemaAdditiveAccepted,
    /// Post-merge LWW/RGA verification completed.
    MergeVerified,
    /// A payload was not in Automerge format; the Automerge merge was skipped.
    NonAutomergePayload,

    // CommandDecision
    /// A Biscuit token was invalid, expired, or from an unknown CA.
    TokenInvalid,

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

    // Startup / Diagnostic
    /// Gateway startup completed.
    BootCompleted,
    /// A persisted lockdown flag was found at boot.
    LockdownFlagFound,
    /// A trust-root record with a stale version was rejected at boot/rotation.
    TrustRootRollbackRejected,
}

impl ReasonCode {
    /// Canonical string name, matching the catalog row.
    pub fn as_str(&self) -> &'static str {
        match self {
            ReasonCode::DeltaQuarantined => "DeltaQuarantined",
            ReasonCode::ClockJump => "ClockJump",
            ReasonCode::MissingDependency => "MissingDependency",
            ReasonCode::MissingDependencyTimeout => "MissingDependencyTimeout",
            ReasonCode::PendingQueueOverflow => "PendingQueueOverflow",
            ReasonCode::RateExceeded => "RateExceeded",
            ReasonCode::Oversize => "Oversize",
            ReasonCode::OpCountExceeded => "OpCountExceeded",
            ReasonCode::BatchExceeded => "BatchExceeded",
            ReasonCode::HeadCountExceeded => "HeadCountExceeded",
            ReasonCode::DepCountExceeded => "DepCountExceeded",
            ReasonCode::TraversalBudgetExceeded => "TraversalBudgetExceeded",
            ReasonCode::DeltaRouted => "DeltaRouted",
            ReasonCode::SchemaAdditiveAccepted => "SchemaAdditiveAccepted",
            ReasonCode::MergeVerified => "MergeVerified",
            ReasonCode::NonAutomergePayload => "NonAutomergePayload",
            ReasonCode::TokenInvalid => "TokenInvalid",
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
            ReasonCode::MigrationApplied => "MigrationApplied",
            ReasonCode::PostconditionFailed => "PostconditionFailed",
            ReasonCode::FuelExhausted => "FuelExhausted",
            ReasonCode::MigrationCancelled => "MigrationCancelled",
            ReasonCode::EngineVersionMismatch => "EngineVersionMismatch",
            ReasonCode::NonDeterministicModule => "NonDeterministicModule",
            ReasonCode::ExpandContractViolation => "ExpandContractViolation",
            ReasonCode::FleetPreconditionMissing => "FleetPreconditionMissing",
            ReasonCode::MonotonicCounterRegression => "MonotonicCounterRegression",
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
            ReasonCode::BootCompleted => "BootCompleted",
            ReasonCode::LockdownFlagFound => "LockdownFlagFound",
            ReasonCode::TrustRootRollbackRejected => "TrustRootRollbackRejected",
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

#[cfg(test)]
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
