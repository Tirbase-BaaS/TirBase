//! TirBase Command Guard crate.
//! Provides the CommandGuard, EnvelopeProfile, PolicyLifecycle,
//! AppliedEffectsLedger, AntiReplayWindow, SingleWriterLease,
//! TimeRatchet, ActuationPermit, and SecurityEventLog.
//! Full implementation in –16.

#![deny(unsafe_code)]
// Narrow `unsafe` is allowed only in modules that explicitly opt in for
// OS fd ownership boundaries (e.g. `device_transport`).
// Warn on dead private code across this crate. `pub` items are naturally exempt
// (the Rust dead_code lint does not fire on reachable public items).
#![warn(dead_code)]
// HashMap is banned in guard/sim (PV-12): iteration order is not
// deterministic. Use BTreeMap (ordered) or IndexMap (insertion-ordered).
#![deny(clippy::disallowed_types)]

pub mod signed_operation;

/// Policy lifecycle: bundle types (wire), 11-criterion tightening classification,
/// tightening-floor enforcement, loosening M-of-N/timelock path, anti-rollback,
/// and pending-approval accumulation (12.10 — CLAIM-12.1…12.10).
pub mod policy;

/// `TimeRatchet`, authenticated-time estimate, and freshness state
/// (7.5 — CLAIM-7.2…7.5, PV-22).
pub mod time;

/// Single-writer lease type (PV-5.8/5.8a).
pub mod single_writer_lease;

/// Anti-replay sliding window and PolicyAuthority-signed reset
/// (20.3 — CLAIM-20.1…20.3, PV-5.5, INV-10).
pub mod anti_replay;

/// Node operational mode and mode × operation matrix (/// CLAIM-13.1, PV-4.13).
pub mod node_mode;

/// LOCKDOWN entry/exit, persistence, crash-loop escalation, and safe-default
/// arming (CLAIM-13.2/3/5/6, PV-4.13, PV-4.15).
pub mod lockdown;
pub use lockdown::{apply_chain_recovery, ChainRecoveryPayload};

/// Envelope profile install/validation and target-to-profile hot-swap
/// (10.6 — CLAIM-10.4…10.6, PV-4.5).
pub mod envelope;

/// Trust root record and per-role registry (8.3a — CLAIM-8.3,
/// CLAIM-8.3a, PV-3.2, PV-3.3, PV-3.4).
pub mod trust_root;

/// Per-device enrollment epoch, nonce store, and Stage 8 guard check (tasks
/// 8.5–8.8 — CLAIM-8.5…CLAIM-8.8, PV-3.11, PV-3.13, PV-5.5, PV-9.8).
pub mod epoch;

/// Table-driven authorization matrix and typed role-authorization checks
/// (PV-3.3, CLAIM-56.1).
pub mod auth_matrix;

/// `CommandMessage` signing/verification (CLAIM-11.1, PV-4.1/4.2).
pub mod command;

/// Unforgeable actuation capability (CLAIM-11.2, PV-4.3).
pub mod permit;

/// Guard-owned dispatch to the device/driver boundary (CLAIM-11.3).
pub mod device_transport;
pub mod driver_proxy;

/// Unified command admission: the only `ActuationPermit` issuer (13).
pub mod admit;
pub mod commit;
pub mod guard;

/// First-boot device identity generation, replay-safe bootstrap, and scoped
/// token issuance (CLAIM-8.6, PV-3.11).
pub mod enrollment;

pub use enrollment::{
    enrollment_message, DeviceIdentity, EnrolledDevice, EnrollmentRequest, EnrollmentService,
    ENROLLMENT_BOOTSTRAP_CONTEXT,
};

pub use epoch::{
    decommission_message, verify_decommission_credential, CommandEnvelope, DecommissionCredential,
    DeviceEpoch, DeviceEpochStore, EnrollmentNonceStore, EpochBump, EpochCommandGuard, EpochError,
    EpochRegistry, InMemoryEpochStore, InMemoryNonceStore, DEFAULT_ENROLLMENT_NONCE_CAPACITY,
    DEFAULT_ENROLLMENT_NONCE_RETENTION_SECS,
};

pub use admit::{
    admit_stages_0_to_15, AdmitContext, AdmitDecision, AdmitPipelineState, AdmitRejection,
    ChallengeNonce, ChallengeNonceStore, DEFAULT_CHALLENGE_NONCE_TTL_SECS,
    DEFAULT_CHALLENGE_REQUESTS_PER_MINUTE,
};
pub use command::{command_signing_bytes, sign_command, verify_command_signature, CommandError};
pub use commit::{
    coarse_for_rejection, commit_dispatch_finalize, dispatch_and_await, stage17_acceptance,
    stage17_rejection, CoarseRejection, EffectTerminalState, Stage16Error, Stage16Request,
    Stage16Store,
};
pub use device_transport::{DeviceTransport, GuardDeviceTransport};
pub use driver_proxy::{DriverProxy, IngressSource};
pub use guard::{
    single_target_guard, AdmitError, AdmittedCommand, CommandGuard, GuardConfig, TargetAdmission,
};
pub use permit::{ActuationPermit, ActuationPermitRef};
pub use auth_matrix::{
    check_role_authorization, denied_cells, role_index, AuthOperation, MatrixAuthorizationError,
    MatrixCell, MatrixRow, AUTHORIZATION_MATRIX, MATRIX_ROLES,
};
pub use tirbase_types::command::CONTEXT_COMMAND_MESSAGE;

pub use lockdown::{
    apply_crash_decision, apply_lockdown_exit, arm_controller_watchdogs, enter_lockdown,
    CrashLoopEscalation, CrashLoopTracker, InMemoryLockdownStore, LockdownEntryReason,
    LockdownError, LockdownExitPayload, LockdownFileMarker, LockdownStore, SafeDefaultBinding,
    CONTEXT_LOCKDOWN_EXIT, LOCKDOWN_DB_KEY, LOCKDOWN_FILE_PATH,
};
pub use node_mode::{NodeMode, NodeModeState};

pub use trust_root::{
    AuthorizedRoleSigner, ParamFloor, RolePolicy, TrustRootError, TrustRootManager,
    TrustRootRecord, TrustRootSignature,
};

pub use policy::{
    check_tightening_floors, classify_bundle, make_bundle, policy_bundle_body_hash,
    policy_bundle_signing_bytes, verify_policy_cosignature, ActivePolicyState,
    PendingLoosenOperation, PolicyError, PolicyIngestOutcome, PolicyLifecycle,
};
pub use tirbase_types::policy::{PolicyBundle, PolicyBundleKind, PolicyCoSignature};

pub use anti_replay::{
    check_sequence, verify_and_apply_window_reset, AntiReplayDecision, AntiReplayWindow,
    AntiReplayWindowReset, CONTEXT_ANTI_REPLAY_WINDOW_RESET, DEFAULT_FORWARD_GAP_G,
    DEFAULT_WINDOW_W,
};
pub use signed_operation::{
    SignatureEntry, SignedOperation, SignedOperationError, SignedOperationPayload,
    CONTEXT_EPOCH_BUMP, CONTEXT_POLICY_BUNDLE,
};
pub use single_writer_lease::SingleWriterLease;

pub use time::{
    FreshnessState, RatchetAdvance, TimeBeacon, TimeRatchet, TimeRatchetConfig, TimeRatchetError,
    TimeRatchetRecord, TimeRatchetStore, CONTEXT_TIME_BEACON, DEFAULT_MAX_FORWARD_JUMP_SECS,
    DEFAULT_REQUIRED_ANCHOR_SIGNATURES, DEFAULT_STALENESS_WINDOW_SECS,
};

pub use envelope::{
    install_profile, profile_signing_bytes, validate_profile, verify_profile_signature, FieldError,
    ProfileInstallError, ProfileMap,
};
pub use tirbase_types::envelope::{
    ConstraintOperator, DeviceModel, DeviceParameter, EnvelopeProfile, EnvelopeProfileBody,
    LinearConstraint, ParameterKind, ParameterSpec,
};

pub use tirbase_types;
