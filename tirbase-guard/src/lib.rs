//! TirBase Command Guard crate.
//! Provides the CommandGuard, EnvelopeProfile, PolicyLifecycle,
//! AppliedEffectsLedger, AntiReplayWindow, SingleWriterLease,
//! TimeRatchet, ActuationPermit, and SecurityEventLog.
//! Full implementation in tasks 7–16.

#![forbid(unsafe_code)]
// Warn on dead private code across this crate. `pub` items are naturally exempt
// (the Rust dead_code lint does not fire on reachable public items).
#![warn(dead_code)]

pub mod signed_operation;

/// Policy lifecycle: bundle types (wire), 11-criterion tightening classification,
/// tightening-floor enforcement, loosening M-of-N/timelock path, anti-rollback,
/// and pending-approval accumulation (tasks 12.1–12.10 — CLAIM-12.1…12.10).
pub mod policy;

/// `TimeRatchet`, authenticated-time estimate, and freshness state
/// (tasks 7.2–7.5 — CLAIM-7.2…7.5, PV-22).
pub mod time;

/// Node operational mode and mode × operation matrix (task 13.1 —
/// CLAIM-13.1, PV-4.13).
pub mod node_mode;

/// LOCKDOWN entry/exit, persistence, crash-loop escalation, and safe-default
/// arming (tasks 13.2, 13.3, 13.5, 13.6 — CLAIM-13.2/3/5/6, PV-4.13, PV-4.15).
pub mod lockdown;

/// Envelope profile install/validation and target-to-profile hot-swap
/// (tasks 10.4–10.6 — CLAIM-10.4…10.6, PV-4.5).
pub mod envelope;

/// Trust root record and per-role registry (tasks 8.3/8.3a — CLAIM-8.3,
/// CLAIM-8.3a, PV-3.2, PV-3.3, PV-3.4).
pub mod trust_root;

/// Per-device enrollment epoch, nonce store, and Stage 8 guard check (tasks
/// 8.5–8.8 — CLAIM-8.5…CLAIM-8.8, PV-3.11, PV-3.13, PV-5.5, PV-9.8).
pub mod epoch;

/// `CommandMessage` signing/verification (task 11.1, CLAIM-11.1, PV-4.1/4.2).
pub mod command;

/// Unforgeable actuation capability (task 11.2, CLAIM-11.2, PV-4.3).
pub mod permit;

/// Guard-owned dispatch to the device/driver boundary (task 11.3, CLAIM-11.3).
pub mod driver_proxy;

/// Unified command admission: the only `ActuationPermit` issuer (tasks 11/13).
pub mod admit;
pub mod commit;
pub mod guard;

/// First-boot device identity generation, replay-safe bootstrap, and scoped
/// token issuance (task 8.6 — CLAIM-8.6, PV-3.11).
pub mod enrollment;

pub use enrollment::{
    enrollment_message, DeviceIdentity, EnrolledDevice, EnrollmentRequest, EnrollmentService,
    ENROLLMENT_BOOTSTRAP_CONTEXT,
};

pub use epoch::{
    decommission_message, verify_decommission_credential, CommandEnvelope, EpochCommandGuard,
    DecommissionCredential, DeviceEpoch, DeviceEpochStore, EnrollmentNonceStore, EpochBump,
    EpochError, EpochRegistry, InMemoryEpochStore, InMemoryNonceStore,
    DEFAULT_ENROLLMENT_NONCE_CAPACITY, DEFAULT_ENROLLMENT_NONCE_RETENTION_SECS,
};

pub use command::{
    command_signing_bytes, sign_command, verify_command_signature, CommandError,
};
pub use tirbase_types::command::CONTEXT_COMMAND_MESSAGE;
pub use driver_proxy::{DriverProxy, IngressSource};
pub use guard::{single_target_guard, AdmitError, AdmittedCommand, CommandGuard, GuardConfig, TargetAdmission};
pub use admit::{AdmitContext, AdmitDecision, AdmitPipelineState, AdmitRejection, admit_stages_0_to_15};
pub use permit::{ActuationPermit, ActuationPermitRef};
pub use commit::{
    coarse_for_rejection, commit_dispatch_finalize, dispatch_and_await, stage17_acceptance,
    stage17_rejection, CoarseRejection, EffectTerminalState, Stage16Error, Stage16Request,
    Stage16Store,
};

pub use node_mode::{NodeMode, NodeModeState};
pub use lockdown::{
    arm_controller_watchdogs, apply_crash_decision, apply_lockdown_exit, enter_lockdown,
    CrashLoopEscalation, CrashLoopTracker, InMemoryLockdownStore, LockdownEntryReason,
    LockdownError, LockdownExitPayload, LockdownFileMarker, LockdownStore, SafeDefaultBinding,
    CONTEXT_LOCKDOWN_EXIT, LOCKDOWN_DB_KEY, LOCKDOWN_FILE_PATH,
};

pub use trust_root::{
    AuthorizedRoleSigner, ParamFloor, RolePolicy, TrustRootError, TrustRootManager,
    TrustRootRecord, TrustRootSignature,
};

pub use policy::{
    check_tightening_floors, classify_bundle, make_bundle, policy_bundle_body_hash,
    policy_bundle_signing_bytes, verify_policy_cosignature, ActivePolicyState, PendingLoosenOperation,
    PolicyError, PolicyIngestOutcome, PolicyLifecycle,
};
pub use tirbase_types::policy::{PolicyBundle, PolicyBundleKind, PolicyCoSignature};

pub use signed_operation::{
    SignatureEntry, SignedOperation, SignedOperationError, SignedOperationPayload,
    CONTEXT_EPOCH_BUMP, CONTEXT_POLICY_BUNDLE,
};

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
