//! LOCKDOWN entry/exit, persistence, crash-loop escalation, and safe-default
//! arming (tasks 13.2, 13.3, 13.5, 13.6 — CLAIM-13.2/3/5/6, PV-1.11, PV-4.13,
//! PV-4.15, INV-5, S24).

use std::fmt;
use std::fs;
use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tirbase_core::events::{emit, ReasonCode, SecurityEvent, SecurityEventCategory, Severity};
use tirbase_types::envelope::EnvelopeProfile;
use tirbase_types::CommandRole;

use crate::node_mode::{NodeMode, NodeModeState};
use crate::signed_operation::{SignedOperation, SignedOperationError, SignedOperationPayload};
use crate::trust_root::{TrustRootError, TrustRootRecord};

pub const LOCKDOWN_DB_KEY: &str = "lockdown_state";
pub const LOCKDOWN_FILE_PATH: &str = "/var/lib/tirbase/lockdown";
pub use crate::signed_operation::CONTEXT_LOCKDOWN_EXIT;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockdownEntryReason {
    GuardDecision,
    CrashLoopEscalation,
    CounterRegression,
}

impl LockdownEntryReason {
    pub fn as_str(self) -> &'static str {
        match self {
            LockdownEntryReason::GuardDecision => "guard_decision",
            LockdownEntryReason::CrashLoopEscalation => "crash_loop_escalation",
            LockdownEntryReason::CounterRegression => "counter_regression",
        }
    }
}

#[derive(Debug)]
pub enum LockdownError {
    Store(String),
    Io(io::Error),
    SignedOperation(SignedOperationError),
    TrustRoot(TrustRootError),
    InsufficientDistinctRoles { got: usize, need: usize },
    MissingEnvelopeProfile,
}

impl fmt::Display for LockdownError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockdownError::Store(e) => write!(f, "lockdown persistence failed: {e}"),
            LockdownError::Io(e) => write!(f, "lockdown file persistence failed: {e}"),
            LockdownError::SignedOperation(e) => write!(f, "lockdown-exit signature rejected: {e}"),
            LockdownError::TrustRoot(e) => write!(f, "lockdown-exit authorization rejected: {e}"),
            LockdownError::InsufficientDistinctRoles { got, need } => write!(
                f,
                "lockdown-exit requires co-signatures from >= {need} distinct roles (got {got})"
            ),
            LockdownError::MissingEnvelopeProfile => {
                write!(
                    f,
                    "lockdown-exit requires a full EnvelopeProfile matching the payload"
                )
            }
        }
    }
}

impl std::error::Error for LockdownError {}
impl From<SignedOperationError> for LockdownError {
    fn from(e: SignedOperationError) -> Self {
        LockdownError::SignedOperation(e)
    }
}
impl From<TrustRootError> for LockdownError {
    fn from(e: TrustRootError) -> Self {
        LockdownError::TrustRoot(e)
    }
}

/// Durable LOCKDOWN persistence.  Production implementation persists to
/// `primary.db` `monotonic_counters(lockdown_state)` AND a secondary file
/// indicator (CLAIM-13.2).  `/run` must never be the sole persistence.
pub trait LockdownStore: Send + Sync + fmt::Debug {
    fn set_lockdown(&self, reason: LockdownEntryReason) -> Result<(), LockdownError>;
    fn clear_lockdown(&self) -> Result<(), LockdownError>;
    fn is_lockdown(&self) -> Result<bool, LockdownError>;
}

/// Secondary file indicator helper (best-effort companion to DB persistence).
#[derive(Debug, Clone)]
pub struct LockdownFileMarker {
    path: PathBuf,
}

impl LockdownFileMarker {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        LockdownFileMarker { path: path.into() }
    }
    pub fn default_path() -> Self {
        Self::new(LOCKDOWN_FILE_PATH)
    }
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
    pub fn write(&self, reason: LockdownEntryReason) -> Result<(), LockdownError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(LockdownError::Io)?;
            }
        }
        fs::write(
            &self.path,
            format!("lockdown_state=1\nreason={}\n", reason.as_str()),
        )
        .map_err(LockdownError::Io)
    }
    pub fn remove(&self) -> Result<(), LockdownError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(LockdownError::Io(e)),
        }
    }
    pub fn exists(&self) -> bool {
        self.path.exists()
    }
}

/// In-memory store for tests/sim; production uses a DB-backed implementation.
#[derive(Debug, Default)]
pub struct InMemoryLockdownStore {
    locked: std::sync::atomic::AtomicBool,
    marker: Option<LockdownFileMarker>,
}

impl InMemoryLockdownStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_marker(marker: LockdownFileMarker) -> Self {
        InMemoryLockdownStore {
            locked: std::sync::atomic::AtomicBool::new(false),
            marker: Some(marker),
        }
    }
}

impl LockdownStore for InMemoryLockdownStore {
    fn set_lockdown(&self, reason: LockdownEntryReason) -> Result<(), LockdownError> {
        self.locked.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(m) = &self.marker {
            m.write(reason)?;
        }
        Ok(())
    }
    fn clear_lockdown(&self) -> Result<(), LockdownError> {
        self.locked
            .store(false, std::sync::atomic::Ordering::SeqCst);
        if let Some(m) = &self.marker {
            m.remove()?;
        }
        Ok(())
    }
    fn is_lockdown(&self) -> Result<bool, LockdownError> {
        Ok(self.locked.load(std::sync::atomic::Ordering::SeqCst))
    }
}

pub fn enter_lockdown(
    store: &dyn LockdownStore,
    mode: &NodeModeState,
    reason: LockdownEntryReason,
) -> Result<(), LockdownError> {
    store.set_lockdown(reason)?;
    mode.set(NodeMode::Lockdown);
    emit(
        SecurityEvent::new(
            SecurityEventCategory::ModeTransition,
            Severity::Critical,
            ReasonCode::EnteredLockdown,
        )
        .with_detail(format!("LOCKDOWN entered ({}), persisted", reason.as_str())),
    );
    Ok(())
}

/// Signed `LockdownExit` payload (context `TirBase/v1/LockdownExit`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockdownExitPayload {
    pub node_id: String,
    pub issued_at_est: i64,
    pub reason: String,
    pub envelope_profile_id: [u8; 16],
}

impl SignedOperationPayload for LockdownExitPayload {
    const CONTEXT: &'static str = crate::signed_operation::CONTEXT_LOCKDOWN_EXIT;
}

/// Verify and apply LOCKDOWN exit (CLAIM-13.3, PV-4.13).
pub fn apply_lockdown_exit(
    operation: &SignedOperation<LockdownExitPayload>,
    payload: &LockdownExitPayload,
    trust_root: &TrustRootRecord,
    envelope_profile: Option<&EnvelopeProfile>,
    store: &dyn LockdownStore,
    mode: &NodeModeState,
) -> Result<(), LockdownError> {
    let profile = envelope_profile.ok_or_else(|| {
        emit(
            SecurityEvent::new(
                SecurityEventCategory::ModeTransition,
                Severity::High,
                ReasonCode::LockdownExitRejected,
            )
            .with_detail("lockdown-exit rejected: full EnvelopeProfile required"),
        );
        LockdownError::MissingEnvelopeProfile
    })?;
    if profile.profile_id != payload.envelope_profile_id {
        emit(
            SecurityEvent::new(
                SecurityEventCategory::ModeTransition,
                Severity::High,
                ReasonCode::LockdownExitRejected,
            )
            .with_detail("lockdown-exit rejected: envelope profile id mismatch"),
        );
        return Err(LockdownError::MissingEnvelopeProfile);
    }

    let resolve = |did: &str| {
        for role in [
            CommandRole::PolicyAuthority,
            CommandRole::RevocationManager,
            CommandRole::UpdateSigner,
            CommandRole::CommandIssuer,
            CommandRole::Auditor,
            CommandRole::TimeAnchor,
        ] {
            if let Some(policy) = trust_root.role_policy(role) {
                if let Some(pk) = policy.public_key_for(did) {
                    return Some(pk.to_vec());
                }
            }
        }
        None
    };
    if let Err(e) = operation.verify(payload, resolve) {
        emit(
            SecurityEvent::new(
                SecurityEventCategory::ModeTransition,
                Severity::High,
                ReasonCode::LockdownExitRejected,
            )
            .with_detail(format!("lockdown-exit rejected: {e}")),
        );
        return Err(e.into());
    }

    let mut distinct_roles: Vec<CommandRole> = Vec::new();
    let message = operation.signing_bytes();
    for entry in &operation.signatures {
        if let Err(e) = trust_root.verify_role_cosignature(
            entry.role,
            &entry.signer_did,
            &message,
            &entry.signature,
        ) {
            emit(
                SecurityEvent::new(
                    SecurityEventCategory::ModeTransition,
                    Severity::High,
                    ReasonCode::LockdownExitRejected,
                )
                .with_detail(format!("lockdown-exit role/signature rejected: {e}")),
            );
            return Err(e.into());
        }
        if !distinct_roles.contains(&entry.role) {
            distinct_roles.push(entry.role);
        }
    }
    if distinct_roles.len() < 2 {
        let err = LockdownError::InsufficientDistinctRoles {
            got: distinct_roles.len(),
            need: 2,
        };
        emit(
            SecurityEvent::new(
                SecurityEventCategory::ModeTransition,
                Severity::High,
                ReasonCode::LockdownExitRejected,
            )
            .with_detail(err.to_string()),
        );
        return Err(err);
    }

    store.clear_lockdown()?;
    mode.set(NodeMode::Normal);
    emit(
        SecurityEvent::new(
            SecurityEventCategory::ModeTransition,
            Severity::High,
            ReasonCode::LockdownExitApplied,
        )
        .with_detail(format!(
            "LOCKDOWN exited for {} ({} distinct roles, profile {:?})",
            payload.node_id,
            distinct_roles.len(),
            profile.profile_id
        )),
    );
    Ok(())
}

// ─── Crash-loop escalation (CLAIM-13.6, S24) ───────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashLoopEscalation {
    RestartNormal { crashes_in_window: usize },
    EscalateLockdown { crashes_in_window: usize },
}

#[derive(Debug, Clone)]
pub struct CrashLoopTracker {
    pub threshold_n: usize,
    pub window_secs: u64,
    crashes: Vec<u64>,
}

impl CrashLoopTracker {
    pub fn new_default() -> Self {
        Self::new(3, 300)
    }
    pub fn new(threshold_n: usize, window_secs: u64) -> Self {
        CrashLoopTracker {
            threshold_n: threshold_n.max(1),
            window_secs,
            crashes: Vec::new(),
        }
    }
    pub fn record_crash(&mut self, now_mono_secs: u64) -> CrashLoopEscalation {
        self.crashes.push(now_mono_secs);
        let cutoff = now_mono_secs.saturating_sub(self.window_secs);
        self.crashes.retain(|t| *t >= cutoff);
        let count = self.crashes.len();
        if count >= self.threshold_n {
            emit(
                SecurityEvent::new(
                    SecurityEventCategory::ModeTransition,
                    Severity::Critical,
                    ReasonCode::CrashLoopEscalation,
                )
                .with_detail(format!(
                    "{count} crashes within {}s (threshold {}) -> LOCKDOWN",
                    self.window_secs, self.threshold_n
                )),
            );
            CrashLoopEscalation::EscalateLockdown {
                crashes_in_window: count,
            }
        } else {
            CrashLoopEscalation::RestartNormal {
                crashes_in_window: count,
            }
        }
    }
    pub fn crashes_in_window(&self, now_mono_secs: u64) -> usize {
        let cutoff = now_mono_secs.saturating_sub(self.window_secs);
        self.crashes.iter().filter(|t| **t >= cutoff).count()
    }
}

/// Apply crash-loop decision: restart to Normal (no lockdown) or escalate.
pub fn apply_crash_decision(
    decision: CrashLoopEscalation,
    store: &dyn LockdownStore,
    mode: &NodeModeState,
) -> Result<(), LockdownError> {
    match decision {
        CrashLoopEscalation::RestartNormal { .. } => {
            mode.set(NodeMode::Normal);
            Ok(())
        }
        CrashLoopEscalation::EscalateLockdown { .. } => {
            enter_lockdown(store, mode, LockdownEntryReason::CrashLoopEscalation)
        }
    }
}

// ─── Safe-default enforcement (CLAIM-13.5, PV-4.15, PV-23.1) ───────────────
// Option (a): proactively program controller fallback/watchdog registers while
// the guard is healthy so the controller self-reverts on loss of command.
// ExecStopPost= cannot drive safe defaults because driver children die with the
// guard.  See docs/safe-default-guard-death.md.

pub trait SafeDefaultBinding: Send + Sync + fmt::Debug {
    fn controller_id(&self) -> &str;
    fn arm_watchdog(&self, timeout_secs: u32, safe_default: &str) -> Result<(), String>;
    fn refresh_watchdog(&self) -> Result<(), String>;
    fn current_value(&self) -> String;
}

pub fn arm_controller_watchdogs(
    bindings: &[&dyn SafeDefaultBinding],
    timeout_secs: u32,
    safe_default: &str,
) -> Result<(), String> {
    for b in bindings {
        b.arm_watchdog(timeout_secs, safe_default).map_err(|e| {
            format!(
                "failed to arm safe-default watchdog for {}: {e}",
                b.controller_id()
            )
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    #[derive(Debug)]
    struct MemBinding {
        id: String,
        armed: AtomicBool,
        value: Mutex<String>,
        safe: Mutex<String>,
    }
    impl MemBinding {
        fn new(id: &str, initial: &str) -> Self {
            MemBinding {
                id: id.into(),
                armed: AtomicBool::new(false),
                value: Mutex::new(initial.into()),
                safe: Mutex::new(String::new()),
            }
        }
        fn simulate_guard_death(&self) {
            if self.armed.load(Ordering::SeqCst) {
                *self.value.lock().unwrap() = self.safe.lock().unwrap().clone();
            }
        }
    }
    impl SafeDefaultBinding for MemBinding {
        fn controller_id(&self) -> &str {
            &self.id
        }
        fn arm_watchdog(&self, _timeout_secs: u32, safe_default: &str) -> Result<(), String> {
            *self.safe.lock().unwrap() = safe_default.to_string();
            self.armed.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn refresh_watchdog(&self) -> Result<(), String> {
            Ok(())
        }
        fn current_value(&self) -> String {
            self.value.lock().unwrap().clone()
        }
    }

    #[test]
    fn option_a_watchdog_reverts_controller_on_guard_death() {
        let c = MemBinding::new("chiller-1", "commanded:18C");
        arm_controller_watchdogs(&[&c as &dyn SafeDefaultBinding], 5, "safe:22C").unwrap();
        c.simulate_guard_death();
        assert_eq!(c.current_value(), "safe:22C");
    }

    #[test]
    fn crash_loop_escalates_after_n_crashes_in_window() {
        let mut t = CrashLoopTracker::new(3, 300);
        assert!(matches!(
            t.record_crash(100),
            CrashLoopEscalation::RestartNormal { .. }
        ));
        assert!(matches!(
            t.record_crash(200),
            CrashLoopEscalation::RestartNormal { .. }
        ));
        assert!(matches!(
            t.record_crash(250),
            CrashLoopEscalation::EscalateLockdown {
                crashes_in_window: 3
            }
        ));
    }

    #[test]
    fn crash_loop_restarts_to_normal_when_outside_window() {
        let mut t = CrashLoopTracker::new(3, 300);
        t.record_crash(0);
        t.record_crash(100);
        assert!(matches!(
            t.record_crash(400),
            CrashLoopEscalation::RestartNormal {
                crashes_in_window: 2
            }
        ));
    }
}
