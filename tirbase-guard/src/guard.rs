//! `CommandGuard` — unified admission pipeline entry point (PV-4.2, PV-4.3,
//! PV-4.4, CLAIM-11.1, CLAIM-11.2, CLAIM-11.3).
//!
//! Task 11 wires the structural invariants required by the spec:
//! * signed [`CommandMessage`]s are accepted only after signature verification
//!   over canonical CBOR of all fields except `signature` (CLAIM-11.1);
//! * [`ActuationPermit`] is minted **only** by [`CommandGuard::admit()`]
//!   (CLAIM-11.2);
//! * actuation frames reach the device only through [`DriverProxy`] after
//!   `admit()` (CLAIM-11.3); every ingress path must converge here.
//!
//! The full 19-stage pipeline (token binding, replay, envelope, lease, ledger,
//! etc.) is implemented incrementally by tasks 13–16.  This module provides the
//! task-11 admission core and the ingress-convergence helpers those later
//! stages extend.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, RwLock};

use tirbase_core::events::{emit, ReasonCode, SecurityEvent, SecurityEventCategory, Severity};
use tirbase_types::command::CommandMessage;
use tirbase_types::TargetId;

use crate::command::{verify_command_signature, CommandError};
use crate::driver_proxy::{DriverProxy, IngressSource};
use crate::epoch::{EpochError, EpochRegistry};
use crate::permit::{ActuationPermit, ActuationPermitRef};

/// Admission / dispatch outcome.
#[derive(Debug)]
pub struct AdmittedCommand {
    pub permit_ref: ActuationPermitRef,
    pub ingress: IngressSource,
}

/// Rejection reasons surfaced by the task-11 guard core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitError {
    InvalidSignature(String),
    Epoch(EpochError),
    Dispatch(String),
    MissingParameter(String),
}

impl std::fmt::Display for AdmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdmitError::InvalidSignature(e) => write!(f, "command signature rejected: {e}"),
            AdmitError::Epoch(e) => write!(f, "epoch check rejected: {e}"),
            AdmitError::Dispatch(e) => write!(f, "actuation dispatch failed: {e}"),
            AdmitError::MissingParameter(e) => write!(f, "missing parameter: {e}"),
        }
    }
}

impl std::error::Error for AdmitError {}

impl From<CommandError> for AdmitError {
    fn from(e: CommandError) -> Self {
        AdmitError::InvalidSignature(e.to_string())
    }
}

impl From<EpochError> for AdmitError {
    fn from(e: EpochError) -> Self {
        AdmitError::Epoch(e)
    }
}

/// Minimal target admission context used by task 11.  Later tasks replace the
/// ad-hoc frame encoder with the driver codec and extend checks.
#[derive(Debug, Clone)]
pub struct TargetAdmission {
    /// The local device identity for epoch checks.
    pub device_id: String,
}

/// Guard configuration for task-11 admission.
#[derive(Debug, Default)]
pub struct GuardConfig {
    pub targets: BTreeMap<TargetId, TargetAdmission>,
}

/// Unified command guard.
///
/// Holds shared epoch state (reusing task 8's [`EpochRegistry`]) and exposes
/// the single [`CommandGuard::admit`] entry point that all ingress handlers
/// must call.  `admit()` is the **only** code path that mints an
/// [`ActuationPermit`].
pub struct CommandGuard {
    epochs: Arc<EpochRegistry>,
    config: RwLock<GuardConfig>,
    /// Monotonic entry-id source (task-11 placeholder; task 14/16 wire the
    /// durable effects ledger entry id).
    next_entry: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for CommandGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandGuard")
            .field("epochs", &self.epochs)
            .finish_non_exhaustive()
    }
}

impl CommandGuard {
    pub fn new(epochs: Arc<EpochRegistry>, config: GuardConfig) -> Self {
        CommandGuard {
            epochs,
            config: RwLock::new(config),
            next_entry: std::sync::atomic::AtomicU64::new(1),
        }
    }

    pub fn epochs(&self) -> &Arc<EpochRegistry> {
        &self.epochs
    }

    fn entry_id(&self) -> [u8; 16] {
        let n = self
            .next_entry
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&n.to_le_bytes());
        id
    }

    /// Admit `cmd` and, on success, dispatch it through `proxy`.
    ///
    /// This is the **only** production constructor path for
    /// [`ActuationPermit`].  Bypassing `admit()` cannot produce a permit
    /// because [`ActuationPermit::new`] is `pub(crate)` and the type is sealed.
    pub fn admit<W: Write + Send>(
        &self,
        cmd: &CommandMessage,
        ingress: IngressSource,
        proxy: &mut DriverProxy<W>,
        frame: &[u8],
    ) -> Result<AdmittedCommand, AdmitError> {
        // 1. Signature verification (CLAIM-11.1, PV-4.2).  Unsigned / invalid
        //    signatures are rejected before any stateful checks.
        if let Err(e) = verify_command_signature(cmd) {
            emit(
                SecurityEvent::new(
                    SecurityEventCategory::CommandDecision,
                    Severity::Medium,
                    ReasonCode::CommandSignatureInvalid,
                )
                .with_actor(cmd.issuer_did.as_str())
                .with_target(cmd.target_id.as_str())
                .with_detail(format!("command signature rejected: {e}")),
            );
            return Err(AdmitError::InvalidSignature(e.to_string()));
        }

        // 2. Stage 8 epoch check (task 8.7, preserved).  The target's local
        //    device identity is looked up from config; if absent we still verify
        //    the signature but cannot perform the epoch gate (later tasks require
        //    a profile/target binding).
        if let Ok(cfg) = self.config.read() {
            if let Some(target) = cfg.targets.get(&cmd.target_id) {
                self.epochs
                    .check_command_epoch(&target.device_id, cmd.enrollment_epoch)?;
            }
        }

        // 3. Mint permit (CLAIM-11.2) — only here.
        let permit = ActuationPermit::new(
            cmd.target_id.clone(),
            cmd.param.clone(),
            cmd.desired_state,
            self.entry_id(),
        );

        // 4. Dispatch through DriverProxy (CLAIM-11.3).  The permit is consumed.
        let permit_ref = proxy
            .dispatch(permit, frame)
            .map_err(|e| AdmitError::Dispatch(e.to_string()))?;

        emit(
            SecurityEvent::new(
                SecurityEventCategory::CommandDecision,
                Severity::Low,
                ReasonCode::CommandAccepted,
            )
            .with_actor(cmd.issuer_did.as_str())
            .with_target(cmd.target_id.as_str())
            .with_detail(format!("admitted via {:?}", ingress)),
        );

        Ok(AdmittedCommand { permit_ref, ingress })
    }
}

/// Build a `CommandGuard` wired for a single local device/target (test helper
/// and minimal production bootstrap).
pub fn single_target_guard(
    epochs: Arc<EpochRegistry>,
    target_id: TargetId,
    device_id: String,
) -> CommandGuard {
    let mut targets = BTreeMap::new();
    targets.insert(target_id, TargetAdmission { device_id });
    CommandGuard::new(epochs, GuardConfig { targets })
}
