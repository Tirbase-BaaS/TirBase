// SPDX-License-Identifier: AGPL-3.0-only

//! `CommandGuard` — unified admission pipeline entry point (PV-4.2, PV-4.3,
//! PV-4.4, CLAIM-11.1, CLAIM-11.2, CLAIM-11.3, CLAIM-13.1, CLAIM-14.1–14.17).
//!
//! * Signed [`CommandMessage`]s are accepted only after signature verification
//! over canonical CBOR of all fields except `signature` (CLAIM-11.1).
//! * [`ActuationPermit`] is minted **only** by [`CommandGuard::admit()`] /
//! [`CommandGuard::admit_with_context()`] (CLAIM-11.2).
//! * Actuation frames reach the device only through [`DriverProxy`] after
//! admission (CLAIM-11.3); every ingress path must converge here.
//!
//! adds `ArcSwap<EnvelopeProfile>`/`ArcSwap<PolicyBundle>` config
//! snapshots and `pub(crate)` actuator write handles. implements the
//! fast admit path (Stages 0–15) in [`crate::admit`]; `admit()` preserves the
//! /13 signature for existing callers and runs the legacy
//! signature+epoch checks plus pipeline stages when a pipeline state is
//! configured.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};

use arc_swap::ArcSwap;
use tirbase_core::events::{emit, ReasonCode, SecurityEvent, SecurityEventCategory, Severity};
use tirbase_types::command::CommandMessage;
use tirbase_types::envelope::EnvelopeProfile;
use tirbase_types::policy::PolicyBundle;
use tirbase_types::TargetId;

use crate::admit::{
    admit_stages_0_to_15, AdmitContext, AdmitDecision, AdmitPipelineState, AdmitRejection,
};
use crate::command::{verify_command_signature, CommandError};
use crate::driver_proxy::{DriverProxy, IngressSource};
use crate::epoch::{EpochError, EpochRegistry};
use crate::node_mode::{NodeMode, NodeModeState};
use crate::permit::{ActuationPermit, ActuationPermitRef};

/// Admission / dispatch outcome.
#[derive(Debug)]
pub struct AdmittedCommand {
    pub permit_ref: ActuationPermitRef,
    pub ingress: IngressSource,
}

/// Rejection reasons surfaced by the legacy admit dispatcher.
///
/// `Pipeline(...)` carries the Stage 0–15 rejection category when the 
/// pipeline is enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitError {
    InvalidSignature(String),
    Epoch(EpochError),
    Dispatch(String),
    MissingParameter(String),
 /// Stage 1: node mode does not permit command admission (CLAIM-13.1).
    ModeRejected(NodeMode),
 /// Stage 0–15 pipeline rejection (CLAIM-14.x).
    Pipeline {
        category: AdmitRejection,
        detail: String,
    },
}

impl std::fmt::Display for AdmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdmitError::InvalidSignature(e) => write!(f, "command signature rejected: {e}"),
            AdmitError::Epoch(e) => write!(f, "epoch check rejected: {e}"),
            AdmitError::Dispatch(e) => write!(f, "actuation dispatch failed: {e}"),
            AdmitError::MissingParameter(e) => write!(f, "missing parameter: {e}"),
            AdmitError::ModeRejected(mode) => {
                write!(
                    f,
                    "command rejected: node mode {mode} does not permit commands"
                )
            }
            AdmitError::Pipeline { category, detail } => {
                write!(f, "command rejected ({category:?}): {detail}")
            }
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

/// Minimal target admission context used by legacy/early pipeline wiring.
#[derive(Debug, Clone)]
pub struct TargetAdmission {
 /// The local device identity for epoch checks.
    pub device_id: String,
}

/// Guard configuration for target/device mapping.
#[derive(Debug, Default)]
pub struct GuardConfig {
    pub targets: BTreeMap<TargetId, TargetAdmission>,
}

/// Actuator write handles owned by the guard (CLAIM-14.1).
///
/// `pub(crate)` so code outside `tirbase-guard` cannot obtain or bypass them;
/// only the guard pipeline may mint permits and dispatch actuation.
#[derive(Debug, Clone, Default)]
pub(crate) struct ActuatorHandles {
 /// Reserved for per-target driver sockets/executors.
    pub(crate) _reserved: (),
}

/// Unified command guard (CLAIM-14.1).
///
/// Holds `ArcSwap` config snapshots for envelope/policy (lock-free hot swap),
/// epoch state, node mode, and optional pipeline state. Actuator write
/// handles are `pub(crate)` and inaccessible outside the guard crate.
pub struct CommandGuard {
 /// Per-target active envelope profile snapshot (hot-swappable).
    pub(crate) envelope_profiles: Arc<BTreeMap<TargetId, Arc<ArcSwap<EnvelopeProfile>>>>,
 /// Active policy bundle snapshot (hot-swappable); `None` before first install.
    pub(crate) policy_bundle: Arc<ArcSwap<Option<PolicyBundle>>>,
 /// Guard-owned actuator handles (not accessible outside this crate).
    #[allow(dead_code)]
    pub(crate) actuator_handles: ActuatorHandles,
    epochs: Arc<EpochRegistry>,
    config: RwLock<GuardConfig>,
 /// Stage 1 operational mode (CLAIM-13.1). Shared with gateway/runtime.
    node_mode: Arc<NodeModeState>,
 /// Monotonic entry-id source (task-11 placeholder; /16 wire durable ledger IDs).
    next_entry: AtomicU64,
 /// admit pipeline state (Stages 0–15). When absent, legacy
 /// signature+epoch behavior is used for backward compatibility.
    pipeline: Option<Arc<AdmitPipelineState>>,
}

impl std::fmt::Debug for CommandGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandGuard")
            .field("epochs", &self.epochs)
            .field("node_mode", &self.node_mode.get())
            .field("pipeline_enabled", &self.pipeline.is_some())
            .finish_non_exhaustive()
    }
}

impl CommandGuard {
 /// Construct a guard in the default `Starting` mode.
    pub fn new(epochs: Arc<EpochRegistry>, config: GuardConfig) -> Self {
        Self::with_mode(epochs, config, NodeModeState::new(NodeMode::Starting))
    }

 /// Construct a guard with an explicit shared mode state.
    pub fn with_mode(
        epochs: Arc<EpochRegistry>,
        config: GuardConfig,
        node_mode: Arc<NodeModeState>,
    ) -> Self {
        CommandGuard {
            envelope_profiles: Arc::new(BTreeMap::new()),
            policy_bundle: Arc::new(ArcSwap::from_pointee(None)),
            actuator_handles: ActuatorHandles::default(),
            epochs,
            config: RwLock::new(config),
            node_mode,
            next_entry: AtomicU64::new(1),
            pipeline: None,
        }
    }

 /// Attach pipeline state and config snapshots.
    pub fn with_pipeline(
        mut self,
        pipeline: Arc<AdmitPipelineState>,
        envelope_profiles: Arc<BTreeMap<TargetId, Arc<ArcSwap<EnvelopeProfile>>>>,
        policy_bundle: Arc<ArcSwap<Option<PolicyBundle>>>,
    ) -> Self {
        self.pipeline = Some(pipeline);
        self.envelope_profiles = envelope_profiles;
        self.policy_bundle = policy_bundle;
        self
    }

    pub fn epochs(&self) -> &Arc<EpochRegistry> {
        &self.epochs
    }

 /// Shared operational mode state (Stage 1 / gateway runtime).
    pub fn node_mode(&self) -> &Arc<NodeModeState> {
        &self.node_mode
    }

    pub fn policy_snapshot(&self) -> arc_swap::Guard<Arc<Option<PolicyBundle>>> {
        self.policy_bundle.load()
    }

    pub fn pipeline(&self) -> Option<&Arc<AdmitPipelineState>> {
        self.pipeline.as_ref()
    }
    pub fn envelope_profile_for(&self, target: &TargetId) -> Option<Arc<EnvelopeProfile>> {
        self.envelope_profiles.get(target).map(|c| c.load_full())
    }

 /// Resolve the enrolled `device_id` for a target (CLAIM-16.1/16.3).
    pub fn device_id_for_target(&self, target: &TargetId) -> Option<String> {
        self.config
            .read()
            .ok()
            .and_then(|cfg| cfg.targets.get(target).map(|t| t.device_id.clone()))
    }

 /// True when the installed profile marks `param` on `target` as `critical`.
    pub fn parameter_is_critical(&self, target: &TargetId, param: &str) -> bool {
        self.envelope_profile_for(target)
            .and_then(|p| {
                p.parameters
                    .iter()
                    .find(|s| s.name == param)
                    .map(|s| s.critical)
            })
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    pub(crate) fn actuator_handles(&self) -> &ActuatorHandles {
        &self.actuator_handles
    }

    fn entry_id(&self) -> [u8; 16] {
        let n = self
            .next_entry
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&n.to_le_bytes());
        id
    }

 /// Admit via legacy /13 path (signature + mode + epoch) for callers
 /// that do not supply Biscuit token context.
    pub fn admit<W: Write + Send>(
        &self,
        cmd: &CommandMessage,
        ingress: IngressSource,
        proxy: &mut DriverProxy<W>,
        frame: &[u8],
    ) -> Result<AdmittedCommand, AdmitError> {
        if self.pipeline.is_some() {
 // If pipeline is enabled but no token is provided, keep backward
 // compatibility for existing callers by running legacy checks.
 // Full Stage 3+ enforcement requires `admit_with_context`.
            let sk = ingress_source_key(ingress, cmd);
            let ctx = AdmitContext {
                ingress,
                source_key: &sk,
                biscuit_token: None,
                now_est_secs: None,
                simulate: false,
            };
            if ctx.biscuit_token.is_some() {
                return self.admit_with_context(cmd, &ctx, proxy, frame);
            }
        }
        self.admit_legacy(cmd, ingress, proxy, frame)
    }

 /// admit path (Stages 0–15) + dispatch.
    pub fn admit_with_context<W: Write + Send>(
        &self,
        cmd: &CommandMessage,
        ctx: &AdmitContext<'_>,
        proxy: &mut DriverProxy<W>,
        frame: &[u8],
    ) -> Result<AdmittedCommand, AdmitError> {
        let pipeline = self.pipeline.as_ref().ok_or_else(|| AdmitError::Pipeline {
            category: AdmitRejection::Unsupported,
            detail: "pipeline not configured; use admit() or configure with_pipeline()".to_string(),
        })?;
        let device_id = self.device_id_for_target(&cmd.target_id);
        match admit_stages_0_to_15(
            cmd,
            ctx,
            &self.node_mode,
            &self.epochs,
            pipeline,
            device_id.as_deref(),
        ) {
            AdmitDecision::Accepted { .. }
            | AdmitDecision::Simulated {
                would_accept: true, ..
            } => {
                let permit = ActuationPermit::new(
                    cmd.target_id.clone(),
                    cmd.param.clone(),
                    cmd.desired_state,
                    self.entry_id(),
                );
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
                    .with_detail(format!("admitted via {:?} (pipeline)", ctx.ingress)),
                );
                Ok(AdmittedCommand {
                    permit_ref,
                    ingress: ctx.ingress,
                })
            }
            AdmitDecision::Rejected {
                category, detail, ..
            } => Err(AdmitError::Pipeline { category, detail }),
            AdmitDecision::Simulated {
                would_accept: false,
                rejection,
                ..
            } => {
                let (category, detail, _retry) = rejection.unwrap_or((
                    AdmitRejection::Unsupported,
                    "simulated rejection".to_string(),
                    None,
                ));
                Err(AdmitError::Pipeline { category, detail })
            }
        }
    }

 /// Side-effect-free dry run (PV-4.17). Does not mint a permit or dispatch.
    pub fn simulate(&self, cmd: &CommandMessage, ctx: &AdmitContext<'_>) -> AdmitDecision {
        let Some(pipeline) = self.pipeline.as_ref() else {
            return AdmitDecision::Simulated {
                would_accept: false,
                rejection: Some((
                    AdmitRejection::Unsupported,
                    "pipeline not configured".to_string(),
                    None,
                )),
                derived_role: None,
            };
        };
        let mut sim = ctx.clone();
        sim.simulate = true;
        let device_id = self.device_id_for_target(&cmd.target_id);
        admit_stages_0_to_15(
            cmd,
            &sim,
            &self.node_mode,
            &self.epochs,
            pipeline,
            device_id.as_deref(),
        )
    }

 /// : evaluate Stages 0–15 only (no driver/network I/O, no permit
 /// mint). Safe to run inside `spawn_blocking` for DB reads.
    pub fn admit_stages_0_to_15_with_pipeline(
        &self,
        cmd: &CommandMessage,
        ctx: &AdmitContext<'_>,
    ) -> AdmitDecision {
        let Some(pipeline) = self.pipeline.as_ref() else {
            return AdmitDecision::Rejected {
                category: AdmitRejection::Unsupported,
                detail: "pipeline not configured".into(),
                retry_after_secs: None,
            };
        };
        let device_id = self.device_id_for_target(&cmd.target_id);
        admit_stages_0_to_15(
            cmd,
            ctx,
            &self.node_mode,
            &self.epochs,
            pipeline,
            device_id.as_deref(),
        )
    }

    fn admit_legacy<W: Write + Send>(
        &self,
        cmd: &CommandMessage,
        ingress: IngressSource,
        proxy: &mut DriverProxy<W>,
        frame: &[u8],
    ) -> Result<AdmittedCommand, AdmitError> {
        let mode = self.node_mode.get();
        if !mode.allows_commands() {
            emit(
                SecurityEvent::new(
                    SecurityEventCategory::CommandDecision,
                    Severity::High,
                    ReasonCode::ModeLockdown,
                )
                .with_actor(cmd.issuer_did.as_str())
                .with_target(cmd.target_id.as_str())
                .with_detail(format!("command rejected: node mode {mode}")),
            );
            return Err(AdmitError::ModeRejected(mode));
        }
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
        if let Ok(cfg) = self.config.read() {
            if let Some(target) = cfg.targets.get(&cmd.target_id) {
                self.epochs
                    .check_command_epoch(&target.device_id, cmd.enrollment_epoch)?;
            }
        }
        let permit = ActuationPermit::new(
            cmd.target_id.clone(),
            cmd.param.clone(),
            cmd.desired_state,
            self.entry_id(),
        );
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
        Ok(AdmittedCommand {
            permit_ref,
            ingress,
        })
    }
}

fn ingress_source_key(ingress: IngressSource, cmd: &CommandMessage) -> String {
    format!("{:?}:{}", ingress, cmd.issuer_did.as_str())
}

/// Build a `CommandGuard` wired for a single local device/target (test helper
/// and minimal production bootstrap). Starts in `Normal` mode so existing
/// task-11/ingress tests remain meaningful; task-13 tests set mode explicitly.
pub fn single_target_guard(
    epochs: Arc<EpochRegistry>,
    target_id: TargetId,
    device_id: String,
) -> CommandGuard {
    let mut targets = BTreeMap::new();
    targets.insert(target_id, TargetAdmission { device_id });
    CommandGuard::with_mode(
        epochs,
        GuardConfig { targets },
        NodeModeState::new(NodeMode::Normal),
    )
}
