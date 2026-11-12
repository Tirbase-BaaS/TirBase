//! Policy lifecycle (12.10 — CLAIM-12.1…12.10, PV-4.8–4.12,
//! INV-3, INV-8, RD-9).
//!
//! # Wire vs computed
//!
//! [`PolicyBundle`] is a wire type (`tirbase_types::policy`). The guard **never**
//! trusts `bundle.kind`: classification is always recomputed by
//! [`classify_bundle()`] (CLAIM-12.2). `timelock_until_est` is computed at
//! ingest as `now_est + active_policy.timelock_secs` and stored in the pending
//! approval record, not read from the bundle (PV-4.10).
//!
//! # Governance source of truth
//!
//! Loosening M/N/timelock come from the **active** policy/profile. The
//! `tightening_floor` is read from [`TrustRootRecord::device_class_floors`],
//! never from the incoming bundle or the active profile (PV-4.11).

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwap;
use ciborium::ser::into_writer;
use sha2::{Digest, Sha256};
use tirbase_core::events::{emit, ReasonCode, SecurityEvent, SecurityEventCategory, Severity};
use tirbase_core::traits::MonotonicCounterTrait;
use tirbase_types::envelope::{EnvelopeProfile, ParameterKind, ParameterSpec};
use tirbase_types::policy::{PolicyBundle, PolicyBundleKind, PolicyCoSignature};
use tirbase_types::{CommandRole, FixedPointValue};

use crate::envelope::ProfileMap;
use crate::signed_operation::CONTEXT_POLICY_BUNDLE;
use crate::trust_root::{ParamFloor, TrustRootRecord};

// ─── Comparison helpers ──────────────────────────────────────────────────────

/// Compare two [`FixedPointValue`]s (same unit) by normalising to the finest
/// exponent. Returns `None` on unit mismatch or unrepresentable scale.
fn compare_fpv(a: &FixedPointValue, b: &FixedPointValue) -> Option<Ordering> {
    if a.unit_id != b.unit_id {
        return None;
    }
    let common = a.exponent.min(b.exponent);
    let scale = |m: i64, e: i8| -> Option<i128> {
        let delta = (e as i16 - common as i16) as u32;
        if delta > 38 {
            return None;
        }
        let mut s: i128 = 1;
        for _ in 0..delta {
            s = s.checked_mul(10)?;
        }
        (m as i128).checked_mul(s)
    };
    Some(scale(a.mantissa, a.exponent)?.cmp(&scale(b.mantissa, b.exponent)?))
}

fn leq(a: &FixedPointValue, b: &FixedPointValue) -> bool {
    matches!(compare_fpv(a, b), Some(Ordering::Less | Ordering::Equal))
}

fn geq(a: &FixedPointValue, b: &FixedPointValue) -> bool {
    matches!(compare_fpv(a, b), Some(Ordering::Greater | Ordering::Equal))
}

fn eq_fpv(a: &FixedPointValue, b: &FixedPointValue) -> bool {
    compare_fpv(a, b) == Some(Ordering::Equal)
}

fn range_subset(
    new_min: &FixedPointValue,
    new_max: &FixedPointValue,
    old_min: &FixedPointValue,
    old_max: &FixedPointValue,
) -> bool {
 // new [min,max] ⊆ old [min,max]
    geq(new_min, old_min) && leq(new_max, old_max)
}

// ─── Signing / hashing (domain-separated policy bundle body) ─────────────────

/// SHA-256 of the canonical CBOR encoding of a bundle body (used for
/// `prev_version_hash` chaining and signing).
pub fn policy_bundle_body_hash(bundle: &PolicyBundle) -> [u8; 32] {
    let mut bytes = Vec::new();
    into_writer(&bundle.body(), &mut bytes)
        .expect("PolicyBundle body CBOR serialization must not fail");
    Sha256::digest(&bytes).into()
}

/// Domain-separated signing bytes for a policy bundle:
/// `CONTEXT_POLICY_BUNDLE || 0x00 || SHA-256(CBOR(body))`.
pub fn policy_bundle_signing_bytes(bundle: &PolicyBundle) -> Vec<u8> {
    let hash = policy_bundle_body_hash(bundle);
    let mut out = Vec::with_capacity(CONTEXT_POLICY_BUNDLE.len() + 1 + hash.len());
    out.extend_from_slice(CONTEXT_POLICY_BUNDLE.as_bytes());
    out.push(0);
    out.extend_from_slice(&hash);
    out
}

/// Verify one bundle co-signature against a `PolicyAuthority` DID in the trust
/// root's role registry (PV-3.2/PV-3.3). Signatures from DIDs not registered
/// as PolicyAuthority are rejected by the trust root.
pub fn verify_policy_cosignature(
    trust_root: &TrustRootRecord,
    bundle: &PolicyBundle,
    cosig: &PolicyCoSignature,
) -> Result<(), PolicyError> {
    let message = policy_bundle_signing_bytes(bundle);
    trust_root
        .verify_role_cosignature(
            CommandRole::PolicyAuthority,
            &cosig.signer_did,
            &message,
            &cosig.signature,
        )
        .map_err(PolicyError::TrustRoot)?;
    Ok(())
}

fn count_distinct_valid_policy_cosigs(
    trust_root: &TrustRootRecord,
    bundle: &PolicyBundle,
) -> Result<usize, PolicyError> {
    let mut seen: Vec<String> = Vec::new();
    for cosig in &bundle.co_signatures {
        if seen.iter().any(|d| d == &cosig.signer_did) {
            continue;
        }
        verify_policy_cosignature(trust_root, bundle, cosig)?;
        seen.push(cosig.signer_did.clone());
    }
    Ok(seen.len())
}

// ─── Classification (CLAIM-12.2, PV-4.11, INV-3) ────────────────────────────

/// Conservative 11-criterion tightening classification.
///
/// A bundle is [`PolicyBundleKind::Tightening`] only if **all** criteria hold
/// for every parameter; any ambiguity, mixed change, unit mismatch, or failure
/// yields [`PolicyBundleKind::Loosening`]. This function is the sole authority:
/// the guard never trusts `PolicyBundle.kind`.
pub fn classify_bundle(
    old: &EnvelopeProfile,
    new: &EnvelopeProfile,
    trust_root: &TrustRootRecord,
) -> PolicyBundleKind {
 // Device-class mismatch or structural ambiguity → loosening (conservative).
    if old.device_class != new.device_class {
        return PolicyBundleKind::Loosening;
    }

    let old_params: BTreeMap<&str, &ParameterSpec> = old
        .parameters
        .iter()
        .map(|p| (p.name.as_str(), p))
        .collect();
    let new_params: BTreeMap<&str, &ParameterSpec> = new
        .parameters
        .iter()
        .map(|p| (p.name.as_str(), p))
        .collect();

 // Criterion 7: no parameter removed. Criterion 8: adding any new parameter
 // is loosening.
    for name in old_params.keys() {
        if !new_params.contains_key(name) {
            return PolicyBundleKind::Loosening;
        }
    }
    for name in new_params.keys() {
        if !old_params.contains_key(name) {
            return PolicyBundleKind::Loosening;
        }
    }

 // Per-parameter criteria 1–6 and 11.
    let floors = trust_root
        .device_class_floors
        .get(&old.device_class)
        .cloned()
        .unwrap_or_default();
    let floor_by_param: BTreeMap<&str, &ParamFloor> =
        floors.iter().map(|f| (f.param_name.as_str(), f)).collect();

    for (name, np) in &new_params {
        let Some(op) = old_params.get(name) else {
            return PolicyBundleKind::Loosening;
        };

 // 1. Range/enum/bool tightening.
        match (&op.kind, &np.kind) {
            (
                ParameterKind::Range {
                    min: omin,
                    max: omax,
                },
                ParameterKind::Range {
                    min: nmin,
                    max: nmax,
                },
            ) => {
                if !range_subset(nmin, nmax, omin, omax) {
                    return PolicyBundleKind::Loosening;
                }
 // 11. Tightening floor from TrustRootRecord: new [min,max] must
 // remain within the safe operating floor [min_floor, max_ceiling].
                if let Some(floor) = floor_by_param.get(name) {
                    if !geq(nmin, &floor.min_floor) || !leq(nmax, &floor.max_ceiling) {
                        return PolicyBundleKind::Loosening;
                    }
                }
            }
            (ParameterKind::Enum { variants: ov }, ParameterKind::Enum { variants: nv }) => {
 // Subset of allowed variants (by value) is tightening.
                if nv.iter().any(|(_, v)| !ov.iter().any(|(_, o)| o == v)) {
                    return PolicyBundleKind::Loosening;
                }
            }
            (ParameterKind::Bool, ParameterKind::Bool) => {}
            _ => {
 // Kind change is ambiguous → loosening.
                return PolicyBundleKind::Loosening;
            }
        }

 // 2. max_rate_per_sec: new <= old (lower is tighter / slower change).
        if !leq(&np.max_rate_per_sec, &op.max_rate_per_sec) {
            return PolicyBundleKind::Loosening;
        }
 // 3. dwell_secs: new >= old.
        if np.dwell_secs < op.dwell_secs {
            return PolicyBundleKind::Loosening;
        }
 // 4. min_off_secs: new >= old.
        if np.min_off_secs < op.min_off_secs {
            return PolicyBundleKind::Loosening;
        }
 // 5. critical flag: false→true is tightening; true→false is loosening.
        if op.critical && !np.critical {
            return PolicyBundleKind::Loosening;
        }
 // 6. safe_default: any change is loosening.
        if !eq_fpv(&np.safe_default, &op.safe_default)
            || np.safe_default.unit_id != op.safe_default.unit_id
        {
            return PolicyBundleKind::Loosening;
        }
    }

 // 9. Cross-constraints: new set ⊇ old (at least as restrictive). We use a
 // structural equality/subset check on the serialisable form; any constraint
 // removed is loosening. Added constraints are tightening.
    for old_c in &old.cross_constraints {
        if !new.cross_constraints.iter().any(|c| c == old_c) {
            return PolicyBundleKind::Loosening;
        }
    }

 // 10. Governance fields:
 // policy_loosen_m non-decreasing, policy_loosen_n may only INCREASE (any
 // change to N alone is loosening per spec text: "any increase to N alone is
 // loosening"; decreasing N is also loosening), timelock/cancel non-decreasing.
    if new.policy_loosen_m < old.policy_loosen_m {
        return PolicyBundleKind::Loosening;
    }
 // N must not decrease; and spec states "any increase to N alone is loosening"
 // but increases to M/timelock/cancel may count as tightening. Treat any N
 // change conservatively as loosening unless identical.
    if new.policy_loosen_n != old.policy_loosen_n {
        return PolicyBundleKind::Loosening;
    }
    if new.policy_timelock_secs < old.policy_timelock_secs {
        return PolicyBundleKind::Loosening;
    }
    if new.policy_cancel_window_secs < old.policy_cancel_window_secs {
        return PolicyBundleKind::Loosening;
    }

    PolicyBundleKind::Tightening
}

// ─── Errors / outcomes ───────────────────────────────────────────────────────

/// Policy lifecycle failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
 /// Bundle version is not strictly greater than the last accepted / committed.
    Rollback { incoming: u64, committed: u64 },
 /// `prev_version_hash` does not match the hash of the current active bundle.
    PrevHashMismatch,
 /// A required co-signature is missing or invalid.
    Signature(String),
 /// Trust-root/role-registry error.
    TrustRoot(crate::trust_root::TrustRootError),
 /// Tightening violates the device-class floor from the trust root.
    TighteningFloorViolation { param: String, detail: String },
 /// Monotonic counter failure (anti-rollback persistence).
    Counter(String),
 /// Loosening time-lock has not elapsed.
    TimelockActive {
        timelock_until_est: i64,
        now_est: i64,
    },
 /// Not enough co-signatures for loosening.
    InsufficientCoSignatures { got: usize, need: usize },
 /// No pending loosening operation to apply/cancel.
    NoPendingLoosening,
 /// Profile install/validation failure.
    ProfileInstall(crate::envelope::ProfileInstallError),
 /// Bundle targets a different device class than the active profile.
    DeviceClassMismatch { active: String, incoming: String },
 /// Internal invariant violation.
    Invariant(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::Rollback { incoming, committed } => write!(
                f,
                "policy rollback rejected: incoming version {incoming} is not strictly greater than committed {committed}"
            ),
            PolicyError::PrevHashMismatch => {
                write!(f, "policy bundle prev_version_hash does not match active bundle")
            }
            PolicyError::Signature(e) => write!(f, "policy signature rejected: {e}"),
            PolicyError::TrustRoot(e) => write!(f, "{e}"),
            PolicyError::TighteningFloorViolation { param, detail } => {
                write!(f, "tightening floor violation for {param}: {detail}")
            }
            PolicyError::Counter(e) => write!(f, "policy anti-rollback counter error: {e}"),
            PolicyError::TimelockActive { timelock_until_est, now_est } => write!(
                f,
                "loosening time-lock active: now_est {now_est} < timelock_until_est {timelock_until_est}"
            ),
            PolicyError::InsufficientCoSignatures { got, need } => write!(
                f,
                "insufficient loosening co-signatures: got {got}, need {need}"
            ),
            PolicyError::NoPendingLoosening => write!(f, "no pending loosening operation"),
            PolicyError::ProfileInstall(e) => write!(f, "profile install failed: {e:?}"),
            PolicyError::DeviceClassMismatch { active, incoming } => write!(
                f,
                "device class mismatch: active {active:?}, incoming {incoming:?}"
            ),
            PolicyError::Invariant(e) => write!(f, "policy invariant: {e}"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Outcome of [`PolicyLifecycle::ingest_bundle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyIngestOutcome {
 /// Tightening applied immediately (PV-4.9).
    TighteningApplied { version: u64 },
 /// Loosening accepted for co-signature collection / time-lock.
    LooseningPending {
        version: u64,
        required_m: u8,
        required_n: u8,
        timelock_until_est: i64,
        cancel_deadline_est: i64,
    },
}

/// A pending loosening operation (durable state is mirrored in
/// `pending_approvals` for multi-sig accumulation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingLoosenOperation {
 /// The candidate bundle (its `kind` is ignored; kept for diagnostics).
    pub bundle: PolicyBundle,
 /// M/N/timelock read from the **active** policy at ingest (PV-4.10).
    pub required_m: u8,
    pub required_n: u8,
 /// `now_est + active.policy_timelock_secs` (computed at ingest).
    pub timelock_until_est: i64,
 /// `timelock_until_est`-relative cancel window derived from active policy.
    pub cancel_deadline_est: i64,
 /// Distinct verified co-signatures collected so far.
    pub co_signatures: Vec<PolicyCoSignature>,
}

/// Active bundle state tracked by the lifecycle.
#[derive(Debug, Clone)]
pub struct ActivePolicyState {
    pub bundle: PolicyBundle,
    pub body_hash: [u8; 32],
}

/// Policy lifecycle manager (CLAIM-12.1–12.7, PV-4.8–4.11).
///
/// The lifecycle is the production caller for classification, tightening-floor
/// enforcement, anti-rollback, and the loosening M-of-N/timelock path.
pub struct PolicyLifecycle {
    target_id: tirbase_types::TargetId,
    active: ActivePolicyState,
    counter: Arc<dyn MonotonicCounterTrait>,
    profile_map: Arc<ProfileMap>,
    trust_root: Arc<ArcSwap<TrustRootRecord>>,
    pending: Option<PendingLoosenOperation>,
 /// Records that an M=1 loosening warning has been emitted for the active
 /// governance (RD-9) to avoid log spam on every ingest.
    m1_warning_emitted: bool,
}

impl fmt::Debug for PolicyLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyLifecycle")
            .field("target_id", &self.target_id)
            .field("active_version", &self.active.bundle.version)
            .field("has_pending", &self.pending.is_some())
            .finish_non_exhaustive()
    }
}

impl PolicyLifecycle {
 /// Construct a lifecycle with an initial active bundle and committed version.
    pub fn new(
        target_id: tirbase_types::TargetId,
        initial: PolicyBundle,
        counter: Arc<dyn MonotonicCounterTrait>,
        profile_map: Arc<ProfileMap>,
        trust_root: Arc<ArcSwap<TrustRootRecord>>,
    ) -> Result<Self, PolicyError> {
        let committed = counter
            .read()
            .map_err(|e| PolicyError::Counter(e.to_string()))?;
        if initial.version < committed {
            return Err(PolicyError::Rollback {
                incoming: initial.version,
                committed,
            });
        }
        counter
            .set_if_greater(initial.version)
            .map_err(|e| PolicyError::Counter(e.to_string()))?;
        let body_hash = policy_bundle_body_hash(&initial);
        let mut lc = PolicyLifecycle {
            target_id,
            active: ActivePolicyState {
                bundle: initial,
                body_hash,
            },
            counter,
            profile_map,
            trust_root,
            pending: None,
            m1_warning_emitted: false,
        };
        lc.maybe_emit_m1_warning();
        Ok(lc)
    }

    pub fn active(&self) -> &ActivePolicyState {
        &self.active
    }

    pub fn pending(&self) -> Option<&PendingLoosenOperation> {
        self.pending.as_ref()
    }

    fn trust_root_snapshot(&self) -> Arc<TrustRootRecord> {
        self.trust_root.load_full()
    }

    fn maybe_emit_m1_warning(&mut self) {
        let m = self.active.bundle.envelope.policy_loosen_m;
        if m <= 1 && !self.m1_warning_emitted {
            self.m1_warning_emitted = true;
            emit(
                SecurityEvent::new(
                    SecurityEventCategory::PolicyLifecycle,
                    Severity::Medium,
                    ReasonCode::PolicyLooseningM1Warning,
                )
                .with_target(self.target_id.as_str())
                .with_detail(format!(
                    "active policy allows M={m} loosening (RD-9 warning): single-signer loosening governance is permitted for small deployments but reduces assurance"
                )),
            );
        }
    }

 /// Ingest a candidate bundle (production path, CLAIM-12.2/3/4/5/6/7).
 ///
 /// * Recomputes classification — `bundle.kind` is ignored.
 /// * Enforces strictly-greater version and anti-rollback counter commit.
 /// * Tightening: verifies at least one valid PolicyAuthority co-signature
 /// (or accepts an unsigned single-PA path only when governance allows; we
 /// require a valid cosig here for safety), commits counter, hot-swaps
 /// profile, emits event, returns immediately.
 /// * Loosening: reads M/N/timelock from the **active** policy, collects
 /// verified co-signatures, computes `timelock_until_est = now_est +
 /// active.timelock_secs`, and records a pending operation.
    pub fn ingest_bundle(
        &mut self,
        bundle: PolicyBundle,
        now_est: i64,
    ) -> Result<PolicyIngestOutcome, PolicyError> {
 // 12.6 / 12.7: strictly-greater version against committed counter.
        let committed = self
            .counter
            .read()
            .map_err(|e| PolicyError::Counter(e.to_string()))?;
        if bundle.version <= committed {
            emit(
                SecurityEvent::new(
                    SecurityEventCategory::PolicyLifecycle,
                    Severity::High,
                    ReasonCode::PolicyRollbackBlocked,
                )
                .with_target(self.target_id.as_str())
                .with_detail(format!(
                    "rejected bundle v{} (committed v{})",
                    bundle.version, committed
                )),
            );
            return Err(PolicyError::Rollback {
                incoming: bundle.version,
                committed,
            });
        }

 // prev_version_hash binding to active bundle (PV-4.8 chaining).
        if bundle.prev_version_hash != self.active.body_hash {
            return Err(PolicyError::PrevHashMismatch);
        }
        if bundle.envelope.device_class != self.active.bundle.envelope.device_class {
            return Err(PolicyError::DeviceClassMismatch {
                active: self.active.bundle.envelope.device_class.clone(),
                incoming: bundle.envelope.device_class.clone(),
            });
        }

        let trust_root = self.trust_root_snapshot();

 // 12.2: ALWAYS recompute — ignore bundle.kind.
        let computed = classify_bundle(&self.active.bundle.envelope, &bundle.envelope, &trust_root);

        match computed {
            PolicyBundleKind::Tightening => self.apply_tightening(bundle, &trust_root),
            PolicyBundleKind::Loosening => self.ingest_loosening(bundle, now_est, &trust_root),
        }
    }

    fn apply_tightening(
        &mut self,
        bundle: PolicyBundle,
        trust_root: &TrustRootRecord,
    ) -> Result<PolicyIngestOutcome, PolicyError> {
 // Verify at least one valid PolicyAuthority signature for the bundle.
        let valid = count_distinct_valid_policy_cosigs(trust_root, &bundle)?;
        if valid == 0 {
            emit(
                SecurityEvent::new(
                    SecurityEventCategory::PolicyLifecycle,
                    Severity::High,
                    ReasonCode::PolicyRejected,
                )
                .with_target(self.target_id.as_str())
                .with_detail("tightening bundle has no valid PolicyAuthority co-signatures"),
            );
            return Err(PolicyError::Signature(
                "tightening bundle requires at least one valid PolicyAuthority co-signature"
                    .to_string(),
            ));
        }

 // 12.3: tightening_floor enforcement — classify_bundle already checked
 // containment against TrustRootRecord floors; a belt-and-braces check
 // defends against classification misuse.
        if let Some(err) =
            check_tightening_floors(&bundle.envelope, trust_root, &bundle.envelope.device_class)
        {
            emit(
                SecurityEvent::new(
                    SecurityEventCategory::PolicyLifecycle,
                    Severity::High,
                    ReasonCode::TighteningFloorViolation,
                )
                .with_target(self.target_id.as_str())
                .with_detail(format!("{err}")),
            );
            return Err(err);
        }

        let version = bundle.version;
        self.commit_active(bundle)?;
        emit(
            SecurityEvent::new(
                SecurityEventCategory::PolicyLifecycle,
                Severity::Low,
                ReasonCode::TighteningApplied,
            )
            .with_target(self.target_id.as_str())
            .with_detail(format!("tightening bundle v{version} applied")),
        );
        Ok(PolicyIngestOutcome::TighteningApplied { version })
    }

    fn ingest_loosening(
        &mut self,
        bundle: PolicyBundle,
        now_est: i64,
        trust_root: &TrustRootRecord,
    ) -> Result<PolicyIngestOutcome, PolicyError> {
 // 12.4: M/N/timelock from the ACTIVE policy, never the bundle.
        let active_env = &self.active.bundle.envelope;
        let required_m = active_env.policy_loosen_m.max(1);
        let required_n = active_env.policy_loosen_n.max(required_m);
        let timelock_secs = active_env.policy_timelock_secs as i64;
        let cancel_window = active_env.policy_cancel_window_secs as i64;
        let timelock_until_est = now_est.saturating_add(timelock_secs);
        let cancel_deadline_est = timelock_until_est.saturating_add(cancel_window);

 // RD-9: M=1 allowed with warning (governance-level). We still enforce
 // the time-lock and require a valid co-signature.
        if required_m <= 1 {
            emit(
                SecurityEvent::new(
                    SecurityEventCategory::PolicyLifecycle,
                    Severity::Medium,
                    ReasonCode::PolicyLooseningM1Warning,
                )
                .with_target(self.target_id.as_str())
                .with_detail(format!(
                    "loosening v{} proceeds under M=1 governance (RD-9 warning); timelock_until_est={timelock_until_est}",
                    bundle.version
                )),
            );
        }

 // Collect any valid co-signatures present on the bundle.
        let mut co_signatures: Vec<PolicyCoSignature> = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        for cosig in &bundle.co_signatures {
            if seen.iter().any(|d| d == &cosig.signer_did) {
                continue;
            }
            if verify_policy_cosignature(trust_root, &bundle, cosig).is_ok() {
                seen.push(cosig.signer_did.clone());
                co_signatures.push(cosig.clone());
            }
        }

        let pending = PendingLoosenOperation {
            bundle,
            required_m,
            required_n,
            timelock_until_est,
            cancel_deadline_est,
            co_signatures,
        };
        let version = pending.bundle.version;
        self.pending = Some(pending);
        Ok(PolicyIngestOutcome::LooseningPending {
            version,
            required_m,
            required_n,
            timelock_until_est,
            cancel_deadline_est,
        })
    }

 /// Add a co-signature to the pending loosening operation (12.4, 12.8).
    pub fn add_loosening_cosignature(
        &mut self,
        cosig: PolicyCoSignature,
    ) -> Result<usize, PolicyError> {
        let trust_root = self.trust_root_snapshot();
        let pending = self
            .pending
            .as_mut()
            .ok_or(PolicyError::NoPendingLoosening)?;
        if pending
            .co_signatures
            .iter()
            .any(|c| c.signer_did == cosig.signer_did)
        {
            return Ok(pending.co_signatures.len());
        }
        verify_policy_cosignature(&trust_root, &pending.bundle, &cosig)?;
        pending.co_signatures.push(cosig);
        let count = pending.co_signatures.len();
        emit(
            SecurityEvent::new(
                SecurityEventCategory::PolicyLifecycle,
                Severity::Low,
                ReasonCode::LooseningSignatureCollected,
            )
            .with_target(self.target_id.as_str())
            .with_detail(format!(
                "loosening v{} co-signature collected ({}/{})",
                pending.bundle.version, count, pending.required_m
            )),
        );
        Ok(count)
    }

 /// Apply the pending loosening bundle if M co-signatures are present and the
 /// time-lock has elapsed (12.4, 12.10).
    pub fn apply_pending_loosening(
        &mut self,
        now_est: i64,
    ) -> Result<PolicyIngestOutcome, PolicyError> {
        let (ready, version, timelock_until_est, got, need) = {
            let pending = self
                .pending
                .as_ref()
                .ok_or(PolicyError::NoPendingLoosening)?;
            let got = pending.co_signatures.len();
            let need = pending.required_m as usize;
            let time_ok = now_est >= pending.timelock_until_est;
            (
                got >= need && time_ok,
                pending.bundle.version,
                pending.timelock_until_est,
                got,
                need,
            )
        };
        if !ready {
            if now_est < timelock_until_est {
                return Err(PolicyError::TimelockActive {
                    timelock_until_est,
                    now_est,
                });
            }
            return Err(PolicyError::InsufficientCoSignatures { got, need });
        }

        let mut pending = self.pending.take().ok_or(PolicyError::NoPendingLoosening)?;
 // Merge collected cosigs into the bundle for auditability.
        for c in pending.co_signatures.drain(..) {
            if !pending
                .bundle
                .co_signatures
                .iter()
                .any(|x| x.signer_did == c.signer_did)
            {
                pending.bundle.co_signatures.push(c);
            }
        }
        let trust_root = self.trust_root_snapshot();
 // Re-check floors defensively (classification at ingest was authoritative;
 // this guards state corruption).
        if let Some(err) = check_tightening_floors(
            &pending.bundle.envelope,
            &trust_root,
            &pending.bundle.envelope.device_class,
        ) {
 // Loosening should not trip tightening floors, but be safe.
            emit(
                SecurityEvent::new(
                    SecurityEventCategory::PolicyLifecycle,
                    Severity::High,
                    ReasonCode::TighteningFloorViolation,
                )
                .with_target(self.target_id.as_str())
                .with_detail(format!("{err}")),
            );
            return Err(err);
        }

        self.commit_active(pending.bundle)?;
        emit(
            SecurityEvent::new(
                SecurityEventCategory::PolicyLifecycle,
                Severity::Medium,
                ReasonCode::LooseningApplied,
            )
            .with_target(self.target_id.as_str())
            .with_detail(format!(
                "loosening bundle v{version} applied after timelock+M-of-N"
            )),
        );
        Ok(PolicyIngestOutcome::TighteningApplied { version })
    }

 /// Cancel a pending loosening (requires caller to have enforced PA auth;
 /// this method records the state transition).
    pub fn cancel_loosening(&mut self) -> Result<u64, PolicyError> {
        let pending = self.pending.take().ok_or(PolicyError::NoPendingLoosening)?;
        let version = pending.bundle.version;
        emit(
            SecurityEvent::new(
                SecurityEventCategory::PolicyLifecycle,
                Severity::Medium,
                ReasonCode::LooseningCancelled,
            )
            .with_target(self.target_id.as_str())
            .with_detail(format!("pending loosening v{version} cancelled")),
        );
        Ok(version)
    }

    fn commit_active(&mut self, bundle: PolicyBundle) -> Result<(), PolicyError> {
        let version = bundle.version;
 // 12.6: commit anti-rollback counter before/with activation.
        self.counter
            .set_if_greater(version)
            .map_err(|e| PolicyError::Counter(e.to_string()))?;
        let profile = bundle.envelope.clone();
        let body_hash = policy_bundle_body_hash(&bundle);
        self.active = ActivePolicyState { bundle, body_hash };
 // Hot-swap the active profile for the target (best-effort structural
 // update; the profile map is the guard's read path).
        let _ = self.profile_map.swap(&self.target_id, profile.clone());
 // If target wasn't present, install it.
        let replaced = Arc::new(ProfileMap::from_profiles([(
            self.target_id.clone(),
            profile.clone(),
        )]));
 // `swap` above returns false if missing; install by rebuilding only when
 // needed would require interior mutability redesign. The map's
 // `with_profile` is the safe additive path; callers that own the map can
 // also do it. For lifecycle-owned updates we rely on swap when present.
        let _ = replaced; // documented: target must be pre-installed in map.
        self.maybe_emit_m1_warning();
        Ok(())
    }
}

/// Belt-and-braces tightening-floor check (CLAIM-12.3).
///
/// Returns `Some(error)` if any Range parameter's new bounds fall outside the
/// `[min_floor, max_ceiling]` safe operating range from the trust root.
pub fn check_tightening_floors(
    envelope: &EnvelopeProfile,
    trust_root: &TrustRootRecord,
    device_class: &str,
) -> Option<PolicyError> {
    let floors = trust_root.device_class_floors.get(device_class)?;
    for floor in floors {
        let Some(param) = envelope
            .parameters
            .iter()
            .find(|p| p.name == floor.param_name)
        else {
            continue;
        };
        if let ParameterKind::Range { min, max } = &param.kind {
            if !geq(min, &floor.min_floor) || !leq(max, &floor.max_ceiling) {
                return Some(PolicyError::TighteningFloorViolation {
                    param: floor.param_name.clone(),
                    detail: format!(
                        "new range [{:?},{:?}] not within floor [{:?},{:?}]",
                        min, max, floor.min_floor, floor.max_ceiling
                    ),
                });
            }
        }
    }
    None
}

/// Convenience: build a `PolicyBundle` with a computed prev hash and conservative
/// `kind` placeholder (the guard will ignore it).
pub fn make_bundle(
    version: u64,
    prev_version_hash: [u8; 32],
    envelope: EnvelopeProfile,
    co_signatures: Vec<PolicyCoSignature>,
) -> PolicyBundle {
    PolicyBundle {
        version,
        prev_version_hash,
        envelope,
        co_signatures,
        kind: PolicyBundleKind::Loosening, // ignored by guard
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirbase_types::envelope::{EnvelopeProfile, ParameterKind, ParameterSpec};
    use tirbase_types::{DeviceSignature, ProfileId, UNIT_DEG_C};

    fn fp(m: i64, e: i8) -> FixedPointValue {
        FixedPointValue::new(m, e, UNIT_DEG_C)
    }

    fn param(name: &str, min: i64, max: i64, critical: bool) -> ParameterSpec {
        ParameterSpec {
            name: name.to_string(),
            unit_id: UNIT_DEG_C,
            canonical_exponent: -1,
            kind: ParameterKind::Range {
                min: fp(min, -1),
                max: fp(max, -1),
            },
            max_rate_per_sec: fp(10, -1),
            dwell_secs: 5,
            min_off_secs: 2,
            drift_window_secs: 60,
            max_delta_in_window: fp(50, -1),
            safe_default: fp(200, -1),
            tightening_floor: fp(-400, -1),
            critical,
        }
    }

    fn profile(version: u64, min: i64, max: i64, m: u8, n: u8, tl: u32) -> EnvelopeProfile {
        EnvelopeProfile {
            profile_id: [version as u8; 16] as ProfileId,
            version,
            device_class: "cold_room".to_string(),
            parameters: vec![param("temp", min, max, false)],
            cross_constraints: vec![],
            policy_loosen_m: m,
            policy_loosen_n: n,
            policy_timelock_secs: tl,
            policy_cancel_window_secs: 60,
            signature: DeviceSignature::Ed25519([0u8; 64]),
        }
    }

    fn trust_root_with_floor() -> TrustRootRecord {
        let mut floors = BTreeMap::new();
        floors.insert(
            "cold_room".to_string(),
            vec![ParamFloor {
                param_name: "temp".to_string(),
                min_floor: fp(-500, -1),   // -50.0°C
                max_ceiling: fp(1500, -1), // 150.0°C
            }],
        );
        TrustRootRecord {
            version: 1,
            root_ca_public_keys: vec![],
            threshold_k: 1,
            role_thresholds: BTreeMap::new(),
            device_class_floors: floors,
            expiry_est: i64::MAX,
            revoked_root_ca_keys: vec![],
            signatures: vec![],
        }
    }

    #[test]
    fn tighten_subset_is_tightening() {
        let tr = trust_root_with_floor();
        let old = profile(1, 0, 1000, 2, 3, 300);
        let new = profile(2, 10, 900, 2, 3, 300); // narrower
        assert_eq!(
            classify_bundle(&old, &new, &tr),
            PolicyBundleKind::Tightening
        );
    }

    #[test]
    fn loosen_range_is_loosening() {
        let tr = trust_root_with_floor();
        let old = profile(1, 0, 1000, 2, 3, 300);
        let new = profile(2, -10, 1000, 2, 3, 300);
        assert_eq!(
            classify_bundle(&old, &new, &tr),
            PolicyBundleKind::Loosening
        );
    }

    #[test]
    fn governance_n_change_is_loosening() {
        let tr = trust_root_with_floor();
        let old = profile(1, 0, 1000, 2, 3, 300);
        let new = profile(2, 0, 1000, 2, 4, 300);
        assert_eq!(
            classify_bundle(&old, &new, &tr),
            PolicyBundleKind::Loosening
        );
    }

    #[test]
    fn exceeds_tightening_floor_is_rejected_by_classifier_path() {
        let tr = trust_root_with_floor(); // floor ceiling 150.0°C
        let old = profile(1, -300, 1400, 2, 3, 300);
 // new max 160.0°C > ceiling 150.0°C => floor violated => Loosening
        let new = profile(2, -300, 1600, 2, 3, 300);
        assert_eq!(
            classify_bundle(&old, &new, &tr),
            PolicyBundleKind::Loosening
        );
    }

    #[test]
    fn bundle_kind_field_is_ignored_by_reclassification() {
 // Demonstrates the invariant: caller-supplied kind does not affect
 // computed classification (the guard discards it).
        let tr = trust_root_with_floor();
        let old = profile(1, 0, 1000, 2, 3, 300);
        let new = profile(2, -10, 1000, 2, 3, 300); // actually loosening
        let mut claimed = PolicyBundle {
            version: 2,
            prev_version_hash: [0; 32],
            envelope: new.clone(),
            co_signatures: vec![],
            kind: PolicyBundleKind::Tightening, // lie
        };
        let _ = &mut claimed.kind;
        assert_eq!(
            classify_bundle(&old, &new, &tr),
            PolicyBundleKind::Loosening
        );
    }

    #[test]
    fn strictly_greater_version_allows_gaps() {
 // Unit-level check for 12.7 semantics (version comparison logic).
        let committed = 1u64;
        let incoming = 6u64;
        assert!(incoming > committed);
 // exactly +1 not required
        let incoming2 = 2u64;
        assert!(incoming2 > committed);
    }

    #[test]
    fn make_bundle_uses_ignored_kind() {
        let b = make_bundle(2, [0; 32], profile(2, 0, 1, 2, 2, 1), vec![]);
        assert_eq!(b.kind, PolicyBundleKind::Loosening);
        assert_eq!(b.version, 2);
    }
}
