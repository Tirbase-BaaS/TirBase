//! CommandGuard admit pipeline — Stages 0–15 (task 14, CLAIM-14.1–14.17).
//!
//! This module implements the fast synchronous `admit()` path: it performs
//! validation, rate limiting, auth/binding, envelope, and quorum checks. It
//! does NOT mint `ActuationPermit` or dispatch to `DriverProxy`; that remains
//! the responsibility of the legacy `CommandGuard::admit()` (tasks 11/13/15)
//! until the Stage 16–19 executor split lands.
//!
//! `simulate()` runs the same validation path but skips side-effecting token
//! consumption for Stage 0, Stage 9 nonce consumption, and Stage 14 per-issuer
//! consumption (PV-4.17, CLAIM-14.10, CLAIM-14.16).

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use arc_swap::ArcSwap;
use tirbase_core::auth::command_token::{
    check_command_binding, verify_command_token, CommandTokenClaims,
};
use tirbase_core::auth::root_ca::RootCaRegistry;
use tirbase_core::events::{emit, ReasonCode, SecurityEvent, SecurityEventCategory, Severity};
use tirbase_core::traits::TimeSource;
use tirbase_types::command::CommandMessage;
use tirbase_types::envelope::{ConstraintOperator, EnvelopeProfile, ParameterKind, ParameterSpec};
use tirbase_types::policy::PolicyBundle;
use tirbase_types::{CommandRole, Did, FixedPointValue, TargetId};

use crate::command::verify_command_signature;
use crate::driver_proxy::IngressSource;
use crate::envelope::ProfileMap;
use crate::epoch::{EpochError, EpochRegistry};
use crate::node_mode::{NodeMode, NodeModeState};
use crate::time::{FreshnessState, TimeRatchet};

pub(crate) const DEFAULT_PRE_AUTH_RPS: u32 = 50;
pub(crate) const DEFAULT_ISSUER_RPS: u32 = 10;
pub(crate) const DEFAULT_MAX_TTL_SECS: i64 = 3600;
pub(crate) const DEFAULT_CHALLENGE_NONCE_TTL_SECS: u64 = 300;

pub trait DriftHistoryStore: Send + Sync + std::fmt::Debug {
    fn record(&self, issuer_did: &str, target_id: &str, param: &str, mono_secs: i64, value_mantissa: i64, exponent: i8, unit_id: u16) -> Result<(), String>;
    fn recent(&self, issuer_did: &str, target_id: &str, param: &str, since_mono_secs: i64) -> Result<Vec<DriftRecord>, String>;
}
pub trait DecidedOutcomeStore: Send + Sync + std::fmt::Debug {
    fn lookup(&self, issuer_did: &str, target_id: &str, sequence_number: u64, enrollment_epoch: u64) -> Result<Option<AdmitDecision>, String>;
    fn store(&self, issuer_did: &str, target_id: &str, sequence_number: u64, enrollment_epoch: u64, decision: &AdmitDecision) -> Result<(), String>;
}
pub trait ChallengeNonceStore: Send + Sync + std::fmt::Debug {
    fn consume_if_valid(&self, nonce: &[u8; 32], issuer_did: &str, target_id: &str, param: &str, mono_secs_now: i64, consume: bool) -> Result<bool, String>;
}
pub trait PendingApprovalQuorum: Send + Sync + std::fmt::Debug {
    fn has_quorum(&self, issuer_did: &str, target_id: &str, param: &str, sequence_number: u64, required_m: usize) -> Result<bool, String>;
}

/// Outcome of admit/simulate pipeline (Stages 0–15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitDecision {
    Accepted { idempotency_cache_hit: bool, derived_role: CommandRole },
    Rejected { category: AdmitRejection, detail: String, retry_after_secs: Option<u32> },
    Simulated { would_accept: bool, rejection: Option<(AdmitRejection, String, Option<u32>)>, derived_role: Option<CommandRole> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdmitRejection {
    PreAuthRateLimit,
    ModeLockdown,
    InvalidSignature,
    TokenInvalid,
    ScopeViolation,
    IssuerRevoked,
    StaleEpoch,
    TargetBusy,
    Expired,
    ChallengeMissing,
    ValueInvalid,
    EnvelopeViolation,
    ConstraintViolation,
    DriftExceeded,
    RateLimit,
    QuorumRequired,
    NoProfile,
    Unsupported,
    CommitConflict,
}

impl AdmitRejection {
    pub fn reason_code(self) -> ReasonCode {
        match self {
            AdmitRejection::PreAuthRateLimit => ReasonCode::PreAuthRateLimit,
            AdmitRejection::ModeLockdown => ReasonCode::ModeLockdown,
            AdmitRejection::InvalidSignature => ReasonCode::CommandSignatureInvalid,
            AdmitRejection::TokenInvalid => ReasonCode::TokenInvalid,
            AdmitRejection::ScopeViolation => ReasonCode::ScopeViolation,
            AdmitRejection::IssuerRevoked => ReasonCode::IssuerRevoked,
            AdmitRejection::StaleEpoch => ReasonCode::StaleEpoch,
            AdmitRejection::TargetBusy => ReasonCode::TargetBusy,
            AdmitRejection::Expired => ReasonCode::Expired,
            AdmitRejection::ChallengeMissing => ReasonCode::ChallengeMissing,
            AdmitRejection::ValueInvalid => ReasonCode::ValueInvalid,
            AdmitRejection::EnvelopeViolation => ReasonCode::EnvelopeViolation,
            AdmitRejection::ConstraintViolation => ReasonCode::ConstraintViolation,
            AdmitRejection::DriftExceeded => ReasonCode::DriftExceeded,
            AdmitRejection::RateLimit => ReasonCode::RateLimit,
            AdmitRejection::QuorumRequired => ReasonCode::QuorumRequired,
            AdmitRejection::NoProfile => ReasonCode::NoProfile,
            AdmitRejection::Unsupported => ReasonCode::Unsupported,
            AdmitRejection::CommitConflict => ReasonCode::CommitConflict,
        }
    }
}

/// Context required by the Stage 0–15 admit pipeline.
///
/// `biscuit_token` must be provided by the authenticated ingress path (Stage 3).
/// Existing task 11/13 callers that have not been upgraded can use
/// [`CommandGuard::admit_legacy`] which preserves prior signature+epoch behavior.
#[derive(Debug, Clone)]
pub struct AdmitContext<'a> {
    pub ingress: IngressSource,
    pub source_key: &'a str,
    pub biscuit_token: Option<&'a [u8]>,
    pub now_est_secs: Option<i64>,
    pub simulate: bool,
}

/// In-memory token bucket (O(1)) used by Stage 0 and Stage 14.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last: Instant,
    capacity: f64,
    refill_per_sec: f64,
}

impl TokenBucket {
    fn new(rate_per_sec: u32) -> Self {
        let cap = (rate_per_sec.max(1)) as f64;
        TokenBucket { tokens: cap, last: Instant::now(), capacity: cap, refill_per_sec: cap }
    }
    fn try_take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if self.tokens >= 1.0 { self.tokens -= 1.0; true } else { false }
    }
}

#[derive(Debug, Default)]
pub(crate) struct RateLimiters {
    pre_auth: Mutex<HashMap<String, TokenBucket>>,
    per_issuer: Mutex<HashMap<String, TokenBucket>>,
}

impl RateLimiters {
    pub fn check_pre_auth(&self, source_key: &str, consume: bool, rps: u32) -> bool {
        if rps == 0 { return true; }
        let mut map = match self.pre_auth.lock() { Ok(g) => g, Err(p) => p.into_inner() };
        let b = map.entry(source_key.to_string()).or_insert_with(|| TokenBucket::new(rps));
        if !consume { return true; }
        b.try_take()
    }
    pub fn check_issuer(&self, issuer_did: &str, consume: bool, rps: u32) -> bool {
        if rps == 0 { return true; }
        let mut map = match self.per_issuer.lock() { Ok(g) => g, Err(p) => p.into_inner() };
        let b = map.entry(issuer_did.to_string()).or_insert_with(|| TokenBucket::new(rps));
        if !consume { return true; }
        b.try_take()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftRecord {
    pub mono_secs: i64,
    pub value_mantissa: i64,
    pub exponent: i8,
    pub unit_id: u16,
}

/// Pipeline state held by `CommandGuard` for Task 14 stages.
#[derive(Debug)]
pub struct AdmitPipelineState {
    pub(crate) profiles: Arc<BTreeMap<TargetId, Arc<ArcSwap<EnvelopeProfile>>>>,
    pub(crate) policy: Arc<ArcSwap<Option<PolicyBundle>>>,
    pub(crate) root_ca_registry: Arc<RwLock<RootCaRegistry>>,
    pub(crate) revoked_dids: Arc<RwLock<BTreeSet<String>>>,
    pub(crate) decided_outcomes: Arc<Mutex<HashMap<(String, String, u64, u64), AdmitDecision>>>,
    pub(crate) unknown_targets: Arc<RwLock<BTreeSet<String>>>,
    pub(crate) challenge_nonces: Arc<Mutex<HashMap<[u8; 32], (String, String, String, i64)>>>, // nonce -> (issuer,target,param,expires_mono_secs)
    pub(crate) drift_history: Arc<Mutex<HashMap<(String, String, String), VecDeque<DriftRecord>>>>, // (issuer,target,param)
    pub(crate) rate_limiters: Arc<RateLimiters>,
    pub(crate) pre_auth_rps: AtomicU64,
    pub(crate) issuer_rps: AtomicU64,
    pub(crate) max_ttl_secs: AtomicU64,
    pub(crate) ratchet: Arc<Mutex<TimeRatchet>>,
    pub(crate) trust_root: Arc<ArcSwap<Option<crate::trust_root::TrustRootRecord>>>,
    pub(crate) time_source: Arc<dyn TimeSource>,
    pub(crate) drift_store: Arc<RwLock<Option<Arc<dyn DriftHistoryStore>>>>,
    pub(crate) decided_store: Arc<RwLock<Option<Arc<dyn DecidedOutcomeStore>>>>,
    pub(crate) challenge_store: Arc<RwLock<Option<Arc<dyn ChallengeNonceStore>>>>,
    pub(crate) quorum_provider: Arc<RwLock<Option<Arc<dyn PendingApprovalQuorum>>>>,
    pub(crate) desired_state: Arc<RwLock<BTreeMap<(String, String), FixedPointValue>>>, // (target,param) pending+committed
}

impl AdmitPipelineState {
    pub fn new(
        profiles: Arc<BTreeMap<TargetId, Arc<ArcSwap<EnvelopeProfile>>>>,
        policy: Arc<ArcSwap<Option<PolicyBundle>>>,
        root_ca_registry: Arc<RwLock<RootCaRegistry>>,
        ratchet: Arc<Mutex<TimeRatchet>>,
        time_source: Arc<dyn TimeSource>,
    ) -> Self {
        AdmitPipelineState {
            profiles,
            policy,
            root_ca_registry,
            revoked_dids: Arc::new(RwLock::new(BTreeSet::new())),
            decided_outcomes: Arc::new(Mutex::new(HashMap::new())),
            unknown_targets: Arc::new(RwLock::new(BTreeSet::new())),
            challenge_nonces: Arc::new(Mutex::new(HashMap::new())),
            drift_history: Arc::new(Mutex::new(HashMap::new())),
            rate_limiters: Arc::new(RateLimiters::default()),
            pre_auth_rps: AtomicU64::new(DEFAULT_PRE_AUTH_RPS as u64),
            issuer_rps: AtomicU64::new(DEFAULT_ISSUER_RPS as u64),
            max_ttl_secs: AtomicU64::new(DEFAULT_MAX_TTL_SECS as u64),
            ratchet,
            trust_root: Arc::new(ArcSwap::from_pointee(None)),
            time_source,
            drift_store: Arc::new(RwLock::new(None)),
            decided_store: Arc::new(RwLock::new(None)),
            challenge_store: Arc::new(RwLock::new(None)),
            quorum_provider: Arc::new(RwLock::new(None)),
            desired_state: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }
    pub fn set_pre_auth_rps(&self, rps: u32) { self.pre_auth_rps.store(rps as u64, Ordering::Relaxed); }
    pub fn set_issuer_rps(&self, rps: u32) { self.issuer_rps.store(rps as u64, Ordering::Relaxed); }
    pub fn set_max_ttl_secs(&self, secs: i64) { self.max_ttl_secs.store(secs.max(0) as u64, Ordering::Relaxed); }
    pub fn revoke_did(&self, did: impl Into<String>) {
        if let Ok(mut g) = self.revoked_dids.write() { g.insert(did.into()); }
    }
    pub fn mark_target_unknown(&self, target_id: impl Into<String>) {
        if let Ok(mut g) = self.unknown_targets.write() { g.insert(target_id.into()); }
    }
    pub fn clear_target_unknown(&self, target_id: &str) {
        if let Ok(mut g) = self.unknown_targets.write() { g.remove(target_id); }
    }

    pub fn set_drift_store(&self, store: Arc<dyn DriftHistoryStore>) { if let Ok(mut g)=self.drift_store.write() { *g=Some(store); } }
    pub fn set_decided_store(&self, store: Arc<dyn DecidedOutcomeStore>) { if let Ok(mut g)=self.decided_store.write() { *g=Some(store); } }
    pub fn set_challenge_store(&self, store: Arc<dyn ChallengeNonceStore>) { if let Ok(mut g)=self.challenge_store.write() { *g=Some(store); } }
    pub fn set_quorum_provider(&self, p: Arc<dyn PendingApprovalQuorum>) { if let Ok(mut g)=self.quorum_provider.write() { *g=Some(p); } }
    pub fn set_desired_state(&self, target_id: &str, param: &str, value: FixedPointValue) { if let Ok(mut g)=self.desired_state.write() { g.insert((target_id.to_string(), param.to_string()), value); } }
    pub fn issue_challenge_nonce(&self, issuer_did: &str, target_id: &str, param: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut nonce = [0u8; 32];
        let seed = format!("{}:{}:{}:{}", issuer_did, target_id, param, self.time_source.monotonic_now());
        nonce.copy_from_slice(&Sha256::digest(seed.as_bytes()));
        let expires = (self.time_source.monotonic_now() / 1_000_000) as i64 + DEFAULT_CHALLENGE_NONCE_TTL_SECS as i64;
        if let Ok(mut g) = self.challenge_nonces.lock() {
            g.insert(nonce, (issuer_did.to_string(), target_id.to_string(), param.to_string(), expires));
        }
        nonce
    }
}

fn reject(cat: AdmitRejection, detail: impl Into<String>, actor: &Did, target: &TargetId) -> AdmitDecision {
    let detail = detail.into();
    emit(SecurityEvent::new(SecurityEventCategory::CommandDecision, Severity::Medium, cat.reason_code())
        .with_actor(actor.as_str())
        .with_target(target.as_str())
        .with_detail(detail.clone()));
    AdmitDecision::Rejected { category: cat, detail, retry_after_secs: if matches!(cat, AdmitRejection::RateLimit|AdmitRejection::PreAuthRateLimit) { Some(1) } else { None } }
}

/// Evaluate Stages 0–15. Returns an `AdmitDecision`; does not mint permits.
pub fn admit_stages_0_to_15(
    cmd: &CommandMessage,
    ctx: &AdmitContext<'_>,
    node_mode: &NodeModeState,
    epochs: &EpochRegistry,
    pipeline: &AdmitPipelineState,
    device_id_for_epoch: Option<&str>,
) -> AdmitDecision {
    let simulate = ctx.simulate;
    // Stage 0: pre-auth per-source rate limit (before any cryptographic operation)
    let pre_rps = pipeline.pre_auth_rps.load(Ordering::Relaxed) as u32;
    if !pipeline.rate_limiters.check_pre_auth(ctx.source_key, !simulate, pre_rps) {
        let retry_after_secs = if pre_rps == 0 { 0 } else { 1 }; return reject(AdmitRejection::PreAuthRateLimit, format!("pre-auth rate limit exceeded; retry_after_secs={retry_after_secs}"), &cmd.issuer_did, &cmd.target_id);
    }

    // Stage 1: OperationalMode check
    let mode = node_mode.get();
    if !mode.allows_commands() {
        return reject(AdmitRejection::ModeLockdown, format!("node mode {mode} does not permit commands"), &cmd.issuer_did, &cmd.target_id);
    }

    // Stage 2: command signature
    if let Err(e) = verify_command_signature(cmd) {
        return reject(AdmitRejection::InvalidSignature, e.to_string(), &cmd.issuer_did, &cmd.target_id);
    }

    // Stage 3 + 4: Biscuit token verification and binding
    let (now_est, freshness) = {
        let ratchet = match pipeline.ratchet.lock() { Ok(g) => g, Err(p) => p.into_inner() };
        let now = ctx.now_est_secs.unwrap_or_else(|| ratchet.now_est(pipeline.time_source.as_ref()));
        let fresh = ratchet.freshness(pipeline.time_source.as_ref());
        (now, fresh)
    };
    let token_bytes = match ctx.biscuit_token {
        Some(b) if !b.is_empty() => b,
        _ => return reject(AdmitRejection::TokenInvalid, "missing Biscuit token", &cmd.issuer_did, &cmd.target_id),
    };
    let claims = {
        let reg = match pipeline.root_ca_registry.read() { Ok(g) => g, Err(p) => p.into_inner() };
        let keys = reg.active_keys();
        if keys.is_empty() {
            return reject(AdmitRejection::TokenInvalid, "no active root CA keys", &cmd.issuer_did, &cmd.target_id);
        }
        let mut last = None;
        let mut ok = None;
        for key in keys {
            match verify_command_token(token_bytes, &key, now_est) {
                Ok(c) => { ok = Some(c); break; }
                Err(e) => last = Some(e.to_string()),
            }
        }
        match ok {
            Some(c) => c,
            None => return reject(AdmitRejection::TokenInvalid, last.unwrap_or_else(|| "token verification failed".into()), &cmd.issuer_did, &cmd.target_id),
        }
    };
    // Stage 4: derive role from token (never cmd.role), bind scope/DID
    if claims.did != cmd.issuer_did.as_str() {
        return reject(AdmitRejection::ScopeViolation, format!("token DID {} != command issuer {}", claims.did, cmd.issuer_did.as_str()), &cmd.issuer_did, &cmd.target_id);
    }
    if claims.role != CommandRole::CommandIssuer {
        // v1 command path requires CommandIssuer; admin roles use other paths.
        return reject(AdmitRejection::ScopeViolation, format!("token role {:?} not authorized for command admission", claims.role), &cmd.issuer_did, &cmd.target_id);
    }
    if let Err(e) = check_command_binding(&claims, cmd.target_id.as_str(), &cmd.param) {
        return reject(AdmitRejection::ScopeViolation, e, &cmd.issuer_did, &cmd.target_id);
    }

    // Stage 5: issuer DID revocation
    if let Ok(rev) = pipeline.revoked_dids.read() {
        if rev.contains(cmd.issuer_did.as_str()) {
            return reject(AdmitRejection::IssuerRevoked, "issuer DID revoked", &cmd.issuer_did, &cmd.target_id);
        }
    }

    // Stage 6: device enrollment epoch check
    if let Some(dev) = device_id_for_epoch {
        if let Err(e) = epochs.check_command_epoch(dev, cmd.enrollment_epoch) {
            let detail = e.to_string();
            return reject(AdmitRejection::StaleEpoch, detail, &cmd.issuer_did, &cmd.target_id);
        }
    }

    // Stage 6.5: TargetBusy pre-check
    if let Ok(unk) = pipeline.unknown_targets.read() {
        if unk.contains(cmd.target_id.as_str()) {
            return reject(AdmitRejection::TargetBusy, "target has unresolved Unknown ledger entry", &cmd.issuer_did, &cmd.target_id);
        }
    }

    // Stage 7: decided-outcome cache (memory + optional DB)
    let cache_key = (cmd.issuer_did.as_str().to_string(), cmd.target_id.as_str().to_string(), cmd.sequence_number, cmd.enrollment_epoch);
    if let Ok(cache) = pipeline.decided_outcomes.lock() {
        if let Some(hit) = cache.get(&cache_key) {
            return match hit {
                AdmitDecision::Accepted { derived_role, .. } => AdmitDecision::Accepted { idempotency_cache_hit: true, derived_role: *derived_role },
                other => other.clone(),
            };
        }
    }
    if let Ok(g)=pipeline.decided_store.read() { if let Some(store)=g.as_ref() {
        if let Ok(Some(hit))=store.lookup(cmd.issuer_did.as_str(), cmd.target_id.as_str(), cmd.sequence_number, cmd.enrollment_epoch) {
            return match hit { AdmitDecision::Accepted { derived_role, .. } => AdmitDecision::Accepted { idempotency_cache_hit:true, derived_role }, other => other };
        }
    }}

    // Stage 8: expiry using now_est
    let max_ttl = pipeline.max_ttl_secs.load(Ordering::Relaxed) as i64;
    if max_ttl > 0 && cmd.expiry_est.saturating_sub(now_est) > max_ttl {
        return reject(AdmitRejection::Expired, format!("command TTL exceeds max_ttl_secs={max_ttl}"), &cmd.issuer_did, &cmd.target_id);
    }
    if now_est > cmd.expiry_est {
        return reject(AdmitRejection::Expired, format!("command expired: now_est={now_est} > expiry_est={}", cmd.expiry_est), &cmd.issuer_did, &cmd.target_id);
    }

    // Resolve profile/spec for remaining checks
    let profile = match pipeline.profiles.get(&cmd.target_id).map(|c| c.load_full()) {
        Some(p) => p,
        None => return reject(AdmitRejection::NoProfile, "no envelope profile for target", &cmd.issuer_did, &cmd.target_id),
    };
    let spec = match profile.parameters.iter().find(|p| p.name == cmd.param) {
        Some(s) => s,
        None => return reject(AdmitRejection::ValueInvalid, format!("parameter {} not in profile", cmd.param), &cmd.issuer_did, &cmd.target_id),
    };

    // Stage 9: challenge nonce for Unverified + critical
    if freshness == FreshnessState::Unverified && spec.critical {
        let nonce = match cmd.challenge_nonce {
            Some(n) => n,
            None => return reject(AdmitRejection::ChallengeMissing, "critical parameter requires challenge nonce in Unverified freshness", &cmd.issuer_did, &cmd.target_id),
        };
        let mono_now = (pipeline.time_source.monotonic_now() / 1_000_000) as i64;
        let mut ok = if let Ok(g)=pipeline.challenge_store.read() { if let Some(store)=g.as_ref() { store.consume_if_valid(&nonce, cmd.issuer_did.as_str(), cmd.target_id.as_str(), &cmd.param, mono_now, !simulate).unwrap_or(false) } else { false } } else { false };
        if !ok { ok = if let Ok(mut store) = pipeline.challenge_nonces.lock() {
            if let Some((issuer, target, param, exp)) = store.get(&nonce).cloned() {
                let valid = issuer == cmd.issuer_did.as_str() && target == cmd.target_id.as_str() && param == cmd.param && mono_now <= exp;
                if valid && !simulate { store.remove(&nonce); }
                valid
            } else { false }
        } else { false }; }
        if !ok {
            return reject(AdmitRejection::ChallengeMissing, "invalid, expired, or reused challenge nonce", &cmd.issuer_did, &cmd.target_id);
        }
    }

    // Stage 10: FixedPointValue canonical exponent
    if cmd.desired_state.unit_id != spec.unit_id {
        return reject(AdmitRejection::ValueInvalid, format!("unit_id mismatch: got {}, expected {}", cmd.desired_state.unit_id, spec.unit_id), &cmd.issuer_did, &cmd.target_id);
    }
    let canonical = match cmd.desired_state.with_canonical_exponent(spec.canonical_exponent) {
        Ok(v) => v,
        Err(e) => return reject(AdmitRejection::ValueInvalid, format!("non-canonical exponent/value: {:?}", e), &cmd.issuer_did, &cmd.target_id),
    };

    // Stage 11: envelope bounds (i128 intermediates)
    if let ParameterKind::Range { min, max } = &spec.kind {
        match canonical.compare_with_bounds(min, max) {
            Ok(tirbase_types::fixed_point::BoundsCheck::WithinBounds) => {}
            Ok(other) => return reject(AdmitRejection::EnvelopeViolation, format!("value outside bounds: {:?}", other), &cmd.issuer_did, &cmd.target_id),
            Err(e) => return reject(AdmitRejection::ValueInvalid, format!("bounds comparison failed: {:?}", e), &cmd.issuer_did, &cmd.target_id),
        }
    } else if let ParameterKind::Bool = spec.kind {
        if canonical.mantissa != 0 && canonical.mantissa != 1 { return reject(AdmitRejection::EnvelopeViolation, "bool parameter must be 0 or 1", &cmd.issuer_did, &cmd.target_id); }
    }

    // Stage 12: cross-parameter linear constraints over pending+committed desired-state values.
    let desired = if let Ok(g)=pipeline.desired_state.read() { g.clone() } else { BTreeMap::new() };
    for c in &profile.cross_constraints {
        let mut lhs: i128 = 0;
        let mut involved = false;
        let common = c.bound.exponent;
        for (name, coeff) in &c.coefficients {
            let val = if name == &cmd.param { Some(canonical) } else { desired.get(&(cmd.target_id.as_str().to_string(), name.clone())).copied() };
            if let Some(v)=val {
                involved = true;
                let vscaled = scale_to(v.mantissa, v.exponent, common);
                let cscaled = scale_to(coeff.mantissa, coeff.exponent, common);
                lhs = lhs.saturating_add(vscaled.saturating_mul(cscaled));
            }
        }
        if involved {
            let rhs = scale_to(c.bound.mantissa, c.bound.exponent, common);
            let ok = match c.operator { ConstraintOperator::Leq => lhs <= rhs, ConstraintOperator::Geq => lhs >= rhs, ConstraintOperator::Eq => lhs == rhs };
            if !ok { return reject(AdmitRejection::ConstraintViolation, "cross-parameter linear constraint violated (pending+committed)", &cmd.issuer_did, &cmd.target_id); }
        }
    }

    // Stage 13: rate-of-change / cumulative drift
    let mono_secs = (pipeline.time_source.monotonic_now() / 1_000_000) as i64;
    let drift_key = (cmd.issuer_did.as_str().to_string(), cmd.target_id.as_str().to_string(), cmd.param.clone());
    if spec.drift_window_secs > 0 || spec.max_rate_per_sec.mantissa != 0 {
        if let Ok(mut hist) = pipeline.drift_history.lock() {
            let q = hist.entry(drift_key.clone()).or_insert_with(VecDeque::new);
            // prune
            let window = spec.drift_window_secs as i64;
            while let Some(front) = q.front() { if window > 0 && mono_secs - front.mono_secs > window { q.pop_front(); } else { break; } }
            if let Some(last) = q.back() {
                let dt = (mono_secs - last.mono_secs).max(1) as i128;
                let last_v = FixedPointValue::new(last.value_mantissa, last.exponent, last.unit_id);
                let delta = abs_scaled_diff(&canonical, &last_v);
                // rate check: delta/dt <= max_rate_per_sec (scaled conservatively)
                if spec.max_rate_per_sec.mantissa > 0 {
                    let max_rate = abs_scaled_value(&spec.max_rate_per_sec, canonical.exponent.min(spec.max_rate_per_sec.exponent));
                    let allowed = max_rate.saturating_mul(dt);
                    let dscaled = delta;
                    if dscaled > allowed { return reject(AdmitRejection::DriftExceeded, "max rate-per-second exceeded", &cmd.issuer_did, &cmd.target_id); }
                }
                // cumulative drift
                if window > 0 {
                    let mut cum: i128 = 0;
                    let mut prev = last_v;
                    let mut iter = q.iter();
                    while let Some(r) = iter.next() {
                        let v = FixedPointValue::new(r.value_mantissa, r.exponent, r.unit_id);
                        cum = cum.saturating_add(abs_scaled_diff(&v, &prev));
                        prev = v;
                    }
                    cum = cum.saturating_add(abs_scaled_diff(&canonical, &prev));
                    let max_delta = abs_scaled_value(&spec.max_delta_in_window, canonical.exponent.min(spec.max_delta_in_window.exponent));
                    if max_delta > 0 && cum > max_delta { return reject(AdmitRejection::DriftExceeded, "cumulative drift window exceeded", &cmd.issuer_did, &cmd.target_id); }
                }
            }
            if !simulate {
                let rec = DriftRecord { mono_secs, value_mantissa: canonical.mantissa, exponent: canonical.exponent, unit_id: canonical.unit_id };
                q.push_back(rec.clone());
                while q.len() > 1024 { q.pop_front(); }
                if let Ok(g)=pipeline.drift_store.read() { if let Some(store)=g.as_ref() { let _=store.record(cmd.issuer_did.as_str(), cmd.target_id.as_str(), &cmd.param, mono_secs, canonical.mantissa, canonical.exponent, canonical.unit_id); } }
            }
        }
    }

    // Stage 14: per-issuer rate limit (skip token consumption in simulate)
    let issuer_rps = pipeline.issuer_rps.load(Ordering::Relaxed) as u32;
    if !simulate && !pipeline.rate_limiters.check_issuer(cmd.issuer_did.as_str(), true, issuer_rps) {
        let retry_after_secs = if issuer_rps == 0 { 0 } else { 1 }; return reject(AdmitRejection::RateLimit, format!("per-issuer rate limit exceeded ({issuer_rps} cmd/s); retry_after_secs={retry_after_secs}"), &cmd.issuer_did, &cmd.target_id);
    }

    // Stage 15: quorum for critical parameters (co-signatures and/or pending_approvals provider)
    if spec.critical {
        let m = profile.policy_loosen_m.max(2) as usize; // conservative default for critical commands
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut ok_count = 0usize;
        let bytes = match crate::command::command_signing_bytes(cmd) { Ok(b) => b, Err(e) => return reject(AdmitRejection::InvalidSignature, e.to_string(), &cmd.issuer_did, &cmd.target_id) };
        let tr = pipeline.trust_root.load();
        for co in &cmd.co_signatures {
            if seen.contains(&co.signer_did) { continue; }
            if let tirbase_types::DeviceSignature::Ed25519(sig_bytes) = &co.signature {
                let mut verified = false;
                if let Some(tr) = tr.as_ref().as_ref() {
                    if tr.verify_role_cosignature(co.role, &co.signer_did, &bytes, &tirbase_types::DeviceSignature::Ed25519(*sig_bytes)).is_ok() {
                        verified = true;
                    }
                } else {
                    // no trust root configured: accept structurally valid DID-bound signatures by resolving did:key
                    if let Ok(pk) = tirbase_core::identity::did::resolve_did(&co.signer_did) {
                        if tirbase_core::identity::keypair::verify(&pk, &bytes, &tirbase_core::crdt::delta::Ed25519Signature::from_bytes(*sig_bytes)).is_ok() {
                            verified = true;
                        }
                    }
                }
                if verified { seen.insert(co.signer_did.clone()); ok_count += 1; }
            }
        }
        if ok_count < m {
            let provider_ok = if let Ok(g)=pipeline.quorum_provider.read() { if let Some(p)=g.as_ref() { p.has_quorum(cmd.issuer_did.as_str(), cmd.target_id.as_str(), &cmd.param, cmd.sequence_number, m).unwrap_or(false) } else { false } } else { false };
            if !provider_ok {
                return reject(AdmitRejection::QuorumRequired, format!("critical parameter requires {m} co-signatures, got {ok_count}; retry_after_secs=0"), &cmd.issuer_did, &cmd.target_id);
            }
        }
    }

    if !simulate {
        let decision = AdmitDecision::Accepted { idempotency_cache_hit: false, derived_role: claims.role };
        if let Ok(mut cache) = pipeline.decided_outcomes.lock() { cache.insert(cache_key.clone(), decision.clone()); }
        if let Ok(g)=pipeline.decided_store.read() { if let Some(store)=g.as_ref() { let _=store.store(&cache_key.0,&cache_key.1,cache_key.2,cache_key.3,&decision); } }
        return decision;
    }

    let decision = AdmitDecision::Accepted { idempotency_cache_hit: false, derived_role: claims.role };
    if simulate { AdmitDecision::Simulated { would_accept: true, rejection: None, derived_role: Some(claims.role) } } else { decision }
}

fn abs_scaled_value(v: &FixedPointValue, common_exp: i8) -> i128 {
    scale_to(v.mantissa, v.exponent, common_exp).unsigned_abs() as i128
}
fn abs_scaled_diff(a: &FixedPointValue, b: &FixedPointValue) -> i128 {
    let common = a.exponent.min(b.exponent);
    (scale_to(a.mantissa, a.exponent, common) - scale_to(b.mantissa, b.exponent, common)).unsigned_abs() as i128
}
fn value_at_common(v: &FixedPointValue, common_exp: i8) -> i128 { scale_to(v.mantissa, v.exponent, common_exp) }
fn linear_term(v: &FixedPointValue, coeff: &FixedPointValue) -> i128 {
    // compute (v * coeff) approximately in common exponent space: (m1*m2) * 10^(e1+e2-common)
    let common = v.exponent.min(coeff.exponent);
    let a = scale_to(v.mantissa, v.exponent, common);
    let b = scale_to(coeff.mantissa, coeff.exponent, common);
    a.saturating_mul(b)
}
fn scale_to(mantissa: i64, exp: i8, common: i8) -> i128 {
    let delta = (exp as i16 - common as i16).max(0) as u32;
    let mut s: i128 = 1;
    for _ in 0..delta.min(38) { s = s.saturating_mul(10); }
    (mantissa as i128).saturating_mul(s)
}
