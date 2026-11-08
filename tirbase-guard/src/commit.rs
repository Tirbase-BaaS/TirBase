//! Stage 16–19 atomic commit and dispatch (CLAIM-15.1–15.5, PV-5.1, PV-5.5,
//! PV-4.21, INV-2, INV-10, INV-11, INV-12).
//!
//! Stage 16 is one atomic commit (via [`Stage16Store`]) that performs:
//! (a) non-mutating anti-replay check, (b) non-mutating idempotency check,
//! (c) `SingleWriterLease` acquisition inside the same atomic boundary,
//! (d) anti-replay advance, (e) idempotency insert, (f) `Actuating` write,
//! plus decided-outcome cache update. Any failure rolls back all effects —
//! including idempotency/anti-replay on lease failure.
//!
//! Dispatch (Stage 18) occurs only after Stage 16 commit/fsync completes.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use tirbase_core::events::{emit, ReasonCode, SecurityEvent, SecurityEventCategory, Severity};
use tirbase_types::command::CommandMessage;

use crate::admit::AdmitRejection;
use crate::driver_proxy::DriverProxy;
use crate::permit::ActuationPermit;

/// Coarse rejection codes for issuers (PV-4.18, PV-24.1, CLAIM-15.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoarseRejection {
    EnvelopeViolation,
    AntiReplay,
    RateLimit,
    LeaseHeld,
    ValueInvalid,
    NoProfile,
    ModeLockdown,
    QuorumRequired,
    Unauthorized,
    Expired,
    ChallengeRequired,
    TargetBusy,
    Unsupported,
}

impl CoarseRejection {
    pub fn as_str(self) -> &'static str {
        match self {
            CoarseRejection::EnvelopeViolation => "ENVELOPE_VIOLATION",
            CoarseRejection::AntiReplay => "ANTI_REPLAY",
            CoarseRejection::RateLimit => "RATE_LIMIT",
            CoarseRejection::LeaseHeld => "LEASE_HELD",
            CoarseRejection::ValueInvalid => "VALUE_INVALID",
            CoarseRejection::NoProfile => "NO_PROFILE",
            CoarseRejection::ModeLockdown => "MODE_LOCKDOWN",
            CoarseRejection::QuorumRequired => "QUORUM_REQUIRED",
            CoarseRejection::Unauthorized => "UNAUTHORIZED",
            CoarseRejection::Expired => "EXPIRED",
            CoarseRejection::ChallengeRequired => "CHALLENGE_REQUIRED",
            CoarseRejection::TargetBusy => "TARGET_BUSY",
            CoarseRejection::Unsupported => "UNSUPPORTED",
        }
    }
}

pub fn coarse_for_rejection(category: AdmitRejection) -> CoarseRejection {
    match category {
        AdmitRejection::EnvelopeViolation
        | AdmitRejection::ConstraintViolation
        | AdmitRejection::DriftExceeded => CoarseRejection::EnvelopeViolation,
        AdmitRejection::RateLimit | AdmitRejection::PreAuthRateLimit => CoarseRejection::RateLimit,
        AdmitRejection::CommitConflict => CoarseRejection::AntiReplay,
        AdmitRejection::ValueInvalid => CoarseRejection::ValueInvalid,
        AdmitRejection::NoProfile => CoarseRejection::NoProfile,
        AdmitRejection::ModeLockdown => CoarseRejection::ModeLockdown,
        AdmitRejection::QuorumRequired => CoarseRejection::QuorumRequired,
        AdmitRejection::TokenInvalid
        | AdmitRejection::ScopeViolation
        | AdmitRejection::IssuerRevoked
        | AdmitRejection::InvalidSignature
        | AdmitRejection::StaleEpoch => CoarseRejection::Unauthorized,
        AdmitRejection::Expired => CoarseRejection::Expired,
        AdmitRejection::ChallengeMissing => CoarseRejection::ChallengeRequired,
        AdmitRejection::TargetBusy => CoarseRejection::TargetBusy,
        AdmitRejection::Unsupported => CoarseRejection::Unsupported,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectTerminalState {
    Complete,
    Failed,
    Unknown,
}
impl EffectTerminalState {
    pub fn as_str(&self) -> &'static str {
        match self {
            EffectTerminalState::Complete => "Complete",
            EffectTerminalState::Failed => "Failed",
            EffectTerminalState::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage16Error {
    AntiReplay,
    IdempotencyHit { original_result: String },
    LeaseHeld { holder: String },
    Store(String),
}

/// Default idempotency key retention: 24 hours (PV-5.6, CLAIM-20.5).
pub const DEFAULT_IDEMPOTENCY_RETENTION_SECS: i64 = 24 * 60 * 60;
pub const MIN_IDEMPOTENCY_RETENTION_SECS: i64 = 60;
pub const MAX_IDEMPOTENCY_RETENTION_SECS: i64 = 7 * 24 * 60 * 60;

pub fn clamp_idempotency_retention_secs(secs: i64) -> i64 {
    secs.clamp(
        MIN_IDEMPOTENCY_RETENTION_SECS,
        MAX_IDEMPOTENCY_RETENTION_SECS,
    )
}

#[derive(Debug, Clone)]
pub struct Stage16Request<'a> {
    pub cmd: &'a CommandMessage,
    pub entry_id: [u8; 16],
    pub actuating_ts: i64,
    pub now_est: i64,
    pub now_mono_secs: i64,
    pub lease_duration_secs: i64,
    pub max_consecutive_renewals: u32,
    pub original_result_json: &'a str,
    /// Idempotency retention window in seconds (CLAIM-20.5). Clamped to
    /// [1 min, 7 days]; default 24h.
    pub idempotency_retention_secs: i64,
}

/// Atomic Stage 16 store. Implementations MUST make `commit_actuating` atomic:
/// any failure (including lease acquisition) rolls back anti-replay/idempotency
/// advances and leaves no trace.
pub trait Stage16Store: Send + Sync {
    fn commit_actuating(&self, req: &Stage16Request<'_>) -> Result<(), Stage16Error>;
    fn finalize_terminal(
        &self,
        entry_id: &[u8; 16],
        target_id: &str,
        issuer_did: &str,
        state: EffectTerminalState,
        completion_ts: i64,
        driver_response: Option<&[u8]>,
    ) -> Result<(), String>;
}

/// Stage 17 caller-redacted rejection payload (CLAIM-15.3).
pub fn stage17_rejection(
    cmd: &CommandMessage,
    category: AdmitRejection,
    fine_detail: &str,
    caller_privileged: bool,
) -> serde_json::Value {
    let coarse = coarse_for_rejection(category);
    emit(
        SecurityEvent::new(
            SecurityEventCategory::CommandDecision,
            Severity::Medium,
            category.reason_code(),
        )
        .with_actor(cmd.issuer_did.as_str())
        .with_target(cmd.target_id.as_str())
        .with_detail(format!("{}: {}", coarse.as_str(), fine_detail)),
    );
    if caller_privileged {
        serde_json::json!({"status":"rejected","code":coarse.as_str(),"detail":fine_detail,"category":format!("{category:?}")})
    } else {
        serde_json::json!({"status":"rejected","code":coarse.as_str()})
    }
}

pub fn stage17_acceptance(cmd: &CommandMessage, entry_id: &[u8; 16]) {
    emit(
        SecurityEvent::new(
            SecurityEventCategory::CommandDecision,
            Severity::Low,
            ReasonCode::CommandAccepted,
        )
        .with_actor(cmd.issuer_did.as_str())
        .with_target(cmd.target_id.as_str())
        .with_detail(format!(
            "stage16_actuating_committed entry_id={}",
            hex_entry(entry_id)
        )),
    );
}

fn hex_entry(id: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(32);
    for b in id {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Stage 18+19: dispatch only after Stage 16 commit/fsync, then await driver.
pub fn dispatch_and_await<W, R, S>(
    store: &S,
    cmd: &CommandMessage,
    entry_id: [u8; 16],
    proxy: &mut DriverProxy<W>,
    frame: &[u8],
    driver_reader: &mut R,
    completion_ts: i64,
    timeout: Duration,
) -> Result<EffectTerminalState, String>
where
    W: Write + Send,
    R: Read,
    S: Stage16Store + ?Sized,
{
    // Stage 18: permit minted here (only tirbase-guard can mint), dispatch after fsync'd commit.
    let permit = ActuationPermit::new(
        cmd.target_id.clone(),
        cmd.param.clone(),
        cmd.desired_state,
        entry_id,
    );
    proxy
        .dispatch(permit, frame)
        .map_err(|e| format!("stage18 dispatch: {e}"))?;
    // Stage 19: await confirmation
    let terminal = read_driver_confirmation(driver_reader, timeout);
    store
        .finalize_terminal(
            &entry_id,
            cmd.target_id.as_str(),
            cmd.issuer_did.as_str(),
            terminal.clone(),
            completion_ts,
            None,
        )
        .map_err(|e| format!("stage19 finalize: {e}"))?;
    Ok(terminal)
}

fn read_driver_confirmation<R: Read>(reader: &mut R, timeout: Duration) -> EffectTerminalState {
    let start = Instant::now();
    let mut buf = [0u8; 128];
    // Blocking read approximation; real socketpair/timeout handled by gateway executor.
    match reader.read(&mut buf) {
        Ok(n) if n > 0 => {
            let s = String::from_utf8_lossy(&buf[..n]).to_ascii_uppercase();
            if s.contains("OK") || s.contains("COMPLETE") || s.contains("SUCCESS") {
                EffectTerminalState::Complete
            } else if s.contains("FAIL") || s.contains("ERROR") || s.contains("REJECT") {
                EffectTerminalState::Failed
            } else {
                EffectTerminalState::Unknown
            }
        }
        _ => {
            let _ = start.elapsed() >= timeout;
            EffectTerminalState::Unknown
        }
    }
}

/// Execute Stages 16–19 for an already-admitted command.
pub fn commit_dispatch_finalize<W, R, S>(
    store: &S,
    cmd: &CommandMessage,
    entry_id: [u8; 16],
    actuating_ts: i64,
    now_est: i64,
    now_mono_secs: i64,
    proxy: &mut DriverProxy<W>,
    frame: &[u8],
    driver_reader: &mut R,
    completion_ts: i64,
) -> serde_json::Value
where
    W: Write + Send,
    R: Read,
    S: Stage16Store + ?Sized,
{
    let original =
        serde_json::json!({"status":"accepted","entry_id":hex_entry(&entry_id)}).to_string();
    let req = Stage16Request {
        cmd,
        entry_id,
        actuating_ts,
        now_est,
        now_mono_secs,
        lease_duration_secs: 30,
        max_consecutive_renewals: 10,
        original_result_json: &original,
        idempotency_retention_secs: DEFAULT_IDEMPOTENCY_RETENTION_SECS,
    };
    match store.commit_actuating(&req) {
        Err(Stage16Error::LeaseHeld { holder }) => {
            let mut v = stage17_rejection(
                cmd,
                AdmitRejection::TargetBusy,
                &format!("lease held by {holder}"),
                false,
            );
            v["code"] = serde_json::json!(CoarseRejection::LeaseHeld.as_str());
            v
        }
        Err(Stage16Error::AntiReplay) => {
            let mut v =
                stage17_rejection(cmd, AdmitRejection::CommitConflict, "anti-replay", false);
            v["code"] = serde_json::json!(CoarseRejection::AntiReplay.as_str());
            v
        }
        Err(Stage16Error::IdempotencyHit { original_result }) => {
            serde_json::json!({"status":"accepted","idempotency_cache_hit":true,"original_result":original_result})
        }
        Err(Stage16Error::Store(e)) => {
            stage17_rejection(cmd, AdmitRejection::Unsupported, &e, false)
        }
        Ok(()) => {
            stage17_acceptance(cmd, &entry_id);
            match dispatch_and_await(
                store,
                cmd,
                entry_id,
                proxy,
                frame,
                driver_reader,
                completion_ts,
                Duration::from_secs(30),
            ) {
                Ok(state) => {
                    serde_json::json!({"status":"accepted","entry_id":hex_entry(&entry_id),"terminal_state":state.as_str()})
                }
                Err(e) => {
                    let _ = store.finalize_terminal(
                        &entry_id,
                        cmd.target_id.as_str(),
                        cmd.issuer_did.as_str(),
                        EffectTerminalState::Unknown,
                        completion_ts,
                        None,
                    );
                    serde_json::json!({"status":"accepted","entry_id":hex_entry(&entry_id),"terminal_state":"Unknown","dispatch_error":e})
                }
            }
        }
    }
}
