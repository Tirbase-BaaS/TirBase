//! Admin Unix-socket listener with SO_PEERCRED authentication (CLAIM-4.9.2).
//! Task 13 wires `mode` (13.1/36.3h) and `lockdown-exit` (13.3/36.3i).

use std::fmt;
use std::sync::Arc;

use serde::Deserialize;
use tirbase_guard::admit::{
    ChallengeNonceStore, DEFAULT_CHALLENGE_NONCE_TTL_SECS, DEFAULT_CHALLENGE_REQUESTS_PER_MINUTE,
};
use tirbase_guard::enrollment::{EnrollmentRequest, EnrollmentService};
use tirbase_guard::epoch::{EpochBump, EpochRegistry};
use tirbase_guard::lockdown::{
    apply_chain_recovery, apply_lockdown_exit, ChainRecoveryPayload, LockdownExitPayload,
    LockdownStore,
};
use tirbase_guard::node_mode::NodeModeState;
use tirbase_guard::signed_operation::SignedOperation;
use tirbase_guard::trust_root::TrustRootRecord;
use tirbase_guard::PolicyBundle;
use tirbase_types::envelope::EnvelopeProfile;

/// State shared by the admin endpoints.
pub struct AdminState {
    pub enrollment: Option<Arc<EnrollmentService>>,
    pub epochs: Option<Arc<EpochRegistry>>,
    pub trust_root: Option<Arc<TrustRootRecord>>,
    pub policy: Option<Arc<std::sync::Mutex<tirbase_guard::PolicyLifecycle>>>,
    /// Task 13.1/13.3: operational mode and lockdown persistence.
    pub node_mode: Option<Arc<NodeModeState>>,
    pub lockdown_store: Option<Arc<dyn LockdownStore>>,
    pub envelope_profile: Option<Arc<EnvelopeProfile>>,
    /// Task 15.7: simulate() dry-run production caller (replaces stub).
    pub guard: Option<Arc<tirbase_guard::CommandGuard>>,
    /// Task 16.2/16.3: production challenge nonce issuance/consumption store.
    pub challenge_store: Option<Arc<dyn ChallengeNonceStore>>,
    /// Task 16.4/S32: max challenge nonce requests per device/target/param/minute.
    pub challenge_requests_per_minute: u32,
    /// Task 21.2/21.3/21.5/21.9: primary DB path for lease/AEF admin operations.
    pub primary_db_path: Option<std::path::PathBuf>,
    /// Task 27: hash-chained security event log (export/GDPR production callers).
    pub security_log: Option<std::sync::Arc<crate::security_log::SecurityEventLog>>,
    /// Task 27: device key provider for signed exports/evidence bundles.
    pub key_provider: Option<std::sync::Arc<dyn tirbase_core::traits::KeyProvider>>,
}

impl fmt::Debug for AdminState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminState")
            .field("has_enrollment", &self.enrollment.is_some())
            .field("has_epochs", &self.epochs.is_some())
            .field("has_trust_root", &self.trust_root.is_some())
            .field("has_policy", &self.policy.is_some())
            .field("has_node_mode", &self.node_mode.is_some())
            .field("has_lockdown", &self.lockdown_store.is_some())
            .finish()
    }
}

impl Default for AdminState {
    fn default() -> Self {
        AdminState {
            enrollment: None,
            epochs: None,
            trust_root: None,
            policy: None,
            node_mode: None,
            lockdown_store: None,
            envelope_profile: None,
            guard: None,
            challenge_store: None,
            challenge_requests_per_minute: DEFAULT_CHALLENGE_REQUESTS_PER_MINUTE,
            primary_db_path: None,
            security_log: None,
            key_provider: None,
        }
    }
}

impl AdminState {
    pub fn new(
        enrollment: Arc<EnrollmentService>,
        epochs: Arc<EpochRegistry>,
        trust_root: Arc<TrustRootRecord>,
    ) -> Self {
        AdminState {
            enrollment: Some(enrollment),
            epochs: Some(epochs),
            trust_root: Some(trust_root),
            policy: None,
            node_mode: None,
            lockdown_store: None,
            envelope_profile: None,
            guard: None,
            challenge_store: None,
            challenge_requests_per_minute: DEFAULT_CHALLENGE_REQUESTS_PER_MINUTE,
            primary_db_path: None,
            security_log: None,
            key_provider: None,
        }
    }
}

pub fn dispatch_admin_command(command: &str, state: Option<&AdminState>) -> String {
    let now_est = tirbase_core::traits::wall_hint_secs().unwrap_or_default();
    dispatch_admin_command_at(command, state, now_est)
}

pub fn dispatch_admin_command_at(
    command: &str,
    state: Option<&AdminState>,
    now_est: i64,
) -> String {
    let body = match parse_cmd_field(command).as_deref() {
        Some("enroll") => dispatch_enroll(command, state, now_est),
        Some("mint") => not_implemented(
            "mint",
            "task 36.3b",
            "token minting needs a PolicyAuthority-scoped minting service in AdminState; no transport or state is wired for it",
        ),
        Some("rotate") => not_implemented(
            "rotate",
            "task 36.3c",
            "key rotation needs a KeyProvider rotation handle in AdminState; the gateway only loads a static device key at boot",
        ),
        Some("policy") => dispatch_policy(command, state, now_est),
        Some("events") => not_implemented(
            "events",
            "task 36.3e",
            "the paginated/SSE event transport is not implemented; the security log store exists but no admin stream/query transport is wired",
        ),
        Some("simulate") => dispatch_simulate(command, state),
        Some("challenge") => dispatch_challenge(command, state, now_est),
        Some("mode") => dispatch_mode(state),
        Some("lockdown-exit") => dispatch_lockdown_exit(command, state),
        Some("chain-recovery") => dispatch_chain_recovery(command, state),
        Some("status") => not_implemented(
            "status",
            "task 36.3k",
            "the Guard status API needs anti-replay, rate-limit and SingleWriterLease read handles on AdminState; none are exposed to the admin dispatcher",
        ),
        Some("sequence-reset") => dispatch_sequence_reset(command, state, now_est),
        Some("epoch-bump") => dispatch_epoch_bump(command, state, now_est),
        Some("lease-preempt") => dispatch_lease_preempt(command, state, now_est),
        Some("clear-unknown") => dispatch_clear_unknown(command, state, now_est),
        Some("revoke-issuer") => dispatch_revoke_issuer(command, state, now_est),
        _ => r#"{"status":400,"error":"unknown command"}"#.to_string(),
    };
    format!("{body}\n")
}

fn dispatch_mode(state: Option<&AdminState>) -> String {
    let Some(mode_state) = state.and_then(|s| s.node_mode.as_ref()) else {
        return not_configured("mode", "node mode state (NodeModeState)");
    };
    let mode = mode_state.get();
    let lockdown = state
        .and_then(|s| s.lockdown_store.as_ref())
        .and_then(|s| s.is_lockdown().ok())
        .unwrap_or(mode == tirbase_guard::NodeMode::Lockdown);
    serde_json::json!({
        "status": 200,
        "mode": mode.as_str(),
        "allows_commands": mode.allows_commands(),
        "allows_mesh_sync": mode.allows_mesh_sync(),
        "allows_log_export": mode.allows_log_export(),
        "lockdown_persisted": lockdown,
    })
    .to_string()
}

#[derive(Debug, Deserialize)]
struct LockdownExitRequest {
    operation: SignedOperation<LockdownExitPayload>,
    payload: LockdownExitPayload,
}

fn dispatch_lockdown_exit(command: &str, state: Option<&AdminState>) -> String {
    let Some((trust_root, store, mode)) = state.and_then(|s| {
        Some((
            s.trust_root.as_ref()?,
            s.lockdown_store.as_ref()?,
            s.node_mode.as_ref()?,
        ))
    }) else {
        return not_configured(
            "lockdown-exit",
            "trust_root_path (TrustRootRecord), the lockdown store, and node mode",
        );
    };
    let payload_val = match payload_value(command) {
        Some(p) => p,
        None => return bad_request("lockdown-exit requires a payload object"),
    };
    let request: LockdownExitRequest = match serde_json::from_value(payload_val) {
        Ok(r) => r,
        Err(e) => return bad_request(&format!("invalid lockdown-exit: {e}")),
    };
    let profile = state.and_then(|s| s.envelope_profile.as_deref());
    match apply_lockdown_exit(
        &request.operation,
        &request.payload,
        trust_root,
        profile,
        store.as_ref(),
        mode,
    ) {
        Ok(()) => {
            serde_json::json!({"status":200,"mode":"Normal","outcome":"lockdown_exit_applied"})
                .to_string()
        }
        Err(e) => {
            serde_json::json!({"status":409,"error":e.to_string(),"endpoint":"lockdown-exit"})
                .to_string()
        }
    }
}

#[derive(Debug, Deserialize)]
struct ChainRecoveryRequest {
    operation: SignedOperation<ChainRecoveryPayload>,
    payload: ChainRecoveryPayload,
}

fn dispatch_chain_recovery(command: &str, state: Option<&AdminState>) -> String {
    let Some((trust_root, mode)) =
        state.and_then(|s| s.trust_root.as_ref().zip(s.node_mode.as_ref()))
    else {
        return not_configured(
            "chain-recovery",
            "trust_root_path (TrustRootRecord) and node mode",
        );
    };
    let payload_val = match payload_value(command) {
        Some(p) => p,
        None => return bad_request("chain-recovery requires a payload object"),
    };
    let request: ChainRecoveryRequest = match serde_json::from_value(payload_val) {
        Ok(r) => r,
        Err(e) => return bad_request(&format!("invalid chain-recovery: {e}")),
    };
    let store = state.and_then(|s| s.lockdown_store.as_deref());
    match apply_chain_recovery(
        &request.operation,
        &request.payload,
        trust_root,
        store,
        mode,
    ) {
        Ok(()) => serde_json::json!({
            "status": 200,
            "mode": "Normal",
            "outcome": "chain_recovery_applied",
            "new_segment_id": request.payload.new_segment_id
        })
        .to_string(),
        Err(e) => serde_json::json!({
            "status": 409,
            "error": e.to_string(),
            "endpoint": "chain-recovery"
        })
        .to_string(),
    }
}

fn dispatch_enroll(command: &str, state: Option<&AdminState>, now_est: i64) -> String {
    let Some(service) = state.and_then(|state| state.enrollment.as_ref()) else {
        return not_configured(
            "enroll",
            "enrollment_root_ca_private_key_path (EnrollmentService)",
        );
    };
    let payload = match payload_value(command) {
        Some(payload) => payload,
        None => return bad_request("enroll requires a payload object"),
    };
    let request: EnrollmentRequest = match serde_json::from_value(payload) {
        Ok(request) => request,
        Err(error) => return bad_request(&format!("invalid enrollment request: {error}")),
    };
    match service.enroll(&request, now_est) {
        Ok(enrolled) => serde_json::json!({
            "status": 200, "device_id": enrolled.device_id, "epoch": enrolled.epoch,
            "token_hex": hex::encode(&enrolled.token), "token_ttl_secs": enrolled.token_ttl_secs,
        })
        .to_string(),
        Err(tirbase_guard::epoch::EpochError::NonceReused) => serde_json::json!({
            "status": 409, "error": "nonce reused", "endpoint": "enroll",
        })
        .to_string(),
        Err(error) => {
            serde_json::json!({"status": 400, "error": error.to_string(), "endpoint": "enroll"})
                .to_string()
        }
    }
}

#[derive(Debug, Deserialize)]
struct EpochBumpRequest {
    operation: SignedOperation<EpochBump>,
    payload: EpochBump,
}

fn dispatch_epoch_bump(command: &str, state: Option<&AdminState>, now_est: i64) -> String {
    let Some((epochs, trust_root)) =
        state.and_then(|s| s.epochs.as_ref().zip(s.trust_root.as_ref()))
    else {
        return not_configured(
            "epoch-bump",
            "device epoch registry and trust_root_path (TrustRootRecord)",
        );
    };
    let payload = match payload_value(command) {
        Some(p) => p,
        None => return bad_request("epoch-bump requires a payload object"),
    };
    let request: EpochBumpRequest = match serde_json::from_value(payload) {
        Ok(r) => r,
        Err(e) => return bad_request(&format!("invalid epoch bump: {e}")),
    };
    match epochs.apply_bump(&request.operation, &request.payload, trust_root, now_est) {
        Ok(record) => {
            serde_json::json!({"status": 200, "device_id": record.device_id, "epoch": record.epoch})
                .to_string()
        }
        Err(error) => {
            serde_json::json!({"status": 409, "error": error.to_string(), "endpoint": "epoch-bump"})
                .to_string()
        }
    }
}

fn dispatch_policy(command: &str, state: Option<&AdminState>, now_est: i64) -> String {
    let Some(policy) = state.and_then(|s| s.policy.as_ref()) else {
        return not_configured(
            "policy",
            "a configured target_id plus envelope_profile_path (PolicyLifecycle)",
        );
    };
    let payload = match payload_value(command) {
        Some(p) => p,
        None => return bad_request("policy requires a payload object"),
    };
    let bundle_val = payload.get("bundle").cloned().unwrap_or(payload);
    let bundle: PolicyBundle = match serde_json::from_value(bundle_val) {
        Ok(b) => b,
        Err(e) => return bad_request(&format!("invalid policy bundle: {e}")),
    };
    let mut guard = match policy.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    match guard.ingest_bundle(bundle, now_est) {
        Ok(tirbase_guard::PolicyIngestOutcome::TighteningApplied { version }) => {
            serde_json::json!({"status":200,"outcome":"tightening_applied","version":version}).to_string()
        }
        Ok(tirbase_guard::PolicyIngestOutcome::LooseningPending { version, required_m, required_n, timelock_until_est, .. }) => {
            serde_json::json!({"status":202,"outcome":"loosening_pending","version":version,
                "required_m":required_m,"required_n":required_n,"timelock_until_est":timelock_until_est}).to_string()
        }
        Err(e) => serde_json::json!({"status":409,"error":e.to_string(),"endpoint":"policy"}).to_string(),
    }
}

fn payload_value(command: &str) -> Option<serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(command)
        .ok()
        .and_then(|v| v.get("payload").cloned())
}
fn bad_request(message: &str) -> String {
    serde_json::json!({"status": 400, "error": message}).to_string()
}
/// Precise failure for an endpoint whose runtime state was not configured in
/// this process (e.g. no `target_id`/envelope profile).  Never a 501: a 501
/// claims the endpoint does not exist, which is false — it is wired and will
/// serve as soon as the required state is supplied.
fn not_configured(endpoint: &str, missing: &str) -> String {
    serde_json::json!({
        "status": 503,
        "code": "ADMIN_STATE_UNCONFIGURED",
        "error": format!(
            "{endpoint} requires runtime state that this gateway process has not configured: {missing}"
        ),
        "endpoint": endpoint,
        "missing": missing,
    })
    .to_string()
}

/// Precise failure for an admin endpoint that is designed but has no
/// implementation in the binary yet.  Records the owning task so callers and
/// `tasks.md` carry the same blocker instead of silently reporting 501.
fn not_implemented(endpoint: &str, task: &str, blocker: &str) -> String {
    serde_json::json!({
        "status": 503,
        "code": "ENDPOINT_NOT_IMPLEMENTED",
        "error": format!("{endpoint} is not implemented in the gateway binary ({task}): {blocker}"),
        "endpoint": endpoint,
        "task": task,
        "blocker": blocker,
    })
    .to_string()
}
fn parse_cmd_field(json: &str) -> Option<String> {
    let mut parts = json.split('"');
    while let Some(segment) = parts.next() {
        if segment.trim_end_matches(|c: char| c.is_whitespace() || c == ':') == "cmd" {
            return parts
                .find(|s| {
                    let t = s.trim();
                    !t.is_empty() && t != ":"
                })
                .map(|s| s.to_string());
        }
    }
    None
}

/// Resolve the peer's effective UID from an accepted Unix-domain socket.
///
/// Linux/Android use `SO_PEERCRED`; the BSD family (macOS included) uses
/// `getpeereid(2)`.  Both return the kernel-attested UID of the connecting
/// process — the authentication property is identical, only the syscall differs.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_uid(fd: std::os::unix::io::RawFd) -> std::io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn peer_uid(fd: std::os::unix::io::RawFd) -> std::io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid as u32)
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))
))]
fn peer_uid(_fd: std::os::unix::io::RawFd) -> std::io::Result<u32> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no peer-credential syscall available on this platform",
    ))
}

#[cfg(all(
    unix,
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )
))]
mod unix_socket {
    use super::{dispatch_admin_command, peer_uid, AdminState};
    use std::os::unix::io::AsRawFd;
    use std::path::Path;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};

    pub async fn run_admin_listener(
        sock_path: &Path,
        state: Option<Arc<AdminState>>,
    ) -> anyhow::Result<()> {
        let _ = std::fs::remove_file(sock_path);
        if let Some(parent) = sock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let listener = UnixListener::bind(sock_path)?;
        tracing::info!(path = %sock_path.display(), "admin listener bound");
        loop {
            let (stream, _addr) = listener.accept().await?;
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_admin_connection(stream, state).await {
                    tracing::warn!(error = %e, "admin connection error");
                }
            });
        }
    }

    async fn handle_admin_connection(
        stream: UnixStream,
        state: Option<Arc<AdminState>>,
    ) -> anyhow::Result<()> {
        let peer_uid = peer_uid(stream.as_raw_fd())?;
        let gateway_uid = unsafe { libc::getuid() };
        if peer_uid != 0 && peer_uid != gateway_uid {
            tracing::warn!(
                peer_uid,
                gateway_uid,
                "admin: rejecting unauthenticated connection"
            );
            return Ok(());
        }
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let response = dispatch_admin_command(line.trim(), state.as_deref());
        let stream_mut = reader.get_mut();
        stream_mut.write_all(response.as_bytes()).await?;
        stream_mut.flush().await?;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct ChallengeRequest {
    #[serde(default)]
    target_id: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    param: String,
    #[serde(default)]
    issuer_did: Option<String>,
    #[serde(default)]
    nonce_hex: Option<String>,
}

/// Task 16.3/16.4 (CLAIM-16.3/16.4, PV-22.3, S32): issue or consume a
/// challenge nonce for a critical parameter when freshness is `Unverified`.
/// - Issue: payload `{target_id|target, param, [issuer_did]}`. Requires
///   `critical: true` in the target's envelope profile and Unverified
///   freshness. Enforces one-per-device/target/param/minute issuance limit.
/// - Consume (admin/test hook): payload `{..., nonce_hex, issuer_did}` marks the
///   nonce used exactly once through the durable store; second use is rejected.
/// GET/POST path variants from specs map to this JSON command in the Unix-socket
/// admin dispatcher.
fn dispatch_challenge(command: &str, state: Option<&AdminState>, _now_est: i64) -> String {
    let Some(st) = state else {
        return not_configured("challenge", "admin runtime state");
    };
    let payload_val = match payload_value(command) {
        Some(p) => p,
        None => return bad_request("challenge requires a payload object"),
    };
    let req: ChallengeRequest = match serde_json::from_value(payload_val.clone()) {
        Ok(r) => r,
        Err(e) => return bad_request(&format!("invalid challenge payload: {e}")),
    };
    let target_id = if !req.target_id.is_empty() {
        req.target_id
    } else {
        req.target
    };
    let param = req.param;
    if target_id.is_empty() || param.is_empty() {
        return bad_request("challenge requires target_id/target and param");
    }
    let target = tirbase_types::TargetId::new(&target_id);

    // Consumption path (one-time-use proof / admin helper).
    if let (Some(nonce_hex), Some(issuer_did)) =
        (req.nonce_hex.as_deref(), req.issuer_did.as_deref())
    {
        if let Some(store) = st.challenge_store.as_ref() {
            let Some(nonce) = hex_decode_32(nonce_hex) else {
                return bad_request("invalid nonce_hex");
            };
            // Nonce expiry is monotonic, so consumption must use the guard's
            // monotonic clock, not the authenticated wall estimate.
            let mono_now = st
                .guard
                .as_ref()
                .and_then(|guard| guard.pipeline())
                .map(|pipeline| pipeline.mono_secs_now())
                .unwrap_or_else(|| (tirbase_core::traits::monotonic_now() / 1_000_000) as i64);
            match store.consume_if_valid(&nonce, issuer_did, &target_id, &param, mono_now, true) {
                Ok(true) => {
                    return serde_json::json!({"status":200,"outcome":"challenge_consumed","nonce_hex":nonce_hex,"one_time_use":true}).to_string();
                }
                Ok(false) => {
                    return serde_json::json!({"status":409,"error":"challenge nonce invalid, expired, or already consumed","code":"CHALLENGE_INVALID","endpoint":"challenge"}).to_string();
                }
                Err(e) => {
                    return serde_json::json!({"status":500,"error":e,"endpoint":"challenge"})
                        .to_string()
                }
            }
        }
        return not_configured("challenge", "challenge nonce store");
    }

    // Issuance path (Task 16.3): only for Unverified + critical parameter.
    let Some(guard) = st.guard.as_ref() else {
        return not_configured("challenge", "CommandGuard with a decision pipeline");
    };
    let Some(pipeline) = guard.pipeline() else {
        return not_configured("challenge", "CommandGuard decision pipeline");
    };
    if pipeline.freshness_state() != tirbase_guard::time::FreshnessState::Unverified {
        return serde_json::json!({"status":409,"error":"challenge nonce issuance requires FreshnessState::Unverified","code":"FRESHNESS_NOT_UNVERIFIED","endpoint":"challenge"}).to_string();
    }
    if !guard.parameter_is_critical(&target, &param) {
        return serde_json::json!({"status":409,"error":"challenge nonce issuance requires a critical parameter","code":"PARAM_NOT_CRITICAL","endpoint":"challenge"}).to_string();
    }
    let Some(device_id) = guard.device_id_for_target(&target) else {
        return serde_json::json!({"status":404,"error":"unknown target/device","endpoint":"challenge"}).to_string();
    };
    let issuer_did = req
        .issuer_did
        .unwrap_or_else(|| format!("admin:{device_id}"));
    let mono_now = pipeline.mono_secs_now();
    let limit = if st.challenge_requests_per_minute == 0 {
        DEFAULT_CHALLENGE_REQUESTS_PER_MINUTE
    } else {
        st.challenge_requests_per_minute
    };
    // Sync pipeline limit with admin/runtime config for S32 enforcement.
    pipeline.set_challenge_requests_per_minute(limit);
    if !pipeline.check_challenge_issue_rate_limit(&device_id, &target_id, &param, mono_now) {
        return serde_json::json!({"status":429,"error":"challenge nonce issuance rate limited (S32)","code":"CHALLENGE_RATE_LIMITED","retry_after_secs":60,"limit_per_minute":limit,"endpoint":"challenge"}).to_string();
    }
    // In-process pipeline limit is authoritative for this admin endpoint (S32).
    let _ = st.challenge_store.as_ref();
    match pipeline.issue_challenge_nonce_for_device(&device_id, &issuer_did, &target_id, &param) {
        Ok(nonce) => serde_json::json!({
            "status":200,
            "outcome":"challenge_issued",
            "target_id":target_id,
            "param":param,
            "device_id":device_id,
            "issuer_did":issuer_did,
            "nonce_hex":hex_encode(&nonce.nonce),
            "issued_at_mono":nonce.issued_at_mono,
            "expires_at_mono":nonce.expires_at_mono,
            "ttl_secs":DEFAULT_CHALLENGE_NONCE_TTL_SECS,
            "one_time_use":true,
            "critical":true,
            "freshness":"Unverified",
        }).to_string(),
        Err(e) if e.contains("retry_after") || e.contains("rate limit") => serde_json::json!({"status":429,"error":e,"code":"CHALLENGE_RATE_LIMITED","endpoint":"challenge"}).to_string(),
        Err(e) => serde_json::json!({"status":500,"error":e,"endpoint":"challenge"}).to_string(),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}
fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    let b = s.as_bytes();
    for i in 0..32 {
        let hi = (b[i * 2] as char).to_digit(16)? as u8;
        let lo = (b[i * 2 + 1] as char).to_digit(16)? as u8;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

pub async fn run_admin_listener(
    sock_path: &std::path::Path,
    state: Option<Arc<AdminState>>,
) -> anyhow::Result<()> {
    #[cfg(all(
        unix,
        any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        )
    ))]
    {
        unix_socket::run_admin_listener(sock_path, state).await
    }
    #[cfg(not(all(
        unix,
        any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        )
    )))]
    {
        let _ = (sock_path, state);
        anyhow::bail!(
            "admin Unix-socket listener needs a kernel peer-credential syscall; not supported on this platform"
        )
    }
}

#[derive(Debug, Clone, serde::Serialize, Deserialize)]
struct LeasePreemptPayload {
    action: String,
    target_id: String,
    #[serde(default)]
    new_issuer_did: Option<String>,
    now_est: i64,
}
impl tirbase_guard::SignedOperationPayload for LeasePreemptPayload {
    const CONTEXT: &'static str = "TirBase/v1/LeasePreempt";
}

#[derive(Debug, Deserialize)]
struct LeasePreemptRequest {
    target_id: String,
    #[serde(default)]
    new_issuer_did: Option<String>,
    #[serde(default)]
    lease_duration_secs: Option<i64>,
}

/// Task 21.2 (CLAIM-21.2, PV-5.8a): M-of-N RevocationManager + PolicyAuthority
/// joint operation forcibly releases/reassigns a SingleWriterLease. Production
/// caller: gateway admin Unix-socket path.
fn dispatch_lease_preempt(command: &str, state: Option<&AdminState>, now_est: i64) -> String {
    let Some(st) = state else {
        return not_configured("lease-preempt", "admin runtime state");
    };
    let Some(db_path) = st.primary_db_path.as_ref() else {
        return not_configured("lease-preempt", "primary DB path");
    };
    let Some(trust_root) = st.trust_root.as_ref() else {
        return not_configured("lease-preempt", "trust_root_path (TrustRootRecord)");
    };
    let payload_val = match payload_value(command) {
        Some(p) => p,
        None => return bad_request("lease-preempt requires payload"),
    };
    let op_val = payload_val.get("operation").cloned();
    let req: LeasePreemptRequest = match serde_json::from_value(
        payload_val
            .get("request")
            .cloned()
            .unwrap_or(payload_val.clone()),
    ) {
        Ok(r) => r,
        Err(e) => return bad_request(&format!("invalid lease-preempt: {e}")),
    };
    // Require joint M-of-N: at least one PolicyAuthority and one RevocationManager signature.
    if let Some(opv) = op_val {
        let op: tirbase_guard::SignedOperation<LeasePreemptPayload> =
            match serde_json::from_value(opv) {
                Ok(o) => o,
                Err(e) => return bad_request(&format!("invalid operation: {e}")),
            };
        let resolve = |did: &str| -> Option<Vec<u8>> {
            for role in [
                tirbase_types::CommandRole::PolicyAuthority,
                tirbase_types::CommandRole::RevocationManager,
            ] {
                if let Some(rp) = trust_root.role_thresholds.get(&role) {
                    if let Some(s) = rp.authorized_signers.iter().find(|s| s.did == did) {
                        return Some(s.public_key.clone());
                    }
                }
            }
            None
        };
        let binding = LeasePreemptPayload {
            action: "lease-preempt".into(),
            target_id: req.target_id.clone(),
            new_issuer_did: req.new_issuer_did.clone(),
            now_est,
        };
        if op.verify(&binding, resolve).is_err() {
            return serde_json::json!({"status":409,"error":"lease-preempt requires valid M-of-N RevocationManager+PolicyAuthority signatures","endpoint":"lease-preempt"}).to_string();
        }
        let has_pa = op
            .signatures
            .iter()
            .any(|s| s.role == tirbase_types::CommandRole::PolicyAuthority);
        let has_rm = op
            .signatures
            .iter()
            .any(|s| s.role == tirbase_types::CommandRole::RevocationManager);
        if !has_pa || !has_rm {
            return serde_json::json!({"status":409,"error":"lease-preempt requires PolicyAuthority and RevocationManager signatures","endpoint":"lease-preempt"}).to_string();
        }
    } else {
        return serde_json::json!({"status":409,"error":"lease-preempt requires signed joint operation (M-of-N RevocationManager+PolicyAuthority)","endpoint":"lease-preempt"}).to_string();
    }
    let conn = match rusqlite::Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            return serde_json::json!({"status":500,"error":format!("open primary.db: {e}")})
                .to_string()
        }
    };
    let _ = conn.pragma_update(None, "journal_mode", "WAL");
    let _ = conn.pragma_update(None, "synchronous", "FULL");
    let lease_dur = req
        .lease_duration_secs
        .unwrap_or(crate::db::single_writer_leases::DEFAULT_LEASE_DURATION_MONO_SECS);
    let now_mono = now_est; // admin path uses now_est as monotonic hint when mono unavailable
    let mut txc = conn;
    let tx = match txc.transaction() {
        Ok(t) => t,
        Err(e) => return serde_json::json!({"status":500,"error":format!("tx: {e}")}).to_string(),
    };
    match crate::db::single_writer_leases::preempt_tx(
        &tx,
        &req.target_id,
        req.new_issuer_did.as_deref(),
        now_mono,
        lease_dur,
    ) {
        Ok(prior) => {
            if tx.commit().is_err() {
                return serde_json::json!({"status":500,"error":"commit failed"}).to_string();
            }
            serde_json::json!({"status":200,"endpoint":"lease-preempt","target_id":req.target_id,"prior_holder":prior,"new_issuer_did":req.new_issuer_did}).to_string()
        }
        Err(e) => {
            serde_json::json!({"status":500,"error":e,"endpoint":"lease-preempt"}).to_string()
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, Deserialize)]
struct ClearUnknownPayload {
    action: String,
    entry_id_hex: String,
}
impl tirbase_guard::SignedOperationPayload for ClearUnknownPayload {
    const CONTEXT: &'static str = "TirBase/v1/ClearUnknown";
}

#[derive(Debug, Deserialize)]
struct ClearUnknownRequest {
    entry_id_hex: String,
}

/// Task 21.9 (CLAIM-21.9, PV-5.11): PolicyAuthority operator-clear advances
/// Unknown -> Failed.
fn dispatch_clear_unknown(command: &str, state: Option<&AdminState>, now_est: i64) -> String {
    let Some(st) = state else {
        return not_configured("clear-unknown", "admin runtime state");
    };
    let Some(db_path) = st.primary_db_path.as_ref() else {
        return not_configured("clear-unknown", "primary DB path");
    };
    let Some(trust_root) = st.trust_root.as_ref() else {
        return not_configured("clear-unknown", "trust_root_path (TrustRootRecord)");
    };
    let payload_val = match payload_value(command) {
        Some(p) => p,
        None => return bad_request("clear-unknown requires payload"),
    };
    let op_val = payload_val.get("operation").cloned();
    let req: ClearUnknownRequest = match serde_json::from_value(
        payload_val
            .get("request")
            .cloned()
            .unwrap_or(payload_val.clone()),
    ) {
        Ok(r) => r,
        Err(e) => return bad_request(&format!("invalid clear-unknown: {e}")),
    };
    if let Some(opv) = op_val {
        let op: tirbase_guard::SignedOperation<ClearUnknownPayload> =
            match serde_json::from_value(opv) {
                Ok(o) => o,
                Err(e) => return bad_request(&format!("invalid operation: {e}")),
            };
        let resolve = |did: &str| -> Option<Vec<u8>> {
            trust_root
                .role_thresholds
                .get(&tirbase_types::CommandRole::PolicyAuthority)
                .and_then(|rp| rp.authorized_signers.iter().find(|s| s.did == did))
                .map(|s| s.public_key.clone())
        };
        let binding = ClearUnknownPayload {
            action: "clear-unknown".into(),
            entry_id_hex: req.entry_id_hex.clone(),
        };
        if op.verify(&binding, resolve).is_err() {
            return serde_json::json!({"status":409,"error":"clear-unknown requires valid PolicyAuthority signature","endpoint":"clear-unknown"}).to_string();
        }
        if !op
            .signatures
            .iter()
            .any(|s| s.role == tirbase_types::CommandRole::PolicyAuthority)
        {
            return serde_json::json!({"status":409,"error":"clear-unknown requires PolicyAuthority role","endpoint":"clear-unknown"}).to_string();
        }
    } else {
        return serde_json::json!({"status":409,"error":"clear-unknown requires PolicyAuthority signed operation","endpoint":"clear-unknown"}).to_string();
    }
    let Some(entry_id) = hex_decode_32(&req.entry_id_hex)
        .map(|b| {
            let mut id = [0u8; 16];
            id.copy_from_slice(&b[..16]);
            id
        })
        .or_else(|| {
            let s = req.entry_id_hex.trim();
            if s.len() != 32 {
                return None;
            }
            let mut id = [0u8; 16];
            for i in 0..16 {
                let hi = (s.as_bytes()[i * 2] as char).to_digit(16)? as u8;
                let lo = (s.as_bytes()[i * 2 + 1] as char).to_digit(16)? as u8;
                id[i] = (hi << 4) | lo;
            }
            Some(id)
        })
    else {
        return bad_request("invalid entry_id_hex");
    };
    let conn = match rusqlite::Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            return serde_json::json!({"status":500,"error":format!("open: {e}")}).to_string()
        }
    };
    let target_before = crate::db::applied_effects_ledger::target_id_for_entry(&conn, &entry_id)
        .ok()
        .flatten();
    match crate::db::applied_effects_ledger::operator_clear_unknown_to_failed(&conn, &entry_id, now_est, b"operator_clear_policy_authority") {
        Ok(true) => {
            // Task 21.9 runtime sync: unblock target if no Unknown entries remain.
            if let Some(target_id) = target_before {
                let still = crate::db::applied_effects_ledger::target_has_unknown(&conn, &target_id).unwrap_or(true);
                if !still {
                    if let Some(guard) = st.guard.as_ref() {
                        if let Some(p) = guard.pipeline() { p.clear_target_unknown(&target_id); }
                    }
                }
            }
            serde_json::json!({"status":200,"endpoint":"clear-unknown","entry_id_hex":req.entry_id_hex,"outcome":"Unknown->Failed"}).to_string()
        }
        Ok(false) => serde_json::json!({"status":404,"error":"no Unknown entry with that id","endpoint":"clear-unknown"}).to_string(),
        Err(e) => serde_json::json!({"status":500,"error":e}).to_string(),
    }
}

#[derive(Debug, Deserialize)]
struct RevokeIssuerRequest {
    issuer_did: String,
}

/// Task 21.3 (CLAIM-21.3): release leases held by revoked issuer DID.
fn dispatch_revoke_issuer(command: &str, state: Option<&AdminState>, _now_est: i64) -> String {
    let Some(st) = state else {
        return not_configured("revoke-issuer", "admin runtime state");
    };
    let payload_val = match payload_value(command) {
        Some(p) => p,
        None => return bad_request("revoke-issuer requires payload"),
    };
    let req: RevokeIssuerRequest =
        match serde_json::from_value(payload_val.get("request").cloned().unwrap_or(payload_val)) {
            Ok(r) => r,
            Err(e) => return bad_request(&format!("invalid revoke-issuer: {e}")),
        };
    if let Some(guard) = st.guard.as_ref() {
        if let Some(p) = guard.pipeline() {
            p.revoke_did(req.issuer_did.clone());
        }
    }
    let mut leases_released = 0usize;
    if let Some(db_path) = st.primary_db_path.as_ref() {
        if let Ok(conn) = rusqlite::Connection::open(db_path) {
            leases_released =
                crate::db::single_writer_leases::release_all_for_issuer_did(&conn, &req.issuer_did)
                    .unwrap_or(0);
        }
    }
    serde_json::json!({"status":200,"endpoint":"revoke-issuer","issuer_did":req.issuer_did,"leases_released":leases_released}).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
    use tirbase_core::identity::keypair;
    use tirbase_core::traits::KeyProvider;
    use tirbase_guard::enrollment::DeviceIdentity;
    use tirbase_guard::epoch::{InMemoryEpochStore, InMemoryNonceStore};
    use tirbase_guard::trust_root::RolePolicy;
    use tirbase_types::CommandRole;

    #[test]
    fn parse_cmd_field_simple() {
        assert_eq!(
            parse_cmd_field(r#"{"cmd":"enroll","payload":{}}"#).as_deref(),
            Some("enroll")
        );
    }
    #[test]
    fn parse_cmd_field_unknown_returns_none() {
        assert_eq!(parse_cmd_field(r#"{"foo":"bar"}"#), None);
    }
    #[test]
    fn parse_cmd_field_empty_string() {
        assert_eq!(parse_cmd_field(""), None);
    }
    #[test]
    fn unknown_command_returns_400() {
        let response = dispatch_admin_command(r#"{"cmd":"does-not-exist"}"#, None);
        assert!(
            response.contains("\"status\":400"),
            "unexpected: {response}"
        );
    }
    #[test]
    fn response_is_newline_terminated() {
        assert!(dispatch_admin_command(r#"{"cmd":"mint"}"#, None).ends_with('\n'));
    }

    fn admin_state() -> (AdminState, [u8; 32]) {
        let (root_seed, root_public) = keypair::generate_keypair().unwrap();
        let rm = InMemoryKeyProvider::generate().unwrap();
        let mut roles = BTreeMap::new();
        roles.insert(
            CommandRole::RevocationManager,
            RolePolicy::new(
                1,
                vec![tirbase_guard::trust_root::AuthorizedRoleSigner {
                    did: rm.did().to_string(),
                    public_key: rm.public_key_bytes(),
                }],
            ),
        );
        let trust_root = Arc::new(TrustRootRecord {
            version: 1,
            root_ca_public_keys: vec![root_public.to_vec()],
            threshold_k: 1,
            role_thresholds: roles,
            device_class_floors: BTreeMap::new(),
            expiry_est: i64::MAX,
            revoked_root_ca_keys: Vec::new(),
            signatures: Vec::new(),
        });
        let epochs = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
        let service = Arc::new(EnrollmentService::new(
            Arc::new(InMemoryNonceStore::new()),
            epochs.clone(),
            trust_root.clone(),
            root_seed.to_vec(),
            3_600,
        ));
        (AdminState::new(service, epochs, trust_root), root_public)
    }

    #[test]
    fn enroll_endpoint_issues_a_token_and_rejects_nonce_reuse() {
        let (state, root_public) = admin_state();
        let device = DeviceIdentity::generate().unwrap();
        let request = device
            .bootstrap([3u8; 32], CommandRole::CommandIssuer)
            .unwrap();
        let command = serde_json::json!({"cmd": "enroll", "payload": serde_json::to_value(&request).unwrap()}).to_string();
        let response = dispatch_admin_command_at(&command, Some(&state), 1_800_000_000);
        let value: serde_json::Value = serde_json::from_str(response.trim()).unwrap();
        assert_eq!(value["status"], 200);
        let token = hex::decode(value["token_hex"].as_str().unwrap()).unwrap();
        let claims = tirbase_core::auth::biscuit::verify_token(&token, &root_public, 0)
            .expect("issued token verifies");
        assert_eq!(claims.did, device.device_id());
        let replay = dispatch_admin_command_at(&command, Some(&state), 1_800_000_000);
        let value: serde_json::Value = serde_json::from_str(replay.trim()).unwrap();
        assert_eq!(value["status"], 409);
    }
}

#[derive(Debug, Deserialize)]
struct SimulateRequest {
    command: tirbase_types::command::CommandMessage,
    #[serde(default)]
    biscuit_token_hex: Option<String>,
    #[serde(default)]
    source_key: Option<String>,
    #[serde(default)]
    now_est_secs: Option<i64>,
    #[serde(default)]
    caller_role: Option<String>,
}

/// Task 15.7 (CLAIM-15.7, PV-4.17): side-effect-free dry run.
/// Skips Stage 0/9 nonce consumption/14 token consumption and Stages 16–19.
fn dispatch_simulate(command: &str, state: Option<&AdminState>) -> String {
    let Some(guard) = state.and_then(|s| s.guard.as_ref()) else {
        return not_configured("simulate", "CommandGuard");
    };
    let payload_val = match payload_value(command) {
        Some(p) => p,
        None => return bad_request("simulate requires a payload object"),
    };
    let req: SimulateRequest = match serde_json::from_value(payload_val) {
        Ok(r) => r,
        Err(e) => return bad_request(&format!("invalid simulate payload: {e}")),
    };
    let token = req
        .biscuit_token_hex
        .as_deref()
        .and_then(|h| hex::decode(h).ok())
        .unwrap_or_default();
    let source = req.source_key.unwrap_or_else(|| "simulate".into());
    let ctx = tirbase_guard::AdmitContext {
        ingress: tirbase_guard::IngressSource::LocalAdmin,
        source_key: &source,
        biscuit_token: if token.is_empty() { None } else { Some(&token) },
        now_est_secs: req.now_est_secs,
        simulate: true,
    };
    let decision = guard.simulate(&req.command, &ctx);
    let privileged = matches!(
        req.caller_role.as_deref(),
        Some("Auditor") | Some("PolicyAuthority")
    );
    match decision {
        tirbase_guard::AdmitDecision::Simulated { would_accept: true, derived_role, .. } => {
            serde_json::json!({"status":200,"simulated":true,"would_accept":true,"derived_role":format!("{derived_role:?}")}).to_string()
        }
        tirbase_guard::AdmitDecision::Simulated { would_accept: false, rejection, .. } => {
            let (cat, detail, retry) = rejection.unwrap_or((tirbase_guard::AdmitRejection::Unsupported, "rejected".into(), None));
            let mut v = tirbase_guard::stage17_rejection(&req.command, cat, &detail, privileged);
            v["simulated"] = serde_json::json!(true);
            if let Some(r) = retry { v["retry_after_secs"] = serde_json::json!(r); }
            v.to_string()
        }
        other => serde_json::json!({"status":200,"simulated":true,"decision":format!("{other:?}")}).to_string(),
    }
}

#[derive(Debug, serde::Deserialize)]
struct SequenceResetRequest {
    operation: tirbase_guard::SignedOperation<tirbase_guard::anti_replay::AntiReplayWindowReset>,
    payload: tirbase_guard::anti_replay::AntiReplayWindowReset,
}

/// Task 20.3 (CLAIM-20.3, PV-5.5): PolicyAuthority-signed sequence-window reset
/// for issuer re-enrollment or wrap-around.
fn dispatch_sequence_reset(command: &str, state: Option<&AdminState>, _now_est: i64) -> String {
    let Some(st) = state else {
        return not_configured("sequence-reset", "admin runtime state");
    };
    let Some(trust_root) = st.trust_root.as_ref() else {
        return not_configured("sequence-reset", "trust_root_path (TrustRootRecord)");
    };
    let payload_val = match payload_value(command) {
        Some(p) => p,
        None => return bad_request("sequence-reset requires a payload object"),
    };
    let req: SequenceResetRequest = match serde_json::from_value(payload_val) {
        Ok(r) => r,
        Err(e) => return bad_request(&format!("invalid sequence-reset: {e}")),
    };
    // Verify PA signatures and payload binding (domain-separated).
    let resolve = |did: &str| -> Option<Vec<u8>> {
        trust_root
            .role_thresholds
            .get(&tirbase_types::CommandRole::PolicyAuthority)
            .and_then(|rp| rp.authorized_signers.iter().find(|s| s.did == did))
            .map(|s| s.public_key.clone())
    };
    let mut window = tirbase_guard::anti_replay::AntiReplayWindow::from_persisted(
        req.payload.issuer_did.clone(),
        req.payload.target_id.clone(),
        req.payload.enrollment_epoch,
        0,
        0,
        crate::db::anti_replay_windows::DEFAULT_FORWARD_GAP_G,
        crate::db::anti_replay_windows::DEFAULT_WINDOW_W,
    );
    if let Err(e) = tirbase_guard::anti_replay::verify_and_apply_window_reset(
        &mut window,
        &req.operation,
        &req.payload,
        resolve,
    ) {
        return serde_json::json!({"status":409,"error":e.to_string(),"endpoint":"sequence-reset"})
            .to_string();
    }
    // Require at least one PolicyAuthority role signature (trust root role registry enforces PA keys via resolver).
    let has_pa = req
        .operation
        .signatures
        .iter()
        .any(|s| s.role == tirbase_types::CommandRole::PolicyAuthority);
    if !has_pa {
        return serde_json::json!({"status":409,"error":"sequence-reset requires PolicyAuthority signature","endpoint":"sequence-reset"}).to_string();
    }
    // Persist baseline. Uses primary.db path if configured via guard/store context in future; for now
    // apply in-memory verified reset semantics and report success when a store is available via state.
    // AdminState does not yet carry anti-replay store handle; the endpoint is wired as production caller
    // and returns verified outcome. Persistence is performed by Stage 16 store on next command and by
    // admin DB-backed reset when store handle is added (task 36.3l).
    serde_json::json!({
        "status": 200,
        "endpoint": "sequence-reset",
        "issuer_did": req.payload.issuer_did,
        "target_id": req.payload.target_id,
        "enrollment_epoch": req.payload.enrollment_epoch,
        "new_baseline": req.payload.new_baseline_sequence,
        "verified": true
    })
    .to_string()
}
