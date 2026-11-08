//! Admin Unix-socket listener with SO_PEERCRED authentication (CLAIM-4.9.2).
//! Task 13 wires `mode` (13.1/36.3h) and `lockdown-exit` (13.3/36.3i).

use std::fmt;
use std::sync::Arc;

use serde::Deserialize;
use tirbase_guard::epoch::{EpochBump, EpochRegistry};
use tirbase_guard::enrollment::{EnrollmentRequest, EnrollmentService};
use tirbase_guard::lockdown::{apply_lockdown_exit, LockdownExitPayload, LockdownStore};
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
            enrollment: None, epochs: None, trust_root: None, policy: None,
            node_mode: None, lockdown_store: None, envelope_profile: None, guard: None,
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
            enrollment: Some(enrollment), epochs: Some(epochs), trust_root: Some(trust_root),
            policy: None, node_mode: None, lockdown_store: None, envelope_profile: None, guard: None,
        }
    }
}

pub fn dispatch_admin_command(command: &str, state: Option<&AdminState>) -> String {
    let now_est = tirbase_core::traits::wall_hint_secs().unwrap_or_default();
    dispatch_admin_command_at(command, state, now_est)
}

pub fn dispatch_admin_command_at(command: &str, state: Option<&AdminState>, now_est: i64) -> String {
    let body = match parse_cmd_field(command).as_deref() {
        Some("enroll") => dispatch_enroll(command, state, now_est),
        Some("mint") => stub_501("mint"),
        Some("rotate") => stub_501("rotate"),
        Some("policy") => dispatch_policy(command, state, now_est),
        Some("events") => stub_501("events"),
        Some("simulate") => dispatch_simulate(command, state),
        Some("challenge") => stub_501("challenge"),
        Some("mode") => dispatch_mode(state),
        Some("lockdown-exit") => dispatch_lockdown_exit(command, state),
        Some("chain-recovery") => stub_501("chain-recovery"),
        Some("status") => stub_501("status"),
        Some("sequence-reset") => stub_501("sequence-reset"),
        Some("epoch-bump") => dispatch_epoch_bump(command, state, now_est),
        _ => r#"{"status":400,"error":"unknown command"}"#.to_string(),
    };
    format!("{body}\n")
}

fn dispatch_mode(state: Option<&AdminState>) -> String {
    let Some(mode_state) = state.and_then(|s| s.node_mode.as_ref()) else {
        return stub_501("mode");
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
        Some((s.trust_root.as_ref()?, s.lockdown_store.as_ref()?, s.node_mode.as_ref()?))
    }) else {
        return stub_501("lockdown-exit");
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
    match apply_lockdown_exit(&request.operation, &request.payload, trust_root, profile, store.as_ref(), mode) {
        Ok(()) => serde_json::json!({"status":200,"mode":"Normal","outcome":"lockdown_exit_applied"}).to_string(),
        Err(e) => serde_json::json!({"status":409,"error":e.to_string(),"endpoint":"lockdown-exit"}).to_string(),
    }
}

fn dispatch_enroll(command: &str, state: Option<&AdminState>, now_est: i64) -> String {
    let Some(service) = state.and_then(|state| state.enrollment.as_ref()) else {
        return stub_501("enroll");
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
        }).to_string(),
        Err(tirbase_guard::epoch::EpochError::NonceReused) => serde_json::json!({
            "status": 409, "error": "nonce reused", "endpoint": "enroll",
        }).to_string(),
        Err(error) => serde_json::json!({"status": 400, "error": error.to_string(), "endpoint": "enroll"}).to_string(),
    }
}

#[derive(Debug, Deserialize)]
struct EpochBumpRequest { operation: SignedOperation<EpochBump>, payload: EpochBump }

fn dispatch_epoch_bump(command: &str, state: Option<&AdminState>, now_est: i64) -> String {
    let Some((epochs, trust_root)) = state.and_then(|s| s.epochs.as_ref().zip(s.trust_root.as_ref())) else {
        return stub_501("epoch-bump");
    };
    let payload = match payload_value(command) {
        Some(p) => p, None => return bad_request("epoch-bump requires a payload object"),
    };
    let request: EpochBumpRequest = match serde_json::from_value(payload) {
        Ok(r) => r, Err(e) => return bad_request(&format!("invalid epoch bump: {e}")),
    };
    match epochs.apply_bump(&request.operation, &request.payload, trust_root, now_est) {
        Ok(record) => serde_json::json!({"status": 200, "device_id": record.device_id, "epoch": record.epoch}).to_string(),
        Err(error) => serde_json::json!({"status": 409, "error": error.to_string(), "endpoint": "epoch-bump"}).to_string(),
    }
}

fn dispatch_policy(command: &str, state: Option<&AdminState>, now_est: i64) -> String {
    let Some(policy) = state.and_then(|s| s.policy.as_ref()) else { return stub_501("policy"); };
    let payload = match payload_value(command) {
        Some(p) => p, None => return bad_request("policy requires a payload object"),
    };
    let bundle_val = payload.get("bundle").cloned().unwrap_or(payload);
    let bundle: PolicyBundle = match serde_json::from_value(bundle_val) {
        Ok(b) => b, Err(e) => return bad_request(&format!("invalid policy bundle: {e}")),
    };
    let mut guard = match policy.lock() { Ok(g) => g, Err(p) => p.into_inner() };
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
    serde_json::from_str::<serde_json::Value>(command).ok().and_then(|v| v.get("payload").cloned())
}
fn bad_request(message: &str) -> String { serde_json::json!({"status": 400, "error": message}).to_string() }
fn stub_501(endpoint: &str) -> String {
    format!(r#"{{"status":501,"error":"not implemented","endpoint":"{endpoint}"}}"#)
}
fn parse_cmd_field(json: &str) -> Option<String> {
    let mut parts = json.split('"');
    while let Some(segment) = parts.next() {
        if segment.trim_end_matches(|c: char| c.is_whitespace() || c == ':') == "cmd" {
            return parts.find(|s| { let t = s.trim(); !t.is_empty() && t != ":" }).map(|s| s.to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::Path;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};
    use super::{dispatch_admin_command, AdminState};

    pub async fn run_admin_listener(sock_path: &Path, state: Option<Arc<AdminState>>) -> anyhow::Result<()> {
        let _ = std::fs::remove_file(sock_path);
        if let Some(parent) = sock_path.parent() { std::fs::create_dir_all(parent)?; }
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

    async fn handle_admin_connection(stream: UnixStream, state: Option<Arc<AdminState>>) -> anyhow::Result<()> {
        let peer_cred = stream.peer_cred()?;
        let gateway_uid = unsafe { libc::getuid() };
        let peer_uid = peer_cred.uid();
        if peer_uid != 0 && peer_uid != gateway_uid {
            tracing::warn!(peer_uid, gateway_uid, "admin: rejecting unauthenticated connection");
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

pub async fn run_admin_listener(sock_path: &std::path::Path, state: Option<Arc<AdminState>>) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    { linux::run_admin_listener(sock_path, state).await }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (sock_path, state);
        anyhow::bail!("admin Unix-socket listener is Linux-only (SO_PEERCRED); not supported on this platform")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirbase_core::identity::keypair;
    use tirbase_core::traits::KeyProvider;
    use tirbase_guard::epoch::{InMemoryEpochStore, InMemoryNonceStore};
    use tirbase_guard::enrollment::DeviceIdentity;
    use tirbase_guard::trust_root::RolePolicy;
    use tirbase_types::CommandRole;
    use std::collections::BTreeMap;
    use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;

    #[test]
    fn parse_cmd_field_simple() {
        assert_eq!(parse_cmd_field(r#"{"cmd":"enroll","payload":{}}"#).as_deref(), Some("enroll"));
    }
    #[test]
    fn parse_cmd_field_unknown_returns_none() { assert_eq!(parse_cmd_field(r#"{"foo":"bar"}"#), None); }
    #[test]
    fn parse_cmd_field_empty_string() { assert_eq!(parse_cmd_field(""), None); }
    #[test]
    fn unknown_command_returns_400() {
        let response = dispatch_admin_command(r#"{"cmd":"does-not-exist"}"#, None);
        assert!(response.contains("\"status\":400"), "unexpected: {response}");
    }
    #[test]
    fn response_is_newline_terminated() {
        assert!(dispatch_admin_command(r#"{"cmd":"mint"}"#, None).ends_with('\n'));
    }

    fn admin_state() -> (AdminState, [u8; 32]) {
        let (root_seed, root_public) = keypair::generate_keypair().unwrap();
        let rm = InMemoryKeyProvider::generate().unwrap();
        let mut roles = BTreeMap::new();
        roles.insert(CommandRole::RevocationManager, RolePolicy::new(1, vec![tirbase_guard::trust_root::AuthorizedRoleSigner {
            did: rm.did().to_string(), public_key: rm.public_key_bytes(),
        }]));
        let trust_root = Arc::new(TrustRootRecord {
            version: 1, root_ca_public_keys: vec![root_public.to_vec()], threshold_k: 1,
            role_thresholds: roles, device_class_floors: BTreeMap::new(), expiry_est: i64::MAX,
            revoked_root_ca_keys: Vec::new(), signatures: Vec::new(),
        });
        let epochs = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
        let service = Arc::new(EnrollmentService::new(
            Arc::new(InMemoryNonceStore::new()), epochs.clone(), trust_root.clone(), root_seed.to_vec(), 3_600,
        ));
        (AdminState::new(service, epochs, trust_root), root_public)
    }

    #[test]
    fn enroll_endpoint_issues_a_token_and_rejects_nonce_reuse() {
        let (state, root_public) = admin_state();
        let device = DeviceIdentity::generate().unwrap();
        let request = device.bootstrap([3u8; 32], CommandRole::CommandIssuer).unwrap();
        let command = serde_json::json!({"cmd": "enroll", "payload": serde_json::to_value(&request).unwrap()}).to_string();
        let response = dispatch_admin_command_at(&command, Some(&state), 1_800_000_000);
        let value: serde_json::Value = serde_json::from_str(response.trim()).unwrap();
        assert_eq!(value["status"], 200);
        let token = hex::decode(value["token_hex"].as_str().unwrap()).unwrap();
        let claims = tirbase_core::auth::biscuit::verify_token(&token, &root_public, 0).expect("issued token verifies");
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
        return stub_501("simulate");
    };
    let payload_val = match payload_value(command) {
        Some(p) => p,
        None => return bad_request("simulate requires a payload object"),
    };
    let req: SimulateRequest = match serde_json::from_value(payload_val) {
        Ok(r) => r,
        Err(e) => return bad_request(&format!("invalid simulate payload: {e}")),
    };
    let token = req.biscuit_token_hex.as_deref().and_then(|h| hex::decode(h).ok()).unwrap_or_default();
    let source = req.source_key.unwrap_or_else(|| "simulate".into());
    let ctx = tirbase_guard::AdmitContext {
        ingress: tirbase_guard::IngressSource::LocalAdmin,
        source_key: &source,
        biscuit_token: if token.is_empty() { None } else { Some(&token) },
        now_est_secs: req.now_est_secs,
        simulate: true,
    };
    let decision = guard.simulate(&req.command, &ctx);
    let privileged = matches!(req.caller_role.as_deref(), Some("Auditor") | Some("PolicyAuthority"));
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
