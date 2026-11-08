//! Admin Unix-socket listener with SO_PEERCRED authentication.
//!
//! Listens on `/run/tirbase/admin.sock` (configurable via `GatewayConfig`).
//! Authenticates callers via `SO_PEERCRED` — only processes running as root
//! (UID 0) or the same UID as the gateway process are accepted.
//!
//! Task 8 wires two endpoints into the dispatch table:
//!
//! * `enroll` — replay-safe device enrollment and scoped token issuance
//!   (tasks 8.5/8.6, CLAIM-8.5, CLAIM-8.6);
//! * `epoch-bump` — a `SignedOperation<EpochBump>` with PolicyAuthority and
//!   RevocationManager co-signatures (task 8.8, CLAIM-8.8).
//!
//! All other endpoints still return `501 Not Implemented` until their own
//! tasks land.
//!
//! # Endpoint inventory (task 36.3a – 36.3l)
//!
//! | Method | Path                         | Task |
//! |--------|------------------------------|------|
//! | POST   | /admin/enroll                | 8.6  |
//! | POST   | /admin/mint                  | 36.3b |
//! | POST   | /admin/rotate                | 36.3c |
//! | POST   | /admin/policy                | 36.3d |
//! | GET    | /admin/events                | 36.3e |
//! | POST   | /admin/simulate              | 36.3f |
//! | POST   | /admin/challenge             | 36.3g |
//! | GET    | /admin/mode                  | 36.3h |
//! | POST   | /admin/lockdown-exit         | 36.3i |
//! | POST   | /admin/chain-recovery        | 36.3j |
//! | GET    | /admin/status/{issuer_did}   | 36.3k |
//! | POST   | /admin/sequence-reset        | 36.3l |
//! | POST   | /admin/epoch-bump            | 8.8  |
//!
//! # Security note
//! `SO_PEERCRED` is a Linux kernel facility (see `man 7 unix`).  The entire
//! listener and peer-credential check are `#[cfg(target_os = "linux")]` so the
//! crate still compiles on macOS / Windows developer machines.  On those
//! platforms `run_admin_listener` returns an `Err` indicating the feature is
//! unsupported.  The dispatch logic itself is platform-independent so it can
//! be unit-tested everywhere.
//!
//! CLAIM-4.9.2 — PV-30.2

use std::fmt;
use std::sync::Arc;

use serde::Deserialize;
use tirbase_guard::epoch::{EpochBump, EpochRegistry};
use tirbase_guard::enrollment::{EnrollmentRequest, EnrollmentService};
use tirbase_guard::signed_operation::SignedOperation;
use tirbase_guard::trust_root::TrustRootRecord;
use tirbase_guard::PolicyBundle;

/// State shared by the admin endpoints.
pub struct AdminState {
    /// Enrollment service; `None` disables the `enroll` endpoint (501).
    pub enrollment: Option<Arc<EnrollmentService>>,
    /// Epoch registry used by `epoch-bump`.
    pub epochs: Option<Arc<EpochRegistry>>,
    /// Trust root used for role-threshold checks during an epoch bump.
    pub trust_root: Option<Arc<TrustRootRecord>>,
    /// Policy lifecycle (tasks 12.1–12.7, CLAIM-12.1–7). When present,
    /// `/admin/policy` pushes bundles through `PolicyLifecycle::ingest_bundle`
    /// (reclassifies — never trusts `bundle.kind`, enforces anti-rollback).
    pub policy: Option<Arc<std::sync::Mutex<tirbase_guard::PolicyLifecycle>>>,
}

impl fmt::Debug for AdminState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminState")
            .field("has_enrollment", &self.enrollment.is_some())
            .field("has_epochs", &self.epochs.is_some())
            .field("has_trust_root", &self.trust_root.is_some())
            .field("has_policy", &self.policy.is_some())
            .finish()
    }
}

impl Default for AdminState {
    fn default() -> Self {
        AdminState { enrollment: None, epochs: None, trust_root: None, policy: None }
    }
}

impl AdminState {
    /// Build an admin state with enrollment and epoch-bump enabled.
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
        }
    }
}

/// Parse the `"cmd"` field and dispatch one newline-delimited JSON command.
///
/// A `None` state keeps every endpoint at `501`; this preserves the original
/// admin-contract tests and lets the gateway start without enrollment config.
pub fn dispatch_admin_command(command: &str, state: Option<&AdminState>) -> String {
    let now_est = tirbase_core::traits::wall_hint_secs().unwrap_or_default();
    dispatch_admin_command_at(command, state, now_est)
}

/// Dispatch with an explicit `now_est`.
///
/// Production callers go through [`dispatch_admin_command`]; tests use this
/// entry point so a concurrently installed simulated `TimeSource` cannot make
/// nonces appear older than their 72-hour retention window.
pub fn dispatch_admin_command_at(command: &str, state: Option<&AdminState>, now_est: i64) -> String {
    let body = match parse_cmd_field(command).as_deref() {
        Some("enroll") => dispatch_enroll(command, state, now_est),
        Some("mint") => stub_501("mint"),
        Some("rotate") => stub_501("rotate"),
        Some("policy") => dispatch_policy(command, state, now_est),
        Some("events") => stub_501("events"),
        Some("simulate") => stub_501("simulate"),
        Some("challenge") => stub_501("challenge"),
        Some("mode") => stub_501("mode"),
        Some("lockdown-exit") => stub_501("lockdown-exit"),
        Some("chain-recovery") => stub_501("chain-recovery"),
        Some("status") => stub_501("status"),
        Some("sequence-reset") => stub_501("sequence-reset"),
        Some("epoch-bump") => dispatch_epoch_bump(command, state, now_est),
        _ => r#"{"status":400,"error":"unknown command"}"#.to_string(),
    };
    format!("{body}\n")
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
            "status": 200,
            "device_id": enrolled.device_id,
            "epoch": enrolled.epoch,
            "token_hex": hex::encode(&enrolled.token),
            "token_ttl_secs": enrolled.token_ttl_secs,
        })
        .to_string(),
        Err(tirbase_guard::epoch::EpochError::NonceReused) => serde_json::json!({
            "status": 409,
            "error": "nonce reused",
            "endpoint": "enroll",
        })
        .to_string(),
        Err(error) => serde_json::json!({
            "status": 400,
            "error": error.to_string(),
            "endpoint": "enroll",
        })
        .to_string(),
    }
}

#[derive(Debug, Deserialize)]
struct EpochBumpRequest {
    operation: SignedOperation<EpochBump>,
    payload: EpochBump,
}

fn dispatch_epoch_bump(command: &str, state: Option<&AdminState>, now_est: i64) -> String {
    let Some((epochs, trust_root)) = state.and_then(|state| {
        state.epochs.as_ref().zip(state.trust_root.as_ref())
    }) else {
        return stub_501("epoch-bump");
    };
    let payload = match payload_value(command) {
        Some(payload) => payload,
        None => return bad_request("epoch-bump requires a payload object"),
    };
    let request: EpochBumpRequest = match serde_json::from_value(payload) {
        Ok(request) => request,
        Err(error) => return bad_request(&format!("invalid epoch bump: {error}")),
    };
    match epochs.apply_bump(&request.operation, &request.payload, trust_root, now_est) {
        Ok(record) => serde_json::json!({
            "status": 200,
            "device_id": record.device_id,
            "epoch": record.epoch,
        })
        .to_string(),
        Err(error) => serde_json::json!({
            "status": 409,
            "error": error.to_string(),
            "endpoint": "epoch-bump",
        })
        .to_string(),
    }
}

fn payload_value(command: &str) -> Option<serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(command)
        .ok()
        .and_then(|value| value.get("payload").cloned())
}

fn bad_request(message: &str) -> String {
    serde_json::json!({"status": 400, "error": message}).to_string()
}

/// Return a JSON 501 Not Implemented response for `endpoint`.
fn stub_501(endpoint: &str) -> String {
    format!(r#"{{"status":501,"error":"not implemented","endpoint":"{endpoint}"}}"#)
}

/// Minimal extraction of the `"cmd"` field value from a JSON object.
fn parse_cmd_field(json: &str) -> Option<String> {
    let mut parts = json.split('"');
    while let Some(segment) = parts.next() {
        if segment.trim_end_matches(|c: char| c.is_whitespace() || c == ':') == "cmd" {
            return parts
                .find(|s| {
                    let trimmed = s.trim();
                    !trimmed.is_empty() && trimmed != ":"
                })
                .map(|s| s.to_string());
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Linux-only listener
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use std::path::Path;
use std::fmt;
use std::sync::Arc;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};

    use super::{dispatch_admin_command, AdminState};

    /// Start the admin listener on the given socket path.
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
        let peer_cred = stream.peer_cred()?;
        // SAFETY: `getuid` is async-signal-safe and has no preconditions.
        let gateway_uid = unsafe { libc::getuid() };

        let peer_uid = peer_cred.uid();
        if peer_uid != 0 && peer_uid != gateway_uid {
            tracing::warn!(
                peer_uid,
                gateway_uid,
                "admin: rejecting unauthenticated connection"
            );
            return Ok(());
        }

        tracing::debug!(peer_uid, "admin: authenticated connection accepted");

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

/// Start the admin Unix-socket listener.
///
/// On Linux this binds the socket, authenticates via `SO_PEERCRED`, and
/// dispatches admin commands using `state`.
///
/// On other platforms (developer macOS, CI) this returns an error immediately
/// to avoid a hard compile-time failure on non-Linux hosts.
pub async fn run_admin_listener(
    sock_path: &std::path::Path,
    state: Option<Arc<AdminState>>,
) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::run_admin_listener(sock_path, state).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (sock_path, state);
        anyhow::bail!(
            "admin Unix-socket listener is Linux-only (SO_PEERCRED); \
             not supported on this platform"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
    use tirbase_core::identity::keypair;
    use tirbase_core::traits::KeyProvider;
    use tirbase_guard::epoch::{InMemoryEpochStore, InMemoryNonceStore};
    use tirbase_guard::enrollment::DeviceIdentity;
    use tirbase_guard::trust_root::RolePolicy;
    use tirbase_types::CommandRole;
    use std::collections::BTreeMap;

    #[test]
    fn parse_cmd_field_simple() {
        let json = r#"{"cmd":"enroll","payload":{}}"#;
        assert_eq!(parse_cmd_field(json).as_deref(), Some("enroll"));
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
    fn all_known_endpoints_return_501_without_state() {
        let endpoints = [
            "enroll",
            "mint",
            "rotate",
            "policy",
            "events",
            "simulate",
            "challenge",
            "mode",
            "lockdown-exit",
            "chain-recovery",
            "status",
            "sequence-reset",
            "epoch-bump",
        ];
        for ep in &endpoints {
            let cmd_json = format!(r#"{{"cmd":"{ep}"}}"#);
            let response = dispatch_admin_command(&cmd_json, None);
            assert!(
                response.contains("\"status\":501"),
                "endpoint '{ep}' did not return 501; got: {response}"
            );
            assert!(
                response.contains(&format!(r#""endpoint":"{ep}""#)),
                "endpoint field missing for '{ep}'; got: {response}"
            );
        }
    }

    #[test]
    fn unknown_command_returns_400() {
        let response = dispatch_admin_command(r#"{"cmd":"does-not-exist"}"#, None);
        assert!(response.contains("\"status\":400"), "unexpected: {response}");
    }

    #[test]
    fn response_is_newline_terminated() {
        let response = dispatch_admin_command(r#"{"cmd":"enroll"}"#, None);
        assert!(response.ends_with('\n'), "got: {response:?}");
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
        let payload = serde_json::to_value(&request).unwrap();
        let command = serde_json::json!({"cmd": "enroll", "payload": payload}).to_string();

        let now_est = 1_800_000_000;
        let response = dispatch_admin_command_at(&command, Some(&state), now_est);
        let value: serde_json::Value = serde_json::from_str(response.trim()).unwrap();
        assert_eq!(value["status"], 200);
        assert_eq!(value["device_id"], device.device_id());
        assert_eq!(value["epoch"], 0);
        let token = hex::decode(value["token_hex"].as_str().unwrap()).unwrap();
        // Verify at t=0 so a concurrently installed simulated `TimeSource`
        // cannot make the token appear expired; this still exercises the
        // signature and claim path.
        let claims = tirbase_core::auth::biscuit::verify_token(&token, &root_public, 0)
            .expect("issued token verifies");
        assert_eq!(claims.did, device.device_id());

        let replay = dispatch_admin_command_at(&command, Some(&state), now_est);
        let value: serde_json::Value = serde_json::from_str(replay.trim()).unwrap();
        assert_eq!(value["status"], 409, "nonce reuse rejected: {value}");
        assert!(value["error"].as_str().unwrap().contains("nonce reused"));
    }

}

fn dispatch_policy(command: &str, state: Option<&AdminState>, now_est: i64) -> String {
    let Some(policy) = state.and_then(|s| s.policy.as_ref()) else {
        return stub_501("policy");
    };
    let payload = match payload_value(command) {
        Some(p) => p,
        None => return bad_request("policy requires a payload object"),
    };
    // Accept {"bundle": <PolicyBundle>} or a direct bundle payload.
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
