// SPDX-License-Identifier: AGPL-3.0-only

//! Outbound-initiated cloud command channel (36.8f).
//!
//! # No inbound cloud listener
//!
//! The gateway never accepts a cloud connection. It dials the configured
//! `cloud_endpoint` outbound over TLS and holds that connection open; there is
//! deliberately no `cloud_listen_addr` configuration field, and
//! [`crate::config::GatewayConfig::validate`] rejects unknown fields.
//!
//! # Device certificate authentication
//!
//! The TLS client authenticates with the configured device certificate and key
//! (`cloud_device_cert_path` / `cloud_device_key_path`). A gateway without
//! valid certificate material cannot complete a session with a cloud endpoint
//! that requires client certificates. The channel additionally sends a
//! `hello` message carrying the device DID and a `KeyProvider` signature over
//! the DID, so the endpoint can bind the TLS identity to the TirBase identity.
//!
//! # Reconnect and offline queue
//!
//! Connection failures and drops reconnect with exponential backoff
//! (`cloud_reconnect_initial_secs` doubling to `cloud_max_reconnect_delay_secs`).
//! Outbound messages produced while disconnected are retained in a bounded ring
//! buffer (`cloud_queue_depth`) and replayed in order on the next connection.
//!
//! # Per-connection limits and certificate rotation
//!
//! Each connection enforces `cloud_rate_limit_per_sec` inbound messages/second
//! and answers excess traffic with a `rate_limit` message without processing
//! it. TLS material is re-read on every connection attempt, so rotating the
//! certificate files takes effect on the next reconnect without tearing down
//! the active connection.
//!
//! # Wire format
//!
//! Newline-delimited JSON in both directions.
//!
//! Device → cloud: `hello`, `result`, `challenge_request`, `rate_limit`.
//! Cloud → device: `command`, `challenge_nonce`, `challenge_error`.

use std::collections::VecDeque;
use std::io::BufReader as StdBufReader;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tirbase_core::traits::{KeyProvider, TimeSource};
use tirbase_guard::{CommandGuard, DriverProxy, IngressSource};
use tirbase_types::command::CommandMessage;
use tirbase_types::TargetId;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use crate::config::GatewayConfig;
use crate::guard::{AdmitRequest, DispatchTarget, admit_and_dispatch_blocking, SqliteStage16Store};

/// Domain separation for the cloud device hello signature.
pub const CLOUD_DEVICE_HELLO_CONTEXT: &str = "TirBase/v1/CloudDeviceHello";

/// One message retained by the offline outbound ring buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedCloudMessage {
 /// Monotonically increasing enqueue sequence used to prove replay order.
    pub seq: u64,
 /// Serialized newline-delimited JSON body.
    pub body: String,
}

/// Bounded FIFO outbound queue used while the cloud channel is disconnected.
#[derive(Debug)]
pub struct CloudOutbox {
    max_depth: usize,
    queue: Mutex<VecDeque<QueuedCloudMessage>>,
    next_seq: AtomicU64,
    dropped: AtomicU64,
}

impl CloudOutbox {
    pub fn new(max_depth: usize) -> Self {
        Self {
            max_depth: max_depth.max(1),
            queue: Mutex::new(VecDeque::new()),
            next_seq: AtomicU64::new(1),
            dropped: AtomicU64::new(0),
        }
    }

 /// Enqueue `body`; when the ring is full the oldest entry is dropped.
 /// Returns the enqueue sequence.
    pub fn push(&self, body: String) -> u64 {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let mut queue = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        while queue.len() >= self.max_depth {
            queue.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        queue.push_back(QueuedCloudMessage { seq, body });
        seq
    }

 /// Remove and return all queued messages in enqueue order.
    pub fn drain(&self) -> Vec<QueuedCloudMessage> {
        let mut queue = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        queue.drain(..).collect()
    }

    pub fn depth(&self) -> usize {
        match self.queue.lock() {
            Ok(guard) => guard.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

// ── Wire messages ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudDeviceHello {
    #[serde(rename = "type")]
    pub kind: String,
    pub device_did: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudResult {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudRateLimitNotice {
    #[serde(rename = "type")]
    pub kind: String,
    pub limit_per_sec: u32,
    pub retry_after_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudChallengeRequestOut {
    #[serde(rename = "type")]
    pub kind: String,
    pub request_id: u64,
    pub issuer_did: String,
    pub target_id: String,
    pub param: String,
    pub command_hash_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudChallengeNonceOut {
    #[serde(rename = "type")]
    pub kind: String,
    pub request_id: u64,
    pub issuer_did: String,
    pub target_id: String,
    pub param: String,
    #[serde(default)]
    pub command_hash_hex: String,
    pub nonce_hex: String,
    pub issued_at_mono: i64,
    pub expires_at_mono: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudChallengeErrorOut {
    #[serde(rename = "type")]
    pub kind: String,
    pub request_id: u64,
    pub code: String,
    pub error: String,
}

#[derive(Debug, Clone, Deserialize)]
struct CloudCommandMessage {
    id: String,
    command: CommandMessage,
    #[serde(default)]
    biscuit_token_hex: Option<String>,
    #[serde(default)]
    frame_hex: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct CloudChallengeRequest {
    request_id: u64,
    issuer_did: String,
    target_id: String,
    param: String,
    #[serde(default)]
    command_hash_hex: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
enum CloudInbound {
    #[serde(rename = "command")]
    Command(Box<CloudCommandMessage>),
    #[serde(rename = "challenge_request")]
    Challenge(CloudChallengeRequest),
    #[serde(rename = "challenge_nonce")]
    ChallengeNonce(serde_json::Value),
    #[serde(rename = "hello_ok")]
    HelloOk(serde_json::Value),
}

// ── TLS material ───────────────────────────────────────────────────────────

/// Paths to the cloud TLS material. Re-read on every connection attempt so a
/// certificate rotation takes effect without dropping the active connection.
#[derive(Debug, Clone)]
pub struct CloudTlsPaths {
    pub ca_cert: PathBuf,
    pub device_cert: PathBuf,
    pub device_key: PathBuf,
}

impl CloudTlsPaths {
    pub fn from_config(config: &GatewayConfig) -> Option<Self> {
        Some(Self {
            ca_cert: config.cloud_ca_cert_path.clone()?,
            device_cert: config.cloud_device_cert_path.clone()?,
            device_key: config.cloud_device_key_path.clone()?,
        })
    }

    fn load_client_config(&self) -> Result<Arc<rustls::ClientConfig>> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in load_certs(&self.ca_cert)? {
            roots
                .add(cert)
                .context("cloud CA certificate is not a usable trust anchor")?;
        }
        let certs = load_certs(&self.device_cert)?;
        let key = load_private_key(&self.device_key)?;
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)
            .map_err(|error| anyhow::anyhow!("cloud TLS client config: {error}"))?;
        Ok(Arc::new(config))
    }
}

fn load_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("open certificate {}", path.display()))?;
    let mut reader = StdBufReader::new(file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        bail!("no PEM certificates in {}", path.display());
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path).with_context(|| format!("open key {}", path.display()))?;
    let mut reader = StdBufReader::new(file);
    rustls_pemfile::private_key(&mut reader)?.context("no PEM private key found")
}

// ── Client ─────────────────────────────────────────────────────────────────

/// Runtime handles needed to process cloud-issued commands and challenge
/// requests.
pub struct CloudRuntime {
    pub guard: Arc<CommandGuard>,
    pub stage16: Arc<SqliteStage16Store>,
    pub time_source: Arc<dyn TimeSource>,
    pub key_provider: Arc<dyn KeyProvider>,
}

/// Outbound cloud client shared by the reconnect loop and callers that need to
/// enqueue messages while offline.
pub struct CloudClient {
    endpoint: String,
    tls: CloudTlsPaths,
    runtime: CloudRuntime,
    outbox: Arc<CloudOutbox>,
    rate_limit_per_sec: u32,
    reconnect_initial: u64,
    reconnect_max: u64,
    sender: Mutex<Option<mpsc::UnboundedSender<String>>>,
    connected: AtomicBool,
    reconnects: AtomicU64,
}

impl CloudClient {
    pub fn from_config(config: &GatewayConfig, runtime: CloudRuntime) -> Result<Option<Self>> {
        let Some(endpoint) = config.cloud_endpoint.clone() else {
            return Ok(None);
        };
        let Some(tls) = CloudTlsPaths::from_config(config) else {
            bail!("cloud_endpoint requires cloud_ca_cert_path, cloud_device_cert_path and cloud_device_key_path");
        };
        Ok(Some(Self {
            endpoint,
            tls,
            runtime,
            outbox: Arc::new(CloudOutbox::new(config.cloud_queue_depth)),
            rate_limit_per_sec: config.cloud_rate_limit_per_sec,
            reconnect_initial: config.cloud_reconnect_initial_secs.max(1),
            reconnect_max: config.cloud_max_reconnect_delay_secs.max(1),
            sender: Mutex::new(None),
            connected: AtomicBool::new(false),
            reconnects: AtomicU64::new(0),
        }))
    }

    pub fn outbox(&self) -> Arc<CloudOutbox> {
        self.outbox.clone()
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    pub fn reconnect_count(&self) -> u64 {
        self.reconnects.load(Ordering::Relaxed)
    }

 /// Send an outbound message now, or queue it for ordered replay on the next
 /// connection.
    pub fn enqueue(&self, body: String) {
        let sender = match self.sender.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        if let Some(sender) = sender {
            if sender.send(body.clone()).is_ok() {
                return;
            }
        }
        self.outbox.push(body);
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

 /// Reconnect loop with exponential backoff.
    pub async fn run(self: Arc<Self>) {
 // Control-plane boot notification. If the endpoint is unreachable this
 // is retained by the bounded outbox and replayed first on reconnect
 // ().
        self.outbox.push(
            serde_json::json!({
                "type": "result",
                "id": "boot",
                "accepted": true,
                "detail": format!("gateway {} online", env!("CARGO_PKG_VERSION")),
            })
            .to_string(),
        );
        let mut delay = self.reconnect_initial;
        loop {
            match self.connect().await {
                Ok(stream) => {
                    delay = self.reconnect_initial;
                    self.connected.store(true, Ordering::Relaxed);
                    self.session(stream).await;
                    self.connected.store(false, Ordering::Relaxed);
                    self.clear_sender();
                    self.reconnects.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        endpoint = %self.endpoint,
                        "cloud channel disconnected; queued messages retained ({})",
                        self.outbox.depth()
                    );
                }
                Err(error) => {
                    self.connected.store(false, Ordering::Relaxed);
                    tracing::warn!(
                        endpoint = %self.endpoint,
                        delay_secs = delay,
                        %error,
                        "cloud channel connect failed"
                    );
                }
            }
            tokio::time::sleep(Duration::from_secs(delay)).await;
            delay = (delay.saturating_mul(2)).min(self.reconnect_max);
        }
    }

    async fn connect(&self) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
        let config = self.tls.load_client_config()?;
        let connector = tokio_rustls::TlsConnector::from(config);
        let server_name = server_name_for(&self.endpoint)?;
        let tcp = tokio::net::TcpStream::connect(&self.endpoint).await?;
        tcp.set_nodelay(true).ok();
        let stream = connector.connect(server_name, tcp).await?;
        Ok(stream)
    }

    fn clear_sender(&self) {
        if let Ok(mut guard) = self.sender.lock() {
            *guard = None;
        }
    }

    async fn session(&self, stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>) {
        let (read_half, mut write_half) = tokio::io::split(stream);

 // Device authentication proof, bound to the DID.
        let hello = self.device_hello();
        if write_half
            .write_all(format!("{hello}\n").as_bytes())
            .await
            .is_err()
        {
            return;
        }
 // Replay queued messages in order before accepting new traffic.
        for queued in self.outbox.drain() {
            tracing::info!(seq = queued.seq, "cloud channel replaying queued message");
            if write_half
                .write_all(format!("{}\n", queued.body).as_bytes())
                .await
                .is_err()
            {
                return;
            }
        }
        let _ = write_half.flush().await;

        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        if let Ok(mut guard) = self.sender.lock() {
            *guard = Some(tx.clone());
        }
        let writer = tokio::spawn(async move {
            while let Some(body) = rx.recv().await {
                if write_half
                    .write_all(format!("{body}\n").as_bytes())
                    .await
                    .is_err()
                {
                    break;
                }
                if write_half.flush().await.is_err() {
                    break;
                }
            }
        });

        let mut lines = BufReader::new(read_half).lines();
        let mut window_start = self.runtime.time_source.monotonic_now();
        let mut window_count: u32 = 0;
        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim().is_empty() {
                continue;
            }
 // Per-connection inbound rate limit ().
            let now = self.runtime.time_source.monotonic_now();
            if now.saturating_sub(window_start) >= 1_000_000 {
                window_start = now;
                window_count = 0;
            }
            window_count = window_count.saturating_add(1);
            if self.rate_limit_per_sec > 0 && window_count > self.rate_limit_per_sec {
                let notice = CloudRateLimitNotice {
                    kind: "rate_limit".into(),
                    limit_per_sec: self.rate_limit_per_sec,
                    retry_after_secs: 1,
                };
                if let Ok(body) = serde_json::to_string(&notice) {
                    let _ = tx.send(body);
                }
                continue;
            }

            match serde_json::from_str::<CloudInbound>(&line) {
                Ok(CloudInbound::Command(command)) => {
                    let response = self.handle_command(*command).await;
                    if let Ok(body) = serde_json::to_string(&response) {
                        let _ = tx.send(body);
                    }
                }
                Ok(CloudInbound::Challenge(request)) => {
                    let response = self.handle_challenge(request);
                    if let Ok(body) = serde_json::to_string(&response) {
                        let _ = tx.send(body);
                    }
                }
                Ok(CloudInbound::ChallengeNonce(value)) => {
                    let _ = value.get("type");
                }
                Ok(CloudInbound::HelloOk(value)) => {
                    let _ = value.get("type");
                }
                Err(error) => {
                    tracing::warn!(%error, "cloud channel dropped malformed message");
                }
            }
        }
 // Drop the shared sender before joining the writer: otherwise the
 // writer's receiver never closes and the reconnect loop stalls.
        self.clear_sender();
        drop(tx);
        let _ = writer.await;
    }

    fn device_hello(&self) -> String {
        let did = self.runtime.key_provider.did().to_string();
        let public_key_hex = hex::encode(self.runtime.key_provider.public_key_bytes());
        let mut message = Vec::new();
        message.extend_from_slice(CLOUD_DEVICE_HELLO_CONTEXT.as_bytes());
        message.push(0);
        message.extend_from_slice(did.as_bytes());
        let signature_hex = match self.runtime.key_provider.sign(&message) {
            Ok(tirbase_types::DeviceSignature::Ed25519(bytes)) => hex::encode(bytes),
            Ok(tirbase_types::DeviceSignature::P256(bytes)) => hex::encode(bytes),
            Err(_) => String::new(),
        };
        serde_json::to_string(&CloudDeviceHello {
            kind: "hello".into(),
            device_did: did,
            public_key_hex,
            signature_hex,
        })
        .unwrap_or_default()
    }

    async fn handle_command(&self, message: CloudCommandMessage) -> CloudResult {
        let token = message
            .biscuit_token_hex
            .as_deref()
            .and_then(|hex_token| hex::decode(hex_token.trim()).ok())
            .unwrap_or_default();
        let frame = message
            .frame_hex
            .as_deref()
            .and_then(|hex_frame| hex::decode(hex_frame.trim()).ok())
            .unwrap_or_else(|| {
                format!(
                    "CLOUD:{}:{}",
                    message.command.target_id.as_str(),
                    message.command.param
                )
                .into_bytes()
            });
        let source_key = format!("Cloud:{}", message.command.issuer_did.as_str());
        let now_est = self
            .runtime
            .guard
            .pipeline()
            .map(|pipeline| {
                pipeline
                    .ratchet()
                    .lock()
                    .map(|r| r.now_est(pipeline.time_source().as_ref()))
                    .unwrap_or_default()
            })
            .unwrap_or_else(|| tirbase_core::traits::wall_hint_secs().unwrap_or_default());
        let now_mono = self
            .runtime
            .guard
            .pipeline()
            .map(|pipeline| pipeline.mono_secs_now())
            .unwrap_or_else(|| (self.runtime.time_source.monotonic_now() / 1_000_000) as i64);
        let decision = admit_and_dispatch_blocking(
            self.runtime.guard.clone(),
            source_key,
            AdmitRequest {
                cmd: message.command,
                token,
                ingress: IngressSource::CloudApi,
                now_est,
                simulate: false,
            },
            DispatchTarget {
                store: self.runtime.stage16.clone(),
                proxy: DriverProxy::new(Vec::new()),
                frame,
                driver_reader: std::io::Cursor::new(Vec::new()),
                now_mono_secs: now_mono,
            },
        )
        .await;
        let status = decision
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("rejected");
        let accepted = status == "accepted" || status == "complete" || status == "completed";
        let code = decision
            .get("code")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .or_else(|| {
                if accepted {
                    None
                } else {
                    Some("UNSUPPORTED".to_string())
                }
            });
        let detail = decision
            .get("detail")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        CloudResult {
            kind: "result".into(),
            id: message.id,
            accepted,
            code,
            detail,
        }
    }

    fn handle_challenge(&self, request: CloudChallengeRequest) -> serde_json::Value {
        let Some(guard) = Some(self.runtime.guard.as_ref()) else {
            return serde_json::to_value(CloudChallengeErrorOut {
                kind: "challenge_error".into(),
                request_id: request.request_id,
                code: "UNSUPPORTED".into(),
                error: "guard unavailable".into(),
            })
            .unwrap_or_default();
        };
        let Some(pipeline) = guard.pipeline() else {
            return serde_json::to_value(CloudChallengeErrorOut {
                kind: "challenge_error".into(),
                request_id: request.request_id,
                code: "UNSUPPORTED".into(),
                error: "guard pipeline unavailable".into(),
            })
            .unwrap_or_default();
        };
        if pipeline.freshness_state() != tirbase_guard::time::FreshnessState::Unverified {
            return serde_json::to_value(CloudChallengeErrorOut {
                kind: "challenge_error".into(),
                request_id: request.request_id,
                code: "FRESHNESS_NOT_UNVERIFIED".into(),
                error: "challenge nonces are only issued in Unverified freshness".into(),
            })
            .unwrap_or_default();
        }
        let target = TargetId::new(&request.target_id);
        if !guard.parameter_is_critical(&target, &request.param) {
            return serde_json::to_value(CloudChallengeErrorOut {
                kind: "challenge_error".into(),
                request_id: request.request_id,
                code: "PARAM_NOT_CRITICAL".into(),
                error: "challenge nonces are only issued for critical parameters".into(),
            })
            .unwrap_or_default();
        }
        let Some(device_id) = guard.device_id_for_target(&target) else {
            return serde_json::to_value(CloudChallengeErrorOut {
                kind: "challenge_error".into(),
                request_id: request.request_id,
                code: "UNKNOWN_TARGET".into(),
                error: "unknown target".into(),
            })
            .unwrap_or_default();
        };
        let mono_now = pipeline.mono_secs_now();
        if !pipeline.check_challenge_issue_rate_limit(
            &device_id,
            &request.target_id,
            &request.param,
            mono_now,
        ) {
            return serde_json::to_value(CloudChallengeErrorOut {
                kind: "challenge_error".into(),
                request_id: request.request_id,
                code: "RATE_LIMIT".into(),
                error: "challenge issuance rate limited".into(),
            })
            .unwrap_or_default();
        }
        match pipeline.issue_challenge_nonce_for_device(
            &device_id,
            &request.issuer_did,
            &request.target_id,
            &request.param,
        ) {
            Ok(nonce) => serde_json::to_value(CloudChallengeNonceOut {
                kind: "challenge_nonce".into(),
                request_id: request.request_id,
                issuer_did: nonce.issuer_did,
                target_id: nonce.target_id,
                param: nonce.param,
                command_hash_hex: request.command_hash_hex.clone(),
                nonce_hex: hex::encode(nonce.nonce),
                issued_at_mono: nonce.issued_at_mono,
                expires_at_mono: nonce.expires_at_mono,
            })
            .unwrap_or_default(),
            Err(error) => serde_json::to_value(CloudChallengeErrorOut {
                kind: "challenge_error".into(),
                request_id: request.request_id,
                code: "ISSUANCE_FAILED".into(),
                error,
            })
            .unwrap_or_default(),
        }
    }
}

fn server_name_for(endpoint: &str) -> Result<rustls::pki_types::ServerName<'static>> {
    let host = endpoint
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(endpoint)
        .trim_matches(['[', ']']);
    rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| anyhow::anyhow!("cloud endpoint host {host:?} is not a valid TLS server name"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbox_is_bounded_and_preserves_enqueue_order() {
        let outbox = CloudOutbox::new(2);
        assert_eq!(outbox.push("a".into()), 1);
        assert_eq!(outbox.push("b".into()), 2);
        assert_eq!(outbox.push("c".into()), 3);
        assert_eq!(outbox.depth(), 2);
        assert_eq!(outbox.dropped(), 1);
        let drained = outbox.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].seq, 2);
        assert_eq!(drained[1].seq, 3);
        assert_eq!(drained[0].body, "b");
        assert_eq!(drained[1].body, "c");
    }
}
