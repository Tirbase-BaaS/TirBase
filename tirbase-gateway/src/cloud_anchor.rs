//! Cloud-anchor checkpoint ingress (26.7a, PV-7.10).
//!
//! The single-gateway witness fallback (26.7) degrades tail-truncation
//! detection when a device has no mesh peers. This module closes that gap: the
//! gateway reports its latest checkpoint hash upstream to a trusted cloud
//! anchor and ingests the anchor's signed acknowledgement.
//!
//! The acknowledgement carries the anchor's *previous* view of this device's
//! chain. If the anchor previously witnessed a higher sequence number (or a
//! different hash at the same sequence number) than the local tail, the local
//! log was truncated; `SecurityEventLog::note_cloud_anchor_witness` emits
//! `TailTruncation` and enters `Restricted` exactly as the mesh-peer path does.
//!
//! # Wire format
//!
//! One JSON object per line over TCP, in both directions.
//!
//! Device → anchor:
//!
//! ```json
//! { "report": { "device_did": "...", "seq": 12, "checkpoint_hash": [..32 bytes..],
//!               "observed_at": 1700000000 },
//!   "signed_operation": { "context_string": "TirBase/v1/CloudAnchorCheckpointReport", "..." : "..." } }
//! ```
//!
//! Anchor → device:
//!
//! ```json
//! { "acknowledgement": { "anchor_did": "...", "device_did": "...",
//!                        "acknowledged_seq": 12, "acknowledged_hash": [..],
//!                        "previously_witnessed_seq": 42,
//!                        "previously_witnessed_hash": [..],
//!                        "observed_at": 1700000001 },
//!   "signed_operation": { "context_string": "TirBase/v1/CloudAnchorCheckpointAck", "..." : "..." } }
//! ```
//!
//! The acknowledgement is rejected unless it is domain-separated, bound to the
//! payload, and signed by the configured anchor DID/public key. The anchor must
//! echo the reported `(seq, hash)` for this device, so a response cannot be
//! replayed across devices or checkpoints.
//!
//! Production caller: `tirbase-gateway/src/main.rs` boots the loop when all
//! three `cloud_anchor_*` settings are present.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tirbase_core::traits::KeyProvider;
use tirbase_guard::signed_operation::{SignedOperation, SignedOperationPayload};
use tirbase_types::CommandRole;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::config::GatewayConfig;
use crate::security_log::SecurityEventLog;

/// Domain separation for the device's checkpoint report.
pub const CLOUD_ANCHOR_REPORT_CONTEXT: &str = "TirBase/v1/CloudAnchorCheckpointReport";
/// Domain separation for the anchor's acknowledgement.
pub const CLOUD_ANCHOR_ACK_CONTEXT: &str = "TirBase/v1/CloudAnchorCheckpointAck";
/// Per-exchange TCP timeout.
pub const CLOUD_ANCHOR_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
/// Validity window for the device report / anchor acknowledgement.
pub const CLOUD_ANCHOR_OPERATION_TTL_SECS: i64 = 300;

/// Checkpoint report sent upstream to the anchor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudAnchorCheckpointReport {
    pub device_did: String,
    pub seq: u64,
    pub checkpoint_hash: [u8; 32],
    pub observed_at: i64,
}

impl SignedOperationPayload for CloudAnchorCheckpointReport {
    const CONTEXT: &'static str = CLOUD_ANCHOR_REPORT_CONTEXT;
}

/// Anchor response: what it acknowledged now and what it witnessed before.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudAnchorAcknowledgement {
    pub anchor_did: String,
    pub device_did: String,
    pub acknowledged_seq: u64,
    pub acknowledged_hash: [u8; 32],
    /// The anchor's prior view of this device's chain (None on first contact).
    pub previously_witnessed_seq: Option<u64>,
    pub previously_witnessed_hash: Option<[u8; 32]>,
    pub observed_at: i64,
}

impl SignedOperationPayload for CloudAnchorAcknowledgement {
    const CONTEXT: &'static str = CLOUD_ANCHOR_ACK_CONTEXT;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudAnchorRequest {
    pub report: CloudAnchorCheckpointReport,
    pub signed_operation: SignedOperation<CloudAnchorCheckpointReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudAnchorResponse {
    pub acknowledgement: CloudAnchorAcknowledgement,
    pub signed_operation: SignedOperation<CloudAnchorAcknowledgement>,
}

/// A verified anchor acknowledgement ready for ingress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudAnchorIngress {
    pub anchor_did: String,
    /// Chain position the anchor has now witnessed for this device.
    pub acknowledged: (u64, [u8; 32]),
    /// The anchor's prior witness, checked against the local tail.
    pub previously_witnessed: Option<(u64, [u8; 32])>,
    pub observed_at: i64,
}

/// Client that reports checkpoints to the trusted cloud anchor.
#[derive(Clone)]
pub struct CloudAnchorClient {
    endpoint: std::net::SocketAddr,
    anchor_did: String,
    anchor_public_key: [u8; 32],
    device_did: String,
    key_provider: Arc<dyn KeyProvider>,
}

impl std::fmt::Debug for CloudAnchorClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudAnchorClient")
            .field("endpoint", &self.endpoint)
            .field("anchor_did", &self.anchor_did)
            .field("device_did", &self.device_did)
            .finish()
    }
}

impl CloudAnchorClient {
    /// Build the client from gateway configuration.
    ///
    /// Returns `Ok(None)` when cloud anchoring is not configured. Partial
    /// configuration is rejected by `GatewayConfig::validate`; a direct caller
    /// gets an error here instead.
    pub fn from_config(
        config: &GatewayConfig,
        key_provider: Arc<dyn KeyProvider>,
    ) -> Result<Option<Self>> {
        let (Some(endpoint), Some(anchor_did), Some(public_key_hex)) = (
            config.cloud_anchor_endpoint,
            config.cloud_anchor_did.clone(),
            config.cloud_anchor_public_key_hex.clone(),
        ) else {
            return Ok(None);
        };
        if anchor_did.trim().is_empty() {
            return Err(anyhow!("cloud anchor DID must not be empty"));
        }
        let bytes =
            hex::decode(public_key_hex.trim()).context("cloud anchor public key is not hex")?;
        let anchor_public_key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            anyhow!(
                "cloud anchor public key must be a 32-byte Ed25519 key (got {} bytes)",
                bytes.len()
            )
        })?;
        Ok(Some(Self {
            endpoint,
            anchor_did,
            anchor_public_key,
            device_did: key_provider.did().to_string(),
            key_provider,
        }))
    }

    /// Report one checkpoint to the anchor and return the verified ingress.
    ///
    /// An acknowledgement signed by anyone other than the configured anchor,
    /// or one that does not echo this device's `(seq, hash)`, is rejected.
    pub async fn exchange_checkpoint(
        &self,
        seq: u64,
        checkpoint_hash: [u8; 32],
        observed_at: i64,
    ) -> Result<Option<CloudAnchorIngress>, String> {
        let report = CloudAnchorCheckpointReport {
            device_did: self.device_did.clone(),
            seq,
            checkpoint_hash,
            observed_at,
        };
        let mut operation = SignedOperation::new(
            &report,
            observed_at,
            Some(observed_at.saturating_add(CLOUD_ANCHOR_OPERATION_TTL_SECS)),
        )
        .map_err(|e| format!("cloud anchor report signing: {e}"))?;
        operation
            .sign_with(self.key_provider.as_ref(), CommandRole::Auditor)
            .map_err(|e| format!("cloud anchor report signing: {e}"))?;
        let request = CloudAnchorRequest {
            report,
            signed_operation: operation,
        };

        let mut line = serde_json::to_string(&request)
            .map_err(|e| format!("cloud anchor request encode: {e}"))?;
        line.push('\n');

        let exchange = async {
            let stream = TcpStream::connect(self.endpoint)
                .await
                .map_err(|e| format!("connect {}: {e}", self.endpoint))?;
            let (read_half, mut write_half) = stream.into_split();
            write_half
                .write_all(line.as_bytes())
                .await
                .map_err(|e| format!("write report: {e}"))?;
            write_half
                .flush()
                .await
                .map_err(|e| format!("flush report: {e}"))?;
            let mut response_line = String::new();
            BufReader::new(read_half)
                .read_line(&mut response_line)
                .await
                .map_err(|e| format!("read acknowledgement: {e}"))?;
            Ok::<String, String>(response_line)
        };
        let response_line = tokio::time::timeout(CLOUD_ANCHOR_EXCHANGE_TIMEOUT, exchange)
            .await
            .map_err(|_| "cloud anchor exchange timed out".to_string())??;
        if response_line.trim().is_empty() {
            return Err(
                "cloud anchor closed the connection without an acknowledgement".to_string(),
            );
        }
        let response: CloudAnchorResponse = serde_json::from_str(&response_line)
            .map_err(|e| format!("cloud anchor acknowledgement decode: {e}"))?;
        response
            .signed_operation
            .verify(&response.acknowledgement, |did| {
                (did == self.anchor_did).then(|| self.anchor_public_key.to_vec())
            })
            .map_err(|e| format!("cloud anchor acknowledgement verification: {e}"))?;

        let ack = response.acknowledgement;
        if ack.anchor_did != self.anchor_did {
            return Err(format!(
                "cloud anchor acknowledgement from unexpected anchor {}",
                ack.anchor_did
            ));
        }
        if ack.device_did != self.device_did {
            return Err(format!(
                "cloud anchor acknowledgement for device {} but this is {}",
                ack.device_did, self.device_did
            ));
        }
        if ack.acknowledged_seq != seq || ack.acknowledged_hash != checkpoint_hash {
            return Err(
                "cloud anchor acknowledgement does not echo the reported checkpoint".to_string(),
            );
        }
        let previously_witnessed =
            match (ack.previously_witnessed_seq, ack.previously_witnessed_hash) {
                (Some(prev_seq), Some(prev_hash)) => Some((prev_seq, prev_hash)),
                (None, None) => None,
                _ => {
                    return Err(
                        "cloud anchor acknowledgement has an inconsistent previous witness"
                            .to_string(),
                    )
                }
            };
        Ok(Some(CloudAnchorIngress {
            anchor_did: ack.anchor_did,
            acknowledged: (ack.acknowledged_seq, ack.acknowledged_hash),
            previously_witnessed,
            observed_at: ack.observed_at,
        }))
    }
}

/// Production caller: report the latest local checkpoint to the cloud anchor at
/// `interval` and feed verified acknowledgements into the security log.
pub async fn run_cloud_anchor_loop(
    client: CloudAnchorClient,
    log: Arc<SecurityEventLog>,
    interval: Duration,
) {
    let mut tick = tokio::time::interval(interval);
    loop {
        tick.tick().await;
        let latest = match log.latest_checkpoint_hash() {
            Ok(Some(latest)) => latest,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(%error, "cloud anchor: local checkpoint unavailable (CLAIM-26.7a)");
                continue;
            }
        };
        let observed_at = tirbase_core::traits::wall_hint_secs().unwrap_or_default();
        match client
            .exchange_checkpoint(latest.0, latest.1, observed_at)
            .await
        {
            Ok(Some(ingress)) => {
                match log.note_cloud_anchor_witness(
                    &ingress.anchor_did,
                    ingress.acknowledged,
                    ingress.previously_witnessed,
                    ingress.observed_at,
                ) {
                    Ok(true) => tracing::error!(
                        anchor = %ingress.anchor_did,
                        "cloud anchor witnessed a truncated local tail; entered Restricted (CLAIM-26.7a)"
                    ),
                    Ok(false) => tracing::debug!(
                        anchor = %ingress.anchor_did,
                        seq = ingress.acknowledged.0,
                        "cloud anchor checkpoint acknowledged (CLAIM-26.7a)"
                    ),
                    Err(error) => tracing::warn!(
                        %error,
                        "cloud anchor witness ingress failed (CLAIM-26.7a)"
                    ),
                }
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, "cloud anchor checkpoint exchange failed (CLAIM-26.7a)")
            }
        }
    }
}
