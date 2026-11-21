// SPDX-License-Identifier: AGPL-3.0-only

//! F-08 outbound webhooks with HMAC signatures, retries and replay protection.
//!
//! Deliveries are persisted before they are attempted, so a crash does not lose
//! an event. Each delivery carries:
//!
//! * `X-TirBase-Delivery` — unique delivery id,
//! * `X-TirBase-Timestamp` — Unix seconds,
//! * `X-TirBase-Signature` — `sha256=<hex HMAC-SHA256(secret, timestamp.body)>`.
//!
//! A receiver verifies the timestamp is within the tolerance window, verifies
//! the HMAC, and records the delivery id. A replayed delivery id is rejected
//! even when the signature is valid. Retries use bounded exponential backoff
//! and stop after [`MAX_WEBHOOK_ATTEMPTS`].

use std::collections::BTreeMap;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_WEBHOOK_ATTEMPTS: u32 = 6;
pub const WEBHOOK_TIMESTAMP_TOLERANCE_SECS: i64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookHeaders {
    pub delivery_id: String,
    pub timestamp: i64,
    pub signature: String,
}

impl WebhookHeaders {
    pub fn as_map(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        map.insert("X-TirBase-Delivery".into(), self.delivery_id.clone());
        map.insert("X-TirBase-Timestamp".into(), self.timestamp.to_string());
        map.insert("X-TirBase-Signature".into(), self.signature.clone());
        map.insert("Content-Type".into(), "application/json".into());
        map
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    pub endpoint_id: String,
    pub url: String,
    /// Secret is never returned to API clients.
    #[serde(skip_serializing)]
    pub secret: String,
    pub enabled: bool,
    pub created_est: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookDelivery {
    pub delivery_id: String,
    pub endpoint_id: String,
    pub event_type: String,
    pub payload_json: String,
    pub attempts: u32,
    pub next_attempt_est: i64,
    pub status: String,
    pub last_error: Option<String>,
    pub created_est: i64,
}

fn vertical_for_event(event_type: &str) -> &'static str {
    if event_type.starts_with("cold-chain.") {
        "cold-chain"
    } else if event_type.starts_with("pos.") {
        "pos"
    } else if event_type.starts_with("venues.") {
        "venues"
    } else {
        "platform"
    }
}

/// Transport seam so tests (and alternate HTTP stacks) can deliver without a
/// network. Production uses [`ReqwestTransport`].
pub trait WebhookTransport: Send + Sync {
    fn post(
        &self,
        url: &str,
        headers: &BTreeMap<String, String>,
        body: &str,
    ) -> Result<u16, String>;
}

/// Blocking reqwest transport. Delivery runs on a dedicated thread/CLI, never
/// on the async admin request path.
#[derive(Debug, Default)]
pub struct ReqwestTransport;

impl WebhookTransport for ReqwestTransport {
    fn post(
        &self,
        url: &str,
        headers: &BTreeMap<String, String>,
        body: &str,
    ) -> Result<u16, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("webhook client: {e}"))?;
        let mut request = client.post(url).body(body.to_string());
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let response = request.send().map_err(|e| format!("webhook post: {e}"))?;
        Ok(response.status().as_u16())
    }
}

pub struct WebhookDispatcher {
    db_path: std::path::PathBuf,
}

impl std::fmt::Debug for WebhookDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookDispatcher")
            .field("db_path", &self.db_path)
            .finish()
    }
}

fn open(db_path: &std::path::Path) -> Result<Connection, String> {
    let conn = Connection::open(db_path).map_err(|e| format!("open webhook db: {e}"))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS webhook_endpoints (
            endpoint_id TEXT PRIMARY KEY,
            url         TEXT NOT NULL,
            secret      TEXT NOT NULL,
            enabled     INTEGER NOT NULL DEFAULT 1,
            created_est INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS webhook_deliveries (
            delivery_id      TEXT PRIMARY KEY,
            endpoint_id      TEXT NOT NULL,
            event_type       TEXT NOT NULL,
            payload_json     TEXT NOT NULL,
            attempts         INTEGER NOT NULL DEFAULT 0,
            next_attempt_est INTEGER NOT NULL,
            status           TEXT NOT NULL,
            last_error       TEXT,
            created_est      INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_webhook_pending
            ON webhook_deliveries(status, next_attempt_est);
         CREATE TABLE IF NOT EXISTS webhook_seen_deliveries (
            delivery_id TEXT PRIMARY KEY,
            received_est INTEGER NOT NULL
         );",
    )
    .map_err(|e| format!("ensure webhook schema: {e}"))?;
    Ok(conn)
}

impl WebhookDispatcher {
    pub fn open(db_path: impl Into<std::path::PathBuf>) -> Result<Self, String> {
        let db_path = db_path.into();
        open(&db_path)?;
        Ok(Self { db_path })
    }

    pub fn add_endpoint(
        &self,
        endpoint_id: &str,
        url: &str,
        secret: &str,
        now_est: i64,
    ) -> Result<WebhookEndpoint, String> {
        if !url.starts_with("https://") {
            return Err("webhook endpoint must use https://".to_string());
        }
        if secret.len() < 16 {
            return Err("webhook secret must be at least 16 characters".to_string());
        }
        let conn = open(&self.db_path)?;
        conn.execute(
            "INSERT INTO webhook_endpoints(endpoint_id,url,secret,enabled,created_est)
             VALUES (?1,?2,?3,1,?4)",
            params![endpoint_id, url, secret, now_est],
        )
        .map_err(|e| format!("add webhook endpoint: {e}"))?;
        Ok(WebhookEndpoint {
            endpoint_id: endpoint_id.to_string(),
            url: url.to_string(),
            secret: secret.to_string(),
            enabled: true,
            created_est: now_est,
        })
    }

    pub fn set_enabled(&self, endpoint_id: &str, enabled: bool) -> Result<(), String> {
        let conn = open(&self.db_path)?;
        conn.execute(
            "UPDATE webhook_endpoints SET enabled=?2 WHERE endpoint_id=?1",
            params![endpoint_id, enabled as i64],
        )
        .map_err(|e| format!("update webhook endpoint: {e}"))?;
        Ok(())
    }

    pub fn endpoints(&self) -> Result<Vec<WebhookEndpoint>, String> {
        let conn = open(&self.db_path)?;
        let mut stmt = conn
            .prepare(
                "SELECT endpoint_id,url,secret,enabled,created_est
                 FROM webhook_endpoints ORDER BY endpoint_id ASC",
            )
            .map_err(|e| format!("endpoint query: {e}"))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(WebhookEndpoint {
                    endpoint_id: r.get(0)?,
                    url: r.get(1)?,
                    secret: r.get(2)?,
                    enabled: r.get::<_, i64>(3)? != 0,
                    created_est: r.get(4)?,
                })
            })
            .map_err(|e| format!("endpoint rows: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("endpoint row: {e}"))
    }

    /// Persist one delivery per enabled endpoint. Returns the created delivery ids.
    pub fn enqueue(
        &self,
        event_type: &str,
        payload_json: &str,
        now_est: i64,
    ) -> Result<Vec<String>, String> {
        let conn = open(&self.db_path)?;
        let endpoints: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT endpoint_id FROM webhook_endpoints WHERE enabled=1")
                .map_err(|e| format!("endpoint list: {e}"))?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(|e| format!("endpoint list rows: {e}"))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("endpoint list row: {e}"))?
        };
        let mut created = Vec::new();
        for endpoint_id in endpoints {
            let mut hasher = sha2::Sha256::new();
            use sha2::Digest;
            hasher.update(b"TirBase/v1/WebhookDelivery\0");
            hasher.update(endpoint_id.as_bytes());
            hasher.update(event_type.as_bytes());
            hasher.update(payload_json.as_bytes());
            hasher.update(now_est.to_le_bytes());
            hasher.update(created.len().to_le_bytes());
            let delivery_id = hex::encode(&hasher.finalize()[..16]);
            conn.execute(
                "INSERT OR IGNORE INTO webhook_deliveries(
                    delivery_id,endpoint_id,event_type,payload_json,attempts,
                    next_attempt_est,status,created_est
                 ) VALUES (?1,?2,?3,?4,0,?5,'pending',?5)",
                params![delivery_id, endpoint_id, event_type, payload_json, now_est],
            )
            .map_err(|e| format!("enqueue webhook: {e}"))?;
            crate::metrics::global_metrics()
                .inc_alarm_delivery(vertical_for_event(event_type), "queued");
            created.push(delivery_id);
        }
        Ok(created)
    }

    pub fn pending(&self, now_est: i64) -> Result<Vec<WebhookDelivery>, String> {
        let conn = open(&self.db_path)?;
        let mut stmt = conn
            .prepare(
                "SELECT delivery_id,endpoint_id,event_type,payload_json,attempts,
                        next_attempt_est,status,last_error,created_est
                 FROM webhook_deliveries
                 WHERE status='pending' AND next_attempt_est <= ?1
                 ORDER BY next_attempt_est ASC LIMIT 100",
            )
            .map_err(|e| format!("pending webhook query: {e}"))?;
        let rows = stmt
            .query_map([now_est], |r| {
                Ok(WebhookDelivery {
                    delivery_id: r.get(0)?,
                    endpoint_id: r.get(1)?,
                    event_type: r.get(2)?,
                    payload_json: r.get(3)?,
                    attempts: r.get::<_, i64>(4)? as u32,
                    next_attempt_est: r.get(5)?,
                    status: r.get(6)?,
                    last_error: r.get(7)?,
                    created_est: r.get(8)?,
                })
            })
            .map_err(|e| format!("pending webhook rows: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("pending webhook row: {e}"))
    }

    /// Attempt every due delivery once. Returns `(delivered, failed)`.
    pub fn deliver_pending(
        &self,
        transport: &dyn WebhookTransport,
        now_est: i64,
    ) -> Result<(usize, usize), String> {
        let conn = open(&self.db_path)?;
        let endpoints = self.endpoint_map()?;
        let mut delivered = 0usize;
        let mut failed = 0usize;
        for delivery in self.pending(now_est)? {
            let vertical = vertical_for_event(&delivery.event_type);
            let mut span = crate::telemetry::Span::start("webhook.delivery");
            span.set_attr("vertical", vertical);
            span.set_attr("event_type", delivery.event_type.clone());
            let Some(endpoint) = endpoints.get(&delivery.endpoint_id) else {
                conn.execute(
                    "UPDATE webhook_deliveries SET status='dead', last_error='endpoint removed'
                     WHERE delivery_id=?1",
                    params![delivery.delivery_id],
                )
                .map_err(|e| format!("webhook endpoint removal: {e}"))?;
                crate::metrics::global_metrics().inc_alarm_delivery(vertical, "dead");
                span.set_attr("outcome", "dead");
                span.finish("error");
                continue;
            };
            let headers = signed_headers(
                &endpoint.secret,
                &delivery.delivery_id,
                now_est,
                &delivery.payload_json,
            )?;
            match transport.post(&endpoint.url, &headers.as_map(), &delivery.payload_json) {
                Ok(status) if (200..300).contains(&status) => {
                    conn.execute(
                        "UPDATE webhook_deliveries
                         SET status='delivered', attempts=attempts+1, last_error=NULL
                         WHERE delivery_id=?1",
                        params![delivery.delivery_id],
                    )
                    .map_err(|e| format!("mark webhook delivered: {e}"))?;
                    let metrics = crate::metrics::global_metrics();
                    metrics.inc_alarm_delivery(vertical, "delivered");
                    let end_to_end = now_est.saturating_sub(delivery.created_est).max(0) as u64;
                    metrics.observe_alarm_delivery(std::time::Duration::from_secs(end_to_end));
                    metrics.inc_adapter_operation("https", "webhook_delivery", "ok");
                    span.set_attr("outcome", "delivered");
                    span.finish("ok");
                    delivered += 1;
                }
                Ok(status) => {
                    let error = format!("HTTP {status}");
                    self.record_failure(&conn, &delivery, now_est, &error)?;
                    crate::metrics::global_metrics().inc_alarm_delivery(vertical, "failed");
                    crate::metrics::global_metrics().inc_adapter_operation(
                        "https",
                        "webhook_delivery",
                        "error",
                    );
                    span.set_attr("outcome", "failed");
                    span.set_attr("http.status", status.to_string());
                    span.finish("error");
                    failed += 1;
                }
                Err(error) => {
                    self.record_failure(&conn, &delivery, now_est, &error)?;
                    crate::metrics::global_metrics().inc_alarm_delivery(vertical, "failed");
                    crate::metrics::global_metrics().inc_adapter_operation(
                        "https",
                        "webhook_delivery",
                        "error",
                    );
                    span.set_attr("outcome", "failed");
                    span.finish("error");
                    failed += 1;
                }
            }
            crate::telemetry::audit(
                "webhook.delivery",
                "attempted",
                &[
                    ("vertical", vertical),
                    ("event_type", delivery.event_type.as_str()),
                ],
            );
        }
        Ok((delivered, failed))
    }

    fn endpoint_map(&self) -> Result<BTreeMap<String, WebhookEndpoint>, String> {
        Ok(self
            .endpoints()?
            .into_iter()
            .map(|e| (e.endpoint_id.clone(), e))
            .collect())
    }

    fn record_failure(
        &self,
        conn: &Connection,
        delivery: &WebhookDelivery,
        now_est: i64,
        error: &str,
    ) -> Result<(), String> {
        let attempts = delivery.attempts.saturating_add(1);
        let backoff = 5i64
            .saturating_mul(2i64.saturating_pow(attempts.min(6)))
            .min(300);
        let status = if attempts >= MAX_WEBHOOK_ATTEMPTS {
            "dead"
        } else {
            "pending"
        };
        conn.execute(
            "UPDATE webhook_deliveries
             SET attempts=?2, next_attempt_est=?3, status=?4, last_error=?5
             WHERE delivery_id=?1",
            params![
                delivery.delivery_id,
                attempts as i64,
                now_est.saturating_add(backoff),
                status,
                error
            ],
        )
        .map_err(|e| format!("record webhook failure: {e}"))?;
        Ok(())
    }

    /// Receiver-side replay guard: records a delivery id exactly once.
    pub fn mark_seen(&self, delivery_id: &str, now_est: i64) -> Result<bool, String> {
        let conn = open(&self.db_path)?;
        let changed = conn
            .execute(
                "INSERT OR IGNORE INTO webhook_seen_deliveries(delivery_id,received_est)
                 VALUES (?1,?2)",
                params![delivery_id, now_est],
            )
            .map_err(|e| format!("record webhook delivery: {e}"))?;
        Ok(changed > 0)
    }
}

pub fn signing_bytes(timestamp: i64, body: &str) -> Vec<u8> {
    format!("{timestamp}.{body}").into_bytes()
}

/// RFC 2104 HMAC-SHA256 (implemented locally because the workspace already
/// uses the sha2 0.11 digest API, which the `hmac` crate does not target).
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        key_block[..32].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    let mut outer = Sha256::new();
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    inner.update(ipad);
    inner.update(message);
    let inner = inner.finalize();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

pub fn sign_webhook(secret: &str, timestamp: i64, body: &str) -> Result<String, String> {
    let mac = hmac_sha256(secret.as_bytes(), &signing_bytes(timestamp, body));
    Ok(format!("sha256={}", hex::encode(mac)))
}

pub fn signed_headers(
    secret: &str,
    delivery_id: &str,
    timestamp: i64,
    body: &str,
) -> Result<WebhookHeaders, String> {
    Ok(WebhookHeaders {
        delivery_id: delivery_id.to_string(),
        timestamp,
        signature: sign_webhook(secret, timestamp, body)?,
    })
}

/// Verify timestamp freshness, HMAC, and (optionally) replay state.
pub fn verify_webhook(
    dispatcher: &WebhookDispatcher,
    secret: &str,
    headers: &WebhookHeaders,
    body: &str,
    now_est: i64,
    enforce_replay: bool,
) -> Result<(), String> {
    if (now_est - headers.timestamp).abs() > WEBHOOK_TIMESTAMP_TOLERANCE_SECS {
        return Err("webhook timestamp outside tolerance window".to_string());
    }
    let expected = sign_webhook(secret, headers.timestamp, body)?;
    if !constant_time_eq(expected.as_bytes(), headers.signature.as_bytes()) {
        return Err("webhook signature mismatch".to_string());
    }
    if enforce_replay && !dispatcher.mark_seen(&headers.delivery_id, now_est)? {
        return Err("webhook delivery replay rejected".to_string());
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}
