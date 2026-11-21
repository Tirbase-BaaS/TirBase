// SPDX-License-Identifier: AGPL-3.0-only

//! F-08 vertical admin resources for cold-chain, POS and venue objects.
//!
//! The routes share one tenant-scoped, revisioned object store:
//!
//! ```text
//! /admin/cold-chain/sites                 GET, POST
//! /admin/cold-chain/sites/{id}            GET, PATCH, DELETE
//! /admin/cold-chain/sites/{id}/readings   GET, POST
//! /admin/pos/orders                       GET, POST
//! /admin/pos/orders/{id}                  GET, PATCH, DELETE
//! /admin/pos/orders/{id}/lines            GET, POST
//! /admin/venues                           GET, POST
//! /admin/venues/{id}                      GET, PATCH, DELETE
//! /admin/venues/{id}/gates                GET, POST
//! ```
//!
//! Every mutation accepts `tenant` (default `default`) and optional
//! `idempotency_key`. Replaying a create with the same key returns the original
//! object and `idempotent_replay: true`. Lists are paginated with
//! `limit`/`cursor` and always filtered by tenant.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::webhooks::WebhookDispatcher;

pub const MAX_PAGE_SIZE: usize = 200;
pub const DEFAULT_PAGE_SIZE: usize = 50;

/// Canonical F-08 route templates. Contract tests assert that each one is
/// documented in OpenAPI and present in both generated SDKs.
pub const VERTICAL_ROUTE_TEMPLATES: &[&str] = &[
    "/admin/cold-chain/sites",
    "/admin/cold-chain/sites/{id}",
    "/admin/cold-chain/sites/{id}/readings",
    "/admin/pos/orders",
    "/admin/pos/orders/{id}",
    "/admin/pos/orders/{id}/lines",
    "/admin/venues",
    "/admin/venues/{id}",
    "/admin/venues/{id}/gates",
];

#[derive(Debug)]
pub struct VerticalApi {
    db_path: PathBuf,
    webhooks: Option<Arc<WebhookDispatcher>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Route {
    vertical: String,
    kind: String,
    id: Option<String>,
    child: Option<String>,
}

impl Route {
    /// `(collection, item, child-collection)` shape used by the handler.
    fn collection(&self) -> &str {
        if self.child.is_some() {
            self.child.as_deref().unwrap_or_default()
        } else {
            &self.kind
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerticalObject {
    pub id: String,
    pub vertical: String,
    pub kind: String,
    pub tenant: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    pub revision: i64,
    pub created_est: i64,
    pub updated_est: i64,
    pub data: Value,
}

fn ensure_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS vertical_objects (
            id              TEXT PRIMARY KEY,
            vertical        TEXT NOT NULL,
            kind            TEXT NOT NULL,
            tenant          TEXT NOT NULL,
            parent_id       TEXT,
            data_json       TEXT NOT NULL,
            revision        INTEGER NOT NULL DEFAULT 1,
            idempotency_key TEXT,
            created_est     INTEGER NOT NULL,
            updated_est     INTEGER NOT NULL
         );
         CREATE UNIQUE INDEX IF NOT EXISTS idx_vertical_idempotency
            ON vertical_objects(tenant, vertical, kind, idempotency_key)
            WHERE idempotency_key IS NOT NULL;
         CREATE INDEX IF NOT EXISTS idx_vertical_list
            ON vertical_objects(vertical, kind, tenant, parent_id, created_est);",
    )
    .map_err(|e| format!("ensure vertical object schema: {e}"))
}

fn valid_name(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | ' '))
}

fn validate_kind(vertical: &str, kind: &str) -> bool {
    matches!(
        (vertical, kind),
        ("cold-chain", "sites")
            | ("cold-chain", "readings")
            | ("pos", "orders")
            | ("pos", "lines")
            | ("venues", "venues")
            | ("venues", "gates")
    )
}

fn is_child_kind(kind: &str) -> bool {
    matches!(kind, "readings" | "lines" | "gates")
}

fn child_kind(vertical: &str, parent_kind: &str) -> Option<&'static str> {
    match (vertical, parent_kind) {
        ("cold-chain", "sites") => Some("readings"),
        ("pos", "orders") => Some("lines"),
        ("venues", "venues") => Some("gates"),
        _ => None,
    }
}

fn singular(kind: &str) -> &str {
    match kind {
        "sites" => "site",
        "readings" => "reading",
        "orders" => "order",
        "lines" => "line",
        "venues" => "venue",
        "gates" => "gate",
        other => other,
    }
}

fn parse_route(path: &str) -> Option<Route> {
    let path = path.split('?').next().unwrap_or(path);
    let rest = path.strip_prefix("/admin/")?;
    let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    match segments.as_slice() {
        // Venues are their own root collection (`/admin/venues`), unlike
        // cold-chain and POS which always have an explicit kind segment.
        ["venues"] => Some(Route {
            vertical: "venues".to_string(),
            kind: "venues".to_string(),
            id: None,
            child: None,
        }),
        ["venues", id] if valid_name(id, 64) => Some(Route {
            vertical: "venues".to_string(),
            kind: "venues".to_string(),
            id: Some(id.to_string()),
            child: None,
        }),
        ["venues", id, child]
            if valid_name(id, 64) && child_kind("venues", "venues") == Some(*child) =>
        {
            Some(Route {
                vertical: "venues".to_string(),
                kind: "venues".to_string(),
                id: Some(id.to_string()),
                child: Some(child.to_string()),
            })
        }
        [vertical, kind] if validate_kind(vertical, kind) && !is_child_kind(kind) => Some(Route {
            vertical: vertical.to_string(),
            kind: kind.to_string(),
            id: None,
            child: None,
        }),
        [vertical, kind, id]
            if validate_kind(vertical, kind) && !is_child_kind(kind) && valid_name(id, 64) =>
        {
            Some(Route {
                vertical: vertical.to_string(),
                kind: kind.to_string(),
                id: Some(id.to_string()),
                child: None,
            })
        }
        [vertical, kind, id, child]
            if validate_kind(vertical, kind)
                && valid_name(id, 64)
                && child_kind(vertical, kind) == Some(*child) =>
        {
            Some(Route {
                vertical: vertical.to_string(),
                kind: kind.to_string(),
                id: Some(id.to_string()),
                child: Some(child.to_string()),
            })
        }
        _ => None,
    }
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn query_map(path: &str) -> BTreeMap<String, String> {
    let Some((_, query)) = path.split_once('?') else {
        return BTreeMap::new();
    };
    query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            (percent_decode(key), percent_decode(value))
        })
        .collect()
}

fn tenant_from(body: &Value, query: &BTreeMap<String, String>) -> Result<String, String> {
    let tenant = body
        .get("tenant")
        .and_then(Value::as_str)
        .or_else(|| query.get("tenant").map(String::as_str))
        .unwrap_or("default");
    if !valid_name(tenant, 64) {
        return Err("invalid tenant".to_string());
    }
    Ok(tenant.to_string())
}

fn validate_resource(kind: &str, data: &Value) -> Result<(), String> {
    let obj = data
        .as_object()
        .ok_or_else(|| "request body must be a JSON object".to_string())?;
    let required_string = |field: &str| -> Result<(), String> {
        obj.get(field)
            .and_then(Value::as_str)
            .filter(|v| valid_name(v, 128))
            .map(|_| ())
            .ok_or_else(|| format!("{kind}.{field} must be a non-empty string"))
    };
    let required_int = |field: &str| -> Result<i64, String> {
        obj.get(field)
            .and_then(Value::as_i64)
            .ok_or_else(|| format!("{kind}.{field} must be an integer"))
    };
    match kind {
        "sites" | "venues" => required_string("name")?,
        "gates" => required_string("name")?,
        "readings" => {
            required_int("celsius_milli")?;
        }
        "orders" => {
            let currency = obj
                .get("currency")
                .and_then(Value::as_str)
                .ok_or_else(|| "orders.currency is required".to_string())?;
            if currency.len() != 3 || !currency.chars().all(|c| c.is_ascii_alphabetic()) {
                return Err("orders.currency must be a 3-letter ISO 4217 code".to_string());
            }
            if required_int("total_minor")? < 0 {
                return Err("orders.total_minor must be >= 0".to_string());
            }
        }
        "lines" => {
            required_string("sku")?;
            if required_int("quantity")? <= 0 {
                return Err("lines.quantity must be > 0".to_string());
            }
            if required_int("unit_price_minor")? < 0 {
                return Err("lines.unit_price_minor must be >= 0".to_string());
            }
        }
        _ => return Err("unsupported resource".to_string()),
    }
    Ok(())
}

fn random_id(prefix: &str, seed: &Value, now_est: i64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"TirBase/v1/VerticalObjectId\0");
    hasher.update(prefix.as_bytes());
    hasher.update(now_est.to_le_bytes());
    hasher.update(seed.to_string().as_bytes());
    hasher.update(std::process::id().to_le_bytes());
    let mut nonce = [0u8; 8];
    let _ = getrandom::getrandom(&mut nonce);
    hasher.update(nonce);
    format!("{prefix}-{}", hex::encode(&hasher.finalize()[..12]))
}

fn row_to_object(row: &rusqlite::Row<'_>) -> rusqlite::Result<VerticalObject> {
    let data_json: String = row.get(6)?;
    Ok(VerticalObject {
        id: row.get(0)?,
        vertical: row.get(1)?,
        kind: row.get(2)?,
        tenant: row.get(3)?,
        parent_id: row.get(4)?,
        revision: row.get(5)?,
        data: serde_json::from_str(&data_json).unwrap_or(Value::Null),
        created_est: row.get(7)?,
        updated_est: row.get(8)?,
    })
}

const SELECT_COLUMNS: &str =
    "id,vertical,kind,tenant,parent_id,revision,data_json,created_est,updated_est";

impl VerticalApi {
    pub fn open(db_path: impl Into<PathBuf>) -> Result<Self, String> {
        let db_path = db_path.into();
        ensure_schema(&Connection::open(&db_path).map_err(|e| format!("open vertical db: {e}"))?)?;
        Ok(Self {
            db_path,
            webhooks: None,
        })
    }

    pub fn with_webhooks(mut self, dispatcher: Arc<WebhookDispatcher>) -> Self {
        self.webhooks = Some(dispatcher);
        self
    }

    pub fn webhooks(&self) -> Option<&Arc<WebhookDispatcher>> {
        self.webhooks.as_ref()
    }

    fn conn(&self) -> Result<Connection, String> {
        Connection::open(&self.db_path).map_err(|e| format!("open vertical db: {e}"))
    }

    fn emit(&self, vertical: &str, kind: &str, action: &str, object: &VerticalObject, now: i64) {
        if let Some(webhooks) = &self.webhooks {
            let payload = json!({
                "type": format!("{vertical}.{}.{action}", singular(kind)),
                "created_est": now,
                "data": object,
            });
            if let Err(error) = webhooks.enqueue(
                payload["type"].as_str().unwrap_or("vertical.object"),
                &payload.to_string(),
                now,
            ) {
                tracing::warn!(%error, "webhook enqueue failed");
            }
        }
    }

    /// Route one vertical API request. Returns `(http_status, json_body)`.
    pub fn dispatch(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        now_est: i64,
    ) -> (u16, String) {
        self.dispatch_with_trace(method, path, body, now_est, None)
    }

    /// Dispatch with optional W3C `traceparent` propagation. The admin HTTP
    /// listener passes the caller's header; internal callers use `None`.
    pub fn dispatch_with_trace(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        now_est: i64,
        traceparent: Option<&str>,
    ) -> (u16, String) {
        let started = Instant::now();
        let method_upper = method.to_ascii_uppercase();
        let mut span =
            crate::telemetry::Span::from_traceparent("vertical_api.dispatch", traceparent);
        span.set_attr("http.method", method_upper.clone());
        let Some(route) = parse_route(path) else {
            span.set_attr("vertical", "unknown");
            span.set_attr("http.status", "404");
            span.finish("error");
            crate::metrics::global_metrics().observe_vertical_request("unknown", started.elapsed());
            return (
                404,
                json!({"status":404,"code":"VERTICAL_ROUTE_NOT_FOUND","error":"unknown vertical route"})
                    .to_string(),
            );
        };
        span.set_attr("vertical", route.vertical.clone());
        span.set_attr("vertical.kind", route.collection().to_string());
        let query = query_map(path);
        let parsed_body: Value = body
            .map(str::trim)
            .filter(|b| !b.is_empty())
            .and_then(|b| serde_json::from_str(b).ok())
            .unwrap_or_else(|| json!({}));
        let result = match (method_upper.as_str(), &route.id, &route.child) {
            ("GET", None, None) => self.list(&route, &query, now_est),
            ("POST", None, None) => self.create(&route, &parsed_body, &query, now_est),
            ("GET", Some(id), None) => self.get(&route, id, &query),
            ("PATCH", Some(id), None) => self.patch(&route, id, &parsed_body, &query, now_est),
            ("DELETE", Some(id), None) => self.delete(&route, id, &query, now_est),
            ("GET", Some(parent), Some(_)) => self.list_child(&route, parent, &query),
            ("POST", Some(parent), Some(_)) => {
                self.create_child(&route, parent, &parsed_body, &query, now_est)
            }
            _ => (
                405,
                json!({"status":405,"code":"METHOD_NOT_ALLOWED","error":"method not allowed"})
                    .to_string(),
            ),
        };
        self.record_dispatch_metrics(&route, &method_upper, started.elapsed(), &result, now_est);
        span.set_attr("http.status", result.0.to_string());
        span.finish(if result.0 >= 500 { "error" } else { "ok" });
        crate::telemetry::audit(
            "vertical.object.request",
            if result.0 < 300 {
                "accepted"
            } else {
                "rejected"
            },
            &[
                ("vertical", route.vertical.as_str()),
                ("kind", route.collection()),
                ("method", method_upper.as_str()),
            ],
        );
        result
    }

    fn record_dispatch_metrics(
        &self,
        route: &Route,
        method: &str,
        elapsed: Duration,
        result: &(u16, String),
        now_est: i64,
    ) {
        let metrics = crate::metrics::global_metrics();
        metrics.observe_vertical_request(&route.vertical, elapsed);
        let outcome = if result.0 < 300 {
            "accepted"
        } else {
            "rejected"
        };
        let kind = route.collection();

        // Vertical ledger appends are readings, order lines and gate events.
        if method == "POST" && matches!(kind, "readings" | "lines" | "gates") {
            metrics.inc_vertical_append(&route.vertical);
            metrics.observe_ledger_append(elapsed);
        }

        // A venue gate transition is the F-08 gate decision surface.
        if route.vertical == "venues" && kind == "gates" && method != "GET" {
            metrics.observe_gate_decision(elapsed);
            metrics.inc_gate_decision("venues", outcome);
        }

        // Payment intent completion: a POS order transitioned to a terminal
        // payment status. The latency is measured from order creation.
        if route.vertical == "pos" && kind == "orders" && method == "PATCH" {
            if let Ok(body) = serde_json::from_str::<Value>(&result.1) {
                let object = body.get("object").unwrap_or(&Value::Null);
                let status = object
                    .get("data")
                    .and_then(|data| data.get("payment_status"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                if matches!(
                    status.as_str(),
                    "paid" | "captured" | "completed" | "succeeded"
                ) {
                    let created = object
                        .get("created_est")
                        .and_then(Value::as_i64)
                        .unwrap_or(now_est);
                    let seconds = now_est.saturating_sub(created).max(0) as f64;
                    metrics.observe_payment_intent_completion(Duration::from_secs_f64(seconds));
                    metrics.inc_payment_intent("pos", "completed");
                } else if result.0 >= 500 {
                    metrics.inc_payment_intent("pos", "failed");
                }
            }
        }
    }

    fn list(
        &self,
        route: &Route,
        query: &BTreeMap<String, String>,
        _now_est: i64,
    ) -> (u16, String) {
        let tenant = match tenant_from(&json!({}), query) {
            Ok(t) => t,
            Err(e) => return bad_request(&e),
        };
        self.list_inner(route, &tenant, None, query)
    }

    fn list_child(
        &self,
        route: &Route,
        parent: &str,
        query: &BTreeMap<String, String>,
    ) -> (u16, String) {
        let tenant = match tenant_from(&json!({}), query) {
            Ok(t) => t,
            Err(e) => return bad_request(&e),
        };
        // The child collection is only visible through an existing parent in
        // the same tenant.
        match self.find_kind(&route.vertical, &route.kind, parent, &tenant) {
            Ok(Some(_)) => self.list_inner(route, &tenant, Some(parent), query),
            Ok(None) => not_found("parent object"),
            Err(e) => store_error(&e),
        }
    }

    fn list_inner(
        &self,
        route: &Route,
        tenant: &str,
        parent: Option<&str>,
        query: &BTreeMap<String, String>,
    ) -> (u16, String) {
        let kind = route.collection();
        let limit = query
            .get("limit")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_PAGE_SIZE)
            .clamp(1, MAX_PAGE_SIZE);
        let offset = query
            .get("cursor")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        let conn = match self.conn() {
            Ok(c) => c,
            Err(e) => return store_error(&e),
        };
        let total: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM vertical_objects
                 WHERE vertical=?1 AND kind=?2 AND tenant=?3 AND parent_id IS ?4",
                params![route.vertical, kind, tenant, parent],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM vertical_objects
             WHERE vertical=?1 AND kind=?2 AND tenant=?3 AND parent_id IS ?4
             ORDER BY created_est ASC, id ASC LIMIT ?5 OFFSET ?6"
        );
        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(e) => return store_error(&format!("prepare list: {e}")),
        };
        let items: Vec<VerticalObject> = match stmt.query_map(
            params![
                route.vertical,
                kind,
                tenant,
                parent,
                limit as i64,
                offset as i64
            ],
            row_to_object,
        ) {
            Ok(rows) => rows.filter_map(Result::ok).collect(),
            Err(e) => return store_error(&format!("list rows: {e}")),
        };
        let next =
            ((offset + items.len()) < total as usize).then(|| (offset + items.len()).to_string());
        (
            200,
            json!({
                "status": 200,
                "vertical": route.vertical,
                "kind": kind,
                "tenant": tenant,
                "items": items,
                "total": total,
                "next_cursor": next,
            })
            .to_string(),
        )
    }

    fn find_kind(
        &self,
        vertical: &str,
        kind: &str,
        id: &str,
        tenant: &str,
    ) -> Result<Option<VerticalObject>, String> {
        let conn = self.conn()?;
        conn.query_row(
            &format!(
                "SELECT {SELECT_COLUMNS} FROM vertical_objects
                 WHERE id=?1 AND vertical=?2 AND kind=?3 AND tenant=?4"
            ),
            params![id, vertical, kind, tenant],
            row_to_object,
        )
        .optional()
        .map_err(|e| format!("find object: {e}"))
    }

    fn find(
        &self,
        route: &Route,
        id: &str,
        tenant: &str,
    ) -> Result<Option<VerticalObject>, String> {
        self.find_kind(&route.vertical, route.collection(), id, tenant)
    }

    fn get(&self, route: &Route, id: &str, query: &BTreeMap<String, String>) -> (u16, String) {
        let tenant = match tenant_from(&json!({}), query) {
            Ok(t) => t,
            Err(e) => return bad_request(&e),
        };
        match self.find(route, id, &tenant) {
            Ok(Some(obj)) => (200, json!({"status":200,"object":obj}).to_string()),
            Ok(None) => not_found("object"),
            Err(e) => store_error(&e),
        }
    }

    fn create(
        &self,
        route: &Route,
        body: &Value,
        query: &BTreeMap<String, String>,
        now_est: i64,
    ) -> (u16, String) {
        let tenant = match tenant_from(body, query) {
            Ok(t) => t,
            Err(e) => return bad_request(&e),
        };
        self.create_inner(route, None, body, &tenant, now_est)
    }

    fn create_child(
        &self,
        route: &Route,
        parent: &str,
        body: &Value,
        query: &BTreeMap<String, String>,
        now_est: i64,
    ) -> (u16, String) {
        let tenant = match tenant_from(body, query) {
            Ok(t) => t,
            Err(e) => return bad_request(&e),
        };
        match self.find_kind(&route.vertical, &route.kind, parent, &tenant) {
            Ok(Some(_)) => self.create_inner(route, Some(parent), body, &tenant, now_est),
            Ok(None) => not_found("parent object"),
            Err(e) => store_error(&e),
        }
    }

    fn create_inner(
        &self,
        route: &Route,
        parent: Option<&str>,
        body: &Value,
        tenant: &str,
        now_est: i64,
    ) -> (u16, String) {
        let kind = route.collection();
        let mut data = body.clone();
        if let Some(obj) = data.as_object_mut() {
            obj.remove("tenant");
            obj.remove("idempotency_key");
        }
        if let Err(e) = validate_resource(kind, &data) {
            return bad_request(&e);
        }
        let idempotency_key = body
            .get("idempotency_key")
            .and_then(Value::as_str)
            .filter(|v| valid_name(v, 128));
        let conn = match self.conn() {
            Ok(c) => c,
            Err(e) => return store_error(&e),
        };
        if let Some(key) = idempotency_key {
            if let Ok(Some(existing)) = conn
                .query_row(
                    &format!(
                        "SELECT {SELECT_COLUMNS} FROM vertical_objects
                         WHERE tenant=?1 AND vertical=?2 AND kind=?3 AND idempotency_key=?4"
                    ),
                    params![tenant, route.vertical, kind, key],
                    row_to_object,
                )
                .optional()
            {
                return (
                    200,
                    json!({"status":200,"idempotent_replay":true,"object":existing}).to_string(),
                );
            }
        }
        let id = body
            .get("id")
            .and_then(Value::as_str)
            .filter(|v| valid_name(v, 64))
            .map(str::to_string)
            .unwrap_or_else(|| random_id(singular(kind), body, now_est));
        let data_json = data.to_string();
        if let Err(e) = conn.execute(
            "INSERT INTO vertical_objects(
                id,vertical,kind,tenant,parent_id,data_json,revision,idempotency_key,
                created_est,updated_est
             ) VALUES (?1,?2,?3,?4,?5,?6,1,?7,?8,?8)",
            params![
                id,
                route.vertical,
                kind,
                tenant,
                parent,
                data_json,
                idempotency_key,
                now_est
            ],
        ) {
            if format!("{e}").contains("UNIQUE") {
                return (
                    409,
                    json!({"status":409,"code":"VERTICAL_ID_CONFLICT","error":"object id already exists"})
                        .to_string(),
                );
            }
            return store_error(&format!("create object: {e}"));
        }
        let object = VerticalObject {
            id: id.clone(),
            vertical: route.vertical.clone(),
            kind: kind.to_string(),
            tenant: tenant.to_string(),
            parent_id: parent.map(str::to_string),
            revision: 1,
            created_est: now_est,
            updated_est: now_est,
            data,
        };
        self.emit(&route.vertical, kind, "created", &object, now_est);
        (201, json!({"status":201,"object":object}).to_string())
    }

    fn patch(
        &self,
        route: &Route,
        id: &str,
        body: &Value,
        query: &BTreeMap<String, String>,
        now_est: i64,
    ) -> (u16, String) {
        let tenant = match tenant_from(body, query) {
            Ok(t) => t,
            Err(e) => return bad_request(&e),
        };
        let kind = route.collection();
        let mut existing = match self.find(route, id, &tenant) {
            Ok(Some(obj)) => obj,
            Ok(None) => return not_found("object"),
            Err(e) => return store_error(&e),
        };
        if let Some(obj) = body.as_object() {
            if let Some(data) = existing.data.as_object_mut() {
                for (key, value) in obj {
                    if !matches!(key.as_str(), "tenant" | "id" | "idempotency_key") {
                        data.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        if let Err(e) = validate_resource(kind, &existing.data) {
            return bad_request(&e);
        }
        let conn = match self.conn() {
            Ok(c) => c,
            Err(e) => return store_error(&e),
        };
        let revision = existing.revision + 1;
        if let Err(e) = conn.execute(
            "UPDATE vertical_objects
             SET data_json=?5, revision=?6, updated_est=?7
             WHERE id=?1 AND vertical=?2 AND kind=?3 AND tenant=?4",
            params![
                id,
                route.vertical,
                kind,
                tenant,
                existing.data.to_string(),
                revision,
                now_est
            ],
        ) {
            return store_error(&format!("update object: {e}"));
        }
        existing.revision = revision;
        existing.updated_est = now_est;
        self.emit(&route.vertical, kind, "updated", &existing, now_est);
        (200, json!({"status":200,"object":existing}).to_string())
    }

    fn delete(
        &self,
        route: &Route,
        id: &str,
        query: &BTreeMap<String, String>,
        now_est: i64,
    ) -> (u16, String) {
        let tenant = match tenant_from(&json!({}), query) {
            Ok(t) => t,
            Err(e) => return bad_request(&e),
        };
        let kind = route.collection();
        let object = match self.find(route, id, &tenant) {
            Ok(Some(obj)) => obj,
            Ok(None) => return not_found("object"),
            Err(e) => return store_error(&e),
        };
        let conn = match self.conn() {
            Ok(c) => c,
            Err(e) => return store_error(&e),
        };
        if let Err(e) = conn.execute(
            "DELETE FROM vertical_objects WHERE id=?1 AND vertical=?2 AND kind=?3 AND tenant=?4",
            params![id, route.vertical, kind, tenant],
        ) {
            return store_error(&format!("delete object: {e}"));
        }
        self.emit(&route.vertical, kind, "deleted", &object, now_est);
        (
            200,
            json!({"status":200,"deleted":true,"id":id,"vertical":route.vertical,"kind":kind})
                .to_string(),
        )
    }
}

fn bad_request(message: &str) -> (u16, String) {
    (
        400,
        json!({"status":400,"code":"VERTICAL_BAD_REQUEST","error":message}).to_string(),
    )
}

fn not_found(what: &str) -> (u16, String) {
    (
        404,
        json!({"status":404,"code":"VERTICAL_NOT_FOUND","error":format!("{what} not found")})
            .to_string(),
    )
}

fn store_error(message: &str) -> (u16, String) {
    (
        500,
        json!({"status":500,"code":"VERTICAL_STORE_ERROR","error":message}).to_string(),
    )
}

trait OptionalRow<T> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalRow<T> for Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error),
        }
    }
}
