// SPDX-License-Identifier: AGPL-3.0-only

//! SQLite persistence for the multi-site fleet service (CC-19).
//!
//! Every row carries its tenant path both as canonical JSON (for exact
//! reconstruction) and as the `TenantPath::as_fact_string()` rendering, which is
//! what makes tenant isolation a property of the query and not of the caller:
//! a subtree read is
//! `tenant_fact = ? OR substr(tenant_fact, 1, length(?) + 1) = ? || '/'`, so a
//! tenant can never match a sibling or an ancestor with a shared prefix.
//!
//! Tables:
//!
//! - `fleet_nodes` — sites, rooms, containers and gateways, with health,
//!   compliance, firmware channel, profile and reported config.
//! - `fleet_tenant_keys` — tenant key references by fingerprint (never the key).
//! - `fleet_configs` — desired configuration per tenant (or per site).
//! - `fleet_exports` — one row per audit export, scoped to its tenant.
//! - `fleet_cross_site_grants` — explicit cross-site capabilities.
//! - `fleet_rollouts` — bulk profile/firmware rollouts with their targets,
//!   applied set and pause evidence.

use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::types::Value;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Row};

use crate::fleet::{
    ComplianceStatus, CrossSiteGrant, FirmwareChannel, FleetError, FleetExport, FleetNode,
    FleetNodeKind, HealthStatus, RolloutKind, RolloutPause, RolloutPlan, RolloutState,
    RolloutTarget, TenantConfig, TenantKeyRef,
};
use tirbase_types::identity::TenantPath;

const NODE_COLUMNS: &str = "node_id, tenant_json, tenant_fact, kind, site_id, parent_id, name, \
     gateway_id, health, compliance, firmware_version, channel, profile_id, config_json, \
     updated_est";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS fleet_nodes (
    node_id          TEXT    PRIMARY KEY,
    tenant_json      TEXT    NOT NULL,
    tenant_fact      TEXT    NOT NULL,
    kind             TEXT    NOT NULL,
    site_id          TEXT    NOT NULL,
    parent_id        TEXT,
    name             TEXT    NOT NULL,
    gateway_id       TEXT,
    health           TEXT    NOT NULL,
    compliance       TEXT    NOT NULL,
    firmware_version TEXT    NOT NULL,
    channel          TEXT    NOT NULL,
    profile_id       TEXT    NOT NULL,
    config_json      TEXT    NOT NULL,
    updated_est      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fleet_nodes_tenant ON fleet_nodes(tenant_fact);
CREATE INDEX IF NOT EXISTS idx_fleet_nodes_site ON fleet_nodes(tenant_fact, site_id);
CREATE INDEX IF NOT EXISTS idx_fleet_nodes_kind ON fleet_nodes(tenant_fact, kind);

CREATE TABLE IF NOT EXISTS fleet_tenant_keys (
    key_id      TEXT    PRIMARY KEY,
    tenant_json TEXT    NOT NULL,
    tenant_fact TEXT    NOT NULL,
    purpose     TEXT    NOT NULL,
    fingerprint TEXT    NOT NULL,
    created_est INTEGER NOT NULL,
    revoked_est INTEGER
);
CREATE INDEX IF NOT EXISTS idx_fleet_tenant_keys_tenant ON fleet_tenant_keys(tenant_fact);

CREATE TABLE IF NOT EXISTS fleet_configs (
    config_id   TEXT    PRIMARY KEY,
    tenant_json TEXT    NOT NULL,
    tenant_fact TEXT    NOT NULL,
    site_id     TEXT,
    values_json TEXT    NOT NULL,
    updated_est INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fleet_configs_tenant ON fleet_configs(tenant_fact);

CREATE TABLE IF NOT EXISTS fleet_exports (
    export_id    TEXT    PRIMARY KEY,
    tenant_json  TEXT    NOT NULL,
    tenant_fact  TEXT    NOT NULL,
    sites_json   TEXT    NOT NULL,
    schema       TEXT    NOT NULL,
    digest       TEXT    NOT NULL,
    node_count   INTEGER NOT NULL,
    node_ids_json TEXT   NOT NULL,
    created_est  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fleet_exports_tenant ON fleet_exports(tenant_fact);

CREATE TABLE IF NOT EXISTS fleet_cross_site_grants (
    grant_id    TEXT    PRIMARY KEY,
    tenant_json TEXT    NOT NULL,
    tenant_fact TEXT    NOT NULL,
    sites_json  TEXT    NOT NULL,
    issued_by   TEXT    NOT NULL,
    issued_est  INTEGER NOT NULL,
    expires_est INTEGER NOT NULL,
    reason      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fleet_grants_tenant ON fleet_cross_site_grants(tenant_fact);

CREATE TABLE IF NOT EXISTS fleet_rollouts (
    operation_id  TEXT    PRIMARY KEY,
    tenant_json   TEXT    NOT NULL,
    tenant_fact   TEXT    NOT NULL,
    kind          TEXT    NOT NULL,
    value         TEXT    NOT NULL,
    channel       TEXT    NOT NULL,
    state         TEXT    NOT NULL,
    batch_size    INTEGER NOT NULL,
    targets_json  TEXT    NOT NULL,
    pause_json    TEXT,
    created_est   INTEGER NOT NULL,
    updated_est   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fleet_rollouts_tenant ON fleet_rollouts(tenant_fact);
"#;

fn store_error(error: impl std::fmt::Display) -> FleetError {
    FleetError::Store(error.to_string())
}

/// Durable store for the fleet service.
#[derive(Debug)]
pub struct FleetStore {
    conn: Connection,
}

impl FleetStore {
    /// Open the store at `path`, applying the gateway hardening pragmas.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, FleetError> {
        let conn = crate::db::open_primary(path)
            .map_err(|error| FleetError::Store(format!("open primary db: {error:?}")))?;
        Self::from_connection(conn)
    }

    /// Open an in-memory store (tests, ephemeral deployments).
    pub fn open_in_memory() -> Result<Self, FleetError> {
        let conn = Connection::open_in_memory().map_err(store_error)?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self, FleetError> {
        conn.execute_batch(SCHEMA)
            .map_err(|error| FleetError::Store(format!("create fleet schema: {error}")))?;
        Ok(Self { conn })
    }

    // -----------------------------------------------------------------------
    // Nodes
    // -----------------------------------------------------------------------

    /// Insert or replace one node.
    pub fn upsert_node(&self, node: &FleetNode) -> Result<(), FleetError> {
        let tenant_json = serde_json::to_string(&node.tenant)
            .map_err(|error| FleetError::Store(format!("encode node tenant: {error}")))?;
        let config = serde_json::to_string(&node.config)
            .map_err(|error| FleetError::Store(format!("encode node config: {error}")))?;
        self.conn
            .execute(
                "INSERT INTO fleet_nodes (node_id, tenant_json, tenant_fact, kind, site_id, \
                 parent_id, name, gateway_id, health, compliance, firmware_version, channel, \
                 profile_id, config_json, updated_est) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15) \
                 ON CONFLICT(node_id) DO UPDATE SET tenant_json=excluded.tenant_json, \
                 tenant_fact=excluded.tenant_fact, kind=excluded.kind, \
                 site_id=excluded.site_id, parent_id=excluded.parent_id, name=excluded.name, \
                 gateway_id=excluded.gateway_id, health=excluded.health, \
                 compliance=excluded.compliance, \
                 firmware_version=excluded.firmware_version, channel=excluded.channel, \
                 profile_id=excluded.profile_id, config_json=excluded.config_json, \
                 updated_est=excluded.updated_est",
                params![
                    node.node_id,
                    tenant_json,
                    node.tenant.as_fact_string(),
                    node.kind.as_str(),
                    node.site_id,
                    node.parent_id,
                    node.name,
                    node.gateway_id,
                    node.health.as_str(),
                    node.compliance.as_str(),
                    node.firmware_version,
                    node.channel.as_str(),
                    node.profile_id,
                    config,
                    node.updated_est,
                ],
            )
            .map_err(|error| FleetError::Store(format!("upsert fleet node: {error}")))?;
        Ok(())
    }

    /// One node by id, whatever its tenant.
    pub fn node(&self, node_id: &str) -> Result<Option<FleetNode>, FleetError> {
        let sql = format!("SELECT {NODE_COLUMNS} FROM fleet_nodes WHERE node_id=?1");
        self.conn
            .query_row(&sql, params![node_id], row_to_node)
            .optional()
            .map_err(store_error)
    }

    /// Count nodes matching a tenant subtree and the optional filters.
    pub fn count_nodes(
        &self,
        tenant_fact: &str,
        sites: &[String],
        kinds: &[FleetNodeKind],
        health: Option<HealthStatus>,
    ) -> Result<usize, FleetError> {
        let (where_sql, params) = node_filter(tenant_fact, sites, kinds, health, None);
        let sql = format!("SELECT COUNT(*) FROM fleet_nodes WHERE {where_sql}");
        let count: i64 = self
            .conn
            .query_row(&sql, params_from_iter(params.iter()), |row| row.get(0))
            .map_err(store_error)?;
        Ok(usize::try_from(count).unwrap_or(usize::MAX))
    }

    /// One page of nodes in a tenant subtree, ordered by id.
    pub fn page_nodes(
        &self,
        tenant_fact: &str,
        sites: &[String],
        kinds: &[FleetNodeKind],
        health: Option<HealthStatus>,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Vec<FleetNode>, FleetError> {
        let (where_sql, mut params) = node_filter(tenant_fact, sites, kinds, health, cursor);
        params.push(Value::Integer(i64::try_from(limit + 1).unwrap_or(i64::MAX)));
        let sql = format!(
            "SELECT {NODE_COLUMNS} FROM fleet_nodes WHERE {where_sql} ORDER BY node_id LIMIT ?"
        );
        let mut statement = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = statement
            .query_map(params_from_iter(params.iter()), row_to_node)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    /// Every node in a tenant subtree, ordered by id (used by exports/views).
    pub fn nodes_in_tenant(&self, tenant_fact: &str) -> Result<Vec<FleetNode>, FleetError> {
        let (where_sql, params) = node_filter(tenant_fact, &[], &[], None, None);
        let sql =
            format!("SELECT {NODE_COLUMNS} FROM fleet_nodes WHERE {where_sql} ORDER BY node_id");
        let mut statement = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = statement
            .query_map(params_from_iter(params.iter()), row_to_node)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    // -----------------------------------------------------------------------
    // Tenant keys
    // -----------------------------------------------------------------------

    /// Insert a tenant key reference.
    pub fn insert_tenant_key(&self, key: &TenantKeyRef) -> Result<(), FleetError> {
        let tenant_json = serde_json::to_string(&key.tenant)
            .map_err(|error| FleetError::Store(format!("encode key tenant: {error}")))?;
        self.conn
            .execute(
                "INSERT INTO fleet_tenant_keys (key_id, tenant_json, tenant_fact, purpose, \
                 fingerprint, created_est, revoked_est) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    key.key_id,
                    tenant_json,
                    key.tenant.as_fact_string(),
                    key.purpose,
                    key.fingerprint,
                    key.created_est,
                    key.revoked_est,
                ],
            )
            .map_err(|error| FleetError::Store(format!("insert tenant key: {error}")))?;
        Ok(())
    }

    /// Tenant key references in a subtree, oldest first.
    pub fn tenant_keys(&self, tenant_fact: &str) -> Result<Vec<TenantKeyRef>, FleetError> {
        let (where_sql, params) = tenant_filter(tenant_fact);
        let sql = format!(
            "SELECT key_id, tenant_json, purpose, fingerprint, created_est, revoked_est \
             FROM fleet_tenant_keys WHERE {where_sql} ORDER BY created_est, key_id"
        );
        let mut statement = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = statement
            .query_map(params_from_iter(params.iter()), row_to_tenant_key)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    // -----------------------------------------------------------------------
    // Configs
    // -----------------------------------------------------------------------

    /// Insert or replace one desired config.
    pub fn upsert_config(&self, config: &TenantConfig) -> Result<(), FleetError> {
        let tenant_json = serde_json::to_string(&config.tenant)
            .map_err(|error| FleetError::Store(format!("encode config tenant: {error}")))?;
        let values = serde_json::to_string(&config.values)
            .map_err(|error| FleetError::Store(format!("encode config values: {error}")))?;
        self.conn
            .execute(
                "INSERT INTO fleet_configs (config_id, tenant_json, tenant_fact, site_id, \
                 values_json, updated_est) VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(config_id) DO UPDATE SET tenant_json=excluded.tenant_json, \
                 tenant_fact=excluded.tenant_fact, site_id=excluded.site_id, \
                 values_json=excluded.values_json, updated_est=excluded.updated_est",
                params![
                    config.config_id,
                    tenant_json,
                    config.tenant.as_fact_string(),
                    config.site_id,
                    values,
                    config.updated_est,
                ],
            )
            .map_err(|error| FleetError::Store(format!("upsert tenant config: {error}")))?;
        Ok(())
    }

    /// One config by id, whatever its tenant.
    pub fn config(&self, config_id: &str) -> Result<Option<TenantConfig>, FleetError> {
        self.conn
            .query_row(
                "SELECT config_id, tenant_json, site_id, values_json, updated_est \
                 FROM fleet_configs WHERE config_id=?1",
                params![config_id],
                row_to_config,
            )
            .optional()
            .map_err(store_error)
    }

    /// Configs in a tenant subtree, oldest first.
    pub fn configs(&self, tenant_fact: &str) -> Result<Vec<TenantConfig>, FleetError> {
        let (where_sql, params) = tenant_filter(tenant_fact);
        let sql = format!(
            "SELECT config_id, tenant_json, site_id, values_json, updated_est \
             FROM fleet_configs WHERE {where_sql} ORDER BY config_id"
        );
        let mut statement = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = statement
            .query_map(params_from_iter(params.iter()), row_to_config)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    // -----------------------------------------------------------------------
    // Exports
    // -----------------------------------------------------------------------

    /// Insert one export row. Fails if the deterministic id already exists.
    pub fn insert_export(&self, export: &FleetExport) -> Result<(), FleetError> {
        let tenant_json = serde_json::to_string(&export.tenant)
            .map_err(|error| FleetError::Store(format!("encode export tenant: {error}")))?;
        let sites = serde_json::to_string(&export.site_ids)
            .map_err(|error| FleetError::Store(format!("encode export sites: {error}")))?;
        let nodes = serde_json::to_string(&export.node_ids)
            .map_err(|error| FleetError::Store(format!("encode export nodes: {error}")))?;
        self.conn
            .execute(
                "INSERT INTO fleet_exports (export_id, tenant_json, tenant_fact, sites_json, \
                 schema, digest, node_count, node_ids_json, created_est) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    export.export_id,
                    tenant_json,
                    export.tenant.as_fact_string(),
                    sites,
                    export.schema,
                    export.digest,
                    i64::try_from(export.node_count).unwrap_or(i64::MAX),
                    nodes,
                    export.created_est,
                ],
            )
            .map_err(|error| FleetError::Store(format!("insert fleet export: {error}")))?;
        Ok(())
    }

    /// One export by id, whatever its tenant.
    pub fn export(&self, export_id: &str) -> Result<Option<FleetExport>, FleetError> {
        self.conn
            .query_row(
                "SELECT export_id, tenant_json, sites_json, schema, digest, node_count, \
                 node_ids_json, created_est FROM fleet_exports WHERE export_id=?1",
                params![export_id],
                row_to_export,
            )
            .optional()
            .map_err(store_error)
    }

    /// Exports in a tenant subtree, oldest first.
    pub fn exports(&self, tenant_fact: &str) -> Result<Vec<FleetExport>, FleetError> {
        let (where_sql, params) = tenant_filter(tenant_fact);
        let sql = format!(
            "SELECT export_id, tenant_json, sites_json, schema, digest, node_count, \
             node_ids_json, created_est FROM fleet_exports WHERE {where_sql} \
             ORDER BY created_est, export_id"
        );
        let mut statement = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = statement
            .query_map(params_from_iter(params.iter()), row_to_export)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    // -----------------------------------------------------------------------
    // Cross-site grants
    // -----------------------------------------------------------------------

    /// Insert one cross-site grant. Fails if the id already exists.
    pub fn insert_grant(&self, grant: &CrossSiteGrant) -> Result<(), FleetError> {
        let tenant_json = serde_json::to_string(&grant.tenant)
            .map_err(|error| FleetError::Store(format!("encode grant tenant: {error}")))?;
        let sites = serde_json::to_string(&grant.sites)
            .map_err(|error| FleetError::Store(format!("encode grant sites: {error}")))?;
        self.conn
            .execute(
                "INSERT INTO fleet_cross_site_grants (grant_id, tenant_json, tenant_fact, \
                 sites_json, issued_by, issued_est, expires_est, reason) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    grant.grant_id,
                    tenant_json,
                    grant.tenant.as_fact_string(),
                    sites,
                    grant.issued_by,
                    grant.issued_est,
                    grant.expires_est,
                    grant.reason,
                ],
            )
            .map_err(|error| FleetError::Store(format!("insert cross-site grant: {error}")))?;
        Ok(())
    }

    /// One grant by id.
    pub fn grant(&self, grant_id: &str) -> Result<Option<CrossSiteGrant>, FleetError> {
        self.conn
            .query_row(
                "SELECT grant_id, tenant_json, sites_json, issued_by, issued_est, \
                 expires_est, reason FROM fleet_cross_site_grants WHERE grant_id=?1",
                params![grant_id],
                row_to_grant,
            )
            .optional()
            .map_err(store_error)
    }

    /// Grants in a tenant subtree, oldest first.
    pub fn grants(&self, tenant_fact: &str) -> Result<Vec<CrossSiteGrant>, FleetError> {
        let (where_sql, params) = tenant_filter(tenant_fact);
        let sql = format!(
            "SELECT grant_id, tenant_json, sites_json, issued_by, issued_est, expires_est, \
             reason FROM fleet_cross_site_grants WHERE {where_sql} ORDER BY issued_est, grant_id"
        );
        let mut statement = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = statement
            .query_map(params_from_iter(params.iter()), row_to_grant)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    // -----------------------------------------------------------------------
    // Rollouts
    // -----------------------------------------------------------------------

    /// Insert or replace one rollout plan.
    pub fn upsert_rollout(&self, plan: &RolloutPlan) -> Result<(), FleetError> {
        let tenant_json = serde_json::to_string(&plan.tenant)
            .map_err(|error| FleetError::Store(format!("encode rollout tenant: {error}")))?;
        let targets = serde_json::to_string(&plan.targets)
            .map_err(|error| FleetError::Store(format!("encode rollout targets: {error}")))?;
        let pause = match plan.pause.as_ref() {
            Some(pause) => Some(
                serde_json::to_string(pause)
                    .map_err(|error| FleetError::Store(format!("encode rollout pause: {error}")))?,
            ),
            None => None,
        };
        self.conn
            .execute(
                "INSERT INTO fleet_rollouts (operation_id, tenant_json, tenant_fact, kind, \
                 value, channel, state, batch_size, targets_json, pause_json, created_est, \
                 updated_est) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
                 ON CONFLICT(operation_id) DO UPDATE SET tenant_json=excluded.tenant_json, \
                 tenant_fact=excluded.tenant_fact, kind=excluded.kind, value=excluded.value, \
                 channel=excluded.channel, state=excluded.state, \
                 batch_size=excluded.batch_size, targets_json=excluded.targets_json, \
                 pause_json=excluded.pause_json, updated_est=excluded.updated_est",
                params![
                    plan.operation_id,
                    tenant_json,
                    plan.tenant.as_fact_string(),
                    plan.kind.as_str(),
                    plan.value,
                    plan.channel.as_str(),
                    plan.state.as_str(),
                    i64::try_from(plan.batch_size).unwrap_or(i64::MAX),
                    targets,
                    pause,
                    plan.created_est,
                    plan.updated_est,
                ],
            )
            .map_err(|error| FleetError::Store(format!("upsert rollout: {error}")))?;
        Ok(())
    }

    /// One rollout by id, whatever its tenant.
    pub fn rollout(&self, operation_id: &str) -> Result<Option<RolloutPlan>, FleetError> {
        self.conn
            .query_row(
                "SELECT operation_id, tenant_json, kind, value, channel, state, batch_size, \
                 targets_json, pause_json, created_est, updated_est \
                 FROM fleet_rollouts WHERE operation_id=?1",
                params![operation_id],
                row_to_rollout,
            )
            .optional()
            .map_err(store_error)
    }

    /// Rollouts in a tenant subtree, oldest first.
    pub fn rollouts(&self, tenant_fact: &str) -> Result<Vec<RolloutPlan>, FleetError> {
        let (where_sql, params) = tenant_filter(tenant_fact);
        let sql = format!(
            "SELECT operation_id, tenant_json, kind, value, channel, state, batch_size, \
             targets_json, pause_json, created_est, updated_est FROM fleet_rollouts \
             WHERE {where_sql} ORDER BY created_est, operation_id"
        );
        let mut statement = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = statement
            .query_map(params_from_iter(params.iter()), row_to_rollout)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

/// The tenant subtree predicate: the fact itself, or any descendant.
fn tenant_filter(tenant_fact: &str) -> (String, Vec<Value>) {
    (
        "(tenant_fact = ? OR substr(tenant_fact, 1, length(?) + 1) = ? || '/')".to_string(),
        vec![
            Value::Text(tenant_fact.to_string()),
            Value::Text(tenant_fact.to_string()),
            Value::Text(tenant_fact.to_string()),
        ],
    )
}

fn node_filter(
    tenant_fact: &str,
    sites: &[String],
    kinds: &[FleetNodeKind],
    health: Option<HealthStatus>,
    cursor: Option<&str>,
) -> (String, Vec<Value>) {
    let (mut clause, mut params) = tenant_filter(tenant_fact);
    if !sites.is_empty() {
        let placeholders = vec!["?"; sites.len()].join(", ");
        clause.push_str(&format!(" AND site_id IN ({placeholders})"));
        for site in sites {
            params.push(Value::Text(site.clone()));
        }
    }
    if !kinds.is_empty() {
        let placeholders = vec!["?"; kinds.len()].join(", ");
        clause.push_str(&format!(" AND kind IN ({placeholders})"));
        for kind in kinds {
            params.push(Value::Text(kind.as_str().to_string()));
        }
    }
    if let Some(health) = health {
        clause.push_str(" AND health = ?");
        params.push(Value::Text(health.as_str().to_string()));
    }
    if let Some(cursor) = cursor {
        clause.push_str(" AND node_id > ?");
        params.push(Value::Text(cursor.to_string()));
    }
    (clause, params)
}

// ---------------------------------------------------------------------------
// Row decoding
// ---------------------------------------------------------------------------

fn conversion_error(column: usize, detail: String) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, detail)),
    )
}

fn decode_tenant(column: usize, json: &str) -> rusqlite::Result<TenantPath> {
    serde_json::from_str(json)
        .map_err(|error| conversion_error(column, format!("decode tenant path: {error}")))
}

fn row_to_node(row: &Row<'_>) -> rusqlite::Result<FleetNode> {
    let tenant_json: String = row.get(1)?;
    let kind: String = row.get(3)?;
    let health: String = row.get(8)?;
    let compliance: String = row.get(9)?;
    let channel: String = row.get(11)?;
    let config_json: String = row.get(13)?;
    Ok(FleetNode {
        node_id: row.get(0)?,
        tenant: decode_tenant(1, &tenant_json)?,
        kind: FleetNodeKind::parse(&kind)
            .map_err(|_| conversion_error(3, format!("unknown fleet node kind {kind}")))?,
        site_id: row.get(4)?,
        parent_id: row.get(5)?,
        name: row.get(6)?,
        gateway_id: row.get(7)?,
        health: HealthStatus::parse(&health)
            .map_err(|_| conversion_error(8, format!("unknown health status {health}")))?,
        compliance: ComplianceStatus::parse(&compliance)
            .map_err(|_| conversion_error(9, format!("unknown compliance status {compliance}")))?,
        firmware_version: row.get(10)?,
        channel: FirmwareChannel::parse(&channel)
            .map_err(|_| conversion_error(11, format!("unknown firmware channel {channel}")))?,
        profile_id: row.get(12)?,
        config: serde_json::from_str::<BTreeMap<String, String>>(&config_json)
            .map_err(|error| conversion_error(13, format!("decode node config: {error}")))?,
        updated_est: row.get(14)?,
    })
}

fn row_to_tenant_key(row: &Row<'_>) -> rusqlite::Result<TenantKeyRef> {
    let tenant_json: String = row.get(1)?;
    Ok(TenantKeyRef {
        key_id: row.get(0)?,
        tenant: decode_tenant(1, &tenant_json)?,
        purpose: row.get(2)?,
        fingerprint: row.get(3)?,
        created_est: row.get(4)?,
        revoked_est: row.get(5)?,
    })
}

fn row_to_config(row: &Row<'_>) -> rusqlite::Result<TenantConfig> {
    let tenant_json: String = row.get(1)?;
    let values_json: String = row.get(3)?;
    Ok(TenantConfig {
        config_id: row.get(0)?,
        tenant: decode_tenant(1, &tenant_json)?,
        site_id: row.get(2)?,
        values: serde_json::from_str::<BTreeMap<String, String>>(&values_json)
            .map_err(|error| conversion_error(3, format!("decode config values: {error}")))?,
        updated_est: row.get(4)?,
    })
}

fn json_vec(column: usize, json: &str) -> rusqlite::Result<Vec<String>> {
    serde_json::from_str(json).map_err(|error| conversion_error(column, error.to_string()))
}

fn row_to_export(row: &Row<'_>) -> rusqlite::Result<FleetExport> {
    let tenant_json: String = row.get(1)?;
    let sites_json: String = row.get(2)?;
    let nodes_json: String = row.get(6)?;
    Ok(FleetExport {
        export_id: row.get(0)?,
        tenant: decode_tenant(1, &tenant_json)?,
        site_ids: json_vec(2, &sites_json)?,
        schema: row.get(3)?,
        digest: row.get(4)?,
        node_count: usize::try_from(row.get::<_, i64>(5)?).unwrap_or(usize::MAX),
        node_ids: json_vec(6, &nodes_json)?,
        created_est: row.get(7)?,
    })
}

fn row_to_grant(row: &Row<'_>) -> rusqlite::Result<CrossSiteGrant> {
    let tenant_json: String = row.get(1)?;
    let sites_json: String = row.get(2)?;
    Ok(CrossSiteGrant {
        grant_id: row.get(0)?,
        tenant: decode_tenant(1, &tenant_json)?,
        sites: json_vec(2, &sites_json)?,
        issued_by: row.get(3)?,
        issued_est: row.get(4)?,
        expires_est: row.get(5)?,
        reason: row.get(6)?,
    })
}

fn row_to_rollout(row: &Row<'_>) -> rusqlite::Result<RolloutPlan> {
    let tenant_json: String = row.get(1)?;
    let kind: String = row.get(2)?;
    let channel: String = row.get(4)?;
    let state: String = row.get(5)?;
    let targets_json: String = row.get(7)?;
    let pause_json: Option<String> = row.get(8)?;
    let pause = match pause_json.as_deref() {
        Some(json) => Some(
            serde_json::from_str::<RolloutPause>(json)
                .map_err(|error| conversion_error(8, format!("decode rollout pause: {error}")))?,
        ),
        None => None,
    };
    Ok(RolloutPlan {
        operation_id: row.get(0)?,
        tenant: decode_tenant(1, &tenant_json)?,
        kind: RolloutKind::parse(&kind)
            .map_err(|_| conversion_error(2, format!("unknown rollout kind {kind}")))?,
        value: row.get(3)?,
        channel: FirmwareChannel::parse(&channel)
            .map_err(|_| conversion_error(4, format!("unknown firmware channel {channel}")))?,
        state: RolloutState::parse(&state)
            .map_err(|_| conversion_error(5, format!("unknown rollout state {state}")))?,
        batch_size: usize::try_from(row.get::<_, i64>(6)?).unwrap_or(usize::MAX),
        targets: serde_json::from_str::<Vec<RolloutTarget>>(&targets_json)
            .map_err(|error| conversion_error(7, format!("decode rollout targets: {error}")))?,
        pause,
        created_est: row.get(9)?,
        updated_est: row.get(10)?,
    })
}
