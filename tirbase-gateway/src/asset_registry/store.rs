// SPDX-License-Identifier: AGPL-3.0-only

//! SQLite persistence for the asset and calibration registry (CC-18).
//!
//! Six tables, created idempotently on open, all append-only except for the
//! closure of a half-open effective range and the resolution of a release block:
//!
//! - `asset_revisions` — one immutable row per `(asset_id, version)`. The
//!   effective range is half-open, `[effective_from_est, effective_to_est)`,
//!   with `effective_to_est` NULL while the version is the newest. A revision
//!   never rewrites a row: it inserts the next version and closes the previous
//!   range at the new start.
//! - `asset_history` — append-only history of every registration, revision,
//!   replacement and retirement, with actor, reason and content digest.
//! - `asset_calibrations` — one row per calibration record, including its
//!   reference points and its certificate *digest* (never the certificate
//!   bytes).
//! - `asset_reference_checks` — one row per reference check, the evidence drift
//!   is detected against.
//! - `asset_release_blocks` — the lots a calibration state has blocked, and
//!   whether the block has been resolved. A resolved block stays on record.
//! - `asset_registry_audit` is not needed separately: the asset history plus the
//!   calibration, reference-check and block rows are the audit trail.
//!
//! Reads are by asset or by "everything in force at `at_est`", which is what
//! resolves an event without consulting today's asset record.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::asset_registry::{
    AssetAction, AssetError, AssetHistoryEntry, AssetIdentity, AssetKind, AssetStatus,
    AssetVersion, CalibrationPoint, CalibrationRecord, CertificateRef, ReferenceCheck,
    ReleaseBlock,
};
use tirbase_types::{FixedPointValue, UNIT_DEG_C};

const ASSET_COLUMNS: &str = "asset_id, version, effective_from_est, effective_to_est, tenant, \
     kind, status, model, serial, manufacturer, firmware, site_id, location_id, installed_est, \
     calibration_required, max_calibration_interval_secs, replaces, replaced_by, digest, \
     actor_did, created_est";

const CALIBRATION_COLUMNS: &str = "calibration_id, asset_id, performed_est, due_est, \
     interval_secs, method, laboratory_party_id, uncertainty_mantissa, uncertainty_exponent, \
     uncertainty_unit, points_json, certificate_id, certificate_sha256, certificate_bytes, \
     certificate_media_type, certificate_issued_est, certificate_expires_est, \
     certificate_issuer, actor_did, digest";

const CHECK_COLUMNS: &str = "check_id, asset_id, at_est, reference_mantissa, reference_exponent, \
     measured_mantissa, measured_exponent, tolerance_mantissa, tolerance_exponent, operator_did, \
     digest";

const BLOCK_COLUMNS: &str = "block_id, lot_id, asset_id, code, detail, raised_est, resolved_est, \
     resolved_by, resolution_reason";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS asset_revisions (
    asset_id                      TEXT    NOT NULL,
    version                       INTEGER NOT NULL,
    effective_from_est            INTEGER NOT NULL,
    effective_to_est              INTEGER,
    tenant                        TEXT    NOT NULL,
    kind                          TEXT    NOT NULL,
    status                        TEXT    NOT NULL,
    model                         TEXT    NOT NULL,
    serial                        TEXT    NOT NULL,
    manufacturer                  TEXT    NOT NULL,
    firmware                      TEXT    NOT NULL,
    site_id                       TEXT    NOT NULL,
    location_id                   TEXT    NOT NULL,
    installed_est                 INTEGER NOT NULL,
    calibration_required          INTEGER NOT NULL,
    max_calibration_interval_secs INTEGER,
    replaces                      TEXT,
    replaced_by                   TEXT,
    digest                        TEXT    NOT NULL,
    actor_did                     TEXT    NOT NULL,
    created_est                   INTEGER NOT NULL,
    PRIMARY KEY (asset_id, version)
);
CREATE INDEX IF NOT EXISTS idx_asset_revisions_open
    ON asset_revisions(asset_id, effective_to_est);
CREATE INDEX IF NOT EXISTS idx_asset_revisions_site
    ON asset_revisions(site_id);
CREATE INDEX IF NOT EXISTS idx_asset_revisions_serial
    ON asset_revisions(serial);

CREATE TABLE IF NOT EXISTS asset_history (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    TEXT    NOT NULL,
    version     INTEGER NOT NULL,
    action      TEXT    NOT NULL,
    actor_did   TEXT    NOT NULL,
    at_est      INTEGER NOT NULL,
    digest      TEXT    NOT NULL,
    reason      TEXT    NOT NULL,
    detail_json TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_asset_history_asset
    ON asset_history(asset_id, seq);

CREATE TABLE IF NOT EXISTS asset_calibrations (
    calibration_id          TEXT    PRIMARY KEY,
    asset_id                TEXT    NOT NULL,
    performed_est           INTEGER NOT NULL,
    due_est                 INTEGER NOT NULL,
    interval_secs           INTEGER NOT NULL,
    method                  TEXT    NOT NULL,
    laboratory_party_id     TEXT    NOT NULL,
    uncertainty_mantissa    INTEGER NOT NULL,
    uncertainty_exponent    INTEGER NOT NULL,
    uncertainty_unit        INTEGER NOT NULL,
    points_json             TEXT    NOT NULL,
    certificate_id          TEXT    NOT NULL,
    certificate_sha256      TEXT    NOT NULL,
    certificate_bytes       INTEGER NOT NULL,
    certificate_media_type  TEXT    NOT NULL,
    certificate_issued_est  INTEGER NOT NULL,
    certificate_expires_est INTEGER,
    certificate_issuer      TEXT    NOT NULL,
    actor_did               TEXT    NOT NULL,
    digest                  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_asset_calibrations_asset
    ON asset_calibrations(asset_id, performed_est);

CREATE TABLE IF NOT EXISTS asset_reference_checks (
    check_id            TEXT    PRIMARY KEY,
    asset_id            TEXT    NOT NULL,
    at_est              INTEGER NOT NULL,
    reference_mantissa  INTEGER NOT NULL,
    reference_exponent  INTEGER NOT NULL,
    measured_mantissa   INTEGER NOT NULL,
    measured_exponent   INTEGER NOT NULL,
    tolerance_mantissa  INTEGER NOT NULL,
    tolerance_exponent  INTEGER NOT NULL,
    operator_did        TEXT    NOT NULL,
    digest              TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_asset_reference_checks_asset
    ON asset_reference_checks(asset_id, at_est);
CREATE INDEX IF NOT EXISTS idx_asset_reference_checks_reference
    ON asset_reference_checks(asset_id, reference_mantissa);

CREATE TABLE IF NOT EXISTS asset_release_blocks (
    block_id          TEXT    PRIMARY KEY,
    lot_id            TEXT    NOT NULL,
    asset_id          TEXT    NOT NULL,
    code              TEXT    NOT NULL,
    detail            TEXT    NOT NULL,
    raised_est        INTEGER NOT NULL,
    resolved_est      INTEGER,
    resolved_by       TEXT,
    resolution_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_asset_release_blocks_lot
    ON asset_release_blocks(lot_id, resolved_est);
"#;

fn store_error(error: impl std::fmt::Display) -> AssetError {
    AssetError::Store(error.to_string())
}

/// Durable store for the asset and calibration registry.
#[derive(Debug)]
pub struct AssetStore {
    conn: Connection,
}

impl AssetStore {
    /// Open the store at `path`, applying the gateway hardening pragmas.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AssetError> {
        let conn = crate::db::open_primary(path)
            .map_err(|error| AssetError::Store(format!("open primary db: {error:?}")))?;
        Self::from_connection(conn)
    }

    /// Open an in-memory store (tests, ephemeral deployments).
    pub fn open_in_memory() -> Result<Self, AssetError> {
        let conn = Connection::open_in_memory().map_err(store_error)?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self, AssetError> {
        conn.execute_batch(SCHEMA)
            .map_err(|error| AssetError::Store(format!("create asset registry schema: {error}")))?;
        Ok(Self { conn })
    }

    // -----------------------------------------------------------------------
    // Asset revisions
    // -----------------------------------------------------------------------

    /// Insert one immutable version. Fails if the row already exists.
    pub fn insert_version(&self, version: &AssetVersion) -> Result<(), AssetError> {
        let identity = &version.identity;
        self.conn
            .execute(
                "INSERT INTO asset_revisions (asset_id, version, effective_from_est, \
                 effective_to_est, tenant, kind, status, model, serial, manufacturer, firmware, \
                 site_id, location_id, installed_est, calibration_required, \
                 max_calibration_interval_secs, replaces, replaced_by, digest, actor_did, \
                 created_est) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, \
                 ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
                params![
                    version.asset_id,
                    version.version,
                    version.effective_from_est,
                    version.effective_to_est,
                    identity.tenant,
                    identity.kind.as_str(),
                    version.status.as_str(),
                    identity.model,
                    identity.serial,
                    identity.manufacturer,
                    identity.firmware,
                    identity.site_id,
                    identity.location_id,
                    identity.installed_est,
                    i64::from(identity.calibration_required),
                    identity
                        .max_calibration_interval_secs
                        .map(|secs| i64::try_from(secs).unwrap_or(i64::MAX)),
                    identity.replaces,
                    identity.replaced_by,
                    version.digest,
                    version.actor_did,
                    version.created_est,
                ],
            )
            .map_err(|error| AssetError::Store(format!("insert asset version: {error}")))?;
        Ok(())
    }

    /// Close a version's effective range at `effective_to_est`.
    pub fn close_version(
        &self,
        asset_id: &str,
        version: u32,
        effective_to_est: i64,
    ) -> Result<(), AssetError> {
        self.conn
            .execute(
                "UPDATE asset_revisions SET effective_to_est=?1 \
                 WHERE asset_id=?2 AND version=?3",
                params![effective_to_est, asset_id, version],
            )
            .map_err(|error| AssetError::Store(format!("close asset version: {error}")))?;
        Ok(())
    }

    /// Every version of one asset, oldest first.
    pub fn versions(&self, asset_id: &str) -> Result<Vec<AssetVersion>, AssetError> {
        let sql = format!(
            "SELECT {ASSET_COLUMNS} FROM asset_revisions WHERE asset_id=?1 ORDER BY version"
        );
        let mut statement = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = statement
            .query_map(params![asset_id], row_to_version)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    /// The newest version of one asset, whatever its effective range.
    pub fn latest(&self, asset_id: &str) -> Result<Option<AssetVersion>, AssetError> {
        let sql = format!(
            "SELECT {ASSET_COLUMNS} FROM asset_revisions WHERE asset_id=?1 \
             ORDER BY version DESC LIMIT 1"
        );
        self.conn
            .query_row(&sql, params![asset_id], row_to_version)
            .optional()
            .map_err(store_error)
    }

    /// The version in force at `at_est`, if any.
    pub fn at(&self, asset_id: &str, at_est: i64) -> Result<Option<AssetVersion>, AssetError> {
        let sql = format!(
            "SELECT {ASSET_COLUMNS} FROM asset_revisions \
             WHERE asset_id=?1 AND effective_from_est<=?2 \
             AND (effective_to_est IS NULL OR effective_to_est > ?2) \
             ORDER BY version DESC LIMIT 1"
        );
        self.conn
            .query_row(&sql, params![asset_id, at_est], row_to_version)
            .optional()
            .map_err(store_error)
    }

    /// Every version in force at `at_est`, ordered by asset id.
    pub fn all_at(&self, at_est: i64) -> Result<Vec<AssetVersion>, AssetError> {
        let sql = format!(
            "SELECT {ASSET_COLUMNS} FROM asset_revisions \
             WHERE effective_from_est<=?1 AND (effective_to_est IS NULL OR effective_to_est > ?1) \
             ORDER BY asset_id"
        );
        let mut statement = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = statement
            .query_map(params![at_est], row_to_version)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    /// Every newest version, ordered by asset id (used for serial uniqueness).
    pub fn open_versions(&self) -> Result<Vec<AssetVersion>, AssetError> {
        let sql = format!(
            "SELECT {ASSET_COLUMNS} FROM asset_revisions \
             WHERE effective_to_est IS NULL ORDER BY asset_id"
        );
        let mut statement = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = statement
            .query_map([], row_to_version)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    // -----------------------------------------------------------------------
    // Audit history
    // -----------------------------------------------------------------------

    /// Append one history row and return its sequence number.
    pub fn append_history(&self, entry: &AssetHistoryEntry) -> Result<i64, AssetError> {
        let detail = serde_json::to_string(&entry.detail)
            .map_err(|error| AssetError::Store(format!("encode history detail: {error}")))?;
        self.conn
            .execute(
                "INSERT INTO asset_history (asset_id, version, action, actor_did, at_est, \
                 digest, reason, detail_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    entry.asset_id,
                    entry.version,
                    entry.action.as_str(),
                    entry.actor_did,
                    entry.at_est,
                    entry.digest,
                    entry.reason,
                    detail,
                ],
            )
            .map_err(|error| AssetError::Store(format!("append asset history: {error}")))?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Append-only history for one asset, oldest first.
    pub fn history(&self, asset_id: &str) -> Result<Vec<AssetHistoryEntry>, AssetError> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT seq, asset_id, version, action, actor_did, at_est, digest, reason, \
                 detail_json FROM asset_history WHERE asset_id=?1 ORDER BY seq",
            )
            .map_err(store_error)?;
        let rows = statement
            .query_map(params![asset_id], row_to_history)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    // -----------------------------------------------------------------------
    // Calibrations
    // -----------------------------------------------------------------------

    /// Insert one calibration record. Fails if the id already exists.
    pub fn insert_calibration(&self, record: &CalibrationRecord) -> Result<(), AssetError> {
        let points: Vec<(i64, i64)> = record
            .points
            .iter()
            .map(|point| (point.reference_c.mantissa, point.measured_c.mantissa))
            .collect();
        let points_json = serde_json::to_string(&points)
            .map_err(|error| AssetError::Store(format!("encode calibration points: {error}")))?;
        let certificate = &record.certificate;
        self.conn
            .execute(
                "INSERT INTO asset_calibrations (calibration_id, asset_id, performed_est, \
                 due_est, interval_secs, method, laboratory_party_id, uncertainty_mantissa, \
                 uncertainty_exponent, uncertainty_unit, points_json, certificate_id, \
                 certificate_sha256, certificate_bytes, certificate_media_type, \
                 certificate_issued_est, certificate_expires_est, certificate_issuer, \
                 actor_did, digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, \
                 ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
                params![
                    record.calibration_id,
                    record.asset_id,
                    record.performed_est,
                    record.due_est,
                    i64::try_from(record.interval_secs).unwrap_or(i64::MAX),
                    record.method,
                    record.laboratory_party_id,
                    record.uncertainty_c.mantissa,
                    i64::from(record.uncertainty_c.exponent),
                    i64::from(record.uncertainty_c.unit_id),
                    points_json,
                    certificate.certificate_id,
                    certificate.sha256,
                    i64::try_from(certificate.bytes).unwrap_or(i64::MAX),
                    certificate.media_type,
                    certificate.issued_est,
                    certificate.expires_est,
                    certificate.issuer,
                    record.actor_did,
                    record.digest,
                ],
            )
            .map_err(|error| AssetError::Store(format!("insert calibration: {error}")))?;
        Ok(())
    }

    /// One calibration by id.
    pub fn calibration(
        &self,
        calibration_id: &str,
    ) -> Result<Option<CalibrationRecord>, AssetError> {
        let sql =
            format!("SELECT {CALIBRATION_COLUMNS} FROM asset_calibrations WHERE calibration_id=?1");
        self.conn
            .query_row(&sql, params![calibration_id], row_to_calibration)
            .optional()
            .map_err(store_error)
    }

    /// Every calibration of one asset, oldest first.
    pub fn calibrations(&self, asset_id: &str) -> Result<Vec<CalibrationRecord>, AssetError> {
        let sql = format!(
            "SELECT {CALIBRATION_COLUMNS} FROM asset_calibrations WHERE asset_id=?1 \
             ORDER BY performed_est, calibration_id"
        );
        let mut statement = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = statement
            .query_map(params![asset_id], row_to_calibration)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    /// The newest calibration performed at or before `at_est`.
    pub fn latest_calibration(
        &self,
        asset_id: &str,
        at_est: i64,
    ) -> Result<Option<CalibrationRecord>, AssetError> {
        let sql = format!(
            "SELECT {CALIBRATION_COLUMNS} FROM asset_calibrations \
             WHERE asset_id=?1 AND performed_est<=?2 \
             ORDER BY performed_est DESC, calibration_id DESC LIMIT 1"
        );
        self.conn
            .query_row(&sql, params![asset_id, at_est], row_to_calibration)
            .optional()
            .map_err(store_error)
    }

    /// Every calibration performed at or before `at_est`, ordered by asset.
    pub fn calibrations_at(&self, at_est: i64) -> Result<Vec<CalibrationRecord>, AssetError> {
        let sql = format!(
            "SELECT {CALIBRATION_COLUMNS} FROM asset_calibrations WHERE performed_est<=?1 \
             ORDER BY asset_id, performed_est, calibration_id"
        );
        let mut statement = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = statement
            .query_map(params![at_est], row_to_calibration)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    // -----------------------------------------------------------------------
    // Reference checks
    // -----------------------------------------------------------------------

    /// Insert one reference check. Fails if the id already exists.
    pub fn insert_check(&self, check: &ReferenceCheck) -> Result<(), AssetError> {
        self.conn
            .execute(
                "INSERT INTO asset_reference_checks (check_id, asset_id, at_est, \
                 reference_mantissa, reference_exponent, measured_mantissa, measured_exponent, \
                 tolerance_mantissa, tolerance_exponent, operator_did, digest) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    check.check_id,
                    check.asset_id,
                    check.at_est,
                    check.reference_c.mantissa,
                    i64::from(check.reference_c.exponent),
                    check.measured_c.mantissa,
                    i64::from(check.measured_c.exponent),
                    check.tolerance_c.mantissa,
                    i64::from(check.tolerance_c.exponent),
                    check.operator_did,
                    check.digest,
                ],
            )
            .map_err(|error| AssetError::Store(format!("insert reference check: {error}")))?;
        Ok(())
    }

    /// One reference check by id.
    pub fn check(&self, check_id: &str) -> Result<Option<ReferenceCheck>, AssetError> {
        let sql = format!("SELECT {CHECK_COLUMNS} FROM asset_reference_checks WHERE check_id=?1");
        self.conn
            .query_row(&sql, params![check_id], row_to_check)
            .optional()
            .map_err(store_error)
    }

    /// Every reference check of one asset, oldest first.
    pub fn checks(&self, asset_id: &str) -> Result<Vec<ReferenceCheck>, AssetError> {
        let sql = format!(
            "SELECT {CHECK_COLUMNS} FROM asset_reference_checks WHERE asset_id=?1 \
             ORDER BY at_est, check_id"
        );
        let mut statement = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = statement
            .query_map(params![asset_id], row_to_check)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    /// The newest reference check for an asset performed at or before `at_est`.
    pub fn latest_check(
        &self,
        asset_id: &str,
        at_est: i64,
    ) -> Result<Option<ReferenceCheck>, AssetError> {
        let sql = format!(
            "SELECT {CHECK_COLUMNS} FROM asset_reference_checks \
             WHERE asset_id=?1 AND at_est<=?2 ORDER BY at_est DESC, check_id DESC LIMIT 1"
        );
        self.conn
            .query_row(&sql, params![asset_id, at_est], row_to_check)
            .optional()
            .map_err(store_error)
    }

    /// The earliest check for an asset at one applied reference (the baseline).
    pub fn baseline_check(
        &self,
        asset_id: &str,
        reference_mantissa: i64,
    ) -> Result<Option<ReferenceCheck>, AssetError> {
        let sql = format!(
            "SELECT {CHECK_COLUMNS} FROM asset_reference_checks \
             WHERE asset_id=?1 AND reference_mantissa=?2 ORDER BY at_est, check_id LIMIT 1"
        );
        self.conn
            .query_row(&sql, params![asset_id, reference_mantissa], row_to_check)
            .optional()
            .map_err(store_error)
    }

    // -----------------------------------------------------------------------
    // Release blocks
    // -----------------------------------------------------------------------

    /// Record a block. A repeat of the same deterministic block id is a no-op,
    /// so re-evaluating a lot after a crash does not duplicate the block.
    pub fn raise_block(&self, block: &ReleaseBlock) -> Result<(), AssetError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO asset_release_blocks (block_id, lot_id, asset_id, code, \
                 detail, raised_est, resolved_est, resolved_by, resolution_reason) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, NULL)",
                params![
                    block.block_id,
                    block.lot_id,
                    block.asset_id,
                    block.code,
                    block.detail,
                    block.raised_est,
                ],
            )
            .map_err(|error| AssetError::Store(format!("raise release block: {error}")))?;
        Ok(())
    }

    /// One block by id.
    pub fn block(&self, block_id: &str) -> Result<Option<ReleaseBlock>, AssetError> {
        let sql = format!("SELECT {BLOCK_COLUMNS} FROM asset_release_blocks WHERE block_id=?1");
        self.conn
            .query_row(&sql, params![block_id], row_to_block)
            .optional()
            .map_err(store_error)
    }

    /// Unresolved blocks for one lot, oldest first.
    pub fn unresolved_blocks_for_lot(&self, lot_id: &str) -> Result<Vec<ReleaseBlock>, AssetError> {
        let sql = format!(
            "SELECT {BLOCK_COLUMNS} FROM asset_release_blocks \
             WHERE lot_id=?1 AND resolved_est IS NULL ORDER BY raised_est, block_id"
        );
        let mut statement = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = statement
            .query_map(params![lot_id], row_to_block)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    /// Blocks raised at or before `at_est`, oldest first (audit export).
    pub fn blocks_at(&self, at_est: i64) -> Result<Vec<ReleaseBlock>, AssetError> {
        let sql = format!(
            "SELECT {BLOCK_COLUMNS} FROM asset_release_blocks WHERE raised_est<=?1 \
             ORDER BY raised_est, block_id"
        );
        let mut statement = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = statement
            .query_map(params![at_est], row_to_block)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    /// Resolve a block. Idempotent: resolving an already-resolved block leaves
    /// the first resolution (and its evidence) untouched.
    pub fn resolve_block(
        &self,
        block_id: &str,
        at_est: i64,
        actor_did: &str,
        reason: &str,
    ) -> Result<(), AssetError> {
        self.conn
            .execute(
                "UPDATE asset_release_blocks SET resolved_est=?1, resolved_by=?2, \
                 resolution_reason=?3 WHERE block_id=?4 AND resolved_est IS NULL",
                params![at_est, actor_did, reason, block_id],
            )
            .map_err(|error| AssetError::Store(format!("resolve release block: {error}")))?;
        Ok(())
    }
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

fn row_to_version(row: &Row<'_>) -> rusqlite::Result<AssetVersion> {
    let kind: String = row.get(5)?;
    let status: String = row.get(6)?;
    let calibration_required: i64 = row.get(14)?;
    let max_interval: Option<i64> = row.get(15)?;
    Ok(AssetVersion {
        asset_id: row.get(0)?,
        version: row.get(1)?,
        effective_from_est: row.get(2)?,
        effective_to_est: row.get(3)?,
        identity: AssetIdentity {
            tenant: row.get(4)?,
            kind: AssetKind::parse(&kind)
                .map_err(|_| conversion_error(5, format!("unknown asset kind {kind}")))?,
            model: row.get(7)?,
            serial: row.get(8)?,
            manufacturer: row.get(9)?,
            firmware: row.get(10)?,
            site_id: row.get(11)?,
            location_id: row.get(12)?,
            installed_est: row.get(13)?,
            calibration_required: calibration_required != 0,
            max_calibration_interval_secs: max_interval
                .map(|secs| u64::try_from(secs).unwrap_or(u64::MAX)),
            replaces: row.get(16)?,
            replaced_by: row.get(17)?,
        },
        status: AssetStatus::parse(&status)
            .map_err(|_| conversion_error(6, format!("unknown asset status {status}")))?,
        digest: row.get(18)?,
        actor_did: row.get(19)?,
        created_est: row.get(20)?,
    })
}

fn row_to_history(row: &Row<'_>) -> rusqlite::Result<AssetHistoryEntry> {
    let action: String = row.get(3)?;
    let detail: String = row.get(8)?;
    Ok(AssetHistoryEntry {
        seq: row.get(0)?,
        asset_id: row.get(1)?,
        version: row.get(2)?,
        action: AssetAction::parse(&action)
            .map_err(|_| conversion_error(3, format!("unknown asset action {action}")))?,
        actor_did: row.get(4)?,
        at_est: row.get(5)?,
        digest: row.get(6)?,
        reason: row.get(7)?,
        detail: serde_json::from_str(&detail).unwrap_or(serde_json::Value::Null),
    })
}

fn row_to_calibration(row: &Row<'_>) -> rusqlite::Result<CalibrationRecord> {
    let points_json: String = row.get(10)?;
    let points: Vec<(i64, i64)> = serde_json::from_str(&points_json)
        .map_err(|error| conversion_error(10, format!("decode calibration points: {error}")))?;
    let uncertainty = FixedPointValue::new(
        row.get(7)?,
        i8::try_from(row.get::<_, i64>(8)?).unwrap_or(-1),
        u16::try_from(row.get::<_, i64>(9)?).unwrap_or(UNIT_DEG_C),
    );
    Ok(CalibrationRecord {
        calibration_id: row.get(0)?,
        asset_id: row.get(1)?,
        performed_est: row.get(2)?,
        due_est: row.get(3)?,
        interval_secs: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(u64::MAX),
        method: row.get(5)?,
        laboratory_party_id: row.get(6)?,
        uncertainty_c: uncertainty,
        points: points
            .into_iter()
            .map(|(reference, measured)| CalibrationPoint {
                reference_c: FixedPointValue::new(reference, -1, UNIT_DEG_C),
                measured_c: FixedPointValue::new(measured, -1, UNIT_DEG_C),
            })
            .collect(),
        certificate: CertificateRef {
            certificate_id: row.get(11)?,
            sha256: row.get(12)?,
            bytes: u64::try_from(row.get::<_, i64>(13)?).unwrap_or(u64::MAX),
            media_type: row.get(14)?,
            issued_est: row.get(15)?,
            expires_est: row.get(16)?,
            issuer: row.get(17)?,
        },
        actor_did: row.get(18)?,
        digest: row.get(19)?,
    })
}

fn row_to_check(row: &Row<'_>) -> rusqlite::Result<ReferenceCheck> {
    Ok(ReferenceCheck {
        check_id: row.get(0)?,
        asset_id: row.get(1)?,
        at_est: row.get(2)?,
        reference_c: FixedPointValue::new(
            row.get(3)?,
            i8::try_from(row.get::<_, i64>(4)?).unwrap_or(-1),
            UNIT_DEG_C,
        ),
        measured_c: FixedPointValue::new(
            row.get(5)?,
            i8::try_from(row.get::<_, i64>(6)?).unwrap_or(-1),
            UNIT_DEG_C,
        ),
        tolerance_c: FixedPointValue::new(
            row.get(7)?,
            i8::try_from(row.get::<_, i64>(8)?).unwrap_or(-1),
            UNIT_DEG_C,
        ),
        operator_did: row.get(9)?,
        digest: row.get(10)?,
    })
}

fn row_to_block(row: &Row<'_>) -> rusqlite::Result<ReleaseBlock> {
    Ok(ReleaseBlock {
        block_id: row.get(0)?,
        lot_id: row.get(1)?,
        asset_id: row.get(2)?,
        code: row.get(3)?,
        detail: row.get(4)?,
        raised_est: row.get(5)?,
        resolved_est: row.get(6)?,
        resolved_by: row.get(7)?,
        resolution_reason: row.get(8)?,
    })
}
