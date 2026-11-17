// SPDX-License-Identifier: AGPL-3.0-only

//! Read-only extraction of report rows from the tables other gateway modules own.
//!
//! Nothing here writes. Every row carries the `SourceRef`s it was derived from —
//! excursion records and their transition events, lot rows and edges, calibration
//! rows, and lineage-ledger entries (`entry_hash` is the ledger's own digest, so
//! a report can be tied back to the exact chain entry). A table that does not
//! exist yet (a store that has never been opened) yields an empty section rather
//! than an error, and row counts are bounded so a report cannot fill memory.

use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::reporting::{
    ReportError, ReportKind, ReportRequest, ReportRow, SourceKind, SourceRef, CONTEXT_SOURCE_ROW,
    MAX_ROWS,
};

/// Rows, columns and roll-up totals for one report.
#[derive(Debug, Clone, Default)]
pub(crate) struct Gathered {
    pub columns: Vec<String>,
    pub rows: Vec<ReportRow>,
    pub totals: std::collections::BTreeMap<String, String>,
    pub latest_source_est: Option<i64>,
}

impl Gathered {
    pub(crate) fn touch(&mut self, at_est: Option<i64>) {
        if let Some(at_est) = at_est {
            self.latest_source_est = Some(
                self.latest_source_est
                    .map(|current| current.max(at_est))
                    .unwrap_or(at_est),
            );
        }
    }
}

pub(crate) fn collect(conn: &Connection, request: &ReportRequest) -> Result<Gathered, ReportError> {
    match request.kind {
        ReportKind::ExcursionHistory => excursion_history(conn, request),
        ReportKind::QuarantineAging => quarantine_aging(conn, request),
        ReportKind::Disposition => disposition(conn, request),
        ReportKind::CalibrationDue => calibration_due(conn, request),
        ReportKind::LotTraceability => lot_traceability(conn, request),
        // Assembled by the service, which owns export verification.
        ReportKind::ExportVerification => Ok(Gathered::default()),
    }
}

fn store_error(error: impl std::fmt::Display) -> ReportError {
    ReportError::Store(error.to_string())
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool, ReportError> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )
        .optional()
        .map_err(store_error)?;
    Ok(found.is_some())
}

/// Domain-separated digest of one source row, so the report can name exactly
/// which stored row it read.
fn row_digest(fields: &serde_json::Value) -> Result<String, ReportError> {
    let bytes = serde_json::to_vec(fields).map_err(|error| {
        ReportError::InvalidRequest(format!("cannot encode source row: {error}"))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(CONTEXT_SOURCE_ROW.as_bytes());
    hasher.update(b"\0");
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn source(kind: SourceKind, id: impl Into<String>, digest: impl Into<String>) -> SourceRef {
    SourceRef {
        kind,
        id: id.into(),
        digest: digest.into(),
    }
}

/// Ledger entries for one excursion/lot, keyed by the lot and device the record
/// names.
fn ledger_sources(
    conn: &Connection,
    lot_id: Option<&str>,
    device_id: Option<&str>,
) -> Result<Vec<SourceRef>, ReportError> {
    if !table_exists(conn, "lineage_ledger")? {
        return Ok(Vec::new());
    }
    let mut statement = conn
        .prepare(
            "SELECT entry_id, entry_hash FROM lineage_ledger \
             WHERE (?1 IS NOT NULL AND lot_id = ?1) OR (?2 IS NOT NULL AND device_id = ?2) \
             ORDER BY seq LIMIT ?3",
        )
        .map_err(store_error)?;
    let rows = statement
        .query_map(
            rusqlite::params![lot_id, device_id, MAX_ROWS as i64],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(store_error)?;
    let mut sources = Vec::new();
    for row in rows {
        let (entry_id, entry_hash) = row.map_err(store_error)?;
        sources.push(source(SourceKind::LedgerEntry, entry_id, entry_hash));
    }
    Ok(sources)
}

struct ExcursionRow {
    record_id: String,
    site_id: String,
    device_id: String,
    lot_id: Option<String>,
    state: String,
    opened_est: i64,
    closed_est: Option<i64>,
    detection_json: String,
    disposition_json: Option<String>,
}

fn excursion_rows(
    conn: &Connection,
    tenant: &str,
    from_est: Option<i64>,
    to_est: Option<i64>,
) -> Result<Vec<ExcursionRow>, ReportError> {
    if !table_exists(conn, "excursion_records")? {
        return Ok(Vec::new());
    }
    let mut statement = conn
        .prepare(
            "SELECT record_id, site_id, device_id, lot_id, state, opened_est, closed_est, \
             detection_json, disposition_json FROM excursion_records \
             WHERE tenant = ?1 AND (?2 IS NULL OR opened_est >= ?2) \
             AND (?3 IS NULL OR opened_est <= ?3) \
             ORDER BY opened_est, record_id LIMIT ?4",
        )
        .map_err(store_error)?;
    let rows = statement
        .query_map(
            rusqlite::params![tenant, from_est, to_est, MAX_ROWS as i64],
            |row| {
                Ok(ExcursionRow {
                    record_id: row.get(0)?,
                    site_id: row.get(1)?,
                    device_id: row.get(2)?,
                    lot_id: row.get(3)?,
                    state: row.get(4)?,
                    opened_est: row.get(5)?,
                    closed_est: row.get(6)?,
                    detection_json: row.get(7)?,
                    disposition_json: row.get(8)?,
                })
            },
        )
        .map_err(store_error)?;
    let mut collected = Vec::new();
    for row in rows {
        collected.push(row.map_err(store_error)?);
    }
    Ok(collected)
}

/// Transition events for one record, as source refs.
fn excursion_event_sources(
    conn: &Connection,
    record_id: &str,
) -> Result<Vec<SourceRef>, ReportError> {
    if !table_exists(conn, "excursion_events")? {
        return Ok(Vec::new());
    }
    let mut statement = conn
        .prepare(
            "SELECT seq, event, at_est, detail_json FROM excursion_events \
             WHERE record_id = ?1 ORDER BY seq",
        )
        .map_err(store_error)?;
    let rows = statement
        .query_map([record_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(store_error)?;
    let mut sources = Vec::new();
    for row in rows {
        let (seq, event, at_est, detail_json) = row.map_err(store_error)?;
        let digest = row_digest(&serde_json::json!({
            "record_id": record_id,
            "seq": seq,
            "event": event,
            "at_est": at_est,
            "detail_json": detail_json,
        }))?;
        sources.push(source(
            SourceKind::ExcursionEvent,
            format!("{record_id}:{seq}"),
            digest,
        ));
    }
    Ok(sources)
}

fn record_source(row: &ExcursionRow) -> Result<SourceRef, ReportError> {
    let digest = row_digest(&serde_json::json!({
        "record_id": row.record_id,
        "site_id": row.site_id,
        "device_id": row.device_id,
        "lot_id": row.lot_id,
        "state": row.state,
        "opened_est": row.opened_est,
        "closed_est": row.closed_est,
        "detection_json": row.detection_json,
        "disposition_json": row.disposition_json,
    }))?;
    Ok(source(
        SourceKind::ExcursionRecord,
        row.record_id.clone(),
        digest,
    ))
}

fn string_cells(pairs: &[(&str, String)]) -> std::collections::BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), value.clone()))
        .collect()
}

fn excursion_history(conn: &Connection, request: &ReportRequest) -> Result<Gathered, ReportError> {
    let records = excursion_rows(conn, &request.tenant, request.from_est, request.to_est)?;
    let mut gathered = Gathered {
        columns: [
            "record_id",
            "site_id",
            "device_id",
            "lot_id",
            "state",
            "opened_est",
            "closed_est",
            "reasons",
            "ledger_entries",
        ]
        .iter()
        .map(|column| (*column).to_string())
        .collect(),
        ..Gathered::default()
    };
    let mut ledger_count = 0usize;
    for record in &records {
        let mut sources = vec![record_source(record)?];
        sources.extend(excursion_event_sources(conn, &record.record_id)?);
        let ledger = ledger_sources(
            conn,
            record.lot_id.as_deref(),
            Some(record.device_id.as_str()),
        )?;
        ledger_count += ledger.len();
        let ledger_ids: Vec<String> = ledger.iter().map(|entry| entry.id.clone()).collect();
        sources.extend(ledger);
        let reasons = serde_json::from_str::<serde_json::Value>(&record.detection_json)
            .ok()
            .and_then(|value| value.get("reasons").cloned())
            .map(|value| match value {
                serde_json::Value::Array(items) => items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect::<Vec<_>>()
                    .join("|"),
                other => other.to_string(),
            })
            .unwrap_or_default();
        gathered.touch(Some(record.opened_est));
        gathered.rows.push(ReportRow {
            key: record.record_id.clone(),
            cells: string_cells(&[
                ("record_id", record.record_id.clone()),
                ("site_id", record.site_id.clone()),
                ("device_id", record.device_id.clone()),
                ("lot_id", record.lot_id.clone().unwrap_or_default()),
                ("state", record.state.clone()),
                ("opened_est", record.opened_est.to_string()),
                (
                    "closed_est",
                    record
                        .closed_est
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                ),
                ("reasons", reasons),
                ("ledger_entries", ledger_ids.join("|")),
            ]),
            sources,
        });
    }
    gathered
        .totals
        .insert("records".to_string(), gathered.rows.len().to_string());
    gathered
        .totals
        .insert("ledger_entries".to_string(), ledger_count.to_string());
    Ok(gathered)
}

fn quarantine_aging(conn: &Connection, request: &ReportRequest) -> Result<Gathered, ReportError> {
    let records = excursion_rows(conn, &request.tenant, request.from_est, request.to_est)?;
    let now = request.now_est;
    let mut gathered = Gathered {
        columns: [
            "record_id",
            "site_id",
            "device_id",
            "lot_id",
            "state",
            "opened_est",
            "age_secs",
            "age_hours",
            "age_bucket",
        ]
        .iter()
        .map(|column| (*column).to_string())
        .collect(),
        ..Gathered::default()
    };
    let mut aging = 0usize;
    for record in &records {
        if !matches!(
            record.state.as_str(),
            "detected" | "quarantined" | "notified"
        ) {
            continue;
        }
        let age_secs = now.saturating_sub(record.opened_est).max(0);
        let age_hours = age_secs / 3_600;
        let bucket = if age_hours >= 72 {
            "critical"
        } else if age_hours >= 24 {
            "aging"
        } else {
            "new"
        };
        let mut sources = vec![record_source(record)?];
        sources.extend(excursion_event_sources(conn, &record.record_id)?);
        sources.extend(ledger_sources(
            conn,
            record.lot_id.as_deref(),
            Some(record.device_id.as_str()),
        )?);
        gathered.touch(Some(record.opened_est));
        gathered.rows.push(ReportRow {
            key: record.record_id.clone(),
            cells: string_cells(&[
                ("record_id", record.record_id.clone()),
                ("site_id", record.site_id.clone()),
                ("device_id", record.device_id.clone()),
                ("lot_id", record.lot_id.clone().unwrap_or_default()),
                ("state", record.state.clone()),
                ("opened_est", record.opened_est.to_string()),
                ("age_secs", age_secs.to_string()),
                ("age_hours", age_hours.to_string()),
                ("age_bucket", bucket.to_string()),
            ]),
            sources,
        });
        if bucket != "new" {
            aging += 1;
        }
    }
    gathered
        .totals
        .insert("quarantined".to_string(), gathered.rows.len().to_string());
    gathered
        .totals
        .insert("aging".to_string(), aging.to_string());
    Ok(gathered)
}

fn disposition(conn: &Connection, request: &ReportRequest) -> Result<Gathered, ReportError> {
    let records = excursion_rows(conn, &request.tenant, request.from_est, request.to_est)?;
    let mut gathered = Gathered {
        columns: [
            "record_id",
            "site_id",
            "lot_id",
            "disposition",
            "reason",
            "operator_did",
            "decided_est",
            "state",
            "lot_dispositions",
        ]
        .iter()
        .map(|column| (*column).to_string())
        .collect(),
        ..Gathered::default()
    };
    for record in &records {
        let Some(json) = record.disposition_json.as_ref() else {
            continue;
        };
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap_or_default();
        let field = |name: &str| {
            parsed
                .get(name)
                .map(|value| match value {
                    serde_json::Value::String(text) => text.clone(),
                    other => other.to_string(),
                })
                .unwrap_or_default()
        };
        let mut sources = vec![
            record_source(record)?,
            source(
                SourceKind::ExcursionDisposition,
                format!("{}:disposition", record.record_id),
                row_digest(&parsed)?,
            ),
        ];
        sources.extend(excursion_event_sources(conn, &record.record_id)?);
        sources.extend(ledger_sources(
            conn,
            record.lot_id.as_deref(),
            Some(record.device_id.as_str()),
        )?);
        let lot_rows = lot_disposition_sources(conn, record.lot_id.as_deref())?;
        let lot_refs: Vec<String> = lot_rows.iter().map(|entry| entry.id.clone()).collect();
        sources.extend(lot_rows);
        gathered.touch(parsed.get("decided_est").and_then(|value| value.as_i64()));
        gathered.rows.push(ReportRow {
            key: record.record_id.clone(),
            cells: string_cells(&[
                ("record_id", record.record_id.clone()),
                ("site_id", record.site_id.clone()),
                ("lot_id", record.lot_id.clone().unwrap_or_default()),
                ("disposition", field("disposition")),
                ("reason", field("reason")),
                ("operator_did", field("operator_did")),
                ("decided_est", field("decided_est")),
                ("state", record.state.clone()),
                ("lot_dispositions", lot_refs.join("|")),
            ]),
            sources,
        });
    }
    gathered
        .totals
        .insert("dispositions".to_string(), gathered.rows.len().to_string());
    Ok(gathered)
}

fn lot_disposition_sources(
    conn: &Connection,
    lot_id: Option<&str>,
) -> Result<Vec<SourceRef>, ReportError> {
    let Some(lot_id) = lot_id else {
        return Ok(Vec::new());
    };
    if !table_exists(conn, "lot_dispositions")? {
        return Ok(Vec::new());
    }
    let mut statement = conn
        .prepare(
            "SELECT record_id, disposition, reason, decided_est FROM lot_dispositions \
             WHERE lot_id = ?1 ORDER BY decided_est, record_id",
        )
        .map_err(store_error)?;
    let rows = statement
        .query_map([lot_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(store_error)?;
    let mut sources = Vec::new();
    for row in rows {
        let (record_id, disposition, reason, decided_est) = row.map_err(store_error)?;
        let digest = row_digest(&serde_json::json!({
            "lot_id": lot_id,
            "record_id": record_id,
            "disposition": disposition,
            "reason": reason,
            "decided_est": decided_est,
        }))?;
        sources.push(source(
            SourceKind::LotDisposition,
            format!("{lot_id}:{record_id}"),
            digest,
        ));
    }
    Ok(sources)
}

fn calibration_due(conn: &Connection, request: &ReportRequest) -> Result<Gathered, ReportError> {
    let mut gathered = Gathered {
        columns: [
            "asset_id",
            "serial",
            "site_id",
            "calibration_id",
            "performed_est",
            "due_est",
            "days_until_due",
            "status",
            "method",
            "laboratory_party_id",
        ]
        .iter()
        .map(|column| (*column).to_string())
        .collect(),
        ..Gathered::default()
    };
    if !table_exists(conn, "asset_calibrations")? || !table_exists(conn, "asset_revisions")? {
        return Ok(gathered);
    }
    let mut statement = conn
        .prepare(
            "SELECT c.calibration_id, c.asset_id, c.due_est, c.performed_est, c.method, \
             c.laboratory_party_id, c.digest, r.serial, r.site_id FROM asset_calibrations c \
             JOIN asset_revisions r ON r.asset_id = c.asset_id AND r.version = \
                 (SELECT MAX(version) FROM asset_revisions r2 WHERE r2.asset_id = c.asset_id) \
             WHERE r.tenant = ?1 \
             AND c.performed_est = \
                 (SELECT MAX(performed_est) FROM asset_calibrations c2 WHERE c2.asset_id = c.asset_id) \
             ORDER BY c.due_est, c.calibration_id LIMIT ?2",
        )
        .map_err(store_error)?;
    let rows = statement
        .query_map(rusqlite::params![request.tenant, MAX_ROWS as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
            ))
        })
        .map_err(store_error)?;
    let mut overdue = 0usize;
    let mut due_soon = 0usize;
    for row in rows {
        let (
            calibration_id,
            asset_id,
            due_est,
            performed_est,
            method,
            laboratory,
            digest,
            serial,
            site_id,
        ) = row.map_err(store_error)?;
        let remaining = due_est.saturating_sub(request.now_est);
        let days_until_due = remaining.div_euclid(86_400);
        let status = if remaining < 0 {
            overdue += 1;
            "overdue"
        } else if remaining <= 30 * 86_400 {
            due_soon += 1;
            "due_soon"
        } else {
            "current"
        };
        gathered.touch(Some(performed_est));
        gathered.rows.push(ReportRow {
            key: calibration_id.clone(),
            cells: string_cells(&[
                ("asset_id", asset_id.clone()),
                ("serial", serial.clone()),
                ("site_id", site_id.clone()),
                ("calibration_id", calibration_id.clone()),
                ("performed_est", performed_est.to_string()),
                ("due_est", due_est.to_string()),
                ("days_until_due", days_until_due.to_string()),
                ("status", status.to_string()),
                ("method", method),
                ("laboratory_party_id", laboratory),
            ]),
            sources: vec![
                source(SourceKind::Calibration, calibration_id, digest),
                source(
                    SourceKind::AssetVersion,
                    asset_id,
                    row_digest(&serde_json::json!({ "serial": serial, "site_id": site_id }))?,
                ),
            ],
        });
    }
    gathered
        .totals
        .insert("calibrations".to_string(), gathered.rows.len().to_string());
    gathered
        .totals
        .insert("overdue".to_string(), overdue.to_string());
    gathered
        .totals
        .insert("due_soon".to_string(), due_soon.to_string());
    Ok(gathered)
}

fn lot_traceability(conn: &Connection, request: &ReportRequest) -> Result<Gathered, ReportError> {
    let mut gathered = Gathered {
        columns: [
            "lot_id",
            "kind",
            "label",
            "site_id",
            "location_id",
            "quantity",
            "uom",
            "window_start_est",
            "window_end_est",
            "revision",
            "parents",
            "children",
            "dispositions",
            "ledger_entries",
        ]
        .iter()
        .map(|column| (*column).to_string())
        .collect(),
        ..Gathered::default()
    };
    if !table_exists(conn, "lot_records")? {
        return Ok(gathered);
    }
    let mut statement = conn
        .prepare(
            "SELECT lot_id, kind, label, site_id, location_id, quantity, uom, \
             window_start_est, window_end_est, revision FROM lot_records \
             WHERE tenant = ?1 AND (?2 IS NULL OR lot_id = ?2) \
             ORDER BY window_start_est, lot_id LIMIT ?3",
        )
        .map_err(store_error)?;
    let rows = statement
        .query_map(
            rusqlite::params![request.tenant, request.subject, MAX_ROWS as i64],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )
        .map_err(store_error)?;
    let mut edge_count = 0usize;
    for row in rows {
        let (
            lot_id,
            kind,
            label,
            site_id,
            location_id,
            quantity,
            uom,
            window_start,
            window_end,
            revision,
        ) = row.map_err(store_error)?;
        let mut sources = vec![source(
            SourceKind::LotRecord,
            lot_id.clone(),
            row_digest(&serde_json::json!({
                "lot_id": lot_id,
                "kind": kind,
                "label": label,
                "site_id": site_id,
                "location_id": location_id,
                "quantity": quantity,
                "uom": uom,
                "window_start_est": window_start,
                "window_end_est": window_end,
                "revision": revision,
            }))?,
        )];
        let mut parents = Vec::new();
        let mut children = Vec::new();
        if table_exists(conn, "lot_edges")? {
            let mut edges = conn
                .prepare(
                    "SELECT parent_id, child_id, kind, operation_id FROM lot_edges \
                     WHERE parent_id = ?1 OR child_id = ?1 ORDER BY parent_id, child_id, kind",
                )
                .map_err(store_error)?;
            let edges = edges
                .query_map([&lot_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                })
                .map_err(store_error)?;
            for edge in edges {
                let (parent, child, kind, operation) = edge.map_err(store_error)?;
                edge_count += 1;
                let digest = row_digest(&serde_json::json!({
                    "parent_id": parent,
                    "child_id": child,
                    "kind": kind,
                    "operation_id": operation,
                }))?;
                sources.push(source(
                    SourceKind::LotEdge,
                    format!("{parent}->{child}:{kind}"),
                    digest,
                ));
                if parent == lot_id {
                    children.push(format!("{child} ({kind})"));
                }
                if child == lot_id {
                    parents.push(format!("{parent} ({kind})"));
                }
                if let Some(operation) = operation {
                    if table_exists(conn, "lot_operations")? {
                        let operation_row: Option<(String, String, i64)> = conn
                            .query_row(
                                "SELECT request_digest, kind, at_est FROM lot_operations \
                                 WHERE operation_id = ?1",
                                [&operation],
                                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                            )
                            .optional()
                            .map_err(store_error)?;
                        if let Some((request_digest, op_kind, at_est)) = operation_row {
                            sources.push(source(
                                SourceKind::LotOperation,
                                operation.clone(),
                                row_digest(&serde_json::json!({
                                    "operation_id": operation,
                                    "request_digest": request_digest,
                                    "kind": op_kind,
                                    "at_est": at_est,
                                }))?,
                            ));
                        }
                    }
                }
            }
        }
        let disposition_sources = lot_disposition_sources(conn, Some(&lot_id))?;
        let dispositions: Vec<String> = disposition_sources
            .iter()
            .map(|entry| entry.id.clone())
            .collect();
        sources.extend(disposition_sources);
        let ledger = ledger_sources(conn, Some(&lot_id), None)?;
        let ledger_ids: Vec<String> = ledger.iter().map(|entry| entry.id.clone()).collect();
        sources.extend(ledger);
        gathered.touch(Some(window_start));
        gathered.rows.push(ReportRow {
            key: lot_id.clone(),
            cells: string_cells(&[
                ("lot_id", lot_id),
                ("kind", kind),
                ("label", label),
                ("site_id", site_id),
                ("location_id", location_id),
                ("quantity", quantity.to_string()),
                ("uom", uom),
                ("window_start_est", window_start.to_string()),
                (
                    "window_end_est",
                    window_end
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                ),
                ("revision", revision.to_string()),
                ("parents", parents.join("|")),
                ("children", children.join("|")),
                ("dispositions", dispositions.join("|")),
                ("ledger_entries", ledger_ids.join("|")),
            ]),
            sources,
        });
    }
    gathered
        .totals
        .insert("lots".to_string(), gathered.rows.len().to_string());
    gathered
        .totals
        .insert("edges".to_string(), edge_count.to_string());
    Ok(gathered)
}
