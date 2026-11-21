// SPDX-License-Identifier: AGPL-3.0-only

//! Reports, ALCOA+ data integrity, e-signatures and the immutable report audit.
//!
//! Six reports (`excursion_history`, `quarantine_aging`, `disposition`,
//! `calibration_due`, `lot_traceability`, `export_verification`) are generated
//! from the tables the excursion, lot, asset-registry and lineage-ledger modules
//! own. Every row carries the [`SourceRef`]s it was read from — including the
//! ledger's own `entry_hash` — so a report can be traced back to the exact
//! source events and chain entries, and every generation, export, signature,
//! retention action and refused re-authentication is appended to a hash-chained
//! `report_audit` log that is never pruned.
//!
//! ## E-signature ceremony
//!
//! 1. `open_ceremony` re-verifies the signer's identity: a credential digest the
//!    operator enrolled earlier, presented inside [`REAUTH_WINDOW_SECS`], plus a
//!    reason. A stale, missing or wrong credential is refused and audited.
//! 2. The ceremony binds the report's content digest, the signer and a
//!    deterministic nonce.
//! 3. `sign_ceremony` signs the canonical [`esign_payload`] with Ed25519. The
//!    payload names the report id, content digest, ceremony and nonce, so the
//!    same signature cannot be replayed onto another record or reused for a
//!    second signature (the ceremony is single-use).
//!
//! ## Retention
//!
//! `prune_export_bodies` drops export payloads older than a cut-off but keeps
//! their digests, manifests and signatures; the audit chain is never touched. A
//! `snapshot_to` copy restores the audit trail, generations and signatures
//! intact. See `docs/reporting.md`.

pub mod gather;
pub mod render;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain context for a report's content digest.
pub const CONTEXT_REPORT_CONTENT: &str = "TirBase/v1/ReportContent";
/// Domain context for an export manifest digest.
pub const CONTEXT_REPORT_MANIFEST: &str = "TirBase/v1/ReportManifest";
/// Domain context for an export body digest.
pub const CONTEXT_REPORT_BODY: &str = "TirBase/v1/ReportBody";
/// Domain context for the audit-chain entry hash.
pub const CONTEXT_REPORT_AUDIT: &str = "TirBase/v1/ReportAudit";
/// Domain context for an e-signature payload.
pub const CONTEXT_ESIGN_PAYLOAD: &str = "TirBase/v1/EsignPayload";
/// Domain context for a source-row digest.
pub const CONTEXT_SOURCE_ROW: &str = "TirBase/v1/ReportSourceRow";
/// Domain context for a ceremony nonce.
pub const CONTEXT_ESIGN_NONCE: &str = "TirBase/v1/EsignNonce";

/// The all-zero hash that precedes the first audit entry.
pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// How old a re-authentication may be before the ceremony refuses it.
pub const REAUTH_WINDOW_SECS: i64 = 900;

/// Shortest accepted signing reason.
pub const MIN_REASON_LEN: usize = 8;

/// Longest accepted signing reason.
pub const MAX_REASON_LEN: usize = 512;

/// Largest row count one report may hold.
pub const MAX_ROWS: usize = 50_000;

/// Most audit entries one read returns.
pub const MAX_AUDIT_READ: usize = 10_000;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a reporting operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportError {
    /// SQLite failed.
    Store(String),
    /// A request field is unusable.
    InvalidRequest(String),
    /// The report, export, ceremony or signature is unknown.
    NotFound(String),
    /// An existing record conflicts with the request.
    Conflict(String),
    /// The signer's credential digest did not match the enrolled one.
    ReauthFailed(String),
    /// The re-authentication is outside the freshness window.
    ReauthNotFresh {
        /// When the credential was presented.
        at_est: i64,
        /// When the ceremony was opened.
        now_est: i64,
        /// Tolerated age.
        window_secs: i64,
    },
    /// The ceremony was already signed.
    CeremonyAlreadyUsed(String),
    /// A ceremony id was reused with different content.
    CeremonyConflict(String),
    /// The report changed after the ceremony was opened.
    RecordChanged(String),
    /// Rendering or manifest construction failed.
    Export(String),
    /// Signing or key material failed.
    Signing(String),
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportError::Store(detail) => write!(f, "report store: {detail}"),
            ReportError::InvalidRequest(detail) => write!(f, "invalid request: {detail}"),
            ReportError::NotFound(detail) => write!(f, "not found: {detail}"),
            ReportError::Conflict(detail) => write!(f, "conflict: {detail}"),
            ReportError::ReauthFailed(detail) => write!(f, "re-authentication failed: {detail}"),
            ReportError::ReauthNotFresh {
                at_est,
                now_est,
                window_secs,
            } => write!(
                f,
                "re-authentication at {at_est} is outside the {window_secs}s window before {now_est}"
            ),
            ReportError::CeremonyAlreadyUsed(id) => {
                write!(f, "ceremony {id} was already signed")
            }
            ReportError::CeremonyConflict(id) => {
                write!(f, "ceremony {id} already exists with different content")
            }
            ReportError::RecordChanged(detail) => write!(f, "record changed: {detail}"),
            ReportError::Export(detail) => write!(f, "export: {detail}"),
            ReportError::Signing(detail) => write!(f, "signing: {detail}"),
        }
    }
}

impl std::error::Error for ReportError {}

fn store_error(error: impl std::fmt::Display) -> ReportError {
    ReportError::Store(error.to_string())
}

// ---------------------------------------------------------------------------
// Report kinds and requests
// ---------------------------------------------------------------------------

/// The reports the service can generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportKind {
    /// Every excursion in a range with its state and transition events.
    ExcursionHistory,
    /// Open quarantines with their age and an aging bucket.
    QuarantineAging,
    /// Operator dispositions with the lot disposition rows they produced.
    Disposition,
    /// Calibrations due, due soon or overdue per asset.
    CalibrationDue,
    /// Lots, lineage edges, operations and dispositions.
    LotTraceability,
    /// Stored exports re-verified against their digests and signatures.
    ExportVerification,
}

impl ReportKind {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            ReportKind::ExcursionHistory => "excursion_history",
            ReportKind::QuarantineAging => "quarantine_aging",
            ReportKind::Disposition => "disposition",
            ReportKind::CalibrationDue => "calibration_due",
            ReportKind::LotTraceability => "lot_traceability",
            ReportKind::ExportVerification => "export_verification",
        }
    }

    /// Parse a wire name.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "excursion_history" => Some(ReportKind::ExcursionHistory),
            "quarantine_aging" => Some(ReportKind::QuarantineAging),
            "disposition" => Some(ReportKind::Disposition),
            "calibration_due" => Some(ReportKind::CalibrationDue),
            "lot_traceability" => Some(ReportKind::LotTraceability),
            "export_verification" => Some(ReportKind::ExportVerification),
            _ => None,
        }
    }

    /// Every kind, for UIs and tests.
    pub fn all() -> &'static [ReportKind] {
        &[
            ReportKind::ExcursionHistory,
            ReportKind::QuarantineAging,
            ReportKind::Disposition,
            ReportKind::CalibrationDue,
            ReportKind::LotTraceability,
            ReportKind::ExportVerification,
        ]
    }
}

/// One request to generate a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportRequest {
    /// Which report.
    pub kind: ReportKind,
    /// Tenant whose rows are read.
    pub tenant: String,
    /// Inclusive lower bound on the primary timestamp, when set.
    pub from_est: Option<i64>,
    /// Inclusive upper bound on the primary timestamp, when set.
    pub to_est: Option<i64>,
    /// Lot or asset the report is limited to, when set.
    pub subject: Option<String>,
    /// Operator generating the report.
    pub generated_by: String,
    /// Generation instant (also used to age quarantines and calibrations).
    pub now_est: i64,
}

impl ReportRequest {
    /// A tenant-wide report for one kind.
    pub fn new(
        kind: ReportKind,
        tenant: impl Into<String>,
        generated_by: impl Into<String>,
        now_est: i64,
    ) -> Self {
        Self {
            kind,
            tenant: tenant.into(),
            from_est: None,
            to_est: None,
            subject: None,
            generated_by: generated_by.into(),
            now_est,
        }
    }

    /// Limit the report to a time range.
    pub fn with_range(mut self, from_est: Option<i64>, to_est: Option<i64>) -> Self {
        self.from_est = from_est;
        self.to_est = to_est;
        self
    }

    /// Limit the report to one lot or asset.
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    fn validate(&self) -> Result<(), ReportError> {
        if self.tenant.trim().is_empty() || self.tenant.len() > 128 {
            return Err(ReportError::InvalidRequest(
                "tenant must be 1..=128 characters".to_string(),
            ));
        }
        if self.generated_by.trim().is_empty() || self.generated_by.len() > 128 {
            return Err(ReportError::InvalidRequest(
                "generated_by must be 1..=128 characters".to_string(),
            ));
        }
        if let (Some(from), Some(to)) = (self.from_est, self.to_est) {
            if from > to {
                return Err(ReportError::InvalidRequest(
                    "from_est must not be after to_est".to_string(),
                ));
            }
        }
        if let Some(subject) = self.subject.as_ref() {
            if subject.trim().is_empty() || subject.len() > 128 {
                return Err(ReportError::InvalidRequest(
                    "subject must be 1..=128 characters".to_string(),
                ));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/// What a report row was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// An `excursion_records` row.
    ExcursionRecord,
    /// An `excursion_events` transition row.
    ExcursionEvent,
    /// The disposition payload on an excursion record.
    ExcursionDisposition,
    /// A `lot_records` row.
    LotRecord,
    /// A `lot_edges` row.
    LotEdge,
    /// A `lot_operations` row.
    LotOperation,
    /// A `lot_dispositions` row.
    LotDisposition,
    /// An `asset_calibrations` row.
    Calibration,
    /// An `asset_revisions` row.
    AssetVersion,
    /// A `lineage_ledger` entry (digest is the entry's own `entry_hash`).
    LedgerEntry,
    /// A `report_exports` row.
    ReportExport,
}

impl SourceKind {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::ExcursionRecord => "excursion_record",
            SourceKind::ExcursionEvent => "excursion_event",
            SourceKind::ExcursionDisposition => "excursion_disposition",
            SourceKind::LotRecord => "lot_record",
            SourceKind::LotEdge => "lot_edge",
            SourceKind::LotOperation => "lot_operation",
            SourceKind::LotDisposition => "lot_disposition",
            SourceKind::Calibration => "calibration",
            SourceKind::AssetVersion => "asset_version",
            SourceKind::LedgerEntry => "ledger_entry",
            SourceKind::ReportExport => "report_export",
        }
    }
}

/// One traceable source.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceRef {
    /// What kind of row.
    pub kind: SourceKind,
    /// Row identifier (for ledger entries, the ledger `entry_id`).
    pub id: String,
    /// SHA-256 of the row, or the ledger entry hash for ledger sources.
    pub digest: String,
}

/// One report row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportRow {
    /// Unique row key within the report.
    pub key: String,
    /// Column values.
    pub cells: BTreeMap<String, String>,
    /// Rows this one was derived from.
    pub sources: Vec<SourceRef>,
}

// ---------------------------------------------------------------------------
// ALCOA+
// ---------------------------------------------------------------------------

/// One ALCOA+ criterion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlcoaCheck {
    /// Whether the criterion holds for this report.
    pub satisfied: bool,
    /// Evidence for the verdict.
    pub detail: String,
}

impl AlcoaCheck {
    fn new(satisfied: bool, detail: impl Into<String>) -> Self {
        Self {
            satisfied,
            detail: detail.into(),
        }
    }
}

/// The nine ALCOA+ criteria, assessed per generated report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlcoaAssessment {
    /// Who generated the report and which sources every row carries.
    pub attributable: AlcoaCheck,
    /// Every declared column is present in every row.
    pub legible: AlcoaCheck,
    /// No source post-dates the generation instant.
    pub contemporaneous: AlcoaCheck,
    /// The content digest recomputes.
    pub original: AlcoaCheck,
    /// Every source carries a 64-hex digest.
    pub accurate: AlcoaCheck,
    /// Totals and columns cover the rows.
    pub complete: AlcoaCheck,
    /// Row keys are unique.
    pub consistent: AlcoaCheck,
    /// The generation is stored and audited.
    pub enduring: AlcoaCheck,
    /// The report is retrievable for export.
    pub available: AlcoaCheck,
}

impl AlcoaAssessment {
    fn pending() -> Self {
        let placeholder = AlcoaCheck::new(false, "not evaluated");
        Self {
            attributable: placeholder.clone(),
            legible: placeholder.clone(),
            contemporaneous: placeholder.clone(),
            original: placeholder.clone(),
            accurate: placeholder.clone(),
            complete: placeholder.clone(),
            consistent: placeholder.clone(),
            enduring: placeholder.clone(),
            available: placeholder,
        }
    }

    /// Whether all nine criteria hold.
    pub fn satisfied(&self) -> bool {
        self.attributable.satisfied
            && self.legible.satisfied
            && self.contemporaneous.satisfied
            && self.original.satisfied
            && self.accurate.satisfied
            && self.complete.satisfied
            && self.consistent.satisfied
            && self.enduring.satisfied
            && self.available.satisfied
    }

    fn evaluate(report: &Report, stored: bool, audited: bool) -> Self {
        let attributable = AlcoaCheck::new(
            !report.generated_by.trim().is_empty()
                && report.rows.iter().all(|row| !row.sources.is_empty()),
            format!(
                "generated by {}; {} row(s), {} source reference(s)",
                report.generated_by,
                report.rows.len(),
                report.sources.len()
            ),
        );
        let legible = AlcoaCheck::new(
            !report.columns.is_empty()
                && report.rows.iter().all(|row| {
                    report
                        .columns
                        .iter()
                        .all(|column| row.cells.contains_key(column))
                }),
            format!(
                "{} column(s) declared; every row renders every column",
                report.columns.len()
            ),
        );
        let latest = report.rows.iter().flat_map(|row| {
            ["opened_est", "window_start_est", "performed_est"]
                .iter()
                .filter_map(|column| row.cells.get(*column))
                .filter_map(|value| value.parse::<i64>().ok())
        });
        let latest = latest.max();
        let contemporaneous = AlcoaCheck::new(
            latest.map(|at| at <= report.generated_est).unwrap_or(true),
            match latest {
                Some(at) => format!(
                    "latest source instant {at} <= generation {}",
                    report.generated_est
                ),
                None => "no timestamped source rows".to_string(),
            },
        );
        let original = AlcoaCheck::new(
            content_digest(report)
                .map(|digest| digest == report.content_sha256)
                .unwrap_or(false),
            format!("content SHA-256 {}", report.content_sha256),
        );
        let accurate = AlcoaCheck::new(
            report.sources.iter().all(|source| {
                source.digest.len() == 64
                    && source
                        .digest
                        .chars()
                        .all(|character| character.is_ascii_hexdigit())
                    && !source.id.is_empty()
            }),
            format!("{} source digest(s) verified shape", report.sources.len()),
        );
        let complete = AlcoaCheck::new(
            !report.totals.is_empty() && report.rows.iter().all(|row| !row.cells.is_empty()),
            format!(
                "{} roll-up total(s), {} row(s)",
                report.totals.len(),
                report.rows.len()
            ),
        );
        let keys: BTreeSet<&str> = report.rows.iter().map(|row| row.key.as_str()).collect();
        let consistent = AlcoaCheck::new(
            keys.len() == report.rows.len(),
            format!("{} row key(s), {} unique", report.rows.len(), keys.len()),
        );
        let enduring = AlcoaCheck::new(
            stored && audited,
            if audited {
                "generation stored and appended to the audit chain".to_string()
            } else {
                "generation is not yet audited".to_string()
            },
        );
        let available = AlcoaCheck::new(
            stored,
            if stored {
                "stored in primary.db and retrievable for export".to_string()
            } else {
                "not stored".to_string()
            },
        );
        Self {
            attributable,
            legible,
            contemporaneous,
            original,
            accurate,
            complete,
            consistent,
            enduring,
            available,
        }
    }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/// A generated, immutable report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    /// Deterministic report id derived from the content digest.
    pub report_id: String,
    /// Report kind.
    pub kind: ReportKind,
    /// Tenant.
    pub tenant: String,
    /// When it was generated.
    pub generated_est: i64,
    /// Who generated it.
    pub generated_by: String,
    /// Requested time range.
    pub range: Option<(i64, i64)>,
    /// Declared columns.
    pub columns: Vec<String>,
    /// Rows.
    pub rows: Vec<ReportRow>,
    /// Roll-up totals.
    pub totals: BTreeMap<String, String>,
    /// Every distinct source, sorted.
    pub sources: Vec<SourceRef>,
    /// SHA-256 over the content document.
    pub content_sha256: String,
    /// ALCOA+ assessment.
    pub alcoa: AlcoaAssessment,
}

impl Report {
    /// Ledger entries this report names.
    pub fn ledger_refs(&self) -> Vec<&SourceRef> {
        self.sources
            .iter()
            .filter(|source| source.kind == SourceKind::LedgerEntry)
            .collect()
    }

    /// Whether `source` is named by the report.
    pub fn cites(&self, kind: SourceKind, id: &str) -> bool {
        self.sources
            .iter()
            .any(|source| source.kind == kind && source.id == id)
    }
}

/// The document a report's content digest covers.
fn content_document(report: &Report) -> serde_json::Value {
    serde_json::json!({
        "kind": report.kind.as_str(),
        "tenant": report.tenant,
        "generated_est": report.generated_est,
        "generated_by": report.generated_by,
        "range": report.range,
        "columns": report.columns,
        "rows": report.rows,
        "totals": report.totals,
        "sources": report.sources,
    })
}

fn content_digest(report: &Report) -> Result<String, ReportError> {
    digest_json(CONTEXT_REPORT_CONTENT, &content_document(report))
}

fn digest_bytes(context: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(context.as_bytes());
    hasher.update(b"\0");
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn digest_json(context: &str, value: &serde_json::Value) -> Result<String, ReportError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ReportError::InvalidRequest(format!("encode digest input: {error}")))?;
    Ok(digest_bytes(context, &bytes))
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

/// Export encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    /// Comma-separated values.
    Csv,
    /// Pretty JSON including provenance and ALCOA+.
    Json,
    /// Paginated PDF.
    Pdf,
}

impl ExportFormat {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            ExportFormat::Csv => "csv",
            ExportFormat::Json => "json",
            ExportFormat::Pdf => "pdf",
        }
    }

    /// Parse a wire name.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "csv" => Some(ExportFormat::Csv),
            "json" => Some(ExportFormat::Json),
            "pdf" => Some(ExportFormat::Pdf),
            _ => None,
        }
    }

    /// Media type of the body.
    pub fn content_type(self) -> &'static str {
        match self {
            ExportFormat::Csv => "text/csv; charset=utf-8",
            ExportFormat::Json => "application/json",
            ExportFormat::Pdf => "application/pdf",
        }
    }

    /// File extension.
    pub fn extension(self) -> &'static str {
        self.as_str()
    }
}

/// Signed description of one export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportManifest {
    /// Manifest schema version.
    pub manifest_version: u32,
    /// Export id.
    pub export_id: String,
    /// Report id.
    pub report_id: String,
    /// Report kind.
    pub kind: ReportKind,
    /// Tenant.
    pub tenant: String,
    /// Report content digest.
    pub content_sha256: String,
    /// Rows exported.
    pub row_count: usize,
    /// When the report was generated.
    pub generated_est: i64,
    /// Encoding.
    pub format: ExportFormat,
    /// SHA-256 of the body.
    pub body_sha256: String,
    /// Body length.
    pub body_bytes: usize,
    /// When it was exported.
    pub exported_est: i64,
    /// Who exported it.
    pub exported_by: String,
    /// Ed25519 public key of the exporter.
    pub signer_public_key: String,
    /// Signature algorithm.
    pub signature_algorithm: String,
}

/// A stored export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportRecord {
    /// Manifest.
    pub manifest: ExportManifest,
    /// Canonical manifest JSON that was signed.
    pub manifest_json: String,
    /// Manifest digest.
    pub manifest_sha256: String,
    /// Ed25519 signature over the manifest JSON.
    pub signature: String,
    /// Rendered body (may be empty after retention pruning).
    pub body: Vec<u8>,
}

/// Result of re-verifying a stored export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportVerification {
    /// Export id.
    pub export_id: String,
    /// Report id.
    pub report_id: String,
    /// Whether the body is still stored.
    pub body_present: bool,
    /// Stored body digest.
    pub body_sha256: String,
    /// Recomputable digest.
    pub recomputed_body_sha256: Option<String>,
    /// Whether the manifest signature verifies.
    pub signature_valid: bool,
    /// Whether everything checks out.
    pub valid: bool,
    /// Why it does not.
    pub reasons: Vec<String>,
}

/// Lightweight export listing entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportSummary {
    /// Export id.
    pub export_id: String,
    /// Report id.
    pub report_id: String,
    /// Encoding.
    pub format: ExportFormat,
    /// When exported.
    pub exported_est: i64,
    /// Who exported.
    pub exported_by: String,
    /// Body digest.
    pub body_sha256: String,
    /// Whether the body was pruned.
    pub body_pruned: bool,
}

// ---------------------------------------------------------------------------
// E-signature types
// ---------------------------------------------------------------------------

/// How the signer re-authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReauthMethod {
    /// Password re-entry.
    Password,
    /// Time-based one-time code.
    Totp,
    /// Platform authenticator (WebAuthn).
    WebAuthn,
    /// Hardware token.
    HardwareToken,
}

impl ReauthMethod {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            ReauthMethod::Password => "password",
            ReauthMethod::Totp => "totp",
            ReauthMethod::WebAuthn => "webauthn",
            ReauthMethod::HardwareToken => "hardware_token",
        }
    }

    /// Parse a wire name.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "password" => Some(ReauthMethod::Password),
            "totp" => Some(ReauthMethod::Totp),
            "webauthn" => Some(ReauthMethod::WebAuthn),
            "hardware_token" => Some(ReauthMethod::HardwareToken),
            _ => None,
        }
    }
}

/// Proof the signer re-authenticated just now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReauthProof {
    /// Method used.
    pub method: ReauthMethod,
    /// When the credential was presented.
    pub at_est: i64,
    /// SHA-256 of the credential as enrolled (never the credential itself).
    pub credential_sha256: String,
}

/// A signer enrolled for e-signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerEnrollment {
    /// Signer id (operator DID).
    pub signer_id: String,
    /// SHA-256 of the credential the signer re-authenticates with.
    pub credential_sha256: String,
    /// Role the signer signs under.
    pub role: String,
    /// When enrolled.
    pub enrolled_est: i64,
}

/// One request to open a signing ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyRequest {
    /// Caller-supplied ceremony id (idempotency key).
    pub ceremony_id: String,
    /// Report being signed.
    pub report_id: String,
    /// Enrolled signer.
    pub signer_id: String,
    /// Why the signer is signing.
    pub reason: String,
    /// Fresh re-authentication.
    pub reauth: ReauthProof,
    /// When the ceremony is being opened (judges re-authentication freshness).
    pub now_est: i64,
}

impl CeremonyRequest {
    /// Build a request.
    pub fn new(
        ceremony_id: impl Into<String>,
        report_id: impl Into<String>,
        signer_id: impl Into<String>,
        reason: impl Into<String>,
        reauth: ReauthProof,
        now_est: i64,
    ) -> Self {
        Self {
            ceremony_id: ceremony_id.into(),
            report_id: report_id.into(),
            signer_id: signer_id.into(),
            reason: reason.into(),
            reauth,
            now_est,
        }
    }
}

/// An opened signing ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsignCeremony {
    /// Ceremony id.
    pub ceremony_id: String,
    /// Report id.
    pub report_id: String,
    /// Signer.
    pub signer_id: String,
    /// Reason.
    pub reason: String,
    /// Report content digest the ceremony is bound to.
    pub record_sha256: String,
    /// Deterministic nonce.
    pub nonce: String,
    /// Re-authentication method.
    pub reauth_method: ReauthMethod,
    /// When re-authentication happened.
    pub reauth_est: i64,
    /// When the ceremony opened.
    pub opened_est: i64,
    /// When it was signed, if it was.
    pub signed_est: Option<i64>,
}

/// A completed e-signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsignResult {
    /// Signature id.
    pub signature_id: String,
    /// Ceremony.
    pub ceremony_id: String,
    /// Report.
    pub report_id: String,
    /// Signer.
    pub signer_id: String,
    /// Reason.
    pub reason: String,
    /// Content digest signed.
    pub record_sha256: String,
    /// Ceremony nonce.
    pub nonce: String,
    /// When signed.
    pub signed_est: i64,
    /// Ed25519 signature (hex).
    pub signature: String,
    /// Signer public key (hex).
    pub signer_public_key: String,
}

/// Result of verifying a stored signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureVerification {
    /// Signature id.
    pub signature_id: String,
    /// Report.
    pub report_id: String,
    /// Signer.
    pub signer_id: String,
    /// Whether the signature verifies against this report.
    pub valid: bool,
    /// Whether the report's content digest still matches the signed digest.
    pub record_matches: bool,
    /// Why it does not verify.
    pub reasons: Vec<String>,
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/// One immutable audit entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Contiguous sequence, starting at 1.
    pub seq: u64,
    /// Previous entry hash, or [`ZERO_HASH`].
    pub prev_hash: String,
    /// Domain-separated hash of this entry.
    pub entry_hash: String,
    /// When it happened.
    pub at_est: i64,
    /// Who caused it.
    pub actor_did: String,
    /// What happened (`report_generated`, `report_exported`, …).
    pub action: String,
    /// Subject (report/export/signature id).
    pub subject: String,
    /// Structured detail.
    pub detail: serde_json::Value,
}

/// Result of verifying the audit chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditVerification {
    /// Whether the chain is intact.
    pub valid: bool,
    /// Entries checked.
    pub entries: usize,
    /// Head hash.
    pub head_hash: String,
    /// Failures.
    pub reasons: Vec<String>,
}

/// Summary of one generated report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSummary {
    /// Report id.
    pub report_id: String,
    /// Kind.
    pub kind: ReportKind,
    /// Tenant.
    pub tenant: String,
    /// Generated at.
    pub generated_est: i64,
    /// Generated by.
    pub generated_by: String,
    /// Rows.
    pub row_count: usize,
    /// Content digest.
    pub content_sha256: String,
    /// Whether every ALCOA+ criterion holds.
    pub alcoa_satisfied: bool,
}

// ---------------------------------------------------------------------------
// Signer
// ---------------------------------------------------------------------------

/// The Ed25519 key the gateway signs exports and e-signatures with.
pub struct ReportSigner {
    signing_key: SigningKey,
}

impl std::fmt::Debug for ReportSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReportSigner")
            .field("public_key", &self.public_key_hex())
            .finish()
    }
}

impl ReportSigner {
    /// Derive a signer from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }

    /// Public key, lower-case hex.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    fn sign_hex(&self, bytes: &[u8]) -> String {
        hex::encode(self.signing_key.sign(bytes).to_bytes())
    }
}

/// Verify an Ed25519 signature over `message`.
pub fn verify_payload_signature(public_key_hex: &str, message: &[u8], signature_hex: &str) -> bool {
    let Ok(key) = hex::decode(public_key_hex) else {
        return false;
    };
    let Ok(key): Result<[u8; 32], _> = key.try_into() else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key) else {
        return false;
    };
    let Ok(signature) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(signature): Result<[u8; 64], _> = signature.try_into() else {
        return false;
    };
    key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))
        .is_ok()
}

/// Canonical bytes an e-signature signs.
pub fn esign_payload(
    report_id: &str,
    record_sha256: &str,
    signer_id: &str,
    ceremony_id: &str,
    nonce: &str,
    reason: &str,
    signed_est: i64,
) -> Result<Vec<u8>, ReportError> {
    let value = serde_json::json!({
        "report_id": report_id,
        "record_sha256": record_sha256,
        "signer_id": signer_id,
        "ceremony_id": ceremony_id,
        "nonce": nonce,
        "reason": reason,
        "signed_est": signed_est,
    });
    let bytes = serde_json::to_vec(&value)
        .map_err(|error| ReportError::Signing(format!("encode e-signature payload: {error}")))?;
    let mut payload = Vec::with_capacity(CONTEXT_ESIGN_PAYLOAD.len() + 1 + bytes.len());
    payload.extend_from_slice(CONTEXT_ESIGN_PAYLOAD.as_bytes());
    payload.push(0);
    payload.extend_from_slice(&bytes);
    Ok(payload)
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS report_generations (
    report_id       TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,
    tenant          TEXT NOT NULL,
    generated_est   INTEGER NOT NULL,
    generated_by    TEXT NOT NULL,
    range_start_est INTEGER,
    range_end_est   INTEGER,
    row_count       INTEGER NOT NULL,
    content_sha256  TEXT NOT NULL,
    content_json    TEXT NOT NULL,
    sources_json    TEXT NOT NULL,
    alcoa_json      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_report_generations_tenant
    ON report_generations(tenant, kind, generated_est);

CREATE TABLE IF NOT EXISTS report_audit (
    seq         INTEGER PRIMARY KEY,
    prev_hash   TEXT NOT NULL,
    entry_hash  TEXT NOT NULL,
    at_est      INTEGER NOT NULL,
    actor_did   TEXT NOT NULL,
    action      TEXT NOT NULL,
    subject     TEXT NOT NULL,
    detail_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_report_audit_subject ON report_audit(subject, seq);

CREATE TABLE IF NOT EXISTS report_exports (
    export_id        TEXT PRIMARY KEY,
    report_id        TEXT NOT NULL,
    format           TEXT NOT NULL,
    created_est      INTEGER NOT NULL,
    created_by       TEXT NOT NULL,
    body             BLOB NOT NULL,
    body_sha256      TEXT NOT NULL,
    body_pruned_est  INTEGER,
    manifest_json    TEXT NOT NULL,
    manifest_sha256  TEXT NOT NULL,
    signature        TEXT NOT NULL,
    signer_public_key TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_report_exports_report ON report_exports(report_id, created_est);

CREATE TABLE IF NOT EXISTS report_signers (
    signer_id         TEXT PRIMARY KEY,
    credential_sha256 TEXT NOT NULL,
    role              TEXT NOT NULL,
    enrolled_est      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS esign_ceremonies (
    ceremony_id   TEXT PRIMARY KEY,
    report_id     TEXT NOT NULL,
    signer_id     TEXT NOT NULL,
    reason        TEXT NOT NULL,
    record_sha256 TEXT NOT NULL,
    nonce         TEXT NOT NULL,
    reauth_method TEXT NOT NULL,
    reauth_est    INTEGER NOT NULL,
    opened_est    INTEGER NOT NULL,
    signed_est    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_esign_ceremonies_report ON esign_ceremonies(report_id);

CREATE TABLE IF NOT EXISTS esign_signatures (
    signature_id      TEXT PRIMARY KEY,
    ceremony_id       TEXT NOT NULL UNIQUE,
    report_id         TEXT NOT NULL,
    signer_id         TEXT NOT NULL,
    reason            TEXT NOT NULL,
    record_sha256     TEXT NOT NULL,
    nonce             TEXT NOT NULL,
    signed_est        INTEGER NOT NULL,
    signature         TEXT NOT NULL,
    signer_public_key TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_esign_signatures_report ON esign_signatures(report_id);
"#;

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// Report generation, export, e-signature and audit service.
#[derive(Debug)]
pub struct ReportService {
    conn: Connection,
    signer: ReportSigner,
}

impl ReportService {
    /// Open the service at `path`, creating its tables.
    pub fn open(path: impl AsRef<Path>, signer: ReportSigner) -> Result<Self, ReportError> {
        let conn = crate::db::open_primary(path)
            .map_err(|error| ReportError::Store(format!("open primary db: {error:?}")))?;
        Self::from_connection(conn, signer)
    }

    /// Open an in-memory service (tests, ephemeral deployments).
    pub fn open_in_memory(signer: ReportSigner) -> Result<Self, ReportError> {
        let conn = Connection::open_in_memory().map_err(store_error)?;
        Self::from_connection(conn, signer)
    }

    fn from_connection(conn: Connection, signer: ReportSigner) -> Result<Self, ReportError> {
        conn.execute_batch(SCHEMA)
            .map_err(|error| ReportError::Store(format!("create reporting schema: {error}")))?;
        Ok(Self { conn, signer })
    }

    /// Public key exports and signatures are made with.
    pub fn signer_public_key_hex(&self) -> String {
        self.signer.public_key_hex()
    }

    // -----------------------------------------------------------------------
    // Enrollment
    // -----------------------------------------------------------------------

    /// Enroll (or re-enroll) a signer with the SHA-256 of their credential.
    pub fn enroll_signer(
        &self,
        enrollment: &SignerEnrollment,
        actor_did: &str,
    ) -> Result<(), ReportError> {
        if enrollment.signer_id.trim().is_empty() {
            return Err(ReportError::InvalidRequest(
                "signer_id is empty".to_string(),
            ));
        }
        if enrollment.credential_sha256.len() != 64
            || !enrollment
                .credential_sha256
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            return Err(ReportError::InvalidRequest(
                "credential_sha256 must be 64 hex characters".to_string(),
            ));
        }
        self.conn
            .execute(
                "INSERT INTO report_signers (signer_id, credential_sha256, role, enrolled_est) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(signer_id) DO UPDATE SET credential_sha256 = excluded.credential_sha256, \
                 role = excluded.role, enrolled_est = excluded.enrolled_est",
                params![
                    enrollment.signer_id,
                    enrollment.credential_sha256,
                    enrollment.role,
                    enrollment.enrolled_est
                ],
            )
            .map_err(store_error)?;
        self.append_audit(
            enrollment.enrolled_est,
            actor_did,
            "signer_enrolled",
            &enrollment.signer_id,
            serde_json::json!({ "role": enrollment.role }),
        )?;
        Ok(())
    }

    /// The enrolled signer, if any.
    pub fn signer(&self, signer_id: &str) -> Result<Option<SignerEnrollment>, ReportError> {
        self.conn
            .query_row(
                "SELECT signer_id, credential_sha256, role, enrolled_est FROM report_signers \
                 WHERE signer_id = ?1",
                [signer_id],
                |row| {
                    Ok(SignerEnrollment {
                        signer_id: row.get(0)?,
                        credential_sha256: row.get(1)?,
                        role: row.get(2)?,
                        enrolled_est: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(store_error)
    }

    // -----------------------------------------------------------------------
    // Generation
    // -----------------------------------------------------------------------

    /// Generate a report and append it to the audit chain.
    pub fn generate(&self, request: &ReportRequest) -> Result<Report, ReportError> {
        request.validate()?;
        let gathered = match request.kind {
            ReportKind::ExportVerification => self.gather_export_verification(request)?,
            _ => gather::collect(&self.conn, request)?,
        };

        let mut sources: Vec<SourceRef> = gathered
            .rows
            .iter()
            .flat_map(|row| row.sources.iter().cloned())
            .collect();
        sources.sort();
        sources.dedup();

        let mut report = Report {
            report_id: String::new(),
            kind: request.kind,
            tenant: request.tenant.clone(),
            generated_est: request.now_est,
            generated_by: request.generated_by.clone(),
            range: match (request.from_est, request.to_est) {
                (None, None) => None,
                (from, to) => Some((
                    from.unwrap_or(gathered.latest_source_est.unwrap_or(0)),
                    to.unwrap_or(request.now_est),
                )),
            },
            columns: gathered.columns,
            rows: gathered.rows,
            totals: gathered.totals,
            sources,
            content_sha256: String::new(),
            alcoa: AlcoaAssessment::pending(),
        };
        report.content_sha256 = content_digest(&report)?;
        report.report_id = format!("rpt-{}", &report.content_sha256[..16]);

        if let Some(existing) = self.load_report_optional(&report.report_id)? {
            return Ok(existing);
        }

        self.conn
            .execute(
                "INSERT INTO report_generations (report_id, kind, tenant, generated_est, \
                 generated_by, range_start_est, range_end_est, row_count, content_sha256, \
                 content_json, sources_json, alcoa_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    report.report_id,
                    report.kind.as_str(),
                    report.tenant,
                    report.generated_est,
                    report.generated_by,
                    report.range.map(|range| range.0),
                    report.range.map(|range| range.1),
                    report.rows.len() as i64,
                    report.content_sha256,
                    serde_json::to_string(&report)
                        .map_err(|error| ReportError::Store(format!("encode report: {error}")))?,
                    serde_json::to_string(&report.sources)
                        .map_err(|error| ReportError::Store(format!("encode sources: {error}")))?,
                    serde_json::to_string(&AlcoaAssessment::pending()).map_err(|error| {
                        ReportError::Store(format!("encode ALCOA+: {error}"))
                    })?,
                ],
            )
            .map_err(store_error)?;

        self.append_audit(
            request.now_est,
            &request.generated_by,
            "report_generated",
            &report.report_id,
            serde_json::json!({
                "kind": report.kind.as_str(),
                "tenant": report.tenant,
                "row_count": report.rows.len(),
                "content_sha256": report.content_sha256,
                "source_count": report.sources.len(),
            }),
        )?;

        report.alcoa = AlcoaAssessment::evaluate(&report, true, true);
        self.conn
            .execute(
                "UPDATE report_generations SET content_json = ?2, alcoa_json = ?3 \
                 WHERE report_id = ?1",
                params![
                    report.report_id,
                    serde_json::to_string(&report)
                        .map_err(|error| ReportError::Store(format!("encode report: {error}")))?,
                    serde_json::to_string(&report.alcoa).map_err(|error| {
                        ReportError::Store(format!("encode ALCOA+: {error}"))
                    })?,
                ],
            )
            .map_err(store_error)?;
        Ok(report)
    }

    /// Load a report by id.
    pub fn load_report(&self, report_id: &str) -> Result<Report, ReportError> {
        self.load_report_optional(report_id)?
            .ok_or_else(|| ReportError::NotFound(format!("report {report_id}")))
    }

    fn load_report_optional(&self, report_id: &str) -> Result<Option<Report>, ReportError> {
        let content: Option<String> = self
            .conn
            .query_row(
                "SELECT content_json FROM report_generations WHERE report_id = ?1",
                [report_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(store_error)?;
        content
            .map(|json| {
                serde_json::from_str(&json)
                    .map_err(|error| ReportError::Store(format!("decode report: {error}")))
            })
            .transpose()
    }

    /// Generated reports for a tenant, newest first.
    pub fn list_reports(
        &self,
        tenant: &str,
        kind: Option<ReportKind>,
        limit: usize,
    ) -> Result<Vec<ReportSummary>, ReportError> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT report_id, kind, tenant, generated_est, generated_by, row_count, \
                 content_sha256, alcoa_json FROM report_generations \
                 WHERE tenant = ?1 AND (?2 IS NULL OR kind = ?2) \
                 ORDER BY generated_est DESC, report_id DESC LIMIT ?3",
            )
            .map_err(store_error)?;
        let rows = statement
            .query_map(
                params![
                    tenant,
                    kind.map(ReportKind::as_str),
                    limit.clamp(1, 1_000) as i64
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                },
            )
            .map_err(store_error)?;
        let mut summaries = Vec::new();
        for row in rows {
            let (
                report_id,
                kind,
                tenant,
                generated_est,
                generated_by,
                row_count,
                content_sha256,
                alcoa,
            ) = row.map_err(store_error)?;
            let alcoa: AlcoaAssessment =
                serde_json::from_str(&alcoa).unwrap_or_else(|_| AlcoaAssessment::pending());
            summaries.push(ReportSummary {
                report_id,
                kind: ReportKind::parse(&kind).unwrap_or(ReportKind::ExcursionHistory),
                tenant,
                generated_est,
                generated_by,
                row_count: row_count as usize,
                content_sha256,
                alcoa_satisfied: alcoa.satisfied(),
            });
        }
        Ok(summaries)
    }

    // -----------------------------------------------------------------------
    // Exports
    // -----------------------------------------------------------------------

    /// Render and sign an export of `report_id`.
    pub fn export(
        &self,
        report_id: &str,
        format: ExportFormat,
        exported_by: &str,
        now_est: i64,
    ) -> Result<ExportRecord, ReportError> {
        if exported_by.trim().is_empty() {
            return Err(ReportError::InvalidRequest(
                "exported_by is empty".to_string(),
            ));
        }
        let report = self.load_report(report_id)?;
        let body = render::render(&report, format)?;
        let body_sha256 = digest_bytes(CONTEXT_REPORT_BODY, &body);
        let export_id = format!("exp-{}", &body_sha256[..16]);
        let manifest = ExportManifest {
            manifest_version: 1,
            export_id: export_id.clone(),
            report_id: report.report_id.clone(),
            kind: report.kind,
            tenant: report.tenant.clone(),
            content_sha256: report.content_sha256.clone(),
            row_count: report.rows.len(),
            generated_est: report.generated_est,
            format,
            body_sha256: body_sha256.clone(),
            body_bytes: body.len(),
            exported_est: now_est,
            exported_by: exported_by.to_string(),
            signer_public_key: self.signer.public_key_hex(),
            signature_algorithm: "ed25519".to_string(),
        };
        let manifest_json = serde_json::to_string(&manifest)
            .map_err(|error| ReportError::Export(format!("encode manifest: {error}")))?;
        let manifest_sha256 = digest_bytes(CONTEXT_REPORT_MANIFEST, manifest_json.as_bytes());
        let signature = self.signer.sign_hex(manifest_json.as_bytes());

        if let Some(existing) = self.load_export(&export_id)? {
            return Ok(existing);
        }
        self.conn
            .execute(
                "INSERT INTO report_exports (export_id, report_id, format, created_est, created_by, \
                 body, body_sha256, manifest_json, manifest_sha256, signature, signer_public_key) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    export_id,
                    report.report_id,
                    format.as_str(),
                    now_est,
                    exported_by,
                    body,
                    body_sha256,
                    manifest_json,
                    manifest_sha256,
                    signature,
                    manifest.signer_public_key,
                ],
            )
            .map_err(store_error)?;
        self.append_audit(
            now_est,
            exported_by,
            "report_exported",
            &export_id,
            serde_json::json!({
                "report_id": report.report_id,
                "format": format.as_str(),
                "body_sha256": body_sha256,
                "manifest_sha256": manifest_sha256,
                "body_bytes": body.len(),
            }),
        )?;
        Ok(ExportRecord {
            manifest,
            manifest_json,
            manifest_sha256,
            signature,
            body,
        })
    }

    fn load_export(&self, export_id: &str) -> Result<Option<ExportRecord>, ReportError> {
        self.conn
            .query_row(
                "SELECT manifest_json, signature, body FROM report_exports WHERE export_id = ?1",
                [export_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(store_error)?
            .map(|(manifest_json, signature, body)| {
                let manifest: ExportManifest = serde_json::from_str(&manifest_json)
                    .map_err(|error| ReportError::Store(format!("decode manifest: {error}")))?;
                let manifest_sha256 =
                    digest_bytes(CONTEXT_REPORT_MANIFEST, manifest_json.as_bytes());
                Ok(ExportRecord {
                    manifest,
                    manifest_json,
                    manifest_sha256,
                    signature,
                    body,
                })
            })
            .transpose()
    }

    /// The stored export body, if it has not been pruned.
    pub fn export_body(&self, export_id: &str) -> Result<Option<Vec<u8>>, ReportError> {
        let body: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT body FROM report_exports WHERE export_id = ?1",
                [export_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(store_error)?;
        Ok(body.filter(|body| !body.is_empty()))
    }

    /// Exports of one report.
    pub fn exports_for(&self, report_id: &str) -> Result<Vec<ExportSummary>, ReportError> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT export_id, report_id, format, created_est, created_by, body_sha256, \
                 body_pruned_est FROM report_exports WHERE report_id = ?1 ORDER BY created_est",
            )
            .map_err(store_error)?;
        let rows = statement
            .query_map([report_id], |row| {
                Ok(ExportSummary {
                    export_id: row.get(0)?,
                    report_id: row.get(1)?,
                    format: ExportFormat::parse(&row.get::<_, String>(2)?)
                        .unwrap_or(ExportFormat::Csv),
                    exported_est: row.get(3)?,
                    exported_by: row.get(4)?,
                    body_sha256: row.get(5)?,
                    body_pruned: row.get::<_, Option<i64>>(6)?.is_some(),
                })
            })
            .map_err(store_error)?;
        let mut exports = Vec::new();
        for row in rows {
            exports.push(row.map_err(store_error)?);
        }
        Ok(exports)
    }

    /// Re-verify a stored export's body digest and manifest signature.
    pub fn verify_export(&self, export_id: &str) -> Result<ExportVerification, ReportError> {
        let (manifest_json, manifest_sha256, signature, body, public_key, report_id): (
            String,
            String,
            String,
            Vec<u8>,
            String,
            String,
        ) = self
            .conn
            .query_row(
                "SELECT manifest_json, manifest_sha256, signature, body, signer_public_key, report_id \
                 FROM report_exports WHERE export_id = ?1",
                [export_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(store_error)?
            .ok_or_else(|| ReportError::NotFound(format!("export {export_id}")))?;
        let manifest: ExportManifest = serde_json::from_str(&manifest_json)
            .map_err(|error| ReportError::Store(format!("decode manifest: {error}")))?;
        let mut reasons = Vec::new();
        let recomputed_manifest = digest_bytes(CONTEXT_REPORT_MANIFEST, manifest_json.as_bytes());
        if recomputed_manifest != manifest_sha256 {
            reasons.push("manifest digest does not match".to_string());
        }
        let signature_valid =
            verify_payload_signature(&public_key, manifest_json.as_bytes(), &signature);
        if !signature_valid {
            reasons.push("manifest signature does not verify".to_string());
        }
        let body_present = !body.is_empty();
        let recomputed_body_sha256 = body_present.then(|| digest_bytes(CONTEXT_REPORT_BODY, &body));
        if let Some(recomputed) = recomputed_body_sha256.as_ref() {
            if recomputed != &manifest.body_sha256 {
                reasons.push("body digest does not match the manifest".to_string());
            }
        } else {
            reasons.push("body was pruned by retention".to_string());
        }
        Ok(ExportVerification {
            export_id: export_id.to_string(),
            report_id,
            body_present,
            body_sha256: manifest.body_sha256.clone(),
            recomputed_body_sha256,
            signature_valid,
            valid: reasons.is_empty(),
            reasons,
        })
    }

    // -----------------------------------------------------------------------
    // E-signatures
    // -----------------------------------------------------------------------

    /// Open a signing ceremony after re-verifying the signer's identity.
    pub fn open_ceremony(&self, request: &CeremonyRequest) -> Result<EsignCeremony, ReportError> {
        let reason = request.reason.trim();
        if reason.len() < MIN_REASON_LEN || reason.len() > MAX_REASON_LEN {
            return Err(ReportError::InvalidRequest(format!(
                "reason must be {MIN_REASON_LEN}..={MAX_REASON_LEN} characters"
            )));
        }
        let report = self.load_report(&request.report_id)?;

        let enrollment = self
            .signer(&request.signer_id)?
            .ok_or_else(|| ReportError::ReauthFailed("signer is not enrolled".to_string()))?;

        if !constant_time_eq(
            enrollment.credential_sha256.as_bytes(),
            request
                .reauth
                .credential_sha256
                .to_ascii_lowercase()
                .as_bytes(),
        ) {
            self.append_audit(
                request.reauth.at_est,
                &request.signer_id,
                "esign_reauth_failed",
                &request.report_id,
                serde_json::json!({
                    "reason": "credential digest mismatch",
                    "ceremony_id": request.ceremony_id,
                }),
            )?;
            return Err(ReportError::ReauthFailed(
                "credential digest does not match the enrolled credential".to_string(),
            ));
        }

        let age = request.now_est.saturating_sub(request.reauth.at_est);
        if request.reauth.at_est > request.now_est || age > REAUTH_WINDOW_SECS {
            self.append_audit(
                request.now_est,
                &request.signer_id,
                "esign_reauth_failed",
                &request.report_id,
                serde_json::json!({
                    "reason": "re-authentication outside the freshness window",
                    "reauth_est": request.reauth.at_est,
                    "ceremony_id": request.ceremony_id,
                }),
            )?;
            return Err(ReportError::ReauthNotFresh {
                at_est: request.reauth.at_est,
                now_est: request.now_est,
                window_secs: REAUTH_WINDOW_SECS,
            });
        }

        let nonce = digest_json(
            CONTEXT_ESIGN_NONCE,
            &serde_json::json!({
                "ceremony_id": request.ceremony_id,
                "report_id": report.report_id,
                "record_sha256": report.content_sha256,
                "signer_id": request.signer_id,
            }),
        )?;
        let ceremony = EsignCeremony {
            ceremony_id: request.ceremony_id.clone(),
            report_id: report.report_id.clone(),
            signer_id: request.signer_id.clone(),
            reason: reason.to_string(),
            record_sha256: report.content_sha256.clone(),
            nonce,
            reauth_method: request.reauth.method,
            reauth_est: request.reauth.at_est,
            opened_est: request.now_est,
            signed_est: None,
        };

        if let Some(existing) = self.ceremony(&request.ceremony_id)? {
            let same = existing.report_id == ceremony.report_id
                && existing.signer_id == ceremony.signer_id
                && existing.reason == ceremony.reason
                && existing.record_sha256 == ceremony.record_sha256
                && existing.nonce == ceremony.nonce;
            if same {
                return Ok(existing);
            }
            return Err(ReportError::CeremonyConflict(request.ceremony_id.clone()));
        }

        self.conn
            .execute(
                "INSERT INTO esign_ceremonies (ceremony_id, report_id, signer_id, reason, \
                 record_sha256, nonce, reauth_method, reauth_est, opened_est, signed_est) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
                params![
                    ceremony.ceremony_id,
                    ceremony.report_id,
                    ceremony.signer_id,
                    ceremony.reason,
                    ceremony.record_sha256,
                    ceremony.nonce,
                    ceremony.reauth_method.as_str(),
                    ceremony.reauth_est,
                    ceremony.opened_est,
                ],
            )
            .map_err(store_error)?;
        self.append_audit(
            request.now_est,
            &ceremony.signer_id,
            "esign_ceremony_opened",
            &ceremony.ceremony_id,
            serde_json::json!({
                "report_id": ceremony.report_id,
                "reason": ceremony.reason,
                "record_sha256": ceremony.record_sha256,
                "reauth_method": ceremony.reauth_method.as_str(),
                "reauth_est": ceremony.reauth_est,
            }),
        )?;
        Ok(ceremony)
    }

    /// Sign an opened ceremony exactly once.
    pub fn sign_ceremony(
        &self,
        ceremony_id: &str,
        now_est: i64,
    ) -> Result<EsignResult, ReportError> {
        let ceremony = self
            .ceremony(ceremony_id)?
            .ok_or_else(|| ReportError::NotFound(format!("ceremony {ceremony_id}")))?;
        if ceremony.signed_est.is_some() {
            return Err(ReportError::CeremonyAlreadyUsed(ceremony_id.to_string()));
        }
        let report = self.load_report(&ceremony.report_id)?;
        if report.content_sha256 != ceremony.record_sha256 {
            return Err(ReportError::RecordChanged(format!(
                "report {} changed after the ceremony opened",
                ceremony.report_id
            )));
        }
        let payload = esign_payload(
            &ceremony.report_id,
            &ceremony.record_sha256,
            &ceremony.signer_id,
            &ceremony.ceremony_id,
            &ceremony.nonce,
            &ceremony.reason,
            now_est,
        )?;
        let signature = self.signer.sign_hex(&payload);
        let signature_id = format!("sig-{}", &ceremony.nonce[..16]);
        self.conn
            .execute(
                "INSERT INTO esign_signatures (signature_id, ceremony_id, report_id, signer_id, \
                 reason, record_sha256, nonce, signed_est, signature, signer_public_key) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    signature_id,
                    ceremony.ceremony_id,
                    ceremony.report_id,
                    ceremony.signer_id,
                    ceremony.reason,
                    ceremony.record_sha256,
                    ceremony.nonce,
                    now_est,
                    signature,
                    self.signer.public_key_hex(),
                ],
            )
            .map_err(store_error)?;
        self.conn
            .execute(
                "UPDATE esign_ceremonies SET signed_est = ?2 WHERE ceremony_id = ?1",
                params![ceremony.ceremony_id, now_est],
            )
            .map_err(store_error)?;
        self.append_audit(
            now_est,
            &ceremony.signer_id,
            "report_signed",
            &signature_id,
            serde_json::json!({
                "report_id": ceremony.report_id,
                "ceremony_id": ceremony.ceremony_id,
                "reason": ceremony.reason,
                "record_sha256": ceremony.record_sha256,
                "reauth_method": ceremony.reauth_method.as_str(),
                "reauth_est": ceremony.reauth_est,
            }),
        )?;
        Ok(EsignResult {
            signature_id,
            ceremony_id: ceremony.ceremony_id,
            report_id: ceremony.report_id,
            signer_id: ceremony.signer_id,
            reason: ceremony.reason,
            record_sha256: ceremony.record_sha256,
            nonce: ceremony.nonce,
            signed_est: now_est,
            signature,
            signer_public_key: self.signer.public_key_hex(),
        })
    }

    /// The ceremony, if it exists.
    pub fn ceremony(&self, ceremony_id: &str) -> Result<Option<EsignCeremony>, ReportError> {
        self.conn
            .query_row(
                "SELECT ceremony_id, report_id, signer_id, reason, record_sha256, nonce, \
                 reauth_method, reauth_est, opened_est, signed_est FROM esign_ceremonies \
                 WHERE ceremony_id = ?1",
                [ceremony_id],
                |row| {
                    Ok(EsignCeremony {
                        ceremony_id: row.get(0)?,
                        report_id: row.get(1)?,
                        signer_id: row.get(2)?,
                        reason: row.get(3)?,
                        record_sha256: row.get(4)?,
                        nonce: row.get(5)?,
                        reauth_method: ReauthMethod::parse(&row.get::<_, String>(6)?)
                            .unwrap_or(ReauthMethod::Password),
                        reauth_est: row.get(7)?,
                        opened_est: row.get(8)?,
                        signed_est: row.get(9)?,
                    })
                },
            )
            .optional()
            .map_err(store_error)
    }

    /// Signatures recorded for a report.
    pub fn signatures_for(&self, report_id: &str) -> Result<Vec<EsignResult>, ReportError> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT signature_id, ceremony_id, report_id, signer_id, reason, record_sha256, \
                 nonce, signed_est, signature, signer_public_key FROM esign_signatures \
                 WHERE report_id = ?1 ORDER BY signed_est, signature_id",
            )
            .map_err(store_error)?;
        let rows = statement
            .query_map([report_id], |row| {
                Ok(EsignResult {
                    signature_id: row.get(0)?,
                    ceremony_id: row.get(1)?,
                    report_id: row.get(2)?,
                    signer_id: row.get(3)?,
                    reason: row.get(4)?,
                    record_sha256: row.get(5)?,
                    nonce: row.get(6)?,
                    signed_est: row.get(7)?,
                    signature: row.get(8)?,
                    signer_public_key: row.get(9)?,
                })
            })
            .map_err(store_error)?;
        let mut signatures = Vec::new();
        for row in rows {
            signatures.push(row.map_err(store_error)?);
        }
        Ok(signatures)
    }

    /// Re-verify a stored signature against the report it names.
    pub fn verify_signature(
        &self,
        signature_id: &str,
    ) -> Result<SignatureVerification, ReportError> {
        let (report_id, signer_id, reason, record_sha256, nonce, signed_est, signature, public_key, ceremony_id): (
            String, String, String, String, String, i64, String, String, String,
        ) = self
            .conn
            .query_row(
                "SELECT report_id, signer_id, reason, record_sha256, nonce, signed_est, signature, \
                 signer_public_key, ceremony_id FROM esign_signatures WHERE signature_id = ?1",
                [signature_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .optional()
            .map_err(store_error)?
            .ok_or_else(|| ReportError::NotFound(format!("signature {signature_id}")))?;

        let mut reasons = Vec::new();
        let report = self.load_report(&report_id)?;
        // Recompute the digest from the stored report instead of trusting its
        // own `content_sha256` field, so editing the stored report is detected.
        let recomputed = content_digest(&report)?;
        let record_matches = report.content_sha256 == record_sha256 && recomputed == record_sha256;
        if !record_matches {
            reasons.push("report content digest no longer matches the signed digest".to_string());
        }
        let payload = esign_payload(
            &report_id,
            &record_sha256,
            &signer_id,
            &ceremony_id,
            &nonce,
            &reason,
            signed_est,
        )?;
        let valid = verify_payload_signature(&public_key, &payload, &signature) && record_matches;
        if !verify_payload_signature(&public_key, &payload, &signature) {
            reasons.push("signature does not verify".to_string());
        }
        Ok(SignatureVerification {
            signature_id: signature_id.to_string(),
            report_id,
            signer_id,
            valid,
            record_matches,
            reasons,
        })
    }

    // -----------------------------------------------------------------------
    // Audit
    // -----------------------------------------------------------------------

    /// Append one hash-chained audit entry.
    pub fn append_audit(
        &self,
        at_est: i64,
        actor_did: &str,
        action: &str,
        subject: &str,
        detail: serde_json::Value,
    ) -> Result<AuditEntry, ReportError> {
        let (seq, prev_hash): (u64, String) = self
            .conn
            .query_row(
                "SELECT seq, entry_hash FROM report_audit ORDER BY seq DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(store_error)?
            .map(|(seq, hash)| (seq + 1, hash))
            .unwrap_or((1, ZERO_HASH.to_string()));
        let detail_json = serde_json::to_string(&detail)
            .map_err(|error| ReportError::Store(format!("encode audit detail: {error}")))?;
        let entry_hash = audit_hash(
            seq,
            &prev_hash,
            at_est,
            actor_did,
            action,
            subject,
            &detail_json,
        )?;
        self.conn
            .execute(
                "INSERT INTO report_audit (seq, prev_hash, entry_hash, at_est, actor_did, action, \
                 subject, detail_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    seq as i64,
                    prev_hash,
                    entry_hash,
                    at_est,
                    actor_did,
                    action,
                    subject,
                    detail_json
                ],
            )
            .map_err(store_error)?;
        Ok(AuditEntry {
            seq,
            prev_hash,
            entry_hash,
            at_est,
            actor_did: actor_did.to_string(),
            action: action.to_string(),
            subject: subject.to_string(),
            detail,
        })
    }

    /// Audit entries, oldest first.
    pub fn audit_entries(&self, limit: usize) -> Result<Vec<AuditEntry>, ReportError> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT seq, prev_hash, entry_hash, at_est, actor_did, action, subject, \
                 detail_json FROM report_audit ORDER BY seq LIMIT ?1",
            )
            .map_err(store_error)?;
        let rows = statement
            .query_map([limit.clamp(1, MAX_AUDIT_READ) as i64], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })
            .map_err(store_error)?;
        let mut entries = Vec::new();
        for row in rows {
            let (seq, prev_hash, entry_hash, at_est, actor_did, action, subject, detail_json) =
                row.map_err(store_error)?;
            entries.push(AuditEntry {
                seq,
                prev_hash,
                entry_hash,
                at_est,
                actor_did,
                action,
                subject,
                detail: serde_json::from_str(&detail_json)
                    .map_err(|error| ReportError::Store(format!("decode audit detail: {error}")))?,
            });
        }
        Ok(entries)
    }

    /// Audit entries for one subject.
    pub fn audit_for_subject(&self, subject: &str) -> Result<Vec<AuditEntry>, ReportError> {
        Ok(self
            .audit_entries(MAX_AUDIT_READ)?
            .into_iter()
            .filter(|entry| entry.subject == subject)
            .collect())
    }

    /// Audit entries for one action.
    pub fn audit_for_action(&self, action: &str) -> Result<Vec<AuditEntry>, ReportError> {
        Ok(self
            .audit_entries(MAX_AUDIT_READ)?
            .into_iter()
            .filter(|entry| entry.action == action)
            .collect())
    }

    /// Audit entries that belong to one tenant's reports, exports and signatures.
    ///
    /// Audit rows carry no tenant column (the chain is gateway-wide), so the
    /// subject ids are resolved from the tenant's generations and their exports
    /// and signatures; signer enrollment, pruning and chain-verification rows are
    /// gateway-level and deliberately excluded from a tenant view.
    pub fn audit_for_tenant(
        &self,
        tenant: &str,
        limit: usize,
    ) -> Result<Vec<AuditEntry>, ReportError> {
        let mut subjects: BTreeSet<String> = BTreeSet::new();
        let mut statement = self
            .conn
            .prepare(
                "SELECT report_id FROM report_generations WHERE tenant = ?1 ORDER BY report_id",
            )
            .map_err(store_error)?;
        let rows = statement
            .query_map([tenant], |row| row.get::<_, String>(0))
            .map_err(store_error)?;
        let mut report_ids = Vec::new();
        for row in rows {
            report_ids.push(row.map_err(store_error)?);
        }
        for report_id in &report_ids {
            subjects.insert(report_id.clone());
            subjects.extend(
                self.exports_for(report_id)?
                    .into_iter()
                    .map(|export| export.export_id),
            );
            for signature in self.signatures_for(report_id)? {
                subjects.insert(signature.signature_id);
                subjects.insert(signature.ceremony_id);
            }
        }
        let mut entries: Vec<AuditEntry> = self
            .audit_entries(MAX_AUDIT_READ)?
            .into_iter()
            .filter(|entry| subjects.contains(&entry.subject))
            .collect();
        entries.truncate(limit.clamp(1, MAX_AUDIT_READ));
        Ok(entries)
    }

    /// Number of audit entries.
    pub fn audit_entry_count(&self) -> Result<usize, ReportError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM report_audit", [], |row| row.get(0))
            .map_err(store_error)?;
        Ok(count as usize)
    }

    /// Recompute the audit chain.
    pub fn verify_audit_chain(&self) -> Result<AuditVerification, ReportError> {
        let entries = self.audit_entries(MAX_AUDIT_READ)?;
        let mut reasons = Vec::new();
        let mut expected_prev = ZERO_HASH.to_string();
        let mut expected_seq = 1u64;
        for entry in &entries {
            if entry.seq != expected_seq {
                reasons.push(format!("sequence gap at {}", entry.seq));
            }
            if entry.prev_hash != expected_prev {
                reasons.push(format!("previous-hash mismatch at {}", entry.seq));
            }
            let detail_json = serde_json::to_string(&entry.detail)
                .map_err(|error| ReportError::Store(format!("encode audit detail: {error}")))?;
            let recomputed = audit_hash(
                entry.seq,
                &entry.prev_hash,
                entry.at_est,
                &entry.actor_did,
                &entry.action,
                &entry.subject,
                &detail_json,
            )?;
            if recomputed != entry.entry_hash {
                reasons.push(format!("entry-hash mismatch at {}", entry.seq));
            }
            expected_prev = entry.entry_hash.clone();
            expected_seq = entry.seq + 1;
        }
        Ok(AuditVerification {
            valid: reasons.is_empty(),
            entries: entries.len(),
            head_hash: expected_prev,
            reasons,
        })
    }

    // -----------------------------------------------------------------------
    // Retention and restore
    // -----------------------------------------------------------------------

    /// Drop export bodies older than `before_est`, keeping digests and signatures.
    pub fn prune_export_bodies(
        &self,
        before_est: i64,
        actor_did: &str,
        now_est: i64,
    ) -> Result<usize, ReportError> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT export_id, body_sha256 FROM report_exports \
                 WHERE created_est < ?1 AND body_pruned_est IS NULL ORDER BY export_id",
            )
            .map_err(store_error)?;
        let rows = statement
            .query_map([before_est], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(store_error)?;
        let mut pruned = Vec::new();
        for row in rows {
            pruned.push(row.map_err(store_error)?);
        }
        if pruned.is_empty() {
            return Ok(0);
        }
        self.conn
            .execute(
                "UPDATE report_exports SET body = X'', body_pruned_est = ?2 \
                 WHERE created_est < ?1 AND body_pruned_est IS NULL",
                params![before_est, now_est],
            )
            .map_err(store_error)?;
        self.append_audit(
            now_est,
            actor_did,
            "exports_pruned",
            "report_exports",
            serde_json::json!({
                "before_est": before_est,
                "pruned": pruned.iter().map(|(id, digest)| serde_json::json!({
                    "export_id": id,
                    "body_sha256": digest,
                })).collect::<Vec<_>>(),
                "count": pruned.len(),
            }),
        )?;
        Ok(pruned.len())
    }

    /// Write a consistent snapshot of the reporting state to `path`.
    ///
    /// Uses SQLite's `VACUUM INTO`, which copies a transactionally consistent
    /// database (WAL included) without stopping writers. `path` must not exist.
    pub fn snapshot_to(&self, path: impl AsRef<Path>) -> Result<(), ReportError> {
        let path = path.as_ref();
        let target = path
            .to_str()
            .ok_or_else(|| ReportError::Export("snapshot path is not UTF-8".to_string()))?;
        self.conn
            .execute("VACUUM INTO ?1", [target])
            .map_err(|error| ReportError::Store(format!("snapshot to {target}: {error}")))?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Export verification report
    // -----------------------------------------------------------------------

    fn gather_export_verification(
        &self,
        request: &ReportRequest,
    ) -> Result<gather::Gathered, ReportError> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT e.export_id, e.report_id, e.format, e.created_est, e.created_by, \
                 e.body_sha256, e.manifest_sha256, e.signature, e.body, e.signer_public_key \
                 FROM report_exports e JOIN report_generations g ON g.report_id = e.report_id \
                 WHERE g.tenant = ?1 AND (?2 IS NULL OR e.created_est >= ?2) \
                 AND (?3 IS NULL OR e.created_est <= ?3) \
                 ORDER BY e.created_est, e.export_id LIMIT ?4",
            )
            .map_err(store_error)?;
        let rows = statement
            .query_map(
                params![
                    request.tenant,
                    request.from_est,
                    request.to_est,
                    MAX_ROWS as i64
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                        row.get::<_, String>(9)?,
                    ))
                },
            )
            .map_err(store_error)?;

        let mut gathered = gather::Gathered {
            columns: [
                "export_id",
                "report_id",
                "format",
                "created_est",
                "created_by",
                "body_sha256",
                "body_present",
                "signature_valid",
                "verdict",
            ]
            .iter()
            .map(|column| (*column).to_string())
            .collect(),
            ..gather::Gathered::default()
        };
        let mut valid_count = 0usize;
        for row in rows {
            let (
                export_id,
                report_id,
                format,
                created_est,
                created_by,
                body_sha256,
                manifest_sha256,
                signature,
                body,
                public_key,
            ) = row.map_err(store_error)?;
            let manifest_json: Option<String> = self
                .conn
                .query_row(
                    "SELECT manifest_json FROM report_exports WHERE export_id = ?1",
                    [&export_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(store_error)?;
            let manifest_ok = manifest_json
                .as_ref()
                .map(|json| {
                    digest_bytes(CONTEXT_REPORT_MANIFEST, json.as_bytes()) == manifest_sha256
                })
                .unwrap_or(false);
            let signature_ok = manifest_json
                .as_ref()
                .map(|json| verify_payload_signature(&public_key, json.as_bytes(), &signature))
                .unwrap_or(false);
            let body_present = !body.is_empty();
            let body_ok = body_present && digest_bytes(CONTEXT_REPORT_BODY, &body) == body_sha256;
            let valid = manifest_ok && signature_ok && body_ok;
            if valid {
                valid_count += 1;
            }
            let verdict = if valid {
                "valid"
            } else if !body_present {
                "body_pruned"
            } else if !signature_ok {
                "signature_invalid"
            } else if !body_ok {
                "body_digest_mismatch"
            } else {
                "manifest_digest_mismatch"
            };
            let source_digest = digest_bytes(
                CONTEXT_SOURCE_ROW,
                format!("{export_id}\0{body_sha256}\0{manifest_sha256}").as_bytes(),
            );
            gathered.touch(Some(created_est));
            gathered.rows.push(ReportRow {
                key: export_id.clone(),
                cells: [
                    ("export_id".to_string(), export_id.clone()),
                    ("report_id".to_string(), report_id.clone()),
                    ("format".to_string(), format.clone()),
                    ("created_est".to_string(), created_est.to_string()),
                    ("created_by".to_string(), created_by.clone()),
                    ("body_sha256".to_string(), body_sha256.clone()),
                    ("body_present".to_string(), body_present.to_string()),
                    ("signature_valid".to_string(), signature_ok.to_string()),
                    ("verdict".to_string(), verdict.to_string()),
                ]
                .into_iter()
                .collect(),
                sources: vec![SourceRef {
                    kind: SourceKind::ReportExport,
                    id: export_id,
                    digest: source_digest,
                }],
            });
        }
        gathered
            .totals
            .insert("exports".to_string(), gathered.rows.len().to_string());
        gathered
            .totals
            .insert("valid".to_string(), valid_count.to_string());
        Ok(gathered)
    }
}

// Small helper so the audit chain stores ISO-free JSON keys in a stable order.
fn audit_hash(
    seq: u64,
    prev_hash: &str,
    at_est: i64,
    actor_did: &str,
    action: &str,
    subject: &str,
    detail_json: &str,
) -> Result<String, ReportError> {
    let value = serde_json::json!({
        "seq": seq,
        "prev_hash": prev_hash,
        "at_est": at_est,
        "actor_did": actor_did,
        "action": action,
        "subject": subject,
        "detail": serde_json::from_str::<serde_json::Value>(detail_json)
            .map_err(|error| ReportError::Store(format!("decode audit detail: {error}")))?,
    });
    digest_json(CONTEXT_REPORT_AUDIT, &value)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}
