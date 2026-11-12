use crate::security_log::{
    event_hash, gdpr_salted_commitment, read_personal_fields_for_seq, PersonalFieldCommitment,
    SecurityEvent,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;
use tirbase_core::events::{ReasonCode, SecurityEventCategory, Severity, TimeSourceFlag};
use tirbase_core::traits::KeyProvider;
use tirbase_types::DeviceSignature;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedLog {
    pub format_version: u32,
    pub export_timestamp_unix: i64,
    pub device_did: String,
    pub device_public_key_hex: String,
    pub pseudonymized: bool,
 /// Explicit disclaimer (CLAIM-27.2, PV-7.8): pseudonymized export is NOT chain-verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclaimer: Option<String>,
    pub events: Vec<ExportedEvent>,
    pub checkpoints: Vec<ExportedCheckpoint>,
    pub chain_report: VerifyReport,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedEvent {
    pub seq: u64,
    pub segment_id: u64,
    pub category: String,
    pub severity: String,
    pub actor_did: Option<String>,
    pub target: Option<String>,
    pub reason_code: String,
    pub best_effort_wall_time: i64,
    pub time_source_flag: String,
    pub prev_hash_hex: String,
    pub hash_hex: String,
    pub personal_commitments: Vec<ExportedPersonalCommitment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pseudonymized_personal_fields: Option<Vec<ExportedPseudonymizedField>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedPersonalCommitment {
    pub field_name: String,
    pub commitment_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedPseudonymizedField {
    pub field_name: String,
    pub pseudonym_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedCheckpoint {
    pub seq: u64,
    pub segment_id: u64,
    pub checkpoint_hash_hex: String,
    pub signature_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyReport {
    pub ok: bool,
    pub checked: usize,
    pub broken_ranges: Vec<BrokenRange>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrokenRange {
    pub start_seq: u64,
    pub end_seq: u64,
    pub reason: String,
}

fn sig_hex(sig: &DeviceSignature) -> String {
    match sig {
        DeviceSignature::Ed25519(b) => hex::encode(b),
        DeviceSignature::P256(b) => hex::encode(b),
    }
}

fn sig_from_db(blob: Vec<u8>) -> Option<DeviceSignature> {
    if blob.len() == 64 {
        let mut a = [0u8; 64];
        a.copy_from_slice(&blob);
        Some(DeviceSignature::Ed25519(a))
    } else {
        None
    }
}

pub fn sign_export(key: &dyn KeyProvider, bytes: &[u8]) -> Result<String, String> {
    let sig = key.sign(bytes).map_err(|e| format!("sign export: {e:?}"))?;
    Ok(sig_hex(&sig))
}

fn canonical_cbor_bytes<T: Serialize>(v: &T) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(v, &mut buf).map_err(|e| format!("cbor: {e}"))?;
    Ok(buf)
}

fn pseudonymize(value: &str, salt: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"tirbase-pseudonym-v1");
    h.update(salt);
    h.update(value.as_bytes());
    hex::encode(&h.finalize()[..16]) // fixed-length token (PV-7.8)
}

fn parse_cat(s: &str) -> SecurityEventCategory {
    serde_json::from_str(&format!("\"{}\"", s))
        .or_else(|_| {
            serde_json::from_str(&format!("\"{}\"", s.replace('_', "-").to_ascii_lowercase()))
        })
        .unwrap_or(SecurityEventCategory::CommandDecision)
}
fn parse_sev(s: &str) -> Severity {
    serde_json::from_str(&format!("\"{}\"", s)).unwrap_or(Severity::Low)
}
fn parse_reason(s: &str) -> ReasonCode {
    serde_json::from_str(&format!("\"{}\"", s)).unwrap_or(ReasonCode::CommandAccepted)
}
fn parse_tsf(s: &str) -> TimeSourceFlag {
    serde_json::from_str(&format!("\"{}\"", s)).unwrap_or(TimeSourceFlag::LogicalFallback)
}

fn ensure_personal_fields_table(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS security_event_personal_fields (
            seq        INTEGER NOT NULL,
            field_name TEXT    NOT NULL,
            salt       BLOB    NOT NULL,
            plaintext  BLOB    NOT NULL,
            PRIMARY KEY (seq, field_name)
        );",
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn read_chain_records(conn: &Connection) -> Result<Vec<SecurityEvent>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT seq, segment_id, category, severity, actor_did, target, reason_code,
                best_effort_wall_ts, time_source_flag, prev_hash, is_checkpoint,
                checkpoint_signature, checkpoint_hash
         FROM security_events ORDER BY seq ASC",
        )
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let rows = stmt
        .query_map([], |r| {
            let prev: Vec<u8> = r.get(9)?;
            let mut ph = [0u8; 32];
            if prev.len() == 32 {
                ph.copy_from_slice(&prev);
            }
            let sig_blob: Option<Vec<u8>> = r.get(11)?;
            let ch_blob: Option<Vec<u8>> = r.get(12)?;
            let checkpoint_hash = ch_blob.and_then(|b| {
                if b.len() == 32 {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    Some(a)
                } else {
                    None
                }
            });
            Ok(SecurityEvent {
                seq: r.get::<_, i64>(0)? as u64,
                segment_id: r.get::<_, i64>(1)? as u64,
                category: parse_cat(&r.get::<_, String>(2)?),
                severity: parse_sev(&r.get::<_, String>(3)?),
                actor_did: r.get(4)?,
                target: r.get(5)?,
                reason_code: parse_reason(&r.get::<_, String>(6)?),
                best_effort_wall_time: r.get(7)?,
                time_source_flag: parse_tsf(&r.get::<_, String>(8)?),
                prev_hash: ph,
                checkpoint_signature: sig_blob.and_then(sig_from_db),
                checkpoint_hash,
                personal_commitments: Vec::new(),
            })
        })
        .map_err(|e| e.to_string())?;
    for row in rows {
        let mut ev = row.map_err(|e| e.to_string())?;
 // Reconstruct commitments from stored plaintext+salt for verification/export (27.1).
        let pfs = read_personal_fields_for_seq(conn, ev.seq).map_err(|e| e.to_string())?;
        for (field_name, salt, plaintext_bytes) in pfs {
            let plaintext = String::from_utf8_lossy(&plaintext_bytes).to_string();
            ev.personal_commitments.push(PersonalFieldCommitment {
                field_name,
                commitment: gdpr_salted_commitment(&salt, &plaintext),
            });
        }
        out.push(ev);
    }
    Ok(out)
}

pub fn verify_log_at_path(db_path: &Path) -> Result<VerifyReport, String> {
    let conn = Connection::open(db_path).map_err(|e| format!("open {db_path:?}: {e}"))?;
    ensure_personal_fields_table(&conn)?;
    let events = read_chain_records(&conn)?;
    let mut broken = Vec::new();
    let mut expected_prev = [0u8; 32];
    let mut expected_seq: u64 = 1;
    for ev in &events {
        if ev.seq != expected_seq {
            broken.push(BrokenRange {
                start_seq: ev.seq,
                end_seq: ev.seq,
                reason: format!("sequence gap: expected {expected_seq}, got {}", ev.seq),
            });
            expected_seq = ev.seq;
        }
        if ev.prev_hash != expected_prev {
            broken.push(BrokenRange {
                start_seq: ev.seq,
                end_seq: ev.seq,
                reason: "prev_hash mismatch".into(),
            });
        }
        expected_prev = event_hash(ev, ev.checkpoint_signature.is_some());
        expected_seq = expected_seq.saturating_add(1);
    }
    let mut ranges: Vec<BrokenRange> = Vec::new();
    for b in broken {
        if let Some(last) = ranges.last_mut() {
            if b.start_seq <= last.end_seq.saturating_add(1) && b.reason == last.reason {
                last.end_seq = b.end_seq;
                continue;
            }
        }
        ranges.push(b);
    }
    Ok(VerifyReport {
        ok: ranges.is_empty(),
        checked: events.len(),
        message: if ranges.is_empty() {
            "chain intact".into()
        } else {
            format!("{} broken sequence range(s)", ranges.len())
        },
        broken_ranges: ranges,
    })
}

pub fn export_log(
    db_path: &Path,
    key: &dyn KeyProvider,
    format: &str,
    pseudonymize_fields: bool,
    pseudonym_salt: &[u8],
) -> Result<Vec<u8>, String> {
    let conn = Connection::open(db_path).map_err(|e| format!("open {db_path:?}: {e}"))?;
    ensure_personal_fields_table(&conn)?;
    let events = read_chain_records(&conn)?;
    let report = verify_log_at_path(db_path)?;
    let mut exported_events = Vec::with_capacity(events.len());
    let mut checkpoints = Vec::new();
    for ev in &events {
        let hash = event_hash(ev, ev.checkpoint_signature.is_some());
        let mut ee = ExportedEvent {
            seq: ev.seq,
            segment_id: ev.segment_id,
            category: ev.category.as_str().to_string(),
            severity: ev.severity.as_str().to_string(),
            actor_did: ev.actor_did.clone(),
            target: ev.target.clone(),
            reason_code: ev.reason_code.as_str().to_string(),
            best_effort_wall_time: ev.best_effort_wall_time,
            time_source_flag: ev.time_source_flag.as_str().to_string(),
            prev_hash_hex: hex::encode(ev.prev_hash),
            hash_hex: hex::encode(hash),
            personal_commitments: ev
                .personal_commitments
                .iter()
                .map(|c| ExportedPersonalCommitment {
                    field_name: c.field_name.clone(),
                    commitment_hex: hex::encode(c.commitment),
                })
                .collect(),
            pseudonymized_personal_fields: None,
        };
        if pseudonymize_fields {
            let pfs = read_personal_fields_for_seq(&conn, ev.seq).map_err(|e| e.to_string())?;
            ee.pseudonymized_personal_fields = Some(
                pfs.into_iter()
                    .map(|(name, _s, plain)| ExportedPseudonymizedField {
                        field_name: name,
                        pseudonym_token: pseudonymize(
                            &String::from_utf8_lossy(&plain),
                            pseudonym_salt,
                        ),
                    })
                    .collect(),
            );
            ee.actor_did = ee.actor_did.map(|d| pseudonymize(&d, pseudonym_salt));
        }
        if let Some(sig) = &ev.checkpoint_signature {
            checkpoints.push(ExportedCheckpoint {
                seq: ev.seq,
                segment_id: ev.segment_id,
                checkpoint_hash_hex: hex::encode(ev.checkpoint_hash.unwrap_or(hash)),
                signature_hex: Some(sig_hex(sig)),
            });
        }
        exported_events.push(ee);
    }
    let disclaimer = if pseudonymize_fields {
        Some("DISCLAIMER (PV-7.8): This pseudonymized export is NOT chain-verified. Pseudonymized fields/tokens replace identifying values and the exported representation does not prove hash-chain integrity over original values; use the raw signed export and tirbase-verify-log for chain verification.".into())
    } else {
        None
    };
    let mut export = ExportedLog {
        format_version: 1,
        export_timestamp_unix: tirbase_core::traits::wall_hint_secs().unwrap_or(0),
        device_did: key.did().to_string(),
        device_public_key_hex: hex::encode(key.public_key_bytes()),
        pseudonymized: pseudonymize_fields,
        disclaimer,
        events: exported_events,
        checkpoints,
        chain_report: report,
        signature_hex: String::new(),
    };
    let signable = canonical_cbor_bytes(&export)?;
    export.signature_hex = sign_export(key, &signable)?;
    match format {
        "cbor" => canonical_cbor_bytes(&export),
        _ => serde_json::to_vec_pretty(&export).map_err(|e| e.to_string()),
    }
}

pub fn export_evidence_bundle(
    db_path: &Path,
    key: &dyn KeyProvider,
    out_path: &Path,
) -> Result<(), String> {
    let raw_log = export_log(db_path, key, "json", false, &[])?;
    let report = verify_log_at_path(db_path)?;
    let device_pk = hex::encode(key.public_key_bytes());
    let device_did = key.did().to_string();
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;
    ensure_personal_fields_table(&conn)?;
    let events = read_chain_records(&conn)?;
    let checkpoints: Vec<ExportedCheckpoint> = events
        .iter()
        .filter_map(|e| {
            e.checkpoint_signature
                .as_ref()
                .map(|sig| ExportedCheckpoint {
                    seq: e.seq,
                    segment_id: e.segment_id,
                    checkpoint_hash_hex: hex::encode(
                        e.checkpoint_hash.unwrap_or(event_hash(e, true)),
                    ),
                    signature_hex: Some(sig_hex(sig)),
                })
        })
        .collect();
    let manifest = serde_json::json!({
        "format_version": 1,
        "export_timestamp_unix": tirbase_core::traits::wall_hint_secs().unwrap_or(0),
        "device_did": device_did, "device_public_key_hex": device_pk,
        "contents": ["log.json","checkpoints.json","device_public_key.txt","verify_report.json","manifest.json","signature.hex"],
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    let checkpoints_bytes = serde_json::to_vec_pretty(&checkpoints).map_err(|e| e.to_string())?;
    let report_bytes = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
    let mut bundle = Vec::new();
    for (name, data) in [
        ("manifest.json", manifest_bytes.as_slice()),
        ("log.json", raw_log.as_slice()),
        ("checkpoints.json", checkpoints_bytes.as_slice()),
        ("device_public_key.txt", device_pk.as_bytes()),
        ("verify_report.json", report_bytes.as_slice()),
    ] {
        bundle.extend_from_slice(&(name.len() as u32).to_le_bytes());
        bundle.extend_from_slice(name.as_bytes());
        bundle.extend_from_slice(&(data.len() as u64).to_le_bytes());
        bundle.extend_from_slice(data);
    }
    let sig = sign_export(key, &bundle)?;
    bundle.extend_from_slice(&(b"signature.hex".len() as u32).to_le_bytes());
    bundle.extend_from_slice(b"signature.hex");
    bundle.extend_from_slice(&(sig.len() as u64).to_le_bytes());
    bundle.extend_from_slice(sig.as_bytes());
    let mut f = std::fs::File::create(out_path).map_err(|e| e.to_string())?;
    f.write_all(&bundle).map_err(|e| e.to_string())?;
    Ok(())
}
