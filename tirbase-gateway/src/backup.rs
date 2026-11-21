// SPDX-License-Identifier: AGPL-3.0-only

//! F-07 backup, point-in-time recovery, DR drill, and encrypted ledger export.
//!
//! A backup is a consistent SQLite snapshot plus a signed manifest containing
//! the **ledger root hash** — SHA-256 over the deterministic logical dump
//! (schema-aware, wall-clock bookkeeping excluded). Restoring the snapshot must
//! reproduce exactly that root hash; otherwise the restore is refused.
//!
//! Point-in-time recovery replays a JSONL delta of `security_events` rows
//! captured after the snapshot. Replaying is idempotent (`INSERT OR IGNORE`),
//! and the resulting database is checked against the expected root hash before
//! it is reported as recovered.
//!
//! Exported ledger payloads can be sealed with ChaCha20-Poly1305 using a key
//! derived from the device `KeyProvider` (never persisted), and carry a
//! plaintext SHA-256 so integrity can be checked before decryption is trusted.

use std::io::Write;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use tirbase_core::traits::KeyProvider;

use crate::db::logical_dump;
use crate::db::sqlcipher::derive_db_key;

pub const BACKUP_FORMAT_VERSION: u32 = 1;
pub const BACKUP_LEDGER_FILE: &str = "ledger.db";
pub const BACKUP_MANIFEST_FILE: &str = "manifest.json";

/// Signed snapshot manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub format_version: u32,
    pub created_at_est: i64,
    pub source_db: String,
    pub schema_version: i64,
    pub max_security_event_seq: i64,
    /// SHA-256 over the deterministic logical dump of the snapshot.
    pub ledger_root_hash: String,
    pub signer_did: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

impl BackupManifest {
    /// Bytes covered by the signature (everything except the signature itself).
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let mut unsigned = self.clone();
        unsigned.signature_hex.clear();
        serde_json::to_vec(&unsigned).map_err(|e| format!("manifest bytes: {e}"))
    }

    pub fn verify_signature(&self) -> Result<(), String> {
        let public_key: [u8; 32] = hex::decode(&self.public_key_hex)
            .map_err(|e| format!("manifest public key hex: {e}"))?
            .try_into()
            .map_err(|_| "manifest public key is not 32 bytes".to_string())?;
        let signature: [u8; 64] = hex::decode(&self.signature_hex)
            .map_err(|e| format!("manifest signature hex: {e}"))?
            .try_into()
            .map_err(|_| "manifest signature is not 64 bytes".to_string())?;
        tirbase_core::identity::keypair::verify(
            &public_key,
            &self.signing_bytes()?,
            &tirbase_core::crdt::delta::Ed25519Signature::from_bytes(signature),
        )
        .map_err(|e| format!("backup manifest signature invalid: {e}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupReport {
    pub out_dir: String,
    pub ledger_root_hash: String,
    pub max_security_event_seq: i64,
    pub snapshot_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreReport {
    pub target_db: String,
    pub ledger_root_hash: String,
    pub matches_manifest: bool,
    pub quick_check_ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PitrReport {
    pub target_db: String,
    pub delta_records_applied: usize,
    pub ledger_root_hash: String,
    pub matches_expected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrDrillReport {
    pub backup_root_hash: String,
    pub restored_root_hash: String,
    pub live_root_hash: Option<String>,
    pub delta_records_applied: usize,
    pub passed: bool,
}

/// Deterministic root over the complete logical ledger state.
pub fn ledger_root_hash(conn: &Connection) -> Result<String, String> {
    let dump = logical_dump::logical_dump(conn)?;
    let bytes = serde_json::to_vec(&dump).map_err(|e| format!("logical dump: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(b"TirBase/v1/LedgerRoot\0");
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn quick_check(conn: &Connection) -> Result<(), String> {
    let result: String = conn
        .query_row("PRAGMA quick_check;", [], |r| r.get(0))
        .map_err(|e| format!("quick_check: {e}"))?;
    if result.trim() != "ok" {
        return Err(format!("quick_check failed: {result}"));
    }
    Ok(())
}

fn sql_path(path: &Path) -> String {
    path.display().to_string().replace('\'', "''")
}

/// Create a consistent snapshot and signed manifest under `out_dir`.
pub fn create_backup(
    db_path: &Path,
    out_dir: &Path,
    key: &dyn KeyProvider,
    now_est: i64,
) -> Result<BackupReport, String> {
    std::fs::create_dir_all(out_dir).map_err(|e| format!("backup dir: {e}"))?;
    let ledger_path = out_dir.join(BACKUP_LEDGER_FILE);
    let manifest_path = out_dir.join(BACKUP_MANIFEST_FILE);
    if ledger_path.exists() {
        std::fs::remove_file(&ledger_path).map_err(|e| format!("replace snapshot: {e}"))?;
    }

    let conn = Connection::open(db_path).map_err(|e| format!("open source db: {e}"))?;
    quick_check(&conn)?;
    conn.execute_batch(&format!("VACUUM INTO '{}';", sql_path(&ledger_path)))
        .map_err(|e| format!("snapshot: {e}"))?;
    drop(conn);

    let snapshot = Connection::open(&ledger_path).map_err(|e| format!("open snapshot: {e}"))?;
    quick_check(&snapshot)?;
    let root = ledger_root_hash(&snapshot)?;
    let schema_version: i64 = snapshot
        .query_row(
            "SELECT COALESCE(MAX(version),0) FROM schema_migrations",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let max_seq: i64 = snapshot
        .query_row(
            "SELECT COALESCE(MAX(seq),0) FROM security_events",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    drop(snapshot);

    let mut manifest = BackupManifest {
        format_version: BACKUP_FORMAT_VERSION,
        created_at_est: now_est,
        source_db: db_path.display().to_string(),
        schema_version,
        max_security_event_seq: max_seq,
        ledger_root_hash: root.clone(),
        signer_did: key.did().to_string(),
        public_key_hex: hex::encode(key.public_key_bytes()),
        signature_hex: String::new(),
    };
    let signed = key
        .sign(&manifest.signing_bytes()?)
        .map_err(|e| format!("sign manifest: {e}"))?;
    manifest.signature_hex = match signed {
        tirbase_types::DeviceSignature::Ed25519(bytes) => hex::encode(bytes),
        tirbase_types::DeviceSignature::P256(bytes) => hex::encode(bytes),
    };
    let body = serde_json::to_vec_pretty(&manifest).map_err(|e| format!("manifest json: {e}"))?;
    let mut file =
        std::fs::File::create(&manifest_path).map_err(|e| format!("create manifest: {e}"))?;
    file.write_all(&body)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("write manifest: {e}"))?;

    let snapshot_bytes = std::fs::metadata(&ledger_path)
        .map(|m| m.len())
        .unwrap_or(0);
    Ok(BackupReport {
        out_dir: out_dir.display().to_string(),
        ledger_root_hash: root,
        max_security_event_seq: max_seq,
        snapshot_bytes,
    })
}

pub fn read_manifest(out_dir: &Path) -> Result<BackupManifest, String> {
    let body = std::fs::read(out_dir.join(BACKUP_MANIFEST_FILE))
        .map_err(|e| format!("read backup manifest: {e}"))?;
    serde_json::from_slice(&body).map_err(|e| format!("parse backup manifest: {e}"))
}

/// Verify manifest signature, snapshot integrity, and root hash.
pub fn verify_backup(out_dir: &Path) -> Result<BackupManifest, String> {
    let manifest = read_manifest(out_dir)?;
    if manifest.format_version != BACKUP_FORMAT_VERSION {
        return Err(format!(
            "unsupported backup format {}",
            manifest.format_version
        ));
    }
    manifest.verify_signature()?;
    let conn = Connection::open(out_dir.join(BACKUP_LEDGER_FILE))
        .map_err(|e| format!("open snapshot: {e}"))?;
    quick_check(&conn)?;
    let actual = ledger_root_hash(&conn)?;
    if actual != manifest.ledger_root_hash {
        return Err(format!(
            "backup root hash mismatch: manifest {} actual {actual}",
            manifest.ledger_root_hash
        ));
    }
    Ok(manifest)
}

/// Restore a verified snapshot to `target_db`, verifying the reproduced root.
pub fn restore_backup(out_dir: &Path, target_db: &Path) -> Result<RestoreReport, String> {
    let manifest = verify_backup(out_dir)?;
    if let Some(parent) = target_db.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("target dir: {e}"))?;
        }
    }
    let snapshot = Connection::open(out_dir.join(BACKUP_LEDGER_FILE))
        .map_err(|e| format!("open snapshot: {e}"))?;
    let mut target = Connection::open(target_db).map_err(|e| format!("open target: {e}"))?;
    {
        let backup = rusqlite::backup::Backup::new(&snapshot, &mut target)
            .map_err(|e| format!("backup init: {e}"))?;
        backup
            .run_to_completion(128, std::time::Duration::from_millis(0), None)
            .map_err(|e| format!("restore copy: {e}"))?;
    }
    drop(target);
    let restored = Connection::open(target_db).map_err(|e| format!("reopen restored db: {e}"))?;
    quick_check(&restored)?;
    let root = ledger_root_hash(&restored)?;
    let matches = root == manifest.ledger_root_hash;
    if !matches {
        return Err(format!(
            "restore root hash mismatch: manifest {} restored {root}",
            manifest.ledger_root_hash
        ));
    }
    Ok(RestoreReport {
        target_db: target_db.display().to_string(),
        ledger_root_hash: root,
        matches_manifest: true,
        quick_check_ok: true,
    })
}

fn value_to_json(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<serde_json::Value> {
    use rusqlite::types::ValueRef;
    Ok(match row.get_ref(idx)? {
        ValueRef::Null => serde_json::Value::Null,
        ValueRef::Integer(n) => serde_json::json!(n),
        ValueRef::Real(f) => serde_json::json!(f),
        ValueRef::Text(t) => serde_json::json!(String::from_utf8_lossy(t)),
        ValueRef::Blob(b) => serde_json::json!({"blob_hex": hex::encode(b)}),
    })
}

/// Export security-event rows after `after_seq` as deterministic JSONL.
pub fn export_delta(db_path: &Path, after_seq: i64) -> Result<String, String> {
    let conn = Connection::open(db_path).map_err(|e| format!("open db: {e}"))?;
    let mut stmt = conn
        .prepare(
            "SELECT seq, segment_id, category, severity, actor_did, target, reason_code,
                    best_effort_wall_ts, time_source_flag, prev_hash, is_checkpoint,
                    checkpoint_signature, checkpoint_hash, time_evidence_json
             FROM security_events WHERE seq > ?1 ORDER BY seq ASC",
        )
        .map_err(|e| format!("delta query: {e}"))?;
    let rows = stmt
        .query_map([after_seq], |r| {
            Ok(serde_json::json!({
                "seq": r.get::<_, i64>(0)?,
                "segment_id": r.get::<_, i64>(1)?,
                "category": r.get::<_, String>(2)?,
                "severity": r.get::<_, String>(3)?,
                "actor_did": r.get::<_, Option<String>>(4)?,
                "target": r.get::<_, Option<String>>(5)?,
                "reason_code": r.get::<_, String>(6)?,
                "best_effort_wall_ts": r.get::<_, i64>(7)?,
                "time_source_flag": r.get::<_, String>(8)?,
                "prev_hash_hex": hex::encode(r.get::<_, Vec<u8>>(9)?),
                "is_checkpoint": r.get::<_, i64>(10)?,
                "checkpoint_signature": value_to_json(r, 11)?,
                "checkpoint_hash_hex": value_to_json(r, 12)?,
                "time_evidence_json": value_to_json(r, 13)?,
            }))
        })
        .map_err(|e| format!("delta rows: {e}"))?;
    let mut body = String::new();
    for row in rows {
        let row = row.map_err(|e| format!("delta row: {e}"))?;
        body.push_str(&row.to_string());
        body.push('\n');
    }
    Ok(body)
}

fn json_blob(value: &serde_json::Value) -> Option<Vec<u8>> {
    value
        .get("blob_hex")
        .and_then(|v| v.as_str())
        .and_then(|h| hex::decode(h).ok())
}

/// Apply a security-event delta idempotently. Returns rows inserted.
pub fn apply_delta(target_db: &Path, delta_jsonl: &str) -> Result<usize, String> {
    let mut conn = Connection::open(target_db).map_err(|e| format!("open target: {e}"))?;
    let tx = conn
        .transaction()
        .map_err(|e| format!("begin delta replay: {e}"))?;
    let mut applied = 0usize;
    for line in delta_jsonl.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let row: serde_json::Value =
            serde_json::from_str(line).map_err(|e| format!("delta line: {e}"))?;
        let prev_hash = row
            .get("prev_hash_hex")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .unwrap_or_default();
        let sig = row.get("checkpoint_signature").and_then(json_blob);
        let checkpoint_hash = row.get("checkpoint_hash_hex").and_then(json_blob);
        let evidence = row
            .get("time_evidence_json")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        applied += tx
            .execute(
                "INSERT OR IGNORE INTO security_events(
                    seq,segment_id,category,severity,actor_did,target,reason_code,
                    best_effort_wall_ts,time_source_flag,prev_hash,is_checkpoint,
                    checkpoint_signature,checkpoint_hash,time_evidence_json
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                params![
                    row.get("seq").and_then(|v| v.as_i64()).unwrap_or(0),
                    row.get("segment_id").and_then(|v| v.as_i64()).unwrap_or(1),
                    row.get("category")
                        .and_then(|v| v.as_str())
                        .unwrap_or("SecurityLog"),
                    row.get("severity")
                        .and_then(|v| v.as_str())
                        .unwrap_or("LOW"),
                    row.get("actor_did").and_then(|v| v.as_str()),
                    row.get("target").and_then(|v| v.as_str()),
                    row.get("reason_code")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown"),
                    row.get("best_effort_wall_ts")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0),
                    row.get("time_source_flag")
                        .and_then(|v| v.as_str())
                        .unwrap_or("LogicalFallback"),
                    prev_hash,
                    row.get("is_checkpoint")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0),
                    sig,
                    checkpoint_hash,
                    evidence,
                ],
            )
            .map_err(|e| format!("apply delta row: {e}"))?;
    }
    tx.commit().map_err(|e| format!("commit delta: {e}"))?;
    Ok(applied)
}

/// Restore a snapshot then replay a delta. `expected_root` (the live root hash)
/// makes the operation fail closed when recovery is incomplete.
pub fn pitr_restore(
    backup_dir: &Path,
    delta_jsonl: &str,
    target_db: &Path,
    expected_root: Option<&str>,
) -> Result<PitrReport, String> {
    restore_backup(backup_dir, target_db)?;
    let applied = apply_delta(target_db, delta_jsonl)?;
    let conn = Connection::open(target_db).map_err(|e| format!("open restored: {e}"))?;
    quick_check(&conn)?;
    let root = ledger_root_hash(&conn)?;
    let matches = expected_root.map(|e| e == root).unwrap_or(true);
    if !matches {
        return Err(format!(
            "PITR root hash mismatch: expected {} actual {root}",
            expected_root.unwrap_or_default()
        ));
    }
    Ok(PitrReport {
        target_db: target_db.display().to_string(),
        delta_records_applied: applied,
        ledger_root_hash: root,
        matches_expected: matches,
    })
}

/// Backup → verify → restore drill. `delta_jsonl` may be empty for a plain
/// backup/restore drill; `live_db` supplies the expected post-delta root.
pub fn dr_drill(
    live_db: &Path,
    work_dir: &Path,
    key: &dyn KeyProvider,
    now_est: i64,
    delta_jsonl: &str,
) -> Result<DrDrillReport, String> {
    std::fs::create_dir_all(work_dir).map_err(|e| format!("dr work dir: {e}"))?;
    let backup_dir = work_dir.join("backup");
    let backup = create_backup(live_db, &backup_dir, key, now_est)?;
    verify_backup(&backup_dir)?;
    let target = work_dir.join("restored.db");
    let pitr = pitr_restore(&backup_dir, delta_jsonl, &target, None)?;
    let live_conn = Connection::open(live_db).map_err(|e| format!("open live: {e}"))?;
    let live_root = ledger_root_hash(&live_conn)?;
    let passed = delta_jsonl.is_empty() || pitr.ledger_root_hash == live_root;
    Ok(DrDrillReport {
        backup_root_hash: backup.ledger_root_hash,
        restored_root_hash: pitr.ledger_root_hash,
        live_root_hash: Some(live_root),
        delta_records_applied: pitr.delta_records_applied,
        passed,
    })
}

// ── Encrypted exported records ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedExport {
    pub format_version: u32,
    pub key_did: String,
    pub nonce_hex: String,
    /// ChaCha20-Poly1305 ciphertext (includes the 16-byte authentication tag).
    pub ciphertext_hex: String,
    /// SHA-256 of the plaintext, checked after successful decryption.
    pub plaintext_sha256: String,
}

pub const EXPORT_ENCRYPTION_CONTEXT: &[u8] = b"TirBase/v1/EncryptedLedgerExport";

/// Seal exported ledger bytes. The key is derived from the device provider and
/// is never persisted; `aad` binds the export to its manifest/range.
pub fn encrypt_export_records(
    key: &dyn KeyProvider,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedExport, String> {
    let derived = derive_db_key(key, "export-records").map_err(|e| e.to_string())?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(derived.as_ref()));
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("export nonce: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut bound = EXPORT_ENCRYPTION_CONTEXT.to_vec();
    bound.extend_from_slice(aad);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &bound,
            },
        )
        .map_err(|_| "export encryption failed".to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(plaintext);
    Ok(EncryptedExport {
        format_version: 1,
        key_did: key.did().to_string(),
        nonce_hex: hex::encode(nonce_bytes),
        ciphertext_hex: hex::encode(ciphertext),
        plaintext_sha256: hex::encode(hasher.finalize()),
    })
}

/// Open a sealed export, verifying the AEAD tag and plaintext hash.
pub fn decrypt_export_records(
    key: &dyn KeyProvider,
    sealed: &EncryptedExport,
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if sealed.format_version != 1 {
        return Err(format!(
            "unsupported encrypted export format {}",
            sealed.format_version
        ));
    }
    if sealed.key_did != key.did() {
        return Err("encrypted export was sealed by a different device key".to_string());
    }
    let derived = derive_db_key(key, "export-records").map_err(|e| e.to_string())?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(derived.as_ref()));
    let nonce_bytes: [u8; 12] = hex::decode(&sealed.nonce_hex)
        .map_err(|e| format!("nonce hex: {e}"))?
        .try_into()
        .map_err(|_| "nonce is not 12 bytes".to_string())?;
    let ciphertext =
        hex::decode(&sealed.ciphertext_hex).map_err(|e| format!("ciphertext hex: {e}"))?;
    let mut bound = EXPORT_ENCRYPTION_CONTEXT.to_vec();
    bound.extend_from_slice(aad);
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &ciphertext,
                aad: &bound,
            },
        )
        .map_err(|_| "encrypted export authentication failed".to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(&plaintext);
    if hex::encode(hasher.finalize()) != sealed.plaintext_sha256 {
        return Err("encrypted export plaintext hash mismatch".to_string());
    }
    Ok(plaintext)
}

/// Archive a ledger export without breaking the chain: the export is a
/// byte-for-byte signed artefact plus its sealing envelope. No audit rows are
/// removed here; retention is the only path that deletes, and it archives
/// closed segments first.
pub fn write_encrypted_export(
    key: &dyn KeyProvider,
    plaintext: &[u8],
    aad: &[u8],
    out: &Path,
) -> Result<EncryptedExport, String> {
    let sealed = encrypt_export_records(key, plaintext, aad)?;
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("export dir: {e}"))?;
        }
    }
    let body = serde_json::to_vec_pretty(&sealed).map_err(|e| format!("sealed json: {e}"))?;
    let mut file = std::fs::File::create(out).map_err(|e| format!("create export: {e}"))?;
    file.write_all(&body)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("write export: {e}"))?;
    Ok(sealed)
}

/// Read and open a sealed export file.
pub fn read_encrypted_export(
    key: &dyn KeyProvider,
    path: &Path,
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let body = std::fs::read(path).map_err(|e| format!("read sealed export: {e}"))?;
    let sealed: EncryptedExport =
        serde_json::from_slice(&body).map_err(|e| format!("parse sealed export: {e}"))?;
    decrypt_export_records(key, &sealed, aad)
}

/// Convenience for the admin CLI: resolve a backup/target pair without touching
/// the filesystem beyond path joins.
pub fn default_target(work_dir: &Path) -> PathBuf {
    work_dir.join("restored.db")
}
