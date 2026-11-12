//! `tirbase-admin restore` (PV-9.5, RD-2, CLAIM-32.3).
//!
//! Backup/restore workflow:
//! - `quick_check` on source DB.
//! - restore primary DB files from a backup point.
//! - replay a delta/security log file produced after restore point (if provided).
//! - perform a signed enrollment-epoch bump record.
//! - enter LOCKDOWN (operator must re-attest after restore).
//!
//! Safety (S22): this command MUST NOT silently update sequence numbers or
//! anti-rollback counters. It bumps `device_epoch.enrollment_epoch` (signed
//! operator intent) and sets lockdown state; rollback detection remains active.

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tirbase_gateway::db::logical_dump;

#[derive(Debug, Clone)]
pub struct RestoreArgs {
    pub backup_db: PathBuf,
    pub target_db: PathBuf,
    pub delta_log: Option<PathBuf>,
    pub epoch_store_db: PathBuf,
    pub lockdown_db: PathBuf,
 /// Hex 32-byte Ed25519 seed for signed epoch-bump authorization.
    pub signer_seed_hex: String,
    pub output: PathBuf,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RestoreReport {
    pub quick_check_ok: bool,
    pub restored_db: String,
    pub delta_log_replayed: bool,
    pub delta_entries_applied: usize,
    pub previous_enrollment_epoch: u64,
    pub new_enrollment_epoch: u64,
    pub epoch_bump_signature_hex: String,
    pub lockdown_entered: bool,
 /// S22 invariant: sequence/anti-rollback counters are never silently reset.
    pub counters_silently_updated: bool,
    pub post_restore_logical_dump_sha256: String,
}

fn quick_check(path: &Path) -> Result<()> {
    let conn = Connection::open(path).with_context(|| format!("open {}", path.display()))?;
    let result: String = conn
        .query_row("PRAGMA quick_check;", [], |r| r.get(0))
        .context("quick_check")?;
    if result != "ok" {
        bail!("quick_check failed for {}: {result}", path.display());
    }
    Ok(())
}

fn replay_delta_log(target_db: &Path, delta_log: &Path) -> Result<usize> {
    let body = std::fs::read_to_string(delta_log)
        .with_context(|| format!("read delta log {}", delta_log.display()))?;
    let conn = Connection::open(target_db)
        .with_context(|| format!("open target {}", target_db.display()))?;
    conn.execute_batch("BEGIN IMMEDIATE;")
        .context("begin delta replay")?;
    let mut applied = 0usize;
    for line in body.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if line.starts_with('#') {
            continue;
        }
 // Delta-log replay applies opaque SQL statements captured after restore point.
 // Operators must review signed delta logs; this tool never synthesizes counters.
        conn.execute_batch(line)
            .with_context(|| format!("replay delta statement: {line}"))?;
        applied += 1;
    }
    conn.execute_batch("COMMIT;")
        .context("commit delta replay")?;
    Ok(applied)
}

fn sign_epoch_bump(
    seed_hex: &str,
    previous_epoch: u64,
    new_epoch: u64,
    target_db_sha256: &[u8; 32],
) -> Result<(String, String)> {
    let seed = hex::decode(seed_hex.trim()).context("signer_seed_hex")?;
    if seed.len() != 32 {
        bail!("signer seed must be 32 bytes");
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(&seed);
    let sk = SigningKey::from_bytes(&s);
    let vk = sk.verifying_key();
    let mut msg = Vec::new();
    msg.extend_from_slice(b"tirbase/v1/restore/epoch-bump\0");
    msg.extend_from_slice(&previous_epoch.to_le_bytes());
    msg.extend_from_slice(&new_epoch.to_le_bytes());
    msg.extend_from_slice(target_db_sha256);
    let sig = sk.sign(&msg);
    Ok((hex::encode(vk.to_bytes()), hex::encode(sig.to_bytes())))
}

fn bump_enrollment_epoch(epoch_store_db: &Path) -> Result<(u64, u64)> {
    let conn = Connection::open(epoch_store_db)
        .with_context(|| format!("open epoch store {}", epoch_store_db.display()))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS device_epoch (
            key TEXT PRIMARY KEY,
            device_epoch INTEGER NOT NULL,
            enrollment_epoch INTEGER NOT NULL
        );",
    )
    .context("ensure device_epoch table")?;
    let row: Option<(i64, i64)> = conn
        .query_row(
            "SELECT device_epoch, enrollment_epoch FROM device_epoch WHERE key='gateway'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    let (device_epoch, previous) = row.unwrap_or((0, 0));
    let new_epoch = (previous as u64).saturating_add(1);
    conn.execute(
        "INSERT INTO device_epoch(key,device_epoch,enrollment_epoch) VALUES ('gateway',?1,?2)
         ON CONFLICT(key) DO UPDATE SET enrollment_epoch=excluded.enrollment_epoch",
        params![device_epoch, new_epoch as i64],
    )
    .context("bump enrollment_epoch")?;
    Ok((previous as u64, new_epoch))
}

fn enter_lockdown(lockdown_db: &Path, reason: &str) -> Result<()> {
    let conn = Connection::open(lockdown_db)
        .with_context(|| format!("open lockdown db {}", lockdown_db.display()))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS lockdown_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            reason TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );",
    )
    .context("ensure lockdown_state table")?;
    conn.execute(
        "INSERT INTO lockdown_state(key,value,reason,updated_at) VALUES ('gateway','LOCKDOWN',?1,?2)
         ON CONFLICT(key) DO UPDATE SET value='LOCKDOWN', reason=excluded.reason, updated_at=excluded.updated_at",
        params![reason, tirbase_core::traits::wall_hint_secs().unwrap_or(0)],
    )
    .context("enter lockdown")?;
    Ok(())
}

pub fn run(args: &RestoreArgs) -> Result<RestoreReport> {
    quick_check(&args.backup_db)?;
    if let Some(parent) = args.target_db.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::copy(&args.backup_db, &args.target_db)
        .with_context(|| format!("copy backup to {}", args.target_db.display()))?;
    quick_check(&args.target_db)?;

    let (delta_log_replayed, delta_entries_applied) = if let Some(log) = &args.delta_log {
        (true, replay_delta_log(&args.target_db, log)?)
    } else {
        (false, 0usize)
    };

    let dump_conn = Connection::open(&args.target_db)
        .with_context(|| format!("open target for logical dump {}", args.target_db.display()))?;
    let dump = logical_dump::logical_dump(&dump_conn).map_err(|e| anyhow::anyhow!(e))?;
    let dump_bytes = serde_json::to_vec(&dump).context("serialize logical dump")?;
    let mut hasher = Sha256::new();
    hasher.update(&dump_bytes);
    let dump_sha: [u8; 32] = hasher.finalize().into();
    let (_signer_pk, sig) = sign_epoch_bump(
        &args.signer_seed_hex,
        0, // filled below by actual values
        0,
        &dump_sha,
    )
    .or_else(|_| sign_epoch_bump(&args.signer_seed_hex, 0, 1, &dump_sha))?;
    let (previous_enrollment_epoch, new_enrollment_epoch) =
        bump_enrollment_epoch(&args.epoch_store_db)?;
 // Re-sign with actual epoch values for the report (operator audit trail).
    let (_signer_pk, epoch_bump_signature_hex) = sign_epoch_bump(
        &args.signer_seed_hex,
        previous_enrollment_epoch,
        new_enrollment_epoch,
        &dump_sha,
    )?;
    let _ = sig;
    enter_lockdown(
        &args.lockdown_db,
        "restore completed: signed epoch bump + lockdown (S22)",
    )?;

    let report = RestoreReport {
        quick_check_ok: true,
        restored_db: args.target_db.display().to_string(),
        delta_log_replayed,
        delta_entries_applied,
        previous_enrollment_epoch,
        new_enrollment_epoch,
        epoch_bump_signature_hex,
        lockdown_entered: true,
        counters_silently_updated: false,
        post_restore_logical_dump_sha256: hex::encode(dump_sha),
    };
    let body = serde_json::to_vec_pretty(&report)?;
    if let Some(parent) = args.output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&args.output, body)?;
    Ok(report)
}
