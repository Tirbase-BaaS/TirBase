// SPDX-License-Identifier: AGPL-3.0-only

//! F-07 operator commands: backup, restore, PITR, DR drill, retention and
//! storage budgets. All state transitions are delegated to the gateway crate;
//! this module only parses arguments, opens keys, and prints reports.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tirbase_core::identity::file_key_provider::FileKeyProvider;
use tirbase_gateway::backup as gw_backup;
use tirbase_gateway::db::migrations;
use tirbase_gateway::retention::{self, RecordClass, RetentionConfig};
use tirbase_gateway::security_log::SecurityEventLog;
use tirbase_gateway::storage_budget::{self, StorageBudget};

fn load_key(path: &std::path::Path) -> Result<FileKeyProvider> {
    FileKeyProvider::load(path).with_context(|| format!("load device key {}", path.display()))
}

#[derive(Debug, Clone)]
pub struct BackupArgs {
    pub db_path: PathBuf,
    pub out_dir: PathBuf,
    pub key_path: PathBuf,
}

pub fn backup(args: &BackupArgs) -> Result<gw_backup::BackupReport> {
    let key = load_key(&args.key_path)?;
    gw_backup::create_backup(
        &args.db_path,
        &args.out_dir,
        &key,
        tirbase_core::traits::wall_hint_secs().unwrap_or(0),
    )
    .map_err(|e| anyhow::anyhow!(e))
}

#[derive(Debug, Clone)]
pub struct RestoreArgs {
    pub backup_dir: PathBuf,
    pub target_db: PathBuf,
}

pub fn restore(args: &RestoreArgs) -> Result<gw_backup::RestoreReport> {
    gw_backup::restore_backup(&args.backup_dir, &args.target_db).map_err(|e| anyhow::anyhow!(e))
}

#[derive(Debug, Clone)]
pub struct PitrArgs {
    pub backup_dir: PathBuf,
    pub delta_log: PathBuf,
    pub target_db: PathBuf,
    /// Live root hash the recovered database must reproduce.
    pub expected_root: Option<String>,
}

pub fn pitr(args: &PitrArgs) -> Result<gw_backup::PitrReport> {
    let delta = std::fs::read_to_string(&args.delta_log)
        .with_context(|| format!("read delta {}", args.delta_log.display()))?;
    gw_backup::pitr_restore(
        &args.backup_dir,
        &delta,
        &args.target_db,
        args.expected_root.as_deref(),
    )
    .map_err(|e| anyhow::anyhow!(e))
}

#[derive(Debug, Clone)]
pub struct DrDrillArgs {
    pub db_path: PathBuf,
    pub work_dir: PathBuf,
    pub key_path: PathBuf,
    pub delta_log: Option<PathBuf>,
}

pub fn dr_drill(args: &DrDrillArgs) -> Result<gw_backup::DrDrillReport> {
    let key = load_key(&args.key_path)?;
    let delta = match &args.delta_log {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("read delta {}", path.display()))?,
        None => String::new(),
    };
    gw_backup::dr_drill(
        &args.db_path,
        &args.work_dir,
        &key,
        tirbase_core::traits::wall_hint_secs().unwrap_or(0),
        &delta,
    )
    .map_err(|e| anyhow::anyhow!(e))
}

#[derive(Debug, Clone)]
pub struct RetentionArgs {
    pub db_path: PathBuf,
    pub key_path: PathBuf,
    pub operational_days: Option<i64>,
    pub hold_class: Option<String>,
    pub hold_subject: Option<String>,
    pub hold_reason: Option<String>,
    pub release_hold: Option<String>,
}

pub fn retention(args: &RetentionArgs) -> Result<retention::RetentionReport> {
    let conn = migrations::open_primary(&args.db_path).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    retention::ensure_schema(&conn).map_err(|e| anyhow::anyhow!(e))?;
    let now_est = tirbase_core::traits::wall_hint_secs().unwrap_or(0);
    if let Some(h) = &args.release_hold {
        retention::release_legal_hold(&conn, h, now_est).map_err(|e| anyhow::anyhow!(e))?;
    }
    if let Some(class) = &args.hold_class {
        let class = RecordClass::parse(class)
            .ok_or_else(|| anyhow::anyhow!("unknown record class {class}"))?;
        let hold_id = format!("hold-{now_est}-{}", class.as_str());
        retention::add_legal_hold(
            &conn,
            &hold_id,
            class,
            args.hold_subject.as_deref(),
            args.hold_reason.as_deref().unwrap_or("operator legal hold"),
            now_est,
        )
        .map_err(|e| anyhow::anyhow!(e))?;
    }

    let mut cfg = RetentionConfig::default();
    if let Some(days) = args.operational_days {
        if let Some(p) = cfg
            .policies
            .iter_mut()
            .find(|p| p.class == RecordClass::Operational)
        {
            p.max_age_secs = Some(days.saturating_mul(24 * 60 * 60));
        }
    }
    let key = load_key(&args.key_path)?;
    let log = SecurityEventLog::new_persistent(&args.db_path, Some(Arc::new(key)), false);
    retention::apply_retention(
        &conn,
        &log,
        &cfg,
        now_est,
        tirbase_core::traits::monotonic_now() / 1_000_000,
    )
    .map_err(|e| anyhow::anyhow!(e))
}

#[derive(Debug, Clone)]
pub struct StorageBudgetArgs {
    pub data_dir: PathBuf,
    pub ledger_bytes: Option<u64>,
    pub archive_bytes: Option<u64>,
}

pub fn storage_budget(args: &StorageBudgetArgs) -> Result<storage_budget::StorageUsage> {
    let mut budget = StorageBudget::default();
    if let Some(v) = args.ledger_bytes {
        budget.ledgers_bytes = v;
    }
    if let Some(v) = args.archive_bytes {
        budget.archive_bytes = v;
    }
    Ok(storage_budget::evaluate_default(&args.data_dir, budget))
}

#[derive(Debug, Clone)]
pub struct EncryptExportArgs {
    pub key_path: PathBuf,
    pub input: PathBuf,
    pub output: PathBuf,
    pub aad: String,
}

pub fn encrypt_export(args: &EncryptExportArgs) -> Result<gw_backup::EncryptedExport> {
    let key = load_key(&args.key_path)?;
    let plaintext =
        std::fs::read(&args.input).with_context(|| format!("read {}", args.input.display()))?;
    gw_backup::write_encrypted_export(&key, &plaintext, args.aad.as_bytes(), &args.output)
        .map_err(|e| anyhow::anyhow!(e))
}

#[derive(Debug, Clone)]
pub struct DecryptExportArgs {
    pub key_path: PathBuf,
    pub input: PathBuf,
    pub output: PathBuf,
    pub aad: String,
}

pub fn decrypt_export(args: &DecryptExportArgs) -> Result<Vec<u8>> {
    let key = load_key(&args.key_path)?;
    let plaintext = gw_backup::read_encrypted_export(&key, &args.input, args.aad.as_bytes())
        .map_err(|e| anyhow::anyhow!(e))?;
    std::fs::write(&args.output, &plaintext)
        .with_context(|| format!("write {}", args.output.display()))?;
    Ok(plaintext)
}
