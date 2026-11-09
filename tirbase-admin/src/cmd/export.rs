//! `tirbase-admin export-log` / `export-evidence-bundle` production callers
//! (CLAIM-27.2, CLAIM-27.3, PV-7.7, PV-7.8, PV-7.10).

use anyhow::{Context, Result};
use std::path::PathBuf;
use tirbase_core::identity::file_key_provider::FileKeyProvider;

#[derive(Debug, Clone)]
pub struct ExportLogArgs {
    pub db_path: PathBuf,
    pub key_path: PathBuf,
    pub output: PathBuf,
    pub format: String, // json|cbor
    pub pseudonymized: bool,
    pub pseudonym_salt_hex: Option<String>,
}

pub fn run_export_log(args: &ExportLogArgs) -> Result<()> {
    let key = FileKeyProvider::load(&args.key_path)
        .with_context(|| format!("load device key {}", args.key_path.display()))?;
    let salt = match &args.pseudonym_salt_hex {
        Some(h) => hex::decode(h).context("decode --pseudonym-salt-hex")?,
        None => b"tirbase-export-pseudonym-salt-v1".to_vec(),
    };
    let bytes = tirbase_gateway::security_log_export::export_log(
        &args.db_path,
        &key,
        &args.format,
        args.pseudonymized,
        &salt,
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    if let Some(parent) = args.output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&args.output, bytes)
        .with_context(|| format!("write export {}", args.output.display()))?;
    println!("{}", args.output.display());
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ExportEvidenceBundleArgs {
    pub db_path: PathBuf,
    pub key_path: PathBuf,
    pub output: PathBuf,
}

pub fn run_export_evidence_bundle(args: &ExportEvidenceBundleArgs) -> Result<()> {
    let key = FileKeyProvider::load(&args.key_path)
        .with_context(|| format!("load device key {}", args.key_path.display()))?;
    if let Some(parent) = args.output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    tirbase_gateway::security_log_export::export_evidence_bundle(&args.db_path, &key, &args.output)
        .map_err(|e| anyhow::anyhow!(e))?;
    println!("{}", args.output.display());
    Ok(())
}
