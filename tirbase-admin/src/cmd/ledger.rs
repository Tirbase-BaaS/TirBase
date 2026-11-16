// SPDX-License-Identifier: AGPL-3.0-only

//! `tirbase-admin ledger verify` — offline verification of a signed lineage
//! ledger bundle (CC-14).
//!
//! The command reads two files (`bundle.json`, `bundle.sig`) and, when the
//! manifest names attachments, an attachment directory. It never opens a
//! database, contacts a gateway or performs any network I/O, so it verifies a
//! bundle on a machine that has never been online. Exit status is 0 only when
//! every check passes; failures print a typed reason per violation.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use tirbase_gateway::lineage_ledger::export::{
    verify_bundle_hex, BundleReport, BundleViolationKind, LedgerBundle,
};

#[derive(Debug, Clone)]
pub struct LedgerVerifyArgs {
    /// Path to `bundle.json`.
    pub bundle: PathBuf,
    /// Path to the detached signature file (`bundle.sig`, hex).
    pub signature: PathBuf,
    /// Trusted signer keys, each `did=hexpublickey`.
    pub trusted_keys: Vec<String>,
    /// Directory holding the attachments the manifest names.
    pub attachments_dir: Option<PathBuf>,
    /// Print the report as JSON.
    pub json: bool,
}

/// Parse `did=hex` pairs into a trusted-key map.
pub fn parse_trusted_keys(entries: &[String]) -> Result<BTreeMap<String, Vec<u8>>> {
    if entries.is_empty() {
        bail!("at least one --trusted-key <did>=<hex-public-key> is required");
    }
    let mut keys = BTreeMap::new();
    for entry in entries {
        let (did, hex_key) = entry
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("trusted key '{entry}' must be <did>=<hex>"))?;
        if did.trim().is_empty() || hex_key.trim().is_empty() {
            bail!("trusted key '{entry}' must be <did>=<hex>");
        }
        let bytes = hex::decode(hex_key.trim())
            .with_context(|| format!("trusted key for {did} is not hex"))?;
        if bytes.len() != 32 {
            bail!(
                "trusted key for {did} must be 32 bytes (Ed25519), found {}",
                bytes.len()
            );
        }
        keys.insert(did.trim().to_string(), bytes);
    }
    Ok(keys)
}

/// Read `dir/attachments/<name>` for every attachment the bundle names.
fn read_attachments(bundle: &LedgerBundle, dir: Option<&PathBuf>) -> BTreeMap<String, Vec<u8>> {
    let mut attachments = BTreeMap::new();
    let Some(dir) = dir else {
        return attachments;
    };
    for reference in &bundle.manifest.attachments {
        let path = dir.join(&reference.name);
        if let Ok(bytes) = std::fs::read(&path) {
            attachments.insert(reference.name.clone(), bytes);
        }
    }
    attachments
}

/// Verify a bundle file offline.
pub fn run(args: &LedgerVerifyArgs) -> Result<BundleReport> {
    let json = std::fs::read_to_string(&args.bundle)
        .with_context(|| format!("read bundle {}", args.bundle.display()))?;
    let bundle: LedgerBundle = serde_json::from_str(&json)
        .with_context(|| format!("parse bundle {}", args.bundle.display()))?;
    let signature = std::fs::read_to_string(&args.signature)
        .with_context(|| format!("read signature {}", args.signature.display()))?;
    let trusted = parse_trusted_keys(&args.trusted_keys)?;
    let attachments = read_attachments(&bundle, args.attachments_dir.as_ref());
    Ok(verify_bundle_hex(
        &bundle,
        signature.trim(),
        &trusted,
        &attachments,
    ))
}

/// Print a report. Returns `true` when the bundle verified.
pub fn print_report(report: &BundleReport, json: bool) -> Result<bool> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else if report.ok {
        println!("OK: {}", report.message);
        if let Some((start, end)) = report.range {
            println!("  range: {start}..={end}");
        }
        println!(
            "  checks: signature={} chain={} root_hash={} checkpoints={} attachments={}",
            report.signature_ok,
            report.chain_ok,
            report.root_hash_ok,
            report.checkpoints_ok,
            report.attachments_ok
        );
    } else {
        println!("FAILED: {}", report.message);
        if let Some((start, end)) = report.range {
            println!("  range: {start}..={end}");
        }
        for violation in &report.violations {
            println!("  {}: {}", violation.kind.as_str(), violation.detail);
        }
        for kind in [
            BundleViolationKind::SignatureInvalid,
            BundleViolationKind::UntrustedSigner,
            BundleViolationKind::EntryHashMismatch,
            BundleViolationKind::Truncation,
        ] {
            if report
                .violations
                .iter()
                .any(|violation| violation.kind == kind)
            {
                println!("  remedy: {}", remedy(kind));
            }
        }
    }
    Ok(report.ok)
}

fn remedy(kind: BundleViolationKind) -> &'static str {
    match kind {
        BundleViolationKind::SignatureInvalid => {
            "re-download the bundle; if it persists the file was altered in transit"
        }
        BundleViolationKind::UntrustedSigner => {
            "supply the auditor-approved key with --trusted-key <did>=<hex>"
        }
        BundleViolationKind::EntryHashMismatch => {
            "the ledger content does not match its hash; treat the export as tampered"
        }
        BundleViolationKind::Truncation => {
            "the bundle is shorter than its own checkpoints; request the missing range"
        }
        _ => "inspect the bundle against the gateway ledger",
    }
}
