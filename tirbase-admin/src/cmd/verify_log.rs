//! `tirbase-admin verify-log` / `tirbase-verify-log` production caller (CLAIM-27.4,
//! PV-7.5, INV-4). Exits 0 on intact chain, non-zero with gap/mismatch report per
//! broken sequence range.

use anyhow::{Context, Result};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct VerifyLogArgs {
    pub db_path: PathBuf,
    pub json: bool,
}

pub fn run(args: &VerifyLogArgs) -> Result<tirbase_gateway::security_log_export::VerifyReport> {
    tirbase_gateway::security_log_export::verify_log_at_path(&args.db_path)
        .map_err(|e| anyhow::anyhow!(e))
        .with_context(|| format!("verify security log at {}", args.db_path.display()))
}

pub fn print_report(
    report: &tirbase_gateway::security_log_export::VerifyReport,
    json: bool,
) -> Result<bool> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else if report.ok {
        println!("OK: {} ({} events checked)", report.message, report.checked);
    } else {
        println!(
            "FAILED: {} ({} events checked)",
            report.message, report.checked
        );
        for r in &report.broken_ranges {
            println!(
                "  broken range seq {}..{}: {}",
                r.start_seq, r.end_seq, r.reason
            );
        }
    }
    Ok(report.ok)
}
