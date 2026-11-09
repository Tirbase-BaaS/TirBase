//! `tirbase-verify-log` CLI (CLAIM-27.4, PV-7.5, INV-4).
//! Exit 0 on intact chain, non-zero with gap/mismatch report per broken sequence range.
use anyhow::Result;
use tirbase_admin::cmd::verify_log;

fn main() -> Result<()> {
    let mut db_path = None;
    let mut json = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--db-path" => db_path = args.next(),
            "--json" => json = true,
            "-h" | "--help" => {
                eprintln!("Usage: tirbase-verify-log --db-path <primary.db> [--json]");
                return Ok(());
            }
            other if db_path.is_none() && !other.starts_with('-') => {
                db_path = Some(other.to_string())
            }
            _ => {}
        }
    }
    let db_path = db_path.ok_or_else(|| anyhow::anyhow!("--db-path required"))?;
    let report = verify_log::run(&verify_log::VerifyLogArgs {
        db_path: db_path.into(),
        json,
    })?;
    let ok = verify_log::print_report(&report, json)?;
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}
