//! `tirbase-admin` CLI entry point (tasks 9, 27).

#![warn(dead_code)]

use anyhow::{bail, Result};
use std::collections::BTreeMap;
use tirbase_admin::{cli_commands, cmd};

fn parse_flags(args: &[String]) -> BTreeMap<String, Vec<String>> {
    let mut flags: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(key) = arg.strip_prefix("--") {
            let value = args.get(i + 1).cloned().unwrap_or_default();
            flags.entry(key.to_string()).or_default().push(value);
            i += 2;
        } else {
            i += 1;
        }
    }
    flags
}
fn one(flags: &BTreeMap<String, Vec<String>>, key: &str) -> Option<String> {
    flags.get(key).and_then(|v| v.last()).cloned()
}
fn req(flags: &BTreeMap<String, Vec<String>>, key: &str) -> Result<String> {
    one(flags, key).ok_or_else(|| anyhow::anyhow!("missing required --{key}"))
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(subcmd) = args.next() else {
        print_usage();
        bail!("subcommand required");
    };
    let rest: Vec<String> = args.collect();
    let flags = parse_flags(&rest);

    match subcmd.as_str() {
        "enroll" => {
            let result = cmd::enroll::run(&cmd::enroll::EnrollArgs {
                root_ca_seed_hex: req(&flags, "root-ca-seed-hex")?,
                role: one(&flags, "role").unwrap_or_else(|| "CommandIssuer".to_string()),
                ttl_secs: one(&flags, "ttl-secs")
                    .unwrap_or_else(|| "86400".to_string())
                    .parse()?,
                device_key_path: one(&flags, "device-key-path").map(Into::into),
                nonce_hex: one(&flags, "nonce-hex"),
            })?;
            cmd::enroll::print_result(&result)?;
        }
        "mint" => {
            let token = cmd::mint::run(&cmd::mint::MintArgs {
                did: req(&flags, "did")?,
                role: req(&flags, "role")?,
                ttl_secs: one(&flags, "ttl-secs")
                    .unwrap_or_else(|| "3600".to_string())
                    .parse()?,
                root_ca_seed_hex: req(&flags, "root-ca-seed-hex")?,
            })?;
            cmd::mint::print_token(&token)?;
        }
        "rotate" => {
            let result = cmd::rotate::run(&cmd::rotate::RotateArgs {
                key_path: req(&flags, "key-path")?.into(),
                backup_path: one(&flags, "backup-path").map(Into::into),
            })?;
            cmd::rotate::print_result(&result)?;
        }
        "inspect-identities" => {
            let identities = flags
                .get("identity")
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>();
            if identities.is_empty() {
                bail!("inspect-identities requires at least one --identity PATH");
            }
            let records =
                cmd::inspect_identities::run(&cmd::inspect_identities::InspectIdentitiesArgs {
                    identities,
                })?;
            cmd::inspect_identities::print_records(&records)?;
        }
        "export-log" => {
            cmd::export::run_export_log(&cmd::export::ExportLogArgs {
                db_path: req(&flags, "db-path")?.into(),
                key_path: req(&flags, "key-path")?.into(),
                output: req(&flags, "output")?.into(),
                format: one(&flags, "format").unwrap_or_else(|| "json".to_string()),
                pseudonymized: flags.contains_key("pseudonymized")
                    || one(&flags, "pseudonymized").as_deref() == Some("true"),
                pseudonym_salt_hex: one(&flags, "pseudonym-salt-hex"),
            })?;
        }
        "export-evidence-bundle" => {
            cmd::export::run_export_evidence_bundle(&cmd::export::ExportEvidenceBundleArgs {
                db_path: req(&flags, "db-path")?.into(),
                key_path: req(&flags, "key-path")?.into(),
                output: req(&flags, "output")?.into(),
            })?;
        }
        "verify-log" | "tirbase-verify-log" => {
            let report = cmd::verify_log::run(&cmd::verify_log::VerifyLogArgs {
                db_path: req(&flags, "db-path")?.into(),
                json: flags.contains_key("json") || one(&flags, "json").as_deref() == Some("true"),
            })?;
            let ok = cmd::verify_log::print_report(&report, flags.contains_key("json"))?;
            if !ok {
                std::process::exit(1);
            }
        }
        "rollout" => {
            let sub = rest.first().cloned().unwrap_or_default();
            let subflags = parse_flags(&rest.iter().skip(1).cloned().collect::<Vec<_>>());
            match sub.as_str() {
                "status" => {
                    let rollout_id = req(&subflags, "rollout-id")?;
                    let device_ids = subflags.get("device-id").cloned().unwrap_or_default();
                    let rows = cmd::rollout::run_status(&cmd::rollout::RolloutStatusArgs {
                        rollout_id,
                        state_path: one(&subflags, "state-path").map(Into::into),
                        device_ids,
                    })?;
                    println!("{}", serde_json::to_string_pretty(&rows)?);
                }
                "signed-rollback" => {
                    let cmdr =
                        cmd::rollout::run_signed_rollback(&cmd::rollout::SignedRollbackArgs {
                            rollout_id: req(&subflags, "rollout-id")?,
                            target_migration_id_hex: req(&subflags, "target-migration-id-hex")?,
                            signer_seed_hex: req(&subflags, "signer-seed-hex")?,
                            output: req(&subflags, "output")?.into(),
                        })?;
                    println!("{}", serde_json::to_string_pretty(&cmdr)?);
                }
                _ => bail!("rollout requires subcommand: status|signed-rollback"),
            }
        }
        "restore" => {
            let report = cmd::restore::run(&cmd::restore::RestoreArgs {
                backup_db: req(&flags, "backup-db")?.into(),
                target_db: req(&flags, "target-db")?.into(),
                delta_log: one(&flags, "delta-log").map(Into::into),
                epoch_store_db: req(&flags, "epoch-store-db")?.into(),
                lockdown_db: req(&flags, "lockdown-db")?.into(),
                signer_seed_hex: req(&flags, "signer-seed-hex")?,
                output: req(&flags, "output")?.into(),
            })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        "flash-wear-estimate" => {
            let data_path = one(&flags, "data-path")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/tirbase/primary.db"));
            let budget: u64 = one(&flags, "budget-bytes-per-day")
                .and_then(|s| s.parse().ok())
                .unwrap_or(tirbase_gateway::flash_budget::DEFAULT_FLASH_BUDGET_BYTES_PER_DAY);
            let est = tirbase_gateway::flash_budget::estimate_for_data_path(&data_path, budget);
            println!("{}", serde_json::to_string_pretty(&est)?);
        }
        "help" | "--help" | "-h" => print_usage(),
        other => {
            print_usage();
            bail!("unknown subcommand: {other}");
        }
    }
    Ok(())
}

fn print_usage() {
    eprintln!("tirbase-admin subcommands:");
    for cmd in cli_commands() {
        eprintln!("  {:<22} {}", cmd.name, cmd.about);
    }
    eprintln!("\nAliases: tirbase-verify-log (same as verify-log)");
}

#[cfg(test)]
mod tests {
    #[test]
    fn cli_declares_all_task9_and_27_subcommands() {
        let names: Vec<_> = tirbase_admin::cli_commands()
            .into_iter()
            .map(|c| c.name)
            .collect();
        for req in tirbase_admin::REQUIRED_SUBCOMMANDS {
            assert!(names.contains(req), "missing {req}: {names:?}");
        }
    }
}
