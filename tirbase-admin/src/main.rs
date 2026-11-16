// SPDX-License-Identifier: AGPL-3.0-only

//! `tirbase-admin` CLI entry point ().

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
        "ledger" => {
            let sub = rest.first().cloned().unwrap_or_default();
            let subflags = parse_flags(&rest.iter().skip(1).cloned().collect::<Vec<_>>());
            match sub.as_str() {
                "verify" => {
                    let args = cmd::ledger::LedgerVerifyArgs {
                        bundle: req(&subflags, "bundle")?.into(),
                        signature: req(&subflags, "signature")?.into(),
                        trusted_keys: subflags.get("trusted-key").cloned().unwrap_or_default(),
                        attachments_dir: one(&subflags, "attachments").map(Into::into),
                        json: subflags.contains_key("json")
                            || one(&subflags, "json").as_deref() == Some("true"),
                    };
                    let report = cmd::ledger::run(&args)?;
                    let ok = cmd::ledger::print_report(&report, args.json)?;
                    if !ok {
                        std::process::exit(1);
                    }
                }
                _ => bail!("ledger requires subcommand: verify"),
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
        "backup" => {
            let report = cmd::storage::backup(&cmd::storage::BackupArgs {
                db_path: req(&flags, "db-path")?.into(),
                out_dir: req(&flags, "out-dir")?.into(),
                key_path: req(&flags, "key-path")?.into(),
            })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        "restore-backup" => {
            let report = cmd::storage::restore(&cmd::storage::RestoreArgs {
                backup_dir: req(&flags, "backup-dir")?.into(),
                target_db: req(&flags, "target-db")?.into(),
            })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        "pitr" => {
            let report = cmd::storage::pitr(&cmd::storage::PitrArgs {
                backup_dir: req(&flags, "backup-dir")?.into(),
                delta_log: req(&flags, "delta-log")?.into(),
                target_db: req(&flags, "target-db")?.into(),
                expected_root: one(&flags, "expected-root"),
            })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        "dr-drill" => {
            let report = cmd::storage::dr_drill(&cmd::storage::DrDrillArgs {
                db_path: req(&flags, "db-path")?.into(),
                work_dir: req(&flags, "work-dir")?.into(),
                key_path: req(&flags, "key-path")?.into(),
                delta_log: one(&flags, "delta-log").map(Into::into),
            })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        "retention" => {
            let report = cmd::storage::retention(&cmd::storage::RetentionArgs {
                db_path: req(&flags, "db-path")?.into(),
                key_path: req(&flags, "key-path")?.into(),
                operational_days: one(&flags, "operational-days").and_then(|s| s.parse().ok()),
                hold_class: one(&flags, "hold-class"),
                hold_subject: one(&flags, "hold-subject"),
                hold_reason: one(&flags, "hold-reason"),
                release_hold: one(&flags, "release-hold"),
            })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        "storage-budget" => {
            let usage = cmd::storage::storage_budget(&cmd::storage::StorageBudgetArgs {
                data_dir: req(&flags, "data-dir")?.into(),
                ledger_bytes: one(&flags, "ledger-bytes").and_then(|s| s.parse().ok()),
                archive_bytes: one(&flags, "archive-bytes").and_then(|s| s.parse().ok()),
            })?;
            println!("{}", serde_json::to_string_pretty(&usage)?);
        }
        "encrypt-export" => {
            let sealed = cmd::storage::encrypt_export(&cmd::storage::EncryptExportArgs {
                key_path: req(&flags, "key-path")?.into(),
                input: req(&flags, "input")?.into(),
                output: req(&flags, "output")?.into(),
                aad: one(&flags, "aad").unwrap_or_default(),
            })?;
            println!("{}", serde_json::to_string_pretty(&sealed)?);
        }
        "decrypt-export" => {
            let plaintext = cmd::storage::decrypt_export(&cmd::storage::DecryptExportArgs {
                key_path: req(&flags, "key-path")?.into(),
                input: req(&flags, "input")?.into(),
                output: req(&flags, "output")?.into(),
                aad: one(&flags, "aad").unwrap_or_default(),
            })?;
            println!("decrypted {} bytes", plaintext.len());
        }
        "webhook" => {
            let body = cmd::webhook::run(&cmd::webhook::WebhookArgs {
                db_path: req(&flags, "db-path")?.into(),
                action: one(&flags, "action").unwrap_or_else(|| "list".to_string()),
                endpoint_id: one(&flags, "endpoint-id"),
                url: one(&flags, "url"),
                secret_file: one(&flags, "secret-file").map(Into::into),
                now_est: one(&flags, "now-est")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| {
                        tirbase_core::traits::wall_hint_secs().unwrap_or(0)
                    }),
            })?;
            println!("{body}");
        }
        "vertical" => {
            let result = cmd::vertical::run(&cmd::vertical::VerticalArgs {
                db_path: req(&flags, "db-path")?.into(),
                action: one(&flags, "action").unwrap_or_else(|| "list".to_string()),
                vertical: req(&flags, "vertical")?,
                kind: req(&flags, "kind")?,
                id: one(&flags, "id"),
                parent_id: one(&flags, "parent-id"),
                tenant: one(&flags, "tenant"),
                data_json: one(&flags, "data-json"),
                limit: one(&flags, "limit").and_then(|s| s.parse().ok()),
                cursor: one(&flags, "cursor").and_then(|s| s.parse().ok()),
            })?;
            println!("{}", result.body);
        }
        "provisioning" => {
            let action = rest.first().cloned().unwrap_or_default();
            if action.is_empty() {
                bail!("provisioning requires an action: claim|payload|enroll|offline|rotate|revoke|replace|decommission|reissue|transfer|report|drift|query|audit");
            }
            let subflags = parse_flags(&rest.iter().skip(1).cloned().collect::<Vec<_>>());
            let args = cmd::provisioning::ProvisioningArgs {
                action,
                db_path: one(&subflags, "db-path").map(Into::into),
                signer_seed_hex: one(&subflags, "signer-seed-hex"),
                authority_public_key_hex: one(&subflags, "authority-public-key-hex"),
                tenant: one(&subflags, "tenant"),
                site: one(&subflags, "site"),
                device_type: one(&subflags, "device-type"),
                device_id: one(&subflags, "device-id"),
                device_public_key_hex: one(&subflags, "device-public-key-hex"),
                claim_code: one(&subflags, "claim-code"),
                credential_id: one(&subflags, "credential-id"),
                payload_file: one(&subflags, "payload-file").map(Into::into),
                firmware_version: one(&subflags, "firmware-version"),
                config_version: one(&subflags, "config-version"),
                ttl_secs: one(&subflags, "ttl-secs").and_then(|s| s.parse().ok()),
                issued_by: one(&subflags, "issued-by"),
                actor: one(&subflags, "actor"),
                state: one(&subflags, "state"),
            };
            let result = cmd::provisioning::run(&args)?;
            cmd::provisioning::print_result(&result)?;
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
    fn cli_declares_all_admin_subcommands() {
        let names: Vec<_> = tirbase_admin::cli_commands()
            .into_iter()
            .map(|c| c.name)
            .collect();
        for req in tirbase_admin::REQUIRED_SUBCOMMANDS {
            assert!(names.contains(req), "missing {req}: {names:?}");
        }
    }
}
