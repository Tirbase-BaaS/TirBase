//! `tirbase-admin` CLI entry point (task 9.1 — CLAIM-9.1, PV-3.10).
//!
//! Declares `enroll`, `mint`, `rotate`, and `inspect-identities`. The
//! production command logic lives in `cmd/`; the binary dispatches to it.

#![warn(dead_code)]

use std::collections::BTreeMap;

use anyhow::{bail, Result};
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
                ttl_secs: one(&flags, "ttl-secs").unwrap_or_else(|| "86400".to_string()).parse()?,
                device_key_path: one(&flags, "device-key-path").map(Into::into),
                nonce_hex: one(&flags, "nonce-hex"),
            })?;
            cmd::enroll::print_result(&result)?;
        }
        "mint" => {
            let token = cmd::mint::run(&cmd::mint::MintArgs {
                did: req(&flags, "did")?,
                role: req(&flags, "role")?,
                ttl_secs: one(&flags, "ttl-secs").unwrap_or_else(|| "3600".to_string()).parse()?,
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
            let records = cmd::inspect_identities::run(&cmd::inspect_identities::InspectIdentitiesArgs {
                identities,
            })?;
            cmd::inspect_identities::print_records(&records)?;
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
        eprintln!("  {:<18} {}", cmd.name, cmd.about);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn cli_declares_all_task9_subcommands() {
        let names: Vec<_> = tirbase_admin::cli_commands()
            .into_iter()
            .map(|c| c.name)
            .collect();
        for req in tirbase_admin::REQUIRED_SUBCOMMANDS {
            assert!(names.contains(req), "missing {req}: {names:?}");
        }
    }
}
