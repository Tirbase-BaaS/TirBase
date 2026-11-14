// SPDX-License-Identifier: AGPL-3.0-only

//! `tirbase-admin` library surface ().

pub mod cmd;

pub use crate::cmd::{enroll, export, inspect_identities, mint, provisioning, rotate, verify_log};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub name: &'static str,
    pub about: &'static str,
}

/// Required subcommands (CLAIM-9.1, CLAIM-27.2..27.4).
pub const REQUIRED_SUBCOMMANDS: &[&str] = &[
    "enroll",
    "mint",
    "rotate",
    "inspect-identities",
    "export-log",
    "export-evidence-bundle",
    "verify-log",
    "rollout",
    "restore",
    "flash-wear-estimate",
    "provisioning",
];

pub fn cli_commands() -> Vec<CommandSpec> {
    vec![
        CommandSpec { name: "enroll", about: "First-boot device enrollment and scoped token issuance" },
        CommandSpec { name: "mint", about: "Mint a scoped Biscuit token (max lifetime 86400s)" },
        CommandSpec { name: "rotate", about: "Rotate the local device identity key" },
        CommandSpec { name: "inspect-identities", about: "Inspect identity files (public fields only)" },
        CommandSpec { name: "export-log", about: "Export security event log (JSON/CBOR), signed by device key (CLAIM-27.2)" },
        CommandSpec { name: "export-evidence-bundle", about: "Export signed evidence bundle archive (CLAIM-27.3)" },
        CommandSpec { name: "verify-log", about: "Verify hash-chained security log; exit 0 intact, non-zero with broken ranges (CLAIM-27.4)" },
        CommandSpec { name: "rollout", about: "Staged rollout status and signed rollback (CLAIM-30.8, PV-8.9)" },
        CommandSpec { name: "restore", about: "Restore primary DB from backup, replay delta log, signed epoch bump, enter LOCKDOWN (CLAIM-32.3, S22)" },
        CommandSpec { name: "flash-wear-estimate", about: "Report 7-day rolling average/projected durable writes at Linux block layer (CLAIM-44.6, PV-15.4)" },
        CommandSpec { name: "provisioning", about: "Device provisioning/lifecycle: claim|payload|enroll|offline|rotate|revoke|replace|decommission|reissue|transfer|report|drift|query|audit (F-04)" },
    ]
}
