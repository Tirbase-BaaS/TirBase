// SPDX-License-Identifier: AGPL-3.0-only

//! `tirbase-admin` library surface ().

pub mod cmd;

pub use crate::cmd::{
    enroll, export, inspect_identities, ledger, mint, provisioning, rotate, verify_log,
};

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
    "ledger",
    "rollout",
    "restore",
    "backup",
    "restore-backup",
    "pitr",
    "dr-drill",
    "retention",
    "storage-budget",
    "encrypt-export",
    "decrypt-export",
    "flash-wear-estimate",
    "provisioning",
    "vertical",
    "webhook",
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
        CommandSpec { name: "ledger", about: "Offline signed-bundle verification for the lineage ledger: verify --bundle FILE --signature FILE --trusted-key DID=HEX (CC-14)" },
        CommandSpec { name: "rollout", about: "Staged rollout status and signed rollback (CLAIM-30.8, PV-8.9)" },
        CommandSpec { name: "restore", about: "Restore primary DB from backup, replay delta log, signed epoch bump, enter LOCKDOWN (CLAIM-32.3, S22)" },
        CommandSpec { name: "backup", about: "Create a consistent signed snapshot with a ledger root hash (F-07)" },
        CommandSpec { name: "restore-backup", about: "Restore a signed snapshot and verify the reproduced ledger root hash (F-07)" },
        CommandSpec { name: "pitr", about: "Point-in-time recovery: restore a snapshot and replay a security-event delta (F-07)" },
        CommandSpec { name: "dr-drill", about: "Run a backup/restore/PITR disaster-recovery drill and report pass/fail (F-07)" },
        CommandSpec { name: "retention", about: "Apply per-class retention, record legal holds, and audit every purge (F-07)" },
        CommandSpec { name: "storage-budget", about: "Report ledger/archive occupancy against configured budgets (F-07)" },
        CommandSpec { name: "encrypt-export", about: "Seal an exported ledger record set with ChaCha20-Poly1305 (F-07)" },
        CommandSpec { name: "decrypt-export", about: "Verify and open a sealed export (F-07)" },
        CommandSpec { name: "flash-wear-estimate", about: "Report 7-day rolling average/projected durable writes at Linux block layer (CLAIM-44.6, PV-15.4)" },
        CommandSpec { name: "provisioning", about: "Device provisioning/lifecycle: claim|payload|enroll|offline|rotate|revoke|replace|decommission|reissue|transfer|report|drift|query|audit (F-04)" },
        CommandSpec { name: "vertical", about: "Cold-chain, POS and venue resources: list|get|create|patch|delete (F-08)" },
        CommandSpec { name: "webhook", about: "Signed webhook endpoints and delivery drain: add|list|enable|disable|drain (F-08)" },
    ]
}
