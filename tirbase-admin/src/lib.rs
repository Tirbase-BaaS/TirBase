//! `tirbase-admin` library surface (tasks 9, 27).

pub mod cmd;

pub use crate::cmd::{enroll, export, inspect_identities, mint, rotate, verify_log};

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
    ]
}
