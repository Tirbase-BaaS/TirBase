//! `tirbase-admin` library surface (task 9).
//!
//! The binary (`main.rs`) is the production caller; this crate root exposes the
//! command modules and CLI declaration for integration tests and tooling.

pub mod cmd;

pub use crate::cmd::{enroll, inspect_identities, mint, rotate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub name: &'static str,
    pub about: &'static str,
}

/// Required task 9 subcommands (CLAIM-9.1).
pub const REQUIRED_SUBCOMMANDS: &[&str] = &["enroll", "mint", "rotate", "inspect-identities"];

pub fn cli_commands() -> Vec<CommandSpec> {
    vec![
        CommandSpec {
            name: "enroll",
            about: "First-boot device enrollment and scoped token issuance",
        },
        CommandSpec {
            name: "mint",
            about: "Mint a scoped Biscuit token (max lifetime 86400s)",
        },
        CommandSpec {
            name: "rotate",
            about: "Rotate the local device identity key",
        },
        CommandSpec {
            name: "inspect-identities",
            about: "Inspect identity files (public fields only)",
        },
    ]
}
