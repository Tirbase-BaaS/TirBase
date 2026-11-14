// SPDX-License-Identifier: AGPL-3.0-only

//! `tirbase-admin inspect-identities` — report identity material for operator
//! inspection (CLAIM-9.5, PV-3.10).
//!
//! Only public identity fields are reported (DID, public key, key type/path).
//! Private key material is never printed.

use std::path::PathBuf;

use anyhow::Result;

/// Arguments for `tirbase-admin inspect-identities`.
#[derive(Debug, Clone)]
pub struct InspectIdentitiesArgs {
 /// One or more identity JSON files to inspect.
    pub identities: Vec<PathBuf>,
}

/// A redacted identity record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct IdentityRecord {
 /// Source file path.
    pub path: String,
 /// DID, if present.
    pub did: Option<String>,
 /// Hex-encoded public key, if present.
    pub public_key_hex: Option<String>,
 /// Whether a private seed field is present in the file. The seed itself
 /// is never included.
    pub has_private_key: bool,
 /// Parse/load error, if the file could not be inspected.
    pub error: Option<String>,
}

/// Inspect identity files and return redacted records.
pub fn run(args: &InspectIdentitiesArgs) -> Result<Vec<IdentityRecord>> {
    let mut records = Vec::with_capacity(args.identities.len());
    for path in &args.identities {
        records.push(inspect_one(path));
    }
    Ok(records)
}

fn inspect_one(path: &PathBuf) -> IdentityRecord {
    let path_str = path.display().to_string();
    let body = match std::fs::read_to_string(path) {
        Ok(body) => body,
        Err(error) => {
            return IdentityRecord {
                path: path_str,
                did: None,
                public_key_hex: None,
                has_private_key: false,
                error: Some(format!("read failed: {error}")),
            }
        }
    };
    let value: serde_json::Value = match serde_json::from_str(&body) {
        Ok(value) => value,
        Err(error) => {
            return IdentityRecord {
                path: path_str,
                did: None,
                public_key_hex: None,
                has_private_key: false,
                error: Some(format!("parse failed: {error}")),
            }
        }
    };
    IdentityRecord {
        path: path_str,
        did: value
            .get("did")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned),
        public_key_hex: value
            .get("public_key_hex")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned),
        has_private_key: value
            .get("secret_key_hex")
            .and_then(|v| v.as_str())
            .is_some(),
        error: None,
    }
}

/// Print identity records as JSON.
pub fn print_records(records: &[IdentityRecord]) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(records)?);
    Ok(())
}

/// Convenience: inspect a single file (used by tests).
pub fn inspect_file(path: impl Into<PathBuf>) -> IdentityRecord {
    inspect_one(&path.into())
}
