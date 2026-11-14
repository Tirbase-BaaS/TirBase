// SPDX-License-Identifier: Apache-2.0

//! TirBase vertical demo packs.
//!
//! Bundles: cold-chain (flagship), energy-edge, water, logistics, buildings,
//! remote-ops, defense-logistics.
//!
//! ## Demo pack format (CLAIM-46.1, PV-16)
//!
//! Each demo pack is a self-contained directory with the following layout:
//!
//! - `profiles/` — `EnvelopeProfile` TOML documents (and any device-model data)
//! - `scenarios/` — adversary scenario declarations (TOML) wired into the pack
//! - `sim/config.toml` — simulator configuration for the pack
//! - `run.sh` — entry-point script producing observable defended output
//! - `docs/README.md` — pack documentation and non-goals
//! - `docs/modbus-register-map.md` — register map for Modbus-backed packs
//!
//! The cold-chain flagship pack lives at `tirbase-demo/cold-chain/`.

#![forbid(unsafe_code)]
// Warn on dead private code across this crate. `pub` items are naturally exempt
// (the Rust dead_code lint does not fire on reachable public items).
#![warn(dead_code)]

use std::path::Path;

/// Relative paths that define a complete demo pack (CLAIM-46.1).
pub const DEMO_PACK_FORMAT: &[&str] = &[
    "profiles",
    "scenarios",
    "sim/config.toml",
    "run.sh",
    "docs/README.md",
    "docs/modbus-register-map.md",
];

/// Cold-chain flagship pack path relative to the workspace root.
pub const COLD_CHAIN_PACK_DIR: &str = "tirbase-demo/cold-chain";

/// Files required by the cold-chain flagship pack (format + pack-specific assets).
pub const COLD_CHAIN_PACK_FORMAT: &[&str] = &[
    "profiles/cold_chain.toml",
    "scenarios/S1.toml",
    "scenarios/S2.toml",
    "scenarios/S3.toml",
    "sim/config.toml",
    "run.sh",
    "docs/README.md",
    "docs/modbus-register-map.md",
];

/// Returns `true` when every path in `required` exists under `pack_root`.
pub fn pack_has_required_layout(pack_root: &Path, required: &[&str]) -> bool {
    required.iter().all(|rel| pack_root.join(rel).exists())
}

pub use tirbase_types;
