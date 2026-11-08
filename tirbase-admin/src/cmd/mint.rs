//! `tirbase-admin mint` — scoped Biscuit token minting (task 9.3 — CLAIM-9.3,
//! PV-3.10).
//!
//! The CLI enforces a maximum token lifetime of 86,400 seconds (24 hours).
//! Removing that enforcement must fail the integration test.

use anyhow::{bail, Context, Result};
use tirbase_core::auth::biscuit;

/// Maximum token lifetime accepted by the `mint` subcommand (24 hours).
pub const MAX_MINT_TTL_SECS: u64 = 86_400;

/// Arguments for `tirbase-admin mint`.
#[derive(Debug, Clone)]
pub struct MintArgs {
    /// DID the token is issued to.
    pub did: String,
    /// Role carried by the token.
    pub role: String,
    /// Token TTL in seconds.  Must be <= 86,400 (24 hours).
    pub ttl_secs: u64,
    /// Hex-encoded 32-byte Ed25519 root CA private seed.  Never logged.
    pub root_ca_seed_hex: String,
}

/// Mint a scoped Biscuit token.
///
/// Enforces `ttl_secs <= MAX_MINT_TTL_SECS` before delegating to the Biscuit
/// implementation.  This is the production caller; the wiring-mutation check
/// removes this enforcement and expects the integration test to fail.
pub fn run(args: &MintArgs) -> Result<Vec<u8>> {
    if args.ttl_secs > MAX_MINT_TTL_SECS {
        bail!(
            "mint refuses ttl_secs={} > {} (maximum lifetime 86400s)",
            args.ttl_secs,
            MAX_MINT_TTL_SECS
        );
    }
    let seed = hex::decode(args.root_ca_seed_hex.trim()).context("decode root_ca_seed_hex")?;
    if seed.len() != 32 {
        bail!("root_ca_seed_hex must be 32 bytes (got {})", seed.len());
    }
    // Use the standard (non-extended-risk) path; mint is a scoped operator tool
    // and must not mint extended-window tokens.
    biscuit::create_token(&args.did, &args.role, args.ttl_secs, &seed, false)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Print the minted token as hex to stdout.
pub fn print_token(token: &[u8]) -> Result<()> {
    println!("{}", hex::encode(token));
    Ok(())
}
