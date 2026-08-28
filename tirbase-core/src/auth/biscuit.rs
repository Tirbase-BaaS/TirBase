//! Biscuit token creation, offline verification, and caveat checking (Req 8.1).

#![allow(dead_code, unused_variables)]

use crate::errors::TirBaseError;

/// Create a new Biscuit token for the given DID and role.
///
/// TTL must be between 1 hour and 24 hours (Req 8.7).
pub fn create_token(
    did: &str,
    role: &str,
    ttl_secs: u64,
    root_ca_private_key: &[u8],
) -> Result<Vec<u8>, TirBaseError> {
    todo!("Task 4: implement via biscuit-auth crate")
}

/// Verify a Biscuit token offline against the root CA public key (Req 8.1).
///
/// Returns `Ok(BiscuitClaims)` if the token is valid and not expired.
pub fn verify_token(
    token_bytes: &[u8],
    root_ca_public_key: &[u8],
    now_secs: i64,
) -> Result<BiscuitClaims, TirBaseError> {
    todo!("Task 4: implement offline Biscuit verification")
}

/// Check that a token carries a specific caveat (e.g., `disaster-alert` — Req 13.1).
pub fn has_caveat(_token_bytes: &[u8], _caveat: &str) -> bool {
    todo!("Task 4: implement Datalog caveat check")
}

/// Claims extracted from a verified Biscuit token.
#[derive(Debug, Clone)]
pub struct BiscuitClaims {
    pub did: String,
    pub role: String,
    pub issued_at: i64,
    pub expires_at: i64,
}
