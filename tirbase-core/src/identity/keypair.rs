//! Ed25519 keypair generation and signing (Req 7.2).

#![allow(dead_code, unused_variables)]

use crate::errors::TirBaseError;

/// Generate a new Ed25519 keypair.
///
/// Returns `(private_key_bytes [64], public_key_bytes [32])`.
pub fn generate_keypair() -> Result<([u8; 64], [u8; 32]), TirBaseError> {
    todo!("Task 4: implement via ed25519-dalek")
}

/// Sign `payload` with the given Ed25519 private key.
///
/// Returns a 64-byte Ed25519 signature.
pub fn sign(private_key: &[u8; 64], payload: &[u8]) -> Result<[u8; 64], TirBaseError> {
    todo!("Task 4: implement via ed25519-dalek")
}

/// Verify `signature` over `payload` using the Ed25519 public key.
///
/// Returns `Ok(())` on success or `SignatureVerificationFailed` on failure.
pub fn verify(
    public_key: &[u8; 32],
    payload: &[u8],
    signature: &[u8; 64],
) -> Result<(), TirBaseError> {
    todo!("Task 4: implement via ed25519-dalek")
}
