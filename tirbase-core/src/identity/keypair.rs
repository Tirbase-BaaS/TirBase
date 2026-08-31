//! Ed25519 keypair generation and signing (Req 7.2).

#![allow(dead_code, unused_variables)]

use crate::crdt::delta::Ed25519Signature;
use crate::errors::TirBaseError;

use ed25519_dalek::{Signer, Verifier};

/// Generate a new Ed25519 keypair.
///
/// Returns `(secret_key_seed_bytes [32], public_key_bytes [32])`.
///
/// Note: ed25519-dalek v3 uses 32-byte seeds (not 64-byte expanded keys).
/// The returned tuple is (seed/secret, public).
pub fn generate_keypair() -> Result<([u8; 32], [u8; 32]), TirBaseError> {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::rand_core::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let secret_bytes: [u8; 32] = signing_key.to_bytes();
    let public_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    Ok((secret_bytes, public_bytes))
}

/// Sign `payload` with the given Ed25519 secret key seed (32 bytes).
///
/// Returns an `Ed25519Signature`.
pub fn sign(secret_key: &[u8; 32], payload: &[u8]) -> Result<Ed25519Signature, TirBaseError> {
    use ed25519_dalek::SigningKey;

    let signing_key = SigningKey::from_bytes(secret_key);
    let signature = signing_key.sign(payload);
    Ok(Ed25519Signature::from_bytes(signature.to_bytes()))
}

/// Verify `signature` over `payload` using the Ed25519 public key.
///
/// Returns `Ok(())` on success or `SignatureVerificationFailed` on failure.
pub fn verify(
    public_key: &[u8; 32],
    payload: &[u8],
    signature: &Ed25519Signature,
) -> Result<(), TirBaseError> {
    use ed25519_dalek::VerifyingKey;

    let verifying_key = VerifyingKey::from_bytes(public_key).map_err(|e| {
        TirBaseError::SignatureVerificationFailed {
            reason: format!("invalid public key: {e}"),
        }
    })?;

    let sig_bytes = signature.as_bytes().ok_or_else(|| {
        TirBaseError::SignatureVerificationFailed {
            reason: "signature is not exactly 64 bytes".to_string(),
        }
    })?;

    let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(payload, &dalek_sig)
        .map_err(|e| TirBaseError::SignatureVerificationFailed {
            reason: format!("signature verification failed: {e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_round_trip() {
        let (secret, public) = generate_keypair().expect("keypair generation should succeed");
        let payload = b"hello, tirbase!";
        let sig = sign(&secret, payload).expect("signing should succeed");
        verify(&public, payload, &sig).expect("verification should succeed");
    }

    #[test]
    fn test_verify_tampered_payload_fails() {
        let (secret, public) = generate_keypair().unwrap();
        let payload = b"original payload";
        let sig = sign(&secret, payload).unwrap();

        let tampered = b"tampered payload";
        let result = verify(&public, tampered, &sig);
        assert!(
            result.is_err(),
            "verification of tampered payload should fail"
        );
    }

    #[test]
    fn test_verify_tampered_signature_fails() {
        let (secret, public) = generate_keypair().unwrap();
        let payload = b"some payload";
        let mut sig = sign(&secret, payload).unwrap();

        // Flip a byte in the signature
        if let Some(first) = sig.0.first_mut() {
            *first ^= 0xFF;
        }

        let result = verify(&public, payload, &sig);
        assert!(
            result.is_err(),
            "verification of tampered signature should fail"
        );
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let (secret, _public) = generate_keypair().unwrap();
        let (_other_secret, other_public) = generate_keypair().unwrap();

        let payload = b"test payload";
        let sig = sign(&secret, payload).unwrap();

        let result = verify(&other_public, payload, &sig);
        assert!(
            result.is_err(),
            "verification with wrong public key should fail"
        );
    }

    #[test]
    fn test_generate_keypair_produces_unique_keys() {
        let (sk1, pk1) = generate_keypair().unwrap();
        let (sk2, pk2) = generate_keypair().unwrap();
        assert_ne!(sk1, sk2, "secret keys should differ across keypairs");
        assert_ne!(pk1, pk2, "public keys should differ across keypairs");
    }
}
