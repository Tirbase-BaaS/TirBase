//! DID generation, persistence, and resolution.
//!
//! Each TirBase device has a DID of the form `did:key:z6Mk…` derived from
//! its Ed25519 public key (Req 7.1).

#![allow(dead_code, unused_variables)]

use crate::errors::TirBaseError;

/// A `did:key:` DID string.
pub type Did = String;

/// Multicodec prefix for ed25519-pub keys: 0xed 0x01
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

/// Derive a `did:key:` DID from a raw Ed25519 public key (32 bytes).
///
/// The DID is the multibase-encoded (base58btc) multicodec-prefixed public key:
///   `did:key:z` + base58btc(0xed01 || public_key_bytes)
pub fn derive_did(public_key: &[u8; 32]) -> Did {
    let mut prefixed = Vec::with_capacity(2 + 32);
    prefixed.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    prefixed.extend_from_slice(public_key);
    let encoded = bs58::encode(&prefixed).into_string();
    format!("did:key:z{encoded}")
}

/// Resolve a `did:key:` DID to its Ed25519 public key bytes.
///
/// Returns `DidResolutionFailed` if the DID is malformed or uses an
/// unsupported method.
pub fn resolve_did(did: &Did) -> Result<[u8; 32], TirBaseError> {
    // DID must start with "did:key:z"
    let encoded = did.strip_prefix("did:key:z").ok_or_else(|| {
        TirBaseError::DidResolutionFailed {
            did: did.clone(),
            reason: "DID must start with 'did:key:z'".to_string(),
        }
    })?;

    let decoded = bs58::decode(encoded).into_vec().map_err(|e| {
        TirBaseError::DidResolutionFailed {
            did: did.clone(),
            reason: format!("base58btc decode error: {e}"),
        }
    })?;

    // Must start with the ed25519 multicodec prefix 0xed 0x01
    if decoded.len() < 2 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(TirBaseError::DidResolutionFailed {
            did: did.clone(),
            reason: "not an ed25519 did:key (wrong multicodec prefix)".to_string(),
        });
    }

    let key_bytes = &decoded[2..];
    if key_bytes.len() != 32 {
        return Err(TirBaseError::DidResolutionFailed {
            did: did.clone(),
            reason: format!(
                "expected 32-byte public key, got {} bytes",
                key_bytes.len()
            ),
        });
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(key_bytes);
    Ok(out)
}

// ─── Persistence ─────────────────────────────────────────────────────────────

/// The identity file format stored on disk.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredIdentity {
    did: String,
    /// Hex-encoded 32-byte secret key seed.
    secret_key_hex: String,
    /// Hex-encoded 32-byte public key.
    public_key_hex: String,
}

/// Persist the device DID and private key to durable storage (Req 7.1).
///
/// On native: writes a JSON file to `path`.
/// On WASM: no-op (in-memory only).
pub fn persist_identity(did: &Did, keypair_bytes: &[u8]) -> Result<(), TirBaseError> {
    persist_identity_to(did, keypair_bytes, "./tirbase-identity.json")
}

/// Persist the device DID and private key to a specific path (used for testing).
pub fn persist_identity_to(
    did: &Did,
    keypair_bytes: &[u8],
    path: &str,
) -> Result<(), TirBaseError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        if keypair_bytes.len() < 32 {
            return Err(TirBaseError::LocalStoreWriteFailed {
                reason: "keypair_bytes must be at least 32 bytes (secret key seed)".to_string(),
            });
        }

        // keypair_bytes: first 32 bytes = secret key seed, last 32 bytes = public key
        // (ed25519-dalek SigningKey::to_bytes() returns 32-byte seed, not 64-byte)
        let secret_key_hex = hex::encode(&keypair_bytes[..32]);
        let public_key_hex = if keypair_bytes.len() >= 64 {
            hex::encode(&keypair_bytes[32..64])
        } else {
            // Derive public key from secret key
            let pk_bytes = resolve_did(did).unwrap_or([0u8; 32]);
            hex::encode(pk_bytes)
        };

        let stored = StoredIdentity {
            did: did.clone(),
            secret_key_hex,
            public_key_hex,
        };
        let json = serde_json::to_string_pretty(&stored).map_err(|e| {
            TirBaseError::LocalStoreWriteFailed {
                reason: format!("JSON serialisation failed: {e}"),
            }
        })?;

        std::fs::write(path, json).map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("write to {path} failed: {e}"),
        })?;
    }
    Ok(())
}

/// Load the device DID and private key from durable storage (Req 7.1).
/// Returns `None` if no identity has been persisted yet.
pub fn load_identity() -> Result<Option<(Did, Vec<u8>)>, TirBaseError> {
    load_identity_from("./tirbase-identity.json")
}

/// Load identity from a specific path (used for testing).
pub fn load_identity_from(path: &str) -> Result<Option<(Did, Vec<u8>)>, TirBaseError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        if !std::path::Path::new(path).exists() {
            return Ok(None);
        }

        let json = std::fs::read_to_string(path).map_err(|e| {
            TirBaseError::LocalStoreWriteFailed {
                reason: format!("read from {path} failed: {e}"),
            }
        })?;

        let stored: StoredIdentity = serde_json::from_str(&json).map_err(|e| {
            TirBaseError::LocalStoreWriteFailed {
                reason: format!("JSON parse failed: {e}"),
            }
        })?;

        let secret_key_bytes = hex::decode(&stored.secret_key_hex).map_err(|e| {
            TirBaseError::LocalStoreWriteFailed {
                reason: format!("hex decode of secret key failed: {e}"),
            }
        })?;

        let public_key_bytes = hex::decode(&stored.public_key_hex).map_err(|e| {
            TirBaseError::LocalStoreWriteFailed {
                reason: format!("hex decode of public key failed: {e}"),
            }
        })?;

        // Return keypair_bytes as secret_key (32 bytes) + public_key (32 bytes) = 64 bytes
        let mut keypair = secret_key_bytes;
        keypair.extend_from_slice(&public_key_bytes);

        return Ok(Some((stored.did, keypair)));
    }

    #[cfg(target_arch = "wasm32")]
    {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_pubkey() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    #[test]
    fn test_derive_did_format() {
        let pubkey = make_test_pubkey();
        let did = derive_did(&pubkey);
        assert!(
            did.starts_with("did:key:z6Mk"),
            "DID should start with 'did:key:z6Mk', got: {did}"
        );
    }

    #[test]
    fn test_derive_and_resolve_did_round_trip() {
        let pubkey = make_test_pubkey();
        let did = derive_did(&pubkey);
        let resolved = resolve_did(&did).expect("should resolve without error");
        assert_eq!(
            resolved, pubkey,
            "resolved public key should match original"
        );
    }

    #[test]
    fn test_resolve_invalid_did_fails() {
        let invalid_did = "not:a:did".to_string();
        let result = resolve_did(&invalid_did);
        assert!(result.is_err(), "invalid DID should fail resolution");
    }

    #[test]
    fn test_resolve_wrong_multicodec_prefix() {
        // Build a did:key:z with the wrong prefix (0x12 0x20 = sha2-256 hash)
        let wrong_prefix = [0x12u8, 0x20];
        let mut prefixed = Vec::with_capacity(2 + 32);
        prefixed.extend_from_slice(&wrong_prefix);
        prefixed.extend_from_slice(&[0u8; 32]);
        let encoded = bs58::encode(&prefixed).into_string();
        let did = format!("did:key:z{encoded}");
        let result = resolve_did(&did);
        assert!(
            result.is_err(),
            "wrong multicodec prefix should fail resolution"
        );
    }

    #[test]
    fn test_derive_did_different_keys_give_different_dids() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        assert_ne!(
            derive_did(&key1),
            derive_did(&key2),
            "different keys should produce different DIDs"
        );
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_persist_and_load_identity() {
        use std::env;
        let tmp = env::temp_dir().join("tirbase_test_identity.json");
        let path = tmp.to_str().unwrap();

        let pubkey = make_test_pubkey();
        let did = derive_did(&pubkey);

        // Simulate keypair_bytes = [secret(32)] + [public(32)]
        let secret_key = [42u8; 32];
        let mut keypair_bytes = secret_key.to_vec();
        keypair_bytes.extend_from_slice(&pubkey);

        persist_identity_to(&did, &keypair_bytes, path).expect("persist should succeed");

        let loaded = load_identity_from(path).expect("load should succeed");
        assert!(loaded.is_some(), "should load persisted identity");

        let (loaded_did, loaded_keypair) = loaded.unwrap();
        assert_eq!(loaded_did, did, "loaded DID should match");
        assert_eq!(
            &loaded_keypair[..32],
            &secret_key,
            "loaded secret key should match"
        );
        assert_eq!(
            &loaded_keypair[32..],
            &pubkey,
            "loaded public key should match"
        );

        // Clean up
        let _ = std::fs::remove_file(path);
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_load_nonexistent_identity_returns_none() {
        let result =
            load_identity_from("./this_file_does_not_exist_tirbase_test.json").unwrap();
        assert!(result.is_none(), "should return None for missing file");
    }
}
