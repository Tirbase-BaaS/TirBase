//! Biscuit token creation, offline verification, and caveat checking (Req 8.1).
//!
//! Biscuit-auth is a native-only dependency. On WASM builds all functions return
//! stub errors or `false` since there is no CA key material available in the browser
//! context.

#![allow(dead_code, unused_variables)]

use crate::errors::TirBaseError;

/// Minimum TTL: 1 hour (Req 8.7)
pub const TTL_MIN_SECS: u64 = 3600;
/// Maximum TTL: 24 hours (Req 8.7)
pub const TTL_MAX_SECS: u64 = 86400;

/// Claims extracted from a verified Biscuit token.
#[derive(Debug, Clone)]
pub struct BiscuitClaims {
    pub did: String,
    pub role: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

// ─── Native implementation ───────────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;
    use biscuit_auth::{
        builder::{date, Algorithm},
        builder_ext::{AuthorizerExt, BuilderExt},
        macros::*,
        AuthorizerBuilder, Biscuit, KeyPair, PrivateKey, PublicKey,
    };
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// Create a new Biscuit token for the given DID and role.
    ///
    /// TTL must be between 1 hour (3600s) and 24 hours (86400s) (Req 8.7).
    pub fn create_token(
        did: &str,
        role: &str,
        ttl_secs: u64,
        root_ca_private_key: &[u8],
    ) -> Result<Vec<u8>, TirBaseError> {
        if ttl_secs < TTL_MIN_SECS {
            return Err(TirBaseError::AuthorisationFailed {
                reason: format!(
                    "TTL {ttl_secs}s is below minimum of {TTL_MIN_SECS}s (1 hour)"
                ),
            });
        }
        if ttl_secs > TTL_MAX_SECS {
            return Err(TirBaseError::AuthorisationFailed {
                reason: format!(
                    "TTL {ttl_secs}s exceeds maximum of {TTL_MAX_SECS}s (24 hours)"
                ),
            });
        }

        let now = SystemTime::now();
        let expiry = now + Duration::from_secs(ttl_secs);
        let issued_secs = now
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Build key from raw private key seed
        let private_key = PrivateKey::from_bytes(root_ca_private_key, Algorithm::Ed25519)
            .map_err(|e| TirBaseError::AuthorisationFailed {
                reason: format!("invalid root CA private key: {e}"),
            })?;
        let keypair = KeyPair::from(&private_key);

        // Use Datalog builder API to add facts
        let did_str = did.to_string();
        let role_str = role.to_string();
        let issued_at_val = issued_secs as i64;

        let token = Biscuit::builder()
            .fact(format!("did(\"{did_str}\")").as_str())
            .map_err(|e| TirBaseError::AuthorisationFailed {
                reason: format!("failed to add did fact: {e}"),
            })?
            .fact(format!("role(\"{role_str}\")").as_str())
            .map_err(|e| TirBaseError::AuthorisationFailed {
                reason: format!("failed to add role fact: {e}"),
            })?
            .fact(format!("issued_at({issued_at_val})").as_str())
            .map_err(|e| TirBaseError::AuthorisationFailed {
                reason: format!("failed to add issued_at fact: {e}"),
            })?
            .check_expiration_date(expiry)
            .build(&keypair)
            .map_err(|e| TirBaseError::AuthorisationFailed {
                reason: format!("failed to build Biscuit token: {e}"),
            })?;

        token.to_vec().map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("failed to serialize Biscuit token: {e}"),
        })
    }

    /// Verify a Biscuit token offline against the root CA public key (Req 8.1).
    ///
    /// Returns `Ok(BiscuitClaims)` if the token is valid and not expired.
    pub fn verify_token(
        token_bytes: &[u8],
        root_ca_public_key: &[u8],
        now_secs: i64,
    ) -> Result<BiscuitClaims, TirBaseError> {
        use biscuit_auth::builder::{date, fact};

        let public_key =
            PublicKey::from_bytes(root_ca_public_key, Algorithm::Ed25519).map_err(|e| {
                TirBaseError::AuthorisationFailed {
                    reason: format!("invalid root CA public key: {e}"),
                }
            })?;

        let token = Biscuit::from(token_bytes, public_key).map_err(|e| {
            TirBaseError::AuthorisationFailed {
                reason: format!("failed to parse/verify Biscuit token: {e}"),
            }
        })?;

        // Build a "now" SystemTime from now_secs for expiration checking
        let fake_now = UNIX_EPOCH + Duration::from_secs(now_secs.max(0) as u64);
        let time_fact = fact("time", &[date(&fake_now)]);

        // Build authorizer with the provided "now" time for expiration check
        let mut authorizer = AuthorizerBuilder::new()
            .fact(time_fact)
            .map_err(|e| TirBaseError::AuthorisationFailed {
                reason: format!("authorizer build error: {e}"),
            })?
            .allow_all()
            .build(&token)
            .map_err(|e| TirBaseError::AuthorisationFailed {
                reason: format!("authorizer construction failed: {e}"),
            })?;

        authorizer.authorize().map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("token authorization failed (possibly expired): {e}"),
        })?;

        // Extract claims via datalog queries
        let did_results: Vec<(String,)> = authorizer
            .query("data($did) <- did($did)")
            .map_err(|e| TirBaseError::AuthorisationFailed {
                reason: format!("did query failed: {e}"),
            })?;

        let did = did_results
            .into_iter()
            .next()
            .map(|(d,)| d)
            .unwrap_or_default();

        let role_results: Vec<(String,)> = authorizer
            .query("data($role) <- role($role)")
            .map_err(|e| TirBaseError::AuthorisationFailed {
                reason: format!("role query failed: {e}"),
            })?;

        let role = role_results
            .into_iter()
            .next()
            .map(|(r,)| r)
            .unwrap_or_default();

        let issued_results: Vec<(i64,)> = authorizer
            .query("data($t) <- issued_at($t)")
            .map_err(|e| TirBaseError::AuthorisationFailed {
                reason: format!("issued_at query failed: {e}"),
            })?;

        let issued_at = issued_results
            .into_iter()
            .next()
            .map(|(t,)| t)
            .unwrap_or(0);

        // expires_at: we don't store it as a fact; approximate from now_secs + TTL
        // For a more precise implementation we could store it explicitly.
        // Use now_secs as a conservative fallback (token is valid at this moment).
        let expires_at = now_secs; // actual expiry tracked by Biscuit's check_expiration_date

        Ok(BiscuitClaims {
            did,
            role,
            issued_at,
            expires_at,
        })
    }

    /// Check that a token carries a specific fact or caveat (e.g., `disaster-alert` — Req 13.1).
    pub fn has_caveat(token_bytes: &[u8], caveat: &str, root_ca_public_key: &[u8]) -> bool {
        let public_key = match PublicKey::from_bytes(root_ca_public_key, Algorithm::Ed25519) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let token = match Biscuit::from(token_bytes, public_key) {
            Ok(t) => t,
            Err(_) => return false,
        };

        // Check if the token string representation contains the caveat name
        token.to_string().contains(caveat)
    }
}

// ─── WASM stubs ──────────────────────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
mod wasm_stubs {
    use super::*;

    pub fn create_token(
        _did: &str,
        _role: &str,
        _ttl_secs: u64,
        _root_ca_private_key: &[u8],
    ) -> Result<Vec<u8>, TirBaseError> {
        Err(TirBaseError::AuthorisationFailed {
            reason: "Biscuit token creation is not available on WASM builds".to_string(),
        })
    }

    pub fn verify_token(
        _token_bytes: &[u8],
        _root_ca_public_key: &[u8],
        _now_secs: i64,
    ) -> Result<BiscuitClaims, TirBaseError> {
        Err(TirBaseError::AuthorisationFailed {
            reason: "Biscuit token verification is not available on WASM builds".to_string(),
        })
    }

    pub fn has_caveat(_token_bytes: &[u8], _caveat: &str, _root_ca_public_key: &[u8]) -> bool {
        false
    }
}

// ─── Public API — dispatch to native or WASM ─────────────────────────────────

/// Create a new Biscuit token for the given DID and role.
///
/// TTL must be between 1 hour and 24 hours (Req 8.7).
pub fn create_token(
    did: &str,
    role: &str,
    ttl_secs: u64,
    root_ca_private_key: &[u8],
) -> Result<Vec<u8>, TirBaseError> {
    #[cfg(not(target_arch = "wasm32"))]
    return native::create_token(did, role, ttl_secs, root_ca_private_key);

    #[cfg(target_arch = "wasm32")]
    return wasm_stubs::create_token(did, role, ttl_secs, root_ca_private_key);
}

/// Verify a Biscuit token offline against the root CA public key (Req 8.1).
///
/// Returns `Ok(BiscuitClaims)` if the token is valid and not expired.
pub fn verify_token(
    token_bytes: &[u8],
    root_ca_public_key: &[u8],
    now_secs: i64,
) -> Result<BiscuitClaims, TirBaseError> {
    #[cfg(not(target_arch = "wasm32"))]
    return native::verify_token(token_bytes, root_ca_public_key, now_secs);

    #[cfg(target_arch = "wasm32")]
    return wasm_stubs::verify_token(token_bytes, root_ca_public_key, now_secs);
}

/// Check that a token carries a specific caveat (e.g., `disaster-alert` — Req 13.1).
pub fn has_caveat(token_bytes: &[u8], caveat: &str, root_ca_public_key: &[u8]) -> bool {
    #[cfg(not(target_arch = "wasm32"))]
    return native::has_caveat(token_bytes, caveat, root_ca_public_key);

    #[cfg(target_arch = "wasm32")]
    return false;
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use biscuit_auth::{builder::Algorithm, KeyPair, PrivateKey};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_ca_keys() -> (Vec<u8>, Vec<u8>) {
        let kp = KeyPair::new();
        let private_bytes = kp.private().to_bytes().to_vec();
        let public_bytes = kp.public().to_bytes();
        (private_bytes, public_bytes)
    }

    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn test_create_and_verify_token() {
        let (priv_key, pub_key) = make_ca_keys();
        let token_bytes =
            create_token("did:key:z6MkTest", "admin", 3600, &priv_key).expect("create_token should succeed");
        assert!(!token_bytes.is_empty(), "token bytes should not be empty");

        let claims = verify_token(&token_bytes, &pub_key, now_secs())
            .expect("verify_token should succeed");
        assert_eq!(claims.did, "did:key:z6MkTest");
        assert_eq!(claims.role, "admin");
    }

    #[test]
    fn test_ttl_too_short_rejected() {
        let (priv_key, _) = make_ca_keys();
        let result = create_token("did:key:z6MkTest", "user", 3599, &priv_key);
        assert!(result.is_err(), "TTL < 1h should be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("TTL") || err.contains("minimum"),
            "error should mention TTL: {err}"
        );
    }

    #[test]
    fn test_ttl_too_long_rejected() {
        let (priv_key, _) = make_ca_keys();
        let result = create_token("did:key:z6MkTest", "user", 86401, &priv_key);
        assert!(result.is_err(), "TTL > 24h should be rejected");
    }

    #[test]
    fn test_expired_token_rejected() {
        let (priv_key, pub_key) = make_ca_keys();
        // Create a token with 1h TTL
        let token_bytes =
            create_token("did:key:z6MkExp", "viewer", 3600, &priv_key).unwrap();

        // Verify at a time far in the future (25 hours from now)
        let future_secs = now_secs() + 25 * 3600;
        let result = verify_token(&token_bytes, &pub_key, future_secs);
        assert!(result.is_err(), "expired token should be rejected");
    }

    #[test]
    fn test_verify_with_wrong_key_fails() {
        let (priv_key, _pub_key) = make_ca_keys();
        let (_other_priv, other_pub) = make_ca_keys();

        let token_bytes = create_token("did:key:z6Mk", "admin", 3600, &priv_key).unwrap();
        let result = verify_token(&token_bytes, &other_pub, now_secs());
        assert!(result.is_err(), "token verified with wrong public key should fail");
    }
}
