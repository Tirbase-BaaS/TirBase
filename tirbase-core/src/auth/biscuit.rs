//! Biscuit token creation, offline verification, and caveat checking (Req 8.1).
//!
//! The `biscuit-auth` crate is pure Rust and compiles on both `native` and
//! `wasm32-unknown-unknown` targets. These functions are therefore available
//! on both build targets without any platform-specific stubs.

#![allow(dead_code, unused_variables)]

use crate::errors::TirBaseError;

/// Minimum TTL: 1 hour (Req 8.7)
pub const TTL_MIN_SECS: u64 = 3600;
/// Maximum TTL: 24 hours (Req 8.7 — the default cap)
pub const TTL_MAX_SECS: u64 = 86400;
/// Hard ceiling on TTL even with the accepted-risk override: 7 days.
/// This bounds the maximum window a partitioned/compromised device can hold
/// valid token access before the next forced re-authentication.
pub const TTL_OVERRIDE_CEILING_SECS: u64 = 7 * 24 * 3600;

/// Claims extracted from a verified Biscuit token.
#[derive(Debug, Clone)]
pub struct BiscuitClaims {
    pub did: String,
    pub role: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

// ─── Implementation (compiles on native and wasm32) ──────────────────────────

use biscuit_auth::{
    builder::{date, fact, Algorithm},
    builder_ext::{AuthorizerExt, BuilderExt},
    AuthorizerBuilder, Biscuit, KeyPair, PrivateKey, PublicKey,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Create a new Biscuit token for the given DID and role.
///
/// TTL must be between 1 hour (3600s) and 24 hours (86400s) by default (Req 8.7).
///
/// If `extended_ttl_accepted_risk` is `true`, the 24-hour maximum is relaxed
/// (up to [`TTL_OVERRIDE_CEILING_SECS`], currently 7 days).  This is the
/// documented "accepted risk" escape path: at `CoreHandle::init` time, a
/// `biscuit_ttl_secs` value exceeding 24h triggers the `EXTENDED_TTL`
/// diagnostic (Req 21.6), which serves as the deployment's explicit
/// acknowledgment of the extended-window trade-off.  A token created with
/// the override carries a `ttl_override("true")` fact so that offline
/// verifiers can detect extended-window tokens (Req 8.7).
pub fn create_token(
    did: &str,
    role: &str,
    ttl_secs: u64,
    root_ca_private_key: &[u8],
    extended_ttl_accepted_risk: bool,
) -> Result<Vec<u8>, TirBaseError> {
    if ttl_secs < TTL_MIN_SECS {
        return Err(TirBaseError::AuthorisationFailed {
            reason: format!("TTL {ttl_secs}s is below minimum of {TTL_MIN_SECS}s (1 hour)"),
        });
    }
    if ttl_secs > TTL_MAX_SECS {
        if !extended_ttl_accepted_risk {
            return Err(TirBaseError::AuthorisationFailed {
                reason: format!(
                    "TTL {ttl_secs}s exceeds maximum of {TTL_MAX_SECS}s (24 hours); \
                     extended TTL requires an explicit accepted-risk override"
                ),
            });
        }
        if ttl_secs > TTL_OVERRIDE_CEILING_SECS {
            return Err(TirBaseError::AuthorisationFailed {
                reason: format!(
                    "TTL {ttl_secs}s exceeds the extended-TTL ceiling of \
                     {TTL_OVERRIDE_CEILING_SECS}s (7 days) even with the \
                     accepted-risk override"
                ),
            });
        }
    }

    let now = SystemTime::now();
    let issued_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    // When the override is active and the TTL exceeds the default 24h cap,
    // add a `ttl_override("true")` fact so offline verifiers can detect
    // extended-window tokens.
    let extra_facts: Vec<&str> = if extended_ttl_accepted_risk && ttl_secs > TTL_MAX_SECS {
        vec!["ttl_override(\"true\")"]
    } else {
        vec![]
    };

    build_token(
        did,
        role,
        ttl_secs,
        &extra_facts,
        root_ca_private_key,
        now,
        issued_secs,
    )
}

/// Shared token builder: facts (`did`, `role`, `issued_at`) plus optional extra
/// fact strings (e.g. `caveat("disaster-alert")`), signed by the root CA key.
fn build_token(
    did: &str,
    role: &str,
    ttl_secs: u64,
    extra_facts: &[&str],
    root_ca_private_key: &[u8],
    now: SystemTime,
    issued_secs: u64,
) -> Result<Vec<u8>, TirBaseError> {
    let expiry = now + Duration::from_secs(ttl_secs);

    // Build key from raw private key seed
    let private_key =
        PrivateKey::from_bytes(root_ca_private_key, Algorithm::Ed25519).map_err(|e| {
            TirBaseError::AuthorisationFailed {
                reason: format!("invalid root CA private key: {e}"),
            }
        })?;
    let keypair = KeyPair::from(&private_key);

    // Use Datalog builder API to add facts
    let did_str = did.to_string();
    let role_str = role.to_string();
    let issued_at_val = issued_secs as i64;

    let mut builder = Biscuit::builder()
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
        .check_expiration_date(expiry);

    for fact_str in extra_facts {
        builder = builder
            .fact(*fact_str)
            .map_err(|e| TirBaseError::AuthorisationFailed {
                reason: format!("failed to add extra fact: {e}"),
            })?;
    }

    let token = builder
        .build(&keypair)
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("failed to build Biscuit token: {e}"),
        })?;

    token
        .to_vec()
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("failed to serialize Biscuit token: {e}"),
        })
}

/// Build a Biscuit token carrying a `caveat("...")` fact, for tests exercising
/// the production `verify_and_check_caveat` path (Req 13.1).
#[cfg(test)]
pub(crate) fn create_token_with_caveat(
    did: &str,
    role: &str,
    ttl_secs: u64,
    caveat: &str,
    root_ca_private_key: &[u8],
) -> Result<Vec<u8>, TirBaseError> {
    let now = SystemTime::now();
    let issued_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let caveat_fact = format!("caveat(\"{caveat}\")");
    build_token(
        did,
        role,
        ttl_secs,
        &[caveat_fact.as_str()],
        root_ca_private_key,
        now,
        issued_secs,
    )
}

/// Verify a Biscuit token offline against the root CA public key (Req 8.1).
///
/// Returns `Ok(BiscuitClaims)` if the token is valid and not expired.
pub fn verify_token(
    token_bytes: &[u8],
    root_ca_public_key: &[u8],
    now_secs: i64,
) -> Result<BiscuitClaims, TirBaseError> {
    let public_key =
        PublicKey::from_bytes(root_ca_public_key, Algorithm::Ed25519).map_err(|e| {
            TirBaseError::AuthorisationFailed {
                reason: format!("invalid root CA public key: {e}"),
            }
        })?;

    let token =
        Biscuit::from(token_bytes, public_key).map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("failed to parse/verify Biscuit token: {e}"),
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

    // Use generous limits so that authorize() + three query() calls don't
    // exhaust the default 100-iteration Datalog budget (Req 8.1).
    let generous = biscuit_auth::AuthorizerLimits {
        max_facts: 10_000,
        max_iterations: 10_000,
        max_time: Duration::from_secs(5),
    };

    authorizer
        .authorize_with_limits(generous.clone())
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("token authorization failed (possibly expired): {e}"),
        })?;

    // Extract claims via datalog queries (use generous limits to share budget).
    let did_results: Vec<(String,)> = authorizer
        .query_with_limits("data($did) <- did($did)", generous.clone())
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("did query failed: {e}"),
        })?;

    let did = did_results
        .into_iter()
        .next()
        .map(|(d,)| d)
        .unwrap_or_default();

    let role_results: Vec<(String,)> = authorizer
        .query_with_limits("data($role) <- role($role)", generous.clone())
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("role query failed: {e}"),
        })?;

    let role = role_results
        .into_iter()
        .next()
        .map(|(r,)| r)
        .unwrap_or_default();

    let issued_results: Vec<(i64,)> = authorizer
        .query_with_limits("data($t) <- issued_at($t)", generous)
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("issued_at query failed: {e}"),
        })?;

    let issued_at = issued_results.into_iter().next().map(|(t,)| t).unwrap_or(0);

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

/// Check that a token carries a specific caveat fact (e.g., `disaster-alert` — Req 13.1).
///
/// Uses a proper Biscuit datalog authorizer query rather than substring matching.
/// The token must also be valid and not expired at `now_secs`.
///
/// This function uses a single authorizer instance for both the expiry check and
/// the caveat query, minimising Datalog execution budget consumption.
pub fn has_caveat(
    token_bytes: &[u8],
    caveat: &str,
    root_ca_public_key: &[u8],
    now_secs: i64,
) -> bool {
    let public_key = match PublicKey::from_bytes(root_ca_public_key, Algorithm::Ed25519) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let token = match Biscuit::from(token_bytes, public_key) {
        Ok(t) => t,
        Err(_) => return false,
    };

    // Build a fake_now SystemTime from now_secs for expiration checking (same pattern as verify_token).
    let fake_now = UNIX_EPOCH + Duration::from_secs(now_secs.max(0) as u64);
    let time_fact = fact("time", &[date(&fake_now)]);

    // Build the authorizer: inject time fact so check_expiration_date works,
    // then allow_all so we can do our own caveat query afterward.
    let mut authorizer = match AuthorizerBuilder::new()
        .fact(time_fact)
        .map_err(|_| ())
        .and_then(|b| b.allow_all().build(&token).map_err(|_| ()))
    {
        Ok(a) => a,
        Err(_) => return false,
    };

    // authorize() enforces TTL (check_expiration_date) and signature; fail fast if expired/invalid.
    if authorizer.authorize().is_err() {
        return false;
    }

    // Query for the caveat fact: caveat($x) where $x == caveat string.
    let results: Vec<(String,)> = authorizer
        .query("data($x) <- caveat($x)")
        .unwrap_or_default();

    results.into_iter().any(|(v,)| v == caveat)
}

/// Verify that a Biscuit token is valid (signature + expiry) without extracting claims,
/// and simultaneously check for a required caveat fact.
///
/// This single-authorizer function replaces the two-step pattern of calling
/// `verify_token_expiry_only` followed by `has_caveat`, halving the number of
/// Datalog authorizer runs and reducing execution budget consumption. The
/// `verify_disaster_alert_token` path in `saturate.rs` uses this function.
///
/// Returns `Ok(true)` if valid and caveat present, `Ok(false)` if valid but
/// caveat absent, `Err` if the token is invalid or expired.
pub fn verify_and_check_caveat(
    token_bytes: &[u8],
    caveat: &str,
    root_ca_public_key: &[u8],
    now_secs: i64,
) -> Result<bool, TirBaseError> {
    let public_key =
        PublicKey::from_bytes(root_ca_public_key, Algorithm::Ed25519).map_err(|e| {
            TirBaseError::AuthorisationFailed {
                reason: format!("invalid root CA public key: {e}"),
            }
        })?;

    let token =
        Biscuit::from(token_bytes, public_key).map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("failed to parse/verify Biscuit token: {e}"),
        })?;

    let fake_now = UNIX_EPOCH + Duration::from_secs(now_secs.max(0) as u64);
    let time_fact = fact("time", &[date(&fake_now)]);

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

    // Use authorize_with_limits with a generous per-call budget so that cumulative
    // world.iterations from the initial run() pass does not exhaust the 100-iteration
    // default limit when authorize() and query() are both called on the same authorizer.
    let generous = biscuit_auth::AuthorizerLimits {
        max_facts: 10_000,
        max_iterations: 10_000,
        max_time: Duration::from_secs(5),
    };
    authorizer
        .authorize_with_limits(generous.clone())
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("token authorization failed (possibly expired): {e}"),
        })?;

    // Query for the caveat fact in the same authorizer run (no additional authorize() call).
    let results: Result<Vec<(String,)>, _> =
        authorizer.query_with_limits("data($x) <- caveat($x)", generous);
    let has_it = results
        .unwrap_or_default()
        .into_iter()
        .any(|(v,)| v == caveat);
    Ok(has_it)
}

/// Verify that a Biscuit token is valid (signature + expiry) without extracting claims.
///
/// This is a lighter variant of `verify_token` that skips the three extra Datalog
/// queries (did, role, issued_at). It is used by `verify_disaster_alert_token` in
/// `saturate.rs` to reduce Datalog execution budget consumption.
pub fn verify_token_expiry_only(
    token_bytes: &[u8],
    root_ca_public_key: &[u8],
    now_secs: i64,
) -> Result<(), TirBaseError> {
    let public_key =
        PublicKey::from_bytes(root_ca_public_key, Algorithm::Ed25519).map_err(|e| {
            TirBaseError::AuthorisationFailed {
                reason: format!("invalid root CA public key: {e}"),
            }
        })?;

    let token =
        Biscuit::from(token_bytes, public_key).map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("failed to parse/verify Biscuit token: {e}"),
        })?;

    let fake_now = UNIX_EPOCH + Duration::from_secs(now_secs.max(0) as u64);
    let time_fact = fact("time", &[date(&fake_now)]);

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

    authorizer
        .authorize()
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("token authorization failed (possibly expired): {e}"),
        })?;

    Ok(())
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
        let token_bytes = create_token("did:key:z6MkTest", "admin", 3600, &priv_key, false)
            .expect("create_token should succeed");
        assert!(!token_bytes.is_empty(), "token bytes should not be empty");

        let claims =
            verify_token(&token_bytes, &pub_key, now_secs()).expect("verify_token should succeed");
        assert_eq!(claims.did, "did:key:z6MkTest");
        assert_eq!(claims.role, "admin");
    }

    #[test]
    fn test_ttl_too_short_rejected() {
        let (priv_key, _) = make_ca_keys();
        let result = create_token("did:key:z6MkTest", "user", 3599, &priv_key, false);
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
        let result = create_token("did:key:z6MkTest", "user", 86401, &priv_key, false);
        assert!(
            result.is_err(),
            "TTL > 24h should be rejected without override"
        );
    }

    #[test]
    fn test_ttl_extended_with_accepted_risk_override() {
        let (priv_key, pub_key) = make_ca_keys();
        // 48h with the override flag — should succeed.
        let token_bytes = create_token("did:key:z6MkExtended", "admin", 48 * 3600, &priv_key, true)
            .expect("create_token with accepted-risk override should succeed for 48h");
        assert!(!token_bytes.is_empty(), "token bytes should not be empty");

        // Verify it still works at the 48h expiry window.
        let claims = verify_token(&token_bytes, &pub_key, now_secs())
            .expect("extended token should verify at issue time");
        assert_eq!(claims.did, "did:key:z6MkExtended");
    }

    #[test]
    fn test_ttl_extended_without_override_rejected() {
        let (priv_key, _) = make_ca_keys();
        // 48h without the override flag — should be rejected.
        let result = create_token("did:key:z6MkExtended", "admin", 48 * 3600, &priv_key, false);
        assert!(
            result.is_err(),
            "TTL > 24h should be rejected without override"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("accepted-risk override"),
            "error should mention override: {err}"
        );
    }

    #[test]
    fn test_ttl_above_ceiling_rejected_even_with_override() {
        let (priv_key, _) = make_ca_keys();
        // 8 days — above the 7-day ceiling even with the override.
        let result = create_token(
            "did:key:z6MkTooLong",
            "admin",
            8 * 24 * 3600,
            &priv_key,
            true,
        );
        assert!(
            result.is_err(),
            "TTL above 7-day ceiling should be rejected even with override"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("ceiling"),
            "error should mention ceiling: {err}"
        );
    }

    #[test]
    fn test_expired_token_rejected() {
        let (priv_key, pub_key) = make_ca_keys();
        // Create a token with 1h TTL
        let token_bytes =
            create_token("did:key:z6MkExp", "viewer", 3600, &priv_key, false).unwrap();

        // Verify at a time far in the future (25 hours from now)
        let future_secs = now_secs() + 25 * 3600;
        let result = verify_token(&token_bytes, &pub_key, future_secs);
        assert!(result.is_err(), "expired token should be rejected");
    }

    #[test]
    fn test_verify_with_wrong_key_fails() {
        let (priv_key, _pub_key) = make_ca_keys();
        let (_other_priv, other_pub) = make_ca_keys();

        let token_bytes = create_token("did:key:z6Mk", "admin", 3600, &priv_key, false).unwrap();
        let result = verify_token(&token_bytes, &other_pub, now_secs());
        assert!(
            result.is_err(),
            "token verified with wrong public key should fail"
        );
    }

    // ── has_caveat() tests ────────────────────────────────────────────────────

    /// Helper: build a token with an arbitrary extra role fact, using the given CA keypair bytes.
    fn make_token_with_facts(priv_key: &[u8], extra_facts: &[&str], ttl_secs: u64) -> Vec<u8> {
        use biscuit_auth::{builder_ext::BuilderExt, Biscuit};
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let issued_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let expiry = SystemTime::now() + Duration::from_secs(ttl_secs);

        let mut builder = Biscuit::builder()
            .fact(format!("did(\"did:key:z6MkTest\")").as_str())
            .unwrap()
            .fact(format!("role(\"manager\")").as_str())
            .unwrap()
            .fact(format!("issued_at({issued_secs})").as_str())
            .unwrap()
            .check_expiration_date(expiry);

        for fact_str in extra_facts {
            builder = builder.fact(*fact_str).unwrap();
        }

        let kp = KeyPair::from(&PrivateKey::from_bytes(priv_key, Algorithm::Ed25519).unwrap());
        builder.build(&kp).unwrap().to_vec().unwrap()
    }

    #[test]
    fn has_caveat_returns_true_for_token_with_disaster_alert() {
        let (priv_key, pub_key) = make_ca_keys();
        let token_bytes = make_token_with_facts(&priv_key, &["caveat(\"disaster-alert\")"], 3600);
        let now = now_secs();
        assert!(
            has_caveat(&token_bytes, "disaster-alert", &pub_key, now),
            "should return true for a valid token carrying disaster-alert caveat"
        );
    }

    #[test]
    fn has_caveat_returns_false_for_token_without_disaster_alert() {
        let (priv_key, pub_key) = make_ca_keys();
        // Build a token with NO disaster-alert fact.
        let token_bytes = make_token_with_facts(&priv_key, &[], 3600);
        let now = now_secs();
        assert!(
            !has_caveat(&token_bytes, "disaster-alert", &pub_key, now),
            "should return false for a token without the disaster-alert caveat"
        );
    }

    #[test]
    fn has_caveat_returns_false_for_expired_token_with_disaster_alert() {
        let (priv_key, pub_key) = make_ca_keys();
        // Token has disaster-alert but only 1h TTL.
        let token_bytes = make_token_with_facts(&priv_key, &["caveat(\"disaster-alert\")"], 3600);
        // Check 25 hours in the future — well past the 1h TTL.
        let far_future = now_secs() + 25 * 3600;
        assert!(
            !has_caveat(&token_bytes, "disaster-alert", &pub_key, far_future),
            "should return false for an expired token even if it carries disaster-alert"
        );
    }

    #[test]
    fn has_caveat_returns_false_when_token_text_contains_alert_as_substring_of_other_fact() {
        // Regression test for the old string-search bug:
        // A token containing a role like "disaster_alert_manager" textually includes
        // "alert" and even "disaster" but must NOT match a check for caveat("disaster-alert").
        let (priv_key, pub_key) = make_ca_keys();
        let token_bytes =
            make_token_with_facts(&priv_key, &["role(\"disaster_alert_manager\")"], 3600);
        let now = now_secs();
        assert!(
            !has_caveat(&token_bytes, "disaster-alert", &pub_key, now),
            "substring match on role fact must NOT satisfy the disaster-alert caveat check"
        );
    }
}
