//! CapabilityManager — Biscuit token verification, TrustLevel state machine (Req 8).
//!
//! Also re-exports the `RevocationSubsystem` (Req 9) for use by the API layer.

#![allow(dead_code, unused_variables, unused_imports)]

pub mod biscuit;
pub mod revocation;
pub mod root_ca;
pub mod trust;

pub use revocation::{
    DeviceRevocationStatus, ManagerSignature, PendingRevocationStore, RevocationDelta,
    RevocationStatus, RevocationSubsystem,
};

use crate::api::types::{TrustLevel, UnverifiedWarning};
use crate::errors::TirBaseError;
use root_ca::RootCaRegistry;
use trust::TrustLevelStateMachine;

/// The Capability Manager handles Biscuit token creation and offline verification,
/// TrustLevel state transitions, and the M-of-N revocation accumulation.
pub struct CapabilityManager {
    /// TrustLevel state machine for the local device.
    trust_state: TrustLevelStateMachine,
    /// Read-only registry of root CA public keys.
    root_ca_registry: RootCaRegistry,
    /// Pending M-of-N revocation accumulation (retained for legacy callers).
    pending_revocations: PendingRevocationStore,
    /// M threshold for revocation (minimum signatures required).
    revocation_m: usize,
    /// N threshold for revocation (total managers in the set).
    revocation_n: usize,
    /// Whether the deployment has explicitly accepted the >24h TTL risk
    /// (Req 8.7 "accepted risk" escape path).  Set when `biscuit_ttl_secs`
    /// exceeds 24h at init, which triggers the EXTENDED_TTL diagnostic (Req 21.6).
    /// Stored here so that `create_token` can be called via `CapabilityManager`
    /// without re-reading the config.
    extended_ttl_accepted_risk: bool,
    /// Optional timestamp of the last revocation delta applied.
    last_revocation_ts: Option<i64>,
}

impl CapabilityManager {
    /// Initialise the Capability Manager with the given deployment CA keys and M-of-N config.
    ///
    /// The initial trust level starts as `Unverified` until a valid Biscuit token is presented.
    /// `extended_ttl_accepted_risk` should be `true` when the deployment has
    /// explicitly opted into >24h Biscuit TTLs (via the EXTENDED_TTL diagnostic
    /// at init — Req 21.6), allowing `create_token` to mint extended-window
    /// tokens (Req 8.7).
    pub fn new(
        root_ca_keys: Vec<[u8; 32]>,
        revocation_m: usize,
        revocation_n: usize,
        extended_ttl_accepted_risk: bool,
    ) -> Self {
        Self {
            trust_state: TrustLevelStateMachine::new(TrustLevel::Unverified),
            root_ca_registry: RootCaRegistry::new(root_ca_keys),
            pending_revocations: PendingRevocationStore::default(),
            revocation_m,
            revocation_n,
            extended_ttl_accepted_risk,
            last_revocation_ts: None,
        }
    }

    /// Verify a Biscuit token and update TrustLevel if valid (Req 8.3).
    ///
    /// On success: transitions to `Verified` and returns the current trust level.
    /// On failure: returns the error without modifying state.
    pub fn verify_token(
        &mut self,
        token_bytes: &[u8],
        now_secs: i64,
    ) -> Result<TrustLevel, TirBaseError> {
        // The device must not be in REVOKED state — a revoked device cannot re-verify.
        if self.trust_state.level() == TrustLevel::Revoked {
            return Err(TirBaseError::AuthorisationFailed {
                reason: "device is REVOKED; token verification is not permitted".to_string(),
            });
        }

        // Try each registered root CA public key
        let ca_keys: Vec<[u8; 32]> = self.root_ca_registry.keys().to_vec();
        let mut last_err: Option<TirBaseError> = None;

        for ca_key in &ca_keys {
            match biscuit::verify_token(token_bytes, ca_key, now_secs) {
                Ok(_claims) => {
                    self.trust_state.on_valid_token();
                    return Ok(self.trust_state.level());
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(
            last_err.unwrap_or_else(|| TirBaseError::AuthorisationFailed {
                reason: "no registered root CA keys".to_string(),
            }),
        )
    }

    /// Mark the token as expired and transition to UNVERIFIED (Req 8.4).
    pub fn on_token_expired(&mut self, now_micros: i64) {
        self.trust_state.on_token_expired(now_micros);
    }

    /// Return the current TrustLevel of the local device (Req 2.4, 8.2).
    pub fn trust_level(&self) -> TrustLevel {
        self.trust_state.level()
    }

    /// Apply the REVOKED trust level from a validated Revocation_Delta (Req 8.5, 9.4).
    pub fn apply_revocation(&mut self) -> Result<(), TirBaseError> {
        self.trust_state.on_revocation();
        self.last_revocation_ts = Some(current_timestamp_micros());
        Ok(())
    }

    /// Return the UNVERIFIED warning if the device is currently unverified (Req 8.4).
    ///
    /// This warning must be attached to every operation response while in UNVERIFIED state.
    pub fn unverified_warning(&self) -> Option<UnverifiedWarning> {
        self.trust_state.unverified_warning()
    }

    /// Return a 1-of-1 configuration warning if applicable (Req 9.7).
    ///
    /// When M=1, N=1, a single Manager has unilateral exile power, which should
    /// be surfaced to the operator at config load time.
    pub fn check_1_of_1_warning(&self) -> Option<String> {
        PendingRevocationStore::check_1_of_1_warning(self.revocation_m, self.revocation_n)
    }

    /// Timestamp of the last revocation delta applied to this manager.
    pub fn last_revocation_timestamp(&self) -> Option<i64> {
        self.last_revocation_ts
    }

    /// Access the pending revocation store (for mesh gossip integration).
    pub fn pending_revocations_mut(&mut self) -> &mut PendingRevocationStore {
        &mut self.pending_revocations
    }

    /// Return the primary root CA public key for offline Biscuit token verification (Req 8.1).
    ///
    /// Returns `Some([u8; 32])` if at least one root CA key is registered, or `None` if
    /// the registry is empty (e.g. not yet configured at init time for v1).
    pub fn root_ca_primary_key(&self) -> Option<[u8; 32]> {
        self.root_ca_registry.primary_key().copied()
    }

    /// Whether the deployment has explicitly accepted the >24h TTL risk (Req 8.7).
    ///
    /// Set when `biscuit_ttl_secs` exceeds 24h at init (which triggers the
    /// `EXTENDED_TTL` diagnostic, Req 21.6).  When `true`, `create_token` can
    /// mint tokens with TTLs beyond the default 24h cap (up to
    /// [`crate::auth::biscuit::TTL_OVERRIDE_CEILING_SECS`]).
    pub fn extended_ttl_accepted_risk(&self) -> bool {
        self.extended_ttl_accepted_risk
    }

    /// Mint a Biscuit token using the deployment's configured TTL and accepted-risk
    /// flag (Req 8.7).  The token is signed by the deployment's root CA private key.
    ///
    /// The `ttl_secs` parameter overrides the configured `biscuit_ttl_secs` when
    /// provided; otherwise the configured value is used.  The `extended_ttl_accepted_risk`
    /// flag is passed through to `biscuit::create_token` so that tokens with TTL
    /// > 24h are only created when the deployment has explicitly opted in.
    pub fn mint_token(
        &self,
        did: &str,
        role: &str,
        root_ca_private_key: &[u8],
        ttl_secs: Option<u64>,
    ) -> Result<Vec<u8>, TirBaseError> {
        let effective_ttl = ttl_secs.unwrap_or(crate::api::types::DEFAULT_BISCUIT_TTL_SECS);
        biscuit::create_token(
            did,
            role,
            effective_ttl,
            root_ca_private_key,
            self.extended_ttl_accepted_risk,
        )
    }

    /// Register an additional root CA public key at runtime, and optionally
    /// verify a Biscuit token against the newly-registered key (Req 8.1, 8.3).
    ///
    /// When `token_bytes` is `Some`, the token is verified immediately after
    /// the key is registered, transitioning `TrustLevel` to `Verified` if valid.
    /// Returns the current trust level after the operation.
    ///
    /// The key takes effect immediately for subsequent [`Self::verify_token`] calls
    /// and is exposed via [`Self::root_ca_primary_key`] if it is the only/primary key.
    pub(crate) fn register_root_ca_key(
        &mut self,
        key: [u8; 32],
        token_bytes: Option<(&[u8], i64)>,
    ) -> Result<TrustLevel, TirBaseError> {
        self.root_ca_registry.register(key);
        if let Some((token, now_secs)) = token_bytes {
            self.verify_token(token, now_secs)
        } else {
            Ok(self.trust_level())
        }
    }
}

fn current_timestamp_micros() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager(m: usize, n: usize) -> CapabilityManager {
        CapabilityManager::new(vec![], m, n, false)
    }

    #[test]
    fn test_1_of_1_warning_emitted() {
        let mgr = make_manager(1, 1);
        let warning = mgr.check_1_of_1_warning();
        assert!(warning.is_some(), "1-of-1 should emit a warning");
    }

    #[test]
    fn test_no_warning_for_2_of_3() {
        let mgr = make_manager(2, 3);
        let warning = mgr.check_1_of_1_warning();
        assert!(warning.is_none(), "2-of-3 should not emit a warning");
    }

    #[test]
    fn test_apply_revocation_sets_revoked() {
        let mut mgr = make_manager(2, 3);
        assert_eq!(mgr.trust_level(), TrustLevel::Unverified);

        mgr.apply_revocation()
            .expect("apply_revocation should succeed");
        assert_eq!(
            mgr.trust_level(),
            TrustLevel::Revoked,
            "trust level should be REVOKED after apply_revocation"
        );
    }

    #[test]
    fn test_revoked_device_cannot_verify_token() {
        let mut mgr = make_manager(2, 3);
        mgr.apply_revocation().unwrap();

        let result = mgr.verify_token(b"fake-token", 0);
        assert!(
            result.is_err(),
            "revoked device should not be able to verify tokens"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("REVOKED"),
            "error should mention REVOKED: {err}"
        );
    }

    #[test]
    fn test_initial_trust_level_is_unverified() {
        let mgr = make_manager(2, 3);
        assert_eq!(mgr.trust_level(), TrustLevel::Unverified);
    }

    #[test]
    fn test_on_token_expired_transitions_to_unverified_from_verified() {
        let mut mgr = CapabilityManager::new(vec![], 2, 3, false);
        // Manually set to verified via trust_state
        mgr.trust_state.on_valid_token();
        assert_eq!(mgr.trust_level(), TrustLevel::Verified);

        mgr.on_token_expired(1_000_000);
        assert_eq!(mgr.trust_level(), TrustLevel::Unverified);
    }

    #[test]
    fn test_unverified_warning_present_when_unverified() {
        let mut mgr = make_manager(2, 3);
        // Starts as Unverified but with no timestamp — need to trigger expiry
        mgr.trust_state.on_valid_token(); // VERIFIED
        mgr.on_token_expired(5_000_000); // UNVERIFIED
        let warning = mgr.unverified_warning();
        assert!(warning.is_some(), "should produce warning when UNVERIFIED");
        assert_eq!(warning.unwrap().unverified_since, 5_000_000);
    }

    #[test]
    fn test_revocation_timestamp_set_after_apply() {
        let mut mgr = make_manager(2, 3);
        assert!(mgr.last_revocation_timestamp().is_none());
        mgr.apply_revocation().unwrap();
        assert!(
            mgr.last_revocation_timestamp().is_some(),
            "revocation timestamp should be set"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_verify_token_with_valid_biscuit() {
        use biscuit_auth::{builder::Algorithm, KeyPair};

        // Generate a root CA keypair for this test
        let kp = KeyPair::new();
        let private_bytes = kp.private().to_bytes().to_vec();
        let public_bytes: [u8; 32] = kp
            .public()
            .to_bytes()
            .try_into()
            .expect("public key should be 32 bytes");

        let mut mgr = CapabilityManager::new(vec![public_bytes], 2, 3, false);

        // Create a valid token
        let token_bytes =
            biscuit::create_token("did:key:z6MkTest", "admin", 3600, &private_bytes, false)
                .expect("create_token should succeed");

        use std::time::{SystemTime, UNIX_EPOCH};
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let level = mgr
            .verify_token(&token_bytes, now_secs)
            .expect("verify_token should succeed");
        assert_eq!(level, TrustLevel::Verified);
    }
}
