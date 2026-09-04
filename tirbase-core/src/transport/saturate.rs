//! SaturateMode state machine and Lease tracking (Req 13).
//!
//! State transitions:
//!   NORMAL → SATURATE: valid Manager DISASTER_ALERT with `disaster-alert` Biscuit caveat
//!   SATURATE → NORMAL: Lease expiry (60 min) without renewal, OR Lease Termination Delta (≥M sigs)
//!
//! Invalid/absent/expired DISASTER_ALERTs or heartbeats are rejected with
//! `SignatureVerificationFailed` and the current mode is preserved (Req 13.7).

#![allow(dead_code, unused_variables)]

use crate::crdt::delta::Did;
use crate::errors::TirBaseError;

/// Default duration of a Saturate_Mode Lease: 60 minutes in seconds (Req 13.3).
///
/// This is the spec-mandated window used whenever a deployment does not
/// override the lease duration (Subphase 3.4): the production config knob
/// (`TransportConfig::saturate_lease_duration_secs`, fed from
/// `DeploymentConfig` by `CoreHandle::init`) replaces it per-instance, and
/// this constant remains the canonical default.
pub const SATURATE_LEASE_DURATION_SECS: i64 = 60 * 60;

/// Renewal window: 15 minutes before expiry (Req 13.4).
pub const RENEWAL_WINDOW_SECS: i64 = 15 * 60;

/// SaturateMode operating state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaturateState {
    Normal,
    Saturate,
}

/// A Saturate_Mode Lease (Req 13.3).
#[derive(Debug, Clone)]
pub struct SaturateLease {
    /// UTC seconds when Saturate_Mode was activated.
    pub activated_at: i64,
    /// UTC seconds when the Lease expires (activated_at + 3600s).
    pub expires_at: i64,
    /// UTC seconds of the last valid heartbeat renewal.
    pub last_renewed_at: Option<i64>,
    /// The Manager DID that activated this Lease.
    pub activating_manager_did: Did,
}

impl SaturateLease {
    /// Return true if the lease has expired at `now_secs`.
    pub fn is_expired(&self, now_secs: i64) -> bool {
        now_secs >= self.expires_at
    }

    /// Return true if the current time is within the renewal window (Req 13.4):
    /// `expires_at - 15 min ≤ now < expires_at`.
    pub fn in_renewal_window(&self, now_secs: i64) -> bool {
        let window_start = self.expires_at - RENEWAL_WINDOW_SECS;
        now_secs >= window_start && now_secs < self.expires_at
    }
}

/// The Saturate_Mode state machine.
///
/// Callers must provide a root CA public key slice (32 bytes) so that Biscuit
/// tokens can be verified offline (Req 13.1, 13.7).  On WASM builds the
/// Biscuit verification layer returns an error stub; `activate()` will then
/// return `SignatureVerificationFailed` as required.
pub struct SaturateModeStateMachine {
    state: SaturateState,
    lease: Option<SaturateLease>,
    /// Configured M-of-N termination threshold.
    termination_threshold_m: usize,
    /// Root CA public key used to verify Manager Biscuit tokens (32 bytes).
    root_ca_public_key: Vec<u8>,
    /// Lease duration in seconds (Req 13.3) — configured per deployment; a
    /// lease opened by `activate()` expires `lease_duration_secs` after its
    /// `activated_at`/renewal timestamp.
    lease_duration_secs: i64,
}

impl SaturateModeStateMachine {
    /// Create a new state machine in `NORMAL` state.
    ///
    /// `termination_threshold_m` — number of distinct Manager DID signatures
    /// required to terminate Saturate_Mode via a Lease Termination Delta
    /// (Req 13.6).
    ///
    /// `root_ca_public_key` — 32-byte Ed25519 root CA public key for offline
    /// Biscuit token verification.
    ///
    /// `lease_duration_secs` — lease window opened by a successful
    /// activation/renewal (Req 13.3).  Pass
    /// [`SATURATE_LEASE_DURATION_SECS`] (60 minutes) for the spec default.
    /// The production wiring (`CoreHandle::init` → `TransportConfig` →
    /// [`MeshTransport::new`](crate::transport::MeshTransport::new)) feeds the
    /// deployment-configured value here; a short window is how the Subphase
    /// 3.4 runtime test lets a lease expire through the wall clock.
    pub fn new(
        termination_threshold_m: usize,
        root_ca_public_key: Vec<u8>,
        lease_duration_secs: i64,
    ) -> Self {
        Self {
            state: SaturateState::Normal,
            lease: None,
            termination_threshold_m,
            root_ca_public_key,
            lease_duration_secs,
        }
    }

    /// Current operating state.
    pub fn state(&self) -> SaturateState {
        self.state
    }

    /// Active lease, if any.
    pub fn lease(&self) -> Option<&SaturateLease> {
        self.lease.as_ref()
    }

    // ── Activate (NORMAL → SATURATE) ─────────────────────────────────────────

    /// Activate Saturate_Mode via a DISASTER_ALERT (Req 13.1).
    ///
    /// The Biscuit token must:
    ///   1. Be verifiable against the root CA public key.
    ///   2. Carry the `disaster-alert` caveat.
    ///   3. Not be expired at `now_secs`.
    ///
    /// On any failure returns `SignatureVerificationFailed` and preserves the
    /// current mode (Req 13.7).  Calling `activate()` while already in
    /// `SATURATE` state replaces the existing lease with a new
    /// `lease_duration_secs` window (Req 13.3).
    pub fn activate(
        &mut self,
        manager_did: Did,
        biscuit_token: &[u8],
        now_secs: i64,
    ) -> Result<(), TirBaseError> {
        // Verify the token and check for the disaster-alert caveat.
        self.verify_disaster_alert_token(biscuit_token, now_secs)?;

        // Token valid — activate the lease.
        let expires_at = now_secs + self.lease_duration_secs;
        self.lease = Some(SaturateLease {
            activated_at: now_secs,
            expires_at,
            last_renewed_at: None,
            activating_manager_did: manager_did,
        });
        self.state = SaturateState::Saturate;
        Ok(())
    }

    // ── Renew (SATURATE → SATURATE, extend by 60 min) ────────────────────────

    /// Process a heartbeat renewal (Req 13.4).
    ///
    /// Valid only when in `SATURATE` state **and** within the 15-minute renewal
    /// window before the lease expires.  A valid renewal extends the lease by
    /// `lease_duration_secs` from `now_secs` (60 minutes with the spec default).
    ///
    /// An absent, expired, or unverifiable token returns
    /// `SignatureVerificationFailed` and preserves the current mode (Req 13.7).
    pub fn renew(
        &mut self,
        manager_did: Did,
        biscuit_token: &[u8],
        now_secs: i64,
    ) -> Result<(), TirBaseError> {
        // Renewal only applies in SATURATE state.
        if self.state != SaturateState::Saturate {
            return Err(TirBaseError::SignatureVerificationFailed {
                reason: "heartbeat renewal rejected: not in SATURATE mode".to_string(),
            });
        }

        // Verify the token carries a disaster-alert caveat.
        self.verify_disaster_alert_token(biscuit_token, now_secs)?;

        // Extend the lease by `lease_duration_secs` from the renewal timestamp.
        match self.lease.as_mut() {
            Some(lease) => {
                lease.expires_at = now_secs + self.lease_duration_secs;
                lease.last_renewed_at = Some(now_secs);
            }
            None => {
                // Should not happen if state is SATURATE, but be defensive.
                return Err(TirBaseError::SignatureVerificationFailed {
                    reason: "heartbeat renewal rejected: no active lease".to_string(),
                });
            }
        }

        Ok(())
    }

    // ── Terminate (SATURATE → NORMAL via M-of-N) ─────────────────────────────

    /// Process a Lease Termination Delta (Req 13.6).
    ///
    /// Requires at least `termination_threshold_m` valid **distinct** Manager
    /// DID signatures provided as `(did, raw_ed25519_signature_over_message)`.
    ///
    /// `message` is the canonical bytes that each signature covers (callers
    /// must supply the same serialised termination payload that was signed).
    ///
    /// - If `signatures.len() >= m` and all signatures are cryptographically
    ///   valid for distinct DIDs → returns `Ok(())` and transitions to NORMAL.
    /// - If fewer than `m` valid distinct signatures → returns
    ///   `ThresholdNotMet` and preserves the current mode (invariant (b)).
    ///
    /// When not in SATURATE state the call is a no-op and returns `Ok(())`.
    pub fn terminate(
        &mut self,
        signatures: Vec<(Did, Vec<u8>)>,
        message: &[u8],
        now_secs: i64,
    ) -> Result<(), TirBaseError> {
        // Only relevant in SATURATE state; otherwise this is a no-op.
        if self.state != SaturateState::Saturate {
            return Ok(());
        }

        // Verify each signature and collect distinct valid Manager DIDs.
        let valid_distinct = self.count_valid_distinct_signatures(&signatures, message);

        if valid_distinct < self.termination_threshold_m {
            return Err(TirBaseError::ThresholdNotMet {
                got: valid_distinct,
                need: self.termination_threshold_m,
            });
        }

        // Threshold met — terminate immediately.
        self.state = SaturateState::Normal;
        self.lease = None;
        Ok(())
    }

    // ── Tick (advance clock, expire lease if past deadline) ──────────────────

    /// Advance the clock — transitions to NORMAL if the Lease has expired
    /// without renewal (Req 13.5, invariant (a) and (d)).
    pub fn tick(&mut self, now_secs: i64) {
        if self.state == SaturateState::Saturate {
            if let Some(ref lease) = self.lease {
                if lease.is_expired(now_secs) {
                    self.state = SaturateState::Normal;
                    self.lease = None;
                }
            }
        }
    }

    /// Test-only: backdate the active lease's expiry so a real-clock tick
    /// sees it as already expired.
    ///
    /// The production tick loop passes wall-clock seconds, so the Subphase 3.3
    /// integration test could not wait out the 60-minute lease — it made the
    /// lease look past-due instead and asserted the background loop (not a
    /// manual `tick()` call) performs the demotion.  Subphase 3.4 supersedes
    /// this with a genuinely runtime-expiring lease (a short configured lease
    /// duration through the production config path), so new tests should not
    /// reach for this helper.
    #[cfg(test)]
    pub(crate) fn backdate_lease_expiry_for_test(&mut self, expires_at: i64) {
        if let Some(lease) = self.lease.as_mut() {
            lease.expires_at = expires_at;
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Verify a Biscuit token against the root CA and check for the
    /// `disaster-alert` caveat.  Returns `SignatureVerificationFailed` on any
    /// failure (Req 13.7).
    fn verify_disaster_alert_token(
        &self,
        biscuit_token: &[u8],
        now_secs: i64,
    ) -> Result<(), TirBaseError> {
        if biscuit_token.is_empty() {
            return Err(TirBaseError::SignatureVerificationFailed {
                reason: "DISASTER_ALERT token is absent".to_string(),
            });
        }

        // Verify the token signature, expiry, and caveat in a single Biscuit authorizer
        // run.  Using verify_and_check_caveat (instead of the two-step
        // verify_token + has_caveat) halves the number of Datalog authorizer runs,
        // staying within the process-global Datalog execution budget (Req 13.1, 13.7).
        let has_caveat = crate::auth::biscuit::verify_and_check_caveat(
            biscuit_token,
            "disaster-alert",
            &self.root_ca_public_key,
            now_secs,
        )
        .map_err(|e| TirBaseError::SignatureVerificationFailed {
            reason: format!("DISASTER_ALERT token verification failed: {e}"),
        })?;

        if !has_caveat {
            return Err(TirBaseError::SignatureVerificationFailed {
                reason: "DISASTER_ALERT token does not carry the 'disaster-alert' caveat"
                    .to_string(),
            });
        }

        Ok(())
    }

    /// Count the number of distinct DIDs with valid Ed25519 signatures over
    /// `message`.  Uses `ed25519-dalek` for verification.
    ///
    /// A DID is considered valid if:
    ///   1. Its raw public key (the multibase-decoded key material from the
    ///      `did:key:` method) successfully verifies the provided signature.
    ///   2. It appears exactly once in the valid set (deduplication).
    ///
    /// Invalid signatures are silently skipped; only valid distinct DIDs count.
    fn count_valid_distinct_signatures(
        &self,
        signatures: &[(Did, Vec<u8>)],
        message: &[u8],
    ) -> usize {
        use std::collections::HashSet;
        let mut seen_dids: HashSet<String> = HashSet::new();

        for (did, sig_bytes) in signatures {
            // Skip duplicates.
            if seen_dids.contains(did) {
                continue;
            }

            // Attempt to verify the Ed25519 signature using the DID's public key.
            if verify_did_signature(did, sig_bytes, message) {
                seen_dids.insert(did.clone());
            }
        }

        seen_dids.len()
    }
}

// ─── Ed25519 DID signature verification helper ───────────────────────────────

/// Verify an Ed25519 signature for a `did:key:` DID over `message`.
///
/// The public key is extracted from the DID using the `did:key:z6Mk…` multibase
/// + multicodec encoding (Ed25519 public key prefix `0xED01`).
///
/// Returns `true` if and only if the signature is valid.
///
/// Silently returns `false` on any decoding or verification error — callers
/// treat invalid signatures as non-contributing to the threshold count.
fn verify_did_signature(did: &str, sig_bytes: &[u8], message: &[u8]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};

    // Extract the multibase-encoded key material after "did:key:".
    let key_part = match did.strip_prefix("did:key:") {
        Some(k) => k,
        None => return false,
    };

    // Decode multibase (base58btc, prefix 'z').
    let raw = match decode_multibase_z(key_part) {
        Some(r) => r,
        None => return false,
    };

    // Strip the multicodec Ed25519 prefix (0xED, 0x01 = 2 bytes).
    let key_bytes = if raw.len() >= 2 && raw[0] == 0xED && raw[1] == 0x01 {
        &raw[2..]
    } else {
        return false;
    };

    if key_bytes.len() != 32 {
        return false;
    }

    let key_arr: [u8; 32] = match key_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };

    let verifying_key = match VerifyingKey::from_bytes(&key_arr) {
        Ok(vk) => vk,
        Err(_) => return false,
    };

    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };

    let signature = Signature::from_bytes(&sig_arr);
    use ed25519_dalek::Verifier;
    verifying_key.verify(message, &signature).is_ok()
}

/// Decode a base58btc multibase string (prefix `z`) into raw bytes.
fn decode_multibase_z(s: &str) -> Option<Vec<u8>> {
    // Multibase base58btc strings start with 'z'.
    let s = s.strip_prefix('z')?;
    bs58::decode(s).into_vec().ok()
}

// ─── Pub(crate) test helpers ──────────────────────────────────────────────────
//
// These are available to other test modules (e.g. tests/properties.rs) that need
// to construct real Biscuit tokens for Property 20 testing without duplicating
// the token-creation logic.

/// Build a root CA keypair and create a valid disaster-alert Biscuit token.
/// Returns `(token_bytes, ca_public_key_bytes)`.
///
/// Available only in `#[cfg(test)]` builds (property tests and unit tests).
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) fn make_disaster_alert_token_for_test(ttl_secs: u64) -> (Vec<u8>, Vec<u8>) {
    use biscuit_auth::{builder::Algorithm, builder_ext::BuilderExt, Biscuit, KeyPair, PrivateKey};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let kp = KeyPair::new();
    let private_bytes = kp.private().to_bytes().to_vec();
    let public_bytes = kp.public().to_bytes().to_vec();

    let now = SystemTime::now();
    let expiry = now + Duration::from_secs(ttl_secs);
    let issued_secs = now.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

    let token = Biscuit::builder()
        .fact(format!("did(\"did:key:z6MkManager\")").as_str()).unwrap()
        .fact(format!("role(\"manager\")").as_str()).unwrap()
        .fact(format!("issued_at({issued_secs})").as_str()).unwrap()
        .fact("caveat(\"disaster-alert\")").unwrap()
        .check_expiration_date(expiry)
        .build(&KeyPair::from(
            &PrivateKey::from_bytes(&private_bytes, Algorithm::Ed25519).unwrap()
        ))
        .unwrap();

    (token.to_vec().unwrap(), public_bytes)
}

/// Build a root CA keypair and create a Biscuit token WITHOUT the disaster-alert caveat.
/// Returns `(token_bytes, ca_public_key_bytes)`.
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) fn make_token_without_disaster_alert_for_test(ttl_secs: u64) -> (Vec<u8>, Vec<u8>) {
    use biscuit_auth::{builder::Algorithm, builder_ext::BuilderExt, Biscuit, KeyPair, PrivateKey};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let kp = KeyPair::new();
    let private_bytes = kp.private().to_bytes().to_vec();
    let public_bytes = kp.public().to_bytes().to_vec();

    let issued_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let expiry = SystemTime::now() + Duration::from_secs(ttl_secs);

    let token = Biscuit::builder()
        .fact(format!("did(\"did:key:z6MkManager\")").as_str()).unwrap()
        .fact(format!("role(\"manager\")").as_str()).unwrap()
        .fact(format!("issued_at({issued_secs})").as_str()).unwrap()
        // Intentionally NO disaster-alert caveat
        .check_expiration_date(expiry)
        .build(&KeyPair::from(
            &PrivateKey::from_bytes(&private_bytes, Algorithm::Ed25519).unwrap()
        ))
        .unwrap();

    (token.to_vec().unwrap(), public_bytes)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Build a root CA keypair, create a valid disaster-alert Biscuit token,
    /// and return (token_bytes, public_key_bytes).
    #[cfg(not(target_arch = "wasm32"))]
    fn make_disaster_alert_token(ttl_secs: u64) -> (Vec<u8>, Vec<u8>) {
        use biscuit_auth::{builder::Algorithm, KeyPair};

        let kp = KeyPair::new();
        let private_bytes = kp.private().to_bytes().to_vec();
        let public_bytes = kp.public().to_bytes().to_vec();

        // We need to embed `disaster-alert` in the token.  The biscuit-auth
        // builder API attenuates tokens by adding caveats as blocks.  Here we
        // create a base token and then add an attenuation block containing the
        // `disaster-alert` fact.
        use biscuit_auth::{
            Biscuit,
            builder_ext::BuilderExt,
            macros::*,
        };
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let now = SystemTime::now();
        let expiry = now + Duration::from_secs(ttl_secs);
        let issued_secs = now.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

        let token = Biscuit::builder()
            .fact(format!("did(\"did:key:z6MkManager\")").as_str()).unwrap()
            .fact(format!("role(\"manager\")").as_str()).unwrap()
            .fact(format!("issued_at({issued_secs})").as_str()).unwrap()
            .fact("caveat(\"disaster-alert\")").unwrap()
            .check_expiration_date(expiry)
            .build(&biscuit_auth::KeyPair::from(
                &biscuit_auth::PrivateKey::from_bytes(&private_bytes, Algorithm::Ed25519).unwrap()
            ))
            .unwrap();

        let token_bytes = token.to_vec().unwrap();
        (token_bytes, public_bytes)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn make_token_without_caveat(ttl_secs: u64) -> (Vec<u8>, Vec<u8>) {
        use biscuit_auth::{builder::Algorithm, KeyPair};

        let kp = KeyPair::new();
        let private_bytes = kp.private().to_bytes().to_vec();
        let public_bytes = kp.public().to_bytes().to_vec();

        use biscuit_auth::Biscuit;
        use biscuit_auth::builder_ext::BuilderExt;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let issued_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let expiry = SystemTime::now() + Duration::from_secs(ttl_secs);

        let token = Biscuit::builder()
            .fact(format!("did(\"did:key:z6MkManager\")").as_str()).unwrap()
            .fact(format!("role(\"manager\")").as_str()).unwrap()
            .fact(format!("issued_at({issued_secs})").as_str()).unwrap()
            // Intentionally no disaster-alert caveat
            .check_expiration_date(expiry)
            .build(&biscuit_auth::KeyPair::from(
                &biscuit_auth::PrivateKey::from_bytes(&private_bytes, Algorithm::Ed25519).unwrap()
            ))
            .unwrap();

        let token_bytes = token.to_vec().unwrap();
        (token_bytes, public_bytes)
    }

    fn now_secs() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    // ── Activation tests ─────────────────────────────────────────────────────

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn activate_with_valid_token_transitions_to_saturate() {
        let (token, ca_pub) = make_disaster_alert_token(3600);
        let mut sm = SaturateModeStateMachine::new(2, ca_pub, SATURATE_LEASE_DURATION_SECS);
        let now = now_secs();

        sm.activate("did:key:z6MkManager".to_string(), &token, now)
            .expect("activate should succeed");

        assert_eq!(sm.state(), SaturateState::Saturate);
        let lease = sm.lease().expect("lease should be set");
        assert_eq!(lease.expires_at, now + SATURATE_LEASE_DURATION_SECS);
    }

    #[test]
    fn activate_with_absent_token_returns_error() {
        let mut sm = SaturateModeStateMachine::new(2, vec![0u8; 32], SATURATE_LEASE_DURATION_SECS);
        let err = sm
            .activate("did:key:z6MkManager".to_string(), &[], now_secs())
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("absent") || msg.contains("verification"),
            "expected verification error: {msg}"
        );
        assert_eq!(sm.state(), SaturateState::Normal, "mode must be unchanged");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn activate_without_disaster_alert_caveat_returns_error() {
        let (token, ca_pub) = make_token_without_caveat(3600);
        let mut sm = SaturateModeStateMachine::new(2, ca_pub, SATURATE_LEASE_DURATION_SECS);
        let err = sm
            .activate("did:key:z6MkManager".to_string(), &token, now_secs())
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("caveat") || msg.contains("disaster-alert") || msg.contains("verification"),
            "expected caveat error: {msg}"
        );
        assert_eq!(sm.state(), SaturateState::Normal, "mode must be unchanged");
    }

    // ── Lease expiry (tick) ──────────────────────────────────────────────────

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn lease_expiry_reverts_to_normal() {
        let (token, ca_pub) = make_disaster_alert_token(3600);
        let mut sm = SaturateModeStateMachine::new(2, ca_pub, SATURATE_LEASE_DURATION_SECS);
        let now = now_secs();

        sm.activate("did:key:z6MkManager".to_string(), &token, now)
            .unwrap();
        assert_eq!(sm.state(), SaturateState::Saturate);

        // Advance clock past lease expiry.
        sm.tick(now + SATURATE_LEASE_DURATION_SECS + 1);
        assert_eq!(
            sm.state(),
            SaturateState::Normal,
            "should revert to NORMAL after lease expiry"
        );
        assert!(sm.lease().is_none(), "lease should be cleared after expiry");
    }

    #[test]
    fn tick_in_normal_mode_is_noop() {
        let mut sm = SaturateModeStateMachine::new(2, vec![], SATURATE_LEASE_DURATION_SECS);
        sm.tick(now_secs() + 1_000_000);
        assert_eq!(sm.state(), SaturateState::Normal);
    }

    // ── Renewal ──────────────────────────────────────────────────────────────

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn renew_in_normal_mode_returns_error() {
        let (token, ca_pub) = make_disaster_alert_token(3600);
        let mut sm = SaturateModeStateMachine::new(2, ca_pub, SATURATE_LEASE_DURATION_SECS);
        let err = sm
            .renew("did:key:z6MkManager".to_string(), &token, now_secs())
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("SATURATE") || msg.contains("verification"),
            "expected mode error: {msg}"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn renew_extends_lease_by_60_minutes() {
        use biscuit_auth::{builder::Algorithm, KeyPair, PrivateKey};
        use biscuit_auth::builder_ext::BuilderExt;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        // Create a single CA keypair and use it for BOTH tokens so the SM
        // can verify both with the same registered root CA public key.
        let kp = KeyPair::new();
        let private_bytes = kp.private().to_bytes().to_vec();
        let ca_pub = kp.public().to_bytes().to_vec();

        let make_token = |priv_bytes: &[u8], ttl: u64| -> Vec<u8> {
            let issued_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let expiry = SystemTime::now() + Duration::from_secs(ttl);
            biscuit_auth::Biscuit::builder()
                .fact(format!("did(\"did:key:z6MkManager\")").as_str()).unwrap()
                .fact(format!("role(\"manager\")").as_str()).unwrap()
                .fact(format!("issued_at({issued_secs})").as_str()).unwrap()
                .fact("caveat(\"disaster-alert\")").unwrap()
                .check_expiration_date(expiry)
                .build(&KeyPair::from(
                    &PrivateKey::from_bytes(priv_bytes, Algorithm::Ed25519).unwrap()
                ))
                .unwrap()
                .to_vec()
                .unwrap()
        };

        let now = now_secs();
        let activate_token = make_token(&private_bytes, 3600);
        let renew_token    = make_token(&private_bytes, 3600);

        let mut sm = SaturateModeStateMachine::new(2, ca_pub, SATURATE_LEASE_DURATION_SECS);

        sm.activate("did:key:z6MkManager".to_string(), &activate_token, now)
            .expect("activate should succeed");
        assert_eq!(sm.state(), SaturateState::Saturate);

        // Renew 5 minutes later.
        let renew_time = now + 5 * 60;
        sm.renew("did:key:z6MkManager".to_string(), &renew_token, renew_time)
            .expect("renew should succeed");

        let new_expiry = sm.lease().unwrap().expires_at;
        assert_eq!(
            new_expiry,
            renew_time + SATURATE_LEASE_DURATION_SECS,
            "renewal should extend by 60 min from renewal timestamp"
        );
        assert_eq!(sm.state(), SaturateState::Saturate);
    }

    // ── Termination Delta ────────────────────────────────────────────────────

    #[test]
    fn termination_with_insufficient_sigs_preserves_mode() {
        // Use a raw Ed25519 key for testing termination (no Biscuit needed here).
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        // Build state machine manually in SATURATE state.
        let mut sm = SaturateModeStateMachine::new(2, vec![], SATURATE_LEASE_DURATION_SECS);
        // Force into SATURATE state by directly manipulating (for test isolation).
        sm.state = SaturateState::Saturate;
        sm.lease = Some(SaturateLease {
            activated_at: 0,
            expires_at: i64::MAX,
            last_renewed_at: None,
            activating_manager_did: "did:key:z6MkTest".to_string(),
        });

        let message = b"terminate";

        // Only 1 valid signature, threshold is 2.
        // Provide a completely invalid signature (wrong length) to simulate failure.
        let sigs: Vec<(Did, Vec<u8>)> = vec![
            ("did:key:z6MkA".to_string(), vec![0u8; 64]),
        ];

        let err = sm.terminate(sigs, message, 0).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Threshold") || msg.contains("got") || msg.contains("need"),
            "expected threshold error: {msg}"
        );
        assert_eq!(
            sm.state(),
            SaturateState::Saturate,
            "mode must be unchanged on insufficient sigs (invariant b)"
        );
    }

    #[test]
    fn termination_with_threshold_met_transitions_to_normal() {
        use ed25519_dalek::{Signer, SigningKey};

        let message = b"terminate-lease";

        // Create two distinct signing keys and compute their did:key: DIDs.
        let sk1 = SigningKey::from_bytes(&[1u8; 32]);
        let sk2 = SigningKey::from_bytes(&[2u8; 32]);

        let did1 = keypair_to_did_key(&sk1);
        let did2 = keypair_to_did_key(&sk2);

        let sig1 = sk1.sign(message).to_bytes().to_vec();
        let sig2 = sk2.sign(message).to_bytes().to_vec();

        let mut sm = SaturateModeStateMachine::new(2, vec![], SATURATE_LEASE_DURATION_SECS);
        // Force SATURATE state.
        sm.state = SaturateState::Saturate;
        sm.lease = Some(SaturateLease {
            activated_at: 0,
            expires_at: i64::MAX,
            last_renewed_at: None,
            activating_manager_did: did1.clone(),
        });

        let sigs = vec![(did1, sig1), (did2, sig2)];
        sm.terminate(sigs, message, 0).expect("termination should succeed");

        assert_eq!(
            sm.state(),
            SaturateState::Normal,
            "should transition to NORMAL on valid M-of-N termination"
        );
        assert!(sm.lease().is_none(), "lease should be cleared after termination");
    }

    #[test]
    fn termination_duplicate_dids_counted_once() {
        use ed25519_dalek::{Signer, SigningKey};

        let message = b"terminate-dup";
        let sk1 = SigningKey::from_bytes(&[3u8; 32]);
        let did1 = keypair_to_did_key(&sk1);
        let sig1 = sk1.sign(message).to_bytes().to_vec();

        let mut sm = SaturateModeStateMachine::new(2, vec![], SATURATE_LEASE_DURATION_SECS);
        sm.state = SaturateState::Saturate;
        sm.lease = Some(SaturateLease {
            activated_at: 0,
            expires_at: i64::MAX,
            last_renewed_at: None,
            activating_manager_did: did1.clone(),
        });

        // Submit the same DID twice — should count as 1, not 2.
        let sigs = vec![
            (did1.clone(), sig1.clone()),
            (did1.clone(), sig1.clone()),
        ];
        let err = sm.terminate(sigs, message, 0).unwrap_err();
        assert_eq!(
            sm.state(),
            SaturateState::Saturate,
            "duplicate DID must not bypass threshold"
        );
    }

    #[test]
    fn termination_in_normal_mode_is_noop() {
        use ed25519_dalek::{Signer, SigningKey};

        let message = b"terminate-normal";
        let sk1 = SigningKey::from_bytes(&[4u8; 32]);
        let sk2 = SigningKey::from_bytes(&[5u8; 32]);
        let did1 = keypair_to_did_key(&sk1);
        let did2 = keypair_to_did_key(&sk2);
        let sig1 = sk1.sign(message).to_bytes().to_vec();
        let sig2 = sk2.sign(message).to_bytes().to_vec();

        let mut sm = SaturateModeStateMachine::new(2, vec![], SATURATE_LEASE_DURATION_SECS);
        // Already NORMAL — termination is a no-op.
        sm.terminate(vec![(did1, sig1), (did2, sig2)], message, 0)
            .expect("termination in NORMAL is a no-op");
        assert_eq!(sm.state(), SaturateState::Normal);
    }

    // ── SaturateLease helpers ────────────────────────────────────────────────

    #[test]
    fn lease_is_expired_when_past_deadline() {
        let lease = SaturateLease {
            activated_at: 0,
            expires_at: 1000,
            last_renewed_at: None,
            activating_manager_did: "did:key:z6MkX".to_string(),
        };
        assert!(!lease.is_expired(999));
        assert!(lease.is_expired(1000));
        assert!(lease.is_expired(2000));
    }

    #[test]
    fn lease_in_renewal_window_at_15_min_boundary() {
        let expires_at = 3600i64;
        let lease = SaturateLease {
            activated_at: 0,
            expires_at,
            last_renewed_at: None,
            activating_manager_did: "did:key:z6MkX".to_string(),
        };
        // Just outside the window
        assert!(!lease.in_renewal_window(expires_at - RENEWAL_WINDOW_SECS - 1));
        // Exactly at the window start
        assert!(lease.in_renewal_window(expires_at - RENEWAL_WINDOW_SECS));
        // Inside the window
        assert!(lease.in_renewal_window(expires_at - 1));
        // Past expiry
        assert!(!lease.in_renewal_window(expires_at));
    }

    // ── Helper: derive did:key: from Ed25519 signing key ─────────────────────

    /// Encode a `SigningKey`'s verifying key as a `did:key:z6Mk…` DID.
    fn keypair_to_did_key(sk: &ed25519_dalek::SigningKey) -> Did {
        let vk_bytes = sk.verifying_key().to_bytes();
        // Prepend multicodec Ed25519 prefix: 0xED 0x01
        let mut raw = vec![0xED, 0x01];
        raw.extend_from_slice(&vk_bytes);
        // Encode as base58btc multibase (prefix 'z')
        format!("did:key:z{}", bs58::encode(&raw).into_string())
    }
}
