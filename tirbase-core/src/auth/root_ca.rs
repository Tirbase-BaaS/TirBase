//! Root CA public key registry (task 8.1 / 8.2 — CLAIM-8.1, CLAIM-8.2,
//! PV-3.4).
//!
//! The registry holds **multiple simultaneous** root CA Ed25519 public keys.
//! Token verification tries every active key; a token is accepted when it
//! verifies against one of them.  Root rotation is authorised by a k-of-n
//! threshold of the *current* keys (`k ≥ 1`); `k = 1` is permitted for small
//! deployments but the gateway emits a startup diagnostic warning (scenario
//! S11).
//!
//! Root keys can be revoked independently of registration: a revoked key is
//! excluded from [`RootCaRegistry::keys`] immediately and can never verify a
//! token again.

use crate::crdt::delta::Ed25519Signature;
use crate::errors::TirBaseError;
use crate::identity::did::derive_did;
use crate::identity::keypair;
use tirbase_types::DeviceSignature;

/// The root CA public key registry.
///
/// In v1 this is populated from deployment configuration / the offline trust
/// root, then updated by signed rotation ceremonies.
#[derive(Debug, Clone, Default)]
pub struct RootCaRegistry {
    /// Ed25519 public keys of registered root CAs (including revoked keys, so
    /// the revocation is auditable).
    keys: Vec<[u8; 32]>,
    /// Keys explicitly revoked by a rotation ceremony.
    revoked: Vec<[u8; 32]>,
    /// k in the k-of-n rotation threshold (always ≥ 1 for a configured
    /// registry).
    threshold_k: usize,
}

impl RootCaRegistry {
    /// Create a registry from a list of root CA public key bytes with the
    /// default threshold `k = 1`.
    pub fn new(keys: Vec<[u8; 32]>) -> Self {
        RootCaRegistry {
            keys,
            revoked: Vec::new(),
            threshold_k: 1,
        }
    }

    /// Create a registry with an explicit k-of-n rotation threshold.
    ///
    /// Fails when `k == 0` or when `k` exceeds the number of active keys.
    pub fn with_threshold(keys: Vec<[u8; 32]>, threshold_k: usize) -> Result<Self, TirBaseError> {
        let registry = RootCaRegistry {
            keys,
            revoked: Vec::new(),
            threshold_k,
        };
        registry.validate_threshold()?;
        Ok(registry)
    }

    /// Register an additional root CA public key at runtime.
    ///
    /// Idempotent: registering a key that is already present (or revoked) is a
    /// no-op.  A revoked key is *not* un-revoked by re-registration.
    pub fn register(&mut self, key: [u8; 32]) {
        if !self.keys.contains(&key) {
            self.keys.push(key);
        }
    }

    /// Return the raw registered key list, **including revoked keys**.
    ///
    /// Token verification must use [`Self::active_keys`] so a revoked key can
    /// never verify again.  `keys()` exists for audit/export and backwards
    /// compatibility with callers that need the full historical set.
    pub fn keys(&self) -> &[[u8; 32]] {
        &self.keys
    }

    /// All keys ever registered, including revoked keys (audit view).
    pub fn all_keys(&self) -> &[[u8; 32]] {
        &self.keys
    }

    /// Active (non-revoked) keys, in registration order.
    pub fn active_keys(&self) -> Vec<[u8; 32]> {
        self.keys
            .iter()
            .copied()
            .filter(|key| !self.revoked.contains(key))
            .collect()
    }

    /// k in the k-of-n rotation threshold.
    pub fn threshold_k(&self) -> usize {
        self.threshold_k
    }

    /// Startup diagnostic warning when k = 1 (PV-3.4, S11).
    ///
    /// `k = 1` is allowed so a single-gateway deployment can operate, but a
    /// single compromised root key can rotate the whole trust root.  Returns
    /// `None` for `k >= 2` and for an empty registry (nothing to rotate yet).
    pub fn threshold_warning(&self) -> Option<String> {
        (self.threshold_k == 1 && !self.keys.is_empty()).then(|| {
            "root CA threshold k=1: a single root key can rotate the root; \
             k>=2 is strongly recommended (PV-3.4/S11)"
                .to_string()
        })
    }

    /// Check if a given Ed25519 public key is an active registered root CA.
    pub fn is_registered(&self, key: &[u8; 32]) -> bool {
        self.keys.contains(key) && !self.revoked.contains(key)
    }

    /// Whether `key` has been revoked.
    pub fn is_revoked(&self, key: &[u8; 32]) -> bool {
        self.revoked.contains(key)
    }

    /// Revoke a root CA key (task 8.2).
    ///
    /// Returns `true` when the key was active and is now revoked.  Revocation
    /// is permanent for this registry instance; installing a new trust-root
    /// version is the only way to re-admit a key, and doing so is rollback
    /// protected by [`crate::trust_root::TrustRootManager`].
    pub fn revoke(&mut self, key: &[u8; 32]) -> bool {
        if !self.keys.contains(key) || self.revoked.contains(key) {
            return false;
        }
        self.revoked.push(*key);
        true
    }

    /// Return the first active root CA public key, if any.
    pub fn primary_key(&self) -> Option<&[u8; 32]> {
        self.keys.iter().find(|key| !self.revoked.contains(key))
    }

    /// Verify a token against every active root key.
    ///
    /// `verify` is the token-verification closure (for example
    /// [`crate::auth::biscuit::verify_token`]).
    pub fn verify_against_first<T, E>(
        &self,
        mut verify: impl FnMut(&[u8; 32]) -> Result<T, E>,
    ) -> Result<T, TirBaseError> {
        let active = self.active_keys();
        if active.is_empty() {
            return Err(TirBaseError::AuthorisationFailed {
                reason: "no registered root CA keys; cannot verify Biscuit token".to_string(),
            });
        }
        let mut last_error: Option<E> = None;
        for key in &active {
            match verify(key) {
                Ok(value) => return Ok(value),
                Err(error) => last_error = Some(error),
            }
        }
        let _ = last_error;
        Err(TirBaseError::AuthorisationFailed {
            reason: "token verification failed for all registered root CA keys".to_string(),
        })
    }

    /// Rotate the root key set with k-of-n authorisation from the **current**
    /// active keys (task 8.1).
    ///
    /// `message` is the signed rotation statement (the offline ceremony
    /// defines its exact contents; the trust-root record uses its own domain
    /// separated bytes).  `signatures` are `(signer_did, signature)` pairs;
    /// each signer must derive from an active key, and at least
    /// [`Self::threshold_k`] distinct signers are required.
    ///
    /// Only after the threshold verifies are `new_keys`, `new_threshold` and
    /// `revoked_keys` applied.
    pub fn rotate(
        &mut self,
        new_keys: Vec<[u8; 32]>,
        new_threshold_k: usize,
        message: &[u8],
        signatures: &[(String, DeviceSignature)],
        revoked_keys: Vec<[u8; 32]>,
    ) -> Result<(), TirBaseError> {
        if self.threshold_k == 0 {
            return Err(TirBaseError::AuthorisationFailed {
                reason: "root CA threshold k must be >= 1".to_string(),
            });
        }

        let active = self.active_keys();
        let mut valid_signers: Vec<String> = Vec::new();
        for (signer_did, signature) in signatures {
            if valid_signers.iter().any(|did| did == signer_did) {
                continue;
            }
            let Some(key) = active
                .iter()
                .find(|key| derive_did(key) == *signer_did)
            else {
                continue;
            };
            if verify_root_signature(key, message, signature) {
                valid_signers.push(signer_did.clone());
            }
        }

        if valid_signers.len() < self.threshold_k {
            return Err(TirBaseError::ThresholdNotMet {
                got: valid_signers.len(),
                need: self.threshold_k,
            });
        }

        let registry = RootCaRegistry {
            keys: new_keys,
            revoked: revoked_keys,
            threshold_k: new_threshold_k,
        };
        registry.validate_threshold()?;
        self.keys = registry.keys;
        self.revoked = registry.revoked;
        self.threshold_k = registry.threshold_k;
        Ok(())
    }

    /// Validate that the threshold is usable.
    pub fn validate_threshold(&self) -> Result<(), TirBaseError> {
        if self.threshold_k == 0 {
            return Err(TirBaseError::AuthorisationFailed {
                reason: "root CA threshold k must be >= 1 (PV-3.4)".to_string(),
            });
        }
        let active = self.active_keys().len();
        if active == 0 {
            return Err(TirBaseError::AuthorisationFailed {
                reason: "root CA registry has no active keys".to_string(),
            });
        }
        if self.threshold_k > active {
            return Err(TirBaseError::AuthorisationFailed {
                reason: format!(
                    "root CA threshold k={} exceeds active key count {active}",
                    self.threshold_k
                ),
            });
        }
        Ok(())
    }
}

fn verify_root_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &DeviceSignature,
) -> bool {
    match signature {
        DeviceSignature::Ed25519(bytes) => {
            keypair::verify(public_key, message, &Ed25519Signature::from_bytes(*bytes)).is_ok()
        }
        DeviceSignature::P256(_) => false,
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::identity::file_key_provider::InMemoryKeyProvider;
    use crate::traits::KeyProvider;

    #[test]
    fn multiple_root_keys_are_all_registered() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let registry = RootCaRegistry::new(vec![a, b]);
        assert!(registry.is_registered(&a));
        assert!(registry.is_registered(&b));
        assert_eq!(registry.active_keys(), vec![a, b]);
    }

    #[test]
    fn k_equals_one_emits_a_startup_warning() {
        let registry = RootCaRegistry::new(vec![[1u8; 32]]);
        assert!(registry.threshold_warning().is_some());

        let registry = RootCaRegistry::with_threshold(vec![[1u8; 32], [2u8; 32]], 2).unwrap();
        assert!(registry.threshold_warning().is_none());
    }

    #[test]
    fn k_of_n_rotation_requires_threshold_signatures() {
        let a = InMemoryKeyProvider::generate().unwrap();
        let b = InMemoryKeyProvider::generate().unwrap();
        let a_pub: [u8; 32] = a.public_key_bytes().try_into().unwrap();
        let b_pub: [u8; 32] = b.public_key_bytes().try_into().unwrap();
        let mut registry = RootCaRegistry::with_threshold(vec![a_pub, b_pub], 2).unwrap();

        let message = b"rotate to new root";
        let new_keys = vec![[9u8; 32], [10u8; 32]];

        // One signature is not enough for k=2.
        let one = vec![(a.did().to_string(), a.sign(message).unwrap())];
        assert!(matches!(
            registry.rotate(new_keys.clone(), 1, message, &one, vec![]),
            Err(TirBaseError::ThresholdNotMet { got: 1, need: 2 })
        ));

        // Two distinct root signatures rotate the set.
        let two = vec![
            (a.did().to_string(), a.sign(message).unwrap()),
            (b.did().to_string(), b.sign(message).unwrap()),
        ];
        registry
            .rotate(new_keys.clone(), 1, message, &two, vec![])
            .expect("k-of-n rotation accepted");
        assert_eq!(registry.active_keys(), new_keys);
        assert_eq!(registry.threshold_k(), 1);
    }

    #[test]
    fn revoked_root_key_can_no_longer_verify() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let mut registry = RootCaRegistry::new(vec![a, b]);
        assert!(registry.revoke(&a));
        assert!(registry.is_revoked(&a));
        assert!(!registry.is_registered(&a));
        assert_eq!(registry.active_keys(), vec![b]);
        assert_eq!(registry.primary_key(), Some(&b));
        assert!(!registry.revoke(&a), "second revocation is a no-op");
    }

    #[test]
    fn empty_registry_rejects_verification() {
        let registry = RootCaRegistry::new(vec![]);
        let error = registry
            .verify_against_first(|_| Ok::<(), ()>(()))
            .expect_err("no keys");
        assert!(error.to_string().contains("no registered root CA keys"));
    }
}
