// SPDX-License-Identifier: AGPL-3.0-only

//! HSM / offline-ceremony custody interface (F-05 §2).
//!
//! [`KeyCustodian`] is the only surface through which private key material is
//! used. It deliberately has **no export operation** — a custodian can
//! generate, sign, report a public key, revoke, and zeroize, nothing else.
//! Backup of key material, where a deployment needs it, is a separate
//! quorum-gated ceremony artefact, not a method every caller can reach.
//!
//! [`SoftwareCustodian`] is the in-process implementation used by tests,
//! simulations, and development ceremonies. A production binding implements
//! the same trait over PKCS#11 or a vendor HSM: `sign` forwards the payload to
//! the device and returns the signature, and the bytes never enter this
//! process.

use std::collections::BTreeMap;
use std::sync::Mutex;

use ed25519_dalek::Signer;
use secrecy::{ExposeSecret, Secret};
use tirbase_types::DeviceSignature;

use super::{
    KeyDomain, KeyError, KeyRecord, KeyState, RevocationReason, RevocationRecord, ZeroizeReceipt,
};
use crate::identity::keypair;

/// Custody interface for every key domain.
///
/// Implementations must be `Send + Sync + Debug`; `Debug` must redact private
/// material (see [`SoftwareCustodian`]'s manual implementation).
pub trait KeyCustodian: Send + Sync + std::fmt::Debug {
    /// Generate a key in `domain` and return its public record.
    ///
    /// The private material stays inside the custodian.
    fn generate(
        &self,
        domain: KeyDomain,
        key_id: &str,
        version: u32,
        not_before: i64,
        not_after: i64,
    ) -> Result<KeyRecord, KeyError>;

    /// Sign `payload` with `key_id`. Returns only the signature.
    fn sign(
        &self,
        domain: KeyDomain,
        key_id: &str,
        payload: &[u8],
    ) -> Result<DeviceSignature, KeyError>;

    /// Public key bytes for `key_id`.
    fn public_key(&self, key_id: &str) -> Result<Vec<u8>, KeyError>;

    /// Record a revocation. The registry applies lifecycle state; the
    /// custodian records custody-side metadata only.
    fn revoke(
        &self,
        domain: KeyDomain,
        key_id: &str,
        reason: RevocationReason,
        effective_at: i64,
    ) -> Result<RevocationRecord, KeyError>;

    /// Overwrite and destroy the key material. Idempotent.
    fn zeroize(&self, key_id: &str, now: i64) -> Result<ZeroizeReceipt, KeyError>;
}

struct CustodialKey {
    domain: KeyDomain,
    version: u32,
    public_key: [u8; 32],
    /// `None` once zeroized. `Secret` zeroizes the seed when dropped.
    seed: Option<Secret<[u8; 32]>>,
}

/// Software custodian (HSM test double / development ceremony host).
///
/// Holds Ed25519 seeds in [`Secret`] and zeroizes them on drop or on
/// [`KeyCustodian::zeroize`]. `Debug` prints key ids, never material.
pub struct SoftwareCustodian {
    keys: Mutex<BTreeMap<String, CustodialKey>>,
}

impl std::fmt::Debug for SoftwareCustodian {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key_ids: Vec<String> = match self.keys.lock() {
            Ok(guard) => guard.keys().cloned().collect(),
            Err(poisoned) => poisoned.into_inner().keys().cloned().collect(),
        };
        f.debug_struct("SoftwareCustodian")
            .field("key_ids", &key_ids)
            .field("secrets", &"<redacted>")
            .finish()
    }
}

impl Default for SoftwareCustodian {
    fn default() -> Self {
        SoftwareCustodian::new()
    }
}

impl SoftwareCustodian {
    /// Empty custodian.
    pub fn new() -> Self {
        SoftwareCustodian {
            keys: Mutex::new(BTreeMap::new()),
        }
    }

    /// Import a seed produced by an offline ceremony step.
    ///
    /// The seed is consumed and never returned by any method. This exists for
    /// ceremony import into a software custody slot; an HSM generates in place
    /// and does not need it.
    pub fn from_seed(
        &self,
        domain: KeyDomain,
        key_id: &str,
        version: u32,
        not_before: i64,
        not_after: i64,
        seed: [u8; 32],
    ) -> Result<KeyRecord, KeyError> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let mut keys = self.lock();
        if keys.contains_key(key_id) {
            return Err(KeyError::DuplicateKey {
                key_id: key_id.to_string(),
            });
        }
        keys.insert(
            key_id.to_string(),
            CustodialKey {
                domain,
                version,
                public_key,
                seed: Some(Secret::new(seed)),
            },
        );
        Ok(KeyRecord {
            domain,
            key_id: key_id.to_string(),
            version,
            public_key: public_key.to_vec(),
            not_before,
            not_after,
            state: KeyState::Active,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, CustodialKey>> {
        match self.keys.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl KeyCustodian for SoftwareCustodian {
    fn generate(
        &self,
        domain: KeyDomain,
        key_id: &str,
        version: u32,
        not_before: i64,
        not_after: i64,
    ) -> Result<KeyRecord, KeyError> {
        let (seed, public_key) = keypair::generate_keypair()
            .map_err(|_| KeyError::CustodianKeyMissing {
                key_id: key_id.to_string(),
            })?;
        let mut keys = self.lock();
        if keys.contains_key(key_id) {
            return Err(KeyError::DuplicateKey {
                key_id: key_id.to_string(),
            });
        }
        keys.insert(
            key_id.to_string(),
            CustodialKey {
                domain,
                version,
                public_key,
                seed: Some(Secret::new(seed)),
            },
        );
        Ok(KeyRecord {
            domain,
            key_id: key_id.to_string(),
            version,
            public_key: public_key.to_vec(),
            not_before,
            not_after,
            state: KeyState::Active,
        })
    }

    fn sign(
        &self,
        domain: KeyDomain,
        key_id: &str,
        payload: &[u8],
    ) -> Result<DeviceSignature, KeyError> {
        let keys = self.lock();
        let key = keys.get(key_id).ok_or_else(|| KeyError::CustodianKeyMissing {
            key_id: key_id.to_string(),
        })?;
        if key.domain != domain {
            return Err(KeyError::DomainMismatch {
                expected: domain,
                actual: key.domain,
            });
        }
        let Some(seed) = key.seed.as_ref() else {
            return Err(KeyError::Destroyed {
                key_id: key_id.to_string(),
            });
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed.expose_secret());
        Ok(DeviceSignature::Ed25519(
            signing_key.sign(payload).to_bytes(),
        ))
    }

    fn public_key(&self, key_id: &str) -> Result<Vec<u8>, KeyError> {
        let keys = self.lock();
        keys.get(key_id)
            .map(|key| key.public_key.to_vec())
            .ok_or_else(|| KeyError::CustodianKeyMissing {
                key_id: key_id.to_string(),
            })
    }

    fn revoke(
        &self,
        domain: KeyDomain,
        key_id: &str,
        reason: RevocationReason,
        effective_at: i64,
    ) -> Result<RevocationRecord, KeyError> {
        let keys = self.lock();
        let key = keys.get(key_id).ok_or_else(|| KeyError::CustodianKeyMissing {
            key_id: key_id.to_string(),
        })?;
        if key.domain != domain {
            return Err(KeyError::DomainMismatch {
                expected: domain,
                actual: key.domain,
            });
        }
        Ok(RevocationRecord {
            domain,
            key_id: key_id.to_string(),
            version: key.version,
            reason,
            effective_at,
        })
    }

    fn zeroize(&self, key_id: &str, now: i64) -> Result<ZeroizeReceipt, KeyError> {
        let mut keys = self.lock();
        let key = keys.get_mut(key_id).ok_or_else(|| KeyError::CustodianKeyMissing {
            key_id: key_id.to_string(),
        })?;
        let already_destroyed = key.seed.is_none();
        // Dropping the `Secret` overwrites the seed bytes in place.
        drop(key.seed.take());
        Ok(ZeroizeReceipt {
            key_id: key_id.to_string(),
            zeroized_at: now,
            already_destroyed,
        })
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_private_material() {
        let custodian = SoftwareCustodian::new();
        let seed = [0xABu8; 32];
        custodian
            .from_seed(KeyDomain::RootCa, "root-1", 1, 1_000, 2_000, seed)
            .expect("import");

        let rendered = format!("{custodian:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(
            !rendered.contains(&hex::encode(seed)),
            "custodian Debug must not print the seed"
        );
        assert!(
            !rendered.contains("171, 171, 171"),
            "custodian Debug must not print seed bytes in decimal form"
        );
    }

    #[test]
    fn zeroize_is_idempotent_and_blocks_signing() {
        let custodian = SoftwareCustodian::new();
        custodian
            .from_seed(KeyDomain::ExportSigner, "export-1", 1, 1_000, 2_000, [7u8; 32])
            .expect("import");

        let first = custodian.zeroize("export-1", 1_500).expect("zeroize");
        assert!(!first.already_destroyed);
        assert_eq!(
            custodian.sign(KeyDomain::ExportSigner, "export-1", b"x"),
            Err(KeyError::Destroyed {
                key_id: "export-1".to_string()
            })
        );

        let second = custodian.zeroize("export-1", 1_600).expect("replay");
        assert!(second.already_destroyed);
    }
}
