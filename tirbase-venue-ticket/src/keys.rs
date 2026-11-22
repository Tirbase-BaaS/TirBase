// SPDX-License-Identifier: AGPL-3.0-only

//! Issuer key ring: verification keys, rotation with an overlap, revocation.
//!
//! The ring holds **public** keys only. Signing keys stay behind the F-05
//! custodian; this crate consumes signatures through the [`TicketSigner`] seam
//! and verifies them here.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::decision::Denial;
use crate::error::TicketError;

/// Lifecycle of an issuer verification key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerKeyState {
    /// May sign (and verify) now.
    Active,
    /// Rotated out: verifies tickets issued before the overlap ended.
    Retiring,
    /// Compromised or withdrawn: verifies nothing.
    Revoked,
}

/// One issuer verification key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerKey {
    pub key_id: String,
    pub public_key: [u8; 32],
    pub not_before_utc_us: i64,
    pub not_after_utc_us: i64,
    pub state: IssuerKeyState,
}

impl IssuerKey {
    fn window_contains(&self, at_utc_us: i64) -> bool {
        at_utc_us >= self.not_before_utc_us && at_utc_us <= self.not_after_utc_us
    }
}

/// Receipt for a rotation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerRotation {
    pub previous_key_id: Option<String>,
    pub new_key_id: String,
    pub rotated_at_utc_us: i64,
    pub overlap_ends_at_utc_us: i64,
}

/// Verification-only issuer key ring.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerKeyRing {
    keys: BTreeMap<String, IssuerKey>,
    active: Option<String>,
}

impl IssuerKeyRing {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a key. The first key registered becomes active unless it is
    /// registered as `Retiring` or `Revoked`.
    pub fn add_key(&mut self, key: IssuerKey) -> Result<(), TicketError> {
        if self.keys.contains_key(&key.key_id) {
            return Err(TicketError::DuplicateIssuerKey {
                key_id: key.key_id,
            });
        }
        if key.state == IssuerKeyState::Active {
            if self.active.is_some() {
                return Err(TicketError::InvalidConfig(
                    "an active issuer key already exists; use rotate",
                ));
            }
            self.active = Some(key.key_id.clone());
        }
        self.keys.insert(key.key_id.clone(), key);
        Ok(())
    }

    /// Register a fresh active key from raw Ed25519 bytes.
    pub fn add_public_key(
        &mut self,
        key_id: impl Into<String>,
        public_key: [u8; 32],
        not_before_utc_us: i64,
        not_after_utc_us: i64,
    ) -> Result<(), TicketError> {
        let key_id = key_id.into();
        if key_id.is_empty() || key_id.len() > 128 || key_id.chars().any(char::is_control) {
            return Err(TicketError::InvalidIdentifier("issuer key id"));
        }
        if not_after_utc_us <= not_before_utc_us {
            return Err(TicketError::InvalidConfig("issuer key window is empty"));
        }
        VerifyingKey::from_bytes(&public_key).map_err(|_| TicketError::InvalidPublicKey)?;
        self.add_key(IssuerKey {
            key_id,
            public_key,
            not_before_utc_us,
            not_after_utc_us,
            state: IssuerKeyState::Active,
        })
    }

    pub fn active_key_id(&self) -> Option<&str> {
        self.active.as_deref()
    }

    pub fn key(&self, key_id: &str) -> Option<&IssuerKey> {
        self.keys.get(key_id)
    }

    pub fn keys(&self) -> impl Iterator<Item = &IssuerKey> {
        self.keys.values()
    }

    /// Rotate to a new active key.
    ///
    /// Every previously active key becomes `Retiring` and stops verifying after
    /// `min(its own not_after, at + overlap_us)`, so tickets signed before the
    /// rotation keep verifying only for the stated overlap.
    pub fn rotate(
        &mut self,
        new_key_id: impl Into<String>,
        public_key: [u8; 32],
        at_utc_us: i64,
        overlap_us: i64,
        validity_us: i64,
    ) -> Result<IssuerRotation, TicketError> {
        let new_key_id = new_key_id.into();
        if self.keys.contains_key(&new_key_id) {
            return Err(TicketError::DuplicateIssuerKey {
                key_id: new_key_id,
            });
        }
        if overlap_us < 0 || validity_us <= 0 {
            return Err(TicketError::InvalidConfig(
                "rotation requires overlap >= 0 and validity > 0",
            ));
        }
        VerifyingKey::from_bytes(&public_key).map_err(|_| TicketError::InvalidPublicKey)?;

        let overlap_ends_at_utc_us = at_utc_us.saturating_add(overlap_us);
        let previous_key_id = self.active.clone();
        for key in self.keys.values_mut() {
            if key.state == IssuerKeyState::Active {
                key.state = IssuerKeyState::Retiring;
                key.not_after_utc_us = key.not_after_utc_us.min(overlap_ends_at_utc_us);
            }
        }
        self.keys.insert(
            new_key_id.clone(),
            IssuerKey {
                key_id: new_key_id.clone(),
                public_key,
                not_before_utc_us: at_utc_us,
                not_after_utc_us: at_utc_us.saturating_add(validity_us),
                state: IssuerKeyState::Active,
            },
        );
        self.active = Some(new_key_id.clone());
        Ok(IssuerRotation {
            previous_key_id,
            new_key_id,
            rotated_at_utc_us: at_utc_us,
            overlap_ends_at_utc_us,
        })
    }

    /// Revoke one key: it verifies nothing from `at_utc_us` onward.
    pub fn revoke(&mut self, key_id: &str, at_utc_us: i64) -> Result<(), Denial> {
        let key = self
            .keys
            .get_mut(key_id)
            .ok_or_else(|| Denial::UnknownIssuerKey {
                key_id: key_id.to_owned(),
            })?;
        key.state = IssuerKeyState::Revoked;
        key.not_after_utc_us = at_utc_us;
        if self.active.as_deref() == Some(key_id) {
            self.active = None;
        }
        Ok(())
    }

    /// Check that `key_id` may verify an artefact at `at_utc_us`.
    pub fn check_key(&self, key_id: &str, at_utc_us: i64) -> Result<&IssuerKey, Denial> {
        let key = self
            .keys
            .get(key_id)
            .ok_or_else(|| Denial::UnknownIssuerKey {
                key_id: key_id.to_owned(),
            })?;
        if key.state == IssuerKeyState::Revoked {
            return Err(Denial::KeyRevoked {
                key_id: key_id.to_owned(),
            });
        }
        if at_utc_us < key.not_before_utc_us {
            return Err(Denial::KeyNotYetValid {
                key_id: key_id.to_owned(),
                not_before_utc_us: key.not_before_utc_us,
            });
        }
        if !key.window_contains(at_utc_us) {
            return Err(Denial::KeyExpired {
                key_id: key_id.to_owned(),
                not_after_utc_us: key.not_after_utc_us,
            });
        }
        Ok(key)
    }

    /// Verify a hex-encoded Ed25519 signature over `message`.
    pub fn verify(
        &self,
        key_id: &str,
        message: &[u8],
        signature_hex: &str,
        at_utc_us: i64,
    ) -> Result<(), Denial> {
        let key = self.check_key(key_id, at_utc_us)?;
        let bytes =
            hex::decode(signature_hex).map_err(|_| Denial::BadSignature {
                key_id: key_id.to_owned(),
            })?;
        let signature: [u8; 64] = bytes.try_into().map_err(|_| Denial::BadSignature {
            key_id: key_id.to_owned(),
        })?;
        let verifying_key =
            VerifyingKey::from_bytes(&key.public_key).map_err(|_| Denial::BadSignature {
                key_id: key_id.to_owned(),
            })?;
        verifying_key
            .verify_strict(message, &Signature::from_bytes(&signature))
            .map_err(|_| Denial::BadSignature {
                key_id: key_id.to_owned(),
            })
    }
}

/// Something that can sign a ticket without exposing its private key.
///
/// A deployment implements this over its F-05 custodian (HSM, PKCS#11, offline
/// ceremony). The crate only ever calls it with the exact signing bytes.
pub trait TicketSigner {
    fn key_id(&self) -> &str;
    fn public_key(&self) -> [u8; 32];
    fn sign(&self, message: &[u8]) -> [u8; 64];
}

/// In-process Ed25519 signer for tooling and tests.
pub struct Ed25519Signer {
    key_id: String,
    key: SigningKey,
}

impl Ed25519Signer {
    /// Build a signer from a 32-byte seed.
    pub fn from_seed(key_id: impl Into<String>, seed: [u8; 32]) -> Self {
        let key_id = key_id.into();
        Self {
            key_id,
            key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn verifying_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

impl std::fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519Signer")
            .field("key_id", &self.key_id)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl TicketSigner for Ed25519Signer {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.key.sign(message).to_bytes()
    }
}
