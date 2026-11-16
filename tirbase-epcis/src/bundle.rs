// SPDX-License-Identifier: Apache-2.0

//! The signed ledger bundle this adapter consumes (CC-14), re-declared here so
//! the Apache-2.0 adapter can read the format without linking the AGPL crate
//! that produces it.
//!
//! Field names and order match the producer exactly: the detached signature
//! covers `"TirBase/v1/LineageLedgerBundle" || 0x00 || <compact JSON of the
//! bundle>`, so verification re-serialises this model with the same field order
//! and compares bytes. A bundle that was produced by any other serializer fails
//! closed with [`crate::AdapterError::Signature`].

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::AdapterError;

/// Domain-separation prefix of the detached bundle signature.
pub const CONTEXT_LEDGER_BUNDLE: &str = "TirBase/v1/LineageLedgerBundle";

/// Bundle format version this adapter understands.
pub const BUNDLE_FORMAT_VERSION: u32 = 1;

/// A signature as stored in a checkpoint or the detached `.sig` file.
///
/// Serialised as the externally tagged form the ledger uses
/// (`{"Ed25519": [..64 bytes..]}`). `serde` has no array impl for 64 elements,
/// so the impls are written out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleSignature {
    /// Ed25519 signature, 64 bytes.
    Ed25519([u8; 64]),
    /// P-256 (DER-encoded ECDSA) signature.
    P256(Vec<u8>),
}

impl Serialize for BundleSignature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            BundleSignature::Ed25519(bytes) => serializer.serialize_newtype_variant(
                "DeviceSignature",
                0,
                "Ed25519",
                bytes.as_slice(),
            ),
            BundleSignature::P256(bytes) => {
                serializer.serialize_newtype_variant("DeviceSignature", 1, "P256", bytes.as_slice())
            }
        }
    }
}

impl<'de> Deserialize<'de> for BundleSignature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        enum Raw {
            Ed25519(Vec<u8>),
            P256(Vec<u8>),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Ed25519(bytes) => {
                let array: [u8; 64] = bytes.as_slice().try_into().map_err(|_| {
                    serde::de::Error::custom(format!(
                        "Ed25519 signature must be 64 bytes, got {}",
                        bytes.len()
                    ))
                })?;
                Ok(BundleSignature::Ed25519(array))
            }
            Raw::P256(bytes) => Ok(BundleSignature::P256(bytes)),
        }
    }
}

/// One signed checkpoint over the ledger prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerCheckpoint {
    /// Last sequence covered.
    pub seq: u64,
    /// Entries covered.
    pub count: u64,
    /// Entry hash at `seq`.
    pub head_hash: String,
    /// Hash over the checkpoint body.
    pub checkpoint_hash: String,
    /// DID of the signing key.
    pub signer_did: String,
    /// Signature over the checkpoint hash bytes.
    pub signature: BundleSignature,
    /// When the checkpoint was made.
    pub created_est: i64,
}

/// An attachment committed to by the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentRef {
    /// File name.
    pub name: String,
    /// SHA-256 of the bytes, hex.
    pub sha256_hex: String,
    /// Length in bytes.
    pub bytes: u64,
}

/// Bundle manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Bundle format version.
    pub format_version: u32,
    /// When the bundle was created.
    pub created_est: i64,
    /// DID of the signing key.
    pub signer_did: String,
    /// Pinned public key of the signer, hex.
    pub signer_public_key_hex: String,
    /// First sequence in the bundle.
    pub range_start: u64,
    /// Last sequence in the bundle.
    pub range_end: u64,
    /// Hash the first entry links to.
    pub range_prev_hash: String,
    /// Number of entries.
    pub entry_count: u64,
    /// Entry hash of the last entry.
    pub root_hash: String,
    /// Checkpoints inside the range.
    pub checkpoints: Vec<LedgerCheckpoint>,
    /// Attachments, sorted by name.
    pub attachments: Vec<AttachmentRef>,
}

/// One ledger entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Contiguous position, starting at 1.
    pub seq: u64,
    /// Idempotency key of the event.
    pub entry_id: String,
    /// Hash of the previous entry.
    pub prev_hash: String,
    /// Hash of this entry.
    pub entry_hash: String,
    /// Recording time.
    pub recorded_est: i64,
    /// Actor that caused the event.
    pub actor_did: String,
    /// Device the event concerns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Lot the event concerns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lot_id: Option<String>,
    /// Event type.
    pub event_type: String,
    /// Hash of the payload.
    pub payload_hash: String,
    /// The payload itself.
    pub payload: Value,
}

/// A bundle body: manifest plus entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    /// Manifest.
    pub manifest: Manifest,
    /// Entries in sequence order.
    pub entries: Vec<LedgerEntry>,
}

/// Outcome of verifying a bundle's detached signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// DID the signature was checked against.
    pub signer_did: String,
    /// Whether that DID was supplied by the caller as trusted.
    pub trusted: bool,
    /// The trusted public key that verified, hex.
    pub public_key_hex: String,
}

impl Bundle {
    /// Parse a `bundle.json` document.
    pub fn from_json(json: &str) -> Result<Self, AdapterError> {
        let bundle: Self =
            serde_json::from_str(json).map_err(|error| AdapterError::Json(error.to_string()))?;
        bundle.check_shape()?;
        Ok(bundle)
    }

    /// Serialise the bundle exactly as the signature covers it.
    pub fn to_canonical_json(&self) -> Result<String, AdapterError> {
        serde_json::to_string(self).map_err(|error| AdapterError::Json(error.to_string()))
    }

    /// The bytes the detached signature covers.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, AdapterError> {
        let body =
            serde_json::to_vec(self).map_err(|error| AdapterError::Json(error.to_string()))?;
        let mut bytes = Vec::with_capacity(CONTEXT_LEDGER_BUNDLE.len() + 1 + body.len());
        bytes.extend_from_slice(CONTEXT_LEDGER_BUNDLE.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&body);
        Ok(bytes)
    }

    /// Verify the detached signature (hex) against a trusted key.
    ///
    /// `trusted_public_key_hex` is the auditor-supplied key. When it is `None`
    /// the manifest's own pinned key is used and the result is reported as
    /// untrusted: the bytes are consistent, but the key was not vouched for out
    /// of band.
    pub fn verify(
        &self,
        signature_hex: &str,
        trusted_public_key_hex: Option<&str>,
    ) -> Result<Verification, AdapterError> {
        let (key_hex, trusted) = match trusted_public_key_hex {
            Some(key) => (key.to_string(), true),
            None => (self.manifest.signer_public_key_hex.clone(), false),
        };
        let key = decode_hex::<32>("public key", &key_hex)?;
        let signature = decode_hex::<64>("signature", signature_hex)?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key)
            .map_err(|error| AdapterError::Signature(format!("public key: {error}")))?;
        let signature = ed25519_dalek::Signature::from_bytes(&signature);
        let bytes = self.signing_bytes()?;
        verifying_key
            .verify_strict(&bytes, &signature)
            .map_err(|error| {
                AdapterError::Signature(format!("signature did not verify: {error}"))
            })?;
        Ok(Verification {
            signer_did: self.manifest.signer_did.clone(),
            trusted,
            public_key_hex: key_hex,
        })
    }

    /// Structural checks the mapper relies on.
    fn check_shape(&self) -> Result<(), AdapterError> {
        if self.manifest.format_version != BUNDLE_FORMAT_VERSION {
            return Err(AdapterError::InvalidBundle(format!(
                "unsupported bundle format version {}",
                self.manifest.format_version
            )));
        }
        if self.manifest.entry_count as usize != self.entries.len() {
            return Err(AdapterError::InvalidBundle(format!(
                "manifest declares {} entries, bundle carries {}",
                self.manifest.entry_count,
                self.entries.len()
            )));
        }
        for window in self.entries.windows(2) {
            if window[1].seq != window[0].seq + 1 {
                return Err(AdapterError::InvalidBundle(format!(
                    "entries are not contiguous at seq {}",
                    window[1].seq
                )));
            }
        }
        Ok(())
    }
}

/// Parse a `bundle.json` document.
pub fn parse_bundle(json: &str) -> Result<Bundle, AdapterError> {
    Bundle::from_json(json)
}

fn decode_hex<const N: usize>(what: &str, value: &str) -> Result<[u8; N], AdapterError> {
    let bytes = hex::decode(value.trim())
        .map_err(|error| AdapterError::Signature(format!("{what} is not hex: {error}")))?;
    bytes.as_slice().try_into().map_err(|_| {
        AdapterError::Signature(format!("{what} must be {N} bytes, got {}", bytes.len()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn sample() -> Bundle {
        Bundle {
            manifest: Manifest {
                format_version: 1,
                created_est: 1_770_000_000,
                signer_did: "did:key:z6MkTest".to_string(),
                signer_public_key_hex: String::new(),
                range_start: 1,
                range_end: 1,
                range_prev_hash: "0".repeat(64),
                entry_count: 1,
                root_hash: "1".repeat(64),
                checkpoints: Vec::new(),
                attachments: Vec::new(),
            },
            entries: vec![LedgerEntry {
                seq: 1,
                entry_id: "lot-registered:LOT-A".to_string(),
                prev_hash: "0".repeat(64),
                entry_hash: "1".repeat(64),
                recorded_est: 1_770_000_000,
                actor_did: "did:key:z6MkTest".to_string(),
                device_id: None,
                lot_id: Some("LOT-A".to_string()),
                event_type: "lot_registered".to_string(),
                payload_hash: "2".repeat(64),
                payload: serde_json::json!({"lot_id": "LOT-A"}),
            }],
        }
    }

    #[test]
    fn a_signed_bundle_verifies_and_a_changed_bundle_does_not() {
        // A deterministic key: 32 bytes of a fixed seed, hashed into a secret.
        let seed = [7u8; 32];
        let secret = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public = secret.verifying_key();

        let mut bundle = sample();
        bundle.manifest.signer_public_key_hex = hex::encode(public.to_bytes());
        let signature = secret.sign(&bundle.signing_bytes().expect("bytes"));

        let verification = bundle
            .verify(
                &hex::encode(signature.to_bytes()),
                Some(&hex::encode(public.to_bytes())),
            )
            .expect("verifies");
        assert!(verification.trusted);
        assert_eq!(verification.signer_did, "did:key:z6MkTest");

        // The pinned key alone also verifies, but is reported as untrusted.
        let untrusted = bundle
            .verify(&hex::encode(signature.to_bytes()), None)
            .expect("verifies against the pin");
        assert!(!untrusted.trusted);

        // Changing any mapped field invalidates the signature.
        let mut changed = bundle.clone();
        changed.entries[0].payload = serde_json::json!({"lot_id": "LOT-EVIL"});
        assert!(matches!(
            changed.verify(&hex::encode(signature.to_bytes()), None),
            Err(AdapterError::Signature(_))
        ));
    }

    #[test]
    fn a_bundle_with_inconsistent_entry_count_is_rejected() {
        let mut bundle = sample();
        bundle.manifest.entry_count = 2;
        assert!(matches!(
            Bundle::from_json(&serde_json::to_string(&bundle).expect("json")),
            Err(AdapterError::InvalidBundle(_))
        ));
    }
}
