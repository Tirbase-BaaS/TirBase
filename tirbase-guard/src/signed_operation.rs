//! `SignedOperation<T>` — domain-separated multi-party signed wrapper
//! (task 6.7 — CLAIM-6.7, PV-3.6).
//!
//! Every multi-signature artefact in the guard (policy bundles, lockdown exit,
//! enrollment-epoch bump) is wrapped in a [`SignedOperation<T>`].  The wrapper
//! binds three things together:
//!
//! 1. a **context string** identifying the artefact type,
//! 2. the **SHA-256 hash of the deterministic CBOR encoding** of the payload,
//! 3. the co-signatures over `context_string || 0x00 || payload_hash`.
//!
//! Because the context string is part of the signed bytes and is checked
//! against [`SignedOperationPayload::CONTEXT`] for the concrete `T`, a
//! signature collected for one artefact type can never satisfy another:
//! cross-type signature reuse is rejected before any role or quorum logic runs
//! (domain separation).
//!
//! The payload itself is not stored in the wrapper; callers pass it back to
//! [`SignedOperation::verify`], which recomputes the hash and checks the
//! context, so a wrapper cannot be detached from its payload.

use std::fmt;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tirbase_core::crdt::delta::Ed25519Signature;
use tirbase_core::identity::keypair;
use tirbase_core::traits::KeyProvider;
use tirbase_types::{CommandRole, DeviceSignature};

/// Context string for `PolicyBundle` operations.
pub const CONTEXT_POLICY_BUNDLE: &str = "TirBase/v1/PolicyBundle";
/// Context string for `LockdownExit` operations.
pub const CONTEXT_LOCKDOWN_EXIT: &str = "TirBase/v1/LockdownExit";
/// Context string for enrollment-epoch bumps.
pub const CONTEXT_EPOCH_BUMP: &str = "TirBase/v1/EpochBump";

/// A payload type that can be wrapped in a [`SignedOperation`].
///
/// `CONTEXT` is the single authoritative domain string for the type.  It is
/// included in every signature and re-checked at verification time, which is
/// what makes cross-type signature reuse impossible.
pub trait SignedOperationPayload: Serialize {
    /// Domain-separation string, for example [`CONTEXT_POLICY_BUNDLE`].
    const CONTEXT: &'static str;
}

/// One co-signature in a [`SignedOperation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureEntry {
    /// DID of the signer.
    pub signer_did: String,
    /// Role the signer claims for this operation.
    pub role: CommandRole,
    /// Signature over the domain-separated signing bytes.
    pub signature: DeviceSignature,
}

/// Failure modes of [`SignedOperation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedOperationError {
    /// The payload could not be encoded as deterministic CBOR.
    Serialization(String),
    /// The wrapper's context string does not match the payload type's domain.
    ContextMismatch {
        /// Domain expected for `T`.
        expected: &'static str,
        /// Context string embedded in the wrapper.
        actual: String,
    },
    /// The payload hash does not match the wrapper.
    PayloadHashMismatch,
    /// No signatures were collected.
    EmptySignatures,
    /// The key type is not supported by this build.
    UnsupportedKeyType(DeviceSignature),
    /// A signature failed verification.
    SignatureVerification {
        /// DID of the entry that failed.
        signer_did: String,
    },
    /// A signer DID could not be resolved to a public key.
    UnknownSigner(String),
}

impl fmt::Display for SignedOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignedOperationError::Serialization(reason) => {
                write!(f, "signed operation payload serialization failed: {reason}")
            }
            SignedOperationError::ContextMismatch { expected, actual } => write!(
                f,
                "domain-separation failure: expected context {expected:?}, got {actual:?}"
            ),
            SignedOperationError::PayloadHashMismatch => {
                write!(f, "signed operation payload hash does not match")
            }
            SignedOperationError::EmptySignatures => {
                write!(f, "signed operation has no signatures")
            }
            SignedOperationError::UnsupportedKeyType(signature) => {
                write!(f, "unsupported signature key type: {signature:?}")
            }
            SignedOperationError::SignatureVerification { signer_did } => {
                write!(f, "signature verification failed for {signer_did}")
            }
            SignedOperationError::UnknownSigner(did) => {
                write!(f, "no public key available for signer {did}")
            }
        }
    }
}

impl std::error::Error for SignedOperationError {}

/// A payload bound to its context string, payload hash, and co-signatures.
///
/// `T` is only a phantom type parameter: the payload is supplied again on
/// verification so the wrapper can never drift from the data it authorizes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct SignedOperation<T> {
    /// Domain-separation string (`"TirBase/v1/PolicyBundle"`, …).
    pub context_string: String,
    /// SHA-256 of the deterministic CBOR encoding of the payload.
    pub payload_hash: [u8; 32],
    /// Co-signatures over the domain-separated signing bytes.
    pub signatures: Vec<SignatureEntry>,
    /// Creation time (authenticated-time estimate, seconds).
    pub created_est: i64,
    /// Optional expiry (authenticated-time estimate, seconds).
    pub expires_est: Option<i64>,
    /// Phantom payload type.
    #[serde(skip)]
    pub _payload: PhantomData<T>,
}

impl<T: SignedOperationPayload> SignedOperation<T> {
    /// Wrap `payload` for the domain declared by `T::CONTEXT`.
    pub fn new(
        payload: &T,
        created_est: i64,
        expires_est: Option<i64>,
    ) -> Result<Self, SignedOperationError> {
        Ok(SignedOperation {
            context_string: T::CONTEXT.to_string(),
            payload_hash: payload_hash(payload)?,
            signatures: Vec::new(),
            created_est,
            expires_est,
            _payload: PhantomData,
        })
    }

    /// The exact bytes a co-signature covers.
    ///
    /// Format: `context_string || 0x00 || payload_hash`.  The NUL separator
    /// makes the concatenation unambiguous (context strings never contain NUL).
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.context_string.len() + 1 + 32);
        bytes.extend_from_slice(self.context_string.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&self.payload_hash);
        bytes
    }

    /// Sign this operation with `provider` under `role` and append the entry.
    pub fn sign_with(
        &mut self,
        provider: &dyn KeyProvider,
        role: CommandRole,
    ) -> Result<(), SignedOperationError> {
        let bytes = self.signing_bytes();
        let signature = provider
            .sign(&bytes)
            .map_err(|error| SignedOperationError::Serialization(error.to_string()))?;
        self.signatures.push(SignatureEntry {
            signer_did: provider.did().to_string(),
            role,
            signature,
        });
        Ok(())
    }

    /// Check the wrapper against `payload`: context string and payload hash.
    ///
    /// This is the domain-separation gate.  A wrapper built for another
    /// payload type fails here even if its signature is otherwise valid.
    pub fn verify_payload(&self, payload: &T) -> Result<(), SignedOperationError> {
        if self.context_string != T::CONTEXT {
            return Err(SignedOperationError::ContextMismatch {
                expected: T::CONTEXT,
                actual: self.context_string.clone(),
            });
        }
        if self.payload_hash != payload_hash(payload)? {
            return Err(SignedOperationError::PayloadHashMismatch);
        }
        Ok(())
    }

    /// Verify one entry against a raw Ed25519 public key.
    pub fn verify_entry(
        &self,
        entry: &SignatureEntry,
        public_key: &[u8],
    ) -> Result<(), SignedOperationError> {
        let public_key: [u8; 32] =
            public_key
                .try_into()
                .map_err(|_| SignedOperationError::SignatureVerification {
                    signer_did: entry.signer_did.clone(),
                })?;

        match &entry.signature {
            DeviceSignature::Ed25519(bytes) => keypair::verify(
                &public_key,
                &self.signing_bytes(),
                &Ed25519Signature::from_bytes(*bytes),
            )
            .map_err(|_| SignedOperationError::SignatureVerification {
                signer_did: entry.signer_did.clone(),
            }),
            DeviceSignature::P256(_) => Err(SignedOperationError::UnsupportedKeyType(
                entry.signature.clone(),
            )),
        }
    }

    /// Verify every signature using a DID → public-key resolver.
    pub fn verify_signatures(
        &self,
        resolve: impl Fn(&str) -> Option<Vec<u8>>,
    ) -> Result<(), SignedOperationError> {
        if self.signatures.is_empty() {
            return Err(SignedOperationError::EmptySignatures);
        }
        for entry in &self.signatures {
            let public_key = resolve(&entry.signer_did)
                .ok_or_else(|| SignedOperationError::UnknownSigner(entry.signer_did.clone()))?;
            self.verify_entry(entry, &public_key)?;
        }
        Ok(())
    }

    /// Full verification: domain separation, payload binding, then signatures.
    ///
    /// Verification order is deliberate — the domain check runs before any
    /// signature or role logic, so a cross-type signature is rejected for the
    /// right reason.
    pub fn verify(
        &self,
        payload: &T,
        resolve: impl Fn(&str) -> Option<Vec<u8>>,
    ) -> Result<(), SignedOperationError> {
        self.verify_payload(payload)?;
        self.verify_signatures(resolve)
    }
}

/// SHA-256 of deterministic CBOR encoding of `payload`.
fn payload_hash<T: Serialize>(payload: &T) -> Result<[u8; 32], SignedOperationError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(payload, &mut bytes)
        .map_err(|error| SignedOperationError::Serialization(error.to_string()))?;
    Ok(Sha256::digest(&bytes).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;

    #[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct PolicyBundleLike {
        version: u64,
        tightened: bool,
    }

    impl SignedOperationPayload for PolicyBundleLike {
        const CONTEXT: &'static str = CONTEXT_POLICY_BUNDLE;
    }

    #[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct LockdownExitLike {
        version: u64,
        tightened: bool,
    }

    impl SignedOperationPayload for LockdownExitLike {
        const CONTEXT: &'static str = CONTEXT_LOCKDOWN_EXIT;
    }

    fn resolver(provider: &InMemoryKeyProvider) -> impl Fn(&str) -> Option<Vec<u8>> + '_ {
        move |did| {
            if did == provider.did() {
                Some(provider.public_key_bytes())
            } else {
                None
            }
        }
    }

    #[test]
    fn signed_operation_binds_payload_and_verifies() {
        let provider = InMemoryKeyProvider::generate().unwrap();
        let payload = PolicyBundleLike {
            version: 7,
            tightened: true,
        };

        let mut op = SignedOperation::<PolicyBundleLike>::new(&payload, 1_000, Some(2_000))
            .expect("wrap payload");
        op.sign_with(&provider, CommandRole::PolicyAuthority)
            .expect("sign");

        assert_eq!(op.context_string, CONTEXT_POLICY_BUNDLE);
        op.verify(&payload, resolver(&provider))
            .expect("valid operation verifies");
    }

    #[test]
    fn cross_type_signature_reuse_is_rejected_by_domain_separation() {
        let provider = InMemoryKeyProvider::generate().unwrap();
        let payload = PolicyBundleLike {
            version: 7,
            tightened: true,
        };
        let mut op =
            SignedOperation::<PolicyBundleLike>::new(&payload, 1_000, None).expect("wrap payload");
        op.sign_with(&provider, CommandRole::PolicyAuthority)
            .expect("sign");
        op.verify(&payload, resolver(&provider)).expect("valid");

        // Re-use the signature verbatim in a different artefact type with the
        // same payload shape.  The context check rejects it.
        let reused = SignedOperation::<LockdownExitLike> {
            context_string: op.context_string.clone(),
            payload_hash: op.payload_hash,
            signatures: op.signatures.clone(),
            created_est: op.created_est,
            expires_est: op.expires_est,
            _payload: PhantomData,
        };
        let other_payload = LockdownExitLike {
            version: 7,
            tightened: true,
        };

        assert_eq!(
            reused.verify(&other_payload, resolver(&provider)),
            Err(SignedOperationError::ContextMismatch {
                expected: CONTEXT_LOCKDOWN_EXIT,
                actual: CONTEXT_POLICY_BUNDLE.to_string(),
            }),
            "a PolicyBundle signature must not authorize a LockdownExit"
        );
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let provider = InMemoryKeyProvider::generate().unwrap();
        let payload = PolicyBundleLike {
            version: 7,
            tightened: true,
        };
        let mut op = SignedOperation::<PolicyBundleLike>::new(&payload, 1_000, None).unwrap();
        op.sign_with(&provider, CommandRole::PolicyAuthority)
            .unwrap();

        let tampered = PolicyBundleLike {
            version: 8,
            tightened: true,
        };
        assert_eq!(
            op.verify(&tampered, resolver(&provider)),
            Err(SignedOperationError::PayloadHashMismatch)
        );
    }

    #[test]
    fn tampered_context_invalidates_the_signature() {
        let provider = InMemoryKeyProvider::generate().unwrap();
        let payload = PolicyBundleLike {
            version: 7,
            tightened: true,
        };
        let mut op = SignedOperation::<PolicyBundleLike>::new(&payload, 1_000, None).unwrap();
        op.sign_with(&provider, CommandRole::PolicyAuthority)
            .unwrap();

        // Same type, altered domain string: verify_payload catches the
        // mismatch before signatures are even considered.
        let mut altered = op.clone();
        altered.context_string = "TirBase/v1/Other".to_string();
        assert!(matches!(
            altered.verify(&payload, resolver(&provider)),
            Err(SignedOperationError::ContextMismatch { .. })
        ));
    }

    #[test]
    fn empty_signatures_are_rejected() {
        let payload = PolicyBundleLike {
            version: 1,
            tightened: false,
        };
        let op = SignedOperation::<PolicyBundleLike>::new(&payload, 0, None).unwrap();
        assert_eq!(
            op.verify(&payload, |_| Some(vec![0u8; 32])),
            Err(SignedOperationError::EmptySignatures)
        );
    }

    #[test]
    fn payload_hash_is_deterministic_and_context_specific_bytes() {
        let payload = PolicyBundleLike {
            version: 3,
            tightened: false,
        };
        let a = SignedOperation::<PolicyBundleLike>::new(&payload, 0, None).unwrap();
        let b = SignedOperation::<PolicyBundleLike>::new(&payload, 0, None).unwrap();
        assert_eq!(a.payload_hash, b.payload_hash);

        let bytes = a.signing_bytes();
        assert!(bytes.starts_with(CONTEXT_POLICY_BUNDLE.as_bytes()));
        assert_eq!(bytes[CONTEXT_POLICY_BUNDLE.len()], 0);
        assert_eq!(&bytes[CONTEXT_POLICY_BUNDLE.len() + 1..], &a.payload_hash);
    }
}

/// Context string for `EnvelopeProfile` policy documents (CLAIM-10.4, PV-4.5).
pub const CONTEXT_ENVELOPE_PROFILE: &str = "TirBase/v1/EnvelopeProfile";
/// Context string for `AntiReplayWindowReset` (CLAIM-20.3, PV-5.5).
pub const CONTEXT_ANTI_REPLAY_WINDOW_RESET: &str = "TirBase/v1/AntiReplayWindowReset";
/// Context string for signed hash-chain recovery (CLAIM-26.2, PV-7.4, INV-4).
pub const CONTEXT_CHAIN_RECOVERY: &str = "TirBase/v1/ChainRecovery";
