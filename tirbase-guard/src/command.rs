//! `CommandMessage` signing and verification (PV-4.1, PV-4.2, CLAIM-11.1).
//!
//! The data type lives in [`tirbase_types::command`].  This module provides the
//! production signing and verification helpers used by ingress paths and the
//! guard: the signature covers the **canonical CBOR** of all fields except
//! `signature`, prefixed by the domain-separation context
//! `TirBase/v1/CommandMessage`.

use sha2::{Digest, Sha256};
use tirbase_core::crdt::delta::Ed25519Signature;
use tirbase_core::identity::{did as did_identity, keypair};
use tirbase_core::traits::KeyProvider;
use tirbase_types::command::{CommandMessage, CONTEXT_COMMAND_MESSAGE};
use tirbase_types::DeviceSignature;

/// Domain-separated signing bytes for a [`CommandMessage`].
///
/// Format: `CONTEXT_COMMAND_MESSAGE || 0x00 || SHA-256(CBOR(body))`, where
/// `body` is every field except `signature`.
pub fn command_signing_bytes(cmd: &CommandMessage) -> Result<Vec<u8>, CommandError> {
    let mut body_bytes = Vec::new();
    ciborium::ser::into_writer(&cmd.body(), &mut body_bytes)
        .map_err(|e| CommandError::Serialization(e.to_string()))?;
    let hash = Sha256::digest(&body_bytes);
    let mut out = Vec::with_capacity(CONTEXT_COMMAND_MESSAGE.len() + 1 + hash.len());
    out.extend_from_slice(CONTEXT_COMMAND_MESSAGE.as_bytes());
    out.push(0);
    out.extend_from_slice(&hash);
    Ok(out)
}

/// Sign `cmd` in place using `provider`.  The `signature` field is overwritten.
pub fn sign_command(
    cmd: &mut CommandMessage,
    provider: &dyn KeyProvider,
) -> Result<(), CommandError> {
    let bytes = command_signing_bytes(cmd)?;
    cmd.signature = provider
        .sign(&bytes)
        .map_err(|e| CommandError::Signature(e.to_string()))?;
    Ok(())
}

/// Verify `cmd.signature` against `cmd.issuer_did`.
///
/// The issuer DID must resolve to an Ed25519 public key (multicodec 0xed01)
/// and that key must verify the signature over the canonical, domain-separated
/// signing bytes.  Unsigned / malformed / mismatched signatures are rejected.
pub fn verify_command_signature(cmd: &CommandMessage) -> Result<(), CommandError> {
    let bytes = command_signing_bytes(cmd)?;
    let did_str = cmd.issuer_did.as_str().to_string();
    let public_key = did_identity::resolve_did(&did_str)
        .map_err(|e| CommandError::InvalidIssuerDid(e.to_string()))?;
    match &cmd.signature {
        DeviceSignature::Ed25519(sig_bytes) => keypair::verify(
            &public_key,
            &bytes,
            &Ed25519Signature::from_bytes(*sig_bytes),
        )
        .map_err(|e| CommandError::Signature(e.to_string())),
        DeviceSignature::P256(_) => Err(CommandError::UnsupportedSignature(
            "P-256 command signatures are not supported by this guard".to_string(),
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandError {
    Serialization(String),
    Signature(String),
    InvalidIssuerDid(String),
    UnsupportedSignature(String),
    MissingField(String),
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandError::Serialization(e) => write!(f, "command serialization failed: {e}"),
            CommandError::Signature(e) => write!(f, "command signature verification failed: {e}"),
            CommandError::InvalidIssuerDid(e) => write!(f, "invalid issuer DID: {e}"),
            CommandError::UnsupportedSignature(e) => write!(f, "unsupported signature: {e}"),
            CommandError::MissingField(e) => write!(f, "missing command field: {e}"),
        }
    }
}

impl std::error::Error for CommandError {}
