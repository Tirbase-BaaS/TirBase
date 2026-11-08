//! `CommandMessage` — signed declarative desired-state command (PV-4.1, PV-4.2,
//! CLAIM-11.1).
//!
//! Commands are **not** Automerge field writes.  They express only declarative
//! desired state (`target.parameter = value`).  The signature covers the
//! canonical CBOR encoding of every field **except** `signature` itself.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::fixed_point::FixedPointValue;
use crate::{CommandRole, DeviceSignature, Did, TargetId};

/// Domain-separation context for `CommandMessage` signatures (PV-4.2).
pub const CONTEXT_COMMAND_MESSAGE: &str = "TirBase/v1/CommandMessage";

/// A signed command expressing declarative desired state (PV-4.1, PV-4.2).
///
/// The `role` field is carried for audit/display, but the guard **never**
/// trusts it — role is derived from the verified Biscuit token at Stage 4.
/// `signature` is verified over the canonical CBOR of [`CommandMessageBody`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandMessage {
    pub issuer_did: Did,
    /// Carried for audit; never trusted for authorization.
    pub role: CommandRole,
    pub target_id: TargetId,
    /// Name of the parameter being set.
    pub param: String,
    pub desired_state: FixedPointValue,
    pub sequence_number: u64,
    pub idempotency_key: [u8; 16],
    /// Authenticated-time estimate (now_est model, PV-22). Wall clock is never
    /// used directly for expiry evaluation.
    pub expiry_est: i64,
    pub policy_version: u64,
    /// Device enrollment epoch at command creation (PV-5.5, PV-9.8).
    pub enrollment_epoch: u64,
    /// Required when `FreshnessState::Unverified` and the parameter is critical.
    pub challenge_nonce: Option<[u8; 32]>,
    /// Co-signatures for `critical: true` quorum (PV-4.16).  Uses the same
    /// `SignatureEntry` shape as multi-party operations.
    pub co_signatures: Vec<CoSignature>,
    /// Signature over canonical CBOR of all fields except this one.
    pub signature: DeviceSignature,
}

/// Co-signature carried on a critical-parameter command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoSignature {
    pub signer_did: String,
    pub role: CommandRole,
    pub signature: DeviceSignature,
}

/// Unsigned body of a [`CommandMessage`] — the canonical bytes covered by
/// `signature`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommandMessageBody<'a> {
    pub issuer_did: &'a Did,
    pub role: CommandRole,
    pub target_id: &'a TargetId,
    pub param: &'a str,
    pub desired_state: &'a FixedPointValue,
    pub sequence_number: u64,
    pub idempotency_key: &'a [u8; 16],
    pub expiry_est: i64,
    pub policy_version: u64,
    pub enrollment_epoch: u64,
    pub challenge_nonce: &'a Option<[u8; 32]>,
    pub co_signatures: &'a [CoSignature],
}

impl CommandMessage {
    /// Borrow the unsigned body for signing/verification.
    pub fn body(&self) -> CommandMessageBody<'_> {
        CommandMessageBody {
            issuer_did: &self.issuer_did,
            role: self.role,
            target_id: &self.target_id,
            param: &self.param,
            desired_state: &self.desired_state,
            sequence_number: self.sequence_number,
            idempotency_key: &self.idempotency_key,
            expiry_est: self.expiry_est,
            policy_version: self.policy_version,
            enrollment_epoch: self.enrollment_epoch,
            challenge_nonce: &self.challenge_nonce,
            co_signatures: &self.co_signatures,
        }
    }
}
