//! Policy bundle wire types (task 12.1 — CLAIM-12.1, PV-4.8).
//!
//! `PolicyBundle` is the artefact submitted to the policy-push path.  The
//! `kind` field is present for diagnostics but MUST NEVER be trusted: the guard
//! always re-computes classification via `classify_bundle()` and ignores
//! `bundle.kind` (CLAIM-12.2, INV-8).  `timelock_until_est` is computed on
//! ingest from the **active** policy and is not part of the wire format.

extern crate alloc;

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::envelope::EnvelopeProfile;
use crate::DeviceSignature;

/// Classification of a policy bundle relative to the currently active profile.
///
/// Computed by `tirbase_guard::policy::classify_bundle()`; the guard ignores any
/// `kind` carried in a received [`PolicyBundle`] (CLAIM-12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyBundleKind {
    /// Every parameter/constraint/governance change is a strict tightening (or
    /// unchanged); the bundle may be applied immediately (PV-4.9).
    Tightening,
    /// Any loosening, ambiguity, mixed change, or governance weakening; requires
    /// M-of-N co-signatures and a time-lock read from the active policy (PV-4.10).
    Loosening,
}

/// One co-signature attached to a [`PolicyBundle`].
///
/// Uses the same domain-separated signing bytes as `SignedOperation` policy
/// bundles (`TirBase/v1/PolicyBundle || 0x00 || SHA-256(CBOR(body))`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCoSignature {
    /// DID of the signer.
    pub signer_did: alloc::string::String,
    /// Signature over the policy-bundle signing bytes.
    pub signature: DeviceSignature,
}

/// The unsigned body of a [`PolicyBundle`], used for hashing/signing and for
/// anti-rollback binding via `prev_version_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyBundleBody<'a> {
    pub version: u64,
    pub prev_version_hash: &'a [u8; 32],
    pub envelope: &'a EnvelopeProfile,
}

/// Policy bundle wire type (PV-4.8, CLAIM-12.1).
///
/// * `version` must be **strictly greater** than the last accepted version
///   (not exactly +1), supporting partitioned devices missing versions.
/// * `prev_version_hash` binds this bundle to the hash of the previously
///   accepted bundle body.
/// * `kind` is present per task 12.1 but is **never trusted** by the guard.
/// * Co-signatures are collected for loosening operations; tightening may be
///   single-signed by PolicyAuthority (subject to startup diagnostic rules).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundle {
    /// Monotonically increasing bundle version (strictly greater than last).
    pub version: u64,
    /// SHA-256 hash of the previous accepted bundle's canonical body.
    pub prev_version_hash: [u8; 32],
    /// The envelope profile this bundle installs.
    pub envelope: EnvelopeProfile,
    /// Co-signatures authorising this bundle.
    pub co_signatures: Vec<PolicyCoSignature>,
    /// Claimed classification — **ignored by the guard** (CLAIM-12.2).
    #[serde(default = "default_kind_loosening")]
    pub kind: PolicyBundleKind,
}

fn default_kind_loosening() -> PolicyBundleKind {
    // Conservative default: if a receiver cannot trust the field, treat as
    // loosening.  The guard always reclassifies regardless.
    PolicyBundleKind::Loosening
}

impl PolicyBundle {
    /// Borrow the unsigned body for hashing / signing.
    pub fn body(&self) -> PolicyBundleBody<'_> {
        PolicyBundleBody {
            version: self.version,
            prev_version_hash: &self.prev_version_hash,
            envelope: &self.envelope,
        }
    }
}
