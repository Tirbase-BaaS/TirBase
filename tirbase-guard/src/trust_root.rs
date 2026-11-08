//! Trust root record and role registry (task 8.3 / 8.3a — CLAIM-8.3, CLAIM-8.3a,
//! PV-3.2, PV-3.3, PV-3.4).
//!
//! The offline root ceremony produces a [`TrustRootRecord`]: a versioned,
//! threshold-signed description of
//!
//! * the active root CA public keys and the k-of-n threshold that authorises
//!   root rotation,
//! * the per-role co-signature policy and the DID public keys authorised to
//!   co-sign for each [`CommandRole`],
//! * per-device-class tightening floors, and
//! * an expiry in authenticated time.
//!
//! ## Role registry (PV-3.2, PV-3.3)
//!
//! The role registry is deliberately part of the trust root, not the active
//! policy bundle: a PolicyAuthority cannot add itself to a role.  Before any
//! co-signature is accepted, [`TrustRootRecord::verify_role_signatures`] first
//! checks that the signer DID appears in the role's
//! [`RolePolicy::authorized_signers`] list.  A cryptographically valid
//! signature from a DID that is not registered for the claimed role is rejected
//! with [`TrustRootError::RoleNotAuthorized`] — it is never even fed to the
//! verifier.
//!
//! ## Root rollback protection (task 8.2 — CLAIM-8.2)
//!
//! [`TrustRootManager`] commits every installed trust-root version to a
//! [`MonotonicCounterTrait`].  A record whose version is not strictly greater
//! than the committed counter value is rejected as a rollback, so restoring an
//! old `trust-root.json` cannot re-introduce revoked root keys.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tirbase_core::crdt::delta::Ed25519Signature;
use tirbase_core::identity::{did as did_identity, keypair};
use tirbase_core::traits::MonotonicCounterTrait;
use tirbase_types::{CommandRole, DeviceSignature, FixedPointValue};

use crate::signed_operation::SignatureEntry;

/// One DID public key authorised to co-sign for a role (PV-3.2, PV-3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedRoleSigner {
    /// DID bound to `public_key` (`did:key:z6Mk…`).
    pub did: String,
    /// Raw Ed25519 public key bytes.
    pub public_key: Vec<u8>,
}

/// Co-signature policy for one role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolePolicy {
    /// Minimum number of distinct authorised co-signatures required.
    pub required_m: u8,
    /// Total number of authorised signers in the policy (informational; the
    /// authoritative list is [`Self::authorized_signers`]).
    pub required_n: u8,
    /// DID public keys authorised for this role.  A signer absent from this
    /// list is rejected before its signature is verified.
    #[serde(default)]
    pub authorized_signers: Vec<AuthorizedRoleSigner>,
}

impl RolePolicy {
    /// Construct a policy with an explicit authorised-signer list.
    pub fn new(required_m: u8, authorized_signers: Vec<AuthorizedRoleSigner>) -> Self {
        RolePolicy {
            required_m,
            required_n: authorized_signers.len() as u8,
            authorized_signers,
        }
    }

    /// Whether `signer_did` is registered for this role.
    pub fn is_authorized(&self, signer_did: &str) -> bool {
        self.authorized_signers
            .iter()
            .any(|signer| signer.did == signer_did)
    }

    /// Public key registered for `signer_did`, if any.
    pub fn public_key_for(&self, signer_did: &str) -> Option<&[u8]> {
        self.authorized_signers
            .iter()
            .find(|signer| signer.did == signer_did)
            .map(|signer| signer.public_key.as_slice())
    }
}

/// A tightening floor for one parameter, sourced from the signed trust root.
///
/// Tightening may move `min` upwards or `max` downwards but never below
/// `min_floor` or above `max_ceiling` (PV-4.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamFloor {
    /// Parameter name.
    pub param_name: String,
    /// Tightening cannot push `min` below this value.
    pub min_floor: FixedPointValue,
    /// Tightening cannot push `max` above this value.
    pub max_ceiling: FixedPointValue,
}

/// One threshold signature over the unsigned trust-root body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRootSignature {
    /// DID of the root-key holder.
    pub signer_did: String,
    /// Signature over [`TrustRootRecord::signing_bytes`].
    pub signature: DeviceSignature,
}

/// The unsigned body hashed for trust-root signatures.
#[derive(Debug, Clone, Serialize)]
struct TrustRootSigningBody<'a> {
    version: u64,
    root_ca_public_keys: &'a [Vec<u8>],
    threshold_k: u8,
    role_thresholds: &'a BTreeMap<CommandRole, RolePolicy>,
    device_class_floors: &'a BTreeMap<String, Vec<ParamFloor>>,
    expiry_est: i64,
    revoked_root_ca_keys: &'a [Vec<u8>],
}

/// Versioned, threshold-signed trust root (PV-3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRootRecord {
    /// Monotonically increasing trust-root version (rollback protected).
    pub version: u64,
    /// Active k-of-n root CA Ed25519 public keys.
    pub root_ca_public_keys: Vec<Vec<u8>>,
    /// k in the root k-of-n rotation threshold (`k >= 1`).
    pub threshold_k: u8,
    /// Per-role co-signature policy and authorised DID public keys.
    pub role_thresholds: BTreeMap<CommandRole, RolePolicy>,
    /// Per-device-class tightening floors.  This is the authoritative source
    /// for policy classification — never read from an incoming bundle.
    pub device_class_floors: BTreeMap<String, Vec<ParamFloor>>,
    /// Expiry in authenticated-time seconds (`now_est > expiry_est` rejects).
    pub expiry_est: i64,
    /// Root CA keys revoked by a rotation ceremony.
    #[serde(default)]
    pub revoked_root_ca_keys: Vec<Vec<u8>>,
    /// Threshold signatures by the root keys over [`Self::signing_bytes`].
    #[serde(default)]
    pub signatures: Vec<TrustRootSignature>,
}

impl TrustRootRecord {
    /// Root keys that are still active (not revoked).
    pub fn active_root_ca_keys(&self) -> Vec<&[u8]> {
        self.root_ca_public_keys
            .iter()
            .filter(|key| {
                !self
                    .revoked_root_ca_keys
                    .iter()
                    .any(|revoked| revoked.as_slice() == key.as_slice())
            })
            .map(Vec::as_slice)
            .collect()
    }

    /// Whether `key` is explicitly revoked.
    pub fn is_root_revoked(&self, key: &[u8]) -> bool {
        self.revoked_root_ca_keys
            .iter()
            .any(|revoked| revoked.as_slice() == key)
    }

    /// The role policy for `role`, if configured.
    pub fn role_policy(&self, role: CommandRole) -> Option<&RolePolicy> {
        self.role_thresholds.get(&role)
    }

    /// Co-signature threshold for `role` (`None` when the role is unknown).
    pub fn role_threshold(&self, role: CommandRole) -> Option<u8> {
        self.role_policy(role).map(|policy| policy.required_m)
    }

    /// Tightening floor for `param` in `device_class`.
    pub fn device_class_floor(&self, device_class: &str, param: &str) -> Option<&ParamFloor> {
        self.device_class_floors
            .get(device_class)
            .and_then(|floors| floors.iter().find(|floor| floor.param_name == param))
    }

    /// Whether the record has expired at `now_est`.
    pub fn is_expired(&self, now_est: i64) -> bool {
        now_est > self.expiry_est
    }

    /// Startup diagnostic: k=1 is permitted (small deployments) but the
    /// rotation ceremony has no threshold protection, so the gateway emits a
    /// warning at boot (PV-3.4, scenario S11).
    pub fn threshold_warning(&self) -> Option<String> {
        (self.threshold_k == 1).then(|| {
            "trust root threshold k=1: a single root key can rotate the root — \
             k>=2 is strongly recommended (PV-3.4/S11)"
                .to_string()
        })
    }

    /// Domain-separated bytes signed by the root CA keys.
    ///
    /// The signature covers `"TirBase/v1/TrustRootRecord" || 0x00 ||
    /// SHA-256(CBOR(unsigned body))`, so a signature for another artefact type
    /// cannot be reused and the `signatures` field is not self-referential.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let body = TrustRootSigningBody {
            version: self.version,
            root_ca_public_keys: &self.root_ca_public_keys,
            threshold_k: self.threshold_k,
            role_thresholds: &self.role_thresholds,
            device_class_floors: &self.device_class_floors,
            expiry_est: self.expiry_est,
            revoked_root_ca_keys: &self.revoked_root_ca_keys,
        };
        let mut cbor = Vec::new();
        // Infallible for these plain data types; an empty buffer would simply
        // fail signature verification, never accept an unsigned record.
        let _ = ciborium::ser::into_writer(&body, &mut cbor);
        let digest = Sha256::digest(&cbor);

        let mut bytes = Vec::with_capacity("TirBase/v1/TrustRootRecord".len() + 1 + 32);
        bytes.extend_from_slice(b"TirBase/v1/TrustRootRecord");
        bytes.push(0);
        bytes.extend_from_slice(&digest);
        bytes
    }

    /// Verify the root k-of-n threshold signatures over this record.
    ///
    /// Each signature must be from an active root key (the signer DID must
    /// derive from that key) and a distinct signer is required.  Returns the
    /// number of valid signatures; the caller compares against
    /// [`Self::threshold_k`].
    pub fn count_valid_root_signatures(&self) -> usize {
        let message = self.signing_bytes();
        let active = self.active_root_ca_keys();
        let mut seen = Vec::new();

        for entry in &self.signatures {
            if seen.iter().any(|did: &String| did == &entry.signer_did) {
                continue;
            }
            let Some(key) = active
                .iter()
                .find(|key| did_for_key(key) == entry.signer_did)
            else {
                continue;
            };
            if verify_signature(key, &message, &entry.signature) {
                seen.push(entry.signer_did.clone());
            }
        }

        seen.len()
    }

    /// Verify the root threshold signatures (PV-3.4).
    pub fn verify_threshold_signatures(&self) -> Result<(), TrustRootError> {
        if self.threshold_k == 0 {
            return Err(TrustRootError::InvalidThreshold {
                reason: "root threshold k must be >= 1".to_string(),
            });
        }
        if (self.active_root_ca_keys().len() as u8) < self.threshold_k {
            return Err(TrustRootError::InvalidThreshold {
                reason: format!(
                    "only {} active root key(s) but threshold k={}",
                    self.active_root_ca_keys().len(),
                    self.threshold_k
                ),
            });
        }
        let valid = self.count_valid_root_signatures();
        if valid < usize::from(self.threshold_k) {
            return Err(TrustRootError::ThresholdNotMet {
                got: valid,
                need: usize::from(self.threshold_k),
            });
        }
        Ok(())
    }

    /// Verify that `signer_did` is registered for `role` and that
    /// `signature` verifies over `message`.
    ///
    /// The role-registry lookup happens **before** signature verification
    /// (PV-3.3): a valid signature from an unregistered DID is rejected with
    /// [`TrustRootError::RoleNotAuthorized`].
    pub fn verify_role_cosignature(
        &self,
        role: CommandRole,
        signer_did: &str,
        message: &[u8],
        signature: &DeviceSignature,
    ) -> Result<(), TrustRootError> {
        let policy = self
            .role_policy(role)
            .ok_or(TrustRootError::RoleNotConfigured { role })?;
        let public_key = policy
            .public_key_for(signer_did)
            .ok_or_else(|| TrustRootError::RoleNotAuthorized {
                role,
                signer_did: signer_did.to_string(),
            })?;
        if !verify_signature(public_key, message, signature) {
            return Err(TrustRootError::SignatureInvalid {
                signer_did: signer_did.to_string(),
            });
        }
        Ok(())
    }

    /// Verify a full set of co-signatures for `role` against `message`.
    ///
    /// This is the multi-signature verification path used by
    /// [`SignedOperation`](crate::signed_operation::SignedOperation) callers
    /// (epoch bump, lockdown exit, policy bundle).  It:
    ///
    /// 1. rejects an unknown role,
    /// 2. rejects any entry whose claimed role differs from `role`,
    /// 3. rejects any entry whose DID is not in the role registry **before**
    ///    verifying its signature (PV-3.2/PV-3.3), and
    /// 4. requires at least `required_m` distinct valid signatures.
    pub fn verify_role_signatures(
        &self,
        role: CommandRole,
        message: &[u8],
        signatures: &[SignatureEntry],
    ) -> Result<(), TrustRootError> {
        let policy = self
            .role_policy(role)
            .ok_or(TrustRootError::RoleNotConfigured { role })?;

        let mut distinct = Vec::new();
        for entry in signatures {
            if entry.role != role {
                return Err(TrustRootError::RoleMismatch {
                    expected: role,
                    actual: entry.role,
                });
            }
            if distinct.iter().any(|did: &String| did == &entry.signer_did) {
                continue;
            }
            self.verify_role_cosignature(role, &entry.signer_did, message, &entry.signature)?;
            distinct.push(entry.signer_did.clone());
        }

        let need = usize::from(policy.required_m);
        if distinct.len() < need {
            return Err(TrustRootError::ThresholdNotMet {
                got: distinct.len(),
                need,
            });
        }
        Ok(())
    }

    /// Validate structural invariants that must hold regardless of signatures.
    pub fn validate(&self, now_est: i64) -> Result<(), TrustRootError> {
        if self.threshold_k == 0 {
            return Err(TrustRootError::InvalidThreshold {
                reason: "root threshold k must be >= 1 (PV-3.4)".to_string(),
            });
        }
        if self.active_root_ca_keys().is_empty() {
            return Err(TrustRootError::InvalidThreshold {
                reason: "no active root CA keys (all revoked or none configured)".to_string(),
            });
        }
        if (self.active_root_ca_keys().len() as u8) < self.threshold_k {
            return Err(TrustRootError::InvalidThreshold {
                reason: format!(
                    "active root keys ({}) fewer than threshold k={}",
                    self.active_root_ca_keys().len(),
                    self.threshold_k
                ),
            });
        }
        if self.is_expired(now_est) {
            return Err(TrustRootError::Expired {
                expiry_est: self.expiry_est,
                now_est,
            });
        }
        Ok(())
    }
}

/// Derive the `did:key` DID for an Ed25519 public key.
fn did_for_key(public_key: &[u8]) -> String {
    match <[u8; 32]>::try_from(public_key) {
        Ok(key) => did_identity::derive_did(&key).to_string(),
        Err(_) => String::new(),
    }
}

/// Verify one Ed25519 signature; P-256 is not accepted by the v1 trust root.
fn verify_signature(public_key: &[u8], message: &[u8], signature: &DeviceSignature) -> bool {
    let Ok(key) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };
    match signature {
        DeviceSignature::Ed25519(bytes) => keypair::verify(
            &key,
            message,
            &Ed25519Signature::from_bytes(*bytes),
        )
        .is_ok(),
        DeviceSignature::P256(_) => false,
    }
}

/// Trust-root installation and rotation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustRootError {
    /// The record is older than the committed trust-root version.
    Rollback {
        /// Version in the rejected record.
        incoming: u64,
        /// Version currently committed to the monotonic counter.
        current: u64,
    },
    /// The record's expiry has passed.
    Expired {
        /// Record expiry.
        expiry_est: i64,
        /// Current authenticated time.
        now_est: i64,
    },
    /// Structural threshold problem.
    InvalidThreshold {
        /// Human-readable reason.
        reason: String,
    },
    /// Not enough valid signatures.
    ThresholdNotMet {
        /// Valid signatures found.
        got: usize,
        /// Signatures required.
        need: usize,
    },
    /// A signer is not registered for the claimed role.
    RoleNotAuthorized {
        /// Claimed role.
        role: CommandRole,
        /// Offending DID.
        signer_did: String,
    },
    /// No policy is configured for the role.
    RoleNotConfigured {
        /// Missing role.
        role: CommandRole,
    },
    /// A signature entry claims a different role than the one being verified.
    RoleMismatch {
        /// Expected role.
        expected: CommandRole,
        /// Role in the entry.
        actual: CommandRole,
    },
    /// A signature failed cryptographic verification.
    SignatureInvalid {
        /// Offending DID.
        signer_did: String,
    },
    /// The monotonic counter failed.
    Counter(String),
}

impl fmt::Display for TrustRootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustRootError::Rollback { incoming, current } => write!(
                f,
                "trust-root rollback rejected: incoming version {incoming} <= committed version {current}"
            ),
            TrustRootError::Expired {
                expiry_est,
                now_est,
            } => write!(
                f,
                "trust-root record expired: now_est {now_est} > expiry_est {expiry_est}"
            ),
            TrustRootError::InvalidThreshold { reason } => {
                write!(f, "invalid trust-root threshold: {reason}")
            }
            TrustRootError::ThresholdNotMet { got, need } => {
                write!(f, "trust-root threshold not met: got {got}, need {need}")
            }
            TrustRootError::RoleNotAuthorized { role, signer_did } => write!(
                f,
                "role {} co-signature rejected: {signer_did} is not in the role registry",
                role.as_str()
            ),
            TrustRootError::RoleNotConfigured { role } => {
                write!(f, "no role policy configured for {}", role.as_str())
            }
            TrustRootError::RoleMismatch { expected, actual } => write!(
                f,
                "co-signature role mismatch: expected {}, got {}",
                expected.as_str(),
                actual.as_str()
            ),
            TrustRootError::SignatureInvalid { signer_did } => {
                write!(f, "co-signature verification failed for {signer_did}")
            }
            TrustRootError::Counter(reason) => write!(f, "trust-root counter error: {reason}"),
        }
    }
}

impl std::error::Error for TrustRootError {}

impl From<tirbase_core::errors::TirBaseError> for TrustRootError {
    fn from(error: tirbase_core::errors::TirBaseError) -> Self {
        TrustRootError::Counter(error.to_string())
    }
}

/// Installs and rotates trust-root records under monotonic-counter rollback
/// protection (task 8.2 — CLAIM-8.2, PV-3.4).
#[derive(Debug)]
pub struct TrustRootManager {
    record: TrustRootRecord,
    counter: Arc<dyn MonotonicCounterTrait>,
}

impl TrustRootManager {
    /// Install the initial record.
    ///
    /// The committed counter starts at the installed version.  Every later
    /// [`Self::rotate`] must present a strictly greater version.
    pub fn install(
        record: TrustRootRecord,
        counter: Arc<dyn MonotonicCounterTrait>,
        now_est: i64,
    ) -> Result<Self, TrustRootError> {
        record.validate(now_est)?;
        let current = counter.read()?;
        if record.version < current {
            return Err(TrustRootError::Rollback {
                incoming: record.version,
                current,
            });
        }
        counter.set_if_greater(record.version)?;
        Ok(TrustRootManager { record, counter })
    }

    /// Rotate to a new record, rejecting version rollback (task 8.2).
    ///
    /// Root revocation is expressed by listing the key in
    /// `revoked_root_ca_keys`: a rotation that revokes a key and keeps the
    /// remaining active keys at or above `threshold_k` is accepted; a rotation
    /// that rolls the version back is rejected before anything is committed.
    pub fn rotate(
        &mut self,
        record: TrustRootRecord,
        now_est: i64,
    ) -> Result<(), TrustRootError> {
        record.validate(now_est)?;
        let current = self.counter.read()?;
        if record.version <= current {
            return Err(TrustRootError::Rollback {
                incoming: record.version,
                current,
            });
        }
        self.counter.set_if_greater(record.version)?;
        self.record = record;
        Ok(())
    }

    /// Current installed record.
    pub fn record(&self) -> &TrustRootRecord {
        &self.record
    }

    /// Committed trust-root version.
    pub fn committed_version(&self) -> Result<u64, TrustRootError> {
        Ok(self.counter.read()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
    use tirbase_core::traits::KeyProvider;

    fn signer(statement: &str) -> (InMemoryKeyProvider, AuthorizedRoleSigner) {
        let provider = InMemoryKeyProvider::generate().expect("key");
        let signer = AuthorizedRoleSigner {
            did: provider.did().to_string(),
            public_key: provider.public_key_bytes(),
        };
        let _ = statement;
        (provider, signer)
    }

    fn base_record() -> TrustRootRecord {
        TrustRootRecord {
            version: 1,
            root_ca_public_keys: Vec::new(),
            threshold_k: 1,
            role_thresholds: BTreeMap::new(),
            device_class_floors: BTreeMap::new(),
            expiry_est: 4_000_000_000,
            revoked_root_ca_keys: Vec::new(),
            signatures: Vec::new(),
        }
    }

    #[test]
    fn k_equals_one_emits_the_startup_warning_and_k_ge_two_does_not() {
        let mut record = base_record();
        assert!(record.threshold_warning().is_some());
        record.threshold_k = 2;
        assert!(record.threshold_warning().is_none());
    }

    #[test]
    fn co_signature_from_did_not_in_role_registry_is_rejected_even_when_valid() {
        // Authorised PolicyAuthority and an unregistered attacker with a
        // perfectly valid key.
        let (authorized, authorized_signer) = signer("authorized");
        let (attacker, _) = signer("attacker");
        let mut record = base_record();
        record.role_thresholds.insert(
            CommandRole::PolicyAuthority,
            RolePolicy::new(1, vec![authorized_signer]),
        );

        let message = b"epoch-bump";
        let attacker_signature = attacker.sign(message).expect("sign");

        let error = record
            .verify_role_cosignature(
                CommandRole::PolicyAuthority,
                attacker.did(),
                message,
                &attacker_signature,
            )
            .expect_err("unregistered DID must be rejected");

        assert_eq!(
            error,
            TrustRootError::RoleNotAuthorized {
                role: CommandRole::PolicyAuthority,
                signer_did: attacker.did().to_string(),
            },
            "the role-registry lookup must reject before signature verification"
        );

        // The authorised signer is accepted.
        let good = authorized.sign(message).unwrap();
        record
            .verify_role_cosignature(
                CommandRole::PolicyAuthority,
                authorized.did(),
                message,
                &good,
            )
            .expect("authorised signer verifies");
    }

    #[test]
    fn role_registry_enforces_required_m_over_distinct_authorised_signers() {
        let (a, a_signer) = signer("a");
        let (b, b_signer) = signer("b");
        let mut record = base_record();
        record.role_thresholds.insert(
            CommandRole::RevocationManager,
            RolePolicy::new(2, vec![a_signer, b_signer]),
        );

        let message = b"decommission";
        let entries = vec![
            SignatureEntry {
                signer_did: a.did().to_string(),
                role: CommandRole::RevocationManager,
                signature: a.sign(message).unwrap(),
            },
            SignatureEntry {
                signer_did: a.did().to_string(),
                role: CommandRole::RevocationManager,
                signature: a.sign(message).unwrap(),
            },
        ];
        // Duplicate signer counts once.
        assert_eq!(
            record.verify_role_signatures(CommandRole::RevocationManager, message, &entries),
            Err(TrustRootError::ThresholdNotMet { got: 1, need: 2 })
        );

        let entries = vec![
            SignatureEntry {
                signer_did: a.did().to_string(),
                role: CommandRole::RevocationManager,
                signature: a.sign(message).unwrap(),
            },
            SignatureEntry {
                signer_did: b.did().to_string(),
                role: CommandRole::RevocationManager,
                signature: b.sign(message).unwrap(),
            },
        ];
        record
            .verify_role_signatures(CommandRole::RevocationManager, message, &entries)
            .expect("two distinct authorised signers meet m=2");
    }

    #[test]
    fn device_class_floors_are_looked_up_per_class_and_param() {
        use tirbase_types::UNIT_DEG_C;
        let mut record = base_record();
        record.device_class_floors.insert(
            "cold_room".to_string(),
            vec![ParamFloor {
                param_name: "temperature".to_string(),
                min_floor: FixedPointValue::new(-400, -1, UNIT_DEG_C),
                max_ceiling: FixedPointValue::new(100, -1, UNIT_DEG_C),
            }],
        );
        let floor = record
            .device_class_floor("cold_room", "temperature")
            .expect("floor");
        assert_eq!(floor.min_floor.mantissa, -400);
        assert!(record.device_class_floor("office", "temperature").is_none());
    }

    #[test]
    fn rollback_to_older_trust_root_version_is_rejected() {
        use crate::epoch::tests_support::MemoryCounter;
        let counter = Arc::new(MemoryCounter::new(0));
        let mut record = base_record();
        record.root_ca_public_keys = vec![vec![1u8; 32]];
        let mut manager =
            TrustRootManager::install(record, counter.clone(), 1_000).expect("install v1");
        assert_eq!(manager.committed_version().unwrap(), 1);

        let mut rollback = manager.record().clone();
        rollback.version = 0;

        assert_eq!(
            manager.rotate(rollback, 1_000),
            Err(TrustRootError::Rollback {
                incoming: 0,
                current: 1
            })
        );
        assert_eq!(manager.committed_version().unwrap(), 1);

        let mut next = manager.record().clone();
        next.version = 2;
        manager.rotate(next, 1_000).expect("v2 rotates");
        assert_eq!(manager.committed_version().unwrap(), 2);
    }

    #[test]
    fn revoking_a_root_key_leaves_the_remaining_threshold_intact() {
        let mut record = base_record();
        record.root_ca_public_keys = vec![vec![1u8; 32], vec![2u8; 32]];
        record.threshold_k = 1;
        record.revoked_root_ca_keys = vec![vec![1u8; 32]];
        record.validate(1_000).expect("one active key satisfies k=1");
        assert!(record.is_root_revoked(&[1u8; 32]));
        assert_eq!(record.active_root_ca_keys(), vec![&[2u8; 32][..]] as Vec<&[u8]>);

        record.revoked_root_ca_keys.push(vec![2u8; 32]);
        assert!(matches!(
            record.validate(1_000),
            Err(TrustRootError::InvalidThreshold { .. })
        ));
    }
}
