//! Device enrollment flow (CLAIM-8.6, PV-3.11).
//!
//! The enrollment flow covers three things:
//!
//! 1. **First-boot identity generation** — [`DeviceIdentity::generate`] creates
//! a fresh Ed25519 identity and its `did:key` DID. An enrolling device keeps
//! the private seed locally and only sends the DID and public key.
//! 2. **Replay-safe bootstrap** — the bootstrap message carries a 32-byte
//! nonce and a signature over
//! `"TirBase/v1/EnrollmentBootstrap" || 0x00 || DID || 0x00 || pubkey ||
//! nonce || role`. [`EnrollmentService::enroll`] records the nonce and
//! rejects any reuse inside the configured retention window (default 72h),
//! emitting [`ReasonCode::NonceReused`].
//! 3. **Scoped token issuance** — a Biscuit token scoped to the device DID and
//! the requested role is minted by the deployment's root CA key. The TTL
//! is clamped to the Biscuit 1h–24h window so enrollment can never mint an
//! extended-window token.
//!
//! Enrollment also creates the device's initial `device_epoch` row (epoch 0)
//! through [`EpochRegistry::ensure_enrolled`] ().
//!
//! Decommissioning requires a [`DecommissionCredential`] signed by a
//! `RevocationManager` registered in the trust root ().

use serde::{Deserialize, Serialize};
use tirbase_core::auth::biscuit;
use tirbase_core::crdt::delta::Ed25519Signature;
use tirbase_core::events::{emit, ReasonCode, SecurityEvent, SecurityEventCategory, Severity};
use tirbase_core::identity::did::derive_did;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::identity::keypair;
use tirbase_core::traits::KeyProvider;
use tirbase_types::{CommandRole, DeviceSignature};

use crate::epoch::{
    decommission_message, verify_decommission_credential, DecommissionCredential,
    EnrollmentNonceStore, EpochError, EpochRegistry,
};
use crate::trust_root::TrustRootRecord;

/// Domain separator for the signed enrollment bootstrap message.
pub const ENROLLMENT_BOOTSTRAP_CONTEXT: &str = "TirBase/v1/EnrollmentBootstrap";

/// A first-boot device identity.
///
/// The private seed never leaves the device; only [`Self::public_key`] and
/// [`Self::device_id`] travel in the bootstrap message.
#[derive(Debug)]
pub struct DeviceIdentity {
    provider: InMemoryKeyProvider,
}

impl DeviceIdentity {
 /// Generate a fresh Ed25519 identity (first boot).
    pub fn generate() -> Result<Self, EpochError> {
        let provider = InMemoryKeyProvider::generate()
            .map_err(|error| EpochError::TokenIssuance(format!("identity generation: {error}")))?;
        Ok(DeviceIdentity { provider })
    }

 /// Reconstruct a device identity from an existing 32-byte Ed25519 seed.
 ///
 /// Used by operator tooling that persists and reloads device keys; the
 /// seed is never transmitted during enrollment.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        DeviceIdentity {
            provider: InMemoryKeyProvider::from_seed(seed),
        }
    }

 /// The 32-byte Ed25519 seed for local persistence by the owning device.
 ///
 /// This is only for the device's own key file; enrollment bootstrap sends
 /// the public key and signature, never the seed.
    pub fn seed(&self) -> [u8; 32] {
        self.provider.secret_seed()
    }

 /// The device's `did:key` DID.
    pub fn device_id(&self) -> String {
        self.provider.did().to_string()
    }

 /// The device's Ed25519 public key bytes.
    pub fn public_key(&self) -> Vec<u8> {
        self.provider.public_key_bytes()
    }

 /// Sign an enrollment bootstrap message for `nonce` and `role`.
    pub fn sign_bootstrap(
        &self,
        nonce: [u8; 32],
        role: CommandRole,
    ) -> Result<DeviceSignature, EpochError> {
        let message = enrollment_message(&self.device_id(), &self.public_key(), &nonce, role);
        self.provider
            .sign(&message)
            .map_err(|error| EpochError::TokenIssuance(format!("bootstrap signing: {error}")))
    }

 /// Build the complete signed bootstrap request.
    pub fn bootstrap(
        &self,
        nonce: [u8; 32],
        role: CommandRole,
    ) -> Result<EnrollmentRequest, EpochError> {
        Ok(EnrollmentRequest {
            device_did: self.device_id(),
            device_public_key: self.public_key(),
            nonce,
            role,
            signature: self.sign_bootstrap(nonce, role)?,
        })
    }
}

/// Domain-separated bytes signed by the enrolling device.
pub fn enrollment_message(
    device_did: &str,
    device_public_key: &[u8],
    nonce: &[u8; 32],
    role: CommandRole,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64 + device_did.len() + device_public_key.len());
    bytes.extend_from_slice(ENROLLMENT_BOOTSTRAP_CONTEXT.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(device_did.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(device_public_key);
    bytes.push(0);
    bytes.extend_from_slice(nonce);
    bytes.push(0);
    bytes.extend_from_slice(role.as_str().as_bytes());
    bytes
}

/// A signed, replay-safe enrollment bootstrap message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentRequest {
 /// Device DID (`did:key:z6Mk…`).
    pub device_did: String,
 /// Device Ed25519 public key.
    pub device_public_key: Vec<u8>,
 /// One-time bootstrap nonce.
    pub nonce: [u8; 32],
 /// Role the device is requesting.
    pub role: CommandRole,
 /// Signature over [`enrollment_message`].
    pub signature: DeviceSignature,
}

/// Result of a successful enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolledDevice {
 /// Enrolled device DID.
    pub device_id: String,
 /// Initial enrollment epoch (always 0 for a new device).
    pub epoch: u64,
 /// Scoped Biscuit token bytes.
    pub token: Vec<u8>,
 /// Token TTL in seconds.
    pub token_ttl_secs: u64,
}

/// Issues scoped tokens for first-boot devices.
#[derive(Debug)]
pub struct EnrollmentService {
    nonces: std::sync::Arc<dyn EnrollmentNonceStore>,
    epochs: std::sync::Arc<EpochRegistry>,
    trust_root: std::sync::Arc<TrustRootRecord>,
    root_ca_private_key: Vec<u8>,
    token_ttl_secs: u64,
}

impl EnrollmentService {
 /// Construct the service.
 ///
 /// `token_ttl_secs` is clamped to the Biscuit window `[3600, 86400]`.
    pub fn new(
        nonces: std::sync::Arc<dyn EnrollmentNonceStore>,
        epochs: std::sync::Arc<EpochRegistry>,
        trust_root: std::sync::Arc<TrustRootRecord>,
        root_ca_private_key: Vec<u8>,
        token_ttl_secs: u64,
    ) -> Self {
        EnrollmentService {
            nonces,
            epochs,
            trust_root,
            root_ca_private_key,
            token_ttl_secs: token_ttl_secs.clamp(biscuit::TTL_MIN_SECS, biscuit::TTL_MAX_SECS),
        }
    }

 /// Enroll a device and issue its scoped token.
 ///
 /// Verification order:
 /// 1. the DID must derive from the presented public key (identity binding),
 /// 2. the bootstrap signature must verify,
 /// 3. the nonce must be fresh (replay-safe bootstrap),
 /// 4. the device's epoch-0 row is created if missing,
 /// 5. the scoped token is minted.
    pub fn enroll(
        &self,
        request: &EnrollmentRequest,
        now_est: i64,
    ) -> Result<EnrolledDevice, EpochError> {
        let public_key: [u8; 32] =
            request
                .device_public_key
                .as_slice()
                .try_into()
                .map_err(|_| {
                    EpochError::InvalidIdentity(
                        "device public key is not a 32-byte Ed25519 key".into(),
                    )
                })?;

        let derived = derive_did(&public_key).to_string();
        if derived != request.device_did {
            return Err(EpochError::InvalidIdentity(format!(
                "DID {} does not derive from the presented public key ({derived})",
                request.device_did
            )));
        }

        let message = enrollment_message(
            &request.device_did,
            &request.device_public_key,
            &request.nonce,
            request.role,
        );
        let valid = match &request.signature {
            DeviceSignature::Ed25519(bytes) => {
                keypair::verify(&public_key, &message, &Ed25519Signature::from_bytes(*bytes))
                    .is_ok()
            }
            DeviceSignature::P256(_) => false,
        };
        if !valid {
            return Err(EpochError::InvalidIdentity(
                "bootstrap signature did not verify".to_string(),
            ));
        }

        if !self.nonces.record(request.nonce, now_est)? {
            emit(
                SecurityEvent::new(
                    SecurityEventCategory::Enrollment,
                    Severity::High,
                    ReasonCode::NonceReused,
                )
                .with_target(request.device_did.clone())
                .with_detail(
                    "bootstrap enrollment nonce reused inside its retention window; \
                     replay rejected"
                        .to_string(),
                ),
            );
            return Err(EpochError::NonceReused);
        }

        let epoch = self.epochs.ensure_enrolled(&request.device_did, now_est)?;

        let token = biscuit::create_token(
            &request.device_did,
            request.role.as_str(),
            self.token_ttl_secs,
            &self.root_ca_private_key,
            false,
        )
        .map_err(|error| EpochError::TokenIssuance(error.to_string()))?;

        emit(
            SecurityEvent::new(
                SecurityEventCategory::Enrollment,
                Severity::Low,
                ReasonCode::DeviceEnrolled,
            )
            .with_target(request.device_did.clone())
            .with_detail(format!(
                "device enrolled with role {} and a scoped token (ttl={}s, epoch={})",
                request.role.as_str(),
                self.token_ttl_secs,
                epoch.epoch
            )),
        );

        Ok(EnrolledDevice {
            device_id: request.device_did.clone(),
            epoch: epoch.epoch,
            token,
            token_ttl_secs: self.token_ttl_secs,
        })
    }

 /// Decommission a device after verifying a `RevocationManager` credential
 /// (PV-3.13).
 ///
 /// A credential from any other role is rejected, even when its signature is
 /// cryptographically valid.
    pub fn decommission(
        &self,
        device_id: &str,
        credential: &DecommissionCredential,
    ) -> Result<(), EpochError> {
        verify_decommission_credential(&self.trust_root, device_id, credential)?;
        emit(
            SecurityEvent::new(
                SecurityEventCategory::Revocation,
                Severity::High,
                ReasonCode::DidRevoked,
            )
            .with_target(device_id.to_string())
            .with_detail(format!(
                "device decommissioned by RevocationManager {}",
                credential.signer_did
            )),
        );
        Ok(())
    }

 /// The trust root used for role-threshold and decommission checks.
    pub fn trust_root(&self) -> &TrustRootRecord {
        &self.trust_root
    }

 /// The epoch registry shared with the guard/admin paths.
    pub fn epochs(&self) -> &std::sync::Arc<EpochRegistry> {
        &self.epochs
    }

 /// The nonce store shared with the purge task.
    pub fn nonces(&self) -> &std::sync::Arc<dyn EnrollmentNonceStore> {
        &self.nonces
    }

 /// Scoped token TTL in seconds.
    pub fn token_ttl_secs(&self) -> u64 {
        self.token_ttl_secs
    }

 /// The signed bytes for a decommission credential (helper for callers).
    pub fn decommission_message(device_id: &str) -> Vec<u8> {
        decommission_message(device_id)
    }
}

impl Drop for EnrollmentService {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.root_ca_private_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch::{InMemoryEpochStore, InMemoryNonceStore};
    use crate::trust_root::RolePolicy;

    fn trust_root_with_rm(rm: &InMemoryKeyProvider) -> TrustRootRecord {
        let mut roles = std::collections::BTreeMap::new();
        roles.insert(
            CommandRole::RevocationManager,
            RolePolicy::new(
                1,
                vec![crate::trust_root::AuthorizedRoleSigner {
                    did: rm.did().to_string(),
                    public_key: rm.public_key_bytes(),
                }],
            ),
        );
        TrustRootRecord {
            version: 1,
            root_ca_public_keys: vec![vec![1u8; 32]],
            threshold_k: 1,
            role_thresholds: roles,
            device_class_floors: std::collections::BTreeMap::new(),
            expiry_est: i64::MAX,
            revoked_root_ca_keys: Vec::new(),
            signatures: Vec::new(),
        }
    }

    struct Fixture {
        service: EnrollmentService,
        root_public: [u8; 32],
        rm: InMemoryKeyProvider,
    }

    fn fixture() -> Fixture {
        let (root_key, root_public) = keypair::generate_keypair().unwrap();
        let rm = InMemoryKeyProvider::generate().unwrap();
        let nonces = std::sync::Arc::new(InMemoryNonceStore::new());
        let epochs = std::sync::Arc::new(EpochRegistry::new(std::sync::Arc::new(
            InMemoryEpochStore::default(),
        )));
        let service = EnrollmentService::new(
            nonces,
            epochs,
            std::sync::Arc::new(trust_root_with_rm(&rm)),
            root_key.to_vec(),
            3_600,
        );
        Fixture {
            service,
            root_public,
            rm,
        }
    }

    fn token_verifies(token: &[u8], root_public: &[u8; 32], did: &str) -> bool {
        let now = tirbase_core::traits::wall_hint_secs().unwrap_or(0);
        let claims = biscuit::verify_token(token, root_public, now).unwrap();
        claims.did == did
    }

    #[test]
    fn enrollment_issues_a_scoped_token_at_epoch_zero() {
        let Fixture {
            service,
            root_public,
            ..
        } = fixture();
        let device = DeviceIdentity::generate().unwrap();
        let request = device
            .bootstrap([1u8; 32], CommandRole::CommandIssuer)
            .unwrap();

        let enrolled = service.enroll(&request, 1_000).unwrap();
        assert_eq!(enrolled.epoch, 0, "first enrollment starts at epoch 0");
        assert_eq!(enrolled.device_id, device.device_id());
        assert_eq!(enrolled.token_ttl_secs, 3_600);
        assert!(
            token_verifies(&enrolled.token, &root_public, &device.device_id()),
            "issued token must verify against the root CA key and carry the device DID"
        );
    }

    #[test]
    fn replayed_bootstrap_nonce_is_rejected() {
        let Fixture { service, .. } = fixture();
        let device = DeviceIdentity::generate().unwrap();
        let request = device
            .bootstrap([9u8; 32], CommandRole::CommandIssuer)
            .unwrap();

        service.enroll(&request, 1_000).unwrap();
        assert_eq!(
            service.enroll(&request, 1_001),
            Err(EpochError::NonceReused),
            "the bootstrap nonce may only be used once"
        );
    }

    #[test]
    fn bootstrap_signature_from_a_different_key_is_rejected() {
        let Fixture { service, .. } = fixture();
        let device = DeviceIdentity::generate().unwrap();
        let attacker = DeviceIdentity::generate().unwrap();
        let mut request = device
            .bootstrap([5u8; 32], CommandRole::CommandIssuer)
            .unwrap();
        request.signature = attacker
            .sign_bootstrap([5u8; 32], CommandRole::CommandIssuer)
            .unwrap();

        assert!(matches!(
            service.enroll(&request, 1_000),
            Err(EpochError::InvalidIdentity(_))
        ));
    }

    #[test]
    fn ttl_is_clamped_to_the_biscuit_window() {
        let (root_key, _) = keypair::generate_keypair().unwrap();
        let rm = InMemoryKeyProvider::generate().unwrap();
        let make = |ttl: u64| {
            EnrollmentService::new(
                std::sync::Arc::new(InMemoryNonceStore::new()),
                std::sync::Arc::new(EpochRegistry::new(std::sync::Arc::new(
                    InMemoryEpochStore::default(),
                ))),
                std::sync::Arc::new(trust_root_with_rm(&rm)),
                root_key.to_vec(),
                ttl,
            )
        };
        assert_eq!(make(1).token_ttl_secs(), biscuit::TTL_MIN_SECS);
        assert_eq!(make(u64::MAX).token_ttl_secs(), biscuit::TTL_MAX_SECS);
    }

    #[test]
    fn decommission_requires_a_revocation_manager_credential() {
        let Fixture { service, rm, .. } = fixture();
        let pa = InMemoryKeyProvider::generate().unwrap();
        let message = EnrollmentService::decommission_message("did:key:zDevice");

        let wrong = DecommissionCredential {
            signer_did: pa.did().to_string(),
            role: CommandRole::PolicyAuthority,
            signature: pa.sign(&message).unwrap(),
        };
        assert!(matches!(
            service.decommission("did:key:zDevice", &wrong),
            Err(EpochError::RevocationManagerRequired { .. })
        ));

        let good = DecommissionCredential {
            signer_did: rm.did().to_string(),
            role: CommandRole::RevocationManager,
            signature: rm.sign(&message).unwrap(),
        };
        service
            .decommission("did:key:zDevice", &good)
            .expect("RevocationManager credential is accepted");
    }
}
