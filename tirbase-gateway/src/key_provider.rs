//! Device key providers for the gateway binary (PV-3.6, PV-3.7).
//!
//! * [`FileKeyProvider`] — file-backed development/provider path.  It wraps the
//!   core provider, whose seed lives in `secrecy::Secret<[u8; 32]>` and is
//!   zeroized on drop (CLAIM-6.1).  Every gateway signing operation goes through
//!   the [`KeyProvider`] trait; no raw key bytes reach the binary.
//! * [`Tpm2KeyProvider`] — feature-gated TPM2 stub (CLAIM-6.3).
//! * [`Pkcs11KeyProvider`] — feature-gated PKCS#11 stub (CLAIM-6.4).
//!
//! Private key material is never written to configuration files: the file
//! provider writes the identity to its own key file, and the hardware providers
//! keep key material inside the device (the PKCS#11 PIN is supplied by a file
//! path, never inlined in `gateway.toml`).

use std::path::Path;

use async_trait::async_trait;
use tirbase_core::errors::TirBaseError;
use tirbase_core::identity::file_key_provider::FileKeyProvider as CoreFileKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_types::{DeviceKeyType, DeviceSignature};

/// Key provider that loads a device Ed25519 key from a file on disk.
///
/// The private key material is held only in memory after the initial load;
/// it is never written back to configuration files (CLAIM-6.1).
#[derive(Debug)]
pub struct FileKeyProvider {
    inner: CoreFileKeyProvider,
}

impl FileKeyProvider {
    /// Load the key at `key_path`, generating and persisting a new identity
    /// when the file does not exist yet.
    ///
    /// First-boot generation is reported by the caller so an operator can see
    /// that a new device identity was created (task 8.6 adds enrollment).
    pub fn load_or_generate(key_path: impl AsRef<Path>) -> Result<Self, TirBaseError> {
        let inner = CoreFileKeyProvider::load_or_generate(key_path.as_ref())?;
        Ok(FileKeyProvider { inner })
    }

    /// Load an existing key file, failing if it is absent.
    #[cfg(test)]
    pub fn load(key_path: impl AsRef<Path>) -> Result<Self, TirBaseError> {
        let inner = CoreFileKeyProvider::load(key_path.as_ref())?;
        Ok(FileKeyProvider { inner })
    }
}

// The wrapped provider zeroizes its seed on drop; this marker states that the
// gateway-facing wrapper keeps the same guarantee (CLAIM-6.1/6.2).
impl zeroize::ZeroizeOnDrop for FileKeyProvider {}

#[async_trait]
impl KeyProvider for FileKeyProvider {
    fn sign(&self, payload: &[u8]) -> Result<DeviceSignature, TirBaseError> {
        self.inner.sign(payload)
    }

    async fn sign_async(&self, payload: &[u8]) -> Result<DeviceSignature, TirBaseError> {
        self.inner.sign_async(payload).await
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key_bytes()
    }

    fn key_type(&self) -> DeviceKeyType {
        self.inner.key_type()
    }

    fn did(&self) -> &str {
        self.inner.did()
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// TPM2-backed key provider — stub (task 6.3, CLAIM-6.3, PV-3.6)
// ═════════════════════════════════════════════════════════════════════════════

/// How the TPM2 provider would hold the signing key.
///
/// TPM2 chips (for example the Infineon SLB9670/SLB9672) natively support
/// ECDSA P-256 but not Ed25519.  Two deployment options are therefore defined:
///
/// * **`Ed25519SealedSeed`** — an Ed25519 seed is sealed to a PCR policy in a
///   TPM2 NV index.  The seed is unsealed into RAM only for the duration of a
///   signing operation and zeroized immediately afterwards.
/// * **`P256`** — the identity is a P-256 key whose private scalar never leaves
///   the TPM; the DID uses the `z2Dn…` multibase prefix.  No sealed seed is
///   held in software at all.
///
/// # NV-endurance wear-leveling
///
/// The TPM2 NV index holding the sealed seed is written only during key
/// provisioning/rotation, never per signature.  Signature operations use the
/// TPM's object store, not NV.  The monotonic counter in
/// [`crate::monotonic_counter::Tpm2MonotonicCounter`] follows the same rule:
/// NV is written only at checkpoint cadence, not per command, because TPM NV
/// indices are typically rated for ~512k write cycles.
#[cfg(feature = "tpm2")]
// Stub surface: both options are constructed by tests and by deployments once
// the tss-esapi backend lands; the enum is intentionally dormant today.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum Tpm2KeyMode {
    /// Ed25519 seed sealed to a PCR policy in an NV index.
    Ed25519SealedSeed {
        /// TPM2 NV index that holds the sealed seed.
        nv_handle: u32,
        /// PCR selection/policy digest the seed is sealed to.
        pcr_policy: Vec<u8>,
    },
    /// P-256 key resident inside the TPM.
    P256 {
        /// Persistent handle of the P-256 key object.
        persistent_handle: u32,
    },
}

/// TPM2-backed [`KeyProvider`] — compile-only stub (CLAIM-6.3).
///
/// The real implementation will use `tss-esapi` (not linked yet).  Every
/// operation returns [`TirBaseError::KeyProviderUnavailable`] so a deployment
/// that enables the feature but has no TPM fails closed rather than silently
/// falling back to software keys.
#[cfg(feature = "tpm2")]
#[derive(Debug, Clone)]
pub struct Tpm2KeyProvider {
    did: String,
    public_key: Vec<u8>,
    mode: Tpm2KeyMode,
}

#[cfg(feature = "tpm2")]
#[allow(dead_code)] // stub constructors kept for the TPM2 deployment path
impl Tpm2KeyProvider {
    /// Option A: Ed25519 seed sealed to a PCR policy (stub).
    pub fn ed25519_sealed_seed(nv_handle: u32, pcr_policy: Vec<u8>) -> Self {
        Tpm2KeyProvider {
            did: format!("did:key:tpm2-sealed-{nv_handle:08x}"),
            public_key: Vec::new(),
            mode: Tpm2KeyMode::Ed25519SealedSeed {
                nv_handle,
                pcr_policy,
            },
        }
    }

    /// Option B: TPM-resident P-256 key (stub).
    pub fn p256(persistent_handle: u32) -> Self {
        Tpm2KeyProvider {
            did: format!("did:key:tpm2-p256-{persistent_handle:08x}"),
            public_key: Vec::new(),
            mode: Tpm2KeyMode::P256 { persistent_handle },
        }
    }

    /// The sealing strategy this provider was constructed with.
    pub fn mode(&self) -> &Tpm2KeyMode {
        &self.mode
    }

    fn unavailable(&self) -> TirBaseError {
        TirBaseError::KeyProviderUnavailable {
            provider: "tpm2".to_string(),
            reason: "Tpm2KeyProvider is a compile-time stub; tss-esapi-backed \
                     unsealing/signing is not implemented yet"
                .to_string(),
        }
    }
}

#[cfg(feature = "tpm2")]
#[async_trait]
impl KeyProvider for Tpm2KeyProvider {
    fn sign(&self, _payload: &[u8]) -> Result<DeviceSignature, TirBaseError> {
        Err(self.unavailable())
    }

    async fn sign_async(&self, _payload: &[u8]) -> Result<DeviceSignature, TirBaseError> {
        Err(self.unavailable())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    fn key_type(&self) -> DeviceKeyType {
        match self.mode {
            Tpm2KeyMode::Ed25519SealedSeed { .. } => DeviceKeyType::Ed25519,
            Tpm2KeyMode::P256 { .. } => DeviceKeyType::P256,
        }
    }

    fn did(&self) -> &str {
        &self.did
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// PKCS#11-backed key provider — stub (task 6.4, CLAIM-6.4, PV-3.6)
// ═════════════════════════════════════════════════════════════════════════════

/// PKCS#11 hardware-token [`KeyProvider`] — compile-only stub (CLAIM-6.4).
///
/// The PIN is held in a `secrecy::SecretString`, loaded from a file path by the
/// caller (never from `gateway.toml`), and zeroized on drop.  The private key
/// itself never leaves the token; only signing handles cross the boundary.
#[cfg(feature = "pkcs11")]
// The PIN field exists to hold the secret in a zeroizing wrapper even while the
// cryptoki backend is a stub; it is deliberately never read.
#[allow(dead_code)]
#[derive(Debug)]
pub struct Pkcs11KeyProvider {
    did: String,
    public_key: Vec<u8>,
    /// PKCS#11 slot / token identifier.
    slot: u64,
    /// Token PIN — redacted from `Debug` by `secrecy`.
    pin: secrecy::SecretString,
}

#[cfg(feature = "pkcs11")]
#[allow(dead_code)] // stub-only surface
impl Pkcs11KeyProvider {
    /// Construct the stub for a token in `slot`, authenticated with `pin`.
    pub fn new(slot: u64, pin: secrecy::SecretString) -> Self {
        Pkcs11KeyProvider {
            did: format!("did:key:pkcs11-{slot:08x}"),
            public_key: Vec::new(),
            slot,
            pin,
        }
    }

    /// The PKCS#11 slot this provider addresses.
    pub fn slot(&self) -> u64 {
        self.slot
    }

    fn unavailable(&self) -> TirBaseError {
        TirBaseError::KeyProviderUnavailable {
            provider: "pkcs11".to_string(),
            reason: "Pkcs11KeyProvider is a compile-time stub; a cryptoki-backed \
                     session and token key are not implemented yet"
                .to_string(),
        }
    }
}

#[cfg(feature = "pkcs11")]
#[async_trait]
impl KeyProvider for Pkcs11KeyProvider {
    fn sign(&self, _payload: &[u8]) -> Result<DeviceSignature, TirBaseError> {
        Err(self.unavailable())
    }

    async fn sign_async(&self, _payload: &[u8]) -> Result<DeviceSignature, TirBaseError> {
        Err(self.unavailable())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    fn key_type(&self) -> DeviceKeyType {
        // The token's capability decides Ed25519 vs P-256; the stub advertises
        // the more widely available P-256.
        DeviceKeyType::P256
    }

    fn did(&self) -> &str {
        &self.did
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tirbase_core::crdt::delta::Ed25519Signature;
    use tirbase_core::identity::keypair;

    fn temp_key_path(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "tirbase-gateway-key-{tag}-{}-{unique}.json",
            std::process::id()
        ))
    }

    #[test]
    fn gateway_signing_goes_through_the_key_provider_trait() {
        let path = temp_key_path("sign");
        let provider = FileKeyProvider::load_or_generate(&path).expect("provider");

        let payload = b"gateway boot attestation";
        let signature = KeyProvider::sign(&provider, payload).expect("sign via trait");

        assert_eq!(signature.key_type(), DeviceKeyType::Ed25519);
        assert!(provider.did().starts_with("did:key:z6Mk"));

        let public_key: [u8; 32] = provider
            .public_key_bytes()
            .try_into()
            .expect("32-byte ed25519 public key");
        let signature_bytes = match signature {
            DeviceSignature::Ed25519(bytes) => bytes,
            DeviceSignature::P256(_) => panic!("expected Ed25519"),
        };
        keypair::verify(
            &public_key,
            payload,
            &Ed25519Signature::from_bytes(signature_bytes),
        )
        .expect("gateway signature verifies");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn provider_reload_keeps_the_same_identity() {
        let path = temp_key_path("reload");
        let first = FileKeyProvider::load_or_generate(&path).expect("first load");
        let did = first.did().to_string();

        let second = FileKeyProvider::load(&path).expect("reload");
        assert_eq!(second.did(), did);
        assert_eq!(second.public_key_bytes(), first.public_key_bytes());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn gateway_file_provider_is_zeroize_on_drop() {
        fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
        assert_zod::<FileKeyProvider>();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn tpm2_stub_builds_both_key_options_and_fails_closed() {
        let sealed = Tpm2KeyProvider::ed25519_sealed_seed(0x0150_0001, vec![0xaa; 32]);
        assert_eq!(sealed.key_type(), DeviceKeyType::Ed25519);
        assert!(matches!(sealed.mode(), Tpm2KeyMode::Ed25519SealedSeed { .. }));
        assert!(sealed.sign(b"payload").is_err());

        let p256 = Tpm2KeyProvider::p256(0x8100_0001);
        assert_eq!(p256.key_type(), DeviceKeyType::P256);
        assert!(matches!(p256.mode(), Tpm2KeyMode::P256 { .. }));
        assert!(p256.sign(b"payload").is_err());
    }

    #[cfg(feature = "pkcs11")]
    #[test]
    fn pkcs11_stub_fails_closed_and_redacts_pin() {
        use secrecy::SecretString;

        let provider = Pkcs11KeyProvider::new(7, SecretString::from("123456".to_string()));
        assert_eq!(provider.slot(), 7);
        assert!(provider.sign(b"payload").is_err());

        let rendered = format!("{provider:?}");
        assert!(!rendered.contains("123456"), "PIN must not appear in Debug");
    }
}
