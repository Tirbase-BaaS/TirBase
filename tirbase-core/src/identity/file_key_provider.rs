//! File-backed and in-memory [`KeyProvider`] implementations (PV-3.6).
//!
//! [`FileKeyProvider`] loads (or creates) a device Ed25519 key in the same JSON
//! format the original identity persistence used. The private seed is held in
//! a [`secrecy::Secret<[u8; 32]>`] and zeroized when the provider is dropped
//! (PV-3.7, CLAIM-6.1); it is never returned by the [`KeyProvider`] trait.
//!
//! `Debug` is implemented by hand to redact the seed — deriving it would print
//! private key material into logs.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use secrecy::{ExposeSecret, Secret};
use tirbase_types::{DeviceKeyType, DeviceSignature};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::TirBaseError;
use crate::identity::{did, keypair};
use crate::traits::KeyProvider;

// Counts explicit `zeroize()` invocations in test builds.
//
// The wiring-mutation check for CLAIM-6.1 removes the `self.zeroize()` call
// from `Drop` and requires at least one test to fail: `dropping_provider_
// invokes_zeroize_on_the_seed` reads this counter around a drop.
#[cfg(test)]
thread_local! {
 // Per-test-thread counter: each `#[test]` runs on its own thread, so
 // concurrently dropping providers in other tests cannot perturb it.
    pub(crate) static ZEROIZE_INVOCATIONS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[inline]
fn record_zeroize() {
    #[cfg(test)]
    {
        ZEROIZE_INVOCATIONS.with(|count| count.set(count.get() + 1));
    }
}

/// Ed25519 device key persisted in a JSON file.
///
/// File format (unchanged from the pre-KeyProvider identity persistence):
///
/// ```json
/// { "did": "did:key:z6Mk…", "secret_key_hex": "…", "public_key_hex": "…" }
/// ```
pub struct FileKeyProvider {
    did: String,
 /// Private seed, zeroized on drop by `secrecy::Secret` (PV-3.7).
    seed: Secret<[u8; 32]>,
    public_key: [u8; 32],
    path: PathBuf,
}

impl std::fmt::Debug for FileKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileKeyProvider")
            .field("did", &self.did)
            .field("path", &self.path)
            .field("seed", &"<redacted>")
            .finish()
    }
}

impl FileKeyProvider {
 /// Load the key at `path`, creating and persisting a new keypair when no
 /// identity file exists yet.
 ///
 /// This is the first-boot path used by the core `IdentityManager`; 
 /// layers the enrollment flow on top.
    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Self, TirBaseError> {
        let path = path.as_ref();
        if path.exists() {
            return Self::load(path);
        }
        Self::generate(path)
    }

 /// Load an existing key file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, TirBaseError> {
        let path = path.as_ref();
        let path_str = path
            .to_str()
            .ok_or_else(|| TirBaseError::LocalStoreWriteFailed {
                reason: format!("identity path is not valid UTF-8: {}", path.display()),
            })?;
        let (did, keypair_bytes) = did::load_identity_from(path_str)?.ok_or_else(|| {
            TirBaseError::LocalStoreWriteFailed {
                reason: format!("identity file not found: {path_str}"),
            }
        })?;
        if keypair_bytes.len() < 32 {
            return Err(TirBaseError::LocalStoreWriteFailed {
                reason: format!(
                    "identity file {path_str} holds {} key bytes; expected at least 32",
                    keypair_bytes.len()
                ),
            });
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&keypair_bytes[..32]);
        Self::from_seed(seed, did, path.to_path_buf())
    }

 /// Generate a fresh keypair and persist it at `path`.
    pub fn generate(path: impl AsRef<Path>) -> Result<Self, TirBaseError> {
        let path = path.as_ref();
        let (seed, public_key) = keypair::generate_keypair()?;
        let did = did::derive_did(&public_key);

        let mut keypair_bytes = Vec::with_capacity(64);
        keypair_bytes.extend_from_slice(&seed);
        keypair_bytes.extend_from_slice(&public_key);
        let path_str = path
            .to_str()
            .ok_or_else(|| TirBaseError::LocalStoreWriteFailed {
                reason: format!("identity path is not valid UTF-8: {}", path.display()),
            })?;
        did::persist_identity_to(&did, &keypair_bytes, path_str)?;

        let provider = Self::from_seed(seed, did, path.to_path_buf());
 // The stack copy of the seed is no longer needed; wipe it.
        let mut seed_copy = seed;
        seed_copy.zeroize();
        provider
    }

 /// Construct a provider from an existing seed (used by tests and by callers
 /// that already hold an identity file).
    pub fn from_seed(seed: [u8; 32], did: String, path: PathBuf) -> Result<Self, TirBaseError> {
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        Ok(FileKeyProvider {
            did,
            seed: Secret::new(seed),
            public_key,
            path,
        })
    }

 /// Path of the backing key file.
    pub fn path(&self) -> &Path {
        &self.path
    }

 /// Crate-internal access to the seed for subsystems that still take raw
 /// signing keys (CRDT engine, Noise static key, revocation partial delta).
 ///
 /// This is intentionally not part of the [`KeyProvider`] trait: it is a
 /// migration bridge, not an API the rest of the system may use.
    pub fn secret_seed(&self) -> [u8; 32] {
        *self.seed.expose_secret()
    }

 /// 32-byte Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
}

impl Zeroize for FileKeyProvider {
    fn zeroize(&mut self) {
        record_zeroize();
 // Replacing the live secret drops it, which zeroizes the seed bytes in
 // place (secrecy::Secret's Drop impl). The replacement is all-zero so a
 // zeroized provider can never sign again.
        let live = std::mem::replace(&mut self.seed, Secret::new([0u8; 32]));
        drop(live);
        self.public_key.zeroize();
    }
}

impl Drop for FileKeyProvider {
    fn drop(&mut self) {
 // CLAIM-6.1 wiring point: removing this call must fail the
 // `dropping_provider_invokes_zeroize_on_the_seed` test.
        self.zeroize();
    }
}

impl ZeroizeOnDrop for FileKeyProvider {}

#[async_trait]
impl KeyProvider for FileKeyProvider {
    fn sign(&self, payload: &[u8]) -> Result<DeviceSignature, TirBaseError> {
        let signing_key = SigningKey::from_bytes(self.seed.expose_secret());
        Ok(DeviceSignature::Ed25519(
            signing_key.sign(payload).to_bytes(),
        ))
    }

    async fn sign_async(&self, payload: &[u8]) -> Result<DeviceSignature, TirBaseError> {
        self.sign(payload)
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_vec()
    }

    fn key_type(&self) -> DeviceKeyType {
        DeviceKeyType::Ed25519
    }

    fn did(&self) -> &str {
        &self.did
    }
}

/// Ephemeral Ed25519 key held only in memory (WASM builds and tests).
///
/// No persistence: the identity changes on every construction. The seed is
/// held in a [`Secret`] and zeroized on drop (PV-3.7).
pub struct InMemoryKeyProvider {
    did: String,
    seed: Secret<[u8; 32]>,
    public_key: [u8; 32],
}

impl std::fmt::Debug for InMemoryKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryKeyProvider")
            .field("did", &self.did)
            .field("seed", &"<redacted>")
            .finish()
    }
}

impl InMemoryKeyProvider {
 /// Generate a fresh in-memory keypair.
    pub fn generate() -> Result<Self, TirBaseError> {
        let (seed, public_key) = keypair::generate_keypair()?;
        let provider = InMemoryKeyProvider {
            did: did::derive_did(&public_key),
            seed: Secret::new(seed),
            public_key,
        };
        let mut seed_copy = seed;
        seed_copy.zeroize();
        Ok(provider)
    }

 /// Construct from an existing seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        InMemoryKeyProvider {
            did: did::derive_did(&public_key),
            seed: Secret::new(seed),
            public_key,
        }
    }

    pub fn secret_seed(&self) -> [u8; 32] {
        *self.seed.expose_secret()
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
}

impl Zeroize for InMemoryKeyProvider {
    fn zeroize(&mut self) {
        record_zeroize();
        let live = std::mem::replace(&mut self.seed, Secret::new([0u8; 32]));
        drop(live);
        self.public_key.zeroize();
    }
}

impl Drop for InMemoryKeyProvider {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for InMemoryKeyProvider {}

#[async_trait]
impl KeyProvider for InMemoryKeyProvider {
    fn sign(&self, payload: &[u8]) -> Result<DeviceSignature, TirBaseError> {
        let signing_key = SigningKey::from_bytes(self.seed.expose_secret());
        Ok(DeviceSignature::Ed25519(
            signing_key.sign(payload).to_bytes(),
        ))
    }

    async fn sign_async(&self, payload: &[u8]) -> Result<DeviceSignature, TirBaseError> {
        self.sign(payload)
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_vec()
    }

    fn key_type(&self) -> DeviceKeyType {
        DeviceKeyType::Ed25519
    }

    fn did(&self) -> &str {
        &self.did
    }
}

/// Shared test helper: the file provider round-trips through disk.
#[cfg(test)]
pub(crate) fn temp_identity_path(tag: &str) -> PathBuf {
    let unique = uuid::Uuid::now_v7();
    std::env::temp_dir().join(format!("tirbase-key-{tag}-{unique}.json"))
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::identity::keypair;

    fn zeroize_invocations() -> usize {
        ZEROIZE_INVOCATIONS.with(|count| count.get())
    }

    fn render_seed(provider: &FileKeyProvider) -> Vec<u8> {
        provider.secret_seed().to_vec()
    }

    #[test]
    fn file_provider_round_trips_a_signature() {
        let path = temp_identity_path("roundtrip");
        let provider = FileKeyProvider::load_or_generate(&path).expect("generate provider");

        let payload = b"delta-signing-payload";
        let signature = provider.sign(payload).expect("sign");
        assert_eq!(signature.key_type(), DeviceKeyType::Ed25519);

        let public_key: [u8; 32] = provider
            .public_key_bytes()
            .try_into()
            .expect("ed25519 public key is 32 bytes");
        keypair::verify(
            &public_key,
            payload,
            &crate::crdt::delta::Ed25519Signature::from_bytes(match signature {
                DeviceSignature::Ed25519(bytes) => bytes,
                DeviceSignature::P256(_) => panic!("expected Ed25519 signature"),
            }),
        )
        .expect("signature verifies");

 // Reloading the same file yields the same identity and can verify the
 // signature produced by the first instance.
        let reloaded = FileKeyProvider::load(&path).expect("reload provider");
        assert_eq!(reloaded.did(), provider.did());
        assert_eq!(reloaded.public_key_bytes(), provider.public_key_bytes());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn in_memory_provider_signs_and_reports_did() {
        let provider = InMemoryKeyProvider::generate().expect("generate");
        assert!(provider.did().starts_with("did:key:z6Mk"));
        assert_eq!(provider.public_key_bytes().len(), 32);
        let signature = provider.sign(b"payload").expect("sign");
        assert_eq!(signature.key_type(), DeviceKeyType::Ed25519);
    }

    #[test]
    fn debug_output_redacts_private_material() {
        let provider = InMemoryKeyProvider::generate().expect("generate");
        let rendered = format!("{provider:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(&hex::encode(provider.secret_seed())));
    }

    #[test]
    fn zeroize_wipes_the_seed_and_public_key() {
        let mut provider = InMemoryKeyProvider::from_seed([7u8; 32]);
        assert_eq!(provider.secret_seed(), [7u8; 32]);

        provider.zeroize();

        assert_eq!(
            provider.secret_seed(),
            [0u8; 32],
            "explicit zeroize must overwrite the seed"
        );
        assert_eq!(provider.public_key(), [0u8; 32]);
    }

    #[test]
    fn dropping_provider_invokes_zeroize_on_the_seed() {
        let before = zeroize_invocations();
        let provider = InMemoryKeyProvider::from_seed([9u8; 32]);
        assert_eq!(render_seed_file(&provider), vec![9u8; 32]);
        drop(provider);
        let after = zeroize_invocations();
        assert_eq!(
            after,
            before + 1,
            "dropping a key provider must call zeroize() (CLAIM-6.1)"
        );
    }

 // Helper so the drop test also exercises `FileKeyProvider`'s seed accessor
 // without keeping a borrow across the drop.
    fn render_seed_file(provider: &InMemoryKeyProvider) -> Vec<u8> {
        provider.secret_seed().to_vec()
    }

    #[test]
    fn file_provider_zeroize_is_observable() {
        let path = temp_identity_path("zeroize");
        let mut provider = FileKeyProvider::load_or_generate(&path).expect("provider");
        let expected = render_seed(&provider);
        assert_ne!(expected, vec![0u8; 32]);

        provider.zeroize();
        assert_eq!(render_seed(&provider), vec![0u8; 32]);

        let _ = std::fs::remove_file(&path);
    }
}
