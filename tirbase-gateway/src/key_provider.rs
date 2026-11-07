//! File-backed device key provider for the gateway binary (PV-3.6, CLAIM-5.2).
//!
//! Wraps `tirbase_core::identity::file_key_provider::FileKeyProvider` and
//! exposes it through the [`KeyProvider`] trait.  Every gateway signing
//! operation goes through this trait; the private seed is never returned.

use std::path::{Path, PathBuf};

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
    /// Filesystem path to the device key file.
    pub key_path: PathBuf,
}

impl FileKeyProvider {
    /// Load the key at `key_path`, generating and persisting a new identity
    /// when the file does not exist yet.
    ///
    /// First-boot generation is reported by the caller so an operator can see
    /// that a new device identity was created (task 8.6 adds enrollment).
    pub fn load_or_generate(key_path: impl AsRef<Path>) -> Result<Self, TirBaseError> {
        let key_path = key_path.as_ref().to_path_buf();
        let inner = CoreFileKeyProvider::load_or_generate(&key_path)?;
        Ok(FileKeyProvider { inner, key_path })
    }

    /// Load an existing key file, failing if it is absent.
    #[cfg(test)]
    pub fn load(key_path: impl AsRef<Path>) -> Result<Self, TirBaseError> {
        let key_path = key_path.as_ref().to_path_buf();
        let inner = CoreFileKeyProvider::load(&key_path)?;
        Ok(FileKeyProvider { inner, key_path })
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
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
}
