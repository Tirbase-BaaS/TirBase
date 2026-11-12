//! SQLCipher build-variant helpers (CLAIM-32.5, PV-9.6).
//!
//! When feature `sqlcipher` is enabled, gateway DB opens must obtain key
//! material via `KeyProvider` and refuse to open if key derivation fails.
//! Key material is never written to storage; it is applied via `PRAGMA key`
//! only in process memory and zeroized after use.
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use tirbase_core::traits::KeyProvider;
use zeroize::Zeroizing;

pub const SQLCIPHER_CONTEXT: &[u8] = b"TirBase/v1/SQLCipherKeyDerivation";

#[derive(Debug)]
pub enum SqlCipherError {
    KeyProvider(String),
    SqlCipher(String),
}

impl std::fmt::Display for SqlCipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyProvider(e) => write!(f, "KeyProvider error (DB open refused): {e}"),
            Self::SqlCipher(e) => write!(f, "SQLCipher error: {e}"),
        }
    }
}

impl std::error::Error for SqlCipherError {}

/// Derive a database key from `KeyProvider` without persisting it.
/// Uses a domain-separated signature so key material never leaves the provider's
/// secret boundary as a stored artifact.
pub fn derive_db_key(
    provider: &dyn KeyProvider,
    db_label: &str,
) -> Result<Zeroizing<[u8; 32]>, SqlCipherError> {
    let mut msg = SQLCIPHER_CONTEXT.to_vec();
    msg.push(0);
    msg.extend_from_slice(db_label.as_bytes());
    let sig = provider
        .sign(&msg)
        .map_err(|e| SqlCipherError::KeyProvider(e.to_string()))?;
 // Serialize signature deterministically (no key bytes exposed/persisted).
    let sig_bytes =
        serde_json::to_vec(&sig).map_err(|e| SqlCipherError::KeyProvider(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(SQLCIPHER_CONTEXT);
    hasher.update(provider.did().as_bytes());
    hasher.update(db_label.as_bytes());
    hasher.update(&sig_bytes);
    let digest = hasher.finalize();
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&digest);
    Ok(key)
}

/// Apply SQLCipher key to an open connection. Key is hex-encoded in-process for
/// PRAGMA and never written to disk by this crate.
#[cfg(feature = "sqlcipher")]
pub fn apply_sqlcipher_key(
    conn: &Connection,
    provider: &dyn KeyProvider,
    db_label: &str,
) -> Result<(), SqlCipherError> {
    let key = derive_db_key(provider, db_label)?;
    let hex_key = Zeroizing::new(hex::encode(key.as_ref()));
 // Use hex key form; raw key never written to storage.
    let pragma = format!("PRAGMA key = \"x'{}'\";", hex_key.as_str());
    conn.execute_batch(&pragma)
        .map_err(|e| SqlCipherError::SqlCipher(e.to_string()))?;
 // Verify encryption is usable.
    conn.query_row("SELECT count(*) FROM sqlite_master;", [], |_r| Ok(()))
        .map_err(|e| SqlCipherError::SqlCipher(format!("key verification failed: {e}")))?;
    Ok(())
}

#[cfg(not(feature = "sqlcipher"))]
pub fn apply_sqlcipher_key(
    _conn: &Connection,
    _provider: &dyn KeyProvider,
    _db_label: &str,
) -> Result<(), SqlCipherError> {
    Ok(())
}

/// Open a SQLite connection and, when built with `--features sqlcipher`, apply
/// the KeyProvider-derived key. Refuses to open if KeyProvider errors.
pub fn open_encrypted(
    path: impl AsRef<std::path::Path>,
    provider: Option<&dyn KeyProvider>,
    db_label: &str,
) -> Result<Connection, SqlCipherError> {
    let conn = Connection::open(path.as_ref())
        .map_err(|e| SqlCipherError::SqlCipher(format!("open {}: {e}", path.as_ref().display())))?;
    #[cfg(feature = "sqlcipher")]
    {
        let p = provider.ok_or_else(|| {
            SqlCipherError::KeyProvider("sqlcipher build requires KeyProvider for DB key".into())
        })?;
        apply_sqlcipher_key(&conn, p, db_label)?;
    }
    #[cfg(not(feature = "sqlcipher"))]
    {
        let _ = (provider, db_label);
    }
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirbase_core::identity::file_key_provider::FileKeyProvider;

    #[test]
    fn derive_db_key_never_persists_and_is_deterministic_per_provider() {
        let dir = std::env::temp_dir().join(format!("tirbase-sqlcipher-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kp = FileKeyProvider::load_or_generate(dir.join("k.json")).unwrap();
        let a = derive_db_key(&kp, "primary.db").unwrap();
        let b = derive_db_key(&kp, "primary.db").unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
        let c = derive_db_key(&kp, "derived.db").unwrap();
        assert_ne!(a.as_ref(), c.as_ref());
 // wiring mutation: DB key must not be written to storage
        assert!(!dir.join("primary.db.key").exists());
        assert!(!dir.join("db.key").exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn keyprovider_error_refuses_db_key_derivation() {
        #[derive(Debug)]
        struct BadKp;
        #[async_trait::async_trait]
        impl tirbase_core::traits::KeyProvider for BadKp {
            fn sign(
                &self,
                _: &[u8],
            ) -> Result<tirbase_types::DeviceSignature, tirbase_core::errors::TirBaseError>
            {
                Err(tirbase_core::errors::TirBaseError::KeyProviderUnavailable {
                    provider: "bad".into(),
                    reason: "no key".into(),
                })
            }
            async fn sign_async(
                &self,
                _: &[u8],
            ) -> Result<tirbase_types::DeviceSignature, tirbase_core::errors::TirBaseError>
            {
                self.sign(&[])
            }
            fn public_key_bytes(&self) -> Vec<u8> {
                vec![0; 32]
            }
            fn key_type(&self) -> tirbase_types::DeviceKeyType {
                tirbase_types::DeviceKeyType::Ed25519
            }
            fn did(&self) -> &str {
                "did:test:bad"
            }
        }
        let err = derive_db_key(&BadKp, "primary.db").unwrap_err();
        assert!(err.to_string().contains("KeyProvider"));
 // wiring mutation: writing key to config/storage must be caught by tests above
    }
}
