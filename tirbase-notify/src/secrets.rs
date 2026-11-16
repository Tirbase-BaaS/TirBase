// SPDX-License-Identifier: Apache-2.0

//! Secrets **by reference**.
//!
//! An alert channel configuration carries a [`SecretRef`] — a name — never a
//! secret value. The runtime resolves it through a [`SecretStore`] at delivery
//! time, so a connector can be handed the value it needs without the value ever
//! appearing in a config file, a log line, an audit row or a `Debug` output.
//! [`SecretValue`] redacts and zeroizes itself for that reason.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use zeroize::Zeroize;

/// Why a secret could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretError {
    /// The reference is not a legal name (absolute, empty, or containing `..`).
    InvalidRef(String),
    /// No secret is stored under that name.
    Missing(String),
    /// The store could not be read.
    Io(String),
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretError::InvalidRef(reference) => {
                write!(f, "invalid secret reference {reference:?}")
            }
            SecretError::Missing(reference) => write!(f, "secret {reference:?} is not configured"),
            SecretError::Io(detail) => write!(f, "secret store error: {detail}"),
        }
    }
}

impl std::error::Error for SecretError {}

/// A name a secret is stored under, for example `smtp/alerting`.
///
/// Names are relative, and may only contain ASCII alphanumerics and
/// `.-_/`. `..`, absolute paths and empty components are rejected so a reference
/// cannot escape the store's root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretRef(String);

impl SecretRef {
    /// Validate and wrap a secret name.
    pub fn new(name: impl Into<String>) -> Result<Self, SecretError> {
        let name = name.into();
        if name.is_empty() {
            return Err(SecretError::InvalidRef(name));
        }
        let legal = name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | '/')
        });
        let relative = Path::new(&name)
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
        if !legal || !relative || name.contains("..") || name.starts_with('/') {
            return Err(SecretError::InvalidRef(name));
        }
        Ok(Self(name))
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl serde::Serialize for SecretRef {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for SecretRef {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        SecretRef::new(name).map_err(serde::de::Error::custom)
    }
}

/// A resolved secret. Redacts itself in `Debug` and zeroizes on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    /// Wrap a value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The value itself. Callers must not log or persist it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Something that can resolve a [`SecretRef`] into its value.
pub trait SecretStore: Send + Sync + std::fmt::Debug {
    /// Resolve `reference`, or report why it is unavailable.
    fn get(&self, reference: &SecretRef) -> Result<SecretValue, SecretError>;
}

/// File-backed store: one file per secret under a root directory.
///
/// The file's contents are used verbatim except for one trailing newline, which
/// editors add. The resolved path must stay inside the root, symlinked or not,
/// so a reference such as `../../etc/passwd` is rejected both by
/// [`SecretRef::new`] and again here.
#[derive(Debug)]
pub struct FileSecretStore {
    root: PathBuf,
}

impl FileSecretStore {
    /// A store rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl SecretStore for FileSecretStore {
    fn get(&self, reference: &SecretRef) -> Result<SecretValue, SecretError> {
        let path = self.root.join(reference.as_str());
        let canonical_root = std::fs::canonicalize(&self.root).map_err(|error| {
            SecretError::Io(format!("canonicalize {}: {error}", self.root.display()))
        })?;
        let canonical = std::fs::canonicalize(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                SecretError::Missing(reference.as_str().to_string())
            } else {
                SecretError::Io(format!("resolve {}: {error}", path.display()))
            }
        })?;
        if !canonical.starts_with(&canonical_root) {
            return Err(SecretError::InvalidRef(reference.as_str().to_string()));
        }
        let value = std::fs::read_to_string(&canonical)
            .map_err(|error| SecretError::Io(format!("read {}: {error}", canonical.display())))?;
        Ok(SecretValue::new(
            value.strip_suffix('\n').unwrap_or(&value).to_string(),
        ))
    }
}

/// In-memory store for tests and local development.
#[derive(Debug, Default, Clone)]
pub struct MemorySecretStore {
    secrets: BTreeMap<String, String>,
}

impl MemorySecretStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a secret.
    pub fn with(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.secrets.insert(name.into(), value.into());
        self
    }
}

impl SecretStore for MemorySecretStore {
    fn get(&self, reference: &SecretRef) -> Result<SecretValue, SecretError> {
        self.secrets
            .get(reference.as_str())
            .map(SecretValue::new)
            .ok_or_else(|| SecretError::Missing(reference.as_str().to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_reject_traversal_and_absolute_paths() {
        assert!(SecretRef::new("smtp/alerting").is_ok());
        assert!(SecretRef::new("webhook-hook.v1").is_ok());
        for bad in ["", "/etc/passwd", "../secret", "a/../../b", "a b", "a\\b"] {
            assert!(
                SecretRef::new(bad).is_err(),
                "{bad:?} must not be a legal secret reference"
            );
        }
    }

    #[test]
    fn values_redact_themselves() {
        let value = SecretValue::new("hunter2");
        assert_eq!(format!("{value:?}"), "SecretValue(<redacted>)");
        assert_eq!(value.expose(), "hunter2");
    }

    #[test]
    fn file_store_resolves_inside_its_root_and_rejects_escapes() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::create_dir_all(dir.path().join("smtp")).expect("mkdir");
        std::fs::write(dir.path().join("smtp/alerting"), "s3cret\n").expect("write");
        std::fs::write(
            dir.path().parent().expect("parent").join("outside-secret"),
            "x",
        )
        .expect("write");

        let store = FileSecretStore::new(dir.path());
        let reference = SecretRef::new("smtp/alerting").expect("ref");
        assert_eq!(store.get(&reference).expect("secret").expose(), "s3cret");

        let missing = SecretRef::new("smtp/nope").expect("ref");
        assert_eq!(
            store.get(&missing),
            Err(SecretError::Missing("smtp/nope".to_string()))
        );

        // A symlink that escapes the root is refused even though the name is legal.
        let link = dir.path().join("escape");
        std::os::unix::fs::symlink(dir.path().parent().unwrap().join("outside-secret"), &link)
            .expect("symlink");
        let reference = SecretRef::new("escape").expect("ref");
        assert_eq!(
            store.get(&reference),
            Err(SecretError::InvalidRef("escape".to_string()))
        );
    }
}
