// SPDX-License-Identifier: Apache-2.0

//! SFTP connector: one idempotently named JSON file per event.
//!
//! The session is injected as [`SftpSession`]; a host binds an SFTP library and
//! this crate keeps the naming, path-safety and duplicate rules consistent with
//! the other connectors.

use crate::connector::{
    validate_connector_common, AuthKind, Connector, ConnectorBuildError, ConnectorCapabilities,
    ConnectorHealth, ConnectorKind, DeliveryRequest, DeliveryResult, DEFAULT_MAX_PAYLOAD_BYTES,
};

/// Result of a put-if-absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SftpPut {
    /// The file was created.
    Created,
    /// The file already existed.
    AlreadyPresent,
}

/// Transport failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SftpTransportError {
    /// Whether a retry could succeed.
    pub retryable: bool,
    /// Secret-free detail.
    pub detail: String,
}

impl SftpTransportError {
    /// A transient failure.
    pub fn retryable(detail: impl Into<String>) -> Self {
        Self {
            retryable: true,
            detail: detail.into(),
        }
    }

    /// A permanent failure.
    pub fn permanent(detail: impl Into<String>) -> Self {
        Self {
            retryable: false,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for SftpTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.detail)
    }
}

impl std::error::Error for SftpTransportError {}

/// An SFTP session.
pub trait SftpSession: Send + Sync {
    /// Create `path` with `bytes` if it does not exist.
    fn put_if_absent(&self, path: &str, bytes: &[u8]) -> Result<SftpPut, SftpTransportError>;
}

/// An SFTP connector.
pub struct SftpConnector<S: SftpSession> {
    name: String,
    remote_dir: String,
    session: S,
    max_payload_bytes: usize,
}

impl<S: SftpSession> SftpConnector<S> {
    /// Build a connector writing into `remote_dir`.
    pub fn new(
        name: impl Into<String>,
        remote_dir: impl Into<String>,
        session: S,
    ) -> Result<Self, ConnectorBuildError> {
        let name = name.into();
        validate_connector_common(&name, DEFAULT_MAX_PAYLOAD_BYTES)?;
        let remote_dir = remote_dir.into();
        validate_remote_dir(&remote_dir)?;
        Ok(Self {
            name,
            remote_dir,
            session,
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
        })
    }

    /// Restrict the accepted payload size.
    pub fn with_max_payload_bytes(mut self, max_payload_bytes: usize) -> Self {
        self.max_payload_bytes = max_payload_bytes.max(1);
        self
    }

    /// The remote directory.
    pub fn remote_dir(&self) -> &str {
        &self.remote_dir
    }

    /// Remote path for one idempotency key.
    pub fn remote_path(&self, idempotency_key: &str) -> String {
        if self.remote_dir.ends_with('/') {
            format!("{}{}.json", self.remote_dir, idempotency_key)
        } else {
            format!("{}/{}.json", self.remote_dir, idempotency_key)
        }
    }
}

fn validate_remote_dir(remote_dir: &str) -> Result<(), ConnectorBuildError> {
    if remote_dir.is_empty() {
        return Err(ConnectorBuildError::new("remote_dir", "must not be empty"));
    }
    if remote_dir.contains(['\0', '\n', '\r']) {
        return Err(ConnectorBuildError::new(
            "remote_dir",
            "must not contain control characters",
        ));
    }
    for segment in remote_dir.split('/') {
        if segment == ".." {
            return Err(ConnectorBuildError::new(
                "remote_dir",
                "must not contain '..' segments",
            ));
        }
    }
    Ok(())
}

impl<S: SftpSession> Connector for SftpConnector<S> {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> ConnectorKind {
        ConnectorKind::Sftp
    }

    fn capabilities(&self) -> ConnectorCapabilities {
        ConnectorCapabilities {
            idempotent: true,
            auth: vec![AuthKind::MutualTls],
            max_payload_bytes: self.max_payload_bytes,
        }
    }

    fn deliver(&self, request: &DeliveryRequest) -> DeliveryResult {
        let document = serde_json::json!({
            "event_id": request.event_id,
            "event_type": request.event_type,
            "tenant": request.tenant,
            "idempotency_key": request.idempotency_key,
            "attempt": request.attempt,
            "data": request.payload,
        });
        let bytes = match serde_json::to_vec_pretty(&document) {
            Ok(bytes) => bytes,
            Err(error) => return DeliveryResult::permanent(format!("payload: {error}")),
        };
        if bytes.len() > self.max_payload_bytes {
            return DeliveryResult::permanent(format!(
                "{} bytes exceeds the {}-byte ceiling",
                bytes.len(),
                self.max_payload_bytes
            ));
        }
        if !request.idempotency_key.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        }) || request.idempotency_key.contains("..")
        {
            return DeliveryResult::permanent("idempotency key is not a safe file name");
        }
        let path = self.remote_path(&request.idempotency_key);
        match self.session.put_if_absent(&path, &bytes) {
            Ok(SftpPut::Created) => DeliveryResult::delivered(format!("put {path}")),
            Ok(SftpPut::AlreadyPresent) => DeliveryResult::duplicate(format!("{path} exists")),
            Err(error) if error.retryable => DeliveryResult::retryable(error.detail, None),
            Err(error) => DeliveryResult::permanent(error.detail),
        }
    }

    fn health(&self) -> ConnectorHealth {
        ConnectorHealth::healthy(format!("SFTP session bound for {}", self.remote_dir))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_directories_reject_traversal_and_control_characters() {
        assert!(validate_remote_dir("/inbound/tirbase").is_ok());
        assert!(validate_remote_dir("inbound/").is_ok());
        assert!(validate_remote_dir("inbound/../etc").is_err());
        assert!(validate_remote_dir("/inbound\n").is_err());
        assert!(validate_remote_dir("").is_err());
    }
}
