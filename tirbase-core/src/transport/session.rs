//! NoiseSession — Noise_IK_25519_AESGCM_SHA256 handshake, key rotation,
//! and 0-RTT resumption cache (Req 6).

#![allow(dead_code, unused_variables, unused_imports)]

use crate::crdt::delta::Did;
use crate::errors::TirBaseError;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::time::{Duration, UNIX_EPOCH};

/// Maximum number of 0-RTT resumption credentials cached (Req 6.2).
pub const MAX_RESUMPTION_CACHE: usize = 1024;

/// A resumption credential cached for 0-RTT session setup.
#[derive(Debug, Clone)]
pub struct ResumptionCredential {
    pub peer_did: Did,
    /// UTC timestamp (seconds) when this credential was issued.
    pub issued_at: i64,
    /// Opaque credential bytes (Noise session ticket).
    pub credential_bytes: Vec<u8>,
}

impl ResumptionCredential {
    /// Returns true if this credential is still valid (< 24h old — Req 6.2).
    pub fn is_valid(&self, now_secs: i64) -> bool {
        now_secs - self.issued_at < 24 * 3600
    }
}

/// Peer pair key for the resumption cache.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerPair {
    pub local_did: Did,
    pub remote_did: Did,
}

/// An established Noise_IK session.
pub struct NoiseSession {
    pub remote_did: Did,
    /// UTC timestamp (seconds) of the last key rotation.
    pub last_rotated: i64,
    /// Configured key rotation interval in seconds (60–86400 — Req 6.4).
    pub rotation_interval_secs: u64,
}

/// Session manager — handles handshake initiation, resumption cache, and rotation.
pub struct SessionManager {
    /// 0-RTT resumption credential cache, capped at 1024 entries (Req 6.2).
    resumption_cache: LruCache<PeerPair, ResumptionCredential>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            resumption_cache: LruCache::new(
                NonZeroUsize::new(MAX_RESUMPTION_CACHE).unwrap(),
            ),
        }
    }

    /// Initiate a Noise_IK session with a peer.
    ///
    /// 1. Check peer Trust_Level — if REVOKED, return `PeerRevoked` (Req 6.7).
    /// 2. Attempt 0-RTT resumption if a valid credential exists (Req 6.2–6.3).
    /// 3. Fall back to full IK handshake if resumption fails (Req 6.3).
    pub async fn initiate(&mut self, peer_did: Did) -> Result<NoiseSession, TirBaseError> {
        todo!("Task 9: implement Noise IK handshake via snow crate")
    }

    /// Rotate session keys in-place without dropping the connection (Req 6.4).
    /// On failure, terminates the session and schedules renegotiation (Req 6.5).
    pub fn rotate_keys(&mut self, session: &mut NoiseSession) -> Result<(), TirBaseError> {
        todo!("Task 9: implement snow rekey()")
    }

    /// Return an active session for `peer_did` if one exists.
    pub fn get_active_session(&self, peer_did: &Did) -> Option<&NoiseSession> {
        todo!("Task 9: implement session lookup")
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}
