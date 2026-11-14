// SPDX-License-Identifier: AGPL-3.0-only

//! OTA updates: signed bundles, release channels, staged rollout, A/B slots,
//! rollback, offline ingest, and version-skew enforcement (F-11).
//!
//! This module provides:
//! - Ed25519 verification of [`SignedOtaBundle`] manifests (domain separated)
//!   and SHA-256 verification of the referenced artifact.
//! - Anti-downgrade / anti-rollback: a bundle whose `bundle_version` is not
//!   strictly greater than the committed version is rejected.
//! - Channel admission: dev/staging/pilot/production and tenant-pinned.
//! - A/B slot state with a power-loss-safe boot pointer so an interrupted
//!   update boots the previous known-good slot.
//! - Staged rollout bookkeeping with health gates and automatic pause.
//! - Version-skew checks that return typed [`VersionSkewError`] values.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tirbase_types::ota::{
    check_version_skew, OtaBundleBody, OtaComponent, ReleaseChannel, SignedOtaBundle,
    VersionSkewError,
};

pub const OTA_BUNDLE_CONTEXT: &[u8] = b"TirBase/v1/OtaBundle\0";
pub const DEFAULT_STAGED_BATCH_PERCENT: u8 = 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OtaError {
    InvalidManifest { detail: String },
    SignatureInvalid { detail: String },
    MissingSignerKey,
    ArtifactHashMismatch { expected: String, actual: String },
    ArtifactSizeMismatch { expected: u64, actual: u64 },
    DowngradeRejected { bundle_version: u64, committed_version: u64 },
    ChannelRejected { detail: String },
    VersionSkew { error: VersionSkewError },
    StateIo { detail: String },
    RolloutPaused { reason: String },
    NotFound { detail: String },
}

impl std::fmt::Display for OtaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OtaError::InvalidManifest { detail } => write!(f, "invalid OTA bundle: {detail}"),
            OtaError::SignatureInvalid { detail } => {
                write!(f, "OTA bundle signature verification failed: {detail}")
            }
            OtaError::MissingSignerKey => write!(f, "no OTA update-signer public key configured"),
            OtaError::ArtifactHashMismatch { expected, actual } => write!(
                f,
                "artifact hash mismatch: expected {expected}, got {actual}"
            ),
            OtaError::ArtifactSizeMismatch { expected, actual } => write!(
                f,
                "artifact size mismatch: expected {expected}, got {actual}"
            ),
            OtaError::DowngradeRejected {
                bundle_version,
                committed_version,
            } => write!(
                f,
                "unsigned or downgraded bundle rejected: bundle_version {bundle_version} <= committed {committed_version}"
            ),
            OtaError::ChannelRejected { detail } => write!(f, "release channel rejected: {detail}"),
            OtaError::VersionSkew { error } => write!(f, "{error}"),
            OtaError::StateIo { detail } => write!(f, "OTA state error: {detail}"),
            OtaError::RolloutPaused { reason } => write!(f, "staged rollout paused: {reason}"),
            OtaError::NotFound { detail } => write!(f, "OTA not found: {detail}"),
        }
    }
}

impl std::error::Error for OtaError {}

/// Device/deployment channel policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelPolicy {
    /// Channels this device may consume (e.g. ["pilot", "production"]).
    pub allowed_channels: Vec<String>,
    /// Tenant id bound to this device, if any. Required to consume a
    /// `tenant_pinned` bundle for that tenant.
    #[serde(default)]
    pub tenant_id: Option<String>,
}

impl Default for ChannelPolicy {
    fn default() -> Self {
        Self {
            allowed_channels: vec![
                "dev".into(),
                "staging".into(),
                "pilot".into(),
                "production".into(),
            ],
            tenant_id: None,
        }
    }
}

impl ChannelPolicy {
    pub fn allows(&self, channel: &ReleaseChannel) -> bool {
        match channel {
            ReleaseChannel::TenantPinned { tenant_id } => self
                .tenant_id
                .as_deref()
                .map(|t| t == tenant_id)
                .unwrap_or(false),
            other => self
                .allowed_channels
                .iter()
                .any(|c| c.eq_ignore_ascii_case(other.as_str())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotName {
    A,
    B,
}

impl SlotName {
    pub fn other(self) -> Self {
        match self {
            SlotName::A => SlotName::B,
            SlotName::B => SlotName::A,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            SlotName::A => "a",
            SlotName::B => "b",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SlotState {
    #[serde(default)]
    pub bundle_version: Option<u64>,
    #[serde(default)]
    pub release_version: Option<String>,
    #[serde(default)]
    pub artifact_hash_sha256_hex: Option<String>,
    #[serde(default)]
    pub installed: bool,
    #[serde(default)]
    pub healthy: bool,
}

/// Power-loss-safe boot/slot state. Persisted atomically (temp+rename+fsync).
///
/// `pending_slot` means an update was staged/activated but not yet marked
/// healthy. On boot, if a pending slot exists it is treated as failed and the
/// system boots the `known_good` slot (previous known-good version).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootState {
    pub current_slot: SlotName,
    pub known_good_slot: SlotName,
    /// Slot currently undergoing update/health verification, if any.
    #[serde(default)]
    pub pending_slot: Option<SlotName>,
    /// True once the pending slot has passed health gates and been promoted.
    #[serde(default)]
    pub pending_committed: bool,
    /// Highest bundle_version ever committed as known-good (anti-downgrade).
    #[serde(default)]
    pub committed_bundle_version: u64,
    #[serde(default)]
    pub slots: BTreeMap<String, SlotState>,
    /// Sticky reason when a pending update was automatically rolled back.
    #[serde(default)]
    pub last_rollback_reason: Option<String>,
}

impl Default for BootState {
    fn default() -> Self {
        let mut slots = BTreeMap::new();
        slots.insert("a".into(), SlotState::default());
        slots.insert("b".into(), SlotState::default());
        Self {
            current_slot: SlotName::A,
            known_good_slot: SlotName::A,
            pending_slot: None,
            pending_committed: false,
            committed_bundle_version: 0,
            slots,
            last_rollback_reason: None,
        }
    }
}

impl BootState {
    pub fn slot_mut(&mut self, slot: SlotName) -> &mut SlotState {
        self.slots.entry(slot.as_str().into()).or_default()
    }
    pub fn slot(&self, slot: SlotName) -> SlotState {
        self.slots.get(slot.as_str()).cloned().unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutPhase {
    Idle,
    Staged,
    Canary,
    Expanding,
    Paused,
    Completed,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthGate {
    pub name: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutState {
    pub rollout_id: String,
    pub bundle_version: u64,
    pub phase: RolloutPhase,
    /// Percentage of fleet exposed (0-100).
    pub exposure_percent: u8,
    /// Total target count tracked for this rollout (informational).
    #[serde(default)]
    pub target_count: u32,
    /// Targets that reported healthy in the current phase.
    #[serde(default)]
    pub healthy_reports: u32,
    /// Targets that reported unhealthy in the current phase.
    #[serde(default)]
    pub unhealthy_reports: u32,
    /// Configured health gates.
    #[serde(default)]
    pub health_gates: Vec<HealthGate>,
    /// Gates satisfied so far (by name).
    #[serde(default)]
    pub satisfied_gates: Vec<String>,
    #[serde(default)]
    pub pause_reason: Option<String>,
    #[serde(default)]
    pub auto_paused: bool,
    #[serde(default)]
    pub rollback_triggered: bool,
}

/// Domain-separated canonical bytes covered by the OTA bundle signature.
pub fn bundle_signing_bytes(body: &OtaBundleBody) -> Result<Vec<u8>, OtaError> {
    let json = serde_json::to_vec(body).map_err(|e| OtaError::InvalidManifest {
        detail: format!("canonicalize body: {e}"),
    })?;
    let mut out = Vec::with_capacity(OTA_BUNDLE_CONTEXT.len() + json.len());
    out.extend_from_slice(OTA_BUNDLE_CONTEXT);
    out.extend_from_slice(&json);
    Ok(out)
}

fn verify_signature(
    signer_public_key: &[u8; 32],
    message: &[u8],
    signature_hex: &str,
) -> Result<(), OtaError> {
    let sig_bytes = hex::decode(signature_hex.trim()).map_err(|e| OtaError::InvalidManifest {
        detail: format!("signature hex: {e}"),
    })?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| OtaError::InvalidManifest {
            detail: "signature must be 64 bytes".into(),
        })?;
    let key = VerifyingKey::from_bytes(signer_public_key).map_err(|e| {
        OtaError::SignatureInvalid {
            detail: format!("invalid signer public key: {e}"),
        }
    })?;
    let sig = Signature::from_bytes(&sig_arr);
    key.verify(message, &sig)
        .map_err(|_| OtaError::SignatureInvalid {
            detail: "Ed25519 verification failed (unsigned or tampered bundle)".into(),
        })
}

pub fn artifact_sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

/// Verify signature, artifact integrity, channel policy, and anti-downgrade.
/// Returns `Ok(())` only for an admissible signed bundle.
pub fn verify_bundle(
    bundle: &SignedOtaBundle,
    artifact_bytes: &[u8],
    signer_public_key: &[u8; 32],
    committed_bundle_version: u64,
    channel_policy: &ChannelPolicy,
) -> Result<(), OtaError> {
    if bundle.body.artifact_hash_sha256_hex.len() != 64
        || !bundle
            .body
            .artifact_hash_sha256_hex
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    {
        return Err(OtaError::InvalidManifest {
            detail: "artifact_hash_sha256_hex must be 64 hex chars".into(),
        });
    }
    let message = bundle_signing_bytes(&bundle.body)?;
    verify_signature(signer_public_key, &message, &bundle.signature_hex)?;

    let actual_hash = artifact_sha256_hex(artifact_bytes);
    let expected_hash = bundle.body.artifact_hash_sha256_hex.to_ascii_lowercase();
    if actual_hash != expected_hash {
        return Err(OtaError::ArtifactHashMismatch {
            expected: expected_hash,
            actual: actual_hash,
        });
    }
    let actual_size = artifact_bytes.len() as u64;
    if actual_size != bundle.body.artifact_size {
        return Err(OtaError::ArtifactSizeMismatch {
            expected: bundle.body.artifact_size,
            actual: actual_size,
        });
    }
    // Unsigned is already rejected above; downgraded (not strictly newer) is
    // rejected here.
    if bundle.body.bundle_version <= committed_bundle_version {
        return Err(OtaError::DowngradeRejected {
            bundle_version: bundle.body.bundle_version,
            committed_version: committed_bundle_version,
        });
    }
    if !channel_policy.allows(&bundle.body.channel) {
        return Err(OtaError::ChannelRejected {
            detail: format!(
                "channel {:?} is not permitted for this device/tenant",
                bundle.body.channel
            ),
        });
    }
    Ok(())
}

/// Power-loss-safe atomic write: write temp file, fsync, rename, fsync dir.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), OtaError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|e| OtaError::StateIo {
        detail: format!("create dir {}: {e}", parent.display()),
    })?;
    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("state"),
        std::process::id()
    ));
    let mut f = fs::File::create(&tmp).map_err(|e| OtaError::StateIo {
        detail: format!("create {}: {e}", tmp.display()),
    })?;
    f.write_all(bytes).map_err(|e| OtaError::StateIo {
        detail: format!("write {}: {e}", tmp.display()),
    })?;
    f.sync_all().map_err(|e| OtaError::StateIo {
        detail: format!("fsync {}: {e}", tmp.display()),
    })?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        OtaError::StateIo {
            detail: format!("rename to {}: {e}", path.display()),
        }
    })?;
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, OtaError> {
    let body = fs::read_to_string(path).map_err(|e| OtaError::StateIo {
        detail: format!("read {}: {e}", path.display()),
    })?;
    serde_json::from_str(&body).map_err(|e| OtaError::StateIo {
        detail: format!("parse {}: {e}", path.display()),
    })
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), OtaError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| OtaError::StateIo {
        detail: format!("serialize {}: {e}", path.display()),
    })?;
    atomic_write(path, &bytes)
}

/// Manages A/B slots and the power-loss-safe boot pointer.
#[derive(Debug, Clone)]
pub struct AbSlotManager {
    state_path: PathBuf,
    slots_root: PathBuf,
}

impl AbSlotManager {
    pub fn new(state_path: PathBuf, slots_root: PathBuf) -> Self {
        Self {
            state_path,
            slots_root,
        }
    }

    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    pub fn slot_dir(&self, slot: SlotName) -> PathBuf {
        self.slots_root.join(slot.as_str())
    }

    pub fn load_state(&self) -> Result<BootState, OtaError> {
        if !self.state_path.exists() {
            return Ok(BootState::default());
        }
        read_json(&self.state_path)
    }

    pub fn save_state(&self, state: &BootState) -> Result<(), OtaError> {
        write_json(&self.state_path, state)
    }

    /// Boot-time reconciliation: if an interrupted update left a pending slot
    /// uncommitted, revert to the previous known-good slot. This guarantees
    /// "an interrupted update boots the previous known-good version".
    pub fn reconcile_on_boot(&self) -> Result<BootState, OtaError> {
        let mut state = self.load_state()?;
        if let Some(pending) = state.pending_slot {
            if !state.pending_committed {
                // Power loss / crash / failed health gate before commit: boot the
                // previous known-good slot.
                state.last_rollback_reason = Some(format!(
                    "interrupted update on slot {} rolled back to known-good slot {}",
                    pending.as_str(),
                    state.known_good_slot.as_str()
                ));
                state.current_slot = state.known_good_slot;
                state.pending_slot = None;
                state.pending_committed = false;
                {
                    let s = state.slot_mut(pending);
                    s.installed = false;
                    s.healthy = false;
                }
                self.save_state(&state)?;
            }
        }
        Ok(state)
    }

    /// Stage artifact bytes into the inactive slot and mark it pending. The
    /// pointer update is atomic; a crash before commit will be reverted on next
    /// boot.
    pub fn stage_bundle(
        &self,
        bundle: &SignedOtaBundle,
        artifact_bytes: &[u8],
    ) -> Result<(BootState, SlotName), OtaError> {
        let mut state = self.load_state()?;
        let target = state.known_good_slot.other();
        let slot_dir = self.slot_dir(target);
        fs::create_dir_all(&slot_dir).map_err(|e| OtaError::StateIo {
            detail: format!("create slot dir {}: {e}", slot_dir.display()),
        })?;
        let artifact_path = slot_dir.join("artifact.bin");
        let manifest_path = slot_dir.join("manifest.json");
        atomic_write(&artifact_path, artifact_bytes)?;
        let manifest_bytes = serde_json::to_vec_pretty(bundle).map_err(|e| OtaError::StateIo {
            detail: format!("serialize manifest: {e}"),
        })?;
        atomic_write(&manifest_path, &manifest_bytes)?;

        {
            let s = state.slot_mut(target);
            s.bundle_version = Some(bundle.body.bundle_version);
            s.release_version = Some(bundle.body.release_version.clone());
            s.artifact_hash_sha256_hex = Some(bundle.body.artifact_hash_sha256_hex.clone());
            s.installed = true;
            s.healthy = false;
        }
        state.pending_slot = Some(target);
        state.pending_committed = false;
        state.current_slot = target; // activate candidate for health verification
        self.save_state(&state)?;
        Ok((state, target))
    }

    /// Mark the pending slot healthy and commit it as the new known-good.
    pub fn commit_pending(&self) -> Result<BootState, OtaError> {
        let mut state = self.load_state()?;
        let pending = state.pending_slot.ok_or_else(|| OtaError::NotFound {
            detail: "no pending update to commit".into(),
        })?;
        let version = state
            .slot(pending)
            .bundle_version
            .unwrap_or(state.committed_bundle_version);
        {
            let s = state.slot_mut(pending);
            s.healthy = true;
        }
        state.known_good_slot = pending;
        state.current_slot = pending;
        state.pending_slot = None;
        state.pending_committed = true;
        if version > state.committed_bundle_version {
            state.committed_bundle_version = version;
        }
        state.last_rollback_reason = None;
        self.save_state(&state)?;
        Ok(state)
    }

    /// Explicit rollback of the pending/current candidate to the previous
    /// known-good slot.
    pub fn rollback(&self, reason: &str) -> Result<BootState, OtaError> {
        let mut state = self.load_state()?;
        let rolled_from = state.pending_slot.unwrap_or(state.current_slot);
        state.last_rollback_reason = Some(reason.to_string());
        state.current_slot = state.known_good_slot;
        state.pending_slot = None;
        state.pending_committed = false;
        {
            let s = state.slot_mut(rolled_from);
            s.installed = false;
            s.healthy = false;
        }
        self.save_state(&state)?;
        Ok(state)
    }
}

/// In-memory/offline rollout controller (persist callers may serialize state).
#[derive(Debug, Clone)]
pub struct RolloutController {
    pub state: Option<RolloutState>,
}

impl Default for RolloutController {
    fn default() -> Self {
        Self { state: None }
    }
}

impl RolloutController {
    pub fn start(
        &mut self,
        rollout_id: String,
        bundle_version: u64,
        target_count: u32,
        health_gates: Vec<HealthGate>,
    ) {
        self.state = Some(RolloutState {
            rollout_id,
            bundle_version,
            phase: RolloutPhase::Canary,
            exposure_percent: DEFAULT_STAGED_BATCH_PERCENT,
            target_count,
            healthy_reports: 0,
            unhealthy_reports: 0,
            health_gates,
            satisfied_gates: Vec::new(),
            pause_reason: None,
            auto_paused: false,
            rollback_triggered: false,
        });
    }

    pub fn record_health(&mut self, healthy: bool) -> Result<(), OtaError> {
        let st = self.state.as_mut().ok_or_else(|| OtaError::NotFound {
            detail: "no active rollout".into(),
        })?;
        if matches!(st.phase, RolloutPhase::Paused | RolloutPhase::RolledBack) {
            return Err(OtaError::RolloutPaused {
                reason: st.pause_reason.clone().unwrap_or_else(|| "paused".into()),
            });
        }
        if healthy {
            st.healthy_reports = st.healthy_reports.saturating_add(1);
        } else {
            st.unhealthy_reports = st.unhealthy_reports.saturating_add(1);
            // Health gate failure => automatic pause.
            st.phase = RolloutPhase::Paused;
            st.auto_paused = true;
            st.pause_reason = Some("health gate failed: unhealthy report received".into());
            return Err(OtaError::RolloutPaused {
                reason: st.pause_reason.clone().unwrap(),
            });
        }
        Ok(())
    }

    pub fn satisfy_gate(&mut self, gate: &str) -> Result<(), OtaError> {
        let st = self.state.as_mut().ok_or_else(|| OtaError::NotFound {
            detail: "no active rollout".into(),
        })?;
        if !st.satisfied_gates.iter().any(|g| g == gate) {
            st.satisfied_gates.push(gate.to_string());
        }
        Ok(())
    }

    /// Advance staged exposure if all required health gates are satisfied and the
    /// rollout is not paused. Returns the new exposure percent.
    pub fn advance(&mut self) -> Result<u8, OtaError> {
        let st = self.state.as_mut().ok_or_else(|| OtaError::NotFound {
            detail: "no active rollout".into(),
        })?;
        if matches!(st.phase, RolloutPhase::Paused | RolloutPhase::RolledBack) {
            return Err(OtaError::RolloutPaused {
                reason: st.pause_reason.clone().unwrap_or_else(|| "paused".into()),
            });
        }
        let all_required_ok = st
            .health_gates
            .iter()
            .filter(|g| g.required)
            .all(|g| st.satisfied_gates.iter().any(|s| s == &g.name));
        if !all_required_ok {
            st.phase = RolloutPhase::Paused;
            st.auto_paused = true;
            st.pause_reason = Some("automatic pause: required health gates not satisfied".into());
            return Err(OtaError::RolloutPaused {
                reason: st.pause_reason.clone().unwrap(),
            });
        }
        st.phase = RolloutPhase::Expanding;
        st.exposure_percent = (st.exposure_percent.saturating_add(25)).min(100);
        if st.exposure_percent >= 100 {
            st.phase = RolloutPhase::Completed;
        }
        Ok(st.exposure_percent)
    }

    pub fn pause(&mut self, reason: &str) -> Result<(), OtaError> {
        let st = self.state.as_mut().ok_or_else(|| OtaError::NotFound {
            detail: "no active rollout".into(),
        })?;
        st.phase = RolloutPhase::Paused;
        st.auto_paused = true;
        st.pause_reason = Some(reason.to_string());
        Ok(())
    }

    pub fn mark_rolled_back(&mut self, reason: &str) -> Result<(), OtaError> {
        let st = self.state.as_mut().ok_or_else(|| OtaError::NotFound {
            detail: "no active rollout".into(),
        })?;
        st.phase = RolloutPhase::RolledBack;
        st.rollback_triggered = true;
        st.pause_reason = Some(reason.to_string());
        Ok(())
    }
}

/// Offline update path: load a signed bundle + artifact from a local directory
/// (for sites without connectivity). The directory must contain `manifest.json`
/// and `artifact.bin`.
pub fn load_offline_bundle(dir: &Path) -> Result<(SignedOtaBundle, Vec<u8>), OtaError> {
    let manifest_path = dir.join("manifest.json");
    let artifact_path = dir.join("artifact.bin");
    let bundle: SignedOtaBundle = read_json(&manifest_path)?;
    let artifact = fs::read(&artifact_path).map_err(|e| OtaError::StateIo {
        detail: format!("read artifact {}: {e}", artifact_path.display()),
    })?;
    Ok((bundle, artifact))
}

/// Evaluate peer component versions against a bundle's compatibility metadata.
/// Returns a typed [`VersionSkewError`] on incompatibility so callers can refuse
/// negotiation without corruption.
pub fn enforce_version_skew(
    peer_versions: &BTreeMap<OtaComponent, String>,
    body: &OtaBundleBody,
) -> Result<(), OtaError> {
    check_version_skew(peer_versions, &body.compatibility)
        .map_err(|error| OtaError::VersionSkew { error })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use tirbase_types::ota::{OtaCompatibility, OtaComponent};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn signed_bundle(k: &SigningKey, version: u64, artifact: &[u8]) -> SignedOtaBundle {
        let body = OtaBundleBody {
            bundle_version: version,
            release_version: format!("1.0.{version}"),
            channel: ReleaseChannel::Production,
            artifact_hash_sha256_hex: artifact_sha256_hex(artifact),
            artifact_size: artifact.len() as u64,
            compatibility: OtaCompatibility {
                component_versions: BTreeMap::from([(OtaComponent::Gateway, format!("1.0.{version}"))]),
                ..Default::default()
            },
            metadata: BTreeMap::new(),
        };
        let msg = bundle_signing_bytes(&body).unwrap();
        let sig = k.sign(&msg);
        SignedOtaBundle {
            body,
            signer_did: "did:key:zUpdate".into(),
            signature_hex: hex::encode(sig.to_bytes()),
        }
    }

    #[test]
    fn unsigned_or_tampered_bundle_is_rejected() {
        let k = key();
        let artifact = b"firmware-bytes";
        let mut b = signed_bundle(&k, 2, artifact);
        b.body.release_version = "tampered".into(); // mutate after signing
        let err = verify_bundle(&b, artifact, &k.verifying_key().to_bytes(), 1, &ChannelPolicy::default()).unwrap_err();
        assert!(matches!(err, OtaError::SignatureInvalid { .. } | OtaError::ArtifactHashMismatch { .. }));
        // fully unsigned
        b.signature_hex = "00".repeat(64);
        let err = verify_bundle(&b, artifact, &k.verifying_key().to_bytes(), 1, &ChannelPolicy::default()).unwrap_err();
        assert!(matches!(err, OtaError::SignatureInvalid { .. }));
    }

    #[test]
    fn downgraded_bundle_is_rejected() {
        let k = key();
        let artifact = b"firmware-bytes";
        let b = signed_bundle(&k, 5, artifact);
        let err = verify_bundle(&b, artifact, &k.verifying_key().to_bytes(), 5, &ChannelPolicy::default()).unwrap_err();
        assert!(matches!(err, OtaError::DowngradeRejected { .. }));
    }

    #[test]
    fn interrupted_update_boots_previous_known_good() {
        let dir = std::env::temp_dir().join(format!("tirbase-ota-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mgr = AbSlotManager::new(dir.join("boot.json"), dir.join("slots"));
        // seed known-good in slot A
        let mut st = BootState::default();
        st.committed_bundle_version = 1;
        st.slot_mut(SlotName::A).bundle_version = Some(1);
        st.slot_mut(SlotName::A).installed = true;
        st.slot_mut(SlotName::A).healthy = true;
        mgr.save_state(&st).unwrap();
        let k = key();
        let artifact = b"v2";
        let bundle = signed_bundle(&k, 2, artifact);
        mgr.stage_bundle(&bundle, artifact).unwrap();
        // simulate power loss: pending not committed, reboot reconciles
        let booted = mgr.reconcile_on_boot().unwrap();
        assert_eq!(booted.current_slot, SlotName::A, "must boot previous known-good");
        assert_eq!(booted.known_good_slot, SlotName::A);
        assert!(booted.pending_slot.is_none());
        assert!(booted.last_rollback_reason.is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn version_skew_returns_typed_error() {
        let mut compat = OtaCompatibility::default();
        compat.min_compatible.insert(OtaComponent::Sdk, "2.0.0".into());
        let body = OtaBundleBody {
            bundle_version: 2,
            release_version: "1.0.2".into(),
            channel: ReleaseChannel::Production,
            artifact_hash_sha256_hex: "00".repeat(32),
            artifact_size: 0,
            compatibility: compat,
            metadata: BTreeMap::new(),
        };
        let mut peer = BTreeMap::new();
        peer.insert(OtaComponent::Sdk, "1.5.0".into());
        let err = enforce_version_skew(&peer, &body).unwrap_err();
        match err {
            OtaError::VersionSkew { error } => {
                assert!(matches!(error, VersionSkewError::BelowMinimum { .. }));
            }
            other => panic!("expected typed skew error, got {other:?}"),
        }
    }
}
