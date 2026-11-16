// SPDX-License-Identifier: AGPL-3.0-only

//! Signed export bundles for the lineage ledger (CC-14).
//!
//! A bundle is everything an auditor needs and nothing the verifier must fetch:
//! a manifest (range, count, root hash, signer DID, checkpoint signatures,
//! attachment hashes), the entries in that range, and a detached signature. It
//! is JSON so it can be archived, mailed, or handed over on removable media, and
//! [`verify_bundle`] is a pure function over bytes — it opens no database, starts
//! no listener and performs no network I/O, so a bundle verifies on a machine
//! with no network.
//!
//! ```text
//! bundle.json   manifest + entries (canonical JSON)
//! bundle.sig    detached Ed25519 signature over
//!               "TirBase/v1/LineageLedgerBundle" || 0x00 || bundle.json
//! attachments/  optional payloads, each committed to by sha256 + length
//! ```
//!
//! Verification checks, in order: the bundle signature against a caller-supplied
//! trusted key set, the range and count against the manifest, enter-entry
//! linkage and recomputed hashes (so an edited payload fails even if it is
//! re-signed), the root hash, the checkpoint signatures, and every attachment
//! hash. Failures are reported as typed [`BundleViolation`]s with a readable
//! reason rather than a bare "invalid".

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tirbase_core::traits::KeyProvider;
use tirbase_types::DeviceSignature;

use crate::lineage_ledger::{
    verify_chain, verify_checkpoints, verify_ed25519, LedgerCheckpoint, LedgerEntry, LedgerError,
    LineageLedger, ViolationKind, ZERO_HASH,
};

/// Domain-separation context for the detached bundle signature.
pub const CONTEXT_LEDGER_BUNDLE: &str = "TirBase/v1/LineageLedgerBundle";

/// Bundle format version understood by this module.
pub const BUNDLE_FORMAT_VERSION: u32 = 1;

/// Most entries one bundle may carry.
pub const MAX_BUNDLE_ENTRIES: usize = 100_000;

/// One attachment committed to by the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentRef {
    /// File name, relative and contained.
    pub name: String,
    /// SHA-256 of the attachment bytes.
    pub sha256_hex: String,
    /// Length of the attachment in bytes.
    pub bytes: u64,
}

/// Bundle manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Bundle format version.
    pub format_version: u32,
    /// When the bundle was created.
    pub created_est: i64,
    /// DID of the signing key.
    pub signer_did: String,
    /// Raw public key (hex) of the signing key, pinned into the manifest.
    pub signer_public_key_hex: String,
    /// First sequence in the bundle.
    pub range_start: u64,
    /// Last sequence in the bundle.
    pub range_end: u64,
    /// Hash the first entry links to ([`ZERO_HASH`] for a bundle starting at 1).
    pub range_prev_hash: String,
    /// Number of entries in the bundle.
    pub entry_count: u64,
    /// Entry hash of the last entry.
    pub root_hash: String,
    /// Checkpoints inside the range.
    pub checkpoints: Vec<LedgerCheckpoint>,
    /// Attachments, sorted by name.
    pub attachments: Vec<AttachmentRef>,
}

/// A bundle body: manifest plus entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerBundle {
    /// Manifest.
    pub manifest: BundleManifest,
    /// Entries in sequence order.
    pub entries: Vec<LedgerEntry>,
}

/// A bundle plus its detached signature.
#[derive(Debug, Clone)]
pub struct SignedBundle {
    /// Bundle body.
    pub bundle: LedgerBundle,
    /// Detached signature.
    pub signature: DeviceSignature,
}

impl SignedBundle {
    /// Bytes the signature covers.
    pub fn signing_bytes(bundle: &LedgerBundle) -> Result<Vec<u8>, LedgerError> {
        let body = serde_json::to_vec(bundle)
            .map_err(|error| LedgerError::Store(format!("serialise bundle: {error}")))?;
        let mut bytes = Vec::with_capacity(CONTEXT_LEDGER_BUNDLE.len() + 1 + body.len());
        bytes.extend_from_slice(CONTEXT_LEDGER_BUNDLE.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&body);
        Ok(bytes)
    }

    /// Sign a bundle with `key`.
    pub fn sign(bundle: LedgerBundle, key: &dyn KeyProvider) -> Result<Self, LedgerError> {
        let bytes = Self::signing_bytes(&bundle)?;
        let signature = key
            .sign(&bytes)
            .map_err(|error| LedgerError::Store(format!("sign bundle: {error:?}")))?;
        Ok(Self { bundle, signature })
    }

    /// Detached signature as hex.
    pub fn signature_hex(&self) -> String {
        match &self.signature {
            DeviceSignature::Ed25519(bytes) => hex::encode(bytes),
            DeviceSignature::P256(bytes) => hex::encode(bytes),
        }
    }

    /// Bundle JSON (compact, canonical).
    pub fn to_json(&self) -> Result<String, LedgerError> {
        serde_json::to_string(&self.bundle)
            .map_err(|error| LedgerError::Store(format!("serialise bundle: {error}")))
    }

    /// Write `bundle.json`, `bundle.sig` and the attachments under `dir`.
    pub fn write_to_dir(
        &self,
        dir: impl AsRef<Path>,
        attachments: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), LedgerError> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir)
            .map_err(|error| LedgerError::Store(format!("create {dir:?}: {error}")))?;
        std::fs::write(dir.join("bundle.json"), self.to_json()?)
            .map_err(|error| LedgerError::Store(format!("write bundle.json: {error}")))?;
        std::fs::write(dir.join("bundle.sig"), self.signature_hex())
            .map_err(|error| LedgerError::Store(format!("write bundle.sig: {error}")))?;
        if !attachments.is_empty() {
            let attachment_dir = dir.join("attachments");
            std::fs::create_dir_all(&attachment_dir).map_err(|error| {
                LedgerError::Store(format!("create {attachment_dir:?}: {error}"))
            })?;
            for (name, bytes) in attachments {
                std::fs::write(attachment_dir.join(name), bytes).map_err(|error| {
                    LedgerError::Store(format!("write attachment {name}: {error}"))
                })?;
            }
        }
        Ok(())
    }

    /// Read a bundle and its signature from `dir`.
    pub fn read_from_dir(dir: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let dir = dir.as_ref();
        let json = std::fs::read_to_string(dir.join("bundle.json"))
            .map_err(|error| LedgerError::Store(format!("read bundle.json: {error}")))?;
        let bundle: LedgerBundle = serde_json::from_str(&json)
            .map_err(|error| LedgerError::Store(format!("parse bundle.json: {error}")))?;
        let signature_hex = std::fs::read_to_string(dir.join("bundle.sig"))
            .map_err(|error| LedgerError::Store(format!("read bundle.sig: {error}")))?;
        let signature = signature_from_hex(signature_hex.trim())?;
        Ok(Self { bundle, signature })
    }

    /// Read the attachments a bundle's manifest names from `dir/attachments`.
    pub fn read_attachments(&self, dir: impl AsRef<Path>) -> BTreeMap<String, Vec<u8>> {
        let dir = dir.as_ref().join("attachments");
        let mut attachments = BTreeMap::new();
        for reference in &self.bundle.manifest.attachments {
            if let Ok(bytes) = std::fs::read(dir.join(&reference.name)) {
                attachments.insert(reference.name.clone(), bytes);
            }
        }
        attachments
    }
}

/// Parse a hex Ed25519 signature.
pub fn signature_from_hex(value: &str) -> Result<DeviceSignature, LedgerError> {
    let bytes = hex::decode(value.trim())
        .map_err(|error| LedgerError::InvalidRequest(format!("signature is not hex: {error}")))?;
    let array: [u8; 64] = bytes.as_slice().try_into().map_err(|_| {
        LedgerError::InvalidRequest("signature must be 64 bytes (Ed25519)".to_string())
    })?;
    Ok(DeviceSignature::Ed25519(array))
}

/// SHA-256 of an attachment's bytes, hex.
pub fn attachment_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Export `[start, end]` of `ledger` as a signed bundle.
pub fn export_bundle(
    ledger: &LineageLedger,
    key: &dyn KeyProvider,
    start: u64,
    end: u64,
    attachments: &BTreeMap<String, Vec<u8>>,
    created_est: i64,
) -> Result<SignedBundle, LedgerError> {
    if start == 0 || end < start {
        return Err(LedgerError::InvalidRequest(format!(
            "invalid export range {start}..={end}"
        )));
    }
    let entries = ledger.range(start, end)?;
    let expected = end - start + 1;
    if entries.len() as u64 != expected {
        return Err(LedgerError::InvalidRequest(format!(
            "range {start}..={end} needs {expected} entries but the ledger has {}",
            entries.len()
        )));
    }
    if entries.len() > MAX_BUNDLE_ENTRIES {
        return Err(LedgerError::InvalidRequest(format!(
            "bundle is limited to {MAX_BUNDLE_ENTRIES} entries"
        )));
    }
    let range_prev_hash = if start == 1 {
        ZERO_HASH.to_string()
    } else {
        ledger
            .get(start - 1)?
            .map(|entry| entry.entry_hash)
            .ok_or_else(|| {
                LedgerError::InvalidRequest(format!(
                    "entry {} is missing, so the bundle cannot be linked",
                    start - 1
                ))
            })?
    };
    let root_hash = entries
        .last()
        .map(|entry| entry.entry_hash.clone())
        .unwrap_or_else(|| ZERO_HASH.to_string());
    let checkpoints: Vec<LedgerCheckpoint> = ledger
        .checkpoints()?
        .into_iter()
        .filter(|checkpoint| checkpoint.seq >= start && checkpoint.seq <= end)
        .collect();
    let mut attachment_refs: Vec<AttachmentRef> = attachments
        .iter()
        .map(|(name, bytes)| AttachmentRef {
            name: name.clone(),
            sha256_hex: attachment_digest(bytes),
            bytes: bytes.len() as u64,
        })
        .collect();
    attachment_refs.sort_by(|a, b| a.name.cmp(&b.name));

    let bundle = LedgerBundle {
        manifest: BundleManifest {
            format_version: BUNDLE_FORMAT_VERSION,
            created_est,
            signer_did: key.did().to_string(),
            signer_public_key_hex: hex::encode(key.public_key_bytes()),
            range_start: start,
            range_end: end,
            range_prev_hash,
            entry_count: entries.len() as u64,
            root_hash,
            checkpoints,
            attachments: attachment_refs,
        },
        entries,
    };
    SignedBundle::sign(bundle, key)
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Kind of bundle verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleViolationKind {
    /// Unknown bundle format version.
    UnsupportedFormat,
    /// The manifest and the entries disagree about the range or count.
    CountMismatch,
    /// The entries do not start or end where the manifest says.
    RangeMismatch,
    /// A checkpoint commits to entries that are not in the bundle.
    Truncation,
    /// The same sequence appears twice.
    Duplicate,
    /// Entries are out of order.
    Reorder,
    /// An entry does not link to its predecessor.
    PreviousHashMismatch,
    /// An entry hash does not match its content.
    EntryHashMismatch,
    /// An entry payload does not match the committed payload hash.
    PayloadHashMismatch,
    /// The root hash does not match the last entry.
    RootHashMismatch,
    /// The signer is not in the trusted key set.
    UntrustedSigner,
    /// The detached signature does not verify.
    SignatureInvalid,
    /// A checkpoint is malformed or its hash does not match.
    CheckpointInvalid,
    /// A checkpoint signer is not trusted.
    WrongSigner,
    /// An attachment the manifest names is missing.
    AttachmentMissing,
    /// An attachment does not match its committed hash or length.
    AttachmentHashMismatch,
}

impl BundleViolationKind {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            BundleViolationKind::UnsupportedFormat => "unsupported_format",
            BundleViolationKind::CountMismatch => "count_mismatch",
            BundleViolationKind::RangeMismatch => "range_mismatch",
            BundleViolationKind::Truncation => "truncation",
            BundleViolationKind::Duplicate => "duplicate",
            BundleViolationKind::Reorder => "reorder",
            BundleViolationKind::PreviousHashMismatch => "previous_hash_mismatch",
            BundleViolationKind::EntryHashMismatch => "entry_hash_mismatch",
            BundleViolationKind::PayloadHashMismatch => "payload_hash_mismatch",
            BundleViolationKind::RootHashMismatch => "root_hash_mismatch",
            BundleViolationKind::UntrustedSigner => "untrusted_signer",
            BundleViolationKind::SignatureInvalid => "signature_invalid",
            BundleViolationKind::CheckpointInvalid => "checkpoint_invalid",
            BundleViolationKind::WrongSigner => "wrong_signer",
            BundleViolationKind::AttachmentMissing => "attachment_missing",
            BundleViolationKind::AttachmentHashMismatch => "attachment_hash_mismatch",
        }
    }
}

/// One bundle verification failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleViolation {
    /// Kind.
    pub kind: BundleViolationKind,
    /// Human-readable reason.
    pub detail: String,
}

impl BundleViolation {
    fn new(kind: BundleViolationKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

/// Result of verifying a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleReport {
    /// `true` when nothing was reported.
    pub ok: bool,
    /// Signer DID named by the manifest, once it matched a trusted key.
    pub signer_did: Option<String>,
    /// Entries in the bundle.
    pub entry_count: usize,
    /// Range covered.
    pub range: Option<(u64, u64)>,
    /// Whether the detached signature verified.
    pub signature_ok: bool,
    /// Whether the entry chain is intact.
    pub chain_ok: bool,
    /// Whether the manifest root hash matches the last entry.
    pub root_hash_ok: bool,
    /// Whether every checkpoint verified.
    pub checkpoints_ok: bool,
    /// Whether every attachment matched.
    pub attachments_ok: bool,
    /// Failures, in check order.
    pub violations: Vec<BundleViolation>,
    /// One-line summary.
    pub message: String,
}

impl BundleReport {
    /// Failure reasons, one line each.
    pub fn reasons(&self) -> Vec<String> {
        self.violations
            .iter()
            .map(|violation| format!("{}: {}", violation.kind.as_str(), violation.detail))
            .collect()
    }
}

/// Verify a bundle against a trusted key set and attachment bytes.
///
/// Pure computation: no database, filesystem or network access. `trusted_keys`
/// maps a DID to its raw public key; `attachments` maps a manifest name to its
/// bytes. An attachment the manifest names but the caller does not provide is a
/// failure — a bundle is not "verified" when evidence is missing.
pub fn verify_bundle(
    bundle: &LedgerBundle,
    signature: &DeviceSignature,
    trusted_keys: &BTreeMap<String, Vec<u8>>,
    attachments: &BTreeMap<String, Vec<u8>>,
) -> BundleReport {
    let mut violations = Vec::new();
    let manifest = &bundle.manifest;

    // 1. Format.
    if manifest.format_version != BUNDLE_FORMAT_VERSION {
        violations.push(BundleViolation::new(
            BundleViolationKind::UnsupportedFormat,
            format!(
                "bundle format {} is not supported (expected {BUNDLE_FORMAT_VERSION})",
                manifest.format_version
            ),
        ));
    }

    // 2. Signer identity: the manifest must name a key the verifier trusts, and
    // the pinned key must be that key.
    let mut signature_ok = false;
    let mut signer_did = None;
    match trusted_keys.get(&manifest.signer_did) {
        None => violations.push(BundleViolation::new(
            BundleViolationKind::UntrustedSigner,
            format!("no trusted public key for signer {}", manifest.signer_did),
        )),
        Some(public_key) => {
            let pinned = hex::encode(public_key);
            if !pinned.eq_ignore_ascii_case(&manifest.signer_public_key_hex) {
                violations.push(BundleViolation::new(
                    BundleViolationKind::UntrustedSigner,
                    format!(
                        "manifest pins key {} for {}, but the trusted key is {pinned}",
                        manifest.signer_public_key_hex, manifest.signer_did
                    ),
                ));
            } else {
                signer_did = Some(manifest.signer_did.clone());
                match SignedBundle::signing_bytes(bundle)
                    .and_then(|bytes| verify_ed25519(public_key, &bytes, signature))
                {
                    Ok(()) => signature_ok = true,
                    Err(error) => violations.push(BundleViolation::new(
                        BundleViolationKind::SignatureInvalid,
                        format!("detached signature does not verify: {error}"),
                    )),
                }
            }
        }
    }

    // 3. Range and count.
    if manifest.entry_count != bundle.entries.len() as u64 {
        violations.push(BundleViolation::new(
            BundleViolationKind::CountMismatch,
            format!(
                "manifest declares {} entries, bundle carries {}",
                manifest.entry_count,
                bundle.entries.len()
            ),
        ));
    }
    if let (Some(first), Some(last)) = (bundle.entries.first(), bundle.entries.last()) {
        if first.seq > manifest.range_start {
            violations.push(BundleViolation::new(
                BundleViolationKind::Truncation,
                format!(
                    "bundle starts at sequence {}, but the manifest starts at {}",
                    first.seq, manifest.range_start
                ),
            ));
        }
        if first.seq != manifest.range_start {
            violations.push(BundleViolation::new(
                BundleViolationKind::RangeMismatch,
                format!(
                    "first entry is sequence {}, manifest range starts at {}",
                    first.seq, manifest.range_start
                ),
            ));
        }
        if last.seq < manifest.range_end {
            violations.push(BundleViolation::new(
                BundleViolationKind::Truncation,
                format!(
                    "bundle ends at sequence {}, but the manifest ends at {}",
                    last.seq, manifest.range_end
                ),
            ));
        }
        if last.seq != manifest.range_end {
            violations.push(BundleViolation::new(
                BundleViolationKind::RangeMismatch,
                format!(
                    "last entry is sequence {}, manifest range ends at {}",
                    last.seq, manifest.range_end
                ),
            ));
        }
    } else {
        violations.push(BundleViolation::new(
            BundleViolationKind::CountMismatch,
            "bundle carries no entries".to_string(),
        ));
    }

    // 4. Chain: linkage, recomputed hashes, ordering and duplicates.
    let chain_violations = verify_chain(
        &bundle.entries,
        manifest.range_start,
        &manifest.range_prev_hash,
    );
    for violation in &chain_violations {
        violations.push(BundleViolation::new(
            bundle_kind_for(violation.kind),
            format!("seq {}: {}", violation.seq, violation.detail),
        ));
    }
    let chain_ok = chain_violations.is_empty();

    // 5. Root hash.
    let root_hash_ok = bundle
        .entries
        .last()
        .map(|entry| entry.entry_hash == manifest.root_hash)
        .unwrap_or(false);
    if !root_hash_ok {
        violations.push(BundleViolation::new(
            BundleViolationKind::RootHashMismatch,
            format!(
                "manifest root {} does not match the last entry hash",
                manifest.root_hash
            ),
        ));
    }

    // 6. Checkpoints: trusted signer set is the key set the caller supplied.
    let trusted_signers: BTreeSet<String> = trusted_keys.keys().cloned().collect();
    let resolve = |did: &str| trusted_keys.get(did).cloned();
    let checkpoint_violations = verify_checkpoints(
        &bundle.entries,
        &manifest.checkpoints,
        &trusted_signers,
        &resolve,
    );
    for violation in &checkpoint_violations {
        let kind = match violation.kind {
            ViolationKind::WrongSigner => BundleViolationKind::WrongSigner,
            ViolationKind::Truncation => BundleViolationKind::Truncation,
            _ => BundleViolationKind::CheckpointInvalid,
        };
        violations.push(BundleViolation::new(
            kind,
            format!("checkpoint {}: {}", violation.seq, violation.detail),
        ));
    }
    let checkpoints_ok = checkpoint_violations.is_empty();

    // 7. Attachments: every manifest reference must be present and match.
    let mut attachments_ok = true;
    for reference in &manifest.attachments {
        match attachments.get(&reference.name) {
            None => {
                attachments_ok = false;
                violations.push(BundleViolation::new(
                    BundleViolationKind::AttachmentMissing,
                    format!("attachment {} is not present", reference.name),
                ));
            }
            Some(bytes) => {
                let digest = attachment_digest(bytes);
                if digest != reference.sha256_hex || bytes.len() as u64 != reference.bytes {
                    attachments_ok = false;
                    violations.push(BundleViolation::new(
                        BundleViolationKind::AttachmentHashMismatch,
                        format!(
                            "attachment {} is {} bytes hashing to {digest}, manifest commits to {} bytes hashing to {}",
                            reference.name,
                            bytes.len(),
                            reference.bytes,
                            reference.sha256_hex
                        ),
                    ));
                }
            }
        }
    }

    let ok = violations.is_empty();
    BundleReport {
        ok,
        signer_did,
        entry_count: bundle.entries.len(),
        range: Some((manifest.range_start, manifest.range_end)),
        signature_ok,
        chain_ok,
        root_hash_ok,
        checkpoints_ok,
        attachments_ok,
        message: if ok {
            format!(
                "bundle verified: {} entries {}..={} signed by {}",
                bundle.entries.len(),
                manifest.range_start,
                manifest.range_end,
                manifest.signer_did
            )
        } else {
            format!("bundle FAILED: {} violation(s)", violations.len())
        },
        violations,
    }
}

/// Verify a bundle whose signature is carried as hex (the on-disk form).
pub fn verify_bundle_hex(
    bundle: &LedgerBundle,
    signature_hex: &str,
    trusted_keys: &BTreeMap<String, Vec<u8>>,
    attachments: &BTreeMap<String, Vec<u8>>,
) -> BundleReport {
    match signature_from_hex(signature_hex) {
        Ok(signature) => verify_bundle(bundle, &signature, trusted_keys, attachments),
        Err(error) => {
            let violation = BundleViolation::new(
                BundleViolationKind::SignatureInvalid,
                format!("signature cannot be parsed: {error}"),
            );
            BundleReport {
                ok: false,
                signer_did: None,
                entry_count: bundle.entries.len(),
                range: Some((bundle.manifest.range_start, bundle.manifest.range_end)),
                signature_ok: false,
                chain_ok: false,
                root_hash_ok: false,
                checkpoints_ok: false,
                attachments_ok: false,
                violations: vec![violation],
                message: "bundle FAILED: signature cannot be parsed".to_string(),
            }
        }
    }
}

fn bundle_kind_for(kind: ViolationKind) -> BundleViolationKind {
    match kind {
        ViolationKind::Duplicate => BundleViolationKind::Duplicate,
        ViolationKind::Reorder => BundleViolationKind::Reorder,
        ViolationKind::PreviousHashMismatch => BundleViolationKind::PreviousHashMismatch,
        ViolationKind::EntryHashMismatch => BundleViolationKind::EntryHashMismatch,
        ViolationKind::PayloadHashMismatch => BundleViolationKind::PayloadHashMismatch,
        ViolationKind::Truncation => BundleViolationKind::Truncation,
        ViolationKind::SequenceGap => BundleViolationKind::RangeMismatch,
        ViolationKind::CheckpointForgery
        | ViolationKind::CheckpointSignature
        | ViolationKind::WrongSigner => BundleViolationKind::CheckpointInvalid,
    }
}

/// Build a trusted-key map entry from a signing key.
pub fn trusted_key_entry(key: &dyn KeyProvider) -> (String, Vec<u8>) {
    (key.did().to_string(), key.public_key_bytes())
}
