//! Signed `TimeBeacon` ingress (CLAIM-7.4, PV-22.5, PV-28).
//!
//! This is the gateway's production entry point for authenticated time: a
//! `TimeAnchor` beacon arrives as a [`SignedOperation<TimeBeacon>`] envelope and
//! is admitted (or rejected) by [`TimeRatchet::advance`]. The file-based form
//! below is what the gateway consumes at boot; the same admission path serves
//! mesh and admin ingress once those transports carry beacons.
//!
//! # Wire format
//!
//! Trust anchors (`time_anchor_keys_path`):
//!
//! ```json
//! { "anchors": [ { "did": "did:key:z6Mk...", "public_key_hex": "ab12..." } ] }
//! ```
//!
//! Beacon envelope (`time_beacon_path`):
//!
//! ```json
//! { "beacon": { "wall_time_secs": 1800000000, "issuer_did": "did:key:z6Mk...",
//! "mono_seq": 1, "valid_for_secs": 300 },
//! "signed_operation": { "context_string": "TirBase/v1/TimeBeacon", ... } }
//! ```
//!
//! Signatures cover `context || 0x00 || SHA-256(CBOR(beacon))`, so a time-anchor
//! signature cannot be replayed as a command or policy signature.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tirbase_core::traits::TimeSource;
use tirbase_guard::signed_operation::SignedOperation;
use tirbase_guard::time::{RatchetAdvance, TimeBeacon, TimeRatchet};

/// Trusted `TimeAnchor` public keys, keyed by DID.
pub type TimeAnchorKeys = BTreeMap<String, Vec<u8>>;

#[derive(Debug, Deserialize)]
struct TimeAnchorTrustFile {
    anchors: Vec<TimeAnchorEntry>,
}

#[derive(Debug, Deserialize)]
struct TimeAnchorEntry {
    did: String,
    public_key_hex: String,
}

#[derive(Debug, Deserialize)]
struct TimeBeaconEnvelope {
    beacon: TimeBeacon,
    signed_operation: SignedOperation<TimeBeacon>,
}

/// Load the trusted `TimeAnchor` public keys.
///
/// Only 32-byte Ed25519 keys are accepted: P-256 beacon signatures are not
/// implemented yet, and silently skipping a malformed key would weaken the
/// quorum.
pub fn load_trust_anchors(path: &Path) -> Result<TimeAnchorKeys> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read time anchor keys at {}", path.display()))?;
    let file: TimeAnchorTrustFile =
        serde_json::from_str(&raw).context("failed to parse time anchor trust file")?;

    let mut keys = TimeAnchorKeys::new();
    for entry in file.anchors {
        let key = hex::decode(entry.public_key_hex.trim())
            .with_context(|| format!("time anchor {} has a non-hex public_key_hex", entry.did))?;
        if key.len() != 32 {
            bail!(
                "time anchor {} public key is {} bytes; expected a 32-byte Ed25519 key",
                entry.did,
                key.len()
            );
        }
        keys.insert(entry.did, key);
    }

    if keys.is_empty() {
        bail!("time anchor trust file lists no anchors");
    }
    Ok(keys)
}

/// Read a beacon envelope from disk.
pub fn load_beacon_envelope(path: &Path) -> Result<(TimeBeacon, SignedOperation<TimeBeacon>)> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read time beacon at {}", path.display()))?;
    let envelope: TimeBeaconEnvelope =
        serde_json::from_str(&raw).context("failed to parse time beacon envelope")?;
    Ok((envelope.beacon, envelope.signed_operation))
}

/// Admit a beacon file through [`TimeRatchet::advance`].
///
/// A rejected beacon leaves the ratchet (and its persisted floor) untouched and
/// is returned as an error so the caller can log and emit the corresponding
/// security event.
pub fn ingest_time_beacon_file(
    beacon_path: &Path,
    anchors: &TimeAnchorKeys,
    ratchet: &mut TimeRatchet,
    ts: &dyn TimeSource,
) -> Result<RatchetAdvance> {
    let (beacon, operation) = load_beacon_envelope(beacon_path)?;
    ratchet
        .advance(&operation, &beacon, ts, |did| anchors.get(did).cloned())
        .map_err(|error| anyhow::anyhow!("time beacon rejected: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
    use tirbase_core::traits::KeyProvider;
    use tirbase_guard::time::TimeRatchetConfig;
    use tirbase_guard::TimeRatchetStore;
    use tirbase_types::CommandRole;

    #[derive(Debug, Default)]
    struct MemoryStore {
        record: std::sync::Mutex<Option<tirbase_guard::TimeRatchetRecord>>,
    }

    impl TimeRatchetStore for MemoryStore {
        fn load(
            &self,
        ) -> std::result::Result<
            Option<tirbase_guard::TimeRatchetRecord>,
            tirbase_guard::TimeRatchetError,
        > {
            Ok(*self.record.lock().unwrap())
        }

        fn save(
            &self,
            record: &tirbase_guard::TimeRatchetRecord,
        ) -> std::result::Result<(), tirbase_guard::TimeRatchetError> {
            *self.record.lock().unwrap() = Some(*record);
            Ok(())
        }
    }

    fn temp_file(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "tirbase-beacon-{tag}-{}-{unique}.json",
            std::process::id()
        ))
    }

    #[test]
    fn beacon_file_is_admitted_and_advances_the_ratchet() {
        let anchor = InMemoryKeyProvider::generate().expect("key");
 // A jump this large requires the default quorum of two distinct anchors.
        let second_anchor = InMemoryKeyProvider::generate().expect("key");
        let beacon = TimeBeacon {
            wall_time_secs: 1_800_000_000,
            issuer_did: anchor.did().to_string(),
            mono_seq: 1,
            valid_for_secs: 300,
        };
        let mut operation =
            SignedOperation::<TimeBeacon>::new(&beacon, beacon.wall_time_secs, None)
                .expect("wrap beacon");
        operation
            .sign_with(&anchor, CommandRole::TimeAnchor)
            .expect("sign beacon");
        operation
            .sign_with(&second_anchor, CommandRole::TimeAnchor)
            .expect("co-sign beacon");

        let beacon_path = temp_file("admitted");
        let trust_path = temp_file("trust");
        std::fs::write(
            &beacon_path,
            serde_json::to_string(&serde_json::json!({
                "beacon": beacon,
                "signed_operation": operation,
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            &trust_path,
            serde_json::to_string(&serde_json::json!({
                "anchors": [
                    { "did": anchor.did(), "public_key_hex": hex::encode(anchor.public_key_bytes()) },
                    { "did": second_anchor.did(), "public_key_hex": hex::encode(second_anchor.public_key_bytes()) }
                ],
            }))
            .unwrap(),
        )
        .unwrap();

        let anchors = load_trust_anchors(&trust_path).expect("load anchors");
        let ts = tirbase_core::traits::SystemTimeSource::new();
        let mut ratchet = TimeRatchet::open(
            std::sync::Arc::new(MemoryStore::default()),
            TimeRatchetConfig::default(),
        )
        .expect("open ratchet");

        let advance =
            ingest_time_beacon_file(&beacon_path, &anchors, &mut ratchet, &ts).expect("admitted");
        assert_eq!(advance.new_floor, 1_800_000_000);
        assert_eq!(ratchet.persisted_floor(), 1_800_000_000);

        let _ = std::fs::remove_file(&beacon_path);
        let _ = std::fs::remove_file(&trust_path);
    }

    #[test]
    fn trust_file_rejects_non_ed25519_keys() {
        let trust_path = temp_file("bad-trust");
        std::fs::write(
            &trust_path,
            r#"{"anchors":[{"did":"did:key:z2Dn","public_key_hex":"aabb"}]}"#,
        )
        .unwrap();

        let error = load_trust_anchors(&trust_path).expect_err("must reject short key");
        assert!(
            error.to_string().contains("32-byte Ed25519"),
            "unexpected error: {error}"
        );

        let _ = std::fs::remove_file(&trust_path);
    }
}
