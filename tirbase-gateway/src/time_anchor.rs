// SPDX-License-Identifier: AGPL-3.0-only

//! TimeAnchorService (CLAIM-53.1, CLAIM-53.2, PV-28).
//!
//! Periodically produces signed `COSE_Sign1` time beacons and broadcasts them to
//! registered sinks. Beacons carry `(wall_time_secs, issuer_did, mono_seq,
//! valid_for_secs)` as deterministic-CBOR payload (PV-28.2, RD-5).
//!
//! The service also supports multiple TimeAnchor peers: `select_authenticated_beacon`
//! chooses the most recent valid beacon (by `wall_time_secs`, then `mono_seq`)
//! that satisfies the max-forward-jump constraint relative to the ratchet's
//! persisted floor (PV-28.3). Admission of a selected beacon is performed by the
//! guard's `TimeRatchet::advance()` (existing SignedOperation/anchor-quorum path)
//! or by direct ratchet advance for locally-produced service beacons.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ciborium::value::Value as CborValue;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tirbase_core::crdt::delta::Ed25519Signature;
use tirbase_core::identity::keypair;
use tirbase_core::traits::{KeyProvider, TimeSource};
use tirbase_types::DeviceSignature;

/// COSE algorithm identifier for EdDSA (RFC 9053 / COSE Algorithms).
const COSE_ALG_EDDSA: i64 = -8;
/// COSE_Sign1 signature context string (RFC 9052).
const COSE_SIG_STRUCTURE_CONTEXT: &str = "Signature1";

/// Broadcast sink for periodically produced beacons.
pub trait BeaconSink: Send + Sync {
    fn publish(&self, beacon: &CoseSign1Beacon);
}

/// No-op sink used when no broadcast transport is configured.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopBeaconSink;
impl BeaconSink for NoopBeaconSink {
    fn publish(&self, _beacon: &CoseSign1Beacon) {}
}

/// A signed time beacon encoded as a COSE_Sign1 structure (deterministic CBOR).
///
/// Payload fields: `wall_time_secs`, `issuer_did`, `mono_seq`, `valid_for_secs`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoseSign1Beacon {
 /// Protected header bytes (deterministic CBOR map).
    pub protected: Vec<u8>,
 /// Unprotected header map (currently empty).
    pub unprotected: BTreeMap<String, CborValue>,
 /// Deterministic-CBOR payload bytes containing the beacon fields.
    pub payload: Vec<u8>,
 /// Signature bytes (Ed25519, 64 bytes).
    pub signature: Vec<u8>,
}

/// Beacon payload (PV-28.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeBeaconPayload {
    pub wall_time_secs: i64,
    pub issuer_did: String,
    pub mono_seq: u64,
    pub valid_for_secs: u32,
}

impl TimeBeaconPayload {
    pub fn to_deterministic_cbor(&self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf)
            .map_err(|e| format!("cbor encode payload: {e}"))?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, String> {
        ciborium::de::from_reader(bytes).map_err(|e| format!("cbor decode payload: {e}"))
    }
}

fn protected_header_bytes() -> Result<Vec<u8>, String> {
 // { 1: -8 } (alg = EdDSA), deterministic CBOR.
    let header = CborValue::Map(vec![(
        CborValue::Integer(1.into()),
        CborValue::Integer(COSE_ALG_EDDSA.into()),
    )]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&header, &mut buf)
        .map_err(|e| format!("cbor encode protected: {e}"))?;
    Ok(buf)
}

/// Build COSE Sig_structure bytes for COSE_Sign1:
/// ["Signature1", protected, external_aad(empty), payload]
pub fn sig_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
    let structure = CborValue::Array(vec![
        CborValue::Text(COSE_SIG_STRUCTURE_CONTEXT.to_string()),
        CborValue::Bytes(protected.to_vec()),
        CborValue::Bytes(Vec::new()),
        CborValue::Bytes(payload.to_vec()),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&structure, &mut buf)
        .map_err(|e| format!("cbor encode Sig_structure: {e}"))?;
    Ok(buf)
}

/// Create and sign a COSE_Sign1 time beacon with the provided key provider.
pub fn sign_cose_beacon(
    provider: &dyn KeyProvider,
    wall_time_secs: i64,
    mono_seq: u64,
    valid_for_secs: u32,
) -> Result<CoseSign1Beacon, String> {
    let payload_struct = TimeBeaconPayload {
        wall_time_secs,
        issuer_did: provider.did().to_string(),
        mono_seq,
        valid_for_secs,
    };
    let payload = payload_struct.to_deterministic_cbor()?;
    let protected = protected_header_bytes()?;
    let to_sign = sig_structure(&protected, &payload)?;
    let sig = provider
        .sign(&to_sign)
        .map_err(|e| format!("sign beacon: {e}"))?;
    let signature = match sig {
        DeviceSignature::Ed25519(bytes) => bytes.to_vec(),
        other => return Err(format!("unsupported beacon signature type: {other:?}")),
    };
    Ok(CoseSign1Beacon {
        protected,
        unprotected: BTreeMap::new(),
        payload,
        signature,
    })
}

/// Verify a COSE_Sign1 beacon signature against an Ed25519 public key and return
/// the decoded payload if valid.
pub fn verify_cose_beacon(
    beacon: &CoseSign1Beacon,
    public_key: &[u8],
) -> Result<TimeBeaconPayload, String> {
    let pk: [u8; 32] = public_key
        .try_into()
        .map_err(|_| "expected 32-byte Ed25519 public key".to_string())?;
    let sig_bytes: [u8; 64] = beacon
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| "expected 64-byte Ed25519 signature".to_string())?;
    let to_verify = sig_structure(&beacon.protected, &beacon.payload)?;
    keypair::verify(&pk, &to_verify, &Ed25519Signature::from_bytes(sig_bytes))
        .map_err(|e| format!("beacon signature invalid: {e}"))?;
    TimeBeaconPayload::from_cbor(&beacon.payload)
}

/// Encode a COSE_Sign1 beacon as a deterministic-CBOR array
/// `[protected, unprotected, payload, signature]`.
pub fn encode_cose_sign1(beacon: &CoseSign1Beacon) -> Result<Vec<u8>, String> {
 // unprotected is an (empty) map
    let unprot = CborValue::Map(Vec::new());
    let arr = CborValue::Array(vec![
        CborValue::Bytes(beacon.protected.clone()),
        unprot,
        CborValue::Bytes(beacon.payload.clone()),
        CborValue::Bytes(beacon.signature.clone()),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&arr, &mut buf)
        .map_err(|e| format!("encode COSE_Sign1: {e}"))?;
    Ok(buf)
}

/// Decode a COSE_Sign1 beacon from deterministic-CBOR array bytes.
pub fn decode_cose_sign1(bytes: &[u8]) -> Result<CoseSign1Beacon, String> {
    let val: CborValue =
        ciborium::de::from_reader(bytes).map_err(|e| format!("decode COSE_Sign1: {e}"))?;
    let arr = match val {
        CborValue::Array(a) if a.len() == 4 => a,
        _ => return Err("COSE_Sign1 must be a 4-element array".to_string()),
    };
    let protected = match &arr[0] {
        CborValue::Bytes(b) => b.clone(),
        _ => return Err("COSE_Sign1 protected must be bstr".to_string()),
    };
    let payload = match &arr[2] {
        CborValue::Bytes(b) => b.clone(),
        _ => return Err("COSE_Sign1 payload must be bstr".to_string()),
    };
    let signature = match &arr[3] {
        CborValue::Bytes(b) => b.clone(),
        _ => return Err("COSE_Sign1 signature must be bstr".to_string()),
    };
    Ok(CoseSign1Beacon {
        protected,
        unprotected: BTreeMap::new(),
        payload,
        signature,
    })
}

/// Fingerprint of a COSE beacon (for de-dup/selection audits).
pub fn beacon_fingerprint(beacon: &CoseSign1Beacon) -> [u8; 32] {
    let mut hasher = Sha256::new();
    if let Ok(enc) = encode_cose_sign1(beacon) {
        hasher.update(&enc);
    } else {
        hasher.update(&beacon.payload);
        hasher.update(&beacon.signature);
    }
    let d = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Candidate beacon from a TimeAnchor peer (PV-28.3).
#[derive(Debug, Clone)]
pub struct PeerBeacon {
    pub beacon: CoseSign1Beacon,
 /// Trusted Ed25519 public key for the beacon issuer.
    pub anchor_public_key: Vec<u8>,
}

/// Select the most recent valid beacon satisfying the max-forward-jump constraint.
///
/// - Verifies each candidate's COSE_Sign1 signature.
/// - Rejects beacons whose `wall_time_secs` is below `persisted_floor` (replay/rollback).
/// - Enforces `wall_time_secs - persisted_floor <= max_forward_jump_secs`.
/// - Returns the most recent (highest `wall_time_secs`, tie-break by `mono_seq`)
/// among valid candidates, or `None` if none qualify.
pub fn select_authenticated_beacon(
    candidates: &[PeerBeacon],
    persisted_floor: i64,
    max_forward_jump_secs: i64,
) -> Option<(TimeBeaconPayload, CoseSign1Beacon)> {
    let mut best: Option<(TimeBeaconPayload, CoseSign1Beacon)> = None;
    for candidate in candidates {
        let payload = match verify_cose_beacon(&candidate.beacon, &candidate.anchor_public_key) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if payload.wall_time_secs < persisted_floor {
            continue;
        }
        let jump = payload.wall_time_secs.saturating_sub(persisted_floor);
        if jump > max_forward_jump_secs {
 // Large jumps require M-of-N at ratchet admission; single-peer COSE
 // beacon cannot satisfy the quorum here, so do not select it as a
 // standalone most-recent valid estimate.
            continue;
        }
        let replace = match &best {
            None => true,
            Some((cur, _)) => {
                payload.wall_time_secs > cur.wall_time_secs
                    || (payload.wall_time_secs == cur.wall_time_secs
                        && payload.mono_seq > cur.mono_seq)
            }
        };
        if replace {
            best = Some((payload, candidate.beacon.clone()));
        }
    }
    best
}

/// TimeAnchorService: periodically broadcasts signed COSE_Sign1 time beacons
/// (CLAIM-53.1, PV-28.1, PV-28.2).
pub struct TimeAnchorService {
    provider: Arc<dyn KeyProvider>,
    time_source: Arc<dyn TimeSource>,
    interval: Duration,
    valid_for_secs: u32,
    mono_seq: AtomicU64,
    sink: Arc<dyn BeaconSink>,
    running: Arc<AtomicBool>,
 /// Retain last produced beacon for observers/tests.
    last_beacon: Arc<Mutex<Option<CoseSign1Beacon>>>,
}

impl std::fmt::Debug for TimeAnchorService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimeAnchorService")
            .field("interval", &self.interval)
            .field("valid_for_secs", &self.valid_for_secs)
            .finish_non_exhaustive()
    }
}

impl TimeAnchorService {
    pub fn new(
        provider: Arc<dyn KeyProvider>,
        time_source: Arc<dyn TimeSource>,
        interval: Duration,
        valid_for_secs: u32,
        sink: Arc<dyn BeaconSink>,
    ) -> Self {
        Self {
            provider,
            time_source,
            interval,
            valid_for_secs,
            mono_seq: AtomicU64::new(0),
            sink,
            running: Arc::new(AtomicBool::new(false)),
            last_beacon: Arc::new(Mutex::new(None)),
        }
    }

 /// Produce one signed COSE_Sign1 beacon using the current wall hint and
 /// increment the monotonic sequence number.
    pub fn produce_beacon(&self) -> Result<CoseSign1Beacon, String> {
        let seq = self.mono_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let wall = self
            .time_source
            .wall_hint()
            .map(|us| us / 1_000_000)
            .ok_or_else(|| "wall clock unavailable for beacon".to_string())?;
        let beacon = sign_cose_beacon(self.provider.as_ref(), wall, seq, self.valid_for_secs)?;
        if let Ok(mut g) = self.last_beacon.lock() {
            *g = Some(beacon.clone());
        }
        self.sink.publish(&beacon);
        Ok(beacon)
    }

    pub fn last_beacon(&self) -> Option<CoseSign1Beacon> {
        self.last_beacon.lock().ok().and_then(|g| g.clone())
    }

    pub fn mono_seq(&self) -> u64 {
        self.mono_seq.load(Ordering::SeqCst)
    }

 /// Spawn a periodic broadcast loop. Returns a handle that stops the loop
 /// when dropped/set.
    pub fn spawn_periodic(self: &Arc<Self>) -> Arc<AtomicBool> {
        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);
        let svc = self.clone();
        let flag = running.clone();
        std::thread::spawn(move || {
            while flag.load(Ordering::SeqCst) {
                let _ = svc.produce_beacon();
                std::thread::sleep(svc.interval);
            }
        });
        running
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Helper: collect COSE peer beacons and select the best authenticated estimate
/// per PV-28.3 (most recent valid beacon satisfying max-forward-jump).
pub fn best_authenticated_time(
    peers: &[PeerBeacon],
    persisted_floor: i64,
    max_forward_jump_secs: i64,
) -> Option<i64> {
    select_authenticated_beacon(peers, persisted_floor, max_forward_jump_secs)
        .map(|(payload, _)| payload.wall_time_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
    

    #[test]
    fn cose_sign1_beacon_roundtrip_sign_verify_encode_decode() {
        let kp = InMemoryKeyProvider::generate().expect("key");
        let beacon = sign_cose_beacon(&kp, 1_800_000_000, 7, 300).expect("sign");
        let payload = verify_cose_beacon(&beacon, &kp.public_key_bytes()).expect("verify");
        assert_eq!(payload.wall_time_secs, 1_800_000_000);
        assert_eq!(payload.issuer_did, kp.did());
        assert_eq!(payload.mono_seq, 7);
        assert_eq!(payload.valid_for_secs, 300);

        let enc = encode_cose_sign1(&beacon).expect("encode");
        let dec = decode_cose_sign1(&enc).expect("decode");
        let payload2 = verify_cose_beacon(&dec, &kp.public_key_bytes()).expect("verify decoded");
        assert_eq!(payload, payload2);
    }

    #[test]
    fn select_most_recent_valid_beacon_respecting_max_jump() {
        let a = InMemoryKeyProvider::generate().expect("a");
        let b = InMemoryKeyProvider::generate().expect("b");
        let floor = 1_000;
        let max_jump = 100;
        let b1 = sign_cose_beacon(&a, 1_050, 1, 60).expect("b1");
        let b2 = sign_cose_beacon(&b, 1_080, 2, 60).expect("b2");
        let too_far = sign_cose_beacon(&b, 1_500, 3, 60).expect("far");
        let peers = vec![
            PeerBeacon { beacon: b1, anchor_public_key: a.public_key_bytes() },
            PeerBeacon { beacon: b2.clone(), anchor_public_key: b.public_key_bytes() },
            PeerBeacon { beacon: too_far, anchor_public_key: b.public_key_bytes() },
        ];
        let (selected, _) = select_authenticated_beacon(&peers, floor, max_jump).expect("selected");
        assert_eq!(selected.wall_time_secs, 1_080);
        assert_eq!(selected.mono_seq, 2);
    }
}
