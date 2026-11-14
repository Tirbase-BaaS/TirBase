// SPDX-License-Identifier: AGPL-3.0-only

//! Shared helpers for the S1–S35 adversary scenarios.
//!
//! Every helper is deterministic: scenario functions receive a seed from
//! [`crate::runner::ScenarioRunner`] and must produce identical behaviour for
//! the same seed (PV-12.1).

use std::sync::Mutex;

use tirbase_core::crdt::delta::{Delta, Ed25519Signature, PriorityClass};
use tirbase_core::identity::keypair::sign;
use tirbase_core::traits::TimeSource;
use tirbase_guard::time::{TimeRatchetError, TimeRatchetRecord, TimeRatchetStore};
use tirbase_types::{FixedPointValue, UnitId};

/// A test-controlled [`TimeSource`] with independent monotonic, wall and boot
/// domains. Scenarios advance or reboot it explicitly so no wall clock is read.
#[derive(Debug)]
pub struct FixedTimeSource {
    state: Mutex<TimeState>,
}

#[derive(Debug, Clone, Copy)]
struct TimeState {
    mono_micros: u64,
    wall_secs: i64,
    boot_id: u64,
}

impl FixedTimeSource {
    pub fn new(boot_id: u64, wall_secs: i64, mono_secs: u64) -> Self {
        Self {
            state: Mutex::new(TimeState {
                mono_micros: mono_secs.saturating_mul(1_000_000),
                wall_secs,
                boot_id,
            }),
        }
    }

    pub fn advance_secs(&self, secs: i64) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.mono_micros = state
            .mono_micros
            .saturating_add((secs.max(0) as u64).saturating_mul(1_000_000));
    }

    pub fn set_wall_secs(&self, wall_secs: i64) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .wall_secs = wall_secs;
    }

    pub fn reboot(&self, boot_id: u64) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.mono_micros = 1_000_000;
        state.boot_id = boot_id;
    }
}

impl TimeSource for FixedTimeSource {
    fn monotonic_now(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .mono_micros
    }

    fn wall_hint(&self) -> Option<i64> {
        Some(
            self.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .wall_secs
                .saturating_mul(1_000_000),
        )
    }

    fn boot_id(&self) -> u64 {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).boot_id
    }
}

/// In-memory [`TimeRatchetStore`] for scenarios.
#[derive(Debug, Default)]
pub struct MemoryRatchetStore {
    record: Mutex<Option<TimeRatchetRecord>>,
}

impl TimeRatchetStore for MemoryRatchetStore {
    fn load(&self) -> Result<Option<TimeRatchetRecord>, TimeRatchetError> {
        Ok(*self.record.lock().unwrap_or_else(|p| p.into_inner()))
    }

    fn save(&self, record: &TimeRatchetRecord) -> Result<(), TimeRatchetError> {
        *self.record.lock().unwrap_or_else(|p| p.into_inner()) = Some(*record);
        Ok(())
    }
}

/// Build a fixed-point value with a caller-chosen exponent and unit.
pub fn fp(mantissa: i64, exponent: i8, unit_id: UnitId) -> FixedPointValue {
    FixedPointValue::new(mantissa, exponent, unit_id)
}

/// Build a structurally valid, signed Delta. Used by CRDT scenarios that need
/// to drive `apply_incoming_delta` directly.
pub fn signed_delta(
    secret: &[u8; 32],
    author_did: String,
    schema_hash: [u8; 32],
    lamport: u64,
    payload: Vec<u8>,
    seq: u8,
) -> Delta {
    let mut id = [0u8; 32];
    id[0] = seq;
    id[1] = lamport as u8;
    let mut delta = Delta {
        id,
        author_did,
        signature: Ed25519Signature::default(),
        schema_hash,
        automerge_bytes: payload,
        priority: PriorityClass::Low,
        causal_parents: vec![],
        tags: vec![],
        lamport,
        created_at: 0,
    };
    let canonical = delta.canonical_bytes();
    delta.signature = sign(secret, &canonical).expect("sign delta");
    delta.id = Delta::compute_id(&canonical);
    delta
}

/// A payload that is loadable as an Automerge document with one root key.
pub fn automerge_payload(actor: &[u8], key: &str, value: &str) -> Vec<u8> {
    use automerge::transaction::Transactable;
    let mut doc = automerge::AutoCommit::new().with_actor(automerge::ActorId::from(actor));
    doc.put(automerge::ROOT, key, value).expect("automerge put");
    doc.save()
}
