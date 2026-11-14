// SPDX-License-Identifier: AGPL-3.0-only

//! (CLAIM-55.7, PV-30.3): verify each operator runbook procedure by
//! running it against `tirbase-sim` with a simulated fault before the runbook
//! is committed.
//!
//! These tests exercise the production controls and fault scenarios the
//! runbooks prescribe (lockdown/crash-loop, tamper+chain-recovery, restore
//! epoch bump, key revocation, time-anchor UNVERIFIED/recovery) using
//! deterministic `tirbase-sim`/guard/gateway primitives.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rusqlite::{params, Connection};
use tirbase_core::events::{ReasonCode, SecurityEvent as Payload, SecurityEventCategory, Severity};
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::{AssuranceLevel, KeyProvider, MonotonicCounterTrait, TimeSource};
use tirbase_gateway::db::lockdown::SqliteLockdownStore;
use tirbase_gateway::hw_counter_binding::{keys, BootCheck, HardwareCounterBinding};
use tirbase_gateway::security_log::SecurityEventLog;
use tirbase_guard::epoch::{EpochError, EpochRegistry, InMemoryEpochStore};
use tirbase_guard::lockdown::{
    apply_chain_recovery, apply_lockdown_exit, ChainRecoveryPayload, LockdownEntryReason,
    LockdownExitPayload, LockdownStore,
};
use tirbase_guard::node_mode::{NodeMode, NodeModeState};
use tirbase_guard::signed_operation::SignedOperation;
use tirbase_guard::time::{
    FreshnessState, TimeBeacon, TimeRatchet, TimeRatchetConfig, TimeRatchetRecord, TimeRatchetStore,
};
use tirbase_guard::trust_root::{AuthorizedRoleSigner, RolePolicy, TrustRootRecord};
use tirbase_guard::InMemoryLockdownStore;
use tirbase_sim::scenarios::s10_revoked_delta;
use tirbase_sim::scenarios::s24_crash_loop;
use tirbase_types::envelope::{EnvelopeProfile, ParameterKind, ParameterSpec};
use tirbase_types::{CommandRole, DeviceSignature, FixedPointValue, UNIT_BOOLEAN};

static NEXT: AtomicU64 = AtomicU64::new(0);
fn tmp(tag: &str) -> PathBuf {
    let u = NEXT.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("tirbase-runbook-{tag}-{}-{u}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn payload(n: u64) -> Payload {
    Payload::new(
        SecurityEventCategory::CommandDecision,
        Severity::Low,
        ReasonCode::CommandAccepted,
    )
    .with_actor(format!("did:test:{n}"))
    .with_target(format!("t{n}"))
}

fn sample_profile(id: [u8; 16]) -> EnvelopeProfile {
    EnvelopeProfile {
        profile_id: id,
        version: 1,
        device_class: "test".into(),
        parameters: vec![ParameterSpec {
            name: "on".into(),
            unit_id: UNIT_BOOLEAN,
            canonical_exponent: 0,
            kind: ParameterKind::Bool,
            max_rate_per_sec: FixedPointValue::new(1, 0, UNIT_BOOLEAN),
            dwell_secs: 0,
            min_off_secs: 0,
            drift_window_secs: 0,
            max_delta_in_window: FixedPointValue::new(1, 0, UNIT_BOOLEAN),
            safe_default: FixedPointValue::new(0, 0, UNIT_BOOLEAN),
            tightening_floor: FixedPointValue::new(0, 0, UNIT_BOOLEAN),
            critical: false,
        }],
        cross_constraints: vec![],
        policy_loosen_m: 2,
        policy_loosen_n: 2,
        policy_timelock_secs: 0,
        policy_cancel_window_secs: 0,
        signature: DeviceSignature::Ed25519([0u8; 64]),
    }
}

fn trust_root_pa_rm(pa: &InMemoryKeyProvider, rm: &InMemoryKeyProvider) -> TrustRootRecord {
    let mut roles = BTreeMap::new();
    roles.insert(
        CommandRole::PolicyAuthority,
        RolePolicy::new(
            1,
            vec![AuthorizedRoleSigner {
                did: pa.did().to_string(),
                public_key: pa.public_key_bytes(),
            }],
        ),
    );
    roles.insert(
        CommandRole::RevocationManager,
        RolePolicy::new(
            1,
            vec![AuthorizedRoleSigner {
                did: rm.did().to_string(),
                public_key: rm.public_key_bytes(),
            }],
        ),
    );
    TrustRootRecord {
        version: 1,
        root_ca_public_keys: vec![],
        threshold_k: 1,
        role_thresholds: roles,
        device_class_floors: BTreeMap::new(),
        expiry_est: i64::MAX,
        revoked_root_ca_keys: vec![],
        signatures: vec![],
    }
}

// ── CLAIM-55.1 lockdown runbook (S24 fault + M-of-N exit procedure) ──────────
#[test]
fn runbook_lockdown_exit_requires_m_of_n_and_clears_lockdown() {
 // Simulated fault: crash-loop escalation enters LOCKDOWN (runbook/crash-loop & lockdown).
    s24_crash_loop::s24_crash_loop_escalates_to_lockdown_within_window();

 // Procedure: only M-of-N (>=2 distinct roles) with full profile exits LOCKDOWN.
    let dir = tmp("lockdown");
    let store = SqliteLockdownStore::new(dir.join("primary.db"), dir.join("lockdown"));
    let mode = NodeModeState::new(NodeMode::Normal);
    store
        .set_lockdown(LockdownEntryReason::CrashLoopEscalation)
        .unwrap();
    mode.set(NodeMode::Lockdown);

    let pa = InMemoryKeyProvider::generate().unwrap();
    let rm = InMemoryKeyProvider::generate().unwrap();
    let tr = trust_root_pa_rm(&pa, &rm);
    let profile = sample_profile([0x55; 16]);
    let payload = LockdownExitPayload {
        node_id: "node1".into(),
        issued_at_est: 1_000,
        reason: "runbook verified exit".into(),
        envelope_profile_id: profile.profile_id,
    };

 // Single-role attempt must fail (distinct roles required).
    let mut op1 = SignedOperation::new(&payload, 1_000, None).unwrap();
    op1.sign_with(&pa, CommandRole::PolicyAuthority).unwrap();
    assert!(apply_lockdown_exit(&op1, &payload, &tr, Some(&profile), &store, &mode).is_err());
    assert!(store.is_lockdown().unwrap());
    assert_eq!(mode.get(), NodeMode::Lockdown);

 // PA+RM succeeds: clears persistence and returns to Normal.
    let mut op2 = SignedOperation::new(&payload, 1_000, None).unwrap();
    op2.sign_with(&pa, CommandRole::PolicyAuthority).unwrap();
    op2.sign_with(&rm, CommandRole::RevocationManager).unwrap();
    apply_lockdown_exit(&op2, &payload, &tr, Some(&profile), &store, &mode).unwrap();
    assert!(!store.is_lockdown().unwrap());
    assert_eq!(mode.get(), NodeMode::Normal);

    let _ = std::fs::remove_dir_all(dir);
}

// ── CLAIM-55.2 tamper runbook (injected break + signed chain recovery) ──────
#[test]
fn runbook_tamper_detection_and_chain_recovery() {
    let dir = tmp("tamper");
    let primary = dir.join("primary.db");
    let mode = NodeModeState::new(NodeMode::Starting);
    let dev = Arc::new(InMemoryKeyProvider::generate().unwrap());
    {
        let log = SecurityEventLog::new_persistent_with_mode(
            &primary,
            Some(dev.clone()),
            false,
            Some(mode.clone()),
        );
        log.set_rate_limit_enabled(false);
        for i in 1..=8u64 {
            log.append_payload(payload(i));
        }
    }
 // Simulated fault: interior chain break.
    let conn = Connection::open(&primary).unwrap();
    conn.execute(
        "UPDATE security_events SET target='TAMPERED' WHERE seq=?1",
        params![4i64],
    )
    .unwrap();
    drop(conn);

    let mode2 = NodeModeState::new(NodeMode::Starting);
    let log2 = SecurityEventLog::new_persistent_with_mode(
        &primary,
        Some(dev.clone()),
        false,
        Some(mode2.clone()),
    );
    let broken = log2.verify_hash_chain().expect("verify");
    assert!(broken.is_some(), "tamper must break chain");
    assert_eq!(mode2.get(), NodeMode::Restricted);
    assert!(log2
        .chained_events()
        .iter()
        .any(|e| e.reason_code == ReasonCode::TamperDetection));

 // Procedure: signed chain recovery exits Restricted.
    let pa = InMemoryKeyProvider::generate().unwrap();
    let tr = {
        let mut roles = BTreeMap::new();
        roles.insert(
            CommandRole::PolicyAuthority,
            RolePolicy::new(
                1,
                vec![AuthorizedRoleSigner {
                    did: pa.did().to_string(),
                    public_key: pa.public_key_bytes(),
                }],
            ),
        );
        TrustRootRecord {
            version: 1,
            root_ca_public_keys: vec![],
            threshold_k: 1,
            role_thresholds: roles,
            device_class_floors: BTreeMap::new(),
            expiry_est: i64::MAX,
            revoked_root_ca_keys: vec![],
            signatures: vec![],
        }
    };
    let rec = ChainRecoveryPayload {
        recovery_id: [0x55; 16],
        first_broken_seq: broken.unwrap_or(1),
        acknowledged_tamper_seq: broken.unwrap_or(1),
        new_segment_id: 2,
        operator_reason: "tamper runbook recovery".into(),
    };
    let mut op = SignedOperation::new(&rec, 1_000, None).unwrap();
    op.sign_with(&pa, CommandRole::PolicyAuthority).unwrap();
    let ld_store = SqliteLockdownStore::new(dir.join("primary.db"), dir.join("lockdown-chain"));
    apply_chain_recovery(&op, &rec, &tr, Some(&ld_store), &mode2).unwrap();
    assert_eq!(mode2.get(), NodeMode::Normal);

    let _ = std::fs::remove_dir_all(dir);
}

// ── CLAIM-55.3 restore runbook (S22 fault: epoch bump + prior-epoch reject) ─
#[derive(Debug)]
struct MemCounter(std::sync::atomic::AtomicU64);
impl MonotonicCounterTrait for MemCounter {
    fn read(&self) -> Result<u64, tirbase_core::errors::TirBaseError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
    fn increment(&self) -> Result<u64, tirbase_core::errors::TirBaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst) + 1)
    }
    fn set_if_greater(&self, value: u64) -> Result<u64, tirbase_core::errors::TirBaseError> {
        let current = self.0.load(Ordering::SeqCst);
        if value > current {
            self.0.store(value, Ordering::SeqCst);
            Ok(value)
        } else {
            Ok(current)
        }
    }
    fn assurance_level(&self) -> AssuranceLevel {
        AssuranceLevel::Level1
    }
}

#[test]
fn runbook_restore_bumps_epoch_and_rejects_prior_epoch() {
 // Simulated restore/rollback fault (S22) + runbook restore invariants.
    let dir = tmp("restore");
    let db_path = dir.join("primary.db");
    let hw_value = 920u64;
    let binding = HardwareCounterBinding::open(
        &db_path,
        Arc::new(MemCounter(std::sync::atomic::AtomicU64::new(hw_value))),
        1_000,
    )
    .unwrap();
    let connection = Connection::open(&db_path).unwrap();
    connection
        .execute(
            &format!(
                "INSERT OR REPLACE INTO {} (key, value) VALUES (?1, ?2)",
                tirbase_gateway::hw_counter_binding::MONOTONIC_COUNTERS_TABLE
            ),
            params![keys::SW_COUNTER_AT_LAST_HW_WRITE, (hw_value - 400) as i64],
        )
        .unwrap();
    connection
        .execute(
            &format!(
                "INSERT OR REPLACE INTO {} (key, value) VALUES (?1, ?2)",
                tirbase_gateway::hw_counter_binding::MONOTONIC_COUNTERS_TABLE
            ),
            params![keys::HW_COUNTER_VALUE, hw_value as i64],
        )
        .unwrap();
    match binding.check_at_boot().unwrap() {
        BootCheck::Regression { .. } => {}
        BootCheck::Consistent => panic!("restore/rollback must be detected"),
    }
    let lockdown: i64 = connection
        .query_row(
            &format!(
                "SELECT value FROM {} WHERE key = ?1",
                tirbase_gateway::hw_counter_binding::MONOTONIC_COUNTERS_TABLE
            ),
            params![keys::LOCKDOWN_STATE],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(lockdown, 1, "restore rollback must persist LOCKDOWN");

 // Signed-restore semantics: epoch bump invalidates prior-epoch commands.
    let epochs = EpochRegistry::new(Arc::new(InMemoryEpochStore::default()));
    epochs.ensure_enrolled("dev1", 1_000).unwrap();
    let bumped = epochs
        .restore_bump("dev1", "restore runbook", 2_000)
        .unwrap();
    assert_eq!(bumped.epoch, 1);
 // Post-restore: current epoch is 1 (prior epoch 0 commands are stale/rejected).
    assert!(matches!(
        epochs.check_command_epoch("dev1", 0),
        Err(EpochError::StaleEpoch { .. })
    ));
    epochs.check_command_epoch("dev1", 1).unwrap();
    let _ = std::fs::remove_dir_all(dir);
}

// ── CLAIM-55.4 key-compromise runbook (S10 fault: revoked issuer rejected) ──
#[test]
fn runbook_key_compromise_revocation_rejects_revoked_issuer() {
 // Simulated fault: post-revocation delta from revoked DID rejected (S10).
    s10_revoked_delta::run_s10(1).expect("S10 revoked delta must be rejected");
}

// ── CLAIM-55.5 crash-loop runbook (S24 fault) ───────────────────────────────
#[test]
fn runbook_crash_loop_escalates_to_lockdown() {
    s24_crash_loop::s24_crash_loop_escalates_to_lockdown_within_window();
 // Explicit threshold persistence check (procedure expectation).
    let store = InMemoryLockdownStore::new();
    let mode = NodeModeState::new(NodeMode::Starting);
    let mut tracker = tirbase_guard::lockdown::CrashLoopTracker::new(3, 300);
    let _ = tracker.record_crash(10);
    let _ = tracker.record_crash(120);
    let d3 = tracker.record_crash(200);
    tirbase_guard::lockdown::apply_crash_decision(d3, &store, &mode).unwrap();
    assert!(store.is_lockdown().unwrap());
    assert_eq!(mode.get(), NodeMode::Lockdown);
}

// ── CLAIM-55.6 time-anchor-failure runbook (S19/S23/S31) ────────────────────
#[derive(Debug)]
struct FixedTime(u64, i64, u64);
impl TimeSource for FixedTime {
    fn monotonic_now(&self) -> u64 {
        self.0
    }
    fn wall_hint(&self) -> Option<i64> {
        Some(self.1.saturating_mul(1_000_000))
    }
    fn boot_id(&self) -> u64 {
        self.2
    }
}
#[derive(Debug, Default)]
struct MemStore(std::sync::Mutex<Option<TimeRatchetRecord>>);
impl TimeRatchetStore for MemStore {
    fn load(&self) -> Result<Option<TimeRatchetRecord>, tirbase_guard::time::TimeRatchetError> {
        Ok(*self.0.lock().unwrap())
    }
    fn save(
        &self,
        record: &TimeRatchetRecord,
    ) -> Result<(), tirbase_guard::time::TimeRatchetError> {
        *self.0.lock().unwrap() = Some(*record);
        Ok(())
    }
}

#[test]
fn runbook_time_anchor_failure_unverified_and_recovery() {
 // Faults: delayed delivery, poisoning resistance, reboot UNVERIFIED floor.
    tirbase_sim::scenarios::s19_s23_s31_time::run_s19(1).unwrap();
    tirbase_sim::scenarios::s19_s23_s31_time::run_s23(1).unwrap();
    tirbase_sim::scenarios::s19_s23_s31_time::run_s31(1).unwrap();

 // Procedure: after reboot, freshness Unverified and now_est == persisted_floor;
 // a valid M-of-N beacon restores Verified freshness.
    let floor = 1_800_000_000i64;
    let store = Arc::new(MemStore::default());
    store
        .save(&TimeRatchetRecord {
            last_beacon_time: floor,
            mono_at_beacon: 5_000_000_000,
            persisted_floor: floor,
            beacon_boot_id: 7,
            updated_at_mono: 5_000_000_000,
        })
        .unwrap();
    let mut ratchet = TimeRatchet::open(store, TimeRatchetConfig::default()).unwrap();
    let clock = FixedTime(1_000_000, floor + 1_000, 8);
    assert_eq!(ratchet.now_est(&clock), floor);
    assert_eq!(ratchet.freshness(&clock), FreshnessState::Unverified);

    let a = InMemoryKeyProvider::generate().unwrap();
    let b = InMemoryKeyProvider::generate().unwrap();
    let beacon = TimeBeacon {
        wall_time_secs: floor + 10,
        issuer_did: "did:key:z6MktimeAnchor".to_string(),
        mono_seq: 1,
        valid_for_secs: 300,
    };
    let mut op = SignedOperation::<TimeBeacon>::new(&beacon, beacon.wall_time_secs, None).unwrap();
    op.sign_with(&a, CommandRole::TimeAnchor).unwrap();
    op.sign_with(&b, CommandRole::TimeAnchor).unwrap();
    let resolve = |did: &str| {
        if did == a.did() {
            Some(a.public_key_bytes())
        } else if did == b.did() {
            Some(b.public_key_bytes())
        } else {
            None
        }
    };
    ratchet.advance(&op, &beacon, &clock, resolve).unwrap();
    assert_eq!(ratchet.freshness(&clock), FreshnessState::Verified);
    assert!(ratchet.now_est(&clock) >= floor);
}
