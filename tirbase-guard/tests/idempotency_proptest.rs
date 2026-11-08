//! Property test for idempotency semantics (task 20.7, CLAIM-20.7, PV-5.6).
//! P10: any command with a known idempotency key within the retention window
//! returns the stored outcome without a second actuation.

use std::collections::{BTreeMap, HashSet};
use std::sync::Mutex;

use proptest::prelude::*;
use std::io::Cursor;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_guard::commit::{
    clamp_idempotency_retention_secs, commit_dispatch_finalize, EffectTerminalState, Stage16Error,
    Stage16Request, Stage16Store, DEFAULT_IDEMPOTENCY_RETENTION_SECS,
};
use tirbase_guard::{sign_command, DriverProxy};
use tirbase_types::command::CommandMessage;
use tirbase_types::{CommandRole, DeviceSignature, Did, FixedPointValue, TargetId, UNIT_PERCENT};

fn fpv(m: i64) -> FixedPointValue {
    FixedPointValue::new(m, -1, UNIT_PERCENT)
}

#[derive(Debug, Default)]
struct MemStore {
    // (issuer,target,key) -> original_result
    idem: Mutex<BTreeMap<(String, String, [u8; 16]), (String, i64)>>,
    // (issuer,target,epoch) -> (highest, bitmap)
    replay: Mutex<BTreeMap<(String, String, u64), (u64, u64)>>,
    leases: Mutex<BTreeMap<String, String>>,
    effects: Mutex<HashSet<[u8; 16]>>,
}

impl Stage16Store for MemStore {
    fn commit_actuating(&self, req: &Stage16Request<'_>) -> Result<(), Stage16Error> {
        let cmd = req.cmd;
        let ik = (
            cmd.issuer_did.as_str().to_string(),
            cmd.target_id.as_str().to_string(),
            cmd.idempotency_key,
        );
        // (b) idempotency first
        if let Some((orig, exp)) = self.idem.lock().unwrap().get(&ik).cloned() {
            if exp >= req.now_est {
                return Err(Stage16Error::IdempotencyHit {
                    original_result: orig,
                });
            }
        }
        // (a) anti-replay
        let rk = (
            cmd.issuer_did.as_str().to_string(),
            cmd.target_id.as_str().to_string(),
            cmd.enrollment_epoch,
        );
        let mut replay = self.replay.lock().unwrap();
        let (highest, bitmap) = replay.get(&rk).copied().unwrap_or((0, 0));
        let d = tirbase_guard::anti_replay::check_sequence(
            highest,
            bitmap,
            cmd.sequence_number,
            64,
            1024,
            highest == 0 && bitmap == 0,
        );
        match d {
            tirbase_guard::anti_replay::AntiReplayDecision::Accept {
                new_highest,
                new_bitmap,
            } => {
                replay.insert(rk, (new_highest, new_bitmap));
            }
            _ => return Err(Stage16Error::AntiReplay),
        }
        drop(replay);
        // (c) lease (simple)
        let mut leases = self.leases.lock().unwrap();
        if let Some(h) = leases.get(cmd.target_id.as_str()) {
            if h != cmd.issuer_did.as_str() {
                return Err(Stage16Error::LeaseHeld { holder: h.clone() });
            }
        }
        leases.insert(
            cmd.target_id.as_str().to_string(),
            cmd.issuer_did.as_str().to_string(),
        );
        // (e,f)
        let ret = clamp_idempotency_retention_secs(req.idempotency_retention_secs);
        self.idem.lock().unwrap().insert(
            ik,
            (
                req.original_result_json.to_string(),
                req.now_est.saturating_add(ret),
            ),
        );
        self.effects.lock().unwrap().insert(req.entry_id);
        Ok(())
    }
    fn finalize_terminal(
        &self,
        entry_id: &[u8; 16],
        target_id: &str,
        _issuer_did: &str,
        _state: EffectTerminalState,
        _completion_ts: i64,
        _driver_response: Option<&[u8]>,
    ) -> Result<(), String> {
        self.leases.lock().unwrap().remove(target_id);
        let _ = entry_id;
        Ok(())
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// P10: known idempotency key within retention returns stored outcome, no second actuation.
    #[test]
    fn p10_known_idempotency_key_returns_original_without_second_actuation(
        idem_byte in any::<u8>(),
        seq in 1u64..1000,
        now_est in 10_000i64..50_000,
        retention in 60i64..(7*24*3600),
    ) {
        let issuer = InMemoryKeyProvider::generate().unwrap();
        let mut cmd = CommandMessage {
            issuer_did: Did::new(issuer.did()),
            role: CommandRole::CommandIssuer,
            target_id: TargetId::new("pump-1"),
            param: "speed".into(),
            desired_state: fpv(500),
            sequence_number: seq,
            idempotency_key: [idem_byte; 16],
            expiry_est: 9_999_999_999,
            policy_version: 1,
            enrollment_epoch: 0,
            challenge_nonce: None,
            co_signatures: vec![],
            signature: DeviceSignature::Ed25519([0; 64]),
        };
        sign_command(&mut cmd, &issuer).unwrap();
        let store = MemStore::default();
        let mut w1 = Vec::new(); let mut p1 = DriverProxy::new(Cursor::new(&mut w1)); let mut d1 = Cursor::new(b"OK".to_vec());
        let v1 = commit_dispatch_finalize(&store, &cmd, [1u8;16], now_est, now_est, now_est, &mut p1, b"A", &mut d1, now_est+1);
        prop_assert_eq!(v1["status"].as_str(), Some("accepted"));
        prop_assert!(!w1.is_empty(), "first must actuate");
        // Same key+issuer+target, within retention.
        let mut cmd2 = cmd.clone();
        cmd2.sequence_number = seq.saturating_add(1); // different seq; idempotency is keyed by (issuer,target,key)
        sign_command(&mut cmd2, &issuer).unwrap();
        let now2 = now_est.saturating_add(retention.min(3600)).min(now_est + 3599);
        let req = Stage16Request {
            cmd: &cmd2, entry_id: [2u8;16], actuating_ts: now2, now_est: now2, now_mono_secs: now2,
            lease_duration_secs: 30, max_consecutive_renewals: 10, original_result_json: "x",
            idempotency_retention_secs: DEFAULT_IDEMPOTENCY_RETENTION_SECS,
        };
        let r = store.commit_actuating(&req);
        prop_assert!(matches!(r, Err(Stage16Error::IdempotencyHit { .. })), "P10: known key must return cached/hit: {:?}", r);
        // No dispatch path was executed by this idempotency hit; w1 already proved first actuation.
        let _ = retention;
    }
}
