//! Scenarios S26 and S29 — idempotency-key squatting and retry semantics.
//!
//! Both drive the production gateway `SqliteStage16Store` through
//! `commit_dispatch_finalize`, so the checks are performed by the same
//! issuer-scoped idempotency and anti-replay implementation the gateway uses.

use std::io::Cursor;

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_gateway::guard::SqliteStage16Store;
use tirbase_guard::commit::{commit_dispatch_finalize, FinalizeContext};
use tirbase_guard::driver_proxy::DriverProxy;
use tirbase_guard::sign_command;
use tirbase_types::command::CommandMessage;
use tirbase_types::{CommandRole, DeviceSignature, Did, FixedPointValue, TargetId, UNIT_PERCENT};

fn command(
    issuer: &InMemoryKeyProvider,
    idempotency_key: [u8; 16],
    sequence_number: u64,
    value: i64,
) -> CommandMessage {
    let mut command = CommandMessage {
        issuer_did: Did::new(issuer.did()),
        role: CommandRole::CommandIssuer,
        target_id: TargetId::new("pump-idem"),
        param: "speed".to_string(),
        desired_state: FixedPointValue::new(value, -1, UNIT_PERCENT),
        sequence_number,
        idempotency_key,
        expiry_est: 9_999_999_999,
        policy_version: 1,
        enrollment_epoch: 0,
        challenge_nonce: None,
        co_signatures: vec![],
        signature: DeviceSignature::Ed25519([0; 64]),
    };
    sign_command(&mut command, issuer).expect("sign command");
    command
}

struct Outcome {
    value: serde_json::Value,
    actuated: bool,
}

fn commit(
    store: &SqliteStage16Store,
    command: &CommandMessage,
    entry_byte: u8,
    now: i64,
) -> Outcome {
    let mut wire = Vec::new();
    let mut proxy = DriverProxy::new(Cursor::new(&mut wire));
    let mut driver = Cursor::new(b"OK".to_vec());
    let value = commit_dispatch_finalize(
        store,
        command,
        FinalizeContext {
            entry_id: [entry_byte; 16],
            actuating_ts: now,
            now_est: now,
            now_mono_secs: now,
            completion_ts: now + 1,
        },
        &mut proxy,
        b"ACT",
        &mut driver,
    );
    Outcome {
        value,
        actuated: !wire.is_empty(),
    }
}

fn temp_db(tag: &str, seed: u64) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tirbase-sim-{tag}-{}-{seed}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir.join("primary.db")
}

/// S26 — the same key bytes under a different issuer are a different command.
pub fn run_s26(seed: u64) -> Result<(), String> {
    let path = temp_db("s26", seed);
    let store = SqliteStage16Store::open(&path).map_err(|e| format!("S26 store: {e}"))?;
    let result = (|| {
        let attacker =
            InMemoryKeyProvider::generate().map_err(|e| format!("S26 attacker key: {e}"))?;
        let legitimate =
            InMemoryKeyProvider::generate().map_err(|e| format!("S26 legit key: {e}"))?;
        let key = [0xA5u8; 16];

        let squat = commit(&store, &command(&attacker, key, 1, 400), 1, 1_000);
        if squat.value["status"] != "accepted" || !squat.actuated {
            return Err(format!(
                "S26 FAIL: attacker's command did not actuate: {}",
                squat.value
            ));
        }

        let legit = commit(&store, &command(&legitimate, key, 1, 500), 2, 1_002);
        if legit.value["status"] != "accepted" || !legit.actuated {
            return Err(format!(
                "S26 FAIL: legitimate issuer collided with squatted key: {}",
                legit.value
            ));
        }
        if legit.value["idempotency_cache_hit"] == true {
            return Err("S26 FAIL: cross-issuer key returned the attacker's cached result".into());
        }

        let replay = commit(&store, &command(&legitimate, key, 1, 500), 3, 1_004);
        if replay.value["idempotency_cache_hit"] != true || replay.actuated {
            return Err(format!(
                "S26 FAIL: legitimate replay did not use its own cached result: {}",
                replay.value
            ));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(path.parent().unwrap_or(&path));
    result
}

/// S29 — same seq retry and new seq with the same key both return the cached
/// outcome without a second actuation; a new key actuates normally.
pub fn run_s29(seed: u64) -> Result<(), String> {
    let path = temp_db("s29", seed);
    let store = SqliteStage16Store::open(&path).map_err(|e| format!("S29 store: {e}"))?;
    let result = (|| {
        let issuer = InMemoryKeyProvider::generate().map_err(|e| format!("S29 key: {e}"))?;
        let key = [0x5Au8; 16];

        let first = commit(&store, &command(&issuer, key, 1, 500), 1, 1_000);
        if first.value["status"] != "accepted" || !first.actuated {
            return Err(format!(
                "S29 FAIL: first command did not actuate: {}",
                first.value
            ));
        }

        // (a) Same (seq, key) retry.
        let same_seq = commit(&store, &command(&issuer, key, 1, 500), 2, 1_002);
        if same_seq.value["idempotency_cache_hit"] != true || same_seq.actuated {
            return Err(format!(
                "S29 FAIL: same-seq retry actuated twice: {}",
                same_seq.value
            ));
        }

        // (b) New seq, same idempotency key.
        let new_seq = commit(&store, &command(&issuer, key, 2, 500), 3, 1_004);
        if new_seq.value["idempotency_cache_hit"] != true || new_seq.actuated {
            return Err(format!(
                "S29 FAIL: new-seq retry actuated twice: {}",
                new_seq.value
            ));
        }

        // Control: new seq and new key is a new command.
        let fresh = commit(&store, &command(&issuer, [0x5Bu8; 16], 3, 510), 4, 1_006);
        if fresh.value["status"] != "accepted" || !fresh.actuated {
            return Err(format!(
                "S29 FAIL: fresh command after retries was blocked: {}",
                fresh.value
            ));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(path.parent().unwrap_or(&path));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s26_idempotency_key_squatting() {
        run_s26(1).expect("S26");
    }

    #[test]
    fn s29_retry_semantics() {
        run_s29(1).expect("S29");
    }
}
