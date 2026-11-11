//! Gateway-binary integration tests for task 8 (CLAIM-8.1, CLAIM-8.2,
//! CLAIM-8.3, CLAIM-8.7, CLAIM-8.8).
//!
//! The real `tirbase-gateway` binary is spawned with a temporary config; these
//! tests assert the boot path installs the trust root under rollback
//! protection, runs the root CA registration self-test, and persists a signed
//! epoch bump to the `device_epoch` table.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use tirbase_core::auth::biscuit;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::identity::keypair;
use tirbase_core::traits::KeyProvider;
use tirbase_guard::epoch::EpochBump;
use tirbase_guard::signed_operation::SignedOperation;
use tirbase_guard::trust_root::{
    AuthorizedRoleSigner, RolePolicy, TrustRootRecord, TrustRootSignature,
};
use tirbase_types::CommandRole;

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let unique = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "tirbase-gateway-task8-{tag}-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn write_config(dir: &Path, extra: &str) -> PathBuf {
    let config_path = dir.join("gateway.toml");
    let body = format!(
        "key_path = {:?}\n\
         counter_db_path = {:?}\n\
         admin_socket = {:?}\n\
         admin_enabled = false\n\
         health_addr = \"127.0.0.1:0\"\n\
         log_level = \"info\"\n\
         checkpoint_interval_secs = 3600\n\
         {extra}",
        dir.join("device-key.json"),
        dir.join("primary.db"),
        dir.join("admin.sock"),
    );
    std::fs::write(&config_path, body).expect("write config");
    config_path
}

fn sign_record(record: &mut TrustRootRecord, keys: &[&InMemoryKeyProvider]) {
    record.signatures.clear();
    let message = record.signing_bytes();
    for key in keys {
        record.signatures.push(TrustRootSignature {
            signer_did: key.did().to_string(),
            signature: key.sign(&message).unwrap(),
        });
    }
}

fn trust_root(
    version: u64,
    root_key: &InMemoryKeyProvider,
    roles: BTreeMap<CommandRole, RolePolicy>,
) -> TrustRootRecord {
    let mut record = TrustRootRecord {
        version,
        root_ca_public_keys: vec![root_key.public_key_bytes()],
        threshold_k: 1,
        role_thresholds: roles,
        device_class_floors: BTreeMap::new(),
        expiry_est: i64::MAX,
        revoked_root_ca_keys: Vec::new(),
        signatures: Vec::new(),
    };
    sign_record(&mut record, &[root_key]);
    record
}

fn role_signer(provider: &InMemoryKeyProvider) -> AuthorizedRoleSigner {
    AuthorizedRoleSigner {
        did: provider.did().to_string(),
        public_key: provider.public_key_bytes(),
    }
}

fn run_until_marker(config: &Path, needle: &str) -> Vec<String> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tirbase-gateway"))
        .arg(config)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gateway");

    let stdout = child.stdout.take().expect("stdout");
    let stderr = child.stderr.take().expect("stderr");
    let (tx, rx) = mpsc::channel();
    for stream in [
        Box::new(stdout) as Box<dyn std::io::Read + Send>,
        Box::new(stderr),
    ] {
        let tx = tx.clone();
        thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);

    let mut lines = Vec::new();
    let deadline = tirbase_core::traits::monotonic_now() + 30_000_000;
    let mut found = false;
    while tirbase_core::traits::monotonic_now() < deadline {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(line) => {
                let hit = line.contains(needle);
                lines.push(line);
                if hit {
                    found = true;
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    assert!(
        found,
        "gateway did not log marker {needle:?}; output:\n{}",
        lines.join("\n")
    );
    lines
}

/// Remove ANSI SGR sequences so assertions can match the rendered log text.
fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for c in chars.by_ref() {
                    if c == 'm' {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

fn counter_row(db: &Path, key: &str) -> Option<i64> {
    let conn = rusqlite::Connection::open(db).expect("open db");
    conn.query_row(
        "SELECT value FROM monotonic_counters WHERE key = ?1",
        [key],
        |row| row.get(0),
    )
    .ok()
}

#[test]
fn boot_installs_trust_root_and_runs_root_ca_self_test() {
    let dir = temp_dir("self-test");
    let (root_seed, _) = keypair::generate_keypair().unwrap();
    let root_key = InMemoryKeyProvider::from_seed(root_seed);

    let record = trust_root(2, &root_key, BTreeMap::new());
    let trust_path = dir.join("trust-root.json");
    std::fs::write(&trust_path, serde_json::to_string_pretty(&record).unwrap()).unwrap();

    // A token minted by the root key proves the registry registration path.
    let token = biscuit::create_token(
        "did:key:zSelfTest",
        "CommandIssuer",
        3_600,
        &root_seed,
        false,
    )
    .unwrap();
    let token_path = dir.join("self-test-token.hex");
    std::fs::write(&token_path, hex::encode(token)).unwrap();

    let config = write_config(
        &dir,
        &format!(
            "trust_root_path = {:?}\nroot_ca_self_test_token_path = {:?}\n",
            trust_path, token_path
        ),
    );

    let lines = run_until_marker(
        &config,
        "root CA self-test: token verified after CA registration",
    );
    let joined = strip_ansi(&lines.join("\n"));
    assert!(
        joined.contains("root CA self-test: token rejected before CA registration"),
        "the token must fail before CA registration:\n{joined}"
    );
    assert!(
        joined.contains("trust root installed with rollback protection"),
        "trust root must be installed under the counter:\n{joined}"
    );
    assert!(
        joined.contains("k=1"),
        "k=1 must emit the startup diagnostic warning:\n{joined}"
    );
    assert!(
        joined.contains(&format!("version={}", 2)),
        "installed version must be logged:\n{joined}"
    );

    assert_eq!(
        counter_row(&dir.join("primary.db"), "trust_root_version"),
        Some(2),
        "the trust-root version must be committed to monotonic_counters"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn trust_root_version_rollback_is_rejected_at_boot() {
    let dir = temp_dir("rollback");
    let (root_seed, _) = keypair::generate_keypair().unwrap();
    let root_key = InMemoryKeyProvider::from_seed(root_seed);
    let trust_path = dir.join("trust-root.json");

    let v2 = trust_root(2, &root_key, BTreeMap::new());
    std::fs::write(&trust_path, serde_json::to_string(&v2).unwrap()).unwrap();
    let config = write_config(&dir, &format!("trust_root_path = {:?}\n", trust_path));
    run_until_marker(&config, "trust root installed with rollback protection");
    assert_eq!(
        counter_row(&dir.join("primary.db"), "trust_root_version"),
        Some(2)
    );

    // Restore an older root record, as an attacker with filesystem access would.
    let v1 = trust_root(1, &root_key, BTreeMap::new());
    std::fs::write(&trust_path, serde_json::to_string(&v1).unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_tirbase-gateway"))
        .arg(&config)
        .env("RUST_LOG", "info")
        .output()
        .expect("run gateway");
    let joined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.status.success(),
        "a rolled-back trust root must stop the boot:\n{joined}"
    );
    assert!(
        joined.contains("trust root rollback rejected"),
        "rollback must be reported:\n{joined}"
    );
    assert_eq!(
        counter_row(&dir.join("primary.db"), "trust_root_version"),
        Some(2),
        "a rejected rollback must not move the committed version"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn signed_epoch_bump_is_applied_and_persisted() {
    let dir = temp_dir("epoch-bump");
    let (root_seed, _) = keypair::generate_keypair().unwrap();
    let root_key = InMemoryKeyProvider::from_seed(root_seed);
    let pa = InMemoryKeyProvider::generate().unwrap();
    let rm = InMemoryKeyProvider::generate().unwrap();

    let mut roles = BTreeMap::new();
    roles.insert(
        CommandRole::PolicyAuthority,
        RolePolicy::new(1, vec![role_signer(&pa)]),
    );
    roles.insert(
        CommandRole::RevocationManager,
        RolePolicy::new(1, vec![role_signer(&rm)]),
    );
    let record = trust_root(1, &root_key, roles);
    let trust_path = dir.join("trust-root.json");
    std::fs::write(&trust_path, serde_json::to_string(&record).unwrap()).unwrap();

    // Simulate an already-enrolled device with an epoch-0 row.
    let db = dir.join("primary.db");
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS device_epoch (
                 device_id TEXT PRIMARY KEY,
                 epoch INTEGER NOT NULL DEFAULT 0,
                 bumped_at_est INTEGER NOT NULL,
                 co_sig_pa BLOB,
                 co_sig_rm BLOB
             );
             INSERT INTO device_epoch (device_id, epoch, bumped_at_est)
                 VALUES ('did:key:zRestored', 0, 100);",
        )
        .unwrap();
    }

    let payload = EpochBump {
        device_id: "did:key:zRestored".to_string(),
        previous_epoch: 0,
        new_epoch: 1,
        reason: "snapshot restore (S22)".to_string(),
    };
    let mut operation = SignedOperation::new(&payload, 1_000, None).unwrap();
    operation
        .sign_with(&pa, CommandRole::PolicyAuthority)
        .unwrap();
    operation
        .sign_with(&rm, CommandRole::RevocationManager)
        .unwrap();
    let bump_path = dir.join("epoch-bump.json");
    std::fs::write(
        &bump_path,
        serde_json::to_string(&serde_json::json!({
            "operation": operation,
            "payload": payload,
        }))
        .unwrap(),
    )
    .unwrap();

    let config = write_config(
        &dir,
        &format!(
            "trust_root_path = {:?}\nepoch_bump_path = {:?}\n",
            trust_path, bump_path
        ),
    );
    let lines = run_until_marker(&config, "signed epoch bump applied");
    let joined = strip_ansi(&lines.join("\n"));
    assert!(
        joined.contains("epoch=1"),
        "bump must log the new epoch: {joined}"
    );

    let conn = rusqlite::Connection::open(&db).unwrap();
    let (epoch, pa_sig, rm_sig): (i64, Option<Vec<u8>>, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT epoch, co_sig_pa, co_sig_rm FROM device_epoch WHERE device_id = ?1",
            ["did:key:zRestored"],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(epoch, 1, "the durable epoch row must be bumped");
    assert!(pa_sig.is_some(), "PolicyAuthority co-signature persisted");
    assert!(rm_sig.is_some(), "RevocationManager co-signature persisted");

    let _ = std::fs::remove_dir_all(&dir);
}
