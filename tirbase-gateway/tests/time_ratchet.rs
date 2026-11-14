// SPDX-License-Identifier: AGPL-3.0-only

//! Gateway-binary integration tests for (CLAIM-7.1…7.6, PV-22).
//!
//! Each test spawns the real `tirbase-gateway` binary with a temporary
//! `primary.db` and, where needed, a signed `TimeBeacon` envelope plus a
//! `TimeAnchor` trust file, then inspects stdout and the durable SQLite state.
//!
//! Covered:
//! * the gateway installs `SystemTimeSource` (CLOCK_BOOTTIME / CLOCK_REALTIME /
//! kernel boot id) for all time consumers (CLAIM-7.1);
//! * it creates and reads the `time_ratchet` table with the `beacon_boot_id`
//! column at boot (CLAIM-7.6);
//! * the ratchet's persisted floor survives a restart (CLAIM-7.2);
//! * a far-future beacon is rejected without the M-of-N anchor quorum, and
//! accepted with it (CLAIM-7.4, S23);
//! * authenticated-time expiry rejects an attestation after a simulated time
//! advance (CLAIM-7.3).

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_guard::signed_operation::SignedOperation;
use tirbase_guard::time::TimeBeacon;
use tirbase_types::CommandRole;

/// Boot-id override for both runs of a two-process test: the host may not expose
/// a kernel boot id (CI on macOS), and a process restart must not look like a
/// reboot here.
const SAME_BOOT: &str = "424242";

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);
static NEXT_BEACON: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let unique = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "tirbase-gateway-time-{tag}-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Write `gateway.toml`; `time_beacon_path` / `time_anchor_keys_path` are only
/// emitted when supplied.
fn write_config(dir: &Path, beacon: Option<&Path>, anchors: Option<&Path>) -> PathBuf {
    let mut body = format!(
        "key_path = {:?}\n\
         counter_db_path = {:?}\n\
         admin_socket = {:?}\n\
         health_addr = \"127.0.0.1:0\"\n\
         log_level = \"info\"\n\
         checkpoint_interval_secs = 3600\n\
         boot_attestation_ttl_secs = 300\n",
        dir.join("device-key.json"),
        dir.join("primary.db"),
        dir.join("admin.sock"),
    );
    if let Some(beacon) = beacon {
        body.push_str(&format!("time_beacon_path = {beacon:?}\n"));
    }
    if let Some(anchors) = anchors {
        body.push_str(&format!("time_anchor_keys_path = {anchors:?}\n"));
    }

    let config_path = dir.join("gateway.toml");
    std::fs::write(&config_path, body).expect("write config");
    config_path
}

fn spawn_gateway(config: &Path, env: &[(&str, &str)]) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tirbase-gateway"));
    command
        .arg(config)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }
    command.spawn().expect("spawn gateway")
}

fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&n) = chars.peek() {
                    chars.next();
                    if n.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Spawn the gateway and collect stdout lines until `needle` appears; the child
/// is killed before returning.
fn run_until_marker(config: &Path, env: &[(&str, &str)], needle: &str) -> Vec<String> {
    let mut child = spawn_gateway(config, env);
    let stdout = child.stdout.take().expect("child stdout");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(line) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut lines = Vec::new();
 // Use the workspace TimeSource (PV-3.12) rather than a direct clock call.
    let deadline_us = tirbase_core::traits::monotonic_now() + 30_000_000;
    let found = loop {
        if tirbase_core::traits::monotonic_now() >= deadline_us {
            break false;
        }
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(line) => {
                let hit = line.contains(needle);
                lines.push(line);
                if hit {
                    break true;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break false,
        }
    };

    kill(&mut child);
    assert!(
        found,
        "gateway did not log marker {needle:?} before timeout; output:\n{}",
        lines.join("\n")
    );
    lines
}

/// Run the gateway until it exits on its own; returns (success, stdout+stderr).
fn run_expect_exit(config: &Path, env: &[(&str, &str)]) -> (bool, String) {
    let mut child = spawn_gateway(config, env);
    let deadline_us = tirbase_core::traits::monotonic_now() + 30_000_000;
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break Some(status);
        }
        if tirbase_core::traits::monotonic_now() >= deadline_us {
            break None;
        }
        thread::sleep(Duration::from_millis(20));
    };
    let exited = status.is_some();
    if !exited {
        kill(&mut child);
    }

    let mut output = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut output);
    }
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut output);
    }

    (
        status.map(|status| status.success()).unwrap_or(false),
        output,
    )
}

/// Build a signed beacon envelope and a trust file with `anchor_count` anchors.
fn write_beacon(dir: &Path, wall_time_secs: i64, anchor_count: usize) -> (PathBuf, PathBuf) {
    let unique = NEXT_BEACON.fetch_add(1, Ordering::Relaxed);
    let providers: Vec<InMemoryKeyProvider> = (0..anchor_count.max(1))
        .map(|_| InMemoryKeyProvider::generate().expect("anchor key"))
        .collect();

    let beacon = TimeBeacon {
        wall_time_secs,
        issuer_did: providers[0].did().to_string(),
        mono_seq: 1,
        valid_for_secs: 300,
    };
    let mut operation =
        SignedOperation::<TimeBeacon>::new(&beacon, wall_time_secs, None).expect("wrap beacon");
    for provider in &providers {
        operation
            .sign_with(provider, CommandRole::TimeAnchor)
            .expect("sign beacon");
    }

    let beacon_path = dir.join(format!("beacon-{unique}.json"));
    std::fs::write(
        &beacon_path,
        serde_json::to_string_pretty(&serde_json::json!({
            "beacon": beacon,
            "signed_operation": operation,
        }))
        .expect("serialise envelope"),
    )
    .expect("write beacon");

    let anchors: Vec<serde_json::Value> = providers
        .iter()
        .map(|provider| {
            serde_json::json!({
                "did": provider.did(),
                "public_key_hex": hex::encode(provider.public_key_bytes()),
            })
        })
        .collect();
    let anchors_path = dir.join(format!("anchors-{unique}.json"));
    std::fs::write(
        &anchors_path,
        serde_json::to_string_pretty(&serde_json::json!({ "anchors": anchors }))
            .expect("serialise anchors"),
    )
    .expect("write anchors");

    (beacon_path, anchors_path)
}

fn ratchet_column_names(db: &Path) -> Vec<String> {
    let conn = rusqlite::Connection::open(db).expect("open primary.db");
    let mut stmt = conn
        .prepare("PRAGMA table_info(time_ratchet)")
        .expect("table_info");
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .expect("query columns")
        .map(Result::unwrap)
        .collect();
    columns
}

fn ratchet_row_count(db: &Path) -> i64 {
    let conn = rusqlite::Connection::open(db).expect("open primary.db");
    conn.query_row("SELECT COUNT(*) FROM time_ratchet", [], |row| row.get(0))
        .expect("count ratchet rows")
}

fn ratchet_floor(db: &Path) -> i64 {
    let conn = rusqlite::Connection::open(db).expect("open primary.db");
    conn.query_row(
        "SELECT persisted_floor FROM time_ratchet WHERE id = 1",
        [],
        |row| row.get(0),
    )
    .expect("persisted floor")
}

#[test]
fn gateway_boots_with_system_time_source_boottime_realtime_and_boot_id() {
    let dir = temp_dir("time-source");
    let config = write_config(&dir, None, None);

    let lines = run_until_marker(&config, &[("TIRBASE_BOOT_ID", "31")], "TimeRatchet loaded");

    let time_source_line = lines
        .iter()
        .map(|l| strip_ansi(l))
        .find(|line| line.contains("TimeSource installed"))
        .unwrap_or_else(|| panic!("no TimeSource boot diagnostic: {lines:?}"));
    assert!(
        time_source_line.contains("boot_id=31"),
        "boot_id must come from the installed source: {time_source_line}"
    );
    assert!(
        time_source_line.contains("monotonic_now_us="),
        "monotonic_now must be read from the installed source: {time_source_line}"
    );
    let mono_tail = time_source_line
        .split("monotonic_now_us=")
        .nth(1)
        .unwrap_or("");
    let mono_first = mono_tail.trim_start_matches('"').chars().next();
    assert!(
        mono_first.map(|c| c.is_ascii_digit()).unwrap_or(false),
        "monotonic_now_us must be numeric: {time_source_line}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gateway_creates_time_ratchet_table_with_beacon_boot_id_at_boot() {
    let dir = temp_dir("schema");
    let config = write_config(&dir, None, None);

    let lines = run_until_marker(
        &config,
        &[("TIRBASE_BOOT_ID", SAME_BOOT)],
        "TimeRatchet loaded",
    );

    let joined = lines
        .iter()
        .map(|l| strip_ansi(l))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("Unverified"),
        "a device with no beacon must report Unverified freshness: {lines:?}"
    );

    let db = dir.join("primary.db");
    assert_eq!(
        ratchet_column_names(&db),
        vec![
            "id",
            "last_beacon_time",
            "mono_at_beacon",
            "beacon_boot_id",
            "persisted_floor",
            "updated_at_mono",
        ],
        "time_ratchet must be created with the documented columns (CLAIM-7.6)"
    );
    assert_eq!(
        ratchet_row_count(&db),
        0,
        "no ratchet row exists before the first accepted beacon"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gateway_persists_and_reloads_ratchet_across_restarts() {
    let dir = temp_dir("persistence");
    let wall_time = 1_800_000_000i64;
    let (beacon, anchors) = write_beacon(&dir, wall_time, 2);

    let first_config = write_config(&dir, Some(&beacon), Some(&anchors));
    let first_run = run_until_marker(
        &first_config,
        &[("TIRBASE_BOOT_ID", SAME_BOOT)],
        "Beacon accepted",
    );
    let first_joined = first_run
        .iter()
        .map(|l| strip_ansi(l))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        first_joined.contains(&format!("new_floor={wall_time}")),
        "the accepted beacon must advance the floor to {wall_time}: {first_run:?}"
    );

    let db = dir.join("primary.db");
    assert_eq!(
        ratchet_floor(&db),
        wall_time,
        "the ratchet must be persisted to primary.db (CLAIM-7.2)"
    );

 // Restart without a beacon: the floor must be reloaded and now_est floored at it.
    let second_config = write_config(&dir, None, None);
    let second_run = run_until_marker(
        &second_config,
        &[("TIRBASE_BOOT_ID", SAME_BOOT)],
        "TimeRatchet loaded",
    );
    let second_joined = second_run
        .iter()
        .map(|l| strip_ansi(l))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        second_joined.contains(&format!("persisted_floor={wall_time}")),
        "the restarted gateway must reload the ratchet's persisted floor: {second_run:?}"
    );
    let loaded_line = second_run
        .iter()
        .map(|l| strip_ansi(l))
        .find(|line| line.contains("TimeRatchet loaded"))
        .expect("load line");
    let now_est: i64 = loaded_line
        .split("now_est=")
        .nth(1)
        .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit() && c != '-').next())
        .and_then(|value| value.parse().ok())
        .expect("now_est field");
    assert!(
        now_est >= wall_time,
        "now_est must never fall below the persisted floor: {loaded_line}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn far_future_beacon_is_rejected() {
    let dir = temp_dir("far-future");
    let base = 1_800_000_000i64;
 // Establish a baseline floor with the required M-of-N quorum.
    let (bootstrap_beacon, bootstrap_anchors) = write_beacon(&dir, base, 2);
    let bootstrap_config = write_config(&dir, Some(&bootstrap_beacon), Some(&bootstrap_anchors));
    run_until_marker(
        &bootstrap_config,
        &[("TIRBASE_BOOT_ID", SAME_BOOT)],
        "Beacon accepted",
    );

 // One anchor only for a jump beyond max_forward_jump_secs: below M = 2.
    let far_future = base + 86_401;
    let (beacon, anchors) = write_beacon(&dir, far_future, 1);
    let config = write_config(&dir, Some(&beacon), Some(&anchors));

    let lines = run_until_marker(
        &config,
        &[("TIRBASE_BOOT_ID", SAME_BOOT)],
        "Beacon rejected",
    );

    let rejection = lines
        .iter()
        .map(|l| strip_ansi(l))
        .find(|line| line.contains("Beacon rejected"))
        .expect("rejection line");
    assert!(
        rejection.contains("86401") && rejection.contains("max_forward_jump_secs"),
        "the rejection must cite the jump and the limit (S23): {rejection}"
    );
    assert!(
        rejection.contains("1 of 2"),
        "the rejection must cite the unmet M-of-N quorum: {rejection}"
    );

    let db = dir.join("primary.db");
    assert_eq!(
        ratchet_floor(&db),
        base,
        "a rejected far-future beacon must not advance the persisted floor"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn far_future_beacon_with_anchor_quorum_is_accepted() {
    let dir = temp_dir("far-future-quorum");
    let far_future = 1_800_000_000i64 + 86_401;
    let (beacon, anchors) = write_beacon(&dir, far_future, 2);
    let config = write_config(&dir, Some(&beacon), Some(&anchors));

    let lines = run_until_marker(
        &config,
        &[("TIRBASE_BOOT_ID", SAME_BOOT)],
        "Beacon accepted",
    );
    let joined = lines
        .iter()
        .map(|l| strip_ansi(l))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("anchor_signatures=2"),
        "the accepted large jump must carry two TimeAnchor signatures: {lines:?}"
    );
    assert_eq!(ratchet_floor(&dir.join("primary.db")), far_future);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn expired_boot_attestation_is_rejected_after_simulated_time_advance() {
    let dir = temp_dir("expiry");
    let wall_time = 1_800_000_000i64;
    let (beacon, anchors) = write_beacon(&dir, wall_time, 2);

 // Establish the ratchet floor from a real beacon (M-of-N quorum).
    let first_config = write_config(&dir, Some(&beacon), Some(&anchors));
    run_until_marker(
        &first_config,
        &[("TIRBASE_BOOT_ID", SAME_BOOT)],
        "Beacon accepted",
    );

 // Restart with a 1,000-second simulated advance: now_est passes the
 // attestation's authenticated-time expiry (floor + 300 s), so the gateway
 // must refuse to attest the boot. This is Stage-9 expiry semantics driven
 // by now_est (CLAIM-7.3, S19).
    let second_config = write_config(&dir, None, None);
    let (success, output) = run_expect_exit(
        &second_config,
        &[
            ("TIRBASE_BOOT_ID", SAME_BOOT),
            ("TIRBASE_TIME_SIM_OFFSET_SECS", "1000"),
        ],
    );

    assert!(!success, "the gateway must fail closed: {output}");
    assert!(
        output.contains("boot attestation expired"),
        "the expiry must be evaluated against now_est: {output}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
