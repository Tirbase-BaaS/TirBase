// SPDX-License-Identifier: AGPL-3.0-only

//! Guard latency and effects-ledger throughput benchmarks (CLAIM-40.3, PV-15.3).
//! Criterion provides portable benchmark definitions; iai-callgrind provides
//! instruction-count gating on CI (not wall-clock).

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};

fn temp_dir(name: &str) -> std::path::PathBuf {
    let nanos = tirbase_core::traits::monotonic_now();
    let p = std::env::temp_dir().join(format!("tb-bench-{name}-{nanos}-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn make_profile() -> tirbase_types::envelope::EnvelopeProfile {
    use tirbase_types::envelope::{EnvelopeProfile, ParameterKind, ParameterSpec};
    use tirbase_types::{DeviceSignature, FixedPointValue};
    EnvelopeProfile {
        profile_id: [0u8; 16],
        version: 1,
        device_class: "cold_room".to_string(),
        parameters: vec![ParameterSpec {
            name: "temp".to_string(),
            unit_id: 1,
            canonical_exponent: -1,
            kind: ParameterKind::Range {
                min: FixedPointValue {
                    mantissa: -400,
                    exponent: -1,
                    unit_id: 1,
                },
                max: FixedPointValue {
                    mantissa: 300,
                    exponent: -1,
                    unit_id: 1,
                },
            },
            max_rate_per_sec: FixedPointValue {
                mantissa: 10,
                exponent: -1,
                unit_id: 1,
            },
            dwell_secs: 0,
            min_off_secs: 0,
            drift_window_secs: 60,
            max_delta_in_window: FixedPointValue {
                mantissa: 50,
                exponent: -1,
                unit_id: 1,
            },
            safe_default: FixedPointValue {
                mantissa: 40,
                exponent: -1,
                unit_id: 1,
            },
            tightening_floor: FixedPointValue {
                mantissa: -400,
                exponent: -1,
                unit_id: 1,
            },
            critical: false,
        }],
        cross_constraints: vec![],
        policy_loosen_m: 2,
        policy_loosen_n: 3,
        policy_timelock_secs: 60,
        policy_cancel_window_secs: 30,
        signature: DeviceSignature::Ed25519([0u8; 64]),
    }
}

fn bench_guard_decision(c: &mut Criterion) {
    c.bench_function("guard_decision_profile_signing_bytes", |b| {
        b.iter_batched(
            make_profile,
            |p| {
                let bytes = tirbase_guard::envelope::profile_signing_bytes(black_box(&p));
                black_box(bytes)
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_ed25519_verify(c: &mut Criterion) {
    use tirbase_core::identity::file_key_provider::FileKeyProvider;
    use tirbase_core::traits::KeyProvider;
    use tirbase_types::DeviceSignature;

    let dir = temp_dir("ed25519");
    let key_path = dir.join("id.json");
    let kp = FileKeyProvider::load_or_generate(&key_path).expect("keypair");
    let msg = b"tirbase-bench-message";
    let sig = kp.sign(msg).expect("sign");
    let pk = kp.public_key_bytes();
    c.bench_function("ed25519_signature_verify", |b| {
        b.iter(|| {
            if let DeviceSignature::Ed25519(bytes) = &sig {
                let sig = tirbase_core::crdt::delta::Ed25519Signature::from_bytes(*bytes);
                let res = tirbase_core::identity::keypair::verify(
                    pk.as_slice().try_into().unwrap(),
                    black_box(msg),
                    &sig,
                );
                black_box(res.is_ok())
            } else {
                false
            }
        })
    });
    let _ = std::fs::remove_dir_all(dir);
}

fn bench_effects_ledger_write(c: &mut Criterion) {
    c.bench_function("effects_ledger_write_sync_full", |b| {
        b.iter_batched(
            || {
                let dir = temp_dir("ledger-full");
                let db = dir.join("primary.db");
                let conn = rusqlite::Connection::open(&db).unwrap();
                conn.pragma_update(None, "journal_mode", "WAL").unwrap();
                conn.pragma_update(None, "synchronous", "FULL").unwrap();
                conn.execute_batch("CREATE TABLE IF NOT EXISTS t(id INTEGER PRIMARY KEY, v BLOB)")
                    .unwrap();
                (dir, conn)
            },
            |(dir, conn)| {
                conn.execute(
                    "INSERT INTO t(v) VALUES (?1)",
                    rusqlite::params![vec![0u8; 64]],
                )
                .unwrap();
                black_box(());
                drop(conn);
                let _ = std::fs::remove_dir_all(dir);
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("effects_ledger_write_sync_normal_group_commit", |b| {
        b.iter_batched(
            || {
                let dir = temp_dir("ledger-normal");
                let db = dir.join("primary.db");
                let conn = rusqlite::Connection::open(&db).unwrap();
                conn.pragma_update(None, "journal_mode", "WAL").unwrap();
                conn.pragma_update(None, "synchronous", "NORMAL").unwrap();
                conn.execute_batch("CREATE TABLE IF NOT EXISTS t(id INTEGER PRIMARY KEY, v BLOB)")
                    .unwrap();
                (dir, conn)
            },
            |(dir, conn)| {
                conn.execute(
                    "INSERT INTO t(v) VALUES (?1)",
                    rusqlite::params![vec![0u8; 64]],
                )
                .unwrap();
                black_box(());
                drop(conn);
                let _ = std::fs::remove_dir_all(dir);
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    guard_benches,
    bench_guard_decision,
    bench_ed25519_verify,
    bench_effects_ledger_write
);
criterion_main!(guard_benches);
