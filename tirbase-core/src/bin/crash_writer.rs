//! Subphase 7.3 — crash-writer helper binary.
//!
//! This binary is spawned by the integration test in
//! `tests/crash_recovery.rs`.  It opens a SQLite database at the path given
//! as `argv[1]`, creates a projection table, commits one *baseline* row
//! (transaction 1: `BEGIN` → `INSERT` → `COMMIT`), then begins a *second*
//! transaction, inserts a *partial* row, and immediately calls
//! `std::process::abort()` — simulating a hard process kill between `BEGIN`
//! and `COMMIT` with no `ROLLBACK` and a dirty WAL.
//!
//! The marker file path is `argv[2]`: it is written with the string
//! `crashed_between_begin_and_commit` after the partial INSERT succeeds and
//! before `abort()`, so the parent test can confirm the exact crash point was
//! reached.
//!
//! `Cargo.toml` declares this as a `[[bin]]` target named `crash_writer` with
//! `required-features = ["native"]`, so it is only built on the native target
//! (it links `rusqlite`).

use std::env;
use std::fs;
use std::io::Write;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("crash_writer: usage: crash_writer <db_path> <marker_path>");
        process::exit(2);
    }
    let db_path = &args[1];
    let marker_path = &args[2];

    // Write the marker *first* so the parent can detect the crash even if the
    // open fails.
    {
        let dir = std::path::Path::new(marker_path).parent().unwrap();
        fs::create_dir_all(dir).expect("create marker dir");
        let mut f = fs::File::create(marker_path).expect("create marker");
        writeln!(f, "started").expect("write marker");
        f.flush().ok();
    }

    // Open the DB exactly as production does — `sqlite::open` enables WAL mode,
    // foreign keys, runs schema creation, and (on the production path) the
    // crash-recovery checkpoint + integrity check.  The crash_writer opens a
    // fresh DB, so recovery is a no-op here; its job is to crash mid-write.
    let conn = tirbase_core::store::sqlite::open(db_path)
        .expect("crash_writer: sqlite::open must succeed on a fresh DB");

    // 1. Baseline committed row (transaction 1 — commits successfully).
    conn.execute_batch("BEGIN;")
        .expect("crash_writer: BEGIN baseline");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS proj_test_table \
         (key TEXT PRIMARY KEY, data_json TEXT NOT NULL, contaminated INTEGER NOT NULL DEFAULT 0);",
        [],
    )
    .expect("crash_writer: CREATE TABLE");
    conn.execute(
        "INSERT INTO proj_test_table (key, data_json, contaminated) \
         VALUES (?1, ?2, ?3);",
        rusqlite::params!["baseline", r#"{"v": "committed-before-crash"}"#, 0i64],
    )
    .expect("crash_writer: INSERT baseline");
    conn.execute_batch("COMMIT;")
        .expect("crash_writer: COMMIT baseline");

    // Mark that the baseline committed.
    {
        let mut f = fs::File::create(marker_path).expect("crash_writer: marker");
        writeln!(f, "baseline_committed").expect("crash_writer: marker");
        f.flush().ok();
    }

    // 2. Begin the crash transaction — BETWEEN BEGIN AND COMMIT we will die.
    conn.execute_batch("BEGIN;")
        .expect("crash_writer: BEGIN crash-tx");

    // The partial row: inserted but never committed.  After WAL recovery it
    // must be absent.
    conn.execute(
        "INSERT INTO proj_test_table (key, data_json, contaminated) \
         VALUES (?1, ?2, ?3);",
        rusqlite::params![
            "partial-after-begin",
            r#"{"v": "partial-uncommitted"}"#,
            0i64
        ],
    )
    .expect("crash_writer: INSERT partial");

    // Prove we reached the crash point (post-BEGIN, pre-COMMIT).
    {
        let mut f = fs::File::create(marker_path).expect("crash_writer: marker pre-crash");
        writeln!(f, "crashed_between_begin_and_commit").expect("crash_writer: marker");
        f.flush().ok();
    }

    // 3. Simulate a hard process kill: SIGABRT.  No ROLLBACK, no COMMIT,
    //    no graceful connection close — the WAL is left dirty so the next
    //    opener must replay it.
    eprintln!("crash_writer: aborting mid-transaction (between BEGIN and COMMIT)");
    process::abort();
}
