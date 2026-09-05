//! Subphase 7.3 — Process-crash-mid-write recovery test.
//!
//! Acceptance criteria:
//! 1. A process is killed between `BEGIN` and `COMMIT` of the SQLite write
//!    path (`LocalStore::write`).
//! 2. On restart, no corrupted state is present.
//!
//! # Strategy
//!
//! The test spawns the `crash_writer` helper binary (declared as a
//! `[[bin]]` target in Cargo.toml, `required-features = ["native"]`).  The
//! child opens a SQLite DB, writes one fully-committed baseline row, then
//! begins a transaction, inserts a *partial* row, and calls
//! `std::process::abort()` — simulating a hard process kill between `BEGIN`
//! and `COMMIT` (no `ROLLBACK`, no graceful shutdown, WAL left dirty).  The
//! child writes a marker file so the parent can confirm the crash point was
//! reached.
//!
//! After the child aborts, the parent reopens the DB through the *production*
//! store-open path — `LocalStore::open` → `sqlite::open` — which now runs
//! crash recovery (`PRAGMA wal_checkpoint(TRUNCATE)` + `PRAGMA
//! integrity_check`) on startup.  The test then reads back every row and
//! asserts:
//!   - `integrity_check` reports `ok` (no corruption),
//!   - the baseline row is intact (committed-before-crash survives),
//!   - the partial row inserted inside the uncommitted transaction is **not**
//!     present (SQLite rolled it back during WAL replay),
//!   - the projection table contains exactly the one surviving committed row
//!     with a clean `contaminated` flag (no half-applied projection metadata).
//!
//! ## Production caller
//!
//! The recovery path exercised here is [`crate::store::sqlite::open`] (which
//! runs `PRAGMA wal_checkpoint(TRUNCATE)` + `PRAGMA integrity_check`),
//! reached from [`LocalStore::open`](crate::store::LocalStore::open), which
//! is called by [`CoreHandle::init`](crate::api::CoreHandle::init) on every
//! startup — this is the stated production caller that reaches the new
//! recovery code.  The `check_integrity` method on `LocalStore` (the same
//! recovery step invoked from `init`) is covered by the in-crate unit tests
//! in `store/mod.rs` for the `pub(crate)` path.

#![cfg(feature = "native")]

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

use tirbase_core::store::sqlite;
use tirbase_core::store::LocalStore;

/// A unique temp path for this test run.
fn tmp_db_path(suffix: &str) -> PathBuf {
    let mut p = env::temp_dir();
    p.push(format!("tirbase_crash_recovery_{suffix}.db"));
    p
}

/// Remove a DB file and its WAL/SHM sidecars.
fn cleanup_db(path: &PathBuf) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(format!("{}-wal", path.display()));
    let _ = fs::remove_file(format!("{}-shm", path.display()));
}

/// Locate the `crash_writer` binary built alongside this crate.
///
/// `CARGO_BIN_EXE_crash_writer` is set by the test harness for any
/// `[[bin]]` target in the package, so the child binary is found without
/// hardcoding a path.
fn crash_writer_exe() -> PathBuf {
    let exe = env::var_os("CARGO_BIN_EXE_crash_writer")
        .map(PathBuf::from)
        .expect("CARGO_BIN_EXE_crash_writer must be set by the cargo test harness");
    assert!(
        exe.exists(),
        "crash_writer binary not found at {} — is the `native` feature enabled?",
        exe.display()
    );
    exe
}

#[tokio::test]
async fn process_crash_mid_write_leaves_no_corrupted_state() {
    let db_path = tmp_db_path("process_crash");
    let marker_path = tmp_db_path("process_crash.marker");
    cleanup_db(&db_path);
    let _ = fs::remove_file(&marker_path);

    // ── 1. Spawn the child that crashes between BEGIN and COMMIT ─────────────
    let exe = crash_writer_exe();
    let child = Command::new(&exe)
        .arg(&db_path)
        .arg(&marker_path)
        .output()
        .expect("spawn crash_writer child");

    // The child must have been killed by the signal we raised (abort =>
    // SIGABRT).  On Unix `signal: 6` means SIGABRT; the child must NOT exit
    // cleanly (status 0).
    #[cfg(unix)]
    {
        assert!(
            child.status.signal() == Some(6),
            "child must have been killed by SIGABRT (abort); status={:?} signal={:?} stderr={}",
            child.status,
            child.status.signal(),
            String::from_utf8_lossy(&child.stderr),
        );
    }
    #[cfg(not(unix))]
    {
        assert!(
            !child.status.success(),
            "child must not exit cleanly: {:?}",
            child.status
        );
    }

    // The marker must show we reached the exact crash point.
    let marker = fs::read_to_string(&marker_path).expect("marker file must exist after crash");
    assert_eq!(
        marker.trim(),
        "crashed_between_begin_and_commit",
        "child must have crashed after BEGIN but before COMMIT (marker was: {marker})",
    );

    // ── 2. Reopen via the production path — LocalStore::open runs recovery ────
    // `LocalStore::open` → `sqlite::open` → WAL checkpoint + integrity_check.
    // This is the production startup path (api/mod.rs CoreHandle::init calls
    // LocalStore::open, which calls sqlite::open that now runs recovery).
    let store = LocalStore::open(db_path.to_str().expect("db path is utf8"))
        .expect("LocalStore::open must succeed after a mid-write crash");

    // 3a. `LocalStore::open` already ran WAL recovery + integrity_check (via
    //     `sqlite::open`) during the call above; a successful open means the
    //     post-crash DB passed `PRAGMA integrity_check`.  The remaining
    //     assertions read back the rows to confirm no partial state survived.

    // 3b. Baseline row (committed before the crash) must survive intact.
    let baseline = store.read("test_table", "baseline").expect("read baseline");
    assert_eq!(
        baseline.expect("baseline row must survive the crash"),
        serde_json::json!({"v": "committed-before-crash"}),
        "the pre-crash committed row must be intact after recovery",
    );

    // 3c. The partial row inserted inside the uncommitted transaction must NOT
    //     exist — SQLite rolled it back during WAL replay.
    let partial = store.read("test_table", "partial-after-begin");
    match &partial {
        Ok(None) => { /* expected: rolled back */ }
        Ok(Some(v)) => panic!(
            "partial row from the uncommitted transaction must not survive \
             the crash — got: {v}"
        ),
        Err(e) => panic!("reading partial row errored: {e}"),
    }

    // 3d. The projection table must contain exactly the one committed row —
    //     no half-applied projection metadata (contaminated flag left dirty,
    //     a stray row, etc.).
    {
        let conn = sqlite::open(db_path.to_str().expect("db path is utf8"))
            .expect("re-open for row count");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("final checkpoint");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM proj_test_table;", [], |row| {
                row.get(0)
            })
            .expect("count rows");
        assert_eq!(
            count, 1,
            "exactly the one committed row must remain after a mid-write crash; got {count}"
        );

        let contaminated: i64 = conn
            .query_row(
                "SELECT contaminated FROM proj_test_table WHERE key = 'baseline';",
                [],
                |row| row.get(0),
            )
            .expect("read contaminated flag");
        assert_eq!(
            contaminated, 0,
            "the surviving row's contaminated flag must be 0 after recovery"
        );
    }

    cleanup_db(&db_path);
    let _ = fs::remove_file(&marker_path);
}
