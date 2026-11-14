// SPDX-License-Identifier: AGPL-3.0-only

//! WAL PASSIVE checkpoint cadence (CLAIM-32.4, PV-9). Runs `PRAGMA
//! wal_checkpoint(PASSIVE)` every 60 seconds and configures `PRAGMA
//! wal_autocheckpoint=1000` so SQLite auto-checkpoints around 1000 WAL frames.
//! Production caller: background task in `tirbase-gateway/src/main.rs`.
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const WAL_AUTOCHECKPOINT_FRAMES: i64 = 1000;
pub const WAL_PASSIVE_INTERVAL_SECS: u64 = 60;

pub fn configure_wal_autocheckpoint(conn: &Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "wal_autocheckpoint", WAL_AUTOCHECKPOINT_FRAMES)?;
    Ok(())
}

/// Run a PASSIVE checkpoint. Returns (busy, log_frames, checkpointed_frames).
pub fn passive_checkpoint(conn: &Connection) -> rusqlite::Result<(i64, i64, i64)> {
    conn.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })
}

fn checkpoint_path(path: &Path) -> Result<(i64, i64, i64), String> {
    let conn = Connection::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let _ = configure_wal_autocheckpoint(&conn);
    passive_checkpoint(&conn).map_err(|e| format!("passive checkpoint {}: {e}", path.display()))
}

/// Spawn background PASSIVE checkpoint tasks for primary and derived DBs.
// STATE-INVENTORY: RECONSTRUCTIBLE wal checkpoint cadence (CLAIM-32.4, PV-9)
pub fn spawn_wal_checkpoint_loop(
    primary: PathBuf,
    derived: PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(WAL_PASSIVE_INTERVAL_SECS));
        loop {
            ticker.tick().await;
            let p = primary.clone();
            let d = derived.clone();
            let res = tokio::task::spawn_blocking(move || {
                let pr = checkpoint_path(&p);
                let dr = checkpoint_path(&d);
                (pr, dr)
            })
            .await;
            match res {
                Ok((Ok(p), Ok(d))) => tracing::debug!(
                    primary_busy = p.0,
                    primary_log = p.1,
                    derived_busy = d.0,
                    derived_log = d.1,
                    "PASSIVE WAL checkpoint cycle (CLAIM-32.4)"
                ),
                Ok((p, d)) => tracing::warn!(?p, ?d, "PASSIVE WAL checkpoint cycle had errors"),
                Err(e) => tracing::warn!(%e, "PASSIVE WAL checkpoint task join failed"),
            }
        }
    })
}
