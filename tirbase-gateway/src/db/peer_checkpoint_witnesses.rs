//! `peer_checkpoint_witnesses` table helpers (CLAIM-26.5, PV-7.10).
//! Production caller: `tirbase-gateway/src/security_log.rs` checkpoint/tail-truncation.

use rusqlite::{params, Connection, OptionalExtension};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCheckpointWitness {
    pub peer_did: String,
    pub seq: u64,
    pub checkpoint_hash: [u8; 32],
    pub observed_at: i64,
}

pub fn upsert_peer_checkpoint_witness(
    conn: &Connection,
    peer_did: &str,
    seq: u64,
    checkpoint_hash: &[u8; 32],
    observed_at: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO peer_checkpoint_witnesses(peer_did, seq, checkpoint_hash, observed_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(peer_did) DO UPDATE SET
           seq=excluded.seq,
           checkpoint_hash=excluded.checkpoint_hash,
           observed_at=excluded.observed_at",
        params![
            peer_did,
            seq as i64,
            checkpoint_hash.as_slice(),
            observed_at
        ],
    )?;
    Ok(())
}

pub fn get_peer_checkpoint_witness(
    conn: &Connection,
    peer_did: &str,
) -> rusqlite::Result<Option<PeerCheckpointWitness>> {
    conn.query_row(
        "SELECT peer_did, seq, checkpoint_hash, observed_at FROM peer_checkpoint_witnesses WHERE peer_did=?1",
        params![peer_did],
        |r| {
            let hash_blob: Vec<u8> = r.get(2)?;
            let mut hash = [0u8; 32];
            if hash_blob.len() == 32 {
                hash.copy_from_slice(&hash_blob);
            }
            Ok(PeerCheckpointWitness {
                peer_did: r.get(0)?,
                seq: r.get::<_, i64>(1)? as u64,
                checkpoint_hash: hash,
                observed_at: r.get(3)?,
            })
        },
    )
    .optional()
}

pub fn list_peer_checkpoint_witnesses(
    conn: &Connection,
) -> rusqlite::Result<Vec<PeerCheckpointWitness>> {
    let mut stmt = conn.prepare(
        "SELECT peer_did, seq, checkpoint_hash, observed_at FROM peer_checkpoint_witnesses ORDER BY peer_did ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        let hash_blob: Vec<u8> = r.get(2)?;
        let mut hash = [0u8; 32];
        if hash_blob.len() == 32 {
            hash.copy_from_slice(&hash_blob);
        }
        Ok(PeerCheckpointWitness {
            peer_did: r.get(0)?,
            seq: r.get::<_, i64>(1)? as u64,
            checkpoint_hash: hash,
            observed_at: r.get(3)?,
        })
    })?;
    rows.collect()
}

pub fn latest_local_checkpoint(conn: &Connection) -> rusqlite::Result<Option<(u64, [u8; 32])>> {
    conn.query_row(
        "SELECT seq, checkpoint_hash FROM security_events WHERE is_checkpoint=1 AND checkpoint_hash IS NOT NULL ORDER BY seq DESC LIMIT 1",
        [],
        |r| {
            let seq: i64 = r.get(0)?;
            let hash_blob: Vec<u8> = r.get(1)?;
            let mut hash = [0u8; 32];
            if hash_blob.len() == 32 {
                hash.copy_from_slice(&hash_blob);
            }
            Ok((seq as u64, hash))
        },
    )
    .optional()
}
