//! Scenario S25 (Quarantine flush attack, PV-6.7, CLAIM-23.5).
//!
//! An attacker floods structurally anomalous deltas. The Schema_Quarantine_Ledger
//! must enforce per-sender quotas so the attacker cannot flush a legitimate
//! sender's quarantined entries.

use tirbase_core::crdt::delta::{Delta, Ed25519Signature, PriorityClass};
use tirbase_core::crdt::schema_quarantine::{SchemaQuarantineLedger, SchemaQuarantineReason};

pub const S25_SEED: u64 = 0x00C1_0CC0_0000_0025;

fn mk(author: &str, n: u16) -> Delta {
    let mut id = [0u8; 32];
    id[0] = (n & 0xff) as u8;
    id[1] = (n >> 8) as u8;
    Delta {
        id,
        author_did: author.to_string(),
        signature: Ed25519Signature::default(),
        schema_hash: [0u8; 32],
        automerge_bytes: format!("{author}:{n}").into_bytes(),
        priority: PriorityClass::Low,
        causal_parents: vec![],
        tags: vec![],
        lamport: 1,
        created_at: 0,
    }
}

pub fn run_s25(seed: u64) -> Result<(), String> {
    let dir = std::env::temp_dir().join(format!(
        "tirbase_s25_{seed}_{}_{}.db",
        std::process::id(),
        tirbase_core::traits::monotonic_now()
    ));
    let mut l = SchemaQuarantineLedger::open(&dir).map_err(|e| format!("seed={seed} open: {e}"))?;

    let victim = mk("did:key:victim", 9999);
    l.quarantine_delta(&victim, SchemaQuarantineReason::ClockJump, "victim")
        .map_err(|e| format!("seed={seed} victim: {e}"))?;

    let rounds = 1200u16 + ((seed % 50) as u16);
    for i in 0..rounds {
        let atk = mk("did:key:attacker", i);
        l.quarantine_delta(&atk, SchemaQuarantineReason::ClockJump, "attacker")
            .map_err(|e| format!("seed={seed} atk {i}: {e}"))?;
    }

    if !l
        .has_sender("did:key:victim")
        .map_err(|e| format!("seed={seed} has_sender: {e}"))?
    {
        return Err(format!(
            "seed={seed} S25 FAIL: attacker flushed victim quarantine entry"
        ));
    }
    let atk_n = l
        .count_for_sender("did:key:attacker")
        .map_err(|e| format!("seed={seed} count: {e}"))?;
    if atk_n > 1000 {
        return Err(format!(
            "seed={seed} S25 FAIL: attacker exceeded per-sender quota: {atk_n}"
        ));
    }
    let _ = std::fs::remove_file(&dir);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s25_quarantine_flush_per_sender_isolation() {
        if let Err(e) = run_s25(S25_SEED) {
            panic!("S25 failed (seed={S25_SEED}): {e}");
        }
    }

    #[test]
    fn s25_quarantine_flush_seeded_sweep() {
        for seed in 0u64..8 {
            let s = S25_SEED.wrapping_add(seed);
            if let Err(e) = run_s25(s) {
                panic!("S25 failed (seed={s}): {e}");
            }
        }
    }
}
