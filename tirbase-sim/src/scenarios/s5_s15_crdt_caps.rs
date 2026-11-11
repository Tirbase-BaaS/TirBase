//! Scenarios S5 and S15 — delta flood / rate exhaustion and reassembly bomb.
//!
//! Both scenarios call the production `InboundHardening::cheap_checks_first`
//! gate.  S5 proves the per-sender rate rejection quarantines the attacker while
//! another sender continues to be processed.  S15 proves an oversized payload is
//! rejected by the size cap before any Automerge parsing.

use tirbase_core::crdt::delta::{Delta, Ed25519Signature, PriorityClass};
use tirbase_core::crdt::derive_did_from_public_key;
use tirbase_core::crdt::{CheapCheckStage, InboundGate};
use tirbase_core::events::ReasonCode;
use tirbase_core::identity::keypair::generate_keypair;

fn delta(author_did: String, shell_bytes: usize) -> Delta {
    Delta {
        id: [1u8; 32],
        author_did,
        signature: Ed25519Signature::default(),
        schema_hash: [0u8; 32],
        automerge_bytes: vec![0u8; shell_bytes],
        priority: PriorityClass::Low,
        causal_parents: vec![],
        tags: vec![],
        lamport: 1,
        created_at: 0,
    }
}

fn dids() -> (String, String) {
    let (_, attacker_public) = generate_keypair().expect("attacker keypair");
    let (_, victim_public) = generate_keypair().expect("victim keypair");
    (
        derive_did_from_public_key(&attacker_public),
        derive_did_from_public_key(&victim_public),
    )
}

/// S5 — a flood beyond the per-sender rate cap is quarantined as
/// `RateExceeded`, and an unrelated sender is not starved.
pub fn run_s5(seed: u64) -> Result<(), String> {
    let (attacker, victim) = dids();
    let mut hardening = InboundGate::new();
    let max_bytes = 1024 * 1024;
    let max_ops = 1_000;

    let flood_rounds = 2 + (seed % 4) as usize;
    for round in 0..flood_rounds {
        let attack = delta(attacker.clone(), 64 + round);
        match hardening.cheap_checks_first(
            &attack,
            tirbase_core::crdt::CheapCheckLimits {
                rate_exceeded: true, // production caller's per-sender bucket is exhausted
                max_bytes,
                max_ops,
                missing_dependency: false,
            },
            1_000 + round as u64,
            1_700_000_000,
        ) {
            Err(rejection)
                if rejection.stage == CheapCheckStage::RateLimit
                    && rejection.reason == ReasonCode::RateExceeded => {}
            Ok(()) => {
                return Err(format!(
                    "S5 FAIL: over-rate delta from {attacker} was admitted in round {round}"
                ))
            }
            Err(other) => {
                return Err(format!(
                    "S5 FAIL: wrong rejection stage {:?} reason {:?}",
                    other.stage, other.reason
                ))
            }
        }
    }
    if hardening.rate_sender_rejections(&attacker) < flood_rounds as u32 {
        return Err("S5 FAIL: rate quarantine did not record the attacker".to_string());
    }

    // An honest sender with an in-budget delta must still pass the same gate.
    let honest = delta(victim.clone(), 64);
    hardening
        .cheap_checks_first(
            &honest,
            tirbase_core::crdt::CheapCheckLimits {
                rate_exceeded: false,
                max_bytes,
                max_ops,
                missing_dependency: false,
            },
            2_000,
            1_700_000_001,
        )
        .map_err(|rejection| {
            format!(
                "S5 FAIL: honest sender was starved by attacker flood: {:?}",
                rejection.stage
            )
        })?;
    if hardening.rate_sender_rejections(&victim) != 0 {
        return Err("S5 FAIL: honest sender was quarantined".to_string());
    }
    Ok(())
}

/// S15 — a payload larger than the 1 MiB cap is rejected as `Oversize` before
/// decoding and is recorded in the rate-quarantine ledger.
pub fn run_s15(seed: u64) -> Result<(), String> {
    let (attacker, _) = dids();
    let mut hardening = InboundGate::new();
    let max_bytes = 1024 * 1024;
    let oversize = max_bytes + 1 + (seed as usize % 128);
    let bomb = delta(attacker.clone(), oversize);

    match hardening.cheap_checks_first(
        &bomb,
        tirbase_core::crdt::CheapCheckLimits {
            rate_exceeded: false,
            max_bytes,
            max_ops: 1_000,
            missing_dependency: false,
        },
        5_000,
        1_700_000_000,
    )
    {
        Err(rejection)
            if rejection.stage == CheapCheckStage::Size
                && rejection.reason == ReasonCode::Oversize => {}
        Ok(()) => {
            return Err(format!(
                "S15 FAIL: {oversize}-byte delta passed the {max_bytes}-byte cap"
            ))
        }
        Err(other) => {
            return Err(format!(
                "S15 FAIL: wrong stage {:?} reason {:?}",
                other.stage, other.reason
            ))
        }
    }
    if hardening.rate_sender_rejections(&attacker) == 0 {
        return Err("S15 FAIL: oversize rejection was not quarantined".to_string());
    }

    // A within-cap delta from the same sender is still accepted.
    let small = delta(attacker, 128);
    hardening
        .cheap_checks_first(
            &small,
            tirbase_core::crdt::CheapCheckLimits {
                rate_exceeded: false,
                max_bytes,
                max_ops: 1_000,
                missing_dependency: false,
            },
            5_001,
            1_700_000_001,
        )
        .map_err(|rejection| {
            format!(
                "S15 FAIL: within-cap delta rejected at {:?}",
                rejection.stage
            )
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s5_delta_flood_rate_limited() {
        run_s5(1).expect("S5");
    }

    #[test]
    fn s15_reassembly_bomb_rejected() {
        run_s15(1).expect("S15");
    }
}
