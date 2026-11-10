//! CRDT inbound hardening (PV-6.1, PV-6.2, PV-6.4 groundwork).
//!
//! Validates Automerge change metadata before merge so a peer cannot inject
//! inflated operation counters that win every LWW conflict (clock/start_op
//! poisoning, S4).
//!
//! ## start_op validation (PV-6.1)
//!
//! For each change in an incoming Automerge payload, the expected `start_op` is:
//!
//! ```text
//! expected = 1 + max(start_op(dep) + len(dep) - 1)   over all listed deps
//!          = 1                                           if deps is empty
//! ```
//!
//! i.e. one past the maximum operation ID covered by any causal dependency.
//! This is dependency-relative (not an absolute jump threshold) so long-offline
//! honest peers are never quarantined for legitimate history growth. A deviation
//! is a clock anomaly (`ClockJump`).
//!
//! Formula verified against Automerge 0.11 (`automerge` crate v0.11.0): a
//! change's `max_op()` is `start_op + len - 1` and its `deps()` are the causal
//! dependency `ChangeHash`es. The next change that depends on a set of heads
//! starts at `1 + max(max_op(head))` across those heads.
//!
//! If a causal dependency referenced by a change is not present in the local
//! Automerge document, the dependency's `(start_op, len)` cannot be resolved
//! here; the delta is reported as having a missing dependency so the caller can
//! route it to the pending queue (task 23 / PV-6.1). Task 22 wires the
//! `ClockJump` quarantine path for deviations; the pending-queue path is added
//! in task 23.

use std::collections::HashMap;

use crate::crdt::delta::Delta;
use crate::crdt::merge::QuarantineReason;
use crate::events::{emit_crdt, ReasonCode, Severity};

// Re-export inbound caps for convenience
use crate::crdt::inbound_caps::InboundRateLimiter;
pub use crate::crdt::inbound_caps::{
    InboundCapViolation, InboundCaps, INBOUND_CAP_BATCH_CHANGES, INBOUND_CAP_CONNECTIONS,
    INBOUND_CAP_DELTA_SIZE_BYTES, INBOUND_CAP_DEPS_PER_CHANGE, INBOUND_CAP_HEADS,
    INBOUND_CAP_OP_COUNT, INBOUND_CAP_RATE_BURST, INBOUND_CAP_RATE_OPS_PER_SEC,
    INBOUND_CAP_TRAVERSAL_BUDGET,
};

/// Result of [`validate_start_op`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StartOpValidation {
    /// All changes have dependency-consistent `start_op` values.
    Ok,
    /// A change's `start_op` deviates from the value implied by its causal
    /// dependencies (clock/start_op poisoning). The delta must be quarantined
    /// as `ClockJump`.
    ClockJump {
        /// Hex of the offending change hash, when available.
        change_hash: Option<String>,
        expected: u64,
        actual: u64,
    },
    /// A causal dependency could not be resolved in the local document or within
    /// the incoming change set, so `start_op` cannot be verified yet. The
    /// caller should treat this as a missing dependency (pending queue / task 23).
    /// Task 22 does not quarantine this as `ClockJump`.
    MissingDependency,
    /// The payload is not valid Automerge change data (empty or unparseable).
    /// Callers decide how to handle this; it is not a `ClockJump`.
    NotAutomerge,
}

/// Validate `start_op` for every change carried by `delta.automerge_bytes`
/// (PV-6.1, CLAIM-22.1).
///
/// `known_changes` supplies `(start_op, len)` for change hashes already present
/// in the local document so dependencies can be resolved without holding the
/// engine's `AutoCommit` lock across arbitrary work. Changes within the same
/// incoming payload may depend on earlier changes in that payload; those are
/// resolved from the payload itself.
///
/// Returns [`StartOpValidation::NotAutomerge`] for empty/unparseable payloads so
/// the existing merge path keeps its legacy behavior for JSON/test stubs.
pub(crate) fn validate_start_op(
    delta: &Delta,
    known_changes: &HashMap<automerge::ChangeHash, (u64, u64)>,
) -> StartOpValidation {
    if delta.automerge_bytes.is_empty() {
        return StartOpValidation::NotAutomerge;
    }

    // Parse the incoming bytes as Automerge changes. `AutoCommit::load` accepts a
    // full document save (possibly multiple concatenated changes); `get_changes`
    // yields the individual changes with their metadata (start_op, len, deps,
    // hash).
    let mut incoming_doc = match automerge::AutoCommit::load(&delta.automerge_bytes) {
        Ok(doc) => doc,
        Err(_) => return StartOpValidation::NotAutomerge,
    };
    let changes = incoming_doc.get_changes(&[]);
    if changes.is_empty() {
        return StartOpValidation::NotAutomerge;
    }

    // Index changes carried inside this payload so intra-payload dependencies
    // resolve (a batch may contain a chain).
    let mut payload_index: HashMap<automerge::ChangeHash, (u64, u64)> =
        HashMap::with_capacity(changes.len());
    for change in &changes {
        let start = change.start_op().get();
        let len = change.len() as u64;
        payload_index.insert(change.hash(), (start, len));
    }

    for change in &changes {
        let actual = change.start_op().get();
        let deps = change.deps();

        // expected = 1 + max(max_op(dep)) over deps, or 1 when there are no deps.
        let mut max_dep_op: Option<u64> = None;
        for dep_hash in deps {
            let (dep_start, dep_len) = if let Some(v) = payload_index.get(dep_hash) {
                *v
            } else if let Some(v) = known_changes.get(dep_hash) {
                *v
            } else {
                // Dependency not resolvable — cannot verify yet (task 23 pending
                // queue). Do not classify as ClockJump.
                return StartOpValidation::MissingDependency;
            };
            if dep_len == 0 {
                return StartOpValidation::MissingDependency;
            }
            let dep_max_op = dep_start.saturating_add(dep_len.saturating_sub(1));
            max_dep_op = Some(max_dep_op.map_or(dep_max_op, |m| m.max(dep_max_op)));
        }

        let expected = max_dep_op.map_or(1, |m| m.saturating_add(1));
        if actual != expected {
            return StartOpValidation::ClockJump {
                change_hash: Some(change.hash().to_string()),
                expected,
                actual,
            };
        }
    }

    StartOpValidation::Ok
}

/// Build the local change index `(start_op, len)` for all changes currently in
/// `doc`. Used by the inbound path to resolve causal dependencies during
/// `validate_start_op`.
pub(crate) fn known_change_index(
    doc: &mut automerge::AutoCommit,
) -> HashMap<automerge::ChangeHash, (u64, u64)> {
    let changes = doc.get_changes(&[]);
    let mut map = HashMap::with_capacity(changes.len());
    for change in changes {
        map.insert(
            change.hash(),
            (change.start_op().get(), change.len() as u64),
        );
    }
    map
}

/// Quarantine a delta for a `ClockJump` (inflated `start_op`) anomaly (PV-6.1).
///
/// Emits a typed `CrdtHardening/ClockJump` security event and returns the
/// `MergeOutcome::Quarantined` value the inbound path must surface. The
/// Schema_Quarantine_Ledger persistence is wired by task 23; task 22 guarantees
/// the quarantine decision + event on the production path.
pub(crate) fn quarantine_clock_jump(
    delta: &Delta,
    change_hash: Option<&str>,
    expected: u64,
    actual: u64,
) -> crate::crdt::merge::MergeOutcome {
    let delta_hex = hex::encode(delta.id);
    let detail = format!(
        "start_op clock anomaly (PV-6.1/S4): delta={} author={} change={} expected={} actual={}",
        delta_hex,
        delta.author_did,
        change_hash.unwrap_or("<unknown>"),
        expected,
        actual,
    );
    emit_crdt(
        Severity::High,
        ReasonCode::ClockJump,
        Some(delta_hex),
        detail,
    );
    crate::crdt::merge::MergeOutcome::Quarantined {
        reason: QuarantineReason::ClockJump,
    }
}

/// Inflate `start_op` for every change in an Automerge save payload by `offset`.
///
/// **Test-only (characterization/regression, PV-6.2, CLAIM-22.2/22.3).** This
/// produces a semantically hostile payload: the op IDs no longer match the
/// causal history, which is exactly the clock-poisoning attack `validate_start_op`
/// must reject. The inflated payload is *not* a valid honest Automerge history.
///
/// Implementation: decodes each change to an [`automerge::ExpandedChange`],
/// bumps `start_op`, and re-encodes. The change hash changes (it commits to the
/// change content), so callers must re-sign the TirBase `Delta` envelope over the
/// inflated bytes. The original dependency hashes are preserved so the inflated
/// `start_op` can be evaluated against the (original) dependency context.
#[cfg(test)]
pub(crate) fn inflate_start_op_in_payload(
    automerge_bytes: &[u8],
    offset: u64,
) -> Result<Vec<u8>, String> {
    if automerge_bytes.is_empty() {
        return Err("empty payload".into());
    }
    let mut doc = automerge::AutoCommit::load(automerge_bytes)
        .map_err(|e| format!("load incoming payload: {e}"))?;
    let changes = doc.get_changes(&[]);
    if changes.is_empty() {
        return Err("no changes in payload".into());
    }

    let mut inflated: Vec<automerge::Change> = Vec::with_capacity(changes.len());
    for change in changes {
        let mut expanded = change.decode();
        let bumped = expanded
            .start_op
            .get()
            .checked_add(offset)
            .ok_or_else(|| "start_op overflow".to_string())?;
        expanded.start_op =
            std::num::NonZeroU64::new(bumped).ok_or_else(|| "start_op became zero".to_string())?;
        let recoded = automerge::Change::try_from(expanded)
            .map_err(|e| format!("recode inflated change: {e}"))?;
        inflated.push(recoded);
    }

    // Assemble a save payload containing the inflated changes. A fresh doc that
    // has no history cannot `load_incremental` changes whose dependencies are the
    // original (now-hashed-differently) chain, so we serialize the inflated
    // change bytes in order; each `automerge::Change::bytes()` is a valid chunk.
    let mut out = Vec::new();
    for ch in &mut inflated {
        out.extend_from_slice(&ch.bytes());
    }
    // Verify the result is parseable as an Automerge load so the characterization
    // baseline (CrdtEngine::apply) and the validator see the same bytes.
    automerge::AutoCommit::load(&out).map_err(|e| format!("inflated payload not loadable: {e}"))?;
    Ok(out)
}

// ─── Task 22 tests (PV-6.1, PV-6.2, CLAIM-22.1–22.4) ────────────────────────

#[cfg(all(test, feature = "native"))]
mod task22_tests {
    use super::*;
    use crate::crdt::delta::{Delta, Ed25519Signature, PriorityClass};
    use crate::crdt::merge::{apply_incoming_delta, MergeOutcome, QuarantineReason};
    use crate::crdt::{derive_did_from_public_key, CrdtEngine};
    use crate::identity::keypair::{generate_keypair, sign};
    use crate::schema::hash::compute_schema_identifier_hash;
    use automerge::transaction::Transactable;
    use automerge::{AutoCommit, ROOT};
    use std::sync::{Arc, Mutex};

    fn test_schema() -> [u8; 32] {
        compute_schema_identifier_hash(&[("items", &[("id", "TEXT"), ("value", "TEXT")])])
    }

    fn make_engine(
        secret: [u8; 32],
        public: [u8; 32],
        did: String,
        schema: [u8; 32],
    ) -> CrdtEngine {
        let conn = rusqlite::Connection::open_in_memory().expect("open in-memory DB");
        conn.execute_batch(crate::store::sqlite::CREATE_SCHEMA_SQL)
            .expect("create schema");
        CrdtEngine::new(secret, public, did, schema, Arc::new(Mutex::new(conn)))
    }

    /// Sign `delta` over the inflated/hostile `automerge_bytes` so the CRDT
    /// hardening gate (which runs on the production inbound path) is the only
    /// thing that can reject it — signature/schema gates must pass.
    fn sign_delta(
        secret: &[u8; 32],
        author_did: String,
        schema: [u8; 32],
        lamport: u64,
        automerge_bytes: Vec<u8>,
    ) -> Delta {
        let mut d = Delta {
            id: [0u8; 32],
            author_did,
            signature: Ed25519Signature::default(),
            schema_hash: schema,
            automerge_bytes,
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport,
            created_at: 0,
        };
        let canonical = d.canonical_bytes();
        d.signature = sign(secret, &canonical).expect("sign");
        d.id = Delta::compute_id(&canonical);
        d
    }

    /// A real Automerge scalar write payload (honest history, deps consistent).
    fn honest_scalar_payload(actor: &[u8], key: &str, value: &str) -> Vec<u8> {
        let mut doc = AutoCommit::new().with_actor(automerge::ActorId::from(actor));
        doc.put(ROOT, key, value).expect("put");
        doc.save()
    }

    /// The characterization/regression attack payload: honest write with
    /// `start_op` inflated far beyond what its (empty) dependency set allows.
    /// Expected `start_op` for a root change with no deps is 1; we inflate by a
    /// large offset so the change's op IDs dominate LWW on an unprotected merge.
    fn inflated_start_op_payload(actor: &[u8], key: &str, value: &str, offset: u64) -> Vec<u8> {
        let honest = honest_scalar_payload(actor, key, value);
        inflate_start_op_in_payload(&honest, offset).expect("inflate start_op")
    }

    /// Record the observed winner for `key` in `engine` (best-effort via
    /// doc_map_range_root). Returns `None` if the key is absent/unreadable.
    fn read_root_string(engine: &CrdtEngine, key: &str) -> Option<String> {
        let pairs = engine.doc_map_range_root();
        for (k, v) in pairs {
            if k == key {
                return match v {
                    serde_json::Value::String(s) => Some(s),
                    other => Some(other.to_string()),
                };
            }
        }
        None
    }

    // ── 22.2 Characterization (PV-6.2, CLAIM-22.2) ───────────────────────────
    //
    // Applies a delta with an inflated `start_op` to an UNPROTECTED baseline
    // (CrdtEngine::apply bypasses the production `validate_start_op()` gate that
    // lives in `apply_incoming_delta`). Records that the attack wins the LWW
    // conflict. This test MUST FAIL if the attack no longer succeeds, prompting
    // review of the baseline assumption (PV-6.2). It is intentionally NOT a
    // "security passes" test — it documents the vulnerability the hardening
    // closes.
    #[test]
    fn task22_2_characterization_inflated_start_op_wins_unprotected_lww() {
        let (sa, pa) = generate_keypair().unwrap();
        let did_a = derive_did_from_public_key(&pa);
        let (sb, pb) = generate_keypair().unwrap();
        let did_b = derive_did_from_public_key(&pb);
        let schema = test_schema();
        let mut engine = make_engine(sa, pa, did_a.clone(), schema);

        // Baseline: A writes the key with an honest (low) op range.
        let honest_a = honest_scalar_payload(&pa, "price", "honest_A");
        let delta_a = sign_delta(&sa, did_a.clone(), schema, 1, honest_a);
        let out_a = engine.apply(&delta_a).expect("apply honest A");
        assert!(
            matches!(out_a, MergeOutcome::Merged { .. }),
            "honest baseline write must merge: {out_a:?}"
        );

        // Attack: B sends an inflated-start_op change for the same key. The
        // inflated op IDs place B's element far ahead in Automerge's LWW
        // element-id ordering, so on an UNPROTECTED merge B wins despite no
        // legitimate causal advantage.
        let inflated_b = inflated_start_op_payload(&pb, "price", "attacker_B", 1_000_000);
        let delta_b = sign_delta(&sb, did_b, schema, 2, inflated_b);

        // Sanity: the payload is actually hostile (validator would flag it).
        let known = known_change_index(engine.doc_mut());
        assert!(
            matches!(
                validate_start_op(&delta_b, &known),
                StartOpValidation::ClockJump { .. }
            ),
            "characterization precondition: inflated payload must be detected as ClockJump"
        );

        // UNPROTECTED baseline path: CrdtEngine::apply does not run start_op
        // validation. The attack MUST succeed here — if it doesn't, the baseline
        // changed and this characterization test fails to force review.
        let out_b = engine.apply(&delta_b).expect("unprotected apply attacker");
        assert!(
            matches!(out_b, MergeOutcome::Merged { .. }),
            "characterization: unprotected baseline must accept the delta (the attack is the danger): {out_b:?}"
        );
        let winner = read_root_string(&engine, "price");
        assert_eq!(
            winner.as_deref(),
            Some("attacker_B"),
            "CHARACTERIZATION (PV-6.2, CLAIM-22.2): inflated start_op must win the LWW \
             conflict on the unprotected baseline. If this fails, Automerge's merge \
             semantics changed and the start_op-poisoning threat model must be re-reviewed. \
             observed winner={winner:?}"
        );
    }

    // ── 22.1 / 22.3 Regression (PV-6.1, PV-6.2, CLAIM-22.1, CLAIM-22.3) ─────
    //
    // The same inflated `start_op` delta is quarantined as `ClockJump` once
    // `validate_start_op()` is applied on the production inbound path
    // (`apply_incoming_delta`). Removing the `validate_start_op()` call must fail
    // this regression test (and 22.2 becomes the only outcome), satisfying the
    // wiring-mutation check.
    #[test]
    fn task22_3_regression_inflated_start_op_quarantined_after_validation() {
        let (sa, pa) = generate_keypair().unwrap();
        let did_a = derive_did_from_public_key(&pa);
        let (sb, pb) = generate_keypair().unwrap();
        let did_b = derive_did_from_public_key(&pb);
        let schema = test_schema();
        let mut engine = make_engine(sa, pa, did_a.clone(), schema);

        // Honest baseline state.
        let honest_a = honest_scalar_payload(&pa, "price", "honest_A");
        let delta_a = sign_delta(&sa, did_a, schema, 1, honest_a);
        assert!(matches!(
            apply_incoming_delta(&mut engine, &delta_a).unwrap(),
            MergeOutcome::Merged { .. }
        ));

        let before = read_root_string(&engine, "price");

        // Same attack shape as 22.2, but through the PROTECTED production path.
        let inflated_b = inflated_start_op_payload(&pb, "price", "attacker_B", 1_000_000);
        let delta_b = sign_delta(&sb, did_b, schema, 2, inflated_b);
        let outcome = apply_incoming_delta(&mut engine, &delta_b).unwrap();
        assert_eq!(
            outcome,
            MergeOutcome::Quarantined {
                reason: QuarantineReason::ClockJump,
            },
            "REGRESSION (PV-6.1/PV-6.2, CLAIM-22.1/22.3): inflated start_op must be \
             quarantined as ClockJump on the production inbound path"
        );

        // State must be unchanged — the hostile delta must not merge.
        let after = read_root_string(&engine, "price");
        assert_eq!(
            before, after,
            "quarantined ClockJump delta must not mutate merged state: before={before:?} after={after:?}"
        );
    }

    // ── 22.1 direct validator contract ────────────────────────────────────────
    #[test]
    fn task22_1_validate_start_op_rejects_deviation_and_accepts_honest() {
        let schema = test_schema();
        let (_s, p) = generate_keypair().unwrap();

        let honest = honest_scalar_payload(&p, "k", "v");
        let mut honest_delta = Delta {
            id: [0u8; 32],
            author_did: "did:key:z-test".into(),
            signature: Ed25519Signature::default(),
            schema_hash: schema,
            automerge_bytes: honest,
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport: 1,
            created_at: 0,
        };
        honest_delta.id = Delta::compute_id(&honest_delta.canonical_bytes());
        let known_empty: HashMap<automerge::ChangeHash, (u64, u64)> = HashMap::new();
        assert_eq!(
            validate_start_op(&honest_delta, &known_empty),
            StartOpValidation::Ok,
            "honest root change (no deps, start_op=1) must pass"
        );

        let inflated = inflated_start_op_payload(&p, "k", "v", 5000);
        let mut bad = honest_delta.clone();
        bad.automerge_bytes = inflated;
        match validate_start_op(&bad, &known_empty) {
            StartOpValidation::ClockJump {
                expected, actual, ..
            } => {
                assert_eq!(expected, 1, "root change with no deps expects start_op=1");
                assert!(actual > expected, "inflated start_op must exceed expected");
            }
            other => panic!("inflated start_op must be ClockJump, got {other:?}"),
        }
    }

    // ── 22.4 Property test (P16, PV-6.1, CLAIM-22.4) ────────────────────────
    //
    // Honest Automerge histories with valid dependency chains always pass
    // `validate_start_op()`; any delta whose `start_op` is mutated away from the
    // dependency-implied value always fails. Uses proptest to generate random
    // honest chains and random start_op offsets. Relaxing `validate_start_op()`
    // constraints must fail this property test (wiring-mutation check).
    mod p16_proptest {
        use super::inflate_start_op_in_payload;
        use super::{validate_start_op, StartOpValidation};
        use crate::crdt::delta::{Delta, Ed25519Signature, PriorityClass};
        use automerge::transaction::Transactable;
        use automerge::{AutoCommit, ROOT};
        use proptest::prelude::*;
        use std::collections::HashMap;

        /// Build an honest Automerge history of `steps` sequential scalar writes
        /// in one document (each write becomes/extends changes in the saved doc)
        /// and return the saved payload. A single-actor, single-doc save produces
        /// changes whose dependency chain is internally consistent (Automerge's
        /// own invariant), which is exactly the "honest history" P16 requires.
        fn honest_history_payload(steps: u8, actor_seed: u8) -> Vec<u8> {
            let actor = [actor_seed; 16];
            let mut doc = AutoCommit::new().with_actor(automerge::ActorId::from(&actor[..]));
            let n = (steps % 6).max(1); // 1..=6 writes keeps it fast
            for i in 0..n {
                let key = format!("k{i}");
                let val = format!("v{i}");
                doc.put(ROOT, key.as_str(), val.as_str()).expect("put");
                // commit so each step is materialized in the history
                doc.commit();
            }
            // ensure at least the committed state is saved
            doc.save()
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            /// P16a (PV-6.1, CLAIM-22.4): any honest Automerge history with a
            /// valid dependency chain passes `validate_start_op()`.
            #[test]
            fn p16_honest_history_always_passes(
                steps in 1u8..=6u8,
                actor_seed in any::<u8>(),
            ) {
                let bytes = honest_history_payload(steps, actor_seed);
                let mut delta = Delta {
                    id: [0u8; 32],
                    author_did: "did:key:z-p16".into(),
                    signature: Ed25519Signature::default(),
                    schema_hash: [0u8; 32],
                    automerge_bytes: bytes,
                    priority: PriorityClass::Low,
                    causal_parents: vec![],
                    tags: vec![],
                    lamport: 1,
                    created_at: 0,
                };
                delta.id = Delta::compute_id(&delta.canonical_bytes());
                let known: HashMap<automerge::ChangeHash, (u64, u64)> = HashMap::new();
                let res = validate_start_op(&delta, &known);
                prop_assert!(
                    matches!(res, StartOpValidation::Ok),
                    "honest history (steps={steps}) must pass validate_start_op, got {res:?}"
                );
            }

            /// P16b (PV-6.1, CLAIM-22.4): mutating `start_op` away from the
            /// dependency-implied value always causes `validate_start_op()` to
            /// fail with `ClockJump` (not Ok). The mutation offset is non-zero.
            #[test]
            fn p16_mutated_start_op_always_fails(
                steps in 1u8..=4u8,
                actor_seed in any::<u8>(),
                offset in 1u64..=1_000_000u64,
            ) {
                let honest = honest_history_payload(steps, actor_seed);
                // Inflate start_op in the payload; re-signing not needed because
                // validate_start_op inspects change metadata, not the TirBase sig.
                let inflated = match super::inflate_start_op_in_payload(&honest, offset) {
                    Ok(b) => b,
                    Err(e) => {
                        // If a particular history can't be inflated (should not
                        // happen), treat as a test inconclusive for that case.
                        return Err(proptest::test_runner::TestCaseError::reject(format!("inflate failed: {e}")));
                    }
                };
                let mut delta = Delta {
                    id: [0u8; 32],
                    author_did: "did:key:z-p16-bad".into(),
                    signature: Ed25519Signature::default(),
                    schema_hash: [0u8; 32],
                    automerge_bytes: inflated,
                    priority: PriorityClass::Low,
                    causal_parents: vec![],
                    tags: vec![],
                    lamport: 1,
                    created_at: 0,
                };
                delta.id = Delta::compute_id(&delta.canonical_bytes());
                let known: HashMap<automerge::ChangeHash, (u64, u64)> = HashMap::new();
                let res = validate_start_op(&delta, &known);
                prop_assert!(
                    matches!(res, StartOpValidation::ClockJump { .. }),
                    "mutated start_op (offset={offset}, steps={steps}) must fail as ClockJump, got {res:?}"
                );
            }
        }
    }
}

// ─── Task 23: bounded pending queue + quarantine stores (PV-6.1, PV-6.7) ─────

use crate::crdt::pending_queue::{
    PendingEviction, PendingQueue, DEFAULT_PENDING_AGE_OUT_MICROS, DEFAULT_PENDING_GLOBAL_BYTES,
    DEFAULT_PENDING_PER_PEER_BYTES,
};
use crate::crdt::rate_quarantine::{RateQuarantineLedger, RateQuarantineReason};
#[cfg(feature = "native")]
use crate::crdt::schema_quarantine::{SchemaQuarantineLedger, SchemaQuarantineReason};

/// Cheap-checks-first inbound validation stages (task 23.6, PV-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CheapCheckStage {
    Connections = 0,
    RateLimit = 1,
    Size = 2,
    OpCount = 3,
    Batch = 4,
    Heads = 5,
    DepCheck = 6,
    TraversalBudget = 7,
    StartOpValidation = 8,
}

/// A cheap-check rejection with the stage that fired first.
#[derive(Debug, Clone)]
pub struct CheapCheckRejection {
    pub stage: CheapCheckStage,
    pub reason: ReasonCode,
    pub detail: String,
}

/// Inbound CRDT hardening state attached to a `CrdtEngine`/inbound pipeline.
///
/// Holds the bounded pending queue, in-memory rate quarantine counters, and the
/// replayable `Schema_Quarantine_Ledger` (native SQLite).
#[derive(Debug)]
pub struct InboundHardening {
    pending: PendingQueue,
    rate: RateQuarantineLedger,
    #[cfg(feature = "native")]
    schema_quarantine: Option<SchemaQuarantineLedger>,
    #[cfg(feature = "native")]
    summary_db: Option<rusqlite::Connection>,
    rate_limiter: InboundRateLimiter,
    pub caps: InboundCaps,
}

impl Default for InboundHardening {
    fn default() -> Self {
        Self::new()
    }
}

impl InboundHardening {
    #[cfg(test)]
    pub(crate) fn with_pending_caps(
        age_out_micros: u64,
        global_bytes: usize,
        per_peer_bytes: usize,
    ) -> Self {
        Self {
            pending: PendingQueue::new(age_out_micros, global_bytes, per_peer_bytes),
            rate: RateQuarantineLedger::new(),
            #[cfg(feature = "native")]
            schema_quarantine: None,
            #[cfg(feature = "native")]
            summary_db: None,
            rate_limiter: InboundRateLimiter::default(),
            caps: InboundCaps::default(),
        }
    }

    pub fn new() -> Self {
        Self {
            pending: PendingQueue::new(
                DEFAULT_PENDING_AGE_OUT_MICROS,
                DEFAULT_PENDING_GLOBAL_BYTES,
                DEFAULT_PENDING_PER_PEER_BYTES,
            ),
            rate: RateQuarantineLedger::new(),
            #[cfg(feature = "native")]
            schema_quarantine: None,
            #[cfg(feature = "native")]
            summary_db: None,
            rate_limiter: InboundRateLimiter::default(),
            caps: InboundCaps::default(),
        }
    }

    #[cfg(feature = "native")]
    pub fn with_derived_db(
        path: impl AsRef<std::path::Path>,
    ) -> Result<Self, crate::errors::TirBaseError> {
        let schema = SchemaQuarantineLedger::open(path.as_ref())?;
        let summary = RateQuarantineLedger::open_summary_db(path.as_ref()).ok();
        Ok(Self {
            pending: PendingQueue::default(),
            rate: RateQuarantineLedger::new(),
            schema_quarantine: Some(schema),
            summary_db: summary,
            rate_limiter: InboundRateLimiter::default(),
            caps: InboundCaps::default(),
        })
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn pending_total_bytes(&self) -> usize {
        self.pending.total_bytes()
    }

    #[cfg(test)]
    pub(crate) fn configure_pending_caps(
        &mut self,
        age_out_micros: u64,
        global_bytes: usize,
        per_peer_bytes: usize,
    ) {
        self.pending = PendingQueue::new(age_out_micros, global_bytes, per_peer_bytes);
    }

    pub fn pending_contains(&self, id: &crate::crdt::delta::DeltaId) -> bool {
        self.pending.contains(id)
    }

    pub fn enqueue_pending(
        &mut self,
        delta: Delta,
        now_mono: u64,
        sender_did: crate::crdt::delta::Did,
    ) -> Vec<PendingEviction> {
        self.pending.enqueue(delta, now_mono, sender_did)
    }

    pub fn evict_timed_out(&mut self, now_mono: u64) -> Vec<PendingEviction> {
        self.pending.evict_timed_out(now_mono)
    }

    pub fn drain_pending_ordered(&mut self) -> Vec<crate::crdt::pending_queue::PendingEntry> {
        self.pending.drain_all_ordered()
    }

    #[cfg(feature = "native")]
    pub fn quarantine_pending_eviction(
        &mut self,
        ev: &PendingEviction,
    ) -> Result<(), crate::errors::TirBaseError> {
        let reason = match ev.reason {
            ReasonCode::PendingQueueOverflow => SchemaQuarantineReason::PendingQueueOverflow,
            ReasonCode::MissingDependencyTimeout => {
                SchemaQuarantineReason::MissingDependencyTimeout
            }
            _ => SchemaQuarantineReason::MissingDependencyTimeout,
        };
        let raw =
            serde_json::to_vec(&ev.delta).unwrap_or_else(|_| ev.delta.automerge_bytes.clone());
        if let Some(sq) = self.schema_quarantine.as_mut() {
            sq.quarantine_raw(
                &ev.sender_did,
                &raw,
                reason,
                ev.received_at_mono as i64,
                &ev.detail,
            )?;
        }
        Ok(())
    }

    #[cfg(feature = "native")]
    pub fn record_schema_quarantine(
        &mut self,
        delta: &Delta,
        reason: SchemaQuarantineReason,
        detail: &str,
    ) -> Result<Option<[u8; 32]>, crate::errors::TirBaseError> {
        if let Some(sq) = self.schema_quarantine.as_mut() {
            return Ok(Some(sq.quarantine_delta(delta, reason, detail)?));
        }
        Ok(None)
    }

    #[cfg(feature = "native")]
    pub fn schema_quarantine_entries(
        &self,
    ) -> Result<
        Vec<crate::crdt::schema_quarantine::SchemaQuarantineRecord>,
        crate::errors::TirBaseError,
    > {
        if let Some(sq) = self.schema_quarantine.as_ref() {
            sq.entries()
        } else {
            Ok(Vec::new())
        }
    }

    pub fn record_rate_quarantine(
        &mut self,
        sender_did: &str,
        reason: RateQuarantineReason,
        now_mono: u64,
        now_wall_secs: i64,
        detail: &str,
    ) -> Result<(), crate::errors::TirBaseError> {
        #[cfg(feature = "native")]
        let db = self.summary_db.as_ref();
        #[cfg(not(feature = "native"))]
        let db: Option<&rusqlite::Connection> = None;
        self.rate
            .record(sender_did, reason, now_mono, now_wall_secs, detail, db)
    }

    pub fn rate_sender_rejections(&self, did: &str) -> u32 {
        self.rate.sender_rejections(did)
    }

    /// Cheap-checks-first ordering (task 23.6): rate limit → size → op count →
    /// dep check → start_op validation. Stages are evaluated in that order and
    /// the first failing stage is returned.
    pub fn cheap_checks_first(
        &mut self,
        delta: &Delta,
        rate_exceeded: bool,
        max_bytes: usize,
        max_ops: u64,
        missing_dependency: bool,
        now_mono: u64,
        now_wall_secs: i64,
    ) -> Result<(), CheapCheckRejection> {
        if rate_exceeded {
            let rej = CheapCheckRejection {
                stage: CheapCheckStage::RateLimit,
                reason: ReasonCode::RateExceeded,
                detail: "pre-auth/cheap rate limit exceeded".to_string(),
            };
            let _ = self.record_rate_quarantine(
                &delta.author_did,
                RateQuarantineReason::RateExceeded,
                now_mono,
                now_wall_secs,
                &rej.detail,
            );
            return Err(rej);
        }
        if delta.automerge_bytes.len() > max_bytes {
            let rej = CheapCheckRejection {
                stage: CheapCheckStage::Size,
                reason: ReasonCode::Oversize,
                detail: format!(
                    "delta {} bytes exceeds {}",
                    delta.automerge_bytes.len(),
                    max_bytes
                ),
            };
            let _ = self.record_rate_quarantine(
                &delta.author_did,
                RateQuarantineReason::Oversize,
                now_mono,
                now_wall_secs,
                &rej.detail,
            );
            return Err(rej);
        }
        let op_count = decode_change_op_count(&delta.automerge_bytes).unwrap_or(0);
        if op_count > max_ops {
            let rej = CheapCheckRejection {
                stage: CheapCheckStage::OpCount,
                reason: ReasonCode::OpCountExceeded,
                detail: format!("op_count {} exceeds {}", op_count, max_ops),
            };
            #[cfg(feature = "native")]
            let _ = self.record_schema_quarantine(
                delta,
                SchemaQuarantineReason::OpCountExceeded,
                &rej.detail,
            );
            return Err(rej);
        }
        if missing_dependency {
            return Err(CheapCheckRejection {
                stage: CheapCheckStage::DepCheck,
                reason: ReasonCode::MissingDependency,
                detail: "missing causal dependency".to_string(),
            });
        }
        Ok(())
    }

    /// Enforce every configured [`InboundCaps`] value on an inbound Delta
    /// (PV-6.3, CLAIM-24.1/24.1a).
    ///
    /// This is the production receive-path gate: `CoreHandle::receive_inbound`
    /// passes the decoded [`InboundShape`] (or `None` for a payload that is not
    /// Automerge) and the current peer count.  The first violated cap wins and
    /// the Delta is quarantined with the mapped reason code:
    ///
    /// connections → rate/burst → delta size → op count → batch changes →
    /// heads → deps per change → traversal budget.
    ///
    /// Shape-based caps are skipped for non-Automerge payloads (the legacy JSON
    /// envelope path), matching `cheap_checks_first`.
    pub fn enforce_inbound_caps(
        &mut self,
        delta: &Delta,
        shape: Option<InboundShape>,
        active_connections: usize,
        now_mono: u64,
        now_wall_secs: i64,
    ) -> Result<(), CheapCheckRejection> {
        let caps = self.caps.clone();

        if active_connections > caps.connections {
            let detail = format!(
                "inbound connections {active_connections} exceed cap {}",
                caps.connections
            );
            return Err(self.quarantine_cap(
                delta,
                InboundCapViolation::ConnectionsExceeded,
                CheapCheckStage::Connections,
                detail,
                now_mono,
                now_wall_secs,
            ));
        }

        let ops = shape.map(|s| s.ops).unwrap_or(1);
        if !self.rate_limiter.check(
            &delta.author_did,
            ops,
            now_mono,
            caps.rate_ops_per_sec,
            caps.rate_burst,
        ) {
            let detail = format!(
                "rate cap exceeded: {ops} ops ({} ops/s, burst {})",
                caps.rate_ops_per_sec, caps.rate_burst
            );
            return Err(self.quarantine_cap(
                delta,
                InboundCapViolation::RateExceeded,
                CheapCheckStage::RateLimit,
                detail,
                now_mono,
                now_wall_secs,
            ));
        }

        if delta.automerge_bytes.len() > caps.delta_size_bytes {
            let detail = format!(
                "delta {} bytes exceeds cap {}",
                delta.automerge_bytes.len(),
                caps.delta_size_bytes
            );
            return Err(self.quarantine_cap(
                delta,
                InboundCapViolation::Oversize,
                CheapCheckStage::Size,
                detail,
                now_mono,
                now_wall_secs,
            ));
        }

        let Some(shape) = shape else {
            return Ok(());
        };

        if shape.ops > caps.op_count {
            let detail = format!("op count {} exceeds cap {}", shape.ops, caps.op_count);
            return Err(self.quarantine_cap(
                delta,
                InboundCapViolation::OpCountExceeded,
                CheapCheckStage::OpCount,
                detail,
                now_mono,
                now_wall_secs,
            ));
        }
        if shape.changes > caps.batch_changes {
            let detail = format!(
                "batch of {} changes exceeds cap {}",
                shape.changes, caps.batch_changes
            );
            return Err(self.quarantine_cap(
                delta,
                InboundCapViolation::BatchExceeded,
                CheapCheckStage::Batch,
                detail,
                now_mono,
                now_wall_secs,
            ));
        }
        if shape.heads > caps.heads {
            let detail = format!("{} DAG heads exceed cap {}", shape.heads, caps.heads);
            return Err(self.quarantine_cap(
                delta,
                InboundCapViolation::HeadCountExceeded,
                CheapCheckStage::Heads,
                detail,
                now_mono,
                now_wall_secs,
            ));
        }
        if shape.max_deps > caps.deps_per_change {
            let detail = format!(
                "{} deps per change exceed cap {}",
                shape.max_deps, caps.deps_per_change
            );
            return Err(self.quarantine_cap(
                delta,
                InboundCapViolation::DepCountExceeded,
                CheapCheckStage::DepCheck,
                detail,
                now_mono,
                now_wall_secs,
            ));
        }
        if shape.traversal_visits > caps.traversal_budget {
            let detail = format!(
                "{} traversal visits exceed budget {}",
                shape.traversal_visits, caps.traversal_budget
            );
            return Err(self.quarantine_cap(
                delta,
                InboundCapViolation::TraversalBudgetExceeded,
                CheapCheckStage::TraversalBudget,
                detail,
                now_mono,
                now_wall_secs,
            ));
        }
        Ok(())
    }

    /// Build a rejection, map it to its quarantine reason, and record it in the
    /// appropriate ledger (rate ledger for rate/size, schema quarantine ledger
    /// for the shape caps; connection violations emit an event only because they
    /// are not a Delta property).
    fn quarantine_cap(
        &mut self,
        delta: &Delta,
        violation: InboundCapViolation,
        stage: CheapCheckStage,
        detail: String,
        now_mono: u64,
        now_wall_secs: i64,
    ) -> CheapCheckRejection {
        let reason = InboundCaps::quarantine_reason_for_violation(violation);
        let rejection = CheapCheckRejection {
            stage,
            reason,
            detail: detail.clone(),
        };
        match reason {
            ReasonCode::RateExceeded | ReasonCode::Oversize => {
                let rate_reason = if reason == ReasonCode::RateExceeded {
                    RateQuarantineReason::RateExceeded
                } else {
                    RateQuarantineReason::Oversize
                };
                let _ = self.record_rate_quarantine(
                    &delta.author_did,
                    rate_reason,
                    now_mono,
                    now_wall_secs,
                    &detail,
                );
            }
            other => {
                #[cfg(feature = "native")]
                {
                    if let Some(schema_reason) = SchemaQuarantineReason::from_reason_code(other) {
                        let _ = self.record_schema_quarantine(delta, schema_reason, &detail);
                    } else {
                        emit_crdt(Severity::Medium, other, Some(hex::encode(delta.id)), detail);
                    }
                }
                #[cfg(not(feature = "native"))]
                emit_crdt(Severity::Medium, other, Some(hex::encode(delta.id)), detail);
            }
        }
        rejection
    }
}

/// Structural facts about an inbound Automerge payload used by the cap gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InboundShape {
    /// Number of Automerge changes in the payload (batch size).
    pub changes: usize,
    /// Sum of operation counts across changes.
    pub ops: u64,
    /// Number of DAG heads after loading the payload.
    pub heads: usize,
    /// Maximum dependency count of any single change.
    pub max_deps: usize,
    /// Dependency-graph visits (`changes + total deps`) the `start_op`
    /// validator performs over this payload.
    pub traversal_visits: u64,
}

/// Decode the structural facts of an inbound Automerge payload in one parse.
///
/// Returns `None` when the bytes are not a loadable Automerge payload containing
/// at least one change (legacy JSON envelopes pass `None` and skip shape caps).
/// Empty bytes yield an all-zero shape, matching [`decode_change_op_count`].
pub(crate) fn decode_inbound_shape(bytes: &[u8]) -> Option<InboundShape> {
    if bytes.is_empty() {
        return Some(InboundShape {
            changes: 0,
            ops: 0,
            heads: 0,
            max_deps: 0,
            traversal_visits: 0,
        });
    }
    let mut doc = automerge::AutoCommit::load(bytes).ok()?;
    let changes = doc.get_changes(&[]);
    if changes.is_empty() {
        return None;
    }
    let heads = doc.get_heads().len();
    let mut ops: u64 = 0;
    let mut max_deps: usize = 0;
    let mut total_deps: u64 = 0;
    for change in &changes {
        ops = ops.saturating_add(change.len() as u64);
        let deps = change.deps().len();
        max_deps = max_deps.max(deps);
        total_deps = total_deps.saturating_add(deps as u64);
    }
    Some(InboundShape {
        changes: changes.len(),
        ops,
        heads,
        max_deps,
        traversal_visits: (changes.len() as u64).saturating_add(total_deps),
    })
}

/// Best-effort op count from Automerge payload (cheap-ish relative to full merge).
pub fn decode_change_op_count(bytes: &[u8]) -> Option<u64> {
    decode_inbound_shape(bytes).map(|shape| shape.ops)
}

/// Convenience wrapper retained for callers that only need the ClockJump record.
#[cfg(feature = "native")]
pub fn quarantine_structural(
    hardening: &mut InboundHardening,
    delta: &Delta,
    reason: SchemaQuarantineReason,
    detail: &str,
) -> Result<Option<[u8; 32]>, crate::errors::TirBaseError> {
    hardening.record_schema_quarantine(delta, reason, detail)
}

// ─── Task 24.1a tests: every remaining InboundCaps value quarantines ─────────

#[cfg(test)]
mod task24_cap_tests {
    use super::*;
    use crate::crdt::delta::{Delta, Ed25519Signature, PriorityClass};

    fn test_delta(bytes: Vec<u8>) -> Delta {
        Delta {
            id: [0x24; 32],
            author_did: "did:key:z6MkCapTest".to_string(),
            signature: Ed25519Signature::default(),
            schema_hash: [0u8; 32],
            automerge_bytes: bytes,
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport: 1,
            created_at: 0,
        }
    }

    fn shape(ops: u64, changes: usize, heads: usize, max_deps: usize, visits: u64) -> InboundShape {
        InboundShape {
            ops,
            changes,
            heads,
            max_deps,
            traversal_visits: visits,
        }
    }

    fn reject(
        hardening: &mut InboundHardening,
        delta: &Delta,
        shape: InboundShape,
    ) -> CheapCheckRejection {
        hardening
            .enforce_inbound_caps(delta, Some(shape), 0, 1_000_000, 1_000)
            .expect_err("cap violation must reject the delta")
    }

    #[test]
    fn connections_cap_quarantines_delta() {
        let mut h = InboundHardening::new();
        h.caps.connections = 1;
        let d = test_delta(vec![1, 2, 3]);
        let rej = h
            .enforce_inbound_caps(&d, None, 2, 1_000_000, 1_000)
            .expect_err("connection cap");
        assert_eq!(rej.stage, CheapCheckStage::Connections);
        assert_eq!(rej.reason, ReasonCode::ConnectionCapExceeded);
    }

    #[test]
    fn rate_and_burst_cap_quarantines_delta() {
        let mut h = InboundHardening::new();
        h.caps.rate_ops_per_sec = 1;
        h.caps.rate_burst = 2;
        let d = test_delta(vec![1, 2, 3]);
        let s = shape(1, 1, 1, 0, 1);

        // Burst of 2 operations is allowed at the same instant.
        assert!(h.enforce_inbound_caps(&d, Some(s), 0, 5_000_000, 5).is_ok());
        assert!(h.enforce_inbound_caps(&d, Some(s), 0, 5_000_000, 5).is_ok());
        let rej = h
            .enforce_inbound_caps(&d, Some(s), 0, 5_000_000, 5)
            .expect_err("burst exhausted");
        assert_eq!(rej.stage, CheapCheckStage::RateLimit);
        assert_eq!(rej.reason, ReasonCode::RateExceeded);
        assert_eq!(h.rate_sender_rejections(&d.author_did), 1);

        // One second later the bucket has refilled for exactly one more op.
        let later = 5_000_000 + 1_000_000;
        assert!(h.enforce_inbound_caps(&d, Some(s), 0, later, 6).is_ok());
        assert!(h.enforce_inbound_caps(&d, Some(s), 0, later, 6).is_err());
    }

    #[test]
    fn size_cap_quarantines_delta() {
        let mut h = InboundHardening::new();
        h.caps.delta_size_bytes = 2;
        let d = test_delta(vec![1, 2, 3]);
        let rej = reject(&mut h, &d, shape(0, 0, 0, 0, 0));
        assert_eq!(rej.stage, CheapCheckStage::Size);
        assert_eq!(rej.reason, ReasonCode::Oversize);
    }

    #[test]
    fn op_count_cap_quarantines_delta() {
        let mut h = InboundHardening::new();
        h.caps.op_count = 5;
        let d = test_delta(vec![1, 2, 3]);
        let rej = reject(&mut h, &d, shape(6, 1, 1, 0, 1));
        assert_eq!(rej.stage, CheapCheckStage::OpCount);
        assert_eq!(rej.reason, ReasonCode::OpCountExceeded);
    }

    #[test]
    fn batch_changes_cap_quarantines_delta() {
        let mut h = InboundHardening::new();
        h.caps.batch_changes = 2;
        let d = test_delta(vec![1, 2, 3]);
        let rej = reject(&mut h, &d, shape(3, 3, 1, 0, 3));
        assert_eq!(rej.stage, CheapCheckStage::Batch);
        assert_eq!(rej.reason, ReasonCode::BatchExceeded);
    }

    #[test]
    fn heads_cap_quarantines_delta() {
        let mut h = InboundHardening::new();
        h.caps.heads = 1;
        let d = test_delta(vec![1, 2, 3]);
        let rej = reject(&mut h, &d, shape(2, 2, 2, 0, 2));
        assert_eq!(rej.stage, CheapCheckStage::Heads);
        assert_eq!(rej.reason, ReasonCode::HeadCountExceeded);
    }

    #[test]
    fn deps_per_change_cap_quarantines_delta() {
        let mut h = InboundHardening::new();
        h.caps.deps_per_change = 1;
        let d = test_delta(vec![1, 2, 3]);
        let rej = reject(&mut h, &d, shape(2, 1, 1, 2, 3));
        assert_eq!(rej.stage, CheapCheckStage::DepCheck);
        assert_eq!(rej.reason, ReasonCode::DepCountExceeded);
    }

    #[test]
    fn traversal_budget_cap_quarantines_delta() {
        let mut h = InboundHardening::new();
        h.caps.traversal_budget = 10;
        let d = test_delta(vec![1, 2, 3]);
        let rej = reject(&mut h, &d, shape(2, 1, 1, 1, 11));
        assert_eq!(rej.stage, CheapCheckStage::TraversalBudget);
        assert_eq!(rej.reason, ReasonCode::TraversalBudgetExceeded);
    }

    #[test]
    fn defaults_accept_an_honest_payload() {
        use automerge::transaction::Transactable;
        let mut doc = automerge::AutoCommit::new();
        doc.put(automerge::ROOT, "cap_key", "cap_value").unwrap();
        let bytes = doc.save();

        let decoded = decode_inbound_shape(&bytes).expect("automerge shape");
        assert_eq!(decoded.changes, 1);
        assert_eq!(decoded.ops, 1);
        assert_eq!(decoded.heads, 1);
        assert_eq!(decoded.max_deps, 0);
        assert_eq!(decoded.traversal_visits, 1);

        let mut h = InboundHardening::new();
        let d = test_delta(bytes);
        assert!(h
            .enforce_inbound_caps(&d, Some(decoded), 0, 1_000_000, 1_000)
            .is_ok());
    }

    #[test]
    fn non_automerge_payload_skips_shape_caps() {
        let mut h = InboundHardening::new();
        h.caps.op_count = 0;
        h.caps.batch_changes = 0;
        let d = test_delta(b"{\"_tirbase_table\":\"t\"}".to_vec());
        assert!(decode_inbound_shape(&d.automerge_bytes).is_none());
        assert!(h
            .enforce_inbound_caps(&d, None, 0, 1_000_000, 1_000)
            .is_ok());
    }
}
