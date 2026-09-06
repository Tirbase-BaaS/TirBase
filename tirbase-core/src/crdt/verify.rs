//! Post-merge LWW/RGA read-back verification (Subphase 6.1 — T50).
//!
//! After [`CrdtEngine::apply`](super::CrdtEngine::apply) merges an incoming
//! Delta's Automerge bytes, this module reads back the **actual** winning
//! value / ordering from the merged document and compares it against the
//! Lamport-rule prediction (`lww_incoming_wins` / `rga_incoming_has_priority`,
//! Req 4.5 / 4.5a).  On divergence in the *definitive* zone — the incoming
//! Delta's Lamport strictly exceeds the local engine's clock, so the rule
//! mandates the incoming op wins regardless of actor bytes — the divergence is
//! logged and the document is **overridden** so the merged state honours the
//! rule.
//!
//! The read-back catches the failure modes the audit flagged: a peer whose
//! payload changes use a non-DID actor (Automerge then tiebreaks on the wrong
//! bytes) or a payload whose Automerge counter ordering disagrees with the
//! Delta's Lamport ordering.  Both manifest as "the merged doc resolved to the
//! local op although the rule says the incoming op must win".
//!
//! Zones:
//! - **Definitive** (`delta.lamport > local_lamport`): the prediction is
//!   provably exact (the incoming Lamport beats *every* local write, since all
//!   local writes carry a Lamport ≤ the engine's clock).  Divergence here is a
//!   real spec violation and is overridden.
//! - **Indeterminate** (`delta.lamport <= local_lamport`): the engine-wide
//!   local Lamport is only an estimate of the conflicting local write's Lamport
//!   (per-key write Lamports are not tracked), so the read-back is logged for
//!   observability but never overridden — an override here could corrupt data.

use std::collections::HashMap;

use automerge::transaction::Transactable;
use automerge::{AutoCommit, ObjId, ObjType, ReadDoc, ROOT};

use super::{lww_incoming_wins, rga_incoming_has_priority};

/// Summary of one `apply`'s verification pass (used for the log line and by
/// tests to assert the machinery ran).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerificationReport {
    /// Number of conflicting ROOT-level scalar keys read back.
    pub lww_checked: usize,
    /// Number of conflicting same-position list insertions read back.
    pub rga_checked: usize,
    /// Number of definitive-zone divergences detected.
    pub divergences: usize,
    /// Number of overrides successfully applied to the doc.
    pub overrides_applied: usize,
    /// Number of overrides that failed (logged; the merge itself still stands).
    pub overrides_failed: usize,
    /// Number of conflicts read back in the indeterminate zone (log-only).
    pub indeterminate: usize,
}

/// A conflicting ROOT-level scalar key: both docs hold a value for `key`, and
/// the incoming op's element ID differs from the local op's element ID.
#[derive(Debug, Clone)]
pub(crate) struct LwwConflict {
    pub key: String,
    pub incoming_exid: ObjId,
    pub incoming_value: automerge::ScalarValue,
    pub local_exid: ObjId,
    pub local_value: automerge::ScalarValue,
}

/// A concurrent list-insertion pair: the local doc and the incoming doc each
/// inserted an element at the *same* position (same predecessor element ID).
/// Element IDs are `(counter, actor bytes)`.
#[derive(Debug, Clone)]
pub(crate) struct RgaConflict {
    pub local_element: (u64, Vec<u8>),
    pub incoming_element: (u64, Vec<u8>),
    pub local_value: automerge::ScalarValue,
    pub incoming_value: automerge::ScalarValue,
}

/// Pre-merge snapshot of every key / position that the incoming payload
/// conflicts with in the local doc.
#[derive(Debug, Default, Clone)]
pub(crate) struct ConflictSnapshot {
    pub lww: Vec<LwwConflict>,
    pub rga: Vec<RgaConflict>,
}

/// Snapshot the conflicts between `local` (pre-merge) and `incoming`
/// (pre-merge).  Must be called before the merge — after it, the local doc no
/// longer distinguishes the two sides.
pub(crate) fn capture_conflicts(local: &AutoCommit, incoming: &AutoCommit) -> ConflictSnapshot {
    ConflictSnapshot {
        lww: capture_lww(local, incoming),
        rga: capture_rga(local, incoming),
    }
}

fn capture_lww(local: &AutoCommit, incoming: &AutoCommit) -> Vec<LwwConflict> {
    let local_map = root_scalars(local);
    let incoming_map = root_scalars(incoming);

    let mut out: Vec<LwwConflict> = incoming_map
        .into_iter()
        .filter_map(|(key, (incoming_exid, incoming_value))| {
            let (local_exid, local_value) = local_map.get(&key)?;
            // Same element on both sides (shared history) → no conflict.
            if local_exid == &incoming_exid {
                return None;
            }
            Some(LwwConflict {
                key,
                incoming_exid,
                incoming_value,
                local_exid: local_exid.clone(),
                local_value: local_value.clone(),
            })
        })
        .collect();
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

/// ROOT-level scalar entries of a doc as `key → (element ID, value)`.
fn root_scalars(doc: &AutoCommit) -> HashMap<String, (ObjId, automerge::ScalarValue)> {
    doc.map_range(ROOT, ..)
        .filter_map(|item| match item.value {
            automerge::ValueRef::Scalar(ref sv) => {
                let legacy: automerge::ScalarValue = automerge::ScalarValue::from(sv);
                Some((item.key.to_string(), (item.id(), legacy)))
            }
            automerge::ValueRef::Object(_) => None,
        })
        .collect()
}

/// One decoded scalar-valued list insertion: `(predecessor, element id, value)`.
/// `predecessor` is `None` for an insertion at the head of the list.
type InsertOp = (Option<(u64, Vec<u8>)>, (u64, Vec<u8>), automerge::ScalarValue);

fn capture_rga(local: &AutoCommit, incoming: &AutoCommit) -> Vec<RgaConflict> {
    let local_inserts = list_inserts(local);
    let incoming_inserts = list_inserts(incoming);

    let mut out = Vec::new();
    for (loc_pred, loc_elem, loc_val) in &local_inserts {
        for (inc_pred, inc_elem, inc_val) in &incoming_inserts {
            if loc_pred == inc_pred {
                out.push(RgaConflict {
                    local_element: loc_elem.clone(),
                    incoming_element: inc_elem.clone(),
                    local_value: loc_val.clone(),
                    incoming_value: inc_val.clone(),
                });
            }
        }
    }
    out
}

/// Decode every scalar-valued list insertion op in `doc`'s history.
fn list_inserts(doc: &AutoCommit) -> Vec<InsertOp> {
    let mut out = Vec::new();
    // `AutoCommit::get_changes` needs `&mut self`; cloning the read-only handle
    // keeps this a pure read of the pre-merge state.
    let mut doc = doc.clone();
    for change in doc.get_changes(&[]) {
        let expanded = change.decode();
        let start_op = expanded.start_op.get();
        let actor = expanded.actor_id.to_bytes().to_vec();
        for (i, op) in expanded.operations.iter().enumerate() {
            if !op.insert {
                continue;
            }
            let Some(value) = op.primitive_value() else {
                continue;
            };
            // An op at 0-based index `i` of a change carries op ID
            // `(start_op + i, change actor)`.
            let element = (start_op + i as u64, actor.clone());
            let predecessor = op
                .key
                .as_element_id()
                .and_then(|eid| eid.as_opid().map(|oid| (oid.counter(), oid.actor().to_bytes().to_vec())));
            out.push((predecessor, element, value));
        }
    }
    out
}

/// Read the merged doc back and compare the actual winner against the rule;
/// override the doc on definitive-zone divergence.
///
/// `local_lamport` must be the engine's Lamport clock *before* the
/// post-merge advance (the clock the conflicting local write was made under in
/// the single-write case), and `local_pk` the engine's own actor bytes.
pub(crate) fn verify_and_override(
    doc: &mut AutoCommit,
    snapshot: &ConflictSnapshot,
    delta_lamport: u64,
    incoming_pk: &[u8],
    local_lamport: u64,
    local_pk: &[u8],
) -> VerificationReport {
    let mut report = VerificationReport::default();
    let definitive = delta_lamport > local_lamport;

    // ── LWW scalar read-back ───────────────────────────────────────────────
    for conflict in &snapshot.lww {
        let Some(actual) = current_exid(doc, &conflict.key) else {
            continue;
        };
        let actual_incoming_won = actual == conflict.incoming_exid;
        let actual_local_won = actual == conflict.local_exid;
        let predicted_incoming_wins =
            lww_incoming_wins(delta_lamport, incoming_pk, local_lamport, local_pk);

        report.lww_checked += 1;

        if !definitive {
            report.indeterminate += 1;
            eprintln!(
                "[CRDT] LWW read-back key='{}': actual winner {} | rule (incoming lamport {} vs local {}) \
                 says incoming-wins:{} | zone=indeterminate (engine-wide local lamport is not per-key) — \
                 no override",
                conflict.key,
                actual,
                delta_lamport,
                local_lamport,
                predicted_incoming_wins,
            );
            continue;
        }

        // Definitive zone: the rule mandates the incoming op wins.
        if actual_incoming_won {
            eprintln!(
                "[CRDT] LWW read-back key='{}': actual winner=incoming | rule=incoming — OK",
                conflict.key
            );
            continue;
        }
        if !actual_local_won {
            // A third concurrent writer won — cannot attribute, never override.
            report.indeterminate += 1;
            eprintln!(
                "[CRDT] LWW read-back key='{}': winner unattributable ({}) — no override",
                conflict.key, actual
            );
            continue;
        }

        report.divergences += 1;
        eprintln!(
            "[CRDT] LWW DIVERGENCE key='{}': rule says incoming (lamport {} > local {}) but merged doc \
             kept local op {} — OVERRIDING with incoming value {:?}",
            conflict.key,
            delta_lamport,
            local_lamport,
            conflict.local_exid,
            conflict.incoming_value,
        );
        match doc.put(ROOT, conflict.key.as_str(), conflict.incoming_value.clone()) {
            Ok(()) => report.overrides_applied += 1,
            Err(e) => {
                report.overrides_failed += 1;
                eprintln!("[CRDT] LWW OVERRIDE FAILED key='{}': {e}", conflict.key);
            }
        }
    }

    // ── RGA ordering read-back ─────────────────────────────────────────────
    // Post-merge element index per ROOT-level list object, keyed by the
    // element's `(counter, actor)` identity so decoded insert ops can be
    // matched to their position in the merged sequence.
    let mut index_maps: Vec<(String, ObjId, HashMap<(u64, Vec<u8>), usize>)> = Vec::new();
    for item in doc.map_range(ROOT, ..) {
        if let automerge::ValueRef::Object(ObjType::List) = item.value {
            let item_id = item.id();
            let mut map = HashMap::new();
            for (i, li) in doc.list_range(&item_id, ..).enumerate() {
                if let Some(parts) = exid_parts(&li.id()) {
                    map.insert(parts, i);
                }
            }
            index_maps.push((item.key.to_string(), item_id, map));
        }
    }

    for conflict in &snapshot.rga {
        // Both elements must land in the SAME merged list for the ordering
        // rule to apply; pairs whose insertions targeted different lists (the
        // decoded op does not carry the ROOT key) self-filter here.
        let mut found = None;
        for (key, obj, map) in &index_maps {
            if let (Some(&idx_local), Some(&idx_incoming)) = (
                map.get(&conflict.local_element),
                map.get(&conflict.incoming_element),
            ) {
                found = Some((key.clone(), obj.clone(), idx_local, idx_incoming));
                break;
            }
        }
        let Some((key, obj, idx_local, idx_incoming)) = found else {
            continue;
        };

        let predicted_incoming_first =
            rga_incoming_has_priority(delta_lamport, incoming_pk, local_lamport, local_pk);
        let actual_incoming_first = idx_incoming < idx_local;

        report.rga_checked += 1;

        if !definitive {
            report.indeterminate += 1;
            eprintln!(
                "[CRDT] RGA read-back list='{}': actual order incoming-first:{} | rule (incoming lamport {} \
                 vs local {}) says incoming-first:{} | zone=indeterminate — no override",
                key, actual_incoming_first, delta_lamport, local_lamport, predicted_incoming_first,
            );
            continue;
        }

        if actual_incoming_first {
            eprintln!(
                "[CRDT] RGA read-back list='{}': actual order incoming-first | rule=incoming-first — OK",
                key
            );
            continue;
        }

        report.divergences += 1;
        eprintln!(
            "[CRDT] RGA DIVERGENCE list='{}': rule says incoming element first (lamport {} > local {}) but \
             merged order has local first — OVERRIDING order",
            key, delta_lamport, local_lamport,
        );
        // Delete both conflicting elements (higher index first so the lower one
        // does not shift) and re-insert them in the rule order at the run
        // start.  The corrective write is local, so every future peer merge
        // converges on the rule ordering.
        let (lo, hi) = (idx_local.min(idx_incoming), idx_local.max(idx_incoming));
        let result = (|| -> Result<(), automerge::AutomergeError> {
            doc.delete(&obj, hi)?;
            doc.delete(&obj, lo)?;
            doc.insert(&obj, lo, conflict.incoming_value.clone())?;
            doc.insert(&obj, lo + 1, conflict.local_value.clone())?;
            Ok(())
        })();
        match result {
            Ok(()) => report.overrides_applied += 1,
            Err(e) => {
                report.overrides_failed += 1;
                eprintln!("[CRDT] RGA OVERRIDE FAILED list='{}': {e}", key);
            }
        }
    }

    report
}

/// Current element ID at a ROOT-level scalar key (the actual winner).
fn current_exid(doc: &AutoCommit, key: &str) -> Option<ObjId> {
    doc.get(ROOT, key).ok().flatten().map(|(_, id)| id)
}

/// Extract `(counter, actor bytes)` from an element ID.
///
/// `ObjId`'s variant fields are crate-private, so we parse its documented
/// serialised layout (`ObjId::to_bytes`, see `automerge::exid`):
/// `[tag][LEB128 actor_len][actor bytes][LEB128 actor-index hint][LEB128
/// counter]`, version tag 0, type 1.  The actor-index hint is written first
/// and discarded; the counter is the `(counter, actor)` value that `Ord` and
/// `Display` use.
fn exid_parts(exid: &ObjId) -> Option<(u64, Vec<u8>)> {
    let b = exid.to_bytes();
    if b.len() < 2 || b[0] & 0b1111 != 0 {
        return None; // not serialization version 0
    }
    if b[0] >> 4 == 0 {
        return None; // ROOT
    }
    let mut pos = 1usize;
    let actor_len = leb128_u64(&b, &mut pos)?;
    let actor = b.get(pos..pos + actor_len as usize)?.to_vec();
    pos += actor_len as usize;
    let _actor_index_hint = leb128_u64(&b, &mut pos)?;
    let counter = leb128_u64(&b, &mut pos)?;
    Some((counter, actor))
}

fn leb128_u64(b: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *b.get(*pos)?;
        *pos += 1;
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use automerge::transaction::Transactable;

    #[test]
    fn exid_parts_matches_decoded_change_op_id() {
        let mut doc = AutoCommit::new().with_actor(automerge::ActorId::from(b"actor-bytes"));
        doc.put(ROOT, "k", 42_i64).unwrap();

        // The winning element's ExId must parse back to the same (counter,
        // actor) the change decoder computes for its single op.
        let items: Vec<_> = doc.map_range(ROOT, ..).collect();
        assert_eq!(items.len(), 1);
        let parts = exid_parts(&items[0].id()).expect("parse element ID");

        let mut doc = doc;
        let changes = doc.get_changes(&[]);
        let mut decoded = None;
        for c in changes {
            let exp = c.decode();
            if exp.operations.iter().any(|op| op.insert) {
                continue;
            }
            decoded = Some((
                exp.start_op.get(),
                exp.actor_id.to_bytes().to_vec(),
                exp.operations.len(),
            ));
        }
        let (start_op, actor, n_ops) = decoded.expect("a put change exists");
        // The put is the only op of its change → its ID is (start_op, actor).
        assert_eq!(parts.0, start_op);
        assert_eq!(parts.1, actor);
        assert_eq!(n_ops, 1);
    }

    #[test]
    fn exid_parts_root_is_none() {
        assert!(exid_parts(&ObjId::Root).is_none());
    }

    #[test]
    fn capture_conflicts_pairs_concurrent_same_position_inserts() {
        use automerge::{ObjType, ReadDoc};

        let base_bytes: Vec<u8> = {
            let mut base = AutoCommit::new();
            base.put_object(ROOT, "items", ObjType::List).unwrap();
            base.save()
        };

        let mut a = AutoCommit::load(&base_bytes)
            .unwrap()
            .with_actor(automerge::ActorId::from(b"actor-aaaa"));
        let mut b = AutoCommit::load(&base_bytes)
            .unwrap()
            .with_actor(automerge::ActorId::from(b"actor-bbbb"));

        let list_a = match a.get(ROOT, "items").unwrap() {
            Some((automerge::Value::Object(ObjType::List), id)) => id,
            _ => panic!("no list"),
        };
        let list_b = match b.get(ROOT, "items").unwrap() {
            Some((automerge::Value::Object(ObjType::List), id)) => id,
            _ => panic!("no list"),
        };
        a.insert(&list_a, 0, "A").unwrap();
        b.insert(&list_b, 0, "B").unwrap();

        let snapshot = capture_conflicts(&a, &b);
        assert_eq!(snapshot.rga.len(), 1, "one same-position insertion pair");
        assert!(snapshot.lww.is_empty(), "no scalar keys involved");
    }
}