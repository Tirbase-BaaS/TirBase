//! Integration tests for Phase 14.1 — Report 5 closing the field-scenario gaps.
//!
//! Covers five scenarios:
//! 1. Late-arriving descendant taint (Req 10.3) — `tag_contamination_root`
//!    BFS walk reaches descendants inserted after the initial tag.
//! 2. Composite decomposition end-to-end (Req 10.6) — full `verify_data` →
//!    `decompose_composites_if_needed` → surviving sub-chain ICOs carry
//!    `affected_rows` re-marked CONTAMINATED.
//! 3. Contamination resolution production exposure (Req 11.1/11.2) — `verify_data`
//!    appends `DeltaTag::Resolved` + audit entries; `admin_close` transitions ICO to Closed.
//! 4. Token-expiry enforcement (Req 11.5) — `verify_data`/`admin_close` reject
//!    expired manager tokens via `verify_manager_auth`.
//! 5. Beacon signal loss production path (Req 15.4) —
//!    `AnchorAttestedLocation::on_beacon_signal_lost` → permanent
//!    mode reversion to SquadTagFallback.

#![cfg(feature = "native")]

use std::sync::{Arc, Mutex};

use tirbase_core::contamination::incident::{IncidentState, TaintSource};
use tirbase_core::contamination::CausalContaminationEngine;
use tirbase_core::crdt::dag::{ChangesetDag, DagNode};
use tirbase_core::crdt::delta::{DeltaId, DeltaTag, Ed25519Signature};
use tirbase_core::durability::anchor::{AnchorAttestedLocation, AnchorMode, BeaconRegistryEntry};
use tirbase_core::durability::receipt::BeaconToken;
use tirbase_core::errors::TirBaseError;
use tirbase_core::identity::keypair::sign;
use tirbase_core::identity::IdentityManager;
use tirbase_core::store::sqlite;

// ─── Shared helpers ──────────────────────────────────────────────────────────

/// Current time in microseconds since UNIX_EPOCH (mirrors `now_micros` in
/// `contamination::resolution` which is `pub(crate)`).
fn now_micros() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
}

/// A unique in-memory SQLite database, wrapped in Arc<Mutex<>> for sharing
/// between the CCE and a standalone ChangesetDag (needed because the CCE's
/// internal `dag` field is not public).
fn open_cce() -> (
    CausalContaminationEngine,
    Arc<Mutex<rusqlite::Connection>>,
) {
    let conn = sqlite::open(":memory:").expect("open in-memory SQLite");
    let conn = Arc::new(Mutex::new(conn));
    let cce = CausalContaminationEngine::new(conn.clone());
    (cce, conn)
}

/// Create a standalone ChangesetDag sharing the same connection.
fn dag_from_conn(conn: &Arc<Mutex<rusqlite::Connection>>) -> ChangesetDag {
    ChangesetDag::new(conn.clone())
}

/// Insert a minimal DagNode into a ChangesetDag (bypassing the CCE's private dag field).
fn insert_node(dag: &mut ChangesetDag, id: [u8; 32], parents: Vec<[u8; 32]>) {
    dag.insert(DagNode {
        delta_id: id,
        payload: vec![],
        parent_ids: parents,
        actor_id: b"actor".to_vec(),
        lamport: 1,
        schema_hash: [0u8; 32],
        compacted: false,
        delta_bytes: None,
        author_did: "did:key:z6MkTestAuthor".to_string(),
    })
    .expect("insert DagNode");
}

/// Read `tags_json` for a Delta directly from SQLite.
/// `read_tags_from_db` is `pub(crate)` so integration tests query SQL directly.
fn read_tags(conn: &rusqlite::Connection, delta_id: &[u8; 32]) -> Vec<DeltaTag> {
    let json: Option<String> = conn
        .query_row(
            "SELECT tags_json FROM dag_nodes WHERE id = ?1",
            rusqlite::params![delta_id.as_ref()],
            |row| row.get(0),
        )
        .ok();

    json.as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

/// Sign `payload` and return an `Ed25519Signature`.
fn sign_payload(secret: &[u8; 32], payload: &[u8]) -> Ed25519Signature {
    sign(secret, payload).expect("sign")
}

/// Construct the beacon token signing payload (mirrors `beacon_token_signing_payload`
/// which is `pub(crate)`).
fn beacon_signing_payload(epoch: u64, location_claim: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + location_claim.len());
    payload.extend_from_slice(&epoch.to_le_bytes());
    payload.extend_from_slice(location_claim.as_bytes());
    payload
}

/// Build a fresh manager identity and return (manager_did, signing_key_seed).
fn make_manager() -> (String, [u8; 32]) {
    let mgr = IdentityManager::init_in_memory().unwrap();
    let secret = mgr.signing_key_bytes();
    (mgr.did().to_string(), secret)
}

// ─── Test 1: Late-arriving descendant taint (Req 10.3) ──────────────────────

/// Scenario: A revocation delta arrives for a root Delta. At the time `tag_contamination_root`
/// is first called, only `early_child` exists as a descendant. Then `late_child`
/// is inserted as a new child of the root (simulating a peer Delta arriving after
/// the initial taint walk). A subsequent `tag_contamination_root` call must reach
/// `late_child` via the BFS walk, proving the walk is live and not stale-cached.
#[test]
fn test_late_arriving_descendant_taint() {
    let (mut cce, conn) = open_cce();
    let mut dag = dag_from_conn(&conn);

    let root_id: DeltaId = [0x01u8; 32];
    let early_child: DeltaId = [0x02u8; 32];
    let late_child: DeltaId = [0x03u8; 32];

    // Build: root → early_child (both present before tagging).
    insert_node(&mut dag, root_id, vec![]);
    insert_node(&mut dag, early_child, vec![root_id]);

    // Tag the root — BFS should walk to early_child only.
    let ico_id = cce
        .tag_contamination_root(
            root_id,
            TaintSource::DeviceRevocation {
                revocation_delta_id: root_id,
            },
        )
        .expect("tag_contamination_root should succeed");

    // Confirm early_child was tagged with Contaminated.
    {
        let lock = conn.lock().unwrap();
        let tags = read_tags(&lock, &early_child);
        assert!(
            tags.iter().any(|t| matches!(
                t,
                DeltaTag::Contaminated { incident_id, .. } if *incident_id == ico_id
            )),
            "early_child must carry a Contaminated tag from the initial BFS walk"
        );
    }

    // Now simulate the late-arriving descendant: insert it into the DAG.
    insert_node(&mut dag, late_child, vec![root_id]);

    // Re-tag the root to prove the BFS walk reaches the late descendant.
    let source = TaintSource::DeviceRevocation {
        revocation_delta_id: root_id,
    };
    let _ = cce
        .tag_contamination_root(root_id, source)
        .expect("re-tag root");

    // late_child must now have a Contaminated tag.
    let lock = conn.lock().unwrap();
    let tags = read_tags(&lock, &late_child);
    assert!(
        tags.iter().any(|t| matches!(t, DeltaTag::Contaminated { .. })),
        "late-arriving descendant must be caught by a subsequent tag_contamination_root BFS walk"
    );
}

// ─── Test 2: Composite decomposition end-to-end (Req 10.6) ────────────────────

/// Scenario: Two contamination chains (A: root_a → shared, B: root_b → shared)
/// share a descendant `shared`, forming a composite incident.  When `root_a` is
/// VERIFY_DATA'd (resolved), the composite decomposes and `root_b`'s surviving
/// sub-chain is re-registered as a fresh OPEN ICO with `affected_rows`
/// re-marked CONTAMINATED in the projection store.
///
/// Acceptance:
/// - After resolving root_a, a new OPEN ICO exists for root_b only.
/// - Any projection rows attributed to the surviving lineage remain CONTAMINATED.
#[test]
fn test_composite_decomposition_surviving_subchain_remains_contaminated() {
    let (mut cce, conn) = open_cce();
    let mut dag = dag_from_conn(&conn);

    let root_a: DeltaId = [0xAAu8; 32];
    let root_b: DeltaId = [0xBBu8; 32];
    let shared: DeltaId = [0xCCu8; 32]; // child of both root_a and root_b

    // Build the diamond DAG.
    insert_node(&mut dag, root_a, vec![]);
    insert_node(&mut dag, root_b, vec![]);
    insert_node(&mut dag, shared, vec![root_a, root_b]);

    // Create a projection table so resolve_affected_rows finds rows.
    {
        let lock = conn.lock().unwrap();
        lock.execute_batch(
            "CREATE TABLE IF NOT EXISTS proj_reports \
             (key TEXT PRIMARY KEY, data_json TEXT NOT NULL, \
              contaminated INTEGER NOT NULL DEFAULT 0); \
             INSERT OR IGNORE INTO proj_reports (key, data_json) \
             VALUES ('row-1', '{\"v\":1}'), ('row-2', '{\"v\":2}');",
        )
        .expect("setup proj_reports");
    }

    let (mgr_did, mgr_secret) = make_manager();

    // Tag root_a → ICO_A covers {root_a, shared}.
    cce.tag_contamination_root(
        root_a,
        TaintSource::DeviceRevocation {
            revocation_delta_id: root_a,
        },
    )
    .expect("tag root_a");

    // Tag root_b → since `shared` is already contaminated by ICO_A, a composite
    // should form. The returned ID is the composite incident ID.
    let composite_id = cce
        .tag_contamination_root(
            root_b,
            TaintSource::DeviceRevocation {
                revocation_delta_id: root_b,
            },
        )
        .expect("tag root_b");

    // The composite_id should not be a regular ICO — it's a composite.
    // After decomposition, it transitions to Decomposed state, so the regular
    // ICO lookup returns None.
    assert!(
        cce.get_incident(composite_id).expect("get incident").is_none(),
        "composite incident should not be found via get_incident (it lives in composite_incidents)"
    );

    // Resolve root_a — this should decompose the composite and re-register
    // root_b as a fresh OPEN ICO.
    let expiry = now_micros() + 3_600_000_000;
    let sig_a = sign_payload(&mgr_secret, &root_a);
    cce.verify_data(root_a, mgr_did.clone(), sig_a, expiry)
        .expect("verify_data root_a");

    // After decomposition, a new OPEN ICO for root_b must exist.
    // Use open_incidents() (public API) to find it.
    let open_icos = cce.open_incidents().expect("open_incidents");
    assert!(
        open_icos.len() >= 1,
        "at least one OPEN ICO must exist for the surviving sub-chain"
    );

    let surviving = open_icos
        .iter()
        .find(|ico| ico.contamination_roots.contains(&root_b))
        .expect("surviving ICO for root_b must exist");
    assert_eq!(
        surviving.state,
        IncidentState::Open,
        "surviving ICO must be Open"
    );
    assert!(
        surviving
            .affected_rows
            .iter()
            .any(|r| r.table == "reports"),
        "surviving ICO must have affected_rows populated for the unresolved lineage"
    );

    // Projection rows must still be CONTAMINATED via the unresolved lineage
    // (root_b's sub-chain still has an unresolved root).
    let lock = conn.lock().unwrap();
    let contaminated: i64 = lock
        .query_row(
            "SELECT contaminated FROM proj_reports WHERE key = 'row-1'",
            [],
            |row| row.get(0),
        )
        .expect("read contaminated flag");
    assert_eq!(
        contaminated, 1,
        "affected rows must remain CONTAMINATED via the unresolved lineage after decomposition"
    );

    // Verify root_a now has a Resolved tag in the DAG.
    let tags_root_a = read_tags(&lock, &root_a);
    assert!(
        tags_root_a
            .iter()
            .any(|t| matches!(t, DeltaTag::Resolved { .. })),
        "root_a must carry a Resolved tag after verify_data"
    );
}

// ─── Test 3: Contamination resolution production exposure (Req 11.1/11.2) ────

/// Scenario: A full verify→close lifecycle through the CCE's public API,
/// verifying that `verify_data` appends `DeltaTag::Resolved` + an audit entry,
/// and `admin_close` transitions the ICO to Closed with an audit entry.
///
/// Acceptance:
/// - After `verify_data`, root has a `DeltaTag::Resolved` in `dag_nodes.tags_json`.
/// - An `AuditEntry` with `AuditOperation::VerifyData` is present.
/// - After `admin_close`, the ICO state is `Closed` and an `AdminClose` audit
///   entry was appended.
#[test]
fn test_verify_data_and_admin_close_audit_trail() {
    let (mut cce, conn) = open_cce();
    let mut dag = dag_from_conn(&conn);

    let root_id: DeltaId = [0xA1u8; 32];
    let child: DeltaId = [0xA2u8; 32];
    insert_node(&mut dag, root_id, vec![]);
    insert_node(&mut dag, child, vec![root_id]);

    let (mgr_did, mgr_secret) = make_manager();

    // Tag the root.
    let ico_id = cce
        .tag_contamination_root(
            root_id,
            TaintSource::DeviceRevocation {
                revocation_delta_id: root_id,
            },
        )
        .expect("tag root");

    let expiry = now_micros() + 3_600_000_000;
    let sig = sign_payload(&mgr_secret, &root_id);

    // verify_data — must succeed and leave auditable traces.
    cce.verify_data(root_id, mgr_did.clone(), sig, expiry)
        .expect("verify_data");

    // Check the Resolved tag directly in dag_nodes.tags_json.
    {
        let lock = conn.lock().unwrap();
        let tags = read_tags(&lock, &root_id);
        assert!(
            tags.iter().any(|t| matches!(t, DeltaTag::Resolved { .. })),
            "root must carry a Resolved tag after verify_data"
        );
    }

    let ico = cce
        .get_incident(ico_id)
        .expect("get incident ok")
        .expect("ICO exists");
    assert!(
        ico
            .audit_log
            .iter()
            .any(|e| matches!(
                e.operation,
                tirbase_core::contamination::incident::AuditOperation::VerifyData
            )),
        "VerifyData audit entry must be present"
    );

    // admin_close — must succeed and transition to Closed.
    let sig_close = sign_payload(&mgr_secret, ico_id.as_bytes());
    cce.admin_close(ico_id, mgr_did.clone(), sig_close, expiry)
        .expect("admin_close");

    let ico_after = cce
        .get_incident(ico_id)
        .expect("get incident ok")
        .expect("ICO exists");
    assert_eq!(
        ico_after.state,
        IncidentState::Closed,
        "ICO must be Closed after admin_close"
    );
    assert!(
        ico_after
            .audit_log
            .iter()
            .any(|e| matches!(
                e.operation,
                tirbase_core::contamination::incident::AuditOperation::AdminClose
            )),
        "AdminClose audit entry must be present"
    );
    assert_eq!(
        ico_after.audit_log.len(),
        ico.audit_log.len() + 1,
        "exactly one audit entry must be appended by admin_close"
    );
}

// ─── Test 4: Token-expiry enforcement (Req 11.5) ──────────────────────────────

/// Scenario: `verify_data` and `admin_close` must reject expired manager tokens.
/// `verify_manager_auth` checks `token_expiry <= now_micros()`.
///
/// Acceptance:
/// - A token expiring in the past → `AuthorisationFailed("manager token expired")`.
/// - A token expiring in the future → succeeds.
#[test]
fn test_token_expiry_rejects_expired_manager_token() {
    let (mut cce, conn) = open_cce();
    let mut dag = dag_from_conn(&conn);

    let root_id: DeltaId = [0xB1u8; 32];
    insert_node(&mut dag, root_id, vec![]);

    let (mgr_did, mgr_secret) = make_manager();

    let ico_id = cce
        .tag_contamination_root(
            root_id,
            TaintSource::DeviceRevocation {
                revocation_delta_id: root_id,
            },
        )
        .expect("tag root");

    let now = now_micros();

    // --- verify_data with expired token ---
    let expired = now - 1; // 1 microsecond in the past
    let sig = sign_payload(&mgr_secret, &root_id);
    let result = cce.verify_data(root_id, mgr_did.clone(), sig, expired);
    assert!(
        matches!(
            result,
            Err(TirBaseError::AuthorisationFailed { ref reason })
                if reason.contains("manager token expired")
        ),
        "verify_data must reject an expired token: {result:?}"
    );

    // --- verify_data with valid (future) token must not be blocked by expiry ---
    let valid = now + 3_600_000_000;
    let sig2 = sign_payload(&mgr_secret, &root_id);
    cce.verify_data(root_id, mgr_did.clone(), sig2, valid)
        .expect("verify_data with valid token must succeed");

    // --- admin_close with expired token ---
    let sig_close_expired = sign_payload(&mgr_secret, ico_id.as_bytes());
    let result = cce.admin_close(ico_id, mgr_did.clone(), sig_close_expired, expired);
    assert!(
        matches!(
            result,
            Err(TirBaseError::AuthorisationFailed { ref reason })
                if reason.contains("manager token expired")
        ),
        "admin_close must reject an expired token: {result:?}"
    );

    // --- admin_close with valid token must succeed ---
    let sig_close_valid = sign_payload(&mgr_secret, ico_id.as_bytes());
    cce.admin_close(ico_id, mgr_did, sig_close_valid, valid)
        .expect("admin_close with valid token must succeed");
}

// ─── Test 5: Beacon signal loss production path (Req 15.4) ────────────────────

/// Scenario: An `AnchorAttestedLocation` in `BeaconAttested` mode verifies
/// beacon-signed location tokens.  When `on_beacon_signal_lost` is called, the
/// subsystem permanently reverts to `SquadTagFallback` mode — receipts are then
/// counted by squad tag, not beacon-attested location.
///
/// This mirrors the production call chain:
/// `receive_receipt` → anchor in `SquadTagFallback` → `peer_has_valid_token`
/// returns `false` → no beacon token counting.
///
/// Acceptance:
/// - Before signal loss: `peer_has_valid_token` returns true for a valid token.
/// - After signal loss: `mode()` is `SquadTagFallback`, `degradation_log` has one entry,
///   and `peer_has_valid_token` returns false for all tokens.
#[test]
fn test_beacon_signal_loss_permanent_reversion() {
    // Set up a beacon identity.
    let beacon = IdentityManager::init_in_memory().expect("beacon identity");
    let beacon_pk = beacon.public_key_bytes();
    let beacon_did = beacon.did().to_string();

    let registry = vec![BeaconRegistryEntry {
        beacon_did: beacon_did.clone(),
        public_key: beacon_pk,
    }];

    let mut anchor = AnchorAttestedLocation::new(registry, 1);

    // Before signal loss: mode is BeaconAttested.
    assert_eq!(anchor.mode(), AnchorMode::BeaconAttested);

    // Create a valid beacon token for epoch 1.
    let epoch = 1u64;
    let location = "sector-A";
    let payload = beacon_signing_payload(epoch, location);
    let beacon_sig = beacon.sign(&payload).expect("beacon sign");

    let token = BeaconToken {
        beacon_did: beacon_did.clone(),
        beacon_signature: Ed25519Signature::from_bytes(beacon_sig),
        epoch,
        location_claim: location.to_string(),
        issued_at: now_micros(),
    };

    // A valid token should verify.
    anchor
        .verify_beacon_token(&token)
        .expect("valid beacon token must verify");

    // peer_has_valid_token must return true in BeaconAttested mode.
    assert!(
        anchor.peer_has_valid_token(&token),
        "peer_has_valid_token must return true with a valid token in BeaconAttested mode"
    );

    // Simulate beacon signal loss (Req 15.4).
    let affected_dids = vec!["did:key:z6MkPeer1".to_string()];
    anchor
        .on_beacon_signal_lost(now_micros(), affected_dids.clone())
        .expect("on_beacon_signal_lost must succeed");

    // Mode must have reverted permanently to SquadTagFallback.
    assert_eq!(
        anchor.mode(),
        AnchorMode::SquadTagFallback,
        "mode must revert to SquadTagFallback after beacon signal loss"
    );

    // The degradation log must contain exactly one entry.
    assert_eq!(
        anchor.degradation_log().len(),
        1,
        "exactly one TransportDegradationEvent must be logged"
    );

    // After reversion, peer_has_valid_token must return false for ALL tokens
    // (spatial diversity falls back to squad tags entirely).
    assert!(
        !anchor.peer_has_valid_token(&token),
        "peer_has_valid_token must return false after signal loss (SquadTagFallback)"
    );

    // Verify the degradation event carries the affected peer DIDs.
    let event = &anchor.degradation_log()[0];
    assert_eq!(event.affected_peer_dids, affected_dids);
    assert!(
        event.reason.contains("Beacon signal lost"),
        "degradation event reason must mention beacon signal loss"
    );
}

// ─── Test 6: Late-arriving descendant of resolved root receives Decontaminated ─

/// Scenario: A contamination root is tagged and an ICO is created.  Then a
/// late-arriving Delta is inserted as a descendant of the root *after* the
/// initial `tag_contamination_root` snapshot.  When `verify_data` resolves the
/// root, the late-arrival walk must discover the new descendant via the live DAG
/// and append `DeltaTag::Decontaminated` to it.
///
/// Acceptance:
/// - The late-arriving Delta must carry `DeltaTag::Decontaminated` after
///   `verify_data` resolves the root.
#[test]
fn test_late_arriving_descendant_of_resolved_root_is_decontaminated() {
    let (mut cce, conn) = open_cce();
    let mut dag = dag_from_conn(&conn);

    let root_id: DeltaId = [0x11u8; 32];
    let early_child: DeltaId = [0x12u8; 32];
    let late_child: DeltaId = [0x13u8; 32];

    // Build: root → early_child (both present before tagging).
    insert_node(&mut dag, root_id, vec![]);
    insert_node(&mut dag, early_child, vec![root_id]);

    // Tag the root — snapshot covers {root_id, early_child}.
    let ico_id = cce
        .tag_contamination_root(
            root_id,
            TaintSource::DeviceRevocation {
                revocation_delta_id: root_id,
            },
        )
        .expect("tag_contamination_root should succeed");

    // Confirm early_child was tagged with Contaminated.
    {
        let lock = conn.lock().unwrap();
        let tags = read_tags(&lock, &early_child);
        assert!(
            tags.iter().any(|t| matches!(
                t,
                DeltaTag::Contaminated { incident_id, .. } if *incident_id == ico_id
            )),
            "early_child must carry a Contaminated tag from the initial BFS walk"
        );
    }

    // Now simulate the late-arriving descendant: insert it into the DAG
    // AFTER the root was tagged.
    insert_node(&mut dag, late_child, vec![root_id]);

    // Resolve the root via verify_data.
    let (mgr_did, mgr_secret) = make_manager();
    let expiry = now_micros() + 3_600_000_000;
    let sig = sign_payload(&mgr_secret, &root_id);
    cce.verify_data(root_id, mgr_did, sig, expiry)
        .expect("verify_data should succeed");

    // The late-arriving descendant must now have a Decontaminated tag.
    let lock = conn.lock().unwrap();
    let tags = read_tags(&lock, &late_child);
    assert!(
        tags.iter().any(|t| matches!(
            t,
            DeltaTag::Decontaminated { incident_id, .. } if *incident_id == ico_id
        )),
        "late-arriving descendant of resolved root must carry DeltaTag::Decontaminated: {tags:?}"
    );

    // early_child should also still have Decontaminated (from the snapshot walk).
    let early_tags = read_tags(&lock, &early_child);
    assert!(
        early_tags.iter().any(|t| matches!(
            t,
            DeltaTag::Decontaminated { incident_id, .. } if *incident_id == ico_id
        )),
        "early_child must carry DeltaTag::Decontaminated after root resolution"
    );
}

// ─── Test 7: Late-arriving descendant of unresolved root receives Contaminated ─

/// Scenario: Two contamination roots (root_a, root_b) share a descendant `shared`,
/// forming a composite incident.  After the composite is created, a late-arriving
/// Delta is inserted as a descendant of root_b (the root that will remain
/// unresolved).  When root_a is resolved via `verify_data`, the late-arrival walk
/// must find the late descendant of the *unresolved* root_b and tag it
/// `DeltaTag::Contaminated`.
///
/// Acceptance:
/// - The late-arriving Delta must carry `DeltaTag::Contaminated` after
///   `verify_data` resolves root_a (because root_b is still unresolved).
#[test]
fn test_late_arriving_descendant_of_unresolved_root_is_contaminated() {
    let (mut cce, conn) = open_cce();
    let mut dag = dag_from_conn(&conn);

    let root_a: DeltaId = [0x21u8; 32];
    let root_b: DeltaId = [0x22u8; 32];
    let shared: DeltaId = [0x23u8; 32]; // descendant of both roots
    let late_child: DeltaId = [0x24u8; 32]; // late descendant of root_b only

    // Build the diamond: root_a → shared, root_b → shared.
    insert_node(&mut dag, root_a, vec![]);
    insert_node(&mut dag, root_b, vec![]);
    insert_node(&mut dag, shared, vec![root_a, root_b]);

    // Tag root_a → ICO_A covers {root_a, shared}.
    let ico_a_id = cce
        .tag_contamination_root(
            root_a,
            TaintSource::DeviceRevocation {
                revocation_delta_id: root_a,
            },
        )
        .expect("tag root_a");

    // Tag root_b → composite forms (shared is reachable from both roots).
    let composite_id = cce
        .tag_contamination_root(
            root_b,
            TaintSource::DeviceRevocation {
                revocation_delta_id: root_b,
            },
        )
        .expect("tag root_b");

    // The second tag should have produced a composite incident.
    // Composite ICOs live in `composite_incidents`, not `incidents`, so
    // `get_incident` (which queries `incidents` only) should return None.
    assert!(
        cce.get_incident(composite_id).expect("get incident").is_none(),
        "composite incident should not be found via get_incident (it lives in composite_incidents)"
    );

    // Now simulate the late-arriving descendant: insert it as a child of root_b
    // AFTER both roots were tagged and the composite was formed.
    insert_node(&mut dag, late_child, vec![root_b]);

    // Resolve root_a via verify_data — root_b remains unresolved.
    let (mgr_did, mgr_secret) = make_manager();
    let expiry = now_micros() + 3_600_000_000;
    let sig_a = sign_payload(&mgr_secret, &root_a);
    cce.verify_data(root_a, mgr_did, sig_a, expiry)
        .expect("verify_data root_a should succeed");

    // The late-arriving descendant of the unresolved root_b must now have a
    // Contaminated tag from the late-arrival walk.
    let lock = conn.lock().unwrap();
    let tags = read_tags(&lock, &late_child);
    assert!(
        tags.iter().any(|t| matches!(
            t,
            DeltaTag::Contaminated { incident_id, .. }
                if *incident_id == composite_id || *incident_id == ico_a_id
        )),
        "late-arriving descendant of unresolved root must carry DeltaTag::Contaminated: {tags:?}"
    );
}
