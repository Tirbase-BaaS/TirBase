# State Inventory (CLAIM-31.1, PV-9.1)

This document enumerates **authoritative in-memory data structures** in production code. Each entry is annotated with either `PERSISTED: <table/location>` or `RECONSTRUCTIBLE: <source and method>`.

CI enforces registration via `scripts/check-state-inventory.sh` (CLAIM-31.2): production code that declares an authoritative in-memory structure with a `STATE-INVENTORY:` marker must have a corresponding entry here.

## tirbase-core

| Structure | Location | Classification |
|---|---|---|
| `CausalContaminationEngine.incidents` (`HashMap<IncidentId, IncidentContextObject>`) | `tirbase-core/src/contamination/mod.rs` <!-- STATE-INVENTORY: PERSISTED cce_incidents --> | `PERSISTED: cce_incidents` (SQLite, core storage DB) |
| `CausalContaminationEngine.composite_incidents` (`HashMap<IncidentId, CompositeIncidentInstance>`) | `tirbase-core/src/contamination/mod.rs` <!-- STATE-INVENTORY: PERSISTED cce_composite_incidents --> | `PERSISTED: cce_composite_incidents` |
| `CausalContaminationEngine.contaminated_rows` (`HashMap<(String,String), IncidentId>`, O(1) row index) | `tirbase-core/src/contamination/mod.rs` <!-- STATE-INVENTORY: PERSISTED cce_contaminated_rows --> | `PERSISTED: cce_contaminated_rows` |
| `SchemaMigrationEngine` active/quarantine state | `tirbase-core/src/migration/*` <!-- STATE-INVENTORY: RECONSTRUCTIBLE schema state --> | `RECONSTRUCTIBLE: schema quarantine/active state rebuilt from SQLite schema/quarantine tables and signed migration deltas` |
| `CoreHandle` runtime channels/caches (broadcast senders, non-authoritative queues) | `tirbase-core/src/api/mod.rs` <!-- STATE-INVENTORY: RECONSTRUCTIBLE runtime channels --> | `RECONSTRUCTIBLE: ephemeral runtime coordination; authoritative state lives in SQLite/WAL, DAG nodes, and persisted ledgers` |
| `DurabilitySubsystem` / CRDT hardening in-memory coordination | `tirbase-core/src/durability/*`, `tirbase-core/src/crdt/*` <!-- STATE-INVENTORY: RECONSTRUCTIBLE durability/crdt --> | `RECONSTRUCTIBLE: rebuilt from SQLite dag_nodes/dag_edges/automerge_docs/quarantine tables and hardening derived DB` |

## tirbase-gateway

| Structure | Location | Classification |
|---|---|---|
| Applied effects / anti-replay / idempotency / leases / ratchet runtime views | `tirbase-gateway/src/db/*` <!-- STATE-INVENTORY: PERSISTED primary.db --> | `PERSISTED: primary.db` (PrimaryLedger, WAL, synchronous=FULL) |
| Automerge/DAG/quarantine/sidecar runtime views | `tirbase-gateway/src/db/migrations.rs` <!-- STATE-INVENTORY: PERSISTED derived.db --> | `PERSISTED: derived.db` (DerivedLedger, WAL, synchronous=NORMAL); `RECONSTRUCTIBLE: signed delta log / DAG nodes on corruption per PV-9.3/CLAIM-31.5` |
| Node mode / in-process observability state | `tirbase-gateway/src/main.rs`, `tirbase-guard/src/node_mode.rs` <!-- STATE-INVENTORY: RECONSTRUCTIBLE node mode --> | `RECONSTRUCTIBLE: recomputed from boot checks, ledger state, and runtime events` |

## tirbase-guard

| Structure | Location | Classification |
|---|---|---|
| Guard policy/capability caches and pipeline-local admission state | `tirbase-guard/src/*` <!-- STATE-INVENTORY: RECONSTRUCTIBLE guard caches --> | `RECONSTRUCTIBLE: derived from signed policy bundles, persisted guard DB tables, and request inputs` |

## tirbase-drivers

| Structure | Location | Classification |
|---|---|---|
| Driver connection/runtime buffers | `tirbase-drivers/src/*` <!-- STATE-INVENTORY: RECONSTRUCTIBLE driver runtime --> | `RECONSTRUCTIBLE: re-established from configuration and device/protocol state; authoritative command/effect state is in guard/gateway ledgers` |

## Notes

- Primary ledgers (Applied_Effects_Ledger, security event log, monotonic counters, anti-rollback counters) are **never** rebuilt from the delta log (PV-9.3). Corruption triggers `Restricted` mode and operator intervention.
- Derived ledgers (CRDT state, contamination index) may be rebuilt from the signed delta log on corruption (PV-9.3).
- `PRAGMA quick_check` runs at boot on all ledgers; `PRAGMA integrity_check` is deferred to a maintenance window and is not required to complete within 30 seconds (PV-9.2, CLAIM-31.4).
