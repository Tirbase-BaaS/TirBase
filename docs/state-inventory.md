# State Inventory (CLAIM-31.1, PV-9.1)

This document classifies **authoritative in-memory data structures** in
production code as either `PERSISTED: <table/location>` or
`RECONSTRUCTIBLE: <source and method>`.

CI enforces registration via `scripts/check-state-inventory.sh` (CLAIM-31.2).
The script does not trust annotations: it scans the production source roots
(`tirbase-core`, `tirbase-guard`, `tirbase-gateway`, `tirbase-drivers`) for every
named-field `struct`, excluding `#[cfg(test)]` items and `tests/` directories,
and fails if a struct is not listed below with both its name and its file.

The per-struct list at the bottom is generated.  After adding or removing a
struct, regenerate it and commit the result:

```bash
python3 scripts/state_inventory_scan.py --write
```

## Persisted / reconstructible state of record

| Structure | Location | Classification |
|---|---|---|
| `CausalContaminationEngine.incidents` (`HashMap<IncidentId, IncidentContextObject>`) | `tirbase-core/src/contamination/mod.rs` | `PERSISTED: cce_incidents` (SQLite, core storage DB) |
| `CausalContaminationEngine.composite_incidents` (`HashMap<IncidentId, CompositeIncidentInstance>`) | `tirbase-core/src/contamination/mod.rs` | `PERSISTED: cce_composite_incidents` |
| `CausalContaminationEngine.contaminated_rows` (`HashMap<(String,String), IncidentId>`, O(1) row index) | `tirbase-core/src/contamination/mod.rs` | `PERSISTED: cce_contaminated_rows` |
| `SchemaMigrationEngine` active/quarantine state | `tirbase-core/src/migration/mod.rs` | `RECONSTRUCTIBLE: schema quarantine/active state rebuilt from SQLite schema/quarantine tables and signed migration deltas` |
| `CoreHandle` runtime channels/caches (broadcast senders, non-authoritative queues) | `tirbase-core/src/api/mod.rs` | `RECONSTRUCTIBLE: ephemeral runtime coordination; authoritative state lives in SQLite/WAL, DAG nodes, and persisted ledgers` |
| `DurabilitySubsystem` / CRDT hardening in-memory coordination | `tirbase-core/src/durability/mod.rs`, `tirbase-core/src/crdt/mod.rs` | `RECONSTRUCTIBLE: rebuilt from SQLite dag_nodes/dag_edges/automerge_docs/quarantine tables and hardening derived DB` |
| Applied effects / anti-replay / idempotency / leases / ratchet runtime views | `tirbase-gateway/src/db/mod.rs` | `PERSISTED: primary.db` (PrimaryLedger, WAL, synchronous=FULL) |
| Automerge/DAG/quarantine/sidecar runtime views | `tirbase-gateway/src/db/migrations.rs` | `PERSISTED: derived.db` (DerivedLedger, WAL, synchronous=NORMAL); `RECONSTRUCTIBLE: signed delta log / DAG nodes, sidecar_ledger, schema_quarantine, and rate_quarantine_summary from the core store on corruption per PV-9.3/CLAIM-31.5` |
| Node mode / in-process observability state | `tirbase-gateway/src/main.rs`, `tirbase-guard/src/node_mode.rs` | `RECONSTRUCTIBLE: recomputed from boot checks, ledger state, and runtime events` |
| `RevocationSubsystem` / `PendingRevocationStore` (revocation maps) | `tirbase-core/src/auth/revocation.rs` | `RECONSTRUCTIBLE: rebuilt from signed revocation deltas and verified manager signatures` |
| `RevokedMigrationRegistry` (revoked migration set) | `tirbase-core/src/migration/revocation.rs` | `RECONSTRUCTIBLE: rebuilt from signed migration-revocation deltas and known migration hashes` |
| `SaturateModeStateMachine` / `SaturateLease` | `tirbase-core/src/transport/saturate.rs` | `RECONSTRUCTIBLE: recomputed from signed activation tokens, heartbeat renewals, and the monotonic time source` |
| `QuarantineLedger` | `tirbase-core/src/migration/quarantine.rs` | `PERSISTED: quarantine table` (SQLite core store; IndexedDB on WASM) |
| `SchemaQuarantineLedger` | `tirbase-core/src/crdt/schema_quarantine.rs` | `PERSISTED: schema_quarantine table` (replayable per PV-6.7) |
| `SideCarLedger` | `tirbase-core/src/migration/sidecar.rs` | `PERSISTED: sidecar_ledger table` (SQLite core store; IndexedDB on WASM) |

## Notes

- Primary ledgers (Applied_Effects_Ledger, security event log, monotonic counters, anti-rollback counters) are **never** rebuilt from the delta log (PV-9.3). Corruption triggers `Restricted` mode and operator intervention.
- Derived ledgers (CRDT state, contamination index, sidecar/quarantine replay tables) may be rebuilt from the signed delta log on corruption (PV-9.3).
- `PRAGMA quick_check` runs at boot on all ledgers; `PRAGMA integrity_check` is deferred to a maintenance window and is not required to complete within 30 seconds (PV-9.2, CLAIM-31.4).

<!-- BEGIN GENERATED STRUCT INVENTORY -->

The rows below are generated from the production source by
`scripts/state_inventory_scan.py`.  Every named-field struct in the
source roots must appear here.  Regenerate with:

```bash
python3 scripts/state_inventory_scan.py --write
```

| Structure | Location | Classification |
|---|---|---|
| `ActiveExecutionProfile` | `tirbase-core/src/migration/profile.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ActivePolicyState` | `tirbase-guard/src/policy.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ActuatingEntry` | `tirbase-gateway/src/db/applied_effects_ledger.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ActuationPermit` | `tirbase-guard/src/permit.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ActuationPermitRef` | `tirbase-drivers/src/driver_trait.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ActuationPermitRef` | `tirbase-guard/src/permit.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ActuatorHandles` | `tirbase-guard/src/guard.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `AdminState` | `tirbase-gateway/src/admin.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `AdmitContext` | `tirbase-guard/src/admit.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `AdmitPipelineState` | `tirbase-guard/src/admit.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `AdmittedCommand` | `tirbase-guard/src/guard.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `AffectedRow` | `tirbase-core/src/contamination/incident.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `AnchorAttestedLocation` | `tirbase-core/src/durability/anchor.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `AntiReplayWindow` | `tirbase-guard/src/anti_replay.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `AntiReplayWindowReset` | `tirbase-guard/src/anti_replay.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `AntiReplayWindowRow` | `tirbase-gateway/src/db/anti_replay_windows.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `AppendOnlySecurityEventCollection` | `tirbase-core/src/transport/security_event_sync.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `AppliedEffectRow` | `tirbase-gateway/src/db/applied_effects_ledger.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `AuditEntry` | `tirbase-core/src/contamination/incident.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `AuthorizedRoleSigner` | `tirbase-guard/src/trust_root.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `BatcherState` | `tirbase-gateway/src/event_batcher.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `BeaconRegistryEntry` | `tirbase-core/src/durability/anchor.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `BeaconToken` | `tirbase-core/src/durability/receipt.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `BiscuitClaims` | `tirbase-core/src/auth/biscuit.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `BleAdapter` | `tirbase-core/src/transport/ble.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `BrokenRange` | `tirbase-gateway/src/security_log_export.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CacheMetrics` | `tirbase-core/src/crdt/memory_budget.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CacheMetricsHandle` | `tirbase-core/src/crdt/memory_budget.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CanonicalDeltaPayload` | `tirbase-core/src/crdt/delta.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CapabilityManager` | `tirbase-core/src/auth/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CategoryRateLimiter` | `tirbase-gateway/src/security_log.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CausalContaminationEngine` | `tirbase-core/src/contamination/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ChainHashBody` | `tirbase-gateway/src/security_log.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ChainRecoveryPayload` | `tirbase-guard/src/lockdown.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ChainRecoveryRequest` | `tirbase-gateway/src/admin.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ChallengeNonce` | `tirbase-guard/src/admit.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ChallengeNonceRow` | `tirbase-gateway/src/db/challenge_nonces.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ChallengeRequest` | `tirbase-gateway/src/admin.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ChangesetDag` | `tirbase-core/src/crdt/dag.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CheapCheckRejection` | `tirbase-core/src/crdt/hardening.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CheckpointConfig` | `tirbase-gateway/src/security_log.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ChildDriverConfig` | `tirbase-guard/src/driver_proxy.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ClearUnknownPayload` | `tirbase-gateway/src/admin.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ClearUnknownRequest` | `tirbase-gateway/src/admin.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `Cli` | `tirbase-gateway/src/main.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CloudAnchorAcknowledgement` | `tirbase-gateway/src/cloud_anchor.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CloudAnchorCheckpointReport` | `tirbase-gateway/src/cloud_anchor.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CloudAnchorClient` | `tirbase-gateway/src/cloud_anchor.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CloudAnchorIngress` | `tirbase-gateway/src/cloud_anchor.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CloudAnchorRequest` | `tirbase-gateway/src/cloud_anchor.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CloudAnchorResponse` | `tirbase-gateway/src/cloud_anchor.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CloudLedger` | `tirbase-core/src/durability/cloud_ledger.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CloudLedgerConnection` | `tirbase-core/src/durability/cloud_ledger.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CloudOutboundQueue` | `tirbase-core/src/durability/cloud_queue.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CloudSyncResult` | `tirbase-core/src/durability/cloud_queue.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ColdRoomSimDriver` | `tirbase-drivers/src/cold_room_sim.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CommandEnvelope` | `tirbase-guard/src/epoch.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CommandGuard` | `tirbase-guard/src/guard.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CommandRuntime` | `tirbase-gateway/src/main.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CommandTokenClaims` | `tirbase-core/src/auth/command_token.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CompactionSnapshot` | `tirbase-core/src/store/indexed_db.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CompositeIncidentInstance` | `tirbase-core/src/contamination/incident.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ConflictSnapshot` | `tirbase-core/src/crdt/verify.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ConvergentState` | `tirbase-core/src/crdt/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CoreHandle` | `tirbase-core/src/api/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CrashLoopTracker` | `tirbase-guard/src/lockdown.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `CrdtEngine` | `tirbase-core/src/crdt/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DagNode` | `tirbase-core/src/crdt/dag.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DecidedOutcomeRow` | `tirbase-gateway/src/db/decided_outcomes.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DecommissionCredential` | `tirbase-guard/src/epoch.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DecompositionResult` | `tirbase-core/src/contamination/resolution.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `Delta` | `tirbase-core/src/crdt/delta.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DeltaDurabilityState` | `tirbase-core/src/durability/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DeltaFragment` | `tirbase-core/src/transport/fragment.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DeltaRejectionRecord` | `tirbase-core/src/crdt/failure.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DeploymentConfig` | `tirbase-core/src/api/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DeviceEpoch` | `tirbase-guard/src/epoch.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DeviceIdentity` | `tirbase-guard/src/enrollment.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DeviceModel` | `tirbase-drivers/src/driver_trait.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DeviceRevocationStatus` | `tirbase-core/src/auth/revocation.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DiagnosticEntry` | `tirbase-core/src/diagnostics/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DiscoveredPeer` | `tirbase-core/src/transport/discovery.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DriftHistoryRow` | `tirbase-gateway/src/db/drift_rate_history.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DriftRecord` | `tirbase-guard/src/admit.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DriftSummaryRow` | `tirbase-gateway/src/db/drift_rate_history.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DriftTimingSummary` | `tirbase-guard/src/admit.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DriverChildSocket` | `tirbase-guard/src/driver_proxy.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DriverHealth` | `tirbase-drivers/src/driver_trait.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DriverLifecycle` | `tirbase-drivers/src/lifecycle.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DriverProxy` | `tirbase-guard/src/driver_proxy.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DriverSocketPair` | `tirbase-drivers/src/isolation.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DriverSpawnPlan` | `tirbase-drivers/src/isolation.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DrrScheduler` | `tirbase-core/src/transport/scheduler.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DuplexNoiseStream` | `tirbase-core/src/transport/session.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DurabilityReceipt` | `tirbase-core/src/durability/receipt.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DurabilitySubsystem` | `tirbase-core/src/durability/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `DurabilityTierChanged` | `tirbase-core/src/api/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `EmptyDeviceModelError` | `tirbase-drivers/src/driver_trait.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `EnrolledDevice` | `tirbase-guard/src/enrollment.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `EnrollmentRequest` | `tirbase-guard/src/enrollment.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `EnrollmentService` | `tirbase-guard/src/enrollment.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `EpochBump` | `tirbase-guard/src/epoch.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `EpochBumpFile` | `tirbase-gateway/src/main.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `EpochBumpRequest` | `tirbase-gateway/src/admin.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `EpochCommandGuard` | `tirbase-guard/src/epoch.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `EpochRegistry` | `tirbase-guard/src/epoch.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ExecutionProfileVersion` | `tirbase-core/src/migration/profile.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ExportedCheckpoint` | `tirbase-gateway/src/security_log_export.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ExportedEvent` | `tirbase-gateway/src/security_log_export.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ExportedLog` | `tirbase-gateway/src/security_log_export.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ExportedPersonalCommitment` | `tirbase-gateway/src/security_log_export.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ExportedPseudonymizedField` | `tirbase-gateway/src/security_log_export.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `FieldDef` | `tirbase-core/src/schema/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `FieldError` | `tirbase-guard/src/envelope.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `FieldRef` | `tirbase-core/src/schema/diff.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `FileKeyProvider` | `tirbase-core/src/identity/file_key_provider.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `FileKeyProvider` | `tirbase-gateway/src/key_provider.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `FirstOrderThermalModel` | `tirbase-drivers/src/cold_room_sim.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `FpvToml` | `tirbase-gateway/src/profiles.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `GatewayBootRecord` | `tirbase-gateway/src/main.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `GatewayConfig` | `tirbase-gateway/src/config.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `GatewayConfigBundlePayload` | `tirbase-gateway/src/config.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `GatewayMetrics` | `tirbase-gateway/src/metrics.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `GatewaySecurityEventLog` | `tirbase-gateway/src/security_sink.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `GroupCommitBatcher` | `tirbase-gateway/src/event_batcher.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `GuardConfig` | `tirbase-guard/src/guard.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `GuardDeviceTransport` | `tirbase-guard/src/device_transport.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `HandshakeFailureRecord` | `tirbase-core/src/transport/session.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `HardwareCounterBinding` | `tirbase-gateway/src/hw_counter_binding.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `HealthLoopState` | `tirbase-gateway/src/health.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `HostState` | `tirbase-core/src/migration/wasm_sandbox.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `IdbStore` | `tirbase-core/src/store/indexed_db.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `IdempotencyRow` | `tirbase-gateway/src/db/idempotency_keys.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `IdentityManager` | `tirbase-core/src/identity/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `InMemoryEpochStore` | `tirbase-guard/src/epoch.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `InMemoryKeyProvider` | `tirbase-core/src/identity/file_key_provider.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `InMemoryLockdownStore` | `tirbase-guard/src/lockdown.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `InMemoryNonceStore` | `tirbase-guard/src/epoch.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `InMemoryStoreHandle` | `tirbase-core/src/migration/wasm_sandbox.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `InboundCaps` | `tirbase-core/src/crdt/inbound_caps.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `InboundHardening` | `tirbase-core/src/crdt/hardening.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `InboundRateLimiter` | `tirbase-core/src/crdt/inbound_caps.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `InboundShape` | `tirbase-core/src/crdt/hardening.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `IncidentContextObject` | `tirbase-core/src/contamination/incident.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `InitConfig` | `tirbase-core/src/api/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `KernelIsolationCaps` | `tirbase-drivers/src/isolation.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `LandlockRulesetAttr` | `tirbase-drivers/src/isolation.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `LeasePreemptPayload` | `tirbase-gateway/src/admin.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `LeasePreemptRequest` | `tirbase-gateway/src/admin.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `LeaseRow` | `tirbase-gateway/src/db/single_writer_leases.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `LocalAdminCommandRequest` | `tirbase-gateway/src/command_ingress/local_admin.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `LocalStore` | `tirbase-core/src/store/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `LockdownExitPayload` | `tirbase-guard/src/lockdown.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `LockdownExitRequest` | `tirbase-gateway/src/admin.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `LockdownFileMarker` | `tirbase-guard/src/lockdown.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `LogState` | `tirbase-gateway/src/security_log.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `LwwConflict` | `tirbase-core/src/crdt/verify.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ManagerSignature` | `tirbase-core/src/auth/revocation.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ManagerSignature` | `tirbase-core/src/migration/migration_delta.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `MemoryBudgetCaches` | `tirbase-core/src/crdt/memory_budget.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `MeshStatus` | `tirbase-core/src/api/types.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `MeshTransport` | `tirbase-core/src/transport/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `Migration` | `tirbase-gateway/src/db/migrations.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `MigrationDelta` | `tirbase-core/src/migration/migration_delta.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `MigrationExecutionRegistry` | `tirbase-core/src/migration/wasm_sandbox.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `MigrationReport` | `tirbase-gateway/src/db/migrations.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `MigrationRevocationDelta` | `tirbase-core/src/migration/migration_delta.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ModbusRegisterMap` | `tirbase-drivers/src/register_map.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ModbusRtuClient` | `tirbase-drivers/src/modbus.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ModbusRtuSerialConfig` | `tirbase-drivers/src/modbus.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ModbusTcpAdu` | `tirbase-drivers/src/modbus.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ModbusTcpClient` | `tirbase-drivers/src/modbus.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ModbusTcpCodec` | `tirbase-drivers/src/modbus.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `MqttConnectConfig` | `tirbase-drivers/src/mqtt.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `MqttTlsClient` | `tirbase-drivers/src/mqtt.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `NamedMonotonicCounter` | `tirbase-gateway/src/monotonic_counter.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `NodeModeState` | `tirbase-guard/src/node_mode.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `NoiseSession` | `tirbase-core/src/transport/session.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PaFixture` | `tirbase-gateway/src/task34_cli.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PaTrustFixture` | `tirbase-gateway/src/config.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ParamFloor` | `tirbase-guard/src/trust_root.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ParamToml` | `tirbase-gateway/src/profiles.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ParameterDescriptor` | `tirbase-drivers/src/driver_trait.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PeerCheckpointWitness` | `tirbase-gateway/src/db/peer_checkpoint_witnesses.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PeerDiscovery` | `tirbase-core/src/transport/discovery.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PeerPair` | `tirbase-core/src/transport/session.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PeerSecurityEventSyncLimiter` | `tirbase-core/src/transport/security_event_sync.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PeerState` | `tirbase-core/src/transport/discovery.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PendingApprovalRow` | `tirbase-gateway/src/db/pending_approvals.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PendingEntry` | `tirbase-core/src/crdt/pending_queue.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PendingEviction` | `tirbase-core/src/crdt/pending_queue.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PendingLoosenOperation` | `tirbase-guard/src/policy.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PendingQueue` | `tirbase-core/src/crdt/pending_queue.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PendingRevocation` | `tirbase-core/src/auth/revocation.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PendingRevocationStore` | `tirbase-core/src/auth/revocation.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PendingSignatureRow` | `tirbase-gateway/src/db/pending_approvals.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PerDidRateLimiter` | `tirbase-core/src/crdt/rate_quarantine.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PersonalField` | `tirbase-core/src/events.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PersonalFieldCommitment` | `tirbase-gateway/src/security_log.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `Pkcs11KeyProvider` | `tirbase-gateway/src/key_provider.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PolicyLifecycle` | `tirbase-guard/src/policy.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `PreparedMigration` | `tirbase-core/src/migration/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ProfileMap` | `tirbase-guard/src/envelope.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ProfileToml` | `tirbase-gateway/src/profiles.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ProfileTomlError` | `tirbase-gateway/src/profiles.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `QuarantineEntry` | `tirbase-core/src/migration/quarantine.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `QuarantineLedger` | `tirbase-core/src/migration/quarantine.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `QueryResult` | `tirbase-core/src/api/types.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `QueueEntry` | `tirbase-core/src/durability/cloud_queue.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `QueuedDelta` | `tirbase-core/src/transport/scheduler.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `QuorumConfig` | `tirbase-core/src/durability/quorum.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `RatchetAdvance` | `tirbase-guard/src/time.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `RateLimitState` | `tirbase-gateway/src/security_log.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `RateLimiters` | `tirbase-guard/src/admit.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `RateQuarantineLedger` | `tirbase-core/src/crdt/rate_quarantine.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ReassemblyBuffer` | `tirbase-core/src/transport/fragment.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ReconciliationSummary` | `tirbase-gateway/src/db/applied_effects_ledger.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `RecordingBatchBackend` | `tirbase-gateway/src/event_batcher.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `RecordingConn` | `tirbase-core/src/durability/integration_tests.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `RegisterDef` | `tirbase-drivers/src/register_map.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `RegistryGuard` | `tirbase-core/src/migration/wasm_sandbox.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `RejectionRecord` | `tirbase-core/src/durability/cloud_ledger.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ReplaySummary` | `tirbase-core/src/migration/sidecar.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ResumptionCredential` | `tirbase-core/src/transport/session.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `RetryEntry` | `tirbase-core/src/transport/discovery.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `RetypedField` | `tirbase-core/src/schema/diff.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `RevocationDelta` | `tirbase-core/src/auth/revocation.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `RevocationRecord` | `tirbase-core/src/migration/revocation.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `RevocationSubsystem` | `tirbase-core/src/auth/revocation.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `RevokeIssuerRequest` | `tirbase-gateway/src/admin.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `RevokedMigrationRegistry` | `tirbase-core/src/migration/revocation.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `RgaConflict` | `tirbase-core/src/crdt/verify.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `RolePolicy` | `tirbase-guard/src/trust_root.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `RootCaRegistry` | `tirbase-core/src/auth/root_ca.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `S` | `tirbase-core/src/migration/wasm_sandbox.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SaturateLease` | `tirbase-core/src/transport/saturate.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SaturateModeStateMachine` | `tirbase-core/src/transport/saturate.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `Schema` | `tirbase-core/src/schema/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SchemaDiff` | `tirbase-core/src/schema/diff.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SchemaMigrationEngine` | `tirbase-core/src/migration/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SchemaQuarantineLedger` | `tirbase-core/src/crdt/schema_quarantine.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SchemaQuarantineRecord` | `tirbase-core/src/crdt/schema_quarantine.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SchemaVersionPath` | `tirbase-core/src/migration/version_path.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SecurityEvent` | `tirbase-core/src/events.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SecurityEvent` | `tirbase-gateway/src/security_log.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SecurityEventLog` | `tirbase-gateway/src/security_log.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SecurityEventRing` | `tirbase-gateway/src/security_log.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SecurityEventSyncBatch` | `tirbase-core/src/transport/security_event_sync.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SecurityEventSyncHandler` | `tirbase-core/src/transport/security_event_sync.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SecurityEventSyncRecord` | `tirbase-core/src/transport/security_event_sync.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SecurityLogRetentionConfig` | `tirbase-gateway/src/security_log.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SelfUpdateController` | `tirbase-gateway/src/self_update.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SenderCounter` | `tirbase-core/src/crdt/rate_quarantine.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SequenceResetRequest` | `tirbase-gateway/src/admin.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SessionManager` | `tirbase-core/src/transport/session.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `ShadowRunOutcome` | `tirbase-core/src/migration/shadow.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SideCarEntry` | `tirbase-core/src/migration/sidecar.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SideCarLedger` | `tirbase-core/src/migration/sidecar.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SignatureEntry` | `tirbase-guard/src/signed_operation.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SignedConfigRollback` | `tirbase-gateway/src/self_update.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SignedFirmwareManifest` | `tirbase-gateway/src/self_update.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SignedGatewayConfigBundle` | `tirbase-gateway/src/config.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SignedOperation` | `tirbase-guard/src/signed_operation.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SignedPostconditions` | `tirbase-core/src/migration/migration_delta.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SimulateRequest` | `tirbase-gateway/src/admin.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SimulatedHardwareCounter` | `tirbase-gateway/src/monotonic_counter.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SingleWriterLease` | `tirbase-guard/src/single_writer_lease.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SockFilter` | `tirbase-guard/src/bin/driver_isolation_child.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SockFprog` | `tirbase-guard/src/bin/driver_isolation_child.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SoftwareMonotonicCounter` | `tirbase-gateway/src/monotonic_counter.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SpatialDiversityTracker` | `tirbase-core/src/durability/spatial.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SqliteAntiReplayStore` | `tirbase-gateway/src/db/anti_replay_windows.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SqliteAppliedEffectsStore` | `tirbase-gateway/src/db/applied_effects_ledger.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SqliteChallengeNonceStore` | `tirbase-gateway/src/db/challenge_nonces.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SqliteDecidedOutcomesStore` | `tirbase-gateway/src/db/decided_outcomes.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SqliteDeviceEpochStore` | `tirbase-gateway/src/db/device_epoch.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SqliteDriftRateHistoryStore` | `tirbase-gateway/src/db/drift_rate_history.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SqliteEnrollmentNonceStore` | `tirbase-gateway/src/db/enrollment_nonce.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SqliteEventBackend` | `tirbase-gateway/src/security_log.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SqliteIdempotencyStore` | `tirbase-gateway/src/db/idempotency_keys.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SqliteLeaseStore` | `tirbase-gateway/src/db/single_writer_leases.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SqliteLockdownStore` | `tirbase-gateway/src/db/lockdown.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SqlitePendingApprovalsStore` | `tirbase-gateway/src/db/pending_approvals.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SqliteStage16Store` | `tirbase-gateway/src/guard.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SqliteTargetStateStore` | `tirbase-gateway/src/db/target_state.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SqliteTimeRatchetStore` | `tirbase-gateway/src/db/time_ratchet.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `Stage16Request` | `tirbase-guard/src/commit.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `StoredIdentity` | `tirbase-core/src/identity/did.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SupervisedDriver` | `tirbase-guard/src/driver_proxy.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SyncPublisher` | `tirbase-gateway/src/security_log.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `SystemTimeSource` | `tirbase-gateway/src/time_source.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TableDef` | `tirbase-core/src/schema/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TargetAdmission` | `tirbase-guard/src/guard.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TargetStateRow` | `tirbase-gateway/src/db/target_state.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `Task21HydrationReport` | `tirbase-gateway/src/guard.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `Tier1QuorumTracker` | `tirbase-core/src/durability/quorum.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TimeAnchorEntry` | `tirbase-gateway/src/time_beacon.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TimeAnchorTrustFile` | `tirbase-gateway/src/time_beacon.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TimeBeacon` | `tirbase-guard/src/time.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TimeBeaconEnvelope` | `tirbase-gateway/src/time_beacon.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TimeRatchet` | `tirbase-guard/src/time.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TimeRatchetConfig` | `tirbase-guard/src/time.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TimeRatchetRecord` | `tirbase-guard/src/time.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TimeoutError` | `tirbase-drivers/src/driver_trait.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TirBaseBehaviour` | `tirbase-core/src/transport/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TlsValidatedEndpoint` | `tirbase-drivers/src/mqtt.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TokenBucket` | `tirbase-core/src/crdt/inbound_caps.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TokenBucket` | `tirbase-guard/src/admit.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `Tpm2KeyProvider` | `tirbase-gateway/src/key_provider.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `Tpm2MonotonicCounter` | `tirbase-gateway/src/monotonic_counter.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TransportConfig` | `tirbase-core/src/transport/mod.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TransportDegradationEvent` | `tirbase-core/src/durability/anchor.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TrustLevelStateMachine` | `tirbase-core/src/auth/trust.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TrustRootManager` | `tirbase-guard/src/trust_root.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TrustRootRecord` | `tirbase-guard/src/trust_root.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TrustRootSignature` | `tirbase-guard/src/trust_root.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `TrustRootSigningBody` | `tirbase-guard/src/trust_root.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `UnverifiedWarning` | `tirbase-core/src/api/types.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `VerificationReport` | `tirbase-core/src/crdt/verify.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `VerifyReport` | `tirbase-gateway/src/security_log_export.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `WriteContext` | `tirbase-core/src/contamination/human_reaction.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |
| `WriteResult` | `tirbase-core/src/api/types.rs` | `RECONSTRUCTIBLE: value/state container; authoritative data lives in persisted ledgers or is derived from signed inputs` |

<!-- END GENERATED STRUCT INVENTORY -->
