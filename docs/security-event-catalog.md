# Security Event Catalog

> **Status: Partially implemented** — The typed event plumbing (`SecurityEvent`,
> `SecurityEventCategory`, `ReasonCode`, `Severity`) now lives in
> `tirbase-core/src/events.rs`, and every emission site in `crdt/`, `auth/`,
> `transport/`, and `migration/` emits through `SecurityEventSink` (tasks 5.4 and
> 5.8).  The `ReasonCode` enum currently defines the variants those paths emit;
> task 25.1 extends it to the full catalog and adds the hash-chained log
> (`seq`, `prev_hash`, `best_effort_wall_time`, `TimeSourceFlag`, checkpoints).
> The **Status** column below tracks the full hash-chained implementation, so
> most rows remain `Planned` until task 25.1 lands.

## Purpose

`docs/security-event-catalog.md` is the **authoritative list** of every `SecurityEventCategory`
variant and every `ReasonCode` variant that production code is permitted to emit.

`scripts/check-security-event-catalog.sh` runs on every push/PR (CI job `security-event-catalog`,
CLAIM-3.9) and **fails** if it finds any `SecurityEventCategory::Variant` or `ReasonCode::Variant`
reference in production Rust source that is not listed below.

## Machine-readable format

- Each category is introduced with a `## Category: <CategoryName>` heading.
  `CategoryName` must match the `SecurityEventCategory` enum variant name exactly.
- Each row in the table beneath the heading names one `ReasonCode` variant.
- The CI script uses these headings and the *first column* of each table row to
  build the allowed set; other columns are for human readers only.

---

## Category: CommandDecision

Events emitted by the Command Guard when it accepts or rejects a command (Stage 17).

| Reason Code | Description | Severity | Status | PV Reference |
|---|---|---|---|---|
| Accepted | Command passed all guard stages and was admitted | Low | Planned | PV-4 |
| PreAuthRateLimit | Pre-auth per-source token bucket exceeded before any crypto | Medium | Implemented | PV-4.3 |
| ModeLockdown | Node is in Lockdown or Restricted mode; command rejected at Stage 1 | High | Implemented | PV-4.13 |
| InvalidSignature | Command signature failed verification at Stage 2 | High | Planned | PV-4.3 |
| TokenInvalid | Biscuit token invalid, expired, or from unknown CA (Stage 3) | High | Planned | PV-3.2 |
| CommandSignatureInvalid | Command signature failed verification over canonical CBOR (Stage 2) | High | Implemented | PV-4.2 |
| CommandAccepted | Command passed task-11 admission (signature+epoch gate) and was dispatched via DriverProxy | Low | Implemented | PV-4.3 |
| ScopeViolation | Token does not authorise the requested target or parameter (Stage 4) | High | Implemented | PV-4.6 |
| IssuerRevoked | Issuer DID is in the revocation set (Stage 5) | High | Implemented | PV-4.3 |
| StaleEpoch | Command enrollment epoch is less than current device epoch (Stage 6) | Medium | Planned | PV-5.5 |
| TargetBusy | Target has an Unknown ledger entry; command rejected at Stage 6.5 | Medium | Implemented | PV-5.11 |
| Expired | Command expiry (now_est > expiry_est) exceeded max_ttl_secs (Stage 8) | Medium | Planned | PV-22.1 |
| ChallengeMissing | Critical parameter in UNVERIFIED freshness state requires challenge nonce (Stage 9) | Medium | Implemented | PV-22.3 |
| ValueInvalid | FixedPointValue non-finite or canonical-exponent mismatch (Stage 10) | Medium | Implemented | PV-21.1 |
| EnvelopeViolation | Value outside envelope [min, max] bounds (Stage 11) | Medium | Implemented | PV-4.6 |
| ConstraintViolation | Cross-parameter linear constraint failed (Stage 12) | Medium | Implemented | PV-4.5 |
| DriftExceeded | Rate-of-change or cumulative drift window exceeded (Stage 13) | Medium | Implemented | PV-4.7 |
| DwellViolation | Command arrived before dwell period elapsed (Stage 13) | Medium | Implemented | PV-4.7 |
| MinOffViolation | Command arrived before min-off period elapsed (Stage 13) | Medium | Implemented | PV-4.7 |
| RateLimit | Per-issuer rate limit (default 10 cmd/s) exceeded (Stage 14) | Low | Planned | PV-24.2 |
| QuorumRequired | Critical parameter requires M-of-N co-signatures (Stage 15) | Medium | Implemented | PV-4.16 |
| CommitConflict | Atomic Stage 16 transaction conflict (sequence number already seen) | Medium | Planned | PV-5.5 |
| LeaseHeld | Another issuer holds the SingleWriterLease for this target (Stage 16) | Low | Planned | PV-5.8 |
| NoProfile | No EnvelopeProfile installed for the target | High | Implemented | PV-4.5 |
| Unsupported | Multi-parameter command not supported in v1 | Low | Implemented | PV-5.12 |
| PolicyChangedMidActuation | Policy changed while command was in Stages 16–19 | Low | Planned | PV-4 |

---

## Category: EffectsLedger

Events emitted by the Applied Effects Ledger state machine (PV-5).

| Reason Code | Description | Severity | Status | PV Reference |
|---|---|---|---|---|
| ActuationComplete | Driver confirmed state matches commanded value | Low | Planned | PV-5.2 |
| ActuationFailed | Driver read-back did not match commanded value | High | Planned | PV-5.2 |
| ActuationUnknown | Driver did not respond within 30 s; entry marked Unknown | High | Planned | PV-5.3 |
| ReconciliationComplete | Boot-time reconciliation of Actuating entries finished | Low | Implemented | PV-5.3 |
| ReconciliationTimeout | One or more Actuating entries could not be reconciled within timeout | High | Implemented | PV-5.3 |
| OldSchemaEntry | Pre-Actuating ledger entry from an older schema marked Failed at boot | High | Implemented | PV-5.3 |
| LedgerPruned | Background pruning job removed old Complete/Failed entries | Low | Implemented | PV-5.12 |

---

## Category: PolicyLifecycle

Events emitted by the Policy Lifecycle manager (PV-4).

| Reason Code | Description | Severity | Status | PV Reference |
|---|---|---|---|---|
| TighteningApplied | Tightening policy bundle applied within 1 second | Low | Planned | PV-4.9 |
| LooseningSigned | One M-of-N co-signature collected for pending loosening bundle | Low | Planned | PV-4.10 |
| LoosensingApplied | Loosening policy applied after M-of-N threshold and time-lock | Medium | Planned | PV-4.10 |
| RollbackBlocked | Incoming bundle version ≤ anti-rollback counter; rejected | High | Planned | PV-4.8 |
| TimeLockActive | Loosening policy is waiting out the time-lock window | Low | Planned | PV-4.10 |
| LoosensingCancelled | Pending loosening operation cancelled by PolicyAuthority | Medium | Planned | PV-4.10 |
| TighteningFloorViolation | Bundle would tighten beyond device-class floor from TrustRootRecord | High | Planned | PV-4.11 |
| GovernanceWeakening | Bundle classified Loosening because governance fields weakened | High | Planned | PV-4.11 |
| LooseningSignatureCollected | Loosening co-signature collected; operation still pending (implementation variant) | Low | Implemented | PV-4.10 |
| LooseningApplied | Loosening policy applied after M-of-N threshold and time-lock (implementation variant) | Medium | Implemented | PV-4.10 |
| LooseningCancelled | Pending loosening operation cancelled by PolicyAuthority (implementation variant) | Medium | Implemented | PV-4.10 |
| PolicyRollbackBlocked | Incoming bundle version not strictly greater than committed anti-rollback counter; rejected | High | Implemented | PV-4.8 |
| PolicyRejected | Bundle rejected: classification, signature, or governance check failed | High | Implemented | PV-4.8, PV-4.11 |
| PolicyLooseningM1Warning | M=1 loosening governance accepted with a startup/operational warning (RD-9) | Medium | Implemented | PV-4.10 |

---

## Category: ModeTransition

Events emitted when the node changes its operational mode (PV-4.13).

| Reason Code | Description | Severity | Status | PV Reference |
|---|---|---|---|---|
| EnteredStarting | Node entered Starting mode at boot | Low | Planned | PV-4.13 |
| EnteredNormal | Node entered Normal mode after boot reconciliation | Low | Planned | PV-4.13 |
| EnteredDegraded | No comms for > degraded_timeout_secs; entering last-known-safe loop | Medium | Planned | PV-4.13 |
| EnteredRestricted | Security log tampered or PrimaryLedger corrupted; entering Restricted | High | Implemented | PV-4.13 |
| EnteredLockdown | Node entered LOCKDOWN | Critical | Implemented | PV-4.13 |
| ExitedLockdown | Node exited LOCKDOWN after M-of-N authorization | High | Implemented | PV-4.13 |
| ExitedRestricted | Node exited Restricted mode after signed chain-recovery command | High | Planned | PV-4.13 |
| CrashLoopEscalation | Crash-loop threshold exceeded; LOCKDOWN escalation triggered | Critical | Implemented | PV-1.11 |
| LockdownExitApplied | Valid M-of-N lockdown-exit command applied | High | Implemented | PV-4.13 |
| LockdownExitRejected | Lockdown-exit command rejected (signature/quorum/profile) | High | Implemented | PV-4.13 |

---

## Category: Revocation

Events emitted by the revocation subsystem (PV-3).

| Reason Code | Description | Severity | Status | PV Reference |
|---|---|---|---|---|
| DidRevoked | A DID was added to the revocation set | High | Planned | PV-3 |
| RevocationSignatureReceived | One M-of-N co-signature received for a revocation operation | Low | Planned | PV-3 |
| RevocationLeaseReleased | Lease held by a now-revoked DID was forcibly released | Medium | Implemented | PV-5.8a |
| RevocationPostExecution | Migration transform author DID was revoked; transform result discarded | High | Implemented | PV-8.7 |
| RevocationVerificationFailed | A revocation signature or revocation delta failed verification | High | Implemented | PV-3 |

---

## Category: Enrollment

Events emitted by the device enrollment and epoch subsystem (PV-3, PV-5.5).

| Reason Code | Description | Severity | Status | PV Reference |
|---|---|---|---|---|
| DeviceEnrolled | Device successfully enrolled; scoped token issued | Low | Planned | PV-3.11 |
| EpochBumped | Device enrollment epoch bumped; prior-epoch commands will now be rejected | High | Planned | PV-5.5 |
| EpochRegression | Peer reported a lower epoch than previously witnessed | High | Planned | PV-5.5 |
| NonceReused | Bootstrap nonce was reused; replay rejected | High | Planned | PV-3.13 |
| TrustRootRollbackRejected | A trust-root install/rotation record had a version not greater than the committed counter; boot rejected it | High | Implemented | PV-3.4 |

---

## Category: SecurityLog

Events emitted by the Security Event Log integrity subsystem (PV-7).

| Reason Code | Description | Severity | Status | PV Reference |
|---|---|---|---|---|
| CheckpointWritten | Signed checkpoint record written to security_events table | Low | Implemented | PV-7.3 |
| TamperDetection | Hash-chain broken at sequence number N; entering Restricted mode | Critical | Implemented | PV-7.4 |
| ChainRecovery | Signed chain-recovery command accepted; new chain segment opened | High | Implemented | PV-7.4 |
| TailTruncation | Peer observed a higher checkpoint hash than local log | Critical | Implemented | PV-7.10 |
| SyncFailure | Security event sync to mesh peer failed; retry scheduled | Medium | Implemented | PV-7.9 |
| SyncRateLimitReached | Peer sync rate limit (500 events/min) exceeded | Low | Implemented | PV-7.12 |
| SuppressionSummary | Per-category rate limit (100/s) hit; N events suppressed | Medium | Implemented | PV-7.6 |
| NoWitnessAvailable | No mesh peers or cloud connection; checkpoint cannot be externally witnessed | Low | Implemented | PV-7.10 |
| LogRotated | Oldest signed segment archived and removed by background retention job | Low | Implemented | PV-7.13 |

---

## Category: AntiReplay

Events emitted by the anti-replay window (PV-5.5).

| Reason Code | Description | Severity | Status | PV Reference |
|---|---|---|---|---|
| SequenceRejected | Sequence number already seen or outside [highest−W, highest+G] window | High | Implemented | PV-5.5 |
| WindowReset | Anti-replay window baseline reset by PolicyAuthority-signed operation | Medium | Implemented | PV-5.5 |

---

## Category: MonotonicCounter

Events emitted by the monotonic counter subsystem (PV-9.8).

| Reason Code | Description | Severity | Status | PV Reference |
|---|---|---|---|---|
| MonotonicCounterRegression | Hardware counter ahead of software counter at boot; rollback detected | Critical | Implemented | PV-9.8 |
| CounterLevelReported | Boot-time assurance level (Level1/Level2) reported in diagnostics | Low | Planned | PV-9.8 |

---

## Category: TimeRatchet

Events emitted by the TimeRatchet and FreshnessState subsystem (PV-22).

| Reason Code | Description | Severity | Status | PV Reference |
|---|---|---|---|---|
| BeaconAccepted | TimeAnchor beacon advanced the ratchet's persisted_floor | Low | Implemented | PV-22.2 |
| BeaconRejected | TimeAnchor beacon failed: non-TimeAnchor signer, unknown anchor, or replay below the floor | High | Implemented | PV-22.5 |
| BeaconJumpTooLarge | Beacon wall_time − persisted_floor > max_forward_jump_secs without an anchor quorum | High | Implemented | PV-22.5 |
| BeaconSignatureInvalid | Beacon signature did not verify against any trusted TimeAnchor key | High | Implemented | PV-22.5 |
| FreshnessUnverified | Authenticated-time estimate stale; node entered UNVERIFIED freshness state | Medium | Implemented | PV-22.3 |
| FreshnessRestored | Fresh beacon received; VERIFIED freshness state restored | Low | Implemented | PV-22.3 |

---

## Category: MeshTransport

Events emitted by the libp2p gossipsub mesh transport layer (PV-1.13).

| Reason Code | Description | Severity | Status | PV Reference |
|---|---|---|---|---|
| PeerConnected | Mesh peer connected successfully | Low | Planned | PV-1.13 |
| PeerDisconnected | Mesh peer disconnected | Low | Planned | PV-1.13 |
| HandshakeSuccess | Noise IK handshake established | Low | Planned | PV-1.13 |
| HandshakeFailed | Noise IK handshake failed | Medium | Implemented | PV-1.13 |
| CheckpointGossiped | Latest checkpoint hash gossiped to peer during sync | Low | Implemented | PV-7.10 |
| RelaySelected | Delta routed through a relay peer because the destination is not a direct neighbour | Low | Implemented | PV-1.13 |
| FragmentReassemblyFailed | Fragment reassembly failed or produced an unparsable payload | Medium | Implemented | PV-6.3 |

---

## Category: CrdtHardening

Events emitted by the CRDT inbound validation and quarantine system (PV-6).

| Reason Code | Description | Severity | Status | PV Reference |
|---|---|---|---|---|
| UnknownSchemaHash | Inbound delta quarantined because schema hash is unknown or missing in the local schema path | Medium | Implemented | PV-6.1 |
| DeltaQuarantined | Inbound delta quarantined; see reason for specific violation | Medium | Planned | PV-6.4 |
| QuarantineReplayed | Quarantined delta replayed by PolicyAuthority-signed operation | Medium | Planned | PV-6.7 |
| ClockJump | start_op validation failed; probable clock-jump or start_op inflation | High | Planned | PV-6.1 |
| MissingDependency | Delta depends on ops not yet received; placed in pending queue | Low | Planned | PV-6.1 |
| MissingDependencyTimeout | Pending delta timed out waiting for dependencies | Medium | Planned | PV-6.1 |
| PendingQueueOverflow | Pending queue byte cap exceeded; oldest delta evicted and quarantined | Medium | Planned | PV-6.1 |
| RateExceeded | Per-sender op/s rate cap exceeded | Medium | Planned | PV-6.3 |
| Oversize | Delta exceeds max_delta_bytes limit (default 1 MiB) | Medium | Planned | PV-6.3 |
| OpCountExceeded | Delta exceeds max_ops_per_delta limit | Medium | Planned | PV-6.3 |
| BatchExceeded | Batch exceeds max_changes_per_batch limit | Medium | Planned | PV-6.3 |
| HeadCountExceeded | DAG heads exceed max_concurrent_heads limit | Medium | Planned | PV-6.3 |
| DepCountExceeded | Change has more than max_deps_per_change dependencies | Medium | Planned | PV-6.3 |
| TraversalBudgetExceeded | DAG traversal exceeded max_traversal_nodes budget | Medium | Planned | PV-6.3 |
| DeltaRouted | Inbound delta accepted for merge and routed via the LWW or RGA path | Low | Implemented | PV-6.4 |
| SchemaAdditiveAccepted | Additive schema change accepted and merged against the local schema | Low | Implemented | PV-6.4 |
| MergeVerified | Post-merge LWW/RGA read-back verification completed | Medium | Implemented | PV-6.4 |
| NonAutomergePayload | Payload was not Automerge format; Automerge merge skipped | Low | Implemented | PV-6.4 |

---

## Category: Migration

Events emitted by the schema migration engine (PV-8).

| Reason Code | Description | Severity | Status | PV Reference |
|---|---|---|---|---|
| MigrationApplied | Migration WASM module executed and shadow committed | Low | Planned | PV-8.4 |
| PostconditionFailed | Migration postcondition evaluation failed; shadow discarded | High | Planned | PV-8.4 |
| FuelExhausted | WASM sandbox ran out of fuel; migration quarantined | High | Planned | PV-8.3 |
| MigrationCancelled | In-progress migration cancelled at fuel-check boundary | Medium | Planned | PV-8.6 |
| EngineVersionMismatch | Migration module's fuel_cost_table_hash does not match active profile | High | Implemented | PV-8.2a, S9 |
| DeterministicProfileViolation | Migration WASM module violated deterministic execution profile (forbidden opcodes/imports/features) and was quarantined before execution | High | Implemented | PV-8.2, S8 |
| NonDeterministicModule | WASM module contains f32/f64 or SIMD instructions; quarantined | High | Planned | PV-8.2 |
| ExpandContractViolation | Migration both adds and removes fields in the same module | High | Planned | PV-8.5a |
| FleetPreconditionMissing | Contract migration submitted without fleet_precondition_hash | High | Planned | PV-8.5a |

---

## Category: Driver

Events emitted by the driver proxy and out-of-process driver lifecycle (PV-10).

| Reason Code | Description | Severity | Status | PV Reference |
|---|---|---|---|---|
| DriverError | Driver process returned an error or timed out | High | Planned | PV-10 |
| DriverRestarted | Driver process restarted after crash; exponential backoff applied | Medium | Planned | PV-10 |
| IsolationFailure | Driver child exited abnormally or failed seccomp/landlock init | High | Planned | PV-10.4 |

---

## Category: CloudSync

Events emitted by the outbound cloud synchronisation path (PV-11).

| Reason Code | Description | Severity | Status | PV Reference |
|---|---|---|---|---|
| CloudConnected | Outbound TLS connection to cloud endpoint established | Low | Planned | PV-11 |
| CloudDisconnected | Cloud connection lost; exponential backoff reconnect scheduled | Medium | Planned | PV-11 |
| CloudCertRejected | Cloud endpoint rejected device certificate; connection refused | High | Planned | PV-11 |
| CloudRateLimitReached | Per-connection cloud rate limit exceeded | Low | Planned | PV-11 |

---

## Category: Startup

Events emitted during gateway boot and initialisation (PV-11).

| Reason Code | Description | Severity | Status | PV Reference |
|---|---|---|---|---|
| BootCompleted | Gateway startup completed; node entered Normal mode | Low | Planned | PV-11 |
| QuickCheckFailed | PRAGMA quick_check detected database corruption at boot | Critical | Planned | PV-9.3 |
| LockdownFlagFound | Persisted lockdown flag detected at boot; entering Lockdown mode | Critical | Implemented | PV-4.13 |
| StorageFull | SQLITE_FULL (ENOSPC) detected; reducing non-critical write rate | High | Implemented | PV-9, CLAIM-18.4 |
| StorageError | SQLITE_IOERR detected; entering Restricted mode | Critical | Implemented | PV-9, CLAIM-18.4 |
| StorageCorrupt | SQLITE_CORRUPT detected; entering Restricted mode | Critical | Implemented | PV-9, CLAIM-18.4 |
| LedgerRebuilt | Derived ledger rebuilt from signed delta log after corruption | High | Planned | PV-9.3 |

---

## Category: Diagnostic

Non-security informational events and startup warnings (PV-4.15, PV-3.4).

| Reason Code | Description | Severity | Status | PV Reference |
|---|---|---|---|---|
| SingleRootCaKey | Only one root CA key configured (k=1); startup warning emitted | Medium | Planned | PV-3.4 |
| SingleRevocationManager | M=1 revocation configured; startup warning emitted | Medium | Planned | PV-20.4 |
| LongLivedToken | Token with TTL > recommended maximum detected at mint time | Low | Planned | PV-20.5 |
| FlashBudgetExceeded | Projected daily flash writes exceed configured budget; throttling enabled | Medium | Planned | PV-15.4 |
| WatchdogKeepalive | Dedicated health-loop task sent sd_notify WATCHDOG=1 | Low | Planned | PV-4.15 |
