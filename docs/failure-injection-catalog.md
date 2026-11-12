# Failure-Injection Catalog and Procedures (PV-9.5, CLAIM-44.7)

> **Status:** Automated coverage and lab procedures for gateway/guard failure handling. This document records injection mechanisms, expected system responses, and committed test/procedure evidence.

**Release reviewed against:** `<fill at release>` 
**Last reviewed (UTC):** `<YYYY-MM-DD>`

## Scope

This catalog covers the required failure-injection scenarios for :
1. **ENOSPC via small tmpfs → `SQLITE_FULL` → High `SecurityEvent`**
2. **fsync failure via libfiu → `SQLITE_IOERR` → `Restricted`**
3. **Torn write via dm-flakey → logical-dump equivalence**
4. **Driver hang via `SIGSTOP` → `TimeoutError`**
5. **Clock jump via `clock_settime` → `now_est` bounded by `TimeRatchet`**

## Summary matrix

| ID | Injection | Mechanism | Expected behavior | Automated test | Lab/manual procedure |
|---|---|---|---|---|---|
| FI-DISK-FULL | Disk full | small tmpfs / forced ENOSPC on primary DB write path | `SQLITE_FULL` mapped to `SqliteErrorAction::StorageFull`; emit **High** `StorageFull` SecurityEvent; continue with reduced logging (no mode transition) | `tirbase-gateway` test: `failure_injection::enospc_maps_to_sqlite_full_and_emits_high_storage_full` (unit/integration with injected SQLite error / constrained FS) | Mount small tmpfs for data dir, drive writes to exhaustion, verify event and no Restricted transition |
| FI-FSYNC-IOERR | fsync/IO failure | libfiu fault injection on fsync/write (where available) | `SQLITE_IOERR` mapped to `EnterRestrictedIo`; emit Critical `StorageError` + `EnteredRestricted`; node enters `Restricted` | `failure_injection::ioerr_maps_to_restricted_and_emits_storage_error`; libfiu-backed test when `libfiu` present (`TIRBASE_LIBFIU=1`) | Run gateway with libfiu preload/fault point on fsync, confirm Restricted and events |
| FI-44.7c | Torn write / crash consistency | dm-flakey (drop_writes / error_writes around commit barriers) | After recovery, logical dump equivalence holds for committed authoritative state; uncommitted/partial effects reconciled per AEF rules | Logical-dump equivalence property test + failpoint kill-at-step tests; dm-flakey procedure validated on lab hardware | Configure dm-flakey target for primary DB device, inject faults at commit/fsync boundaries, reboot/reopen, compare logical dumps |
| FI-DRIVER-HANG | Driver hang | `SIGSTOP` to driver child/process | Guard/dispatch observes timeout; operation resolves to `TimeoutError`/`Unknown` per effects-ledger reconciliation rules (no unbounded hang) | `failure_injection::driver_hang_sigstop_yields_timeout_error` (process control / mock driver timeout path) | Start supervised driver, send `SIGSTOP`, verify timeout path and recovery/escalation per lifecycle policy |
| FI-CLOCK-JUMP | Clock jump | `clock_settime` / simulated wall-clock jump | `TimeRatchet::now_est` remains bounded by authenticated ratchet/floor semantics; wall-clock poisoning does not extend validity | `failure_injection::clock_jump_does_not_advance_now_est_beyond_ratchet` and `tirbase-guard` ratchet tests | On isolated test host, advance system clock forward/backward; verify `now_est`, freshness, and expiry decisions unchanged except via accepted beacons |

## Detailed procedures

### FI-DISK-FULL — ENOSPC / SQLITE_FULL (High SecurityEvent)

**Automated:** Inject `SQLITE_FULL` via error-mapping/action path and assert `SqliteErrorAction::StorageFull` emits `ReasonCode::StorageFull` with `Severity::High` without entering Restricted. Where filesystem-level injection is feasible in CI, run against a small tmpfs backing the DB.

**Manual (lab):**
1. Create and mount a small tmpfs (e.g. 1–4 MB) as the gateway data directory.
2. Start gateway with primary/derived DBs on that mount; generate durable writes until `SQLITE_FULL`.
3. Verify security log contains a High `StorageFull` event, gateway continues operating with reduced logging, and mode does not transition to Restricted solely due to FULL.
4. Restore space and confirm recovery behavior.

**Pass criteria:** High `StorageFull` emitted; no Restricted transition from FULL alone; no data corruption beyond expected write failure.

### FI-FSYNC-IOERR — fsync failure / SQLITE_IOERR (Restricted)

**Automated:** Map injected `SQLITE_IOERR` to `EnterRestrictedIo`, assert Critical `StorageError` and `EnteredRestricted` events and `NodeMode::Restricted`. libfiu-backed execution is enabled when `libfiu` tooling/library is available and `TIRBASE_LIBFIU=1`.

**Manual (libfiu):**
1. Build/run with libfiu fault points enabled on fsync/write syscalls for the DB paths.
2. Trigger a commit requiring fsync; inject failure.
3. Verify `SQLITE_IOERR` handling enters Restricted and emits required events.

**Pass criteria:** Restricted entered; Critical storage/mode events emitted.

### FI-44.7c — Torn write / logical-dump equivalence (dm-flakey)

**Automated:** Use failpoints/kill-at-step tests to abort around durable boundaries and verify logical-dump equivalence for committed state (`db::logical_dump` / reconciliation tests).

**Manual (dm-flaky):**
1. Place primary DB storage on a dm-flakey device configured to drop or error writes at configured intervals (commit/fsync-aligned).
2. Execute write/commit workloads and power-fault or restart across injected windows.
3. Reopen and reconcile; compute logical dump before/after committed boundaries.
4. Compare dumps for equivalence of authoritative committed records.

**Pass criteria:** Logical-dump equivalence for committed state; reconciliation outcomes match PV-9/INV rules.

### FI-DRIVER-HANG — Driver hang / SIGSTOP → TimeoutError

**Automated:** Exercise dispatch/read-back timeout handling (driver read returns timeout / hang simulation) and assert terminal `Unknown`/timeout handling without blocking the guard admission path; supervised lifecycle reports timeout/error as specified.

**Manual:**
1. Launch gateway with a supervised driver child.
2. Send `SIGSTOP` to the driver process during an actuating operation.
3. Observe guard/driver-proxy timeout, ledger transition to `Unknown` (or configured timeout outcome), and lifecycle restart/escalation per policy.

**Pass criteria:** Timeout surfaced within configured bound; no indefinite block; reconciliation/lifecycle behavior consistent.

### FI-CLOCK-JUMP — Clock jump / TimeRatchet bound

**Automated:** `TimeRatchet` unit/property tests and guard integration tests prove `now_est` does not jump with wall-clock manipulation and remains floored/bounded by persisted/monotonic ratchet state.

**Manual:**
1. On an isolated system (not production), record `now_est`, freshness, and a command near expiry.
2. Apply large forward/backward `clock_settime` jumps to `CLOCK_REALTIME`.
3. Confirm `now_est`, expiry decisions, and beacon acceptance rules remain governed by `TimeRatchet`/monotonic domain; only accepted authenticated beacons advance the floor per policy.

**Pass criteria:** No wall-clock poisoning of `now_est`; ratchet monotonicity and expiry semantics preserved.

## CI execution notes

- Automated tests run in standard CI (no privileged devices). dm-flakey/libfiu/SIGSTOP-on-real-driver and `clock_settime`-on-host-clock procedures are **lab/release procedures** when privileges/hardware are unavailable; CI still executes portable mappings, failpoints, and TimeRatchet/timeout logic.
- Record environment, kernel, privileges, and exact commands in release/lab evidence when running manual procedures.

---
*Failure-injection catalog for CLAIM-44.7/PV-9.5. Automated tests complement, not replace, hardware/lab procedures where required.*
