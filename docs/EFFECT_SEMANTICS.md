# Effect semantics (PV-5.10, CLAIM-21.8)

This document describes command delivery and effect semantics for TirBase v1.

## Delivery model

Commands are delivered **at-least-once** to the driver boundary with **idempotent declarative effects**:

- A command expresses only declarative desired state (`target.parameter = value` with unit).
- The guard admits a command only after Stages 0–15 pass.
- Stage 16 performs one atomic commit (SQLite `IMMEDIATE` transaction under `WAL` + `synchronous=FULL` on the PrimaryLedger) that checks anti-replay and idempotency, acquires the `SingleWriterLease` (inside the same transaction), advances anti-replay state, records the idempotency key, and writes the first durable `Actuating` record to `applied_effects_ledger`. Dispatch to the driver occurs only after this commit/fsync boundary (INV-12).
- Retries carrying the same `(issuer_did, target_id, idempotency_key)` within the retention window return the original stored result without a second actuation (PV-5.6).

## `applied_effects_ledger` states

The conceptual lifecycle is: *(admitted)* → `Actuating` → `Complete` | `Failed` | `Unknown`.

- `Actuating`: first durable state; command dispatched/being actuated.
- `Complete`: driver read-back confirmed the commanded state.
- `Failed`: actuation failed or driver read-back did not confirm the commanded state.
- `Unknown`: effect outcome is not known (e.g. driver did not respond within timeout, or boot reconciliation could not resolve an `Actuating` entry).

## `Unknown` entry semantics (PV-5.11, INV-11)

- An `Unknown` entry for a target blocks new commands to that target with a `TARGET_BUSY` rejection until the entry is resolved.
- Boot reconciliation scans unresolved `Actuating` entries and marks them `Complete`, `Failed`, or `Unknown` based on driver read-back (30s timeout). Pre-Actuating legacy schema entries are marked `Failed` (`OLD_SCHEMA_ENTRY`) and never treated as `Actuating`.
- An operator-clear action with a `PolicyAuthority` credential may advance an unresolved `Unknown` entry to `Failed` after operator review, unblocking the target. Operator clear is audited as a security-relevant decision.

## Retry rules for `Failed` entries

- A new command for the same target may be accepted if the issuer holds or can acquire the `SingleWriterLease` and all guard stages pass.
- `Failed` does not itself create an idempotency hit; idempotency is keyed by the idempotency key within its retention window.

## Single-writer lease

- At most one issuer holds a `SingleWriterLease` per target (INV-13). Lease timing uses monotonic time.
- Leases may be preempted by an M-of-N `RevocationManager + PolicyAuthority` joint operation (production caller: gateway admin path).
- Leases held by a revoked issuer DID are released on revocation.
- Consecutive renewals are capped (default 10). After the cap, the lease enters a cooldown (default one lease duration) before the same issuer may re-acquire, preventing starvation (S21).
- All leases are released at boot so stale leases do not block targets after restart.

## v1 limitation: single-parameter commands only

TirBase v1 supports commands that target **one parameter** on **one target**. Multi-parameter atomic commands are rejected with an `UNSUPPORTED` rejection and are deferred to a post-v1 design.
