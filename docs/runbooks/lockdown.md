# Runbook: LOCKDOWN Entry and M-of-N Exit

> **Status:** Procedure documented and verified against `tirbase-sim` simulated faults (see **Verification**). Applies to failure mode 1 (malicious command) containment and crash-loop escalation (PV-1.11, PV-4.13, PV-4.15, INV-5, S24).
>
> **[CLAIM-55.1]** — **Proven** (procedure + simulated-fault verification `tirbase-sim/tests/runbook_fault_verification.rs::runbook_lockdown_exit_requires_m_of_n_and_clears_lockdown`).

## When to use

- **Security LOCKDOWN entered** by guard decision, counter-rollback detection, or crash-loop escalation (N crashes within window; default 3/5 min per S24/PV-1.11).
- Operator must restore service **without bypassing** authorization: exit requires M-of-N co-signatures from **≥ 2 distinct roles** and a full, valid `EnvelopeProfile` (CLAIM-13.3, PV-4.13).

## Preconditions

- Gateway state is `Lockdown` (commands/actuation suspended except exit flow; mesh/log export behavior per mode matrix).
- `primary.db` lockdown state and secondary indicator `/var/lib/tirbase/lockdown` may be present (persistent; `/run` is not authoritative).
- Signed `EnvelopeProfile` matching the exit payload is available and installed/validatable.
- Trust root contains authorized `PolicyAuthority` and `RevocationManager` (or other distinct authorized roles as policy permits) keys; M-of-N satisfied with **distinct roles**.

## Procedure (M-of-N LOCKDOWN exit)

### 1. Confirm LOCKDOWN and capture diagnostics

**Local admin (Unix socket, kernel-attested):**
```bash
# Mode/status
printf '%s\n' '{"cmd":"mode"}' | socat - UNIX-CONNECT:/run/tirbase/admin.sock
# If configured, inspect status (Auditor/PolicyAuthority credential required remotely)
printf '%s\n' '{"cmd":"status","payload":{"issuer_did":"<issuer-did>"}}' | socat - UNIX-CONNECT:/run/tirbase/admin.sock
```

**Expected output (illustrative):**
```json
{"status":200,"mode":"Lockdown","allows_commands":false,"allows_mesh_sync":false,"allows_log_export":false,"lockdown_persisted":true}
```

Record: reason/events in security log (`ReasonCode::EnteredLockdown` / mode transition), and whether persistence is DB-backed.

### 2. Prepare signed `LockdownExit` operation (≥ 2 distinct roles)

Build `payload`:
```json
{
 "node_id": "<node-id>",
 "issued_at_est": <i64>,
 "reason": "<operator reason>",
 "envelope_profile_id": [/* 16 bytes matching installed profile.profile_id */]
}
```
Wrap as `SignedOperation<LockdownExitPayload>` (context `TirBase/v1/LockdownExit`) and collect co-signatures from **at least two distinct roles** (e.g. `PolicyAuthority` + `RevocationManager`). Single-role or M<2 must be rejected.

### 3. Submit lockdown-exit

```bash
printf '%s\n' '{
 "cmd":"lockdown-exit",
 "payload":{
 "operation": <SignedOperation<LockdownExitPayload> JSON>,
 "payload": <LockdownExitPayload JSON>
 }
}' | socat - UNIX-CONNECT:/run/tirbase/admin.sock
```

**Expected output (success):**
```json
{"status":200,"mode":"Normal","outcome":"lockdown_exit_applied"}
```

**Expected output (rejection examples):** `409` with `error` such as threshold/role/distinct-role failure, missing or mismatched `EnvelopeProfile`, or invalid signatures (typed `LockdownError` / trust-root errors).

### 4. Post-exit verification

```bash
printf '%s\n' '{"cmd":"mode"}' | socat - UNIX-CONNECT:/run/tirbase/admin.sock
```
- `mode` is `Normal` (or expected post-exit mode), `lockdown_persisted` cleared, DB key and `/var/lib/tirbase/lockdown` indicator removed by store.
- Confirm security event `LockdownExitApplied` emitted; monitor for re-entry (crash-loop or new guard decision).

## Rollback / if exit is rejected

- **Do not** force-clear persistence outside the signed exit flow.
- If rejection is `InsufficientDistinctRoles` / threshold not met: obtain required additional distinct-role co-signature(s).
- If rejection cites missing/mismatched envelope/profile: install/validate the correct signed `EnvelopeProfile` and resubmit with matching `envelope_profile_id`.
- If root cause (tamper, rollback, compromise) persists, remain in LOCKDOWN and follow `docs/runbooks/tamper.md`, `docs/runbooks/restore.md`, or `docs/runbooks/key-compromise.md` as applicable.
- For crash-loop source, stabilize the fault and follow `docs/runbooks/crash-loop.md` before re-attempting exit.

## Expected security invariants

- INV-5: LOCKDOWN does not actuate commanded values; only safe-default paths apply.
- Exit requires authorization from ≥ 2 distinct roles and a full envelope profile; removing either must fail.

## Verification

- **Simulated fault:** crash-loop escalation to LOCKDOWN (S24, `tirbase-sim/src/scenarios/s24_crash_loop.rs::s24_crash_loop_escalates_to_lockdown_within_window`).
- **Procedure verification (M-of-N exit, distinct roles, persistence clear, mode Normal):** `tirbase-sim/tests/runbook_fault_verification.rs::runbook_lockdown_exit_requires_m_of_n_and_clears_lockdown`.
