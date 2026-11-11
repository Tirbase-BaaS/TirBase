# Runbook: Crash-Loop Escalation and Manual LOCKDOWN

> **Status:** Procedure documented and verified against `tirbase-sim` simulated faults (see **Verification**). Applies to supervisor crash-loop escalation to security LOCKDOWN (PV-1.11, PV-4.15, S24).
>
> **[CLAIM-55.5]** — **Proven** (procedure + simulated-fault verification `tirbase-sim/tests/runbook_fault_verification.rs::runbook_crash_loop_escalates_to_lockdown`).

## When to use

- Gateway/process repeatedly crashes and the supervisor escalates to **security LOCKDOWN** after N crashes within the configured window (default 3 crashes / 5 minutes, per S24/guard policy).
- Operator needs to diagnose cause, stabilize service, and perform authorized recovery/exit.

## Expected behavior

- Individual crashes may restart to a reconciled safe state; **N crashes within window ⇒ LOCKDOWN** persisted (DB + secondary indicator as configured) and `ReasonCode::EnteredLockdown` / crash-loop reason emitted.
- In LOCKDOWN: commands/actuation suspended (INV-5); only authorized exit flow applies.

## Detection and triage

1. **Check mode and persistence:**
   ```bash
   printf '%s\n' '{"cmd":"mode"}' | socat - UNIX-CONNECT:/run/tirbase/admin.sock
   ```
   Expect `Lockdown` when escalated; confirm indicators/logs.
2. **Collect diagnostics (no secret material):**
   - Service supervisor logs (systemd/journald), crash timestamps/count.
   - `tirbase-admin verify-log --db-path /var/lib/tirbase/primary.db --json`
   - `sqlite3 /var/lib/tirbase/primary.db "PRAGMA quick_check;"`
   - Recent security events (export) for `EnteredLockdown`, crash/fault reasons.
3. **Identify fault class:** config/DB corruption, resource exhaustion, bad deployment, hardware fault, or security-induced failure. If tamper/rollback suspected, switch to `docs/runbooks/tamper.md` or `docs/runbooks/restore.md`.

## Stabilization

- Fix underlying cause (configuration, storage, dependencies, hardware). Do **not** clear LOCKDOWN persistence manually.
- Ensure binaries/config/profiles are consistent and signed artifacts validate.
- If corruption detected, prefer controlled restore (`docs/runbooks/restore.md`) over ad-hoc DB edits.

## Manual/authorized LOCKDOWN considerations

- Security LOCKDOWN is entered by guard/supervisor/escalation logic; operators should not bypass it.
- If an operator must keep the node non-actuating during investigation, maintaining LOCKDOWN is correct until authorized exit conditions are met.

## Recovery and exit

1. After stabilization and verification, perform **M-of-N LOCKDOWN exit** (≥ 2 distinct roles, full valid `EnvelopeProfile`) per `docs/runbooks/lockdown.md`.
2. Monitor for re-escalation; adjust deployment/supervision only through approved change control.

## Rollback / escalation

- If exit cannot be authorized, remain in LOCKDOWN and escalate to key holders/operators.
- If crashes resume after exit, re-enter diagnosis; repeated escalation indicates unresolved fault or active condition—treat as incident.

## Verification

- **Simulated fault:** 3 crashes within 5 minutes escalate to LOCKDOWN; fewer/outside window do not (`tirbase-sim/src/scenarios/s24_crash_loop.rs::s24_crash_loop_escalates_to_lockdown_within_window`).
- **Procedure verification (escalation threshold and persisted lockdown state):** `tirbase-sim/tests/runbook_fault_verification.rs::runbook_crash_loop_escalates_to_lockdown`.
