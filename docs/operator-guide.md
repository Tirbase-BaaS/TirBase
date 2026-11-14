# Operator Guide (TirBase)

This guide is for day-to-day operators of a deployed TirBase gateway/node. It complements runbooks in `docs/runbooks/`.

## Responsibilities (typical)

- Monitor health (`/health`), metrics, and alerts (SLO runbooks under `docs/runbooks/slo-*`).
- Apply approved policy/profile updates only through documented, signed procedures.
- Respond to incidents using runbooks (lockdown, tamper, crash loop, key compromise, time anchor failure, restore, storage/retention/DR).
- Maintain backups and verify restore drills periodically (`docs/runbooks/restore.md`, `docs/runbooks/storage-retention-dr.md`).

## Daily / weekly checks (suggested)

- Verify gateway process healthy and recent security events flowing.
- Review any `LOCKDOWN` or `RESTRICTED` mode transitions.
- Check disk usage, flash write estimates, and certificate/token expiry calendars (external).
- Confirm time synchronization health if applicable (`docs/time-sync.md`).

## Key procedures (pointers)

| Need | Document |
|------|----------|
| Lockdown entry/exit (M-of-N) | `docs/runbooks/lockdown.md` |
| Tamper response | `docs/runbooks/tamper.md` |
| Key compromise | `docs/runbooks/key-compromise.md`, `docs/runbooks/key-management.md` |
| Restore from backup | `docs/runbooks/restore.md` |
| Crash loops | `docs/runbooks/crash-loop.md` |
| OTA/rollout issues | `docs/runbooks/canary-failure.md`, F-11 OTA admin/API docs in code/config comments |

## Safety and non-goals

- TirBase is **not** a SIL/PLC replacement (see `docs/THREAT_MODEL.md`). Physical safety interlocks remain external.

## Getting help

- Follow `SECURITY.md` for vulnerabilities; use internal escalation channels for operational incidents (see incident templates in `docs/incident-communication-templates.md` once published).
