# Operational Procedures

This index covers documented operational procedures. Where a runbook exists,
follow it as the authoritative step-by-step source.

## Enrollment and identity

- Device enrollment and bootstrap (nonce/replay-safe)
- Token minting, rotation, and identity inspection (`tirbase-admin`)
- Root ceremony: [`docs/root-ceremony.md`](../../root-ceremony.md)

## Policy and command operations

- Profile installation and validation
- Policy tightening (fast apply) and loosening (M-of-N, time-lock/cancel window)
- Command simulation/dry-run before actuation
- Challenge nonce flow for critical parameters in `UNVERIFIED` freshness state

## Safety and incident response

- Lockdown entry/exit (M-of-N, multi-role) and restricted-mode recovery
- Hash-chain tamper response and chain recovery
- Unknown-effects reconciliation and operator clear procedures
- Restore from backup (integrity checks, delta replay, epoch bump, lockdown re-entry)
- Key compromise and revocation handling
- Crash-loop escalation handling

## Fleet and rollout

- Fleet inventory/revocation propagation
- Staged rollout status and signed rollback operations

## Verification and export

- Security event inspection/export and evidence bundle generation
- Log verification (`tirbase-verify-log` / documented verification procedures)
- Demo pack execution: `tirbase-demo/<pack>/run.sh`

Runbook sources (when present): `docs/runbooks/*.md`.
