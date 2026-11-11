# Runbook: Key Compromise Detection and Revocation

> **Status:** Procedure documented and verified against `tirbase-sim` simulated faults (see **Verification**). Applies to issuer/device/role key compromise response (PV-3.x, PV-5.5/PV-5.8a, S10).
>
> **[CLAIM-55.4]** — **Proven** (procedure + simulated-fault verification `tirbase-sim/tests/runbook_fault_verification.rs::runbook_key_compromise_revocation_rejects_revoked_issuer`).

## When to use

- Evidence or suspicion that a signing key, Biscuit/root material, device identity, or role credential is compromised (unexpected commands/events, anomalous issuers, leaked secrets, failed integrity checks correlated with actor DID).
- Revoked issuer activity observed (commands/deltas must be rejected; leases/state handled per policy).

## Detection signals

- Security events indicating unauthorized/revoked activity: `IssuerRevoked`, revocation application/propagation events, unexpected `ScopeViolation`/auth failures, or `EpochRegression`/tamper indicators in correlated incidents.
- Mesh: deltas/commands from a revoked DID rejected (S10 / inbound revocation enforcement).
- Audit: `tirbase-admin verify-log`, `export-log`/`export-evidence-bundle`, and guard status for affected issuers.

## Containment (immediate)

1. **Stop trust in the compromised credential:** revoke the DID/credential per authorized process (RevocationManager and/or policy-defined M-of-N). Do not issue new tokens/approvals with compromised material.
2. **Isolate if needed:** if compromise is ongoing or scope unclear, enter/maintain **LOCKDOWN** (see `docs/runbooks/lockdown.md`) to halt commanded actuation while preserving diagnosis/export.
3. **Preserve evidence:** export signed evidence bundle and logs before rotation/remediation steps that may change state.
   ```bash
   tirbase-admin export-evidence-bundle --db-path /var/lib/tirbase/primary.db --key-path <device-key.json> --output /secure/evidence-bundle.json
   tirbase-admin verify-log --db-path /var/lib/tirbase/primary.db --json
   ```

## Revocation procedure

1. **Identify compromised identity scope:** DID(s), role(s), device(s), tokens, and dependent enrollments/leases.
2. **Apply revocation through the authorized control plane** (RevocationManager credential; M-of-N where required by trust root/policy). Use deployment-specific signed revocation/re-enrollment operations; ensure propagation to connected peers (mesh sync) and local admission state.
3. **Confirm enforcement:**
   - Subsequent commands/deltas from revoked DID are rejected with typed authorization/revocation errors (coarse `UNAUTHORIZED`/revocation reasons as applicable).
   - Leases held by revoked issuers released per guard rules; no further actuation accepted from revoked identity.
4. **Rotate/replace affected keys and credentials:**
   ```bash
   # Rotate local device identity (backs up previous key); update dependent trust/enrollment as required
   tirbase-admin rotate --key-path /var/lib/tirbase/device-key.json
   # Inspect identities (public material only)
   tirbase-admin inspect-identities --identity /var/lib/tirbase/device-key.json --identity /var/lib/tirbase/device-key.json.bak
   ```
   Re-enroll/re-mint scoped tokens only after trust root/role registries and epoch posture are correct (`tirbase-admin enroll`, `tirbase-admin mint` within TTL limits).
5. **If root/trust material or epoch integrity is impacted:** follow `docs/runbooks/restore.md` (epoch bump + LOCKDOWN re-entry) and `docs/root-ceremony.md` processes; do not silently rewind counters.

## Post-revocation verification

- `verify-log` intact (or handle per `docs/runbooks/tamper.md` if broken).
- Guard status/mode consistent; no accepted commands from revoked DID.
- Fleet/peers have converged on revocation (within propagation expectations).

## Rollback / escalation

- If revocation cannot be applied due to missing quorum/keys, maintain LOCKDOWN and escalate to authorized custodians.
- If compromise includes PolicyAuthority/RevocationManager/root keys, treat as critical incident: preserve evidence, follow root-ceremony/trust-rotation procedures, and restore/re-enroll per controlled process.
- Avoid reusing or “unrevoking” compromised keys.

## Verification

- **Simulated fault:** revoked-author activity is rejected (`tirbase-sim/src/scenarios/s10_revoked_delta.rs::run_s10` rejects post-revocation deltas from revoked DID).
- **Procedure verification (revoked issuer cannot be treated as authorized):** `tirbase-sim/tests/runbook_fault_verification.rs::runbook_key_compromise_revocation_rejects_revoked_issuer`.
