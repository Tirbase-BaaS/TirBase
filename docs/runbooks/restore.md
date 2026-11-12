# Runbook: Restore from Backup (Epoch Bump + LOCKDOWN Re-entry)

> **Status:** Procedure documented and verified against `tirbase-sim` simulated faults (see **Verification**). Mitigates snapshot-restore/rollback attacks (S22, PV-9.8, RD-2).
>
> **[CLAIM-55.3]** — **Proven** (procedure + simulated-fault verification `tirbase-sim/tests/runbook_fault_verification.rs::runbook_restore_bumps_epoch_and_rejects_prior_epoch`).

## When to use

- Restoring gateway state from a backup after corruption, hardware replacement, or operator recovery.
- Any suspected rollback of primary state/counters/epochs (S22). **Restore is not a silent rewind:** it must advance enrollment epoch and re-enter LOCKDOWN for re-attestation.

## Safety invariants (must hold)

- `tirbase-admin restore` MUST NOT silently update sequence numbers or anti-rollback counters.
- Restore performs: `quick_check` on backup, copy/restore primary DB, optional delta-log replay, **signed enrollment-epoch bump record**, and **enter LOCKDOWN** (reason indicates restore + signed epoch bump).
- After restore, commands from a prior enrollment epoch are rejected (epoch regression/stale-epoch protections).

## Preconditions

- Trusted backup DB file and (if applicable) reviewed, signed delta/security log captured after restore point.
- Paths/DBs: target `primary.db`, `epoch_store.db` (device/enrollment epoch store), `lockdown.db`/state store as used by deployment.
- Operator-held **Ed25519 signer seed** for the signed restore/epoch-bump authorization record (keep secret; never log).

## Procedure

### 1. Validate backup and plan

```bash
sqlite3 /path/to/backup.db "PRAGMA quick_check;"
# Inspect backup provenance and ensure it is the intended restore point.
```
If `quick_check` fails, do not restore from this image.

### 2. Run restore (enters LOCKDOWN, bumps epoch)

```bash
tirbase-admin restore \
 --backup-db /path/to/backup.db \
 --target-db /var/lib/tirbase/primary.db \
 --epoch-store-db /var/lib/tirbase/epoch_store.db \
 --lockdown-db /var/lib/tirbase/lockdown.db \
 --signer-seed-hex <32-byte-ed25519-seed-hex> \
 --output /var/lib/tirbase/restore-report.json \
 [--delta-log /path/to/reviewed-delta-log.sql]
```

**Notes:**
- `--delta-log` (optional): replays reviewed SQL statements captured after the restore point; restore never synthesizes counters.
- `--signer-seed-hex`: operator-held seed for the signed epoch-bump audit record; protect as secret material.

**Expected output (stdout/file `restore-report.json`, illustrative):**
```json
{
 "quick_check_ok": true,
 "restored_db": "/var/lib/tirbase/primary.db",
 "delta_log_replayed": false,
 "delta_entries_applied": 0,
 "previous_enrollment_epoch": <u64>,
 "new_enrollment_epoch": <u64>,
 "epoch_bump_signature_hex": "<hex>",
 "lockdown_entered": true,
 "counters_silently_updated": false,
 "post_restore_logical_dump_sha256": "<hex>"
}
```

**Required checks:** `quick_check_ok=true`, `lockdown_entered=true`, `counters_silently_updated=false`, `new_enrollment_epoch > previous_enrollment_epoch`.

### 3. Verify LOCKDOWN and epoch posture

```bash
printf '%s\n' '{"cmd":"mode"}' | socat - UNIX-CONNECT:/run/tirbase/admin.sock
```
Expect `Lockdown` with persistence indicators set. Confirm prior-epoch commands are rejected and peers observing regression emit `EpochRegression` (operational monitoring).

### 4. Re-attest and exit LOCKDOWN (authorized)

After validating restored state, profiles, keys, and integrity:
- Follow `docs/runbooks/lockdown.md` to perform M-of-N `lockdown-exit` with a full valid `EnvelopeProfile`.
- If integrity/tamper is suspected, follow `docs/runbooks/tamper.md` before exit.

## Rollback / failure handling

- **If restore command fails:** do not start gateway against a partially restored DB; preserve artifacts, fix cause (bad backup, path/permissions, malformed delta log), and retry from a known-good backup.
- **If wrong backup restored:** treat as potential rollback incident (S22): keep system in LOCKDOWN, re-run restore with correct backup (epoch will bump again as recorded), and audit.
- **If epoch/counter regression detected at boot:** gateway must enter LOCKDOWN (PV-9.8 / S22 controls); do not override by manual counter edits.

## Verification

- **Simulated fault:** snapshot restore triggers boot rollback detection + epoch bump invalidating prior-epoch commands and peer regression detection (`tirbase-sim/src/scenarios/s22_snapshot_restore.rs::run_s22`).
- **Procedure verification (epoch bump + prior-epoch rejection semantics):** `tirbase-sim/tests/runbook_fault_verification.rs::runbook_restore_bumps_epoch_and_rejects_prior_epoch`.
