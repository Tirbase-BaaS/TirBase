# Storage, retention, backup and disaster recovery (F-07)

This runbook covers `primary.db` / `derived.db`, the signed security-event
archive, per-class retention, legal holds, and backup/PITR/DR drills. It does
not replace the wider restore procedure in `docs/runbooks/backup-restore.md`
or the lockdown rules in `docs/runbooks/restore.md`.

## Record classes and defaults

| Class | Examples | Default retention | Deletion path |
|---|---|---|---|
| Operational | idempotency keys, enrollment/challenge nonces | 30 days / own expiry | Retention sweep, audited |
| Audit | `security_events`, checkpoints, archive segments | 90 days / 1 GiB | Signed segment archive, then delete |
| Money | `applied_effects_ledger` | Retained (7-year policy is deployment-specific) | Explicit operator opt-in only |
| Safety | pending approvals, safety-relevant records | Retained indefinitely | Manual, with legal review |

Every sweep writes a `retention_runs` row **and** appends a `LogRotated`
security event containing the class, row count and legal-hold state.

## Legal holds

A legal hold freezes a whole class (or can be scoped with a subject) until it is
released. The audit retention loop fails closed: an unreadable hold table is
treated as held, and no segment is archived or deleted.

```bash
# Place an audit hold before litigation/regulator contact
tirbase-admin retention --db-path /var/lib/tirbase/primary.db \
  --key-path /etc/tirbase/device.key \
  --hold-class audit --hold-subject matter-2026-11 --hold-reason "regulator request"

# Release it only after written confirmation
tirbase-admin retention --db-path /var/lib/tirbase/primary.db \
  --key-path /etc/tirbase/device.key --release-hold hold-<timestamp>-audit
```

Verify the hold took effect by checking that the report lists the class under
`blocked_by_legal_hold`, and that the audit log contains the corresponding
`LogRotated` record.

## Migration safety

Migrations run one version per transaction and are idempotent. A failing
migration leaves the previous schema in place; the version does not advance and
no partial DDL survives. Forward and backward operations are available in the
gateway migration framework (`apply_migrations`, `rollback_migrations`).

```bash
# Test a rollback on a copy, never on the live DB
cp /var/lib/tirbase/primary.db /tmp/primary.test.db
# library/API: rollback_migrations(&conn, DbKind::Primary, primary_migrations(), target)
```

Before any schema change: take a signed backup (below), run the migration on a
copy, and verify `quick_check` plus the ledger root hash.

## Backup

```bash
tirbase-admin backup \
  --db-path /var/lib/tirbase/primary.db \
  --out-dir /backup/site-a/2026-11-14 \
  --key-path /etc/tirbase/device.key
```

The output contains `ledger.db` (a consistent SQLite snapshot) and a signed
`manifest.json` with:

- `ledger_root_hash` — SHA-256 over the deterministic logical dump,
- `max_security_event_seq` — the PITR starting point,
- schema version, signer DID and Ed25519 signature.

`VACUUM INTO` is used so the snapshot is transactionally consistent without
stopping the gateway.

## Restore

```bash
tirbase-admin restore-backup \
  --backup-dir /backup/site-a/2026-11-14 \
  --target-db /var/lib/tirbase/primary.restored.db
```

The restore verifies the manifest signature, `quick_check`, and that the
reproduced logical dump hashes to the manifest's `ledger_root_hash`. A mismatch
is refused. Move the verified database into place only during a maintenance
window and follow the lockdown/re-attest steps in the restore runbook.

## Point-in-time recovery

```bash
# Export the delta since the snapshot (typically from a still-live or replicated DB)
# library: backup::export_delta(&db, manifest.max_security_event_seq) -> JSONL

tirbase-admin pitr \
  --backup-dir /backup/site-a/2026-11-14 \
  --delta-log /backup/site-a/2026-11-14.delta.jsonl \
  --target-db /var/lib/tirbase/primary.pitr.db \
  --expected-root <live-ledger-root-hash>
```

PITR replays `security_events` rows with `INSERT OR IGNORE`, so a retried run is
idempotent. The command fails closed unless the recovered root hash equals the
live root hash supplied by the operator.

## DR drill

```bash
tirbase-admin dr-drill \
  --db-path /var/lib/tirbase/primary.db \
  --work-dir /tmp/tirbase-drill \
  --key-path /etc/tirbase/device.key \
  --delta-log /backup/site-a/2026-11-14.delta.jsonl
```

The drill creates and verifies a signed backup, restores it, replays the delta,
and compares the recovered root hash with the live database. Archive the JSON
report as drill evidence; a `passed: false` is an incident.

## Encrypted exports and archives

Retention archives are signed manifests; exported record sets can additionally
be sealed with ChaCha20-Poly1305 using a key derived from the device
`KeyProvider` (never stored):

```bash
tirbase-admin encrypt-export --key-path /etc/tirbase/device.key \
  --input export.json --output export.sealed.json --aad "tenant=site-a;range=1..42"

tirbase-admin decrypt-export --key-path /etc/tirbase/device.key \
  --input export.sealed.json --output export.json --aad "tenant=site-a;range=1..42"
```

The sealed envelope carries a nonce, the AEAD tag, the signer DID and a
plaintext SHA-256. Wrong AAD, wrong device key, or any ciphertext change fails
authentication before plaintext is trusted. Archiving never removes audit rows
by itself; only the retention path deletes, and it archives first.

## Storage budgets

```bash
tirbase-admin storage-budget --data-dir /var/lib/tirbase \
  --ledger-bytes 8589934592 --archive-bytes 34359738368
```

`gateway.toml` sets `ledger_storage_budget_bytes` and
`archive_storage_budget_bytes`; exceeding either is logged at boot as a warning
with the reclaimable classes. Flash *wear* is separate and controlled by
`flash_budget_bytes_per_day` / `flash-wear-estimate` (PV-15.4).
