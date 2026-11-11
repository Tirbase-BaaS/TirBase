# Runbook: Tampered Security Event Log (Hash-Chain Break / Tail Truncation)

> **Status:** Procedure documented and verified against `tirbase-sim` simulated faults (see **Verification**). Applies to tamper detection, restricted mode, and signed chain recovery (PV-7.4, PV-7.10, INV-4, S14).
>
> **[CLAIM-55.2]** — **Proven** (procedure + simulated-fault verification `tirbase-sim/tests/runbook_fault_verification.rs::runbook_tamper_detection_and_chain_recovery`).

## When to use

- Boot or runtime verification reports a **broken hash chain** or **tail truncation** / checkpoint discrepancy.
- Gateway enters **Restricted** mode: commands/actuation rejected; mesh sync and log export remain available for diagnosis (mode matrix, INV-5/INV-4 context).

## Detection and expected indicators

- Security events: `ReasonCode::TamperDetection` (interior break; identifies first broken sequence) and/or `TailTruncation` as applicable.
- New chain segment opened from next valid boundary on interior break; node remains in `Restricted` until signed recovery.
- `tirbase-verify-log` / `tirbase-admin verify-log` reports chain status and broken sequence(s).

**Example (integrity check):**
```bash
tirbase-admin verify-log --db-path /var/lib/tirbase/primary.db
# or JSON
tirbase-admin verify-log --db-path /var/lib/tirbase/primary.db --json
```
**Expected output (intact):** exit code 0 and report indicating chain intact. **On break/tamper:** non-zero exit and report naming affected sequence/range.

## Immediate containment

1. **Preserve evidence:** snapshot/copy `primary.db` (and exports) read-only before repair attempts.
   ```bash
   sqlite3 /var/lib/tirbase/primary.db "PRAGMA quick_check;"
   tirbase-admin export-evidence-bundle --db-path /var/lib/tirbase/primary.db --key-path <device-key.json> --output /secure/evidence-bundle.json
   tirbase-admin export-log --db-path /var/lib/tirbase/primary.db --key-path <device-key.json> --output /secure/security-log.json --format json
   ```
2. **Do not** delete or rewrite security events in place.
3. Confirm `Restricted`:
   ```bash
   printf '%s\n' '{"cmd":"mode"}' | socat - UNIX-CONNECT:/run/tirbase/admin.sock
   ```

## Recovery procedure (signed chain-recovery)

Exit from tamper-induced `Restricted` requires an operator-issued **signed chain-recovery** command (M-of-N PolicyAuthority/RevocationManager per trust-root policy, distinct authorized signers).

### 1. Determine recovery boundary

- Use `verify-log` / evidence bundle to identify first broken/tail-truncated sequence and last trusted checkpoint/segment.
- Establish `new_segment_id` and `from_seq` for the recovery payload per incident findings.

### 2. Prepare and submit `ChainRecoveryPayload`

Payload fields (per `tirbase_guard::lockdown::ChainRecoveryPayload`, context `TirBase/v1/ChainRecovery`): `node_id`, `issued_at_est`, `reason`, `from_seq`, `new_segment_id`. Sign as `SignedOperation<ChainRecoveryPayload>` with required authorized roles.

```bash
printf '%s\n' '{
  "cmd":"chain-recovery",
  "payload":{
    "operation": <SignedOperation<ChainRecoveryPayload> JSON>,
    "payload": {
      "node_id":"<node-id>",
      "issued_at_est": <i64>,
      "reason":"<tamper recovery rationale>",
      "from_seq": <u64>,
      "new_segment_id": <u64>
    }
  }
}' | socat - UNIX-CONNECT:/run/tirbase/admin.sock
```

**Expected output (success):**
```json
{"status":200,"mode":"Normal","outcome":"chain_recovery_applied","new_segment_id":<u64>}
```

**Expected output (failure):** `409` with typed authorization/signature/payload error; node remains `Restricted`.

### 3. Post-recovery verification

- `mode` returns to `Normal` (if no other lockdown condition).
- Append-only logging resumes on the new segment; emit/retain recovery event.
- Re-run `tirbase-admin verify-log` on current chain segment expectations and monitor for recurrence (possible ongoing compromise → escalate to `docs/runbooks/key-compromise.md`).

## Rollback / escalation

- If signatures/threshold cannot be satisfied, remain `Restricted` (safe for diagnosis) and escalate to authorized key holders.
- If tamper indicates key/host compromise, follow `docs/runbooks/key-compromise.md` and consider restore path `docs/runbooks/restore.md`.
- Flooding/suppression context (rate limits, S14): investigate `SuppressionSummary`/rate events but treat unexplained chain breaks as tamper until disproven.

## Verification

- **Simulated fault:** interior hash-chain break injected into `security_events` (production `SecurityEventLog` verification path) triggers `Restricted` and `TamperDetection` (`tirbase-gateway/tests/task26_tamper_detection.rs::claim_26_1_verify_hash_chain_at_startup_enters_restricted_on_broken_link`).
- **Procedure verification (detect break, apply signed chain recovery, mode Normal):** `tirbase-sim/tests/runbook_fault_verification.rs::runbook_tamper_detection_and_chain_recovery`.
