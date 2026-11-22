# ST-07 — Gate anti-replay and ticket revocation

Crate: `tirbase-venue-admission` (AGPL-3.0-only). Depends on ST-05
(`tirbase-venue-ticket`) for signed tickets, denial codes and the issuer key
ring, and sits beside ST-06's capacity counting. The guard reads no clock and
does no I/O; the gate supplies the instant and the caller supplies the
verification keys.

## Replay key

A presentation is keyed as `ticket id + nonce + gate id + epoch`:

```
ReplayKey { ticket_id, nonce, gate_id, epoch }
key()        -> "<ticket>#<nonce>@<gate>@<epoch>"
ticket_key() -> "<ticket>#<nonce>"
```

`EpochPolicy { epoch_len_us }` buckets the presentation time; accepted lengths
are 1 s to 24 h, default 15 minutes. The exact key catches a retried delivery
at the same lane and epoch. The **ticket-level claim** records the first gate
that admitted the ticket and outlives the epoch, so reuse at a second gate is
`CrossGate` even after the epoch rolls over, and a later epoch at the same gate
is `AlreadyUsed`. Both records expire when the ticket's validity window closes.

`GateReplayGuard::admit` answers `Fresh`, `Duplicate`, `CrossGate`,
`AlreadyUsed`, `NotYetValid` or `WindowClosed`, recording only on `Fresh`.
Reuse after the window is refused (`WindowClosed`, or ST-05's `Expired` in the
admission guard) and the store is reclaimed by `prune(now)`.

The store is bounded on both maps by `capacity` (1..=1,000,000, default
100,000), evicting the entry with the earliest expiry and counting evictions.
`to_json`/`from_json` persist it across a reader restart and re-validate the
bounds. Eviction is honest: if both the exact key and the claim for a ticket
have been evicted, that ticket can be admitted again, so deployments size the
bound above the number of live tickets in the longest window.

## Revocation deltas

A `RevocationDelta` is a chained change `base_version -> version` with an
issue time, an expiry, added and removed ticket ids, an approval threshold and
an emergency flag. An empty change is a legal heartbeat that renews the list's
expiry at a new version; a ticket cannot be both added and removed by the same
delta.

Signatures cover deterministic, domain-separated bytes:

```
"TirBase/v1/VenueRevocationDelta" 0x00 || key_id ||
base_version || version || issued_at || expires_at ||
approvals_required || emergency ||
count+added ids || count+removed ids
```

Each approver signs with their own key, so the delta carries a list of
`DeltaSignature { key_id, signature }`. `SignedRevocationDelta::verify`:

1. refuses a delta whose expiry has passed (`Expired`);
2. for an emergency delta, refuses a lifetime longer than
   `policy.emergency_max_ttl_us` (`EmergencyTtlTooLong`);
3. refuses a duplicate signer key (`DuplicateSigner`);
4. verifies every signature against the issuer key ring at the verification
   instant (`Signature`);
5. requires `max(delta.approvals_required, policy threshold)` distinct valid
   signatures (`InsufficientApprovals`), where the threshold is
   `policy.required` routinely and `policy.emergency_required` in an emergency.

`DeltaPolicy::standard()` is one routine signature, two emergency signatures
and six hours of maximum emergency validity. An emergency revocation therefore
needs M of N custodians (2 of 3 in the tests) and cannot be used to keep a stale
list alive.

## Offline accumulation

`RevocationLedger` holds the accumulated version, expiry and revoked ticket
ids. `apply` verifies a delta and requires `base_version == version`, refusing a
gap; re-applying an old version reports `AlreadyApplied`.

`RevocationAccumulator` is the gateway-side queue:

* a delta whose base is the applied version applies immediately and drains any
  queued successors;
* a delta above the applied version with a future base is queued in a bounded
  `pending` map (default 64, max 4,096) and reported as
  `Queued { waiting_for }`;
* a fork below the applied version is `Gap`, and two different deltas claiming
  the same version are `ConflictingVersion`;
* `apply_bundle` sorts a peer's bundle by version and applies the chain
  regardless of arrival order, so gateways that were offline converge.

## Gate decision

`GateAdmission::admit(ticket, gate, at, ring)` evaluates, in order:

1. payload shape and ST-05 signature/key state (`Ticket(Denial)`);
2. the ticket's validity window (`Ticket(NotYetValid | Expired)`);
3. revocation-list freshness — a version 0 ledger is
   `RevocationListMissing`, an expiry at or before `at` is
   `RevocationListExpired`;
4. the accumulated revocation list (`Revoked`);
5. single use (`Duplicate`, `CrossGate`, `AlreadyUsed`).

Both stale-list modes refuse the ticket. `StalePolicy::Alarm` also records a
`RevocationAlarm { reason: Missing | Expired, version, expires_at, detected_at }`
readable with `take_alarm()`; `FailClosed` refuses silently. There is no
"accept anyway" mode.

Ticket entitlement (event, venue, gate, zone scope, holder binding) remains
ST-05's validator's job; this guard assumes an authenticated ticket and adds
cross-gate single use and revocation propagation.

## Tests

`tirbase-venue-admission/tests/st07_replay.rs` (11 tests):

* a ticket admitted once is refused at a second gate (`cross_gate`, naming the
  claiming gate) and again at the first gate (`duplicate` with gate and epoch);
* reuse after the validity window (`expired`), before it (`not_yet_valid`), and
  guard-level `window_closed`/`not_yet_valid`;
* replay keys carry gate and epoch, same gate in a later epoch is
  `already_used`, another gate is `cross_gate`;
* a revoked ticket is denied after a v2 delta syncs, even with a new nonce;
* offline accumulation: v2/v3 arrive before v1 and queue, v1 closes the chain
  to version 3, a peer's reverse-order bundle applies all three, a fork is a
  gap, conflicting versions and a full pending queue are refused;
* stale-list policy: missing and expired lists are refused under both policies
  and alarmed only under `Alarm`; an expired delta is never applied;
* M-of-N: one signature cannot pass a 2-of-3 emergency, two can, duplicate
  signers are refused, an emergency over the TTL cap is refused, a routine
  delta's own threshold and the stricter policy threshold are enforced;
* tampered deltas fail signature verification, and tampered tickets fail with
  ST-05's `bad_signature`/`unknown_issuer_key`;
* the replay store's capacity eviction, window cleanup and JSON persistence;
* eight threads presenting one ticket simultaneously admit exactly once, and
  eight threads × 50 distinct tickets admit all 400 exactly once.

No live gate, reader or gateway sync was exercised; the guard is pure and every
path is driven through signed tickets, signed deltas and typed decisions.
