# ST-05 — Offline ticket validation kernel

Crate: `tirbase-venue-ticket` (AGPL-3.0-only). Depends on ST-01
(`tirbase-venue`) for the shared identifiers; F-05 owns private key custody.
The kernel never reads a clock, never performs I/O and never allocates
unbounded state: the caller supplies `at_utc_us`, the key ring, the signed
revocation list and the replay store.

## Decision path

`OfflineValidator::validate(&SignedTicket, &ValidationRequest)` answers in a
fixed order, stopping at the first failure:

1. payload shape (lengths, non-empty window, non-zero nonce);
2. issuer key state at `at_utc_us` and the Ed25519 signature;
3. venue scope: event, venue, gate, zone;
4. validity window `[valid_from, valid_until)`;
5. holder binding, per `HolderPolicy`;
6. revocation-list presence and freshness;
7. ticket presence in the revocation list;
8. anti-replay (`ticket_id#nonce`), recording only on admission.

A success returns an `Admission` (ids, nonce, whether the holder was bound); a
failure returns a `Denial`, each variant carrying its own typed data and a
stable machine code (`code()`) for gateway events and guard-console grouping.

## Canonical payload and signature

The payload is encoded by hand, not by serde, so the signature covers exactly
the bytes the issuer produced:

```
"TirBase/v1/VenueTicket" 0x00 || key_id || version ||
ticket_id || event_id || venue_id || gate_id || zone_id ||
valid_from (LE i64) || valid_until (LE i64) || nonce (LE u64) ||
holder_present (0|1) [ || holder_kind (u8) || holder_digest ]
```

Every string is `u16` length-prefixed and length-bounded (`MAX_ID_LEN`,
`MAX_HOLDER_LEN`). Ticket JSON exists for transport only; signatures never
cover JSON.

Private keys are not held here. Signing goes through the `TicketSigner`
trait, so an F-05 HSM custodian signs without exporting key material
(`Ed25519Signer`, with a redacted `Debug`, is for tooling and tests).

## Revocation list

`TicketRevocationList { version, issued_at_utc_us, expires_at_utc_us,
tickets }` is sorted and deduplicated on construction and distributed inside
`SignedRevocationList`, signed over a separate domain
(`TirBase/v1/VenueTicketRevocation`) with the same issuer keys.

`refresh_revocation(&signed, at_utc_us)` refuses, in order: a list whose
signature or key state does not verify (`RevocationListSignature`), a version
older than the applied one (`RevocationListRollback`), and a list that is
already expired (`RevocationListExpired`, plus an alarm under the alarm
policy). Equal versions may be re-applied (a renewal with a later expiry).

## Stale-list policy

| Policy | Ticket decision | Operator alarm |
| --- | --- | --- |
| `StaleRevocationPolicy::FailClosed` | denied | none |
| `StaleRevocationPolicy::Alarm` | denied | `StaleListAlarm` via `take_alarm()` |

There is no third "accept anyway" mode. `ValidatorPolicy` additionally carries
`require_revocation_list` (default `true`) and `HolderPolicy`
(`Ignore`/`Optional`/`Required`, default `Optional`). A missing list under
`require_revocation_list` is `RevocationListMissing`; dropping the requirement
is an explicit deployment decision, not a fallback.

## Key rotation and revocation

`IssuerKeyRing` holds public keys only. `rotate(new_key_id, public_key, at,
overlap_us, validity_us)` closes the previous key's window at
`min(its not_after, at + overlap)` and activates the new key at `at`, so
tickets signed before the rotation keep validating through the overlap and
fail with `KeyExpired` afterwards. `revoke(key_id, at)` denies that key
immediately, including inside its overlap.

## Anti-replay bounds

`ReplayStore::new(capacity, retention_us)` accepts `1..=100_000` entries and
`1..=30 days`. `record` prunes entries older than the retention window,
evicts the oldest when still full (counting evictions), then records
`ticket_id#nonce`. `to_json`/`from_json` persist the store across a reader
restart and re-validate the bounds on load.

## Tests

`tirbase-venue-ticket/tests/st05_ticket.rs` (17 tests):

* done-when: a valid ticket admits offline; a replay is `replayed`; a revoked
  ticket is `revoked_ticket`; an expired list is denied under both policies,
  with an alarm only under `Alarm`; a missing list is denied; an expired list
  cannot be refreshed;
* rotation overlap, expiry after the overlap, new-key tickets, and a revoked
  key inside its window;
* revocation refresh: monotonic versions, rollback refusal, forged signature;
* wrong event/venue/gate/zone, early, expired, holder matching/required/ignored,
  corrupted signature, unknown key, tampered payload, deterministic canonical
  bytes and JSON round trips;
* replay store capacity, eviction, retention pruning, persistence and bound
  validation;
* property tests (48 cases each) for replay, times outside the window, wrong
  venue or gate, every single-nibble signature corruption and unknown issuer
  keys.

No live reader, turnstile or network was exercised: the kernel is pure and
tested by construction, and F-05 signing is wired at the custodian seam rather
than in this crate.
