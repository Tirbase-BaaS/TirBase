# ST-14 — Ticketmaster and Eventim connectors

**Status:** complete in the closed product tree (release packaging gated).
**Licence:** commercial / proprietary. **Repo:** closed. **Depends on:** ST-10
connector framework, ST-00 integrator and safety-case gate.

ST-14 is delivered as **two separately sold connectors**, not open runtime code.
Neither the source nor the product documentation is part of this repository: they
live in the git-ignored `closed/venue-ticketing/` tree and ship from the private
repository of the selling entity under
[`LICENSING.md`](../../LICENSING.md).

## What the product does

| Requirement | Delivered behaviour |
|---|---|
| Issuance, cancellation, transfer, revocation feed | Strict, `deny_unknown_fields` lifecycle records with a monotonic per-ticket sequence; a stale replay cannot roll a revoked ticket back to issued. |
| Offline revocation | One sync writes the gate's offline cache. A revocation is effective from its own timestamp and is enforced from the persisted cache with no vendor connection. |
| Scan status and reconciliation | Every scan is recorded once under a deterministic idempotency key; a replay returns the original decision and never admits twice. Reconciliation reports agreement, scans the vendor never saw, scans the venue never recorded and outcome mismatches. |
| Webhook verification and replay protection | Timestamped HMAC-SHA256 callbacks; unsigned, stale, tampered and replayed callbacks are refused before state changes. |
| Event, venue and seat mapping | Explicit vendor-to-venue mapping that refuses conflicts and unmapped ids instead of guessing. |
| Sandbox contract tests and mock server | Loopback mock vendor server (feed, scan submission, scan status) plus opt-in vendor sandbox runs with customer credentials. |
| Setup, credentials and support | Setup, credentials/rotation, sandbox, conformance, failure-recovery and support documents, each a required gate artefact. |
| Open conformance | Both connectors are certified by `tirbase_venue_connectors::certify`. |

## Licence boundary

```text
closed Ticketmaster / Eventim connector (proprietary, sold per product)
        │
        ├── tirbase-venue-connectors   Apache-2.0  (open conformance suite)
        │        └── tirbase-integrations Apache-2.0
        │
        └── (no edge to) tirbase-venue*, tirbase-gateway, tirbase-core, …
                              AGPL-3.0-only venue/runtime crates
```

`scripts/check-venue-ticketing.py` reads the closed `Cargo.lock` and fails on any
first-party crate outside that Apache-2.0 surface, and on any `tirbase-venue*`
runtime crate.

## Verification

```bash
python3 scripts/check-venue-ticketing.py            # repository gate
python3 scripts/check-venue-ticketing.py --test     # + closed suite and both certifications
python3 scripts/package-venue-ticketing.py          # refuses to package unless the gate passes
```

On this development machine the closed suite reports 20 tests passing and two
ignored vendor-sandbox tests (they need customer credentials). The three done
criteria map to named tests:

- revoked ticket refused offline after sync —
  `revoked_ticket_is_rejected_offline_after_sync` in each connector;
- a replayed scan does not admit twice — `a_replayed_scan_does_not_admit_twice`
  in each connector;
- the connector passes the open conformance suite —
  `ticketmaster_passes_the_open_conformance_suite` and
  `eventim_passes_the_open_conformance_suite`.

## Limits

- No Ticketmaster or Eventim affiliation, endorsement or vendor certification.
  API approval, sandbox access and rate limits are the customer's agreement.
- Sandbox tests require customer credentials; they are not a substitute for the
  vendor's certification programme.
- The connector keeps the gate's answer correct offline; the gate kernel remains
  the admission authority.
- The closed tree is not built by the open CI job, which only runs the repository
  gate while the tree is absent.
