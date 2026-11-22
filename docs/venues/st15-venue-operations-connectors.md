# ST-15 — Access, BMS, CCTV and PA connectors

**Status:** complete in the closed product tree (release packaging gated).
**Licence:** commercial / proprietary. **Repo:** closed. **Depends on:** ST-10
connector framework, ST-00 integrator and safety-case gate.

ST-15 is delivered as **seven separately sold connectors**. Neither the source nor
the product documentation is part of this repository: they live in the git-ignored
`closed/venue-operations/` tree and ship from the private repository of the
selling entity under [`LICENSING.md`](../../LICENSING.md).

| Product | Domain | Crate |
|---|---|---|
| HID access | access | `connector-hid` |
| LenelS2 access | access | `connector-lenel` |
| Genetec access | access | `connector-genetec` |
| Siemens BMS | BMS | `connector-bms-siemens` |
| Johnson Controls BMS | BMS | `connector-bms-jci` |
| ONVIF CCTV | CCTV | `connector-onvif-cctv` |
| Public address | PA | `connector-pa` |

## What the product does

| Requirement | Delivered behaviour |
|---|---|
| Access credential and event sync | Credential feed applied to a monotonic offline cache; a revoked credential is refused without the vendor; access decisions delivered signed and idempotent. |
| BMS point mapping and alarm ingestion | Explicit vendor-point to venue-point mapping (conflicts and unmapped ids refused), operational alarm families mapped, unknown families refused. |
| CCTV ONVIF ingestion and camera health | Notification envelope parsed for topic, source and data items; motion, tamper, digital-input and offline topics mapped; camera online/last-seen health cache. |
| No raw video retention | Metadata only by construction: no frame, clip, thumbnail or snapshot field, and a body with a media marker is refused before parsing. |
| PA template, zone, priority, audit | Operator-approved templates rendered with mandatory parameters, explicit zones, priority mapped to severity, and an append-only audit of each broadcast. |
| Sandbox/mock contract tests | Loopback fixture for all seven products (signed posts, dedupe, credential feed, camera health, failure injection) plus opt-in vendor sandbox tests. |
| Setup, credentials, failure recovery | Setup per vendor family, credentials and rotation, sandbox, conformance, failure-recovery and support documents, each a required gate artefact. |
| Open conformance | All seven are certified by `tirbase_venue_connectors::certify`. |

## Done criteria

1. **No connector directly controls fire/life-safety systems.** Life-safety
   markers are refused as point kind, point id, alarm family and point write; the
   framework has no fire alarm family. Tests:
   `life_safety_points_and_alarms_are_refused` (Siemens and Johnson Controls).
2. **Replays do not duplicate announcements or scans.** Idempotent delivery plus
   the PA audit refusal. Tests: `replays_do_not_duplicate_*` in every product and
   `replayed_announcement` behaviour in the PA suite.
3. **Each connector passes the open conformance suite.** Tests:
   `hid_…`, `lenel_…`, `genetec_…`, `siemens_…`, `jci_…`, `onvif_…` and `pa_…`
   `_passes_the_open_conformance_suite`.

## Licence boundary

```text
closed access / BMS / CCTV / PA connector (proprietary, sold per product)
        │
        ├── tirbase-venue-connectors   Apache-2.0  (open conformance suite)
        │        └── tirbase-integrations Apache-2.0
        │
        └── (no edge to) tirbase-venue*, tirbase-gateway, tirbase-core, …
                              AGPL-3.0-only venue/runtime crates
```

## Verification

```bash
python3 scripts/check-venue-operations.py            # repository gate
python3 scripts/check-venue-operations.py --test     # + closed suite, seven certifications
python3 scripts/package-venue-operations.py          # refuses to package unless the gate passes
```

On this development machine the closed suite reports 26 tests passing, one ignored
vendor-sandbox test per vendor family (they need customer credentials), and a
clean clippy run.

## Limits

- No vendor or ONVIF affiliation, endorsement or certification. API approval,
  sandbox access and rate limits are the customer's agreements.
- Vendor sandbox tests require customer credentials and are not a substitute for
  a vendor's own programme.
- No safety-case or regulatory claim; these connectors are deliberately outside
  the life-safety chain and the venue's safety case remains with the installed
  systems and the signed ST-00 record.
- The closed tree is not built by the open CI job, which only runs the repository
  gate while the tree is absent.
