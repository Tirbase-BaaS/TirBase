# Evidence index

Evidence is cited by reference. The integrator receives documents and test/claim
identifiers, never source. Open-repository paths are stable references; the closed
connector evidence is delivered with the connector product.

| Evidence | Location | Supports |
|---|---|---|
| Venue gate HIL campaign and hash-sealed pack | `docs/evidence/hil/st12-venue-gate-safety/` | SR-01, SR-03, SR-04, SR-09 |
| ST-12 gate HIL procedure | `docs/venues/st12-gate-hil.md` | SR-01 |
| Offline ticket kernel | `docs/venues/st05-offline-ticket-kernel.md` | SR-02, SR-10 |
| Gate anti-replay | `docs/venues/st07-gate-anti-replay.md` | SR-04 |
| Lockdown and override controls | `docs/venues/st08-lockdown-override.md` | SR-06 |
| Capacity envelopes | `docs/venues/st06-capacity-envelopes.md` | SR-05 |
| Access control and tenancy | `docs/venues/st03-access-control.md` | SR-16 |
| Privacy runtime and DPIA pack | `docs/venues/st13-privacy.md` | SR-11, SR-12 |
| Ticketing connector evidence | `docs/venues/st14-ticketing-connectors.md` | SR-03, SR-04 |
| Operations connector evidence | `docs/venues/st15-venue-operations-connectors.md` | SR-08, SR-13 |
| Claim registry (machine-checked) | `CLAIMS.md` | All: each claim names its test or gate |
| Independent review plan and record | `safety/independent-review-plan.md`, `review/safety-review-record.md` | Review criterion |
| Commissioning checklist | `integrator/commissioning-checklist.md` | SR-01…SR-18 site verification |
| Auditability evidence | `insurance/auditability.md` | SR-18 |

## Rules

1. A hazard row's `evidence_ref` must resolve to a delivered document or an open
   path in this index. The kit gate checks this.
2. Evidence that is a test identifier must be reproducible by the integrator from
   the licensed build or the delivered report; no source is required.
3. Evidence is versioned with the kit. Replacing a cited document requires a new
   kit version and a review-log entry.
4. A claim without evidence is not used in the safety case, the insurance pack or
   authority reporting.
