# Commissioning checklist

Complete per venue and per lane. Every box needs an observed result and an
evidence reference — not a verbal assurance. No source access is required; every
check is a black-box behaviour, a signed document or a delivered report.

Venue: __________  Event scope: __________  Date: __________
Integrator: __________  Commissioning engineer badge: __________

## A. Prerequisites

- [ ] Signed integrator agreement and active badge verified (A-01).
- [ ] Venue safety owner named and present at handover (A-02).
- [ ] Site risk assessment and occupancy limits received (A-03).
- [ ] Mechanical egress release inspected and tested by the venue (A-04).
- [ ] Network, power and cabinet works signed off by others (A-05).
- [ ] Supported firmware on every device; asset register completed (A-06).

## B. Gate mechanics and safe state

- [ ] Power removed: lane reaches the configured safe state (B-01, SR-01).
- [ ] Power restored: lane restarts to a defined state and re-syncs (B-02, SR-01).
- [ ] Controller stalled or restarted: no partial admit (B-03, SR-01).
- [ ] Brownout simulated: no undefined state (B-04, SR-01).
- [ ] Egress release operated: gate releases independently of TirBase (B-05, SR-07).
- [ ] Adjacent lane absorbs flow when this lane is closed (B-06).

## C. Decision and offline operation

- [ ] Valid ticket admits; invalid ticket refuses with a visible reason (C-01).
- [ ] Same scan presented twice: one admit, replay reported (C-02, SR-04).
- [ ] Network removed: lane continues from the signed local policy (C-03, SR-02).
- [ ] Offline decision matches the connected decision for the same inputs (C-04).
- [ ] Policy age exceeded: lane refuses authoritative operation (C-05).
- [ ] Clock jump during a decision: outcome unchanged (C-06, SR-09).

## D. Revocation and credential sync

- [ ] Feed synced before gates open; watermark and time recorded (D-01, SR-03).
- [ ] Revoked credential refused offline with the vendor unreachable (D-02, SR-03).
- [ ] Credential valid before the revocation still admits in the replay window (D-03).
- [ ] Stale cache blocks the ready declaration (D-04).
- [ ] Reconciliation report clean after reconnect (D-05).

## E. Capacity and lockdown

- [ ] Capacity envelope configured for every area in scope (E-01, SR-05).
- [ ] Load test to the envelope: refusal visible to the operator (E-02).
- [ ] Authorised lockdown applies and is audited (E-03, SR-06).
- [ ] Unauthorised lockdown rejected and logged (E-04).
- [ ] Lockdown drill completed with the venue's security officer (E-05).

## F. Connectors

- [ ] Ticketing seat/event mapping resolves; unmapped id refused (F-01, SR-16).
- [ ] Access mapping resolves; conflicting mapping refused at load (F-02).
- [ ] BMS: operational alarm ingested; life-safety point and alarm refused (F-03, SR-08).
- [ ] CCTV: ONVIF motion event maps to a zone; media payload refused (F-04, SR-11).
- [ ] Camera health reports expected cameras and offline/stale ones (F-05).
- [ ] PA: template renders; announcement audited; replay not broadcast twice (F-06, SR-13).

## G. Observability and audit

- [ ] Gate, sync, connector and camera-health alarms reach the operator (G-01, SR-17).
- [ ] Audit extract produced for the commissioning day (G-02).
- [ ] Reconciliation and scan ledger exported (G-03).
- [ ] Privileged actions are logged; credentials are unique and rotated (G-04, SR-18).

## H. People and handover

- [ ] Venue staff trained on offline fallback and manual operation (H-01, SR-15).
- [ ] On-call rota and escalation contacts exchanged (H-02).
- [ ] Spares delivered and counted against `hardware/spares.md` (H-03, SR-14).
- [ ] Change and rollback procedure briefed (H-04).
- [ ] Badge registry checked; commissioning engineer's badge active (H-05).

## I. Exclusions confirmed

- [ ] Venue confirms TirBase does not control fire, suppression, smoke, gas,
      emergency lighting or egress hardware (I-01, SR-08).
- [ ] Venue confirms life-safety maintenance is held outside this system (I-02).

## Sign-off

| Role | Name | Signature | Date |
|---|---|---|---|
| Commissioning engineer |  |  |  |
| Integrator safety lead |  |  |  |
| Venue safety owner |  |  |  |

Any unchecked box blocks the ready declaration. Record deviations with an owner
and a due date; a safety-critical deviation blocks operation.
