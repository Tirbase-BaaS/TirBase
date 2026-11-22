# Integrator certification exam

## Format

- 40 multiple-choice and short-answer questions, closed book, 75 minutes.
- One practical commissioning assessment of 90 minutes (see `training.md`).
- Pass mark: **80%** written (32/40) **and** a pass on every practical item.
- One resit after seven days; a second failure requires the full course again.

## Blueprint

| Topic | Questions | Source |
|---|---|---|
| System boundary and life-safety exclusion | 6 | `safety/safety-case-report.md`, `EXCLUSIONS.md` |
| Gate safe state, power and egress | 6 | `safety/gate-failure-modes.md` |
| Offline decision and revocation | 6 | `safety/safety-requirements.md` SR-02, SR-03 |
| Ticketing replay and reconciliation | 5 | `docs/venues/st14-ticketing-connectors.md` |
| Access, BMS, CCTV, PA | 7 | `docs/venues/st15-venue-operations-connectors.md` |
| Capacity and lockdown | 4 | `docs/venues/st07-gate-anti-replay.md`, `docs/venues/st08-lockdown-override.md` |
| Privacy and audit | 3 | `docs/venues/st13-privacy.md` |
| Monitoring, on-call, change | 3 | `managed-ops/` |

## Sample questions

1. The venue network fails during ingress. What must a lane do, and what must an
   operator verify before trusting it? *(SR-02, SR-10)*
2. A ticket is revoked at 18:05. A scan from 17:58 is replayed at 18:10. What is
   the correct outcome, and why? *(SR-03, SR-04)*
3. The fire panel activates. Which component releases the turnstile, and what does
   TirBase do? *(SR-07, SR-08)*
4. A BMS point named `fire-alarm-3` is proposed in the mapping. What happens and
   why? *(SR-08)*
5. What evidence proves a gate reached its safe state after a brownout? *(SR-01)*
6. A CCTV integration offers a snapshot URI. What does the connector accept?
   *(SR-11)*
7. A PA template is missing a zone parameter. What should happen? *(SR-13)*
8. Capacity reaches the approved envelope. What must be visible and to whom?
   *(SR-05)*
9. What makes a lockdown command valid, and what is recorded? *(SR-06)*
10. What must an integrator do before declaring a lane ready offline? *(SR-03)*

## Marking rules

- A safety-critical wrong answer (life-safety control, bypassing egress release,
  admitting on a replayed scan, accepting CCTV media) fails the paper regardless
  of total score.
- Practical items are pass/fail; a failed item is re-assessed after remediation.
- Results are recorded in `badge-registry.csv` with the score and date.

## Integrity

Questions are not published with answers. The trainer may vary scenarios while
keeping the same blueprint. A badge is revoked if the holder is found to have
shared exam material or signed a commissioning record they did not perform.
