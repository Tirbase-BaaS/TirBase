# Integrator training

Certification is for an **organisation** and its named engineers. Training is
delivered by the vendor or an approved trainer; the exam and badge are recorded in
`badge-registry.csv`.

## Prerequisites

- Employed by an integrator with a signed agreement.
- Electrical/network competence appropriate to the work, or supervised access.
- Read `safety/hazard-log.csv`, `safety/risk-assessment.md` and `EXCLUSIONS.md`
  before the first module.

## Modules

| # | Module | Hours | Outcome |
|---|---|---|---|
| 1 | System and boundary | 3 | Explain what TirBase does, what it never controls, and where the life-safety system owns egress |
| 2 | Gate mechanics and safe state | 4 | Inspect egress release, verify fail-secure behaviour and restart states |
| 3 | Offline decision model | 4 | Sync policy and revocation, prove offline decisions, run an offline drill |
| 4 | Access, BMS, CCTV, PA connectors | 6 | Map points and zones, refuse life-safety points, keep CCTV metadata-only, render PA templates |
| 5 | Ticketing and credential integration | 4 | Feed sync, seat mapping, replay and reconciliation |
| 6 | Capacity, lockdown and incident command | 4 | Configure envelopes, run a lockdown drill, run an incident workflow |
| 7 | Privacy and data protection | 3 | DPIA inputs, retention, SAR handling and legal hold |
| 8 | Monitoring, on-call and change management | 3 | Thresholds, rota, change approval and rollback |
| 9 | Commissioning and handover | 6 | Complete the commissioning checklist and train the venue's staff |
| 10 | Assessment | 4 | Written exam and practical commissioning assessment |

Total: 41 hours, typically five days.

## Practical requirements

Each engineer must, under observation:

1. Prove a gate reaches its safe state on power loss and restarts to a defined
   state.
2. Run an offline decision drill with the network removed.
3. Commission one lane end to end with a signed checklist.
4. Demonstrate that a life-safety BMS point is refused.
5. Render and audit a PA announcement and show a replay is not broadcast twice.
6. Show a revoked credential refused offline.

## Records

- Attendance and module completion.
- Practical sign-off by the trainer with date.
- Exam result and badge id.
- Any failed practical and the re-assessment date.

`integrator/exam.md` sets the pass mark; `integrator/recertification.md` sets the
renewal cycle.
