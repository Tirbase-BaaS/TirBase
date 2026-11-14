# Partner Training and Certification Checklist (F-15)

> Commercial partner kit materials may extend this baseline; this file is the open-repo minimum.

## Training modules (recommended)

| Module | Audience | Topics | Evidence of completion |
|--------|----------|--------|------------------------|
| T1 — Architecture & threat model | Integrators, pre-sales engineers | Boundaries B1–B8, failure modes, non-goals (no SIL) | Quiz or attestation |
| T2 — Installation & hardening | Integrators | Packaging, config, mTLS, keys, profiles | Lab install checklist signed |
| T3 — Operations & runbooks | Operators, support | Lockdown, tamper, restore, OTA/rollout, SLO alarms | Walkthrough + ticket simulation |
| T4 — Security & privacy | All technical partners | SECURITY.md, vulnerability handling, DPIA/data protection procedures, incident comms | Attestation |
| T5 — Vertical enablement | Vertical specialists | Cold chain / POS / stadium flows, simulators, HIL checklist | Vertical lab exercise |

## Certification checklist (partner readiness)

### Technical
- [ ] Completed T1–T5 (or role-appropriate subset) with recorded attendance/attestation.
- [ ] Performed at least one staging deployment end-to-end (install → profile → command → export).
- [ ] Demonstrated restore from backup in a test environment.
- [ ] Completed privacy review training: can complete `docs/compliance/dpia-templates.md` with DPO/legal support.

### Process
- [ ] Knows how to report vulnerabilities (SECURITY.md) and must not disclose publicly.
- [ ] Has access to internal escalation path and uses `docs/incident-communication-templates.md`.
- [ ] Agrees to keep partner credentials and customer data handling per contract.

### Deliverables partners should produce per customer
- [ ] Completed DPIA/pilot privacy record (linked before pilot).
- [ ] Deployment inventory (hardware profile, versions, network zones).
- [ ] Handover doc: contacts, backup schedule, monitoring endpoints.

## Renewal

- Annual refresher on security advisories and major version changes; re-certify after significant product security architecture changes.
