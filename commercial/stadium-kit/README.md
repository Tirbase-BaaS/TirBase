# Stadium commercial kit — proprietary

**Licence:** Proprietary; see `LICENSE`. Documents and templates only.
**Status of this copy:** **DRAFT — independent safety review and counsel review are
PENDING and unsigned.** Do not represent this kit as reviewed, certified,
approved or insurable. `python3 scripts/check-stadium-kit.py --release` fails
until both reviews are recorded as approved.

The kit is written to be used by an accredited integrator **without source
access**: every step references a behaviour, document or test identifier the
integrator can verify from the outside, and every template is complete enough to
fill in and sign.

## Contents

| Part | Deliverable |
|---|---|
| `safety/` | Hazard log, risk assessment, safety requirements, evidence index, gate failure modes, independent review plan, safety-case report |
| `insurance/` | System description, controls, incident history, auditability, evidence index |
| `authority/` | Capacity, incident and lockdown reporting templates |
| `integrator/` | Training, exam, badge registry, recertification, commissioning checklist |
| `managed-ops/` | Monitoring, on-call, incident command, change management, SLA |
| `hardware/` | Certified gate controllers, readers, spares, firmware support, EOL policy, BOM template |
| `review/` | Safety and counsel review records (unsigned) and the kit review log |
| `manifest.json` | Version, parts, review state, delivery claims |
| `EXCLUSIONS.md` | What this kit does not do |

## How an integrator uses it without source access

1. **Qualify** — read `integrator/training.md`, pass `integrator/exam.md`, receive
   a badge under `integrator/badge.md`.
2. **Design** — map the venue with `integrator/commissioning-checklist.md` and
   `safety/safety-requirements.md`; resolve every hazard owner in
   `safety/hazard-log.csv`.
3. **Commission** — follow the checklist gate by gate, recording the observed
   state and the evidence reference. No source is needed: each check is a
   black-box behaviour, a signed document or a test reference.
4. **Operate** — use `managed-ops/` for monitoring, on-call, incident command,
   change control and SLA.
5. **Report** — use `authority/` templates for capacity, incident and lockdown
   notifications, and `insurance/` for underwriting evidence.

## Reproduce the gate

```bash
python3 scripts/check-stadium-kit.py            # draft completeness
python3 scripts/check-stadium-kit.py --release  # + both reviews approved
python3 scripts/package-stadium-kit.py          # refuses a release without approvals
```

## Honest limits

- **Nothing here is certified or approved by anyone yet.** The review records are
  blank by design; this kit does not sign for an independent reviewer, counsel,
  an insurer or an authority.
- Hazard owners are named **roles**, not individuals. The venue must fill in the
  named person and date before relying on the log.
- Risk scores are a starting assessment for a pilot class venue. They are not a
  substitute for a competent person's assessment of the actual site.
- The kit contains no source code, credential or customer data.
