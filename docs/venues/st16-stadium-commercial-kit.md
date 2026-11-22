# ST-16 — Stadium commercial kit

**Status:** draft — independent safety review and counsel review are outstanding.
**Licence:** commercial / proprietary. **Repo:** closed. **Depends on:** ST-12
gate HIL, ST-13 privacy, ST-14 ticketing connectors, ST-15 venue operations.

ST-16 packages the stadium deliverables as a documents-only kit in
[`commercial/stadium-kit/`](../../commercial/stadium-kit/README.md). It contains
no source, no credential and no customer data, and is usable by an accredited
integrator without repository access. The release gate is closed: both external
reviews are pending and no archive may be released.

## What the kit contains

| Part | Documents |
|---|---|
| Safety case | 20-hazard log, 5×5 risk assessment with tolerability bands, 18 safety requirements, evidence index, gate failure-mode matrix, independent review plan, structured pilot safety-case report |
| Insurance evidence | System description and boundary, 17 controls with verification and evidence, incident history (pilot: no production incidents), append-only auditability, evidence index |
| Local-authority reporting | Capacity, incident and lockdown report templates with completion fields and signature blocks |
| Integrator certification | 10-module training with practical assessments, exam blueprint at an 80% pass mark, badge levels and registry, 24-month recertification, 30-check commissioning checklist |
| Managed venue operations | Monitoring signals and thresholds, on-call tiers and paging, incident command and severities, change management, SLA targets and exclusions |
| Hardware bundle | Controller certification programme and register, reader requirements, spares minimums, firmware support windows, EOL policy, BOM template |

## Done criteria

1. **Every hazard has an owner and mitigation evidence.** Each of H-01..H-20 names
   an owning role, a mitigation, an `SR-xx` reference and an `evidence_ref` that
   resolves to a delivered document or an open evidence path. The gate recomputes
   every risk score and rejects a hazard without any of these.
2. **Independent safety review and counsel have signed off.** **Not met.** No
   reviewer or counsel has been appointed; `review/safety-review-record.md` and
   `review/counsel-review-record.md` are unsigned, the manifest records both as
   `pending`, and `--release` fails. The kit must not be presented as an approved
   safety case or as counsel-approved.
3. **Usable without source access.** Every check is a black-box behaviour, a
   signed document or a delivered report; the commissioning checklist and evidence
   index reference open documentation and published evidence packs only.

## Verification

```bash
python3 scripts/check-stadium-kit.py            # draft gate
python3 scripts/check-stadium-kit.py --release  # fails while a review is pending
python3 scripts/package-stadium-kit.py          # watermarked draft archive
python3 scripts/package-stadium-kit.py --release  # refuses without both approvals
```

The gate checks required files, purity (no code, binary, media, executable bit,
symlink, private key, API key or customer email), hazard completeness and
arithmetic, evidence resolution, requirement coverage, review honesty
(`approved` requires reviewer, organisation, date, no open findings and a signed
record), and the presence of the integrator, operations, hardware, insurance and
authority markers.

## Limits

- **No certification.** The kit is not a safety certification, an insurance
  policy, a fire or life-safety assessment, or legal advice.
- **No approved safety case.** The hazard log and safety-case report are the
  vendor's draft argument; an independent reviewer must still accept, condition or
  reject them.
- **No certified hardware.** `hardware/certified-controllers.md` certifies no
  model; each model needs a witnessed attestation before a lane may be
  commissioned.
- **No operating history.** Incident history records zero public events, which is
  an absence of evidence, not a clean record.
- **No measured site data.** Capacity and timing figures are verified at
  commissioning and are not claimed here.
