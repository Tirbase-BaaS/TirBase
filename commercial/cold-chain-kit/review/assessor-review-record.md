# Accredited assessor review record

**Record id:** REV-ASSESSOR-001
**Status:** PENDING
**Assessment body:** _(accredited body, accreditation number, scope)_
**Lead assessor:** _(name, qualification)_
**Assessment dates:** _( )_
**Kit and baseline reviewed:** 0.1.0-draft / _(release tag, commit digest)_
**Report reference:** _(report id and hash)_

## Evidence provided to the assessor

- `iec62443/SL2-SL3-dossier.md`, `zones.csv` and `conduits.csv`, `requirements.csv`
- `cra/technical-file.md`, `risks.csv`
- `audit-kit/control-to-evidence.csv`, `gaps.csv`
- `calibration/` (procedure, budget, acceptance)
- `docs/evidence/hil/cc22-sensor-controller-validation/` and repository evidence index
- Installed deployment topology, configuration and key-custody procedure

## Assessment result

| Area | Target | Assessor finding | Evidence sampled | Result |
| --- | --- | --- | --- | --- |
| Zones and conduits | SL2/SL3 | | | |
| FR1 identification and authentication | SL2/SL3 | | | |
| FR2 use control | SL2/SL3 | | | |
| FR3 system integrity | SL2/SL3 | | | |
| FR4 data confidentiality | SL2/SL3 | | | |
| FR5 restricted data flow | SL2/SL3 | | | |
| FR6 timely response | SL2/SL3 | | | |
| FR7 resource availability | SL2/SL3 | | | |
| 4-1 lifecycle | SL2/SL3 | | | |
| CRA technical file completeness | CRA | | | |

## Findings and residual risk

| ID | Finding | Severity | Required action | Owner | Due |
| --- | --- | --- | --- | --- | --- |
| | | | | | |

## Decision

- [ ] Assessment complete; the cited claims are supported as scoped.
- [ ] Assessment complete with findings; findings must be closed before representation.
- [ ] Not supported. Reasons: _( )_

**Assessor name / signature:** _( )_ **Date:** _( )_

> Approval is also reflected in `manifest.json.reviews.assessor`. The packaging gate
> refuses `--release` without an approved assessor record. This record is not itself a
> certificate and does not authorise a certification mark.
