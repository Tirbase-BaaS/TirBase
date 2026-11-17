# Counsel review record

**Record id:** REV-COUNSEL-001
**Status:** PENDING
**Reviewer:** _(name, firm, jurisdiction, bar/qualification)_
**Review date:** _(UTC)_
**Kit version reviewed:** 0.1.0-draft
**Signature reference:** _(signed PDF hash or DocuSign envelope id)_

## Scope of review requested

Counsel is asked to review, for the named jurisdictions, and to approve or amend:

- [ ] `README.md` status wording and delivery restrictions.
- [ ] `LICENSE` proprietary terms and the AGPL/commercial boundary statement.
- [ ] `EXCLUSIONS.md` and every "not covered" statement.
- [ ] `audit-kit/retention-guidance.md` retention defaults and legal-hold wording.
- [ ] `audit-kit/SOP-*.md` for statements that could read as regulatory guarantees.
- [ ] `iec62443/SL2-SL3-dossier.md` and `requirements.csv` claim wording.
- [ ] `cra/technical-file.md` and `cra/risks.csv` conformity wording.
- [ ] `licensing/OEM-LICENCE-TEMPLATE.md` and `licensing/24x7-SLA-TEMPLATE.md`.
- [ ] `sensors/certified-sensor-list.csv` use of "certified" and certificate references.
- [ ] Any customer-facing representation of compliance or certification.

## Findings

| ID | Location | Finding | Required change | Disposition |
| --- | --- | --- | --- | --- |
| | | | | |

## Decision

- [ ] Approved for delivery as a draft kit with "no certification claim" wording.
- [ ] Approved for release delivery, subject to the changes above being applied.
- [ ] Not approved. Reasons: _( )_

**Counsel name / signature:** _( )_ **Date:** _( )_

> An approval recorded here is also reflected in `manifest.json.reviews.counsel`. The
> packaging gate reads the manifest and refuses `--release` unless that record is
> `approved` with a reviewer and date.
