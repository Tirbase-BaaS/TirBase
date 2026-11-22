# Independent safety review plan

## Purpose

Obtain an independent opinion on whether the pilot safety case is coherent, its
hazards have credible owners and mitigations, and its residual risks are
tolerable for the defined pilot scope.

## Independence

The reviewer must:

- have no employment, shareholding or paid engagement with the vendor or the
  integrator beyond this review;
- not have authored the hazard log, safety requirements or safety-case report;
- be competent in crowd safety or access-control safety engineering, with
  references;
- declare any prior involvement with the venue.

The review is commissioned by the venue, not by the vendor. The vendor supplies
documents and answers questions; it does not select the reviewer.

## Inputs

The reviewer receives:

1. `safety/hazard-log.csv`, `safety/risk-assessment.md`,
   `safety/safety-requirements.md`, `safety/safety-case-report.md`,
   `safety/gate-failure-modes.md`, `safety/evidence-index.md`.
2. `integrator/commissioning-checklist.md` and the completed pilot checklist.
3. The ST-12 HIL evidence pack and the claim registry, by reference.
4. The venue's own site risk assessment, occupancy limits and evacuation plan.
5. `EXCLUSIONS.md`.

No source access is required or offered. The reviewer may observe a gate drill.

## Review questions

1. Is every credible hazard for the pilot scope identified, including
   organisational and human factors?
2. Does every hazard have a competent owner and a mitigation whose evidence
   actually exists and supports the claim?
3. Are the residual ratings defensible, and is ALARP argued where 5–9 remains?
4. Is the boundary between TirBase and the life-safety systems stated correctly
   everywhere, with no implied control?
5. Do the failure modes and commissioning checks detect the mitigations failing?
6. Are the assumptions explicit, and would a failed assumption invalidate the
   case?
7. Is the pilot scope bounded enough for the evidence available?

## Output

A written report with:

- scope, date, reviewer and independence declaration;
- a finding per question, graded **critical / major / minor / observation**;
- for each finding, the affected hazard or requirement and the required action;
- an overall opinion: **acceptable for the defined pilot scope**, **acceptable
  with conditions**, or **not acceptable**;
- a statement of what was not reviewed.

The record is filed in `review/safety-review-record.md`. Critical and major
findings must be closed and re-reviewed before operation. Minor findings may be
accepted with a named owner and date.

## Re-review triggers

- Any critical or major finding.
- A new hazard, a changed risk rating, or a change of integrator.
- A serious incident or near miss.
- A material change to gate hardware, firmware baseline or offline model.
- Annually, and before each season.

## Current state

**Not yet reviewed.** `review/safety-review-record.md` has no reviewer, date or
signature, and the manifest records `pending`. Until it is signed, this kit is a
draft and must not be used to assert an independent safety opinion.
