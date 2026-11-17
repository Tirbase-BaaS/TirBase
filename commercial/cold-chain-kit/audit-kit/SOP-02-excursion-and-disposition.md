# SOP-02 — Excursion handling, quarantine and disposition

**Owner:** Site Quality. **Trigger:** any reading outside the critical limit, any sensor
fault, or any monitoring gap longer than the site's tolerated outage.

## 1. Detect and record

1. The excursion workflow opens a record with the detection evidence: readings, sensor
   ids, start time and the limit that was crossed. Do not edit or delete readings.
2. Attach the affected lot ids. Lot traceability links the lot to parent/child lots and
   to the ledger entries that recorded each step.
3. Quarantine the affected lot in the runtime. Quarantined lots cannot be released;
   an attempted release is refused and recorded.

## 2. Assess

1. Determine duration, peak and product temperature history from the report export.
2. Compare with the product stability assessment (GDP-02). Record who assessed it and
   the basis.
3. Choose a disposition: release, hold, rework, reject or destroy. For any disposition
   other than release, record the reason and the authorising role.

## 3. Release gate

A release requires: calibration valid for every sensor that contributed evidence, no
open excursion, no unresolved calibration block, and a quality sign-off (electronic
signature with reason where the deployment enables e-signatures). Anything missing is a
documented refusal, not an override.

## 4. Corrective and preventive action

1. Record the root cause and the action in the CAPA register.
2. If the cause is a sensor or controller, raise the maintenance record and re-verify
   with a reference instrument after repair.
3. If the cause is procedural, update this SOP and retrain; record both.

## 5. Records

| Record | Where | Retention |
| --- | --- | --- |
| Excursion record (detection, disposition, resolution) | Runtime + report export | Per retention guidance |
| Product assessment and authorisation | Quality file, linked to the excursion id | Product shelf life + retention minimum |
| CAPA record | Quality system | Per quality-system policy |
| Refused release attempts | Security/audit log export | Per retention guidance |

## 6. Review

Review all excursions monthly for trend and repeat causes. Escalate any repeat cause to
the management review. Keep the review minutes.
