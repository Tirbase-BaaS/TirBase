# SOP-03 — Calibration and verification of monitoring instruments

**Owner:** Engineering. **Reference:** `calibration/procedure.md` and
`calibration/uncertainty-budget.csv` in this kit.

## 1. Scope

Every sensor and controller that contributes evidence to a release decision, plus the
reference instruments used to verify them.

## 2. Register the instrument

1. Register the asset in the asset registry: kind, model, serial, site, location,
   firmware, install time, calibration interval.
2. Record the calibration policy on the asset. The interval must not exceed the
   manufacturer's recommendation or the site's validated interval, whichever is shorter.

## 3. Calibrate

1. Use a reference instrument whose certificate is valid and whose uncertainty is small
   enough that the combined uncertainty in the kit's budget stays below the acceptance
   limit.
2. Perform the points stated in the procedure, at the site's operating range, with
   enough dwell time for thermal equilibrium.
3. Record reference value, indicated value, error and the certificate reference. Store
   the certificate hash and due date in the registry; never store the certificate bytes
   in the runtime.

## 4. Verify between calibrations

1. At the interval in the procedure, perform a reference check at one operating point.
2. Compare with the baseline check at the same point. A drift beyond the acceptance
   criterion is a calibration failure: block the lot, recalibrate, re-verify.
3. Record the drift result and who performed it.

## 5. Expiry and blocking

An expired calibration blocks release of lots observed by that instrument. Resolve by
recalibrating and verifying; resolving the block requires an actor and reason and is
recorded. Do not extend an interval without a documented risk assessment.

## 6. Records

| Record | Where | Retention |
| --- | --- | --- |
| Asset and calibration record (certificate hash, due date) | Asset registry | Asset life + retention period |
| Calibration certificate | Quality file (by reference id/hash) | Per accreditation requirement |
| Reference-check results and drift | Runtime report/export | Per retention guidance |
| Block and resolution records | Runtime + audit export | Per retention guidance |
