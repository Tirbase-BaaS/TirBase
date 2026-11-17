# Calibration and validation procedure — cold-chain monitoring kit

**Applies to:** DS18B20 probes, 4–20 mA transmitters, BLE climate sensors, BACnet and
Modbus controllers that contribute evidence to a release decision.
**Reference standards:** ISO/IEC Guide 98-3 (GUM) for the uncertainty budget; the site's
accreditation requirements for certificate content.

## 1. Equipment

| Item | Requirement |
| --- | --- |
| Reference thermometer | Calibrated, certificate valid, expanded uncertainty ≤ 0.05 °C (k=2) at the test points |
| Temperature source | Dry-block or liquid bath with uniformity ≤ 0.02 °C and stability ≤ 0.01 °C over the dwell |
| Reference current source | 4–20 mA, accuracy ≤ 0.02 % of span, calibrated certificate |
| Reference hygrometer | ±0.5 %RH or better for humidity verification |
| Readout | The runtime under test, with the device mapped to an asset id |
| Environment | 15–30 °C ambient, no direct sunlight, stable draught conditions |

## 2. Traceability and registration

1. Record serial number, certificate id, calibration date, due date and expanded
   uncertainty for every reference instrument. Store the certificate hash in the asset
   registry; never store the certificate bytes in the runtime.
2. Confirm the reference uncertainty is small enough: the combined budget must remain
   below the acceptance limit in `acceptance-criteria.csv`. If not, use a better reference
   rather than accepting a wider margin.
3. Register the device under test with kind, model, serial, site, firmware and interval.

## 3. Test points and dwell

| Transport | Points | Dwell |
| --- | --- | --- |
| DS18B20 | −20, 0, 5, 25, 60 °C (or the site's operating range) | 10 min after the reference stabilises |
| 4–20 mA | 4, 8, 12, 16, 20 mA | 2 min per point |
| BLE climate | 5, 25 °C and 30, 60, 85 %RH | 5 min per point |
| BACnet/Modbus | The configured operating setpoint and two offsets | 5 min per point |

Take at least three readings per point after stabilisation; use the mean and record the
spread. Record the reference value at the same instant as the reading.

## 4. As-found and as-left

1. Perform the as-found run before adjustment. If the error exceeds the acceptance limit,
   record a failed calibration and quarantine affected lots.
2. Adjust only where the manufacturer permits it; record the adjustment.
3. Perform the as-left run. Record points, errors, uncertainty and pass/fail.
4. Update the calibration record: performed time, interval, method, laboratory,
   uncertainty, points, certificate hash and due date.

## 5. Verification between calibrations

At the site's interval (default: quarterly, or after any repair or relocation):

1. Reference check at one operating point; compare with the baseline check.
2. Drift = |measured − baseline|; a drift beyond the acceptance criterion is a failure.
3. Record the check; the runtime reports drift per asset.

## 6. Acceptance

Accept only when: the as-left error is inside `acceptance-criteria.csv`; the combined
uncertainty (expanded, k=2) is below the limit; the certificate is valid; and no reference
check is overdue. Otherwise block release and treat as SOP-02.

## 7. Records

Calibration record with certificate hash and due date; raw readings; uncertainty budget
copy; operator identity; environmental conditions. Retention: life of instrument + 2 years.
