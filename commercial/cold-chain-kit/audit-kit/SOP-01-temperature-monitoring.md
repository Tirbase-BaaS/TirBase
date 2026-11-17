# SOP-01 — Temperature monitoring and critical limits

**Applies to:** cold rooms, reefer units, transport boxes and any storage location whose
product has a temperature critical limit.
**Owner:** Site Quality. **Review:** annually, after any excursion trend, or after a
change to sensors, layout or setpoints.

## 1. Purpose

Define how temperature is measured, how critical limits are set and verified, and what
record proves it. The runtime provides the measurement, admission and record path; this
SOP defines the site's use of it.

## 2. Critical limits

1. Record the product-specific limit from the stability data (GDP-02). Where the product
   has no specific limit, use the site default and record the justification.
2. Configure the limit as the site's policy profile value. The gateway enforces the
   configured value; changing it requires the change-control checklist.
3. Set the alarm threshold below the critical limit by the site's response margin, and
   record both numbers in the site configuration register.

## 3. Monitoring points

1. Every storage location has at least one mapped sensor; map the sensor asset id to the
   location in the asset registry.
2. Record the transport (DS18B20, 4–20 mA, BLE, BACnet, Modbus RTU/TCP), the reference
   instrument used to verify it, and the calibration due date.
3. Sensors with an expired or missing calibration are blocked from release decisions;
   the block is visible as an excursion record, not a silent gap.

## 4. Frequency and health

1. Polling interval is a site decision; record it. The default driver interval is the
   documented value for that transport.
2. A sensor fault (open loop, bad CRC, link loss, timeout) is an alarm, not a missing
   data point. The operator must respond under SOP-04.
3. Record daily that the monitoring chain is live (read success, chain head advancing).

## 5. Records

| Record | Where | Retention |
| --- | --- | --- |
| Sensor map and calibration state | Asset registry + this SOP's register | Life of asset + retention period |
| Temperature readings | Runtime ledger and report exports | Per retention guidance |
| Alarm acknowledgements | Alert delivery audit | Per retention guidance |
| Configuration changes | Change-control record | Per retention guidance |

## 6. Verification

Sample one location per week: compare the runtime reading with an independent reference
reading, record both, and raise a deviation if the difference exceeds the acceptance
criterion in the calibration kit. Keep the reference instrument certificate on file.
