# SOP-04 — Alarm response and escalation

**Owner:** Operations. **Reference:** `docs/alerting.md`, `licensing/24x7-SLA-TEMPLATE.md`.

## 1. Alarm classes

| Class | Example | Initial response |
| --- | --- | --- |
| Critical | Temperature above critical limit, sensor fault during storage, gateway offline | Acknowledge within the SLA target; start SOP-02 |
| High | Approaching limit, repeated transient faults, calibration due soon | Acknowledge same shift; investigate |
| Medium | Single missed poll, link flap, low battery | Acknowledge next shift; trend |
| Informational | Mode change, configuration change, export completed | Review in daily report |

## 2. Response steps

1. Acknowledge the alert in the runtime. Acknowledgement is recorded with the operator
   identity and time, and stops escalation.
2. Confirm the reading with a second source where possible (independent probe, adjacent
   location, manual thermometer). Record both values.
3. If the limit is genuinely crossed, open the excursion workflow (SOP-02).
4. If the alert is a false positive, record why and raise a maintenance/configuration
   action; do not disable the rule without change control.

## 3. Escalation

1. Unacknowledged critical alerts escalate to the next on-call level after the configured
   deadline. If no route resolves, the runtime records the alert as unrouted — that is an
   operational failure and must be treated as critical.
2. The 24/7 matrix (site, role, contact, target) is maintained in the support agreement.
3. Two consecutive delivery failures across channels must be reported to the support
   owner and recorded in the incident log.

## 4. Records

| Record | Where | Retention |
| --- | --- | --- |
| Alert raised, delivered, acknowledged, escalated | Alert delivery audit | Per retention guidance |
| Operator verification readings | Quality file / shift log | Per retention guidance |
| Incident log and actions | Operations system | Per quality-system policy |
