# Risk assessment

**Status:** draft. Prepared for a pilot-class stadium installation; not a
site-specific assessment. A competent person at the venue must review and adopt
it before gates operate.

## Method

5 × 5 scoring. Severity and likelihood are judged for the **unmitigated** hazard;
the residual score is judged after the listed mitigation is verified at
commissioning.

| Severity | Meaning |
|---|---|
| 5 | Fatality or multiple serious injuries |
| 4 | Serious injury or major operational loss |
| 3 | Minor injury or significant disruption |
| 2 | First aid or local disruption |
| 1 | Negligible |

| Likelihood | Meaning |
|---|---|
| 5 | Expected during the event |
| 4 | Likely during the season |
| 3 | Possible during the season |
| 2 | Unlikely |
| 1 | Remote |

`risk_score = severity × likelihood`.

## Tolerability

| Residual score | Rule |
|---|---|
| 1–4 | Tolerable with monitoring; owner named; evidence filed |
| 5–9 | Tolerable only if ALARP; independent safety review must see the argument |
| 10–16 | Not tolerable for operation without a signed deviation and additional controls |
| 17–25 | Unacceptable; the function must not operate |

No unmitigated score of 17–25 exists in the log. The two severity-5 hazards
(H-08 egress, H-09 life-safety integration) are mitigated to residual 2 by
keeping both functions outside TirBase's control and by refusing life-safety
points and alarms.

## Top risks and their argument

| Hazard | Unmitigated | Residual | Argument |
|---|---|---|---|
| H-01 gate latched in a surge | 12 | 4 | Fail-secure is the configured safe state; egress release is mechanical; drill-verified |
| H-03 power loss | 12 | 4 | HIL campaign proves the safe state at every power stage |
| H-06 capacity breach | 12 | 4 | Envelope configured, refusal explicit, live count verified |
| H-08 blocked egress | 10 | 2 | TirBase cannot hold a gate closed for egress; the life-safety system owns release |
| H-09 life-safety interference | 10 | 2 | BMS/connector refusal of life-safety points and alarms; no fire alarm family exists |

## Assumptions

1. The venue has a competent person who owns the safety case and the site
   assessment.
2. Turnstiles have a mechanical egress release that does not depend on TirBase or
   on the gate controller's software.
3. Fire detection, suppression, smoke control, gas detection and emergency
   lighting are installed, certified and maintained by others.
4. The integrator is accredited under `integrator/` and commissions with
   `integrator/commissioning-checklist.md`.
5. Occupancy limits are set by the venue and the authority, not by this kit.

If an assumption fails, the assessment is void for that site until re-reviewed.

## Review cadence

- Before first operation (independent review, unsigned until then).
- After any hazard-log change, serious incident, near miss, major firmware or
  configuration change, or change of integrator.
- At least annually, and before each season.

## Sign-off

| Role | Name | Signature | Date |
|---|---|---|---|
| Venue safety owner |  |  |  |
| Integrator safety lead |  |  |  |
| Independent safety reviewer |  |  |  |

Unsigned rows are unresolved. See `review/safety-review-record.md`.
