# Insurance evidence — incident history

## Current history

**No production incidents are recorded.** The system has been exercised on the
software HIL bench and in drills, not at a live public event. This file must not
be read as a clean operating record; it is a template plus the pilot truth.

| Period | Events operated | Incidents | Near misses | Status |
|---|---|---|---|---|
| Pilot, pre-operation | 0 public events | 0 | 0 | No operating history |

## What must be recorded

Every incident and near miss, whether or not it caused loss:

| Field | Content |
|---|---|
| Incident id | Venue convention |
| Date and time (local and UTC) | With the clock source used |
| Event and phase | Ingress, event, egress, egress emergency |
| Gates and lanes affected | Ids and firmware |
| Description | What happened and what was observed |
| Immediate action | Including any manual gate operation |
| Harm | Injury, crowd, property, data, none |
| Root cause | Confirmed or provisional |
| Contributing controls | Which SR failed or held |
| Corrective action | Owner and due date |
| Reported to | Authority, insurer, DPO, vendor |
| Evidence | Logs, audit extract, HIL replay reference |

## Reporting obligations

The venue's counsel and the authority decide what is notifiable and within what
time. `authority/incident-report-template.md` is the intake form; it is not legal
advice.

## Why this matters to an underwriter

- A disclosed near miss with a closed corrective action is better evidence than an
  empty history.
- Every incident must be traceable to an audit record, a gate log and a
  reconciliation report (`insurance/auditability.md`).
- Repeated incidents against the same control trigger re-review of the hazard and
  the safety case.
