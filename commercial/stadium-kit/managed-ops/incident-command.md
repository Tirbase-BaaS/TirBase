# Managed venue operations — incident command

## Roles

| Role | Responsibility |
|---|---|
| Incident commander | Owns the incident, decisions and communications; does not operate the console |
| Operations lead | Runs the console, gates and fallback |
| Safety officer | Gate-state, crowd and life-safety liaison; can stop the operation |
| Communications lead | Staff, crowd and authority messaging |
| Scribe | Timeline and decisions; preserves evidence |
| Vendor liaison | Connector and platform escalation |

One person may hold two roles only in an S4 and never commander plus operations
during a live event.

## Severity

| Severity | Definition | Command |
|---|---|---|
| S1 | Injury, crowd danger, gate failure that admits without policy, suspected life-safety interference, or whole-venue outage | Full command; safety officer engaged; authority per counsel |
| S2 | Multiple lanes down, sync or connector failure during ingress, lockdown issue without harm | Commander plus operations; vendor engaged |
| S3 | Single lane degraded, mapping or reconciliation drift, camera-health loss | Operations lead; ticket |
| S4 | Question, cosmetic, single camera | Normal queue |

## Flow

1. **Detect** — alert, operator report or vendor notice.
2. **Declare** — severity, commander, incident id, bridge.
3. **Stabilise** — fallback first: offline cache, manual lane, hold the queue.
   Never improvise a life-safety action; that belongs to the venue's procedure.
4. **Diagnose** — evidence before restart; check sync age, gate state, connector
   classification, recent changes.
5. **Resolve** — restore, reconcile scans and revocations, verify with a test
   credential and a replay.
6. **Close** — after-action report within five working days, findings with owners.

## Authority

The safety officer can stop ingress or close a zone without the commander's
agreement. The commander cannot override the life-safety system or the venue's
evacuation procedure.

## Evidence

Timeline, decisions, audit extracts, gate logs, reconciliation report, PA audit
entries, and the incident report. CCTV metadata access is recorded; no video is
pulled by this kit.

## Drills

At least one tabletop and one live gate drill before each season, covering offline
operation, lockdown and a connector outage.
