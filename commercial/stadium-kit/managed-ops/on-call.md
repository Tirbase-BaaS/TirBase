# Managed venue operations — on-call

## Coverage

| Tier | Coverage | Who | Response |
|---|---|---|---|
| Tier 1 | Event hours plus 1 h each side | Venue operations | Acknowledge in 5 min |
| Tier 2 | 24/7 during the event window | Integrator on-call engineer | Respond in 30 min |
| Tier 3 | 24/7 | Vendor support | Respond in 1 h; S1 continuous |
| Safety | Event hours | Venue safety officer | Immediate for gate-state or life-safety signals |

## Rota

- Published at least seven days ahead; one named primary and one secondary per
  tier.
- Handover at least 15 minutes before the window with open incidents, changes and
  known risks.
- A rota gap is an S2 finding; a gap during a live event is S1.

## Paging rules

- S1 pages Tier 2 and Tier 3 immediately, and the venue safety officer.
- S2 pages Tier 2; Tier 3 after 30 min without progress.
- S3/S4 create a ticket; no page outside event hours.

## First 15 minutes

1. Acknowledge and open an incident record.
2. Establish impact: lanes, zones, capacity, life-safety boundary.
3. Apply the documented fallback (offline cache, manual lane) rather than
   improvising.
4. Escalate on the severity rules in `incident-command.md`.
5. Preserve audit and logs before any restart that would lose them.

## Handover fields

Incident ids, current severity, actions taken, next review time, who is paged, and
any open change freeze.

## Out of hours

The venue's own emergency procedure governs life-safety events. On-call supports
the TirBase system; it does not direct an evacuation.
