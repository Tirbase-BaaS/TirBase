# Spares

## Minimum holding per venue

| Item | Minimum | Basis |
|---|---|---|
| Gate controller | 1 per 10 lanes, at least 1 | Lane failure during ingress |
| Reader | 1 per 10 lanes, at least 2 | Highest wear item |
| Network switch | 1 cold spare | Uplink or switch failure |
| Power supply / injector | 2 | Supply failure |
| Cabling and connectors | 10% of installed length | Field repair |
| Configuration and firmware media | Offline copy of the attested baseline | No-internet recovery |
| Hand tools and test credential set | 1 kit | Commissioning and drill |

## Storage and control

- Held at the venue or at a location reachable within the on-call response target.
- Recorded in the asset register with serial numbers and firmware.
- Sealed spares are checked quarterly; a used spare is replaced before the next
  event.
- Test credentials are stored and rotated like operational credentials.

## Swap procedure

1. Record the failing device, lane and observed state.
2. Isolate the lane; keep egress available.
3. Replace with the spare at the attested firmware.
4. Restore configuration from the offline copy; do not hand-edit policy.
5. Run the lane checks in `integrator/commissioning-checklist.md` section B and C.
6. Log the swap as a change and return the failed unit for analysis.

## Limits

Spares restore a lane; they do not replace preventive maintenance or the vendor
support agreement. A spares shortfall during an event is an S2 finding.
