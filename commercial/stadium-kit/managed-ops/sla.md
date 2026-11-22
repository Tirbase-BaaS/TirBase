# Managed venue operations — SLA

## Scope

Support for the TirBase venue runtime and licensed connectors during the agreed
event calendar, plus the monitoring, on-call and incident-command services in this
section. Excluded: venue network and power, gate mechanics, life-safety systems,
vendor services, camera hardware and PA amplification.

## Targets

| Severity | Response | Workaround | Resolution target |
|---|---|---|---|
| S1 | 15 min, 24/7 in the event window | 1 h | Restore safe operation or a documented fallback; root cause within 5 days |
| S2 | 30 min | 4 h | 1 business day |
| S3 | 4 business hours | 1 business day | 5 business days |
| S4 | 1 business day | — | Next release or 10 business days |

"Response" is a qualified human acknowledgement, not an automated ticket.
"Workaround" is a documented fallback that restores the venue's operation.

## Availability

- Monitoring and on-call coverage: 99.5% of the agreed event window per quarter.
- Support portal: 99% monthly.
- The runtime is local-first; a vendor-side outage does not stop an offline gate,
  so platform uptime is not offered as a substitute for the venue's own resilience.

## Measurement

- Incidents are timestamped in the incident record.
- Response and workaround times are measured from the first qualified alert or
  report.
- Monthly service report: incidents, severities, times, changes, findings, repeat
  causes.

## Exclusions and relief

No credit for time caused by the venue's network, power, gate mechanics,
life-safety systems, vendor outage, an unsupported configuration, or a change made
without approval. Planned maintenance is announced seven days ahead and scheduled
outside event windows.

## Credits

Service credits, if any, are set in the signed agreement. This document does not
create a credit entitlement by itself.

## Safety precedence

An S1 safety event suspends SLA credit calculation while the venue's emergency
procedure runs; the incident is still recorded and reviewed.
