# Managed venue operations — monitoring

## Signals

| Signal | Source | Threshold | Action |
|---|---|---|---|
| Lane offline | Gate heartbeat | 30 s | Operator alert; check power, network and controller |
| Sync age | Credential/ticket cache | Greater than the pre-open window | Block ready declaration; sync |
| Feed watermark stall | Connector sync | Two consecutive syncs with no advance | Investigate vendor feed; escalate |
| Delivery failures | Connector classification | Retryable errors for 5 min | On-call; check vendor status |
| Replay or duplicate spike | Scan ledger | Baseline + 3σ | Check for a stuck client or a malicious replay |
| Capacity envelope reached | Live count | At limit | Operator holds the queue; capacity plan |
| Camera offline or stale | Camera health | Offline 2 min or stale 10 min | Check camera and VMS; no media is pulled |
| Connector refusal (life-safety) | Connector log | Any | **Immediate escalation**: a life-safety point was attempted |
| Lockdown state change | Audit log | Any | Confirm with the security officer; record |
| Clock jump | Gate audit | Any | Correct time source; verify decisions |
| Audit store write failure | Local runtime | Any | Stop and treat as an incident |

## Dashboards

1. **Event board** — lanes, throughput, queue, capacity per zone.
2. **Integration board** — connector health, sync age, retries, duplicates,
   refusals.
3. **Safety board** — gate state changes, lockdowns, clock jumps, life-safety
   refusals, camera health.

## Alert routing

- Operator console for operational signals.
- On-call engineer for integration and infrastructure signals.
- Venue safety officer for gate-state, lockdown and life-safety signals.
- Security lead for credential and admin anomalies.

## Retention

Metrics are retained per the venue's policy and the customer DPIA. Alerts and
acknowledgements are part of the incident record. No camera media is collected by
monitoring.

## Limits

This specification describes what to watch. It does not replace the venue's
emergency procedures or the life-safety system's own monitoring.
