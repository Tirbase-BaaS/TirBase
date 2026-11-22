# Gate failure modes

Scope: a gate lane consisting of a TirBase gate controller, a reader, a turnstile
and the network link. Each row states the safe state, how it is detected, and the
evidence. `H-xx` links to the hazard log.

| Mode | Cause | Safe state | Detection | Recovery | Hazard |
|---|---|---|---|---|---|
| Controller power loss | Supply or breaker failure | Turnstile releases to the configured fail-secure state; egress remains mechanically openable | Heartbeat loss; lane offline | Restore power; controller boots to a defined state and re-syncs policy | H-01, H-03 |
| Brownout / unstable supply | Generator transfer or sag | Controller holds the last safe state and does not accept a partial command | Voltage monitor; boot log | Replace supply; verify state at commissioning | H-03 |
| Controller stall | Firmware fault or watchdog trip | Watchdog resets to safe state; no partial admit | Watchdog event; missed heartbeat | Restart; capture logs; replace if recurrent | H-01 |
| Network loss | Switch, uplink or venue server failure | Lane continues offline from the signed local policy | Heartbeat and sync failure alarm | Reconnect; reconcile scans and revocations | H-02, H-10 |
| Policy expiry | Offline policy older than its validity window | Lane refuses authoritative operation and signals for operator fallback | Policy age check | Sync a valid policy or invoke the documented fallback | H-02 |
| Stale revocation cache | No sync before gates open | Lane must not be declared ready; operator uses the documented pre-open check | Cache age and watermark | Sync; verify a revoked test credential is refused | H-04 |
| Clock jump | NTP change or manual set | Decision time is monotonic; a jump does not admit or refuse incorrectly | Clock-jump event in the audit log | Correct time source; re-verify | H-11 |
| Reader failure | Hardware or cable fault | Lane degrades to a supervised manual check; no silent bypass | Reader health; lane alarm | Swap reader from spares; re-test | H-17 |
| Turnstile mechanical jam | Obstruction or mechanism fault | Lane closes; adjacent lanes absorb flow; staff direct the queue | Lane fault alarm | Clear obstruction; engineer if persistent | H-01 |
| Egress activation | Fire alarm or manual release | Turnstile releases mechanically; TirBase state is irrelevant to egress | Life-safety system signal | Follow the venue's evacuation procedure | H-08 |
| Duplicate scan delivery | Retry or replay | Second presentation returns the original decision; no second admit | Duplicate counter | None required | H-05 |
| Capacity envelope reached | Live count at limit | Lane refuses further entry; operator is alerted | Capacity alarm | Hold the queue; follow the capacity plan | H-06 |
| Unauthorised lockdown | Wrong role or forged command | Command is rejected and audited; state unchanged | Authorisation failure log | Investigate; rotate credentials if needed | H-07 |
| Connector attempts a life-safety write | Misconfiguration or malicious point | Request is refused permanently; no life-safety system is reachable | Refusal log with the point id | Remove the point; review the mapping | H-09 |
| CCTV metadata purge fails | Scheduler or store fault | Retention deadline is enforced at read; the record is not readable past it | Purge job error; expired-read attempt | Restore the sweep; reconcile the audit log | H-12 |
| Credential feed over-discloses holder data | Vendor schema change or a custom field | Unknown fields are refused by the strict schema; only the pseudonymous reference is stored | Deserialisation error | Pin the schema; raise with the vendor | H-13 |
| PA announcement duplicated | Retry or operator re-issue | Duplicate answer and no second audit row; the vendor deduplicates on the key | Duplicate classification | None; investigate the retry source | H-14 |
| Monitoring gap | Alert route or rota gap | Operator notices a missing heartbeat at the pre-open check | Coverage report | Restore the route; record an S2 finding | H-15 |
| Gateway or connector compromised | Weak credential or exposed admin | Gate decisions remain policy-bound; credentials rotate; admin actions are audited | Auth anomaly; admin audit | Isolate the host; rotate; investigate | H-16 |
| Untrained operator | No badge or no handover | Badge check blocks the commissioning signature | Badge registry | Remove from the lane; re-train | H-18 |
| Mapping error at commissioning | Manual entry | Unmapped or conflicting ids are refused; no guessed zone | Commissioning mapping check | Correct the mapping; re-run the lane checks | H-19 |
| Vendor outage during ingress | Ticketing or access service failure | Lane continues from the offline cache; scans reconcile later | Sync age; vendor status | Follow the fallback procedure; reconcile after the event | H-20 |

## Tested evidence

- Power, brownout, stall, network and clock cases: ST-12 HIL campaign,
  `docs/evidence/hil/st12-venue-gate-safety/`.
- Replay and revocation: ST-07 and the ticketing connector suite.
- Life-safety refusal: ST-15 BMS tests.

## Not covered here

Fire-system behaviour, mechanical egress hardware certification, turnstile
structural integrity and site evacuation modelling. Those belong to the venue's
life-safety and structural engineers.
