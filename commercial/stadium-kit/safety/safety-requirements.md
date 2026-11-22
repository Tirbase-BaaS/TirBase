# Safety requirements

Each requirement is verifiable by the integrator without source access: by an
observed black-box behaviour, a signed document, or a named test/evidence
reference in the open repository. `H-xx` links to `hazard-log.csv`.

| ID | Requirement | Hazards | Verification |
|---|---|---|---|
| SR-01 | A gate must reach its configured safe state on power loss, controller stall, brownout or restart, and must never latch a state that is neither open nor closed. | H-01, H-03 | HIL campaign `docs/evidence/hil/st12-venue-gate-safety/`; commissioning check |
| SR-02 | A gate must decide from a local signed policy when the network, venue server and vendor are unreachable; the decision must be identical to the connected decision for the same inputs. | H-02 | Offline drill at commissioning; ST-05 kernel |
| SR-03 | A revoked ticket or credential must be refused offline once a sync has completed, and the feed must be synced before gates open. | H-04, H-20 | Connector replay/revocation tests; commissioning check |
| SR-04 | A repeated scan must never admit twice; the second presentation must return the original decision. | H-05 | ST-07 anti-replay evidence; commissioning replay test |
| SR-05 | Occupancy must be refused when the configured capacity envelope is full, and the refusal must be visible to the operator. | H-06 | Commissioning load test; ST-06 |
| SR-06 | Lockdown must require an authorised role and the approved approval path, and must be recorded; an unauthorised command must not change state. | H-07 | ST-08 lockdown evidence; drill record |
| SR-07 | Emergency egress release must be mechanical and independent of TirBase, the gate controller software and the network. | H-01, H-08 | Site inspection; commissioning check |
| SR-08 | No TirBase component may connect to, command, inhibit or substitute for fire detection, suppression, smoke control, gas detection or emergency lighting; life-safety BMS points, alarms and writes must be refused. | H-08, H-09 | ST-15 life-safety refusal tests; commissioning inspection |
| SR-09 | A gate decision must not be changed by a wall-clock jump, drift or manual time change. | H-11 | HIL clock-jump case; commissioning time test |
| SR-10 | Network loss must degrade to local operation with a documented reconciliation after reconnect. | H-02, H-20 | Offline drill; incident procedure |
| SR-11 | CCTV data handled by TirBase must be metadata only, with enforced retention and audited access; video stays in the VMS. | H-12 | ST-13 privacy tests; customer DPIA |
| SR-12 | Credential and ticket feeds must carry only the fields required for admission, with holder references pseudonymised. | H-13 | Privacy register; connector redaction tests |
| SR-13 | PA announcements must render from an approved template with explicit zones, mapped priority and an audit entry; a replay must not broadcast twice. | H-14 | ST-15 PA tests; commissioning announcement drill |
| SR-14 | Only supported controller and reader firmware may be operated, and every component must have a spares and EOL position. | H-17 | `hardware/firmware-support.md`; `hardware/eol-policy.md` |
| SR-15 | Only accredited, badged integrator staff may commission or operate the system, and commissioning must follow the signed checklist. | H-18 | `integrator/`; commissioning sign-off |
| SR-16 | Venue, event, zone and seat mappings must be explicit, conflict-free and tenant-scoped; an unmapped id must be refused. | H-10, H-19 | Mapping conflict tests; commissioning check |
| SR-17 | Monitoring must detect gate, sync, connector and camera-health failures; on-call and incident-command roles must be staffed for every event. | H-15 | `managed-ops/monitoring.md`; `managed-ops/on-call.md` |
| SR-18 | Gateways and connectors must run a supported firmware baseline, use unique rotated credentials, be network-segmented, and log privileged actions. | H-16 | `hardware/firmware-support.md`; `insurance/auditability.md` |

## Completeness check

Every hazard in `hazard-log.csv` appears in at least one requirement above: H-01
to H-20. The gate enforces this cross-reference.
