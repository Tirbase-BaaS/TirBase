# Safety case report (pilot)

**Status:** draft for independent review. Not an approved safety case.

## Scope

A single pilot venue, one integrator, a bounded set of gates and lanes, and the
TirBase venue runtime with its supported connectors. Out of scope: fire and
life-safety systems, structural and mechanical certification, site evacuation
modelling, and any venue-wide security operation not described here.

## Argument

**C1 — The gates fail to a defined safe state.**
Power loss, brownout, stall and restart all leave the lane in the configured safe
state, and egress release is mechanical and independent of TirBase.
*Evidence:* ST-12 HIL campaign; SR-01, SR-07.

**C2 — The gates decide correctly without the network.**
A signed local policy lets every lane decide offline, with the same answer as
when connected, and reconnect reconciles.
*Evidence:* offline kernel behaviour; offline drill; SR-02, SR-10.

**C3 — A revoked or replayed credential does not get in.**
A completed sync makes revocation effective offline; a repeated scan returns the
original decision. Capacity and lockdown rules refuse explicitly.
*Evidence:* connector revocation/replay tests; ST-07; SR-03, SR-04, SR-05, SR-06.

**C4 — TirBase cannot interfere with life safety.**
There is no fire alarm family, connector life-safety points and alarms are
refused, and egress hardware is outside the system.
*Evidence:* ST-15 life-safety refusal tests; SR-08; `EXCLUSIONS.md`.

**C5 — People and process are competent.**
Only accredited, badged staff commission and operate; the commissioning checklist
is signed gate by gate; monitoring and on-call cover every event.
*Evidence:* `integrator/`, `managed-ops/`; SR-15, SR-17.

**C6 — The system can be evidenced after the fact.**
Audit logs, scan ledgers, incident records and reconciliation reports support an
insurer, an authority and a post-incident review.
*Evidence:* `insurance/auditability.md`; SR-18.

## Assumptions

A1 The venue's competent person owns the site safety case.
A2 Mechanical egress release exists and is maintained independently.
A3 Life-safety systems are installed, certified and maintained by others.
A4 The integrator is accredited and commissions with the checklist.
A5 Occupancy limits come from the venue and the authority.
A6 The pilot scope is honoured: no expansion to new zones without re-review.

## Known limitations

- No site-specific measurement yet; capacity and timing figures are planning
  assumptions verified at commissioning.
- The independent review is outstanding. C1–C6 are the vendor's argument, not an
  independent opinion.
- Counsel review of the authority and insurance templates is outstanding.
- Hazard owners are roles; named people must be recorded before operation.

## Conclusion

The argument is internally coherent and every claim cites evidence the integrator
can verify without source access. It is **not** an approved safety case: the
independent review and counsel review are required, and this report must not be
presented as certified.
