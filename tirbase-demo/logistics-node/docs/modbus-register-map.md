# Logistics Node Register Map (CLAIM-48.3)

This pack is a **CRDT BaaS demo** (no Modbus actuation). The logistics node
exercises offline-first CRDT convergence and revocation handling rather than a
physical actuator bus.

- Data model: CRDT document `controls` with `id` and `status` fields.
- Scenarios: S10 (revoked delta propagation rejected) and S12 (partition+rejoin convergence).
- Transport: simulated mesh with partition/heal via `tirbase-sim`.

No physical register map applies; this file is included to satisfy the demo
pack format and to document the absence of a Modbus-backed device.
