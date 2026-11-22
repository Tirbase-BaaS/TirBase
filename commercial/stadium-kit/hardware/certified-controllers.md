# Gate controllers — certification programme

## Status

**No controller model is certified by this kit.** The register below is empty of
approved devices by design: certification requires an attestation with evidence,
and none has been completed. Do not quote a controller as certified.

## What "certified" means here

A controller is certified for a TirBase venue when all of the following are
recorded:

1. Model, hardware revision and supported firmware range.
2. Fail-secure behaviour and power-loss evidence, witnessed on the bench or on
   site (`docs/evidence/hil/st12-venue-gate-safety/`).
3. A mechanical egress release that is independent of controller software.
4. A watchdog and restart-to-defined-state behaviour.
5. Network-loss behaviour: continues from a local policy or fails to the safe
   state.
6. Tamper and cabinet security review.
7. Supply, spares and EOL position (`spares.md`, `eol-policy.md`).
8. A signed attestation by the integrator's safety lead and the vendor's hardware
   owner, with an expiry date.

This is not a third-party safety certification and does not replace one.

## Register

| Model | Revision | Firmware | Egress independent | Bench evidence | Attestation | Expiry | Status |
|---|---|---|---|---|---|---|---|
| *(none)* |  |  |  |  |  |  | pending |

## Rules

- A lane may only be commissioned with a controller whose register row is
  `certified` and in date.
- A firmware change outside the attested range reverts the row to `pending` until
  re-attested.
- A controller with no mechanical egress release cannot be certified, regardless
  of software behaviour.

## Certification path for a new controller

1. Integrator submits the model and evidence to the vendor hardware owner.
2. Bench run of the failure matrix in `safety/gate-failure-modes.md`.
3. Site witness on one lane, including an egress test.
4. Attestation signed and registered with an expiry.
5. The model is added to `bom-template.csv` for quoting.
