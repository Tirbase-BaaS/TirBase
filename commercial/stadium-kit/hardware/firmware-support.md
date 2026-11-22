# Firmware support

## Baseline

The supported baseline is the firmware range recorded in the controller and reader
registers, attested for the installation. A device outside that range is
unsupported and cannot be commissioned.

## Rules

1. **Pinned.** No automatic update. Firmware changes are a normal or major change
   under `managed-ops/change-management.md`.
2. **Signed and verified.** Only vendor-signed images whose hash matches the
   register are installed.
3. **Offline media.** The attested baseline and its hashes are kept with the
   spares so a lane can be recovered without internet access.
4. **Re-attestation.** A firmware change outside the attested range reverts the
   device to `pending` until bench and site checks are repeated.
5. **No end-of-life device.** A device past its EOL date is replaced or covered by
   a signed deviation with an owner and a date.

## Support windows

| Component | Security fixes | Functional fixes | Notes |
|---|---|---|---|
| Gate controller | 24 months from release | 12 months | Critical fixes back-ported to the attested range where feasible |
| Reader | 12 months | 12 months | Replacement preferred over long back-porting |
| Network switch | Vendor window | Vendor window | Venue-managed |

## Vulnerability response

- A critical advisory for an in-baseline component is triaged within one business
  day and patched or mitigated before the next event.
- A device that cannot be patched is isolated or replaced.
- The decision, risk and compensating control are recorded as an emergency change.

## Verification at commissioning

- [ ] Every device firmware version recorded and in the attested range.
- [ ] Image hashes match the register.
- [ ] Offline recovery media present and readable.
- [ ] No device past EOL unaccounted for.
