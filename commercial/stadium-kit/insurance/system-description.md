# Insurance evidence — system description

This pack supports an underwriter's assessment of a pilot venue installation. It
is not a policy, a warranty or a statement that cover will be offered.

## What the system is

TirBase is a local-first venue operations runtime with:

- a gate kernel that decides admission from a signed local policy, online or
  offline;
- access control, capacity envelopes, lockdown controls and anti-replay;
- a command centre for incidents, drills and after-action reports;
- privacy-controlled CCTV metadata (no video) and DPIA templates;
- connectors to ticketing, access control, BMS, CCTV metadata and PA systems;
- a HIL bench and evidence pack for gate safety behaviour.

## What it is not

- It is not a life-safety system and does not control fire detection,
  suppression, smoke control, gas detection, emergency lighting or egress
  hardware.
- It is not a video management system and stores no camera media.
- It is not a certification of the venue, the integrator or the installation.

## Boundary

| Inside TirBase | Outside TirBase |
|---|---|
| Gate decision, offline policy, scan ledger, capacity, lockdown workflow, audit | Turnstile mechanics and egress release, fire panel, suppression, PA amplifier and loudspeakers, VMS recording, building structure |
| Ticketing/access/BMS/CCTV-metadata/PA integration | Vendor service availability, venue network, mains and generator supply |

## Pilot scope

One venue, one integrator, a bounded gate set, a defined event calendar, and a
named venue safety owner. The scope, and any change to it, is recorded with the
safety case and the authority templates.

## Dependencies the underwriter should see

- A mechanical egress release independent of TirBase (SR-07).
- A competent person owning the site safety case (`safety/risk-assessment.md`).
- An accredited integrator (`integrator/`) and signed commissioning.
- Supported firmware and spares (`hardware/`).
- Monitoring, on-call and incident command (`managed-ops/`).
- The venue's life-safety maintenance regime, held by the venue.
