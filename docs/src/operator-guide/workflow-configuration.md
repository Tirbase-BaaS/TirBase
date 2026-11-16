# Workflow pack configuration (CC-13)

The excursion workflow's limits are data. Each pack ships a `workflow.toml`
document; the gateway turns it into detection thresholds, MKT parameters,
assessment windows, a debounce rule, notification routes and disposition codes at
start-up. **Changing a threshold is a file edit and a restart — not a rebuild.**

This guide is for operators and pack authors. The schema lives in the
Apache-2.0 `tirbase-demo` crate (`tirbase_demo::workflow`), which validates every
document field by field; the AGPL gateway consumes the validated document through
`tirbase_gateway::excursion::config::ExcursionPolicy`.

## Where the document lives

| Pack | Document | Loaded by |
|---|---|---|
| `tirbase-demo/cold-room/` | `workflow.toml` | `load_pack`, `ExcursionPolicy::from_pack_dir` |
| `tirbase-demo/reefer/` | `workflow.toml` | same |
| `tirbase-demo/pharma-gdp/` | `workflow.toml` | same |

A pack manifest binds the document with `workflow = "workflow.toml"`. The
document's `pack` field must equal the manifest `id`, so a workflow cannot be
attached to the wrong pack. Packs without a `workflow.toml` are still valid; they
simply have no configured excursion policy.

## Schema at a glance

```toml
schema_version = 1
id = "cold-room-workflow"
pack = "cold-room"
title = "Cold-room excursion workflow"
tirbase_min_version = "0.1.0"

[thresholds]              # detection limits
band_min_c = { mantissa = 0, exponent = -1, unit_id = 1 }      # 0.0 °C
band_max_c = { mantissa = 80, exponent = -1, unit_id = 1 }     # 8.0 °C
max_rate_c_per_sec = { mantissa = 5, exponent = -1, unit_id = 1 }
drift_budget_c = { mantissa = 20, exponent = -1, unit_id = 1 }
max_door_open_secs = 120
max_defrost_secs = 900
compressor_max_runtime_secs = 21600
max_telemetry_gap_secs = 300
mkt_limit_c = { mantissa = 80, exponent = -1, unit_id = 1 }

[windows]                 # how long things may stay open
assessment_secs = 3600
max_quarantine_secs = 86400
reporting_interval_secs = 3600
sampling_interval_secs = 300

[debounce]                # when a finding series becomes a quarantine
min_findings = 2
window_secs = 900
cooldown_secs = 1800

[mkt]                     # Arrhenius constants
activation_energy_j_per_mol = 83144
gas_constant_milli_j_per_mol_k = 8314
max_samples = 10000

[[notification.routes]]   # one entry per channel/event pair
channel = "pager"
event = "quarantine_opened"   # quarantine_opened | disposition_recorded | resolution_signed
enabled = true

[[dispositions.codes]]    # the vocabulary a lot may be given
code = "CR-REJ-003"           # 3..=32 uppercase letters, digits, '-'
kind = "reject"               # release | hold | reject | destroy
label = "Cold-room lot rejected"

[lot]                     # defaults for lot identities created under this pack
lot_kind = "lot"              # lot | batch | repack
uom = "kg"
label_prefix = "CR"
```

### Units

Every temperature is a `FixedPointValue` in **0.1 °C**: `unit_id = 1` and
`exponent = -1`. `{ mantissa = 80, exponent = -1, unit_id = 1 }` is 8.0 °C. The
loader refuses any other unit or exponent and names the field, because a value
silently read as 1 °C would widen a 2–8 °C band by a factor of ten. Durations are
whole seconds. MKT parameters use the units in their field names.

### Validation

The document is refused — with the field path in the message — when:

- a required field is missing (`missing field 'debounce'`);
- an unknown field is present at any level (`unknown field 'unexpected'`);
- a temperature is not 0.1 °C with `unit_id = 1`;
- `band_min_c` is not lower than `band_max_c`;
- the rate is not positive, or a duration is zero;
- `reporting_interval_secs < sampling_interval_secs`,
  `assessment_secs < reporting_interval_secs`, or
  `max_quarantine_secs < assessment_secs`;
- `debounce.min_findings` is outside 1..=32, the window is smaller than the
  sampling interval, or the cooldown is not shorter than the quarantine cap;
- an MKT parameter is zero or `max_samples` is outside 1..=100000;
- a route names an unknown event, a channel that is not lowercase ASCII, a
  duplicate channel/event pair, or no route is enabled;
- a disposition code is malformed or duplicated, a kind is unknown, or any of
  `release`/`hold`/`reject`/`destroy` has no code;
- `lot.kind`, `uom` or `label_prefix` is missing, unknown or empty;
- `schema_version` is not the supported version, or `tirbase_min_version` is
  newer than the running build;
- any key looks like secret material (`password`, `token`, `secret`, `api_key`,
  `private_key`, `credential`, …).

Errors look like:

```text
workflow config field 'thresholds.band_max_c': must use unit_id 1 (degC), found 2
workflow config field 'windows.reporting_interval_secs': must be at least windows.sampling_interval_secs
```

## Changing a threshold without recompiling

1. **Find the active document.** It is the `workflow.toml` beside the pack the
   gateway runs (`tirbase-demo/<pack>/workflow.toml`), or the copy installed under
   the site configuration directory. Check `pack.toml` for the `workflow` entry.
2. **Edit only the value**, keeping the field's unit form. Widen the cold-room
   band to 9.0 °C:
   ```toml
   band_max_c = { mantissa = 90, exponent = -1, unit_id = 1 }   # was 80
   ```
3. **Validate before restarting.** The Apache structural suite validates all
   three committed packs and every field rule:
   ```bash
   cargo test -p tirbase-demo --test workflow_config
   ```
   For a site copy, point a scratch pack at it and run the same test, or start the
   gateway: an invalid document fails start-up with the field-level error above
   and the previous process keeps running.
4. **Restart the gateway.** Detection thresholds, MKT parameters, windows,
   debounce, routes and disposition codes are read once at start-up; nothing is
   cached across a restart.
5. **Verify.** Send an in-band and a just-out-of-band sample and confirm the
   quarantine appears (or does not) at the new limit. Recall and disposition
   queries show the decision the workflow reached.

### Rolling back

Keep the previous file (`workflow.toml.bak`) next to it, restore, restart. The
document is data: no migration is needed for a value change, and a config with a
`tirbase_min_version` newer than the running build is refused rather than
partially applied.

### Secrets

Never put credentials in `workflow.toml`. Routes name a **channel**, not an
address or a token; channel credentials live in the gateway secret/key store.
The loader refuses any key that looks like a secret, so a copied password is a
start-up error rather than a leak in a pack archive.

### What the values mean at runtime

- `thresholds.*` are passed unchanged to `evaluate_detection`; each finding is
  produced exactly when the corresponding limit is crossed.
- `debounce.min_findings` findings inside `debounce.window_secs` raise one
  quarantine; no new quarantine for the same lot until `debounce.cooldown_secs`
  has passed.
- `windows.assessment_secs` sets the assessment deadline
  (`opened_est + assessment_secs`); `windows.max_quarantine_secs` is the hard cap
  after which the hold is overdue.
- `notification.routes` are the channels registered with the dispatcher; only
  enabled routes receive events.
- `dispositions.codes` is the vocabulary an operator may cite; the pack's reject
  code is what a recall report cites for a rejected lot.
- `lot.*` supplies the kind, unit and label prefix for identities created under
  the pack.

## Reference

- Schema and validation: `tirbase-demo/src/workflow.rs`
- Pack loader integration: `tirbase-demo/src/lib.rs` (`load_pack`)
- Policy adapter: `tirbase-gateway/src/excursion/config.rs`
- Structural tests: `tirbase-demo/tests/workflow_config.rs`
- End-to-end tests: `tirbase-gateway/tests/workflow_pack.rs`
- Excursion workflow: CC-11 (`tirbase-gateway/src/excursion/`)
