# ST-09 — Venue scenario pack

**Status:** complete. **Pack licence:** Apache-2.0. **Runner licence:** AGPL-3.0-only.

ST-09 is a deterministic, data-only pack of defensive venue scenarios plus an
AGPL integration runner that executes them against the real ST-02..ST-08
engines. The pack exists so the defences built in earlier prompts can be
demonstrated end to end, with the safety claim asserted rather than printed.

## What this is

- `tirbase-venue-scenarios` (Apache-2.0): a serde model, six JSON documents and
  a strict loader. It has **no** dependency on any `tirbase-` runtime crate and
  contains no executable logic beyond parsing and validation. This is what
  "data-only" means here: auditable JSON that a venue operator, safety reviewer
  or another implementation can read without linking Rust.
- `tirbase-venue-scenario-runner` (AGPL-3.0-only): wires each scenario to
  ST-05 tickets, ST-06 capacity, ST-07 admission/revocation, ST-08 lockdown and
  ST-04 gate fail modes, compares every declared expectation, evaluates the
  scenario's safety invariant over the observed trace, and prints the defended
  output. Failure is an error, not a log line.

The split keeps the scenarios distributable under Apache-2.0 while the AGPL
integration harness stays in the AGPL runtime family, matching the rest of the
venue stack.

## Non-goals

- **Not safety certification.** Passing these scenarios does not certify a
  venue, a gate, a controller or this software for any safety function. They are
  executable examples of designed behaviour, not a hazard analysis, a SIL/ASIL
  assessment or an acceptance test for a real installation.
- **No biometrics.** No scenario, model field or engine reads faces,
  fingerprints, gait or any other biometric. Identity is a signed ticket id and
  a nonce; operators are named custodians.
- **No fire-system control.** Nothing here integrates with, commands, inhibits
  or substitutes for a fire detection or fire suppression system. Life-safety
  egress remains the fire system's responsibility; the scenarios only check that
  ingress is refused while egress stays possible.

The pack is not a substitute for physical security review, licensed engineering
judgement, or the venue's own emergency procedures.

## Scenarios

| id | safety invariant | what it demonstrates |
| --- | --- | --- |
| `gate-replay` | `ticket_admitted_at_most_once` | One ticket admits once; a second gate denies `cross_gate`; a repeat at the first gate denies `duplicate`. |
| `capacity-breach` | `ingress_never_exceeds_hard_limit_without_approved_override` | A gate hard limit refuses the fourth ingress; a 2-of-2 approved capacity override grants headroom and the lane admits again. |
| `sensor-spoof` | `sensor_occupancy_change_requires_audited_adoption` | A sensor claiming 40 against 2 counted people is only observed; adoption needs an attributable actor and reason, raises a disagreement alarm and lands in the audit log. |
| `venue-lockdown` | `lockdown_and_release_use_distinct_m_of_n_approvals` | One approval cannot lock down, two engage it, ingress is refused, reusing the lockdown signatures for a release is rejected, a fresh 2-of-2 release reopens the venue. |
| `revocation-expiry` | `stale_revocation_list_never_admits` | An expired revocation list refuses and alarms at two hours; a signed delta v1→v2 renews it and the same ticket then admits. |
| `power-loss-gate` | `power_loss_leaves_gate_in_safe_state` | A fail-safe lane unlocks and a fail-secure lane locks on power loss, egress is never blocked, and restoration leaves both positions `unknown` pending feedback. |

Every document declares:

- `initial` — venue, base timestamp, venue/zone/gate limits, approval policy,
  stale-list policy, revocation validity, tickets and gate fail modes;
- `timeline` — signed commands, ticket presentations, ingress/egress events,
  sensor observations and power operations at fixed offsets;
- `expected_steps` — the required result and reason code for each step;
- `expected_final` — occupancy, revocation version, lockdowns, postures, audit
  and security events, gate positions;
- `safety_invariant` — an executable invariant id plus its human statement.

## Determinism

The runner uses fixed Ed25519 seeds (`issuer-1`, `custodian-1..3`), the fixed
`base_utc_us` in each document, default replay epoch policy, and no wall clock,
network or randomness. Running a scenario twice yields byte-identical
serialized observations; the AGPL tests assert this for all six.

## Invariants: asserted, not logged

Each scenario names one invariant id. The runner collects typed evidence while
executing — admission counts per ticket, every admitted ingress with gate, zone
and venue occupancy against hard limits and the presence of an override,
adoption audit entries and alarms, executed commands with approval counts and
request ids, stale-list checks before each admission, and gate positions plus
egress state after each power cut — then evaluates the invariant over that
evidence. A false invariant returns `RunError::InvariantFailed` and the process
exits non-zero.

## Tests

Apache-2.0 structural tests (`tirbase-venue-scenarios/tests/st09_structure.rs`):

- all six documents parse under `deny_unknown_fields` and validate;
- ids are unique and match the declared pack;
- unknown document and step fields are rejected;
- round-trip serialization is stable;
- the scenarios directory contains only the declared JSON documents;
- the manifest is Apache-2.0 and depends on no `tirbase-` crate;
- every invariant id is exercised by at least one scenario;
- these docs state the non-goals and data-only guarantee.

AGPL integration tests (`tirbase-venue-scenario-runner/tests/st09_scenarios.rs`):

- every scenario runs to a passing invariant with the real engines;
- two runs produce equal observations and equal JSON;
- a mutated step expectation yields `StepMismatch`;
- a mutated final expectation yields `FinalMismatch`;
- running a scenario with an invariant its trace cannot support yields
  `InvariantFailed` (for example, no stale revocation list observed);
- an unknown invariant id is refused as invalid;
- an undeclared ticket is refused as invalid.

## Running it

```sh
scripts/run-venue-scenarios.sh              # all six, defended output
scripts/run-venue-scenarios.sh --list       # ids and titles
scripts/run-venue-scenarios.sh --scenario gate-replay
```

Or directly:

```sh
cargo run -p tirbase-venue-scenario-runner --bin venue-scenarios
```

The script exits 0 only when every selected scenario defended its invariant;
1 means at least one scenario ran but did not defend; 2 means the pack failed to
load or an unknown scenario was requested.

## Adding a scenario

1. Add a JSON document under `tirbase-venue-scenarios/scenarios/` and register
   it in `SCENARIOS` in that crate's `lib.rs`. Keep the document free of code.
2. Declare the initial state, the timeline with absolute offsets and approvers,
   the expected step results and reasons, the expected final state and one of
   the executable invariant ids.
3. The structural tests will check shape and strictness; the integration runner
   will execute it against the engines. If the engines cannot satisfy the
   document, the document or the engine is wrong — the pack never weakens an
   expectation to pass.
