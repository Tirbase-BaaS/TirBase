# Safe-Default Enforcement on Guard Death (CLAIM-13.5, PV-4.15, PV-23.1)

**Chosen approach: (a) proactive controller watchdog/fallback register programming.**

## Problem
`ExecStopPost=` cannot drive safe defaults because driver children are also dead when the guard exits. Any safe-default mechanism that depends on a guard or driver process running after guard death is unreliable.

## Options considered
- **(a) Proactive controller watchdog registers (chosen):** While the guard is healthy, it programs each controller's own fallback/watchdog registers so the controller self-reverts to a configured `safe_default` if the guard stops refreshing within `timeout_secs`. If the guard dies, the controller's hardware/firmware watchdog times out and applies the safe default without any guard or driver process present.
- **(b) `tirbase-safe-writer` sandboxed driver via ExecStopPost:** A separate sandboxed process with its own driver instance starts during `ExecStopPost`. Not implemented; acceptable alternative if a controller lacks a reliable watchdog/fallback register.

## Production caller
`tirbase_guard::lockdown::arm_controller_watchdogs` is the production caller (invoked by the guard startup/refresh path). Each controller binding implements `SafeDefaultBinding` in `tirbase-drivers` (protocol-specific: Modbus/BACnet/register watchdogs).

## Systemd note
`tirbase-guard.service` uses `OnFailure=tirbase-lockdown.service` to persist LOCKDOWN on guard failure (CLAIM-13.4) and `StartLimitBurst=3`/`StartLimitIntervalSec=300` for crash-loop escalation (CLAIM-13.6). Safe defaults are **not** driven by `ExecStopPost`.

## Invariants
- INV-5: LOCKDOWN mode actuates only `safe_default` values, never a commanded value.
- On guard death, the controller reaches `safe_default` via its own watchdog (no guard/driver dependency).
