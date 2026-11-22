# ST-12 venue gate HIL campaign

Schema: `tirbase.hil.st12.venue-gate-safety.v1`  
Seed: `12`  
Digest: `40d212bba98f9358702db814453629b8163c7ff87f21ece6f184984165a35fa6`  
Result: **PASS**

| Case | Kind | Result | Observation |
| --- | --- | --- | --- |
| `bench.composed` | Bench | PASS | controller=gate-n1 reader=0 turnstile=locked supply=24000mV safe_state=secured |
| `power_loss.fail_safe.idle` | PowerLoss | PASS | at idle: before={"fail_mode": "fail_safe", "position": "locked", "reader_reads": "0", "safe_state": "released", "supply_mv": "24000", "turnstile": "locked", "wall_jumps": "0"} supply=24000mV; after controller=unlocked turnstile=unlocked safe=released command=Some("release"); queued=false |
| `power_loss.fail_safe.reader_tap` | PowerLoss | PASS | at reader_tap: before={"fail_mode": "fail_safe", "position": "locked", "reader_reads": "1", "safe_state": "released", "supply_mv": "24000", "turnstile": "locked", "wall_jumps": "0"} supply=24000mV; after controller=unlocked turnstile=unlocked safe=released command=Some("release"); queued=false |
| `power_loss.fail_safe.permit_armed` | PowerLoss | PASS | at permit_armed: before={"fail_mode": "fail_safe", "position": "locked", "reader_reads": "1", "safe_state": "released", "supply_mv": "24000", "turnstile": "locked", "wall_jumps": "0"} supply=24000mV; after controller=unlocked turnstile=unlocked safe=released command=Some("release"); queued=false |
| `power_loss.fail_safe.actuating` | PowerLoss | PASS | at actuating: before={"fail_mode": "fail_safe", "position": "locked", "reader_reads": "1", "safe_state": "released", "supply_mv": "24000", "turnstile": "unlocked", "wall_jumps": "0"} supply=24000mV; after controller=unlocked turnstile=unlocked safe=released command=Some("release"); queued=false |
| `power_loss.fail_safe.passage` | PowerLoss | PASS | at passage: before={"fail_mode": "fail_safe", "position": "open", "reader_reads": "1", "safe_state": "released", "supply_mv": "24000", "turnstile": "open", "wall_jumps": "0"} supply=24000mV; after controller=unlocked turnstile=unlocked safe=released command=Some("release"); queued=false |
| `power_loss.fail_safe.reclosing` | PowerLoss | PASS | at reclosing: before={"fail_mode": "fail_safe", "position": "open", "reader_reads": "1", "safe_state": "released", "supply_mv": "24000", "turnstile": "open", "wall_jumps": "0"} supply=24000mV; after controller=unlocked turnstile=unlocked safe=released command=Some("release"); queued=false |
| `brownout.fail_safe.shallow` | Brownout | PASS | supply sagged to 20000mV: reader_link=offline turnstile=unlocked (bounded drive, expected unlocked) |
| `brownout.fail_safe.deep` | Brownout | PASS | supply sagged to 16000mV: controller=unlocked turnstile=unlocked safe=released |
| `egress.fail_safe.powered` | EmergencyEgress | PASS | fire input: released=true entry_refused=true re-secured=true controller=locked turnstile=locked |
| `egress.fail_safe.after_power_cut` | EmergencyEgress | PASS | fire input: released=true entry_refused=true re-secured=true controller=locked turnstile=locked |
| `safety.stalled_controller.fail_safe` | SafetyState | PASS | controller stalled for 13s; turnstile watchdog position=unlocked expected=unlocked (fail-safe remains open by design) |
| `safety.stuck_open_power_cut.fail_safe` | SafetyState | PASS | stuck-open mechanism after power cut: controller=unlocked turnstile=unlocked safe=released |
| `power_loss.fail_secure.idle` | PowerLoss | PASS | at idle: before={"fail_mode": "fail_secure", "position": "locked", "reader_reads": "0", "safe_state": "secured", "supply_mv": "24000", "turnstile": "locked", "wall_jumps": "0"} supply=24000mV; after controller=locked turnstile=locked safe=secured command=Some("lock"); queued=false |
| `power_loss.fail_secure.reader_tap` | PowerLoss | PASS | at reader_tap: before={"fail_mode": "fail_secure", "position": "locked", "reader_reads": "1", "safe_state": "secured", "supply_mv": "24000", "turnstile": "locked", "wall_jumps": "0"} supply=24000mV; after controller=locked turnstile=locked safe=secured command=Some("lock"); queued=false |
| `power_loss.fail_secure.permit_armed` | PowerLoss | PASS | at permit_armed: before={"fail_mode": "fail_secure", "position": "locked", "reader_reads": "1", "safe_state": "secured", "supply_mv": "24000", "turnstile": "locked", "wall_jumps": "0"} supply=24000mV; after controller=locked turnstile=locked safe=secured command=Some("lock"); queued=false |
| `power_loss.fail_secure.actuating` | PowerLoss | PASS | at actuating: before={"fail_mode": "fail_secure", "position": "locked", "reader_reads": "1", "safe_state": "secured", "supply_mv": "24000", "turnstile": "unlocked", "wall_jumps": "0"} supply=24000mV; after controller=locked turnstile=locked safe=secured command=Some("lock"); queued=false |
| `power_loss.fail_secure.passage` | PowerLoss | PASS | at passage: before={"fail_mode": "fail_secure", "position": "open", "reader_reads": "1", "safe_state": "secured", "supply_mv": "24000", "turnstile": "open", "wall_jumps": "0"} supply=24000mV; after controller=locked turnstile=locked safe=secured command=Some("lock"); queued=false |
| `power_loss.fail_secure.reclosing` | PowerLoss | PASS | at reclosing: before={"fail_mode": "fail_secure", "position": "open", "reader_reads": "1", "safe_state": "secured", "supply_mv": "24000", "turnstile": "open", "wall_jumps": "0"} supply=24000mV; after controller=locked turnstile=locked safe=secured command=Some("lock"); queued=false |
| `brownout.fail_secure.shallow` | Brownout | PASS | supply sagged to 20000mV: reader_link=offline turnstile=locked (bounded drive, expected locked) |
| `brownout.fail_secure.deep` | Brownout | PASS | supply sagged to 16000mV: controller=locked turnstile=locked safe=secured |
| `egress.fail_secure.powered` | EmergencyEgress | PASS | fire input: released=true entry_refused=true re-secured=true controller=locked turnstile=locked |
| `egress.fail_secure.after_power_cut` | EmergencyEgress | PASS | fire input: released=true entry_refused=true re-secured=true controller=locked turnstile=locked |
| `safety.stalled_controller.fail_secure` | SafetyState | PASS | controller stalled for 13s; turnstile watchdog position=locked expected=locked (fail-safe remains open by design) |
| `safety.stuck_open_power_cut.fail_secure` | SafetyState | PASS | stuck-open mechanism after power cut: controller=locked turnstile=locked safe=secured |
| `network.loss_without_cache` | NetworkLoss | PASS | back-office loss: denied=true stayed_locked=true online_recovered=true |
| `network.loss_with_cache` | NetworkLoss | PASS | cached grant offline=true reader_link=offline controller=unlocked |
| `network.loss_while_open` | NetworkLoss | PASS | network lost with lane open; after open hold controller=locked turnstile=locked |
| `clock.jump_forward` | ClockJump | PASS | wall +1 day: permit=None gate_time_advanced_monotonically=10000001us position=locked |
| `clock.jump_backward` | ClockJump | PASS | wall -1 day: open hold still elapsed on monotonic time; controller=locked turnstile=locked |
| `durability.long_run` | Durability | PASS | cycles=600 cards=600 audit_entries=256 audit_dropped=2144 chain_ok=true restored=true faults=0 |
| `durability.event_flood` | Durability | PASS | rounds=5000 last_event_seq=10000 events_dropped=9936 audit_entries=128 audit_dropped=9872 chain_ok=true |
