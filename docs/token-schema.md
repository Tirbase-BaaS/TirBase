# Biscuit Token Schema and Authorizer

<!-- CLAIM-3.11 -->
<!-- Requirements: PV-3, PV-4 -->

This document describes the Biscuit token fact structure used by TirBase, the server-side
Datalog authorizer program, and the boundary between Biscuit-enforced checks and
Rust-enforced envelope arithmetic. It covers `now_est` injection, attenuation caveats, and
Biscuit revocation IDs.

---

## 1. Token Fact Structure

Biscuit tokens issued by the TirBase guard or admin CLI carry the following facts:

```biscuit
// Facts in token (issued by guard / tirbase-admin mint):
command(#target_id)
scope(#param_name)
role("CommandIssuer")
exp(unix_timestamp)
```

### Fact semantics

| Fact | Type | Meaning |
|---|---|---|
| `command(#target_id)` | symbol | Attenuates the token to exactly one target device ID. A bearer may only issue commands against the named target. |
| `scope(#param_name)` | symbol | Attenuates the token to exactly one parameter name on the named target. A bearer may only set the named parameter. |
| `role("CommandIssuer")` | string | Declares the bearer's role. Valid roles are `CommandIssuer`, `PolicyAuthority`, `UpdateSigner`, `RevocationManager`, `Auditor`, and `TimeAnchor`. The guard derives the `CommandRole` enum value from this fact at Stage 4 and never reads `cmd.role` directly. |
| `exp(unix_timestamp)` | integer | Expiry in Unix seconds. The Biscuit authorizer enforces this against the authenticated-time estimate `now_est` (see §4), not the raw system clock. |

---

## 2. Authorizer Datalog Program

The following Datalog program runs inside the Biscuit authorizer on the server side at
token verification (Stage 3):

```datalog
// Authorizer checks (server-side, in Biscuit Datalog):

// Enforce target and parameter scope: the token must name an existing target and parameter.
check if command($t), scope($p), profile_exists($t), parameter_exists($t, $p)

// Enforce role: bearer must hold the CommandIssuer role.
check if role("CommandIssuer")

// Expiry is enforced by the Biscuit runtime against the authorizer-provided time fact.
// The time fact is set to now_est before authorizer execution (see §4).

// Envelope arithmetic (bounds, rate-of-change, drift) runs in Rust (Stage 11), NOT here:
// deny if envelope_violated($t, $p, $value)
```

The authorizer is evaluated by the Biscuit library. All `check if` rules must pass; any
failing check causes `authorize` to return an error and the token is rejected.

---

## 3. Design Deviation: Envelope Arithmetic Runs in Rust, Not Datalog

> **CRITICAL DEVIATION — must be understood by all Guard contributors.**

The Biscuit authorizer enforces **target and parameter scope attenuation**. Envelope
arithmetic — minimum/maximum bound checks, rate-of-change calculations, and drift
window enforcement — **runs in Rust (Stage 11), NOT in Biscuit Datalog**.

### Reasons for this boundary

1. **Single source of truth.** The envelope logic is shared between the gateway and the
 Phase 11 verifier. Duplicating it in Datalog would create two independent
 implementations that could diverge.

2. **i128 intermediate arithmetic safety.** Envelope bounds checks use i128 intermediates
 to prevent overflow on i64 fixed-point values. Datalog integer operations cannot
 guarantee overflow-free arithmetic for this computation.

3. **`no_std` verifier feasibility.** The Phase 11 verifier needs the same envelope checks
 in a `no_std` environment where the Biscuit crate may not be available.

### What Biscuit CAN enforce (and does)

Biscuit expression constraints **can** perform numeric comparisons; value-attenuation
caveats such as `check if command($t), $t == "target_1"` are expressed on the token.
The token ensures the issuer cannot command a target or parameter that is not in their
token scope.

### Final arbiter of envelope bounds

The guard is the final arbiter of envelope bounds (see `INV-7` in
`docs/system-invariants.md`). Even if a token is valid and the authorizer passes, the
guard's Stage 11 Rust envelope check is always executed.

> Previous documentation claimed that Datalog cannot perform numeric comparisons — this
> was inaccurate and has been corrected. The actual reason for the Rust boundary is the
> single-source-of-truth requirement, overflow safety, and `no_std` verifier feasibility.

---

## 4. `now_est` Injection Before Token Verification

Biscuit expiry is enforced via the authorizer's `time` ambient fact. TirBase sets
this fact to `now_est` — the authenticated-time estimate produced by
`TimeRatchet::now_est` — before calling `authorizer.authorize`.

```rust
// Pseudocode — tirbase-guard/src/guard/stages.rs (Stage 3)
let now = time_ratchet.now_est(&*time_source);
authorizer.set_time(now); // sets the Biscuit time ambient fact
authorizer.authorize(&token)?;
```

### Why `now_est` and not the system clock

The system wall clock (`SystemTime::now`) is explicitly untrusted in TirBase (PV-3.8,
PV-3.9). Using it for token expiry would allow a clock-rollback attack: an adversary who
can set the system clock backwards could make an already-expired token appear valid on
the next presentation.

`now_est` is derived from the most recently accepted signed `TimeBeacon` plus elapsed
monotonic time since that beacon was accepted. It is bounded below by the persisted
ratchet floor stored in the monotonic counter store, so it can only advance, never
retreat — even across reboots (PV-22.1, PV-22.4).

**Clock-rollback defence summary:**

| Attack | Defence |
|---|---|
| Set system clock back | `now_est` does not use the system wall clock |
| Replay an old `TimeBeacon` | `TimeRatchet::advance` rejects beacons that are not strictly greater than the persisted floor |
| Reboot to reset monotonic counter | Boot-ID tracking; on boot-id change, ratchet returns `persisted_floor` only, never a lower value |

---

## 5. Attenuation Caveats

Biscuit tokens support **attenuation**: any holder of a token can append additional
caveats to produce a derived token with a narrower scope. The derived token carries all
original caveats plus the new ones.

### Key properties

- **One-way restriction.** Attenuation can only restrict capability; it can never expand
 it. A `CommandIssuer` token attenuated to target `target_1` cannot be un-attenuated
 to re-admit other targets.

- **All caveats verified.** The guard verifies all caveats from all blocks in the token
 chain, including attenuated blocks appended by intermediate parties.

- **Role attenuation example.** A `PolicyAuthority` token can be attenuated to a
 `CommandIssuer` role for a specific target before delegation to a downstream operator:

 ```biscuit
 // Original PolicyAuthority token block 0 (issued by admin):
 role("PolicyAuthority")
 exp(1735689600)

 // Attenuated block 1 (appended by delegating operator):
 check if role("CommandIssuer")
 check if command("target_cold_room_3")
 ```

- **Scope-narrowing example.** A fleet-wide `CommandIssuer` token can be attenuated to
 a single parameter:

 ```biscuit
 // block 1 (attenuation caveat):
 check if scope("setpoint_degC")
 ```

- **Guard behaviour.** The guard always evaluates the full Datalog authorizer against
 all token blocks. An attenuated token that fails any caveat from any block is rejected
 in full.

---

## 6. Biscuit Revocation IDs

Every Biscuit token has a unique `revocation_id` derived from the cryptographic
signature over its root block. This ID is stable across attenuation — a derived token
shares the root block's `revocation_id`.

### Revocation flow

1. **Issuance.** When `tirbase-admin mint` creates a token, the token's `revocation_id`
 is recorded in the guard's revocation table alongside the issuer DID, target scope,
 and issue timestamp.

2. **Revocation.** A `RevocationManager` credential holder calls
 `POST /admin/revoke { revocation_id: "..." }`. The ID is written to the
 `revoked_tokens` table in the SQLite WAL store with `synchronous = FULL` to ensure
 durability before the API responds.

3. **Verification (Stage 3).** Before the Biscuit authorizer runs, the guard reads the
 token's `revocation_id` and checks it against the `revoked_tokens` table. A match
 causes an immediate rejection with `AuthError::TokenRevoked` before any Datalog
 evaluation occurs.

4. **Propagation.** The revocation record is replicated to all connected peers via the
 CRDT delta log with the same propagation SLA as other durability events (≤ 60 seconds
 to all connected peers, PV-3.11).

5. **In-flight commands.** Commands admitted by the guard before revocation was
 processed complete normally. Revocation takes effect on the **next token presentation**
 at Stage 3.

### Revocation ID format

The `revocation_id` is a 32-byte value serialised as lowercase hex in the admin API.
It is derived by the Biscuit library from the HMAC over the root block; consumers
should treat it as an opaque identifier and not attempt to re-derive it.

---

## Cross-references

| Topic | Where defined |
|---|---|
| `TimeRatchet` and `now_est` semantics | `design.md` §4.3 |
| `EnvelopeProfile` and Stage 11 bounds check | `design.md` §4.5 |
| Token schema and authorizer (source of truth) | `design.md` §4.12 |
| `INV-7` (guard is final arbiter of envelope) | `docs/system-invariants.md` |
| Unit IDs referenced in `FixedPointValue` | `docs/unit-registry.md` |
| `RevocationSubsystem` implementation | `tirbase-core/src/auth/revocation.rs` |
| Authorization matrix and role-pair rejection tests | `tirbase-guard/tests/auth_matrix.rs` |
