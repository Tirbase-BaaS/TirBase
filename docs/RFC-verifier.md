# RFC: `no_std` Verifier Crate (Phase 11)

- **Status:** Draft (design-only RFC). **No verifier implementation code may be written until this RFC is merged to the main branch** (PV-13.5).
- **Requirements:** PV-13, PV-13.1–PV-13.5
- **Claim:** CLAIM-41.1 (this document)
- **Related:** PV-4 (Command Guard), PV-5 (anti-replay), PV-21 (fixed-point), PV-22 (time/freshness), RD-5 (COSE_Sign1 + deterministic CBOR)

## 1. Motivation

TirBase enforces actuator safety at the gateway Command Guard (Linux, `tirbase-guard`/`tirbase-gateway`). Some critical-infrastructure deployments need a last-mile enforcement point on a constrained microcontroller that sits directly in front of an actuator or fieldbus so that a compromised gateway, host OS, or network path cannot bypass envelope and replay protections after a command has been admitted upstream.

This RFC proposes a design-first, `no_std` (+ `alloc`) **trusted verifier core** whose only job is to make the same accept/reject decision as the gateway guard for a narrowly defined command path: verify a signed command, parse it from a binary fixed-width encoding, check it against a signed envelope, and enforce bounded replay state. The goal is to assess viability (interface, determinism, and footprint) before implementation, keeping the trusted computing base small enough to audit and to fit on low-end MCUs.

Non-goal of this phase: replacing the gateway guard, implementing drivers/transport, or claiming SIL/certification.

## 2. Scope and Exclusions

### In scope (trusted verifier core, `no_std` + `alloc`)

The verifier performs **only** the following (PV-13.1):

1. **Signature verification** of the command/authentication envelope (COSE/CBOR + Ed25519, per RD-5; see §3).
2. **Binary fixed-width command parsing** into a canonical in-memory representation (no schema negotiation, no variable-length untrusted parsing beyond fixed-width fields and bounded lengths declared by the format).
3. **Envelope check** of the desired-state value against installed envelope bounds/constraints using fixed-point arithmetic (per RD-5 / PV-21 rules).
4. **Fixed-size replay state** maintenance and lookup, capped at **256 entries** and **≤ 4 KiB RAM** total for the replay structure (including metadata/indices), to reject replayed or out-of-window commands per the verifier's accepted anti-replay contract.

The core exposes a pure decision API (accept/reject + typed reason) over caller-provided bytes/state snapshots; it does not perform I/O, scheduling, storage, or clock reads.

### Explicit exclusions (out of scope for the verifier core)

- Network/mesh/transport, TLS, gateway admin API, policy distribution, enrollment UX, and driver I/O (the MCU integrator wires I/O around the core).
- CRDT merge, schema migration, quarantine ledgers, persistence/recovery, security-event hash chains, observability, and fleet management.
- Full Biscuit/Datalog evaluation, multi-party policy lifecycle, firmware update logic, or dynamic memory growth outside `alloc` budgets stated in §4.
- Any bypass of gateway admission semantics: the verifier is an additional enforcement point, not a replacement for gateway-side authorization, issuance, or audit.
- SIL/safety certification claims (see `docs/THREAT_MODEL.md` non-goals).

### Dependency and code boundaries

- Target: `#![no_std]` with `alloc` permitted for bounded, caller-controlled allocations (or static arenas) consistent with §4 budgets.
- No `std`, no filesystem, no threads, no ambient time/randomness inside the core.
- Cryptography and CBOR code must be deterministic and suitable for embedded builds; float instructions are not used for command/envelope arithmetic (fixed-point only, per RD-5/PV-21).

## 3. Trusted-Core Interface (COSE_Sign1 + deterministic CBOR + Ed25519 + fixed-point per RD-5)

This section defines the proposed interface contract the implementation RFC-follow-on must satisfy. Concrete byte layouts are to be frozen in a companion schema/versioned spec before coding; the invariants below are normative for equivalence.

### 3.1 Message protection and encoding (RD-5)

- **COSE_Sign1** is the signing container for verifier-consumed command/envelope artifacts (aligned with TimeBeacon/attestation use of COSE_Sign1 over deterministic CBOR per RD-5 in `design.md`).
- **Deterministic CBOR** encoding is required for all signed payloads/hashes the verifier checks, so that independent implementations compute identical bytes and hashes for the same logical content (no map-key ambiguity, no non-canonical integer/float encodings). The verifier rejects non-deterministically encoded inputs where the profile requires canonical form.
- **Ed25519** is the signature algorithm for the trusted-core verification path (matching device/key types in `tirbase-types`/guard). Verification is constant-time with respect to secret material where the crypto primitive provides it; the verifier holds no private keys.
- **Fixed-point values (per RD-5 / PV-21)**: all physical quantities and envelope bounds are represented as fixed-point (`mantissa`, `exponent`, `unit_id` / canonical exponent rules consistent with `tirbase-types::FixedPointValue`). No IEEE-754 arithmetic in the decision path; comparisons use integer/i128-safe arithmetic consistent with guard semantics.

### 3.2 Binary fixed-width command parsing

- The verifier accepts a **binary fixed-width command frame** (or a fixed-width view derived from a deterministic-CBOR/COSE payload by a total, bounded decoder) containing, at minimum: issuer/target identifiers (or fixed-size hashes thereof as defined by the wire profile), parameter selector, desired fixed-point value, sequence/anti-replay fields, epoch/policy/version binding fields, and expiry/freshness fields required by the active contract.
- Parsing is total over the declared fixed-width layout: every field offset/length is known a priori; malformed length, unknown version, unit/exponent mismatch, or out-of-range field yields a typed parse/envelope rejection (never a panic/UB). Variable-length payloads, if any, are length-prefixed with explicit maxima counted against §4 budgets.
- The parser produces a canonical `VerifierCommand` view used by signature verification, envelope check, and replay update so that equivalence tests compare decisions, not incidental representations.

### 3.3 Envelope check

- Inputs: verified command view + installed `VerifierEnvelope` (a compact, fixed-width/profiled representation of the relevant `EnvelopeProfile`/parameter bounds: unit, canonical exponent, min/max, and any linear/cross constraints included in the verifier profile; total, non-Turing-complete).
- Checks: canonical exponent/unit match, bounds containment, and profiled constraint evaluation using fixed-point/integer arithmetic identical in meaning to gateway guard stages (bounds/constraint evaluation over the command's desired state).
- Output: `Accept` with a replay-state transition token, or `Reject(reason)` (signature, parse, envelope, replay, expiry/freshness, unsupported/unknown profile), without side effects beyond returning the next replay state.

### 3.4 Fixed-size replay state (capped)

- Replay state is a **fixed-capacity** structure (e.g., sliding window/bitmap or ring indexed by issuer-target-epoch key as frozen by the wire profile) with hard caps: **≤ 256 entries** and **≤ 4 KiB RAM** for the entire replay structure (storage + indices/metadata).
- The verifier rejects duplicates and out-of-window sequence numbers according to the same accept/reject contract as the gateway guard for inputs within the verifier's supported model; capacity/keying limits are explicit typed rejects (not silent eviction that would permit replay).
- State is caller-owned and passed in/out (or mutated in place) so the MCU integrator controls persistence/reset policy; the core defines the deterministic transition function.

### 3.5 API sketch (non-normative)

```text
verify_and_check(
 cmd_bytes: &[u8], // COSE_Sign1 / fixed-width command
 envelope: &VerifierEnvelope, // installed, signed/profiled bounds
 replay: &ReplayState256, // fixed-size, caller-held
 trust: &VerifierTrustRoot, // pinned keys/roots for this profile
 ctx: &VerifierContext // e.g. now_est/freshness inputs supplied by caller
) -> Decision { Accept(ReplayState256), Reject(Reason) }
```

Exact types are implementation details subject to the equivalence contract and §4 budgets.

## 4. Footprint Budgets and Target Hardware

### 4.1 Budgets (normative)

| Resource | Budget | Notes |
|---|---:|---|
| Flash / code + rodata | **≤ 64 KiB** | Trusted verifier core (parse + verify + envelope + replay), excluding application/driver/RTOS and excluding MCU HAL; measured on a release, size-optimized build with LTO for the core. |
| RAM (static + stack + heap-in-use) | **≤ 8 KiB** | Total working memory for a single `verify_and_check` invocation under worst-case bounded input; includes replay state contribution. |
| Replay state sub-budget | **≤ 256 entries, ≤ 4 KiB RAM** | Fixed-size structure as in §3.4 (counted within the 8 KiB RAM budget). |

Budgets are ceilings for the core; integrators must account separately for transport buffers, RTOS, and driver memory. Post-RFC implementation work must include a measure-first size report on reference targets and fail closed (reject feature growth) if the core cannot meet these ceilings without weakening checks.

### 4.2 Named target MCU families (≥ 2)

| MCU family | Representative part (reference) | Core / flash / RAM (part) | Fit rationale |
|---|---|---|---:|
| **STMicroelectronics STM32L4** (ultra-low-power Cortex-M4F) | STM32L476RG | Cortex-M4F @ 80 MHz, 1 MB Flash, 128 KB SRAM | Widely used industrial/secure IoT MCU with ample headroom over the 64 KiB/8 KiB core ceilings; common target for Ed25519/COSE experiments and gateway-adjacent actuator control. |
| **Nordic Semiconductor nRF52** (Cortex-M4F, Bluetooth/IoT) | nRF52840 | Cortex-M4F @ 64 MHz, 1 MB Flash, 256 KB SRAM | Common low-power field MCU in edge/mesh deployments; demonstrates viability on a non-STM32 vendor/toolchain with comfortable margin for the core budgets. |

Both families provide sufficient flash/RAM margin for the verifier core budgets above; final pin-level/board selection is an integration concern. Additional families (e.g., Cortex-M33 with TrustZone, or RISC-V parts such as ESP32-C3/GD32V) may be evaluated later but are not required by this RFC.

## 5. Equivalence and Test Strategy (differential proptest)

The verifier must be decision-equivalent to the gateway guard for the supported command/envelope/replay domain (PV-13.2).

### 5.1 Differential property tests (normative strategy)

- **Same inputs → same accept/reject result:** for every generated case within the verifier's supported profile, feed the logically identical command, envelope, trust material, replay state, and time/freshness context to (a) the gateway guard decision path (`tirbase-guard` admission/envelope/replay logic) and (b) the verifier core, then assert the **decision class and typed reject/accept outcome match**. Any divergence is a release-blocking defect or a documented, versioned profile exclusion.
- **Property-based generation (`proptest`):** generators produce bounded-but-adversarial cases across value ranges, canonical/non-canonical encodings (expect reject on non-canonical where required), boundary exponents/units, sequence windows, replay capacities (including 256-entry saturation), epoch/policy bindings, and signature validity/tampering. Shrinking must yield minimal counterexamples.
- **Vector agreement:** fixed signed test vectors (golden COSE/CBOR + fixed-width frames) shared between gateway and verifier ensure deterministic CBOR/COSE_Sign1/Ed25519/fixed-point handling is bit-stable; vectors are reviewed like security fixtures.

### 5.2 Scope of equivalence

- Equivalence is defined over the **verifier-supported subset/profile** (binary fixed-width command + profiled envelope + bounded replay + fixed-point). Features the MCU core intentionally does not implement (full policy lifecycle, multi-party governance, cloud/mesh ingress, CRDT effects) are excluded from the differential surface and must not be claimed equivalent.
- Unsupported/unknown versions, algorithms, units, or capacities must yield deterministic typed rejects in both implementations for the shared profile.

### 5.3 Execution model (post-merge, design intent)

- Differential harness runs in CI against the gateway guard oracle for the supported profile; `cargo-fuzz`/adversarial cases may be added per the workspace fuzz policy once code exists.
- No verifier implementation or test harness code is added by this RFC; this section specifies the strategy the implementation must satisfy.

## 6. Open Questions

1. **Wire profile freeze:** exact binary fixed-width layout and the deterministic-CBOR/COSE payload schema versioning (and how they map 1:1 to `CommandMessage`/`EnvelopeProfile` fields) — to be specified before implementation.
2. **COSE/crypto crates in `no_std`:** selection and audit of Ed25519 + COSE_Sign1 + deterministic-CBOR stacks that fit ≤64 KiB flash without `std` (and whether `alloc` can be avoided or tightly bounded for signing structures).
3. **Time/freshness on MCU:** how `now_est`/expiry inputs are supplied and trusted at the verifier boundary (caller-injected, monotonic tick, or beacon-derived), and which PV-22 freshness states are in-profile for the MCU core.
4. **Replay keying/capacity semantics:** exact key (issuer,target,epoch,param?) and eviction/overflow behavior at 256 entries to guarantee equivalence with gateway anti-replay without permitting replay.
5. **Envelope/profile distribution:** how the verifier receives and authenticates installed `VerifierEnvelope`/trust roots (provisioning, rotation, rollback) while keeping the core I/O-free.
6. **Multi-target/critical quorum:** whether M-of-N/critical-parameter checks are reduced to a pre-admitted fixed-width artifact or partially enforced on-MCU, and the resulting differential surface.
7. **Measurement methodology:** toolchain/flags (e.g., `opt-level=z`, LTO, panic strategy) and whether budgets are measured per-MCU or on a common Cortex-M reference build.
8. **Fail-safe integration:** how a verifier `Reject` or verifier reset maps to actuator safe-default behavior at the hardware boundary (integration contract, not core logic).

## 7. Implementation gate (PV-13.5)

- This RFC is a **design artifact only**. Per **PV-13.5** and, **no implementation code for any verifier crate may be written until `docs/RFC-verifier.md` is merged to the main branch**.
- Follow-on work (new crate, parsers, crypto wiring, differential harness) must land only after merge and must demonstrate conformance to §§3–5 and the budgets in §4.
