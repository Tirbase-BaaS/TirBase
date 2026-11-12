# TirBase Threat Model

> **[CLAIM-3.4]** — Status: **Planned** (backing integration test not yet written; per PV-2.3 this
> document references a Planned claim and states it explicitly as planned).

---

## 1. Overview and Status

This document is the authoritative threat model for **TirBase** — a hardened edge-node runtime
that makes critical edge nodes safe to command, safe to update, and able to run autonomously.

**Important safety disclaimer (required by PV-20.1):**

> TirBase makes **no Safety Integrity Level (SIL) claims** of any kind. TirBase is **not** a
> Programmable Logic Controller (PLC) and is **not** a replacement for safety-instrumented systems.
> TirBase is a software security and integrity layer that operates above physical control hardware.
> Any deployment requiring SIL certification must provide separately certified safety-instrumented
> systems beneath TirBase.

TirBase targets European critical infrastructure verticals — cold chain, energy edge, water and
heat, logistics nodes, buildings and telecom sites, machine builders, and defense logistics —
running on Linux gateway-class hardware (aarch64 and armv7, 256 MB–1 GB RAM, SQLite). Off-grid
mesh operation (mining, rescue) is a supported mode.

---

## 2. Assets

The following assets require protection. Assets are classified by ledger type where applicable:
**PrimaryLedger** assets cannot be reconstructed from other sources (loss is an unrecoverable
security event); **DerivedLedger** assets can be reconstructed deterministically from the signed
delta log.

### Cryptographic Key Material (by role)

| Role | Key Material | Notes |
|---|---|---|
| CommandIssuer | Ed25519 (default) or P-256 (TPM2) private key; associated Biscuit token | Scoped to specific targets and parameters via token caveats |
| PolicyAuthority | Ed25519 / P-256 private key; includes Enroller sub-delegation key | Signs and tightens/loosens policy bundles; enrolls devices |
| UpdateSigner | Ed25519 / P-256 private key | Signs migration deltas, firmware manifests |
| RevocationManager | Ed25519 / P-256 private key | Accumulates M-of-N revocation signatures; decommissions devices |
| Auditor | Ed25519 / P-256 private key | Read-only; no write or command authority |
| TimeAnchor | Ed25519 / P-256 private key | Signs time beacons only; cannot issue commands or modify policy |
| Root CA keys (offline) | Ed25519 / P-256 key bundle; k-of-n threshold required for rotation | Stored offline; never issued as Biscuit roles; used only for root rotation ceremonies |

### Ledger and State Assets

| Asset | Ledger Class | Criticality |
|---|---|---|
| Applied_Effects_Ledger | PrimaryLedger | Cannot be reconstructed; tracks the lifecycle of every command from `Actuating` → `Complete` / `Failed` / `Unknown`; loss is an unrecoverable security event unless an external backup exists |
| Security event log | PrimaryLedger | Hash-chained, tamper-evident; records every security-relevant accept/reject decision; loss breaks auditability |
| Monotonic counters and anti-rollback counters | PrimaryLedger | Backed by `MonotonicCounterTrait` (SQLite WAL + `synchronous=FULL` at Level 1; TPM2 NV index or eMMC RPMB at Level 2); loss enables replay attacks |
| CRDT delta log | DerivedLedger | Reconstructible; loss requires re-application of the delta log; shared over the mesh |

### Policy and Identity Assets

| Asset | Notes |
|---|---|
| EnvelopeProfile documents | Signed, versioned per-device policy; specifies per-parameter min/max/rate/dwell/cross-parameter constraints and `safe_default` values; must be present for any command to be accepted |
| PolicyBundle | Signed, versioned; strictly monotonic version numbers; anti-rollback counter backed by `MonotonicCounterTrait` |
| Biscuit tokens | Scoped capability tokens carrying role caveats; evaluated by the Guard at every command ingress; maximum TTL 86,400 seconds |
| Device identity | DID (`did:key` Ed25519 default, P-256 for TPM2 deployments) + associated keypair |
| Trust root | Root CA public key set; k-of-n threshold; rotation requires k root key signatures |

### Runtime State Assets

| Asset | Notes |
|---|---|
| TimeRatchet state | Persisted authenticated-time floor; only advances forward; survives reboots; backs the `now_est` authenticated-time estimate |
| AntiReplayWindow state | Per `(issuer, target)` sliding bitmap of width W (default 64); tracks accepted sequence numbers; must survive power loss |
| SingleWriterLease state | Time-bounded exclusive write token per target parameter; lost on crash but reconstructed at next command evaluation |
| WASM migration modules | Signed, sandboxed; validated against `DeterministicWasmProfile` at load time; executed with fuel metering in wasmi |
| Quarantine ledgers | Forensic evidence store for anomalous inbound deltas; typed reason codes; Schema quota: 50,000 entries / 256 MiB; Rate quota: 100,000 entries / 256 MiB |

---

## 3. Actors

### Trusted Actors

**CommandIssuer**
- Trust level: Authenticated via Biscuit token scoped to specific targets and parameters.
- Capabilities: Submits desired-state commands (declarative: `target.parameter = value unit`).
 Commands are bounded by the EnvelopeProfile regardless of credential. Critical parameters
 additionally require M-of-N quorum. Cannot modify policy, sign updates, or read state.

**PolicyAuthority**
- Trust level: Authenticated via Biscuit token; Enroller sub-role requires PolicyAuthority-signed
 delegation token.
- Capabilities: Publishes, tightens, and initiates loosening of policy bundles. Enrolls devices
 (Enroller sub-role). Co-signs LOCKDOWN exits and emergency profile activations. Cannot issue
 commands or sign firmware.

**UpdateSigner**
- Trust level: Authenticated via Biscuit token.
- Capabilities: Signs migration deltas and firmware manifests. Co-signs migration revocations
 jointly with RevocationManager. Cannot issue commands or modify policy.

**RevocationManager**
- Trust level: Authenticated via Biscuit token; M-of-N quorum required for most revocation actions.
- Capabilities: Accumulates M-of-N revocation signatures; decommissions devices; co-signs policy
 loosening and LOCKDOWN exits (counts toward M). Cannot issue commands or sign firmware.

**Auditor**
- Trust level: Authenticated via Biscuit token; read-only.
- Capabilities: Reads state and security events. No write or command authority. No policy or
 revocation capability.

**TimeAnchor**
- Trust level: Authenticated via Biscuit token.
- Capabilities: Submits signed time beacons to update the authenticated-time estimate. Cannot issue
 commands, modify policy, or sign updates. Ratchet resets of more than the configured max forward
 jump require M-of-N TimeAnchor signatures (default M=2).

**Root Keys (offline ceremony keys)**
- Trust level: Highest — used only for root CA rotation ceremonies; stored offline.
- Capabilities: Threshold k-of-n root key signatures for root CA rotation. Never issued as Biscuit
 roles. Not used in normal operations.

### Adversarial Actors

**External attacker**
- Trust level: None — unauthenticated.
- Capabilities: May control the network, inject, replay, or drop packets, and forge messages lacking
 a valid signature. Cannot satisfy Biscuit token verification, EnvelopeProfile signature check, or
 the Noise XX peer authentication handshake. Constrained at the per-source token bucket on the
 cloud API before any cryptographic processing.

**Compromised cloud/vendor**
- Trust level: Holds one valid role credential; no more.
- Capabilities: May issue commands within the EnvelopeProfile bounds of their single role. Cannot
 relax policy bounds, revoke DIDs, sign firmware, or act on behalf of any other role. EnvelopeProfile
 bounds enforcement applies regardless of credential validity; M-of-N quorum required for critical
 parameters even with a valid credential.

**Compromised mesh peer**
- Trust level: Has a legitimate node identity that may have been taken over.
- Capabilities: Can send signed deltas and attempt CRDT poisoning. Replay of prior valid commands
 is blocked by the anti-replay window. Revocation propagates to all peers within 60 seconds.
 Quarantine ledger captures anomalous deltas with typed reason codes.

**Malicious driver**
- Trust level: Runs as a child process of the gateway; isolated.
- Capabilities: Receives only encoded frames over an inherited socketpair (`AF_UNIX SOCK_SEQPACKET`).
 No device fd crosses the boundary. Constrained by `SO_PEERCRED`, seccomp-BPF, `no-new-privs`, and
 Landlock. Cannot communicate outside its sandbox; external socket connections are blocked by the
 seccomp filter.

**Insider with partial key access**
- Trust level: Holds some but not all M keys of a threshold quorum.
- Capabilities: Cannot complete any M-of-N operation alone. Cannot loosen policy, exit LOCKDOWN,
 revoke a DID, or activate an emergency profile without assembling the full quorum. The 1-of-1
 residual risk is documented in Section 7.

---

## 4. Trust Boundaries

### Boundary 1: Ingress boundary (guard crate)

All commands entering from mesh replication, the cloud API, or the local admin socket converge on
a single `CommandGuard::evaluate` function before any driver operation. No compile-time path from
command ingress to a driver bypasses the Guard (enforced by a `trybuild` compile-fail test covering
all three ingress paths).

At this boundary:
- `FixedPointValue` conversion (IEEE 754 floats rejected; NaN/±∞ rejected with a typed error).
- Biscuit token verification against the Root CA registry.
- Role extraction from token caveats (never from the command's own role field).
- EnvelopeProfile presence check (absent profile → all commands rejected).
- EnvelopeProfile bounds check (min/max, rate-of-change, drift window, dwell/min-off-time,
 cross-parameter linear constraints).
- Unit canonicalization check (unit mismatch → rejection; no unit conversion).
- Anti-replay window check per `(issuer, target)`.
- Idempotency key deduplication (default 24-hour retention).
- Authenticated-time expiry (`now_est > command.expiry_time`).
- Per-issuer token bucket (cloud API: enforced before crypto; local/mesh: enforced after auth).
- SecurityEvent emitted on every accept or reject decision.

### Boundary 2: Driver process boundary

The guard process owns all device I/O. The driver child process receives only encoded frames over
an inherited socketpair; no device file descriptor crosses the boundary. Process identity is
verified via `SO_PEERCRED`. The driver sandbox is hardened with seccomp-BPF, `no-new-privs`, and
Landlock. Any connection attempt to an external socket from within the driver sandbox is blocked by
the seccomp filter.

### Boundary 3: Local admin socket

The admin socket uses `SO_PEERCRED` for authentication of local connections. Remote admin
connections require mutual TLS (mTLS) client certificate authentication.

### Boundary 4: Mesh transport

Noise XX handshake (upgrade path to Noise IK identified per RD-13). Peer identity is authenticated
before any message processing. Delta signatures are verified by the RevocationSubsystem before
being applied to the CRDT. Revocation status is re-checked at merge time; a revocation delta
received mid-flight causes pending transform results to be discarded.

### Boundary 5: Cloud API

TLS client certificate (mTLS). A per-source token bucket is applied before any cryptographic
processing to limit DoS exposure. Cloud-sync paths (send and receive) are wired as production
callers in the gateway init path.

### Boundary 6: WASM sandbox boundary

Migration transforms execute inside wasmi with fuel metering (configurable per-transform fuel
budget). The sandbox has no access to the host clock, no host randomness, and no IEEE 754 floats.
Each module is validated against `DeterministicWasmProfile` (no non-canonical NaN, no SIMD, no
threads, no host calls) using `wasmparser` at load time. The `ExecutionProfileVersion` hash is
checked before executing any module; a hash mismatch is rejected with `EngineVersionMismatch`.
Postconditions are verified after execution; a failed postcondition discards the result without
committing the new schema hash.

### Boundary 7: SQLite persistence boundary

The Applied_Effects_Ledger and all PrimaryLedger tables use WAL mode with `synchronous=FULL`.
The first durable write for each command is the `Actuating` record; dispatch occurs only after the
group-commit fsync completes. SQLCipher encryption is available behind a feature flag for
deployments requiring encryption at rest.

---

## 5. Five Failure Modes

TirBase is explicitly designed to handle five failure modes as defined in the requirements
introduction. This section describes the mitigations for each.

### Failure Mode 1: Malicious command through a legitimate channel

*Threat: A vendor key is stolen, or a cloud/SCADA system is compromised. The attacker holds a
valid CommandIssuer (or even PolicyAuthority) credential and issues commands.*

**Mitigations:**
- **EnvelopeProfile bounds enforcement** — all commands must fall within the signed per-parameter
 `min`/`max`/rate/dwell limits regardless of credential validity. A compromised credential cannot
 relax these limits; only a policy loosening operation (requiring M-of-N) can widen them.
- **M-of-N quorum for critical parameters** — `EnvelopeProfile` parameters marked `critical: true`
 require M-of-N signatures (M ≥ 2 by default) before actuation.
- **Per-issuer rate limits and per-device write quotas** — enforced at the Guard boundary;
 commands per 60-second window.
- **Anti-replay window** — per `(issuer, target)` sliding bitmap; sequence number outside
 `[highest_seen − W, highest_seen + G]` is rejected immediately.
- **Authenticated-time expiry** — commands carry an absolute expiry evaluated against `now_est`
 (TimeRatchet-backed); withheld-delivery attacks cannot extend command validity.
- **SecurityEvent** emitted for every reject decision, including the rejection reason and the
 issuer DID, enabling forensic review.

### Failure Mode 2: Bad update or config push

*Threat: A malicious actor with UpdateSigner or PolicyAuthority credentials pushes a harmful
firmware update, migration module, or policy bundle.*

**Mitigations:**
- **UpdateSigner credential** required for any firmware manifest or migration delta signature;
 migration revocation requires both UpdateSigner and RevocationManager co-signatures.
- **WASM sandbox** with fuel metering, postcondition verification, and no host-clock or
 host-randomness access; `DeterministicWasmProfile` validation at load time.
- **Expand-then-contract migration rule** — schema migrations must first add new fields, then
 remove old ones in a subsequent migration; no single-step destructive schema changes.
- **Policy bundle anti-rollback counter** — backed by `MonotonicCounterTrait`; any bundle with a
 version ≤ the last accepted version is rejected.
- **M-of-N for policy loosening** — any bundle that widens any parameter's range requires M-of-N
 approval (M ≥ 2); time-lock and cancel-window durations come from the currently active policy,
 not the incoming bundle.
- **Tightening floor** — a tightening bundle that makes limits more restrictive than the
 `tightening_floor` in the EnvelopeProfile is rejected, preventing a single PolicyAuthority from
 locking limits to an unusable state.

### Failure Mode 3: Supplier or central-system outage

*Threat: The cloud/SCADA vendor goes offline, a network partition isolates the node, or the
supplier's infrastructure becomes unavailable.*

**Mitigations:**
- **DEGRADED mode** — when communications are lost for longer than `degraded_timeout_secs`
 (configurable, default 60 seconds), the node autonomously maintains the last-safe local loop for
 each target, or reverts to the per-target `safe_default` value as configured in the
 EnvelopeProfile.
- **The system never fails open** — on comms loss the node holds the last safe state; it does not
 widen limits, accept new commands from unauthenticated sources, or proceed without an installed
 EnvelopeProfile.
- **CRDT eventual consistency** — on reconnect, the CRDT engine reconciles divergent state
 deterministically; the mesh pending-queue holds out-of-order deltas for up to 24 hours (
 configurable) to handle store-and-forward mesh scenarios.
- **TimeRatchet boot-id awareness** — after a reboot with no beacon, `now_est` uses the ratchet
 floor; the node enters `UNVERIFIED` freshness mode until a beacon is received, without losing
 the previously established time floor.

### Failure Mode 4: Cascading control failure

*Threat: A rapid sequence of individually valid commands causes actuators to exceed safe
operating bounds, or cross-parameter interactions produce a dangerous combined state.*

**Mitigations:**
- **EnvelopeProfile rate-of-change limits** — maximum change per second per parameter; the Guard
 evaluates the cumulative drift window against the applied-state history.
- **Cumulative drift window limits** — the Guard tracks the total change within the
 EnvelopeProfile-defined window duration; exceeding the bound produces a `DriftExceeded`
 rejection.
- **Dwell and min-off-time interlocks** — configurable per parameter in the EnvelopeProfile;
 enforced by the Guard before any actuation.
- **Cross-parameter linear inequality constraints** — conjunctions of linear inequalities over
 parameter values; expressed in a non-Turing-complete constraint language in the EnvelopeProfile.
- **Per-device write quotas** — commands per 60-second window enforced by the Guard.
- **M-of-N quorum for critical parameters** — protects the highest-risk actuators from a single
 compromised or malfunctioning issuer.
- **`safe_default` value** — applied on LOCKDOWN, comms loss, or Guard process exit; the
 supervisor holds the `safe_default` for each target and applies it before restarting the Guard.

### Failure Mode 5: Comms denial or partition

*Threat: An attacker or infrastructure failure denies network connectivity, preventing commands
and policy updates from reaching the node.*

**Mitigations:**
- **DEGRADED mode** — autonomous operation on last-safe state; see Failure Mode 3.
- **CRDT-based state** — eventual consistency after reconnect; no central coordinator required.
- **Pending-queue for out-of-order deltas** — configurable 24-hour age-out for store-and-forward
 mesh scenarios; global cap of 64 MiB / 8 MiB per-peer before `PENDING_QUEUE_OVERFLOW`
 quarantine.
- **TimeRatchet boot-id-aware design** — reboots use the persisted ratchet floor; the node does
 not lose its time floor on power-cycle, even during a prolonged partition.
- **UNVERIFIED freshness mode** — on prolonged beacon denial, non-critical commands are accepted
 with `UNVERIFIED` flag per the `unverified_policy` profile setting; critical commands require a
 device-issued challenge nonce. The residual risk of indefinite UNVERIFIED mode is documented in
 Section 7.

---

## 6. Out-of-Scope Exclusions

Required by PV-20.2. Each item below is a **named discrete exclusion** from TirBase's threat model.
TirBase provides no mitigation for these threats; operators must address them through complementary
controls.

1. **OS root compromise** — A node whose operating system is already compromised at the root level
 is outside scope. All application-layer controls (Biscuit verification, EnvelopeProfile
 enforcement, seccomp sandbox) execute within a process that the OS kernel can intercept or
 modify. TirBase cannot protect what the OS can override.

2. **Physical attacks on hardware** — Physical tampering, side-channel attacks (power analysis,
 timing), cold-boot attacks, and RF extraction of key material are outside scope. TirBase assumes
 the hardware and its environment are physically secured by the deploying organization.

3. **Bypass paths directly to legacy controllers** — If a legacy controller or actuator has a
 communication path that bypasses TirBase entirely (e.g., a direct serial connection, a legacy
 BMS protocol endpoint), TirBase cannot protect it. TirBase only enforces at the command guard
 boundary over paths it controls.

4. **Insiders holding all M keys simultaneously** — An insider who simultaneously holds all M keys
 of a threshold quorum satisfies the quorum by definition. No technical control can prevent this;
 it is a trust and organizational governance matter. The deploying organization must enforce
 key-custody separation as a procedural control. The 1-of-1 residual risk is separately
 documented in Section 7.

5. **Bugs or vulnerabilities within TirBase itself** — TirBase is not a formally verified system.
 The codebase is tested with property-based tests, integration tests, and adversary scenarios,
 and an external cryptographic review and penetration test are scheduled before public security
 claims are made (PV-29). However, the presence of unknown bugs or zero-day vulnerabilities
 within TirBase code is outside the scope of this threat model.

6. **Break-glass emergency override** — Break-glass is permanently excluded from TirBase per
 design decision RD-4. Any operator requiring emergency override must use pre-signed emergency
 profiles activated by M-of-N PolicyAuthority + RevocationManager (narrow scope, bounded
 duration; activating an emergency profile replaces the active EnvelopeProfile so INV-1 continues
 to hold). Any reconsideration of this exclusion requires explicit owner approval and a documented
 threat model update (see Section 8).

7. **Safety Integrity Level (SIL) claims** — TirBase is not a safety-instrumented system and makes
 no SIL claims of any kind. See Section 1.

8. **PLC replacement** — TirBase is not a Programmable Logic Controller and does not replace
 safety-instrumented logic. See Section 1.

9. **Network monitoring** — TirBase does not inspect or monitor network traffic. It enforces
 security only at the command guard boundary over the communication paths it owns. Out-of-band
 network traffic, lateral movement within the local network, and infrastructure-level attacks on
 the network stack are outside scope.

---

## 7. Residual Risks

The following known residual risks are documented with their mitigations and responsible owner.

### RR-1: 1-of-1 revocation quorum

**Risk:** If M=1 is configured for a small deployment, a single RevocationManager credential
compromise grants full revocation authority over all devices without requiring any co-signer.

**Mitigation:** A structured startup diagnostic warning is emitted through the diagnostic system
(not a plain log line) whenever a node starts with a 1-of-1 revocation quorum configured. The
operator must explicitly acknowledge this configuration. The same warning applies when a single
root CA key (k=1) is configured.

**Owner:** Deploying organization (configuration management and key custody policy).

---

### RR-2: Software monotonic counter (Level 1)

**Risk:** The Level 1 `MonotonicCounterTrait` implementation uses SQLite WAL + `synchronous=FULL`.
This detects mistakes and non-physical attackers but does not protect against a physical attacker
who replaces or reflashes the storage medium.

**Mitigation:** Level 2 (TPM2 NV index or eMMC RPMB) is required for any anti-rollback claim in
adversarially physical environments. The gateway reports its counter assurance level at boot. The
design decision RD-2 documents the two assurance levels and specifies that a TPM2 add-on is
required on the reference hardware (RPi 4 has no built-in TPM/RPMB).

**Owner:** Deploying organization (hardware selection and procurement).

---

### RR-3: UNVERIFIED freshness mode

**Risk:** When no time beacon has been received (first boot, or no TimeAnchor connected for longer
than `staleness_window_secs`), all commands are tagged as `UNVERIFIED`. An attacker who can
prevent all time beacon delivery forces non-critical commands into UNVERIFIED mode indefinitely.

**Mitigation:** The `unverified_policy` flag per parameter in the EnvelopeProfile controls
behavior in UNVERIFIED mode: default is `accept_with_flag` for non-critical parameters and
`challenge` (device-issued single-use nonce) for critical parameters. The UNVERIFIED state is
surfaced in SecurityEvent records.

**Owner:** EnvelopeProfile author (per-deployment policy configuration).

---

### RR-4: Noise XX transport (not Noise IK)

**Risk:** The current mesh transport uses Noise XX. Peer identity is authenticated during and after
the handshake, but it is not pinned before the handshake begins. A future upgrade to Noise IK would
pin the peer's static key before the handshake, eliminating a small window for identity confusion.

**Mitigation:** The upgrade path to Noise IK is identified per design decision RD-13 and is
tracked as a v1.x hardening item.

**Owner:** TirBase development team.

---

### RR-5: WASM migration engine version lock

**Risk:** Migration modules carry a signed `ExecutionProfileVersion` including a fuel-cost table
hash. If the wasmi version changes, all previously signed modules must be re-signed and re-tested
before deployment. A version bump not caught before a deployment window could block migrations.

**Mitigation:** CI enforces that the `ExecutionProfileVersion.fuel_cost_table_hash` in every
signed module matches the version embedded in the running wasmi build. A hash mismatch is rejected
as `EngineVersionMismatch` before execution begins.

**Owner:** TirBase development team (release management process).

---

### RR-6: Quarantine ledger per-sender quota

**Risk:** A sustained attacker generating anomalous deltas at or below the per-sender quota
(1,000 entries) can occupy a portion of the quarantine ledger indefinitely.

**Mitigation:** Global size caps (Schema ledger: 50,000 entries / 256 MiB; Rate ledger: 100,000
entries / 256 MiB) with FIFO eviction per-sender. Future work: time-bounded eviction of old
quarantine entries.

**Owner:** TirBase development team.

---

### RR-7: Crash-loop LOCKDOWN from buggy configuration

**Risk:** If the gateway process crashes N times within a 5-minute window (default N=3), the
supervisor escalates to security LOCKDOWN. A buggy EnvelopeProfile or malformed configuration
could trigger this unintentionally, requiring M-of-N to exit.

**Mitigation:** Configuration is validated at startup before the crash-loop counter begins.
LOCKDOWN exit requires M-of-N authorization from at least two distinct roles (e.g., PolicyAuthority
+ RevocationManager).

**Owner:** Deploying organization (configuration management and testing before deployment).

---

### RR-8: External dependency security

**Risk:** TirBase's security properties for Biscuit token handling, libp2p gossipsub Noise
transport, wasmi WASM sandbox, and SQLite / SQLCipher are inherited from upstream crates. A
vulnerability in any of these components directly affects TirBase's security posture.

**Mitigation:** `cargo-audit` runs as a blocking CI gate on every push/PR; pre-existing advisories
are individually acknowledged in `audit.toml`. An external cryptographic review and penetration
test (PV-29) are scheduled before public security claims are made.

**Owner:** TirBase development team (dependency hygiene and security review schedule).

---

## 8. Owner-Decision List

Required by PV-20.3. The following items require **explicit documented owner approval** before any
change is made. Changing any item on this list without documented approval constitutes a policy
violation.

1. **Software license terms** — Changes to the `LICENSE` file or SPDX identifiers in any source
 file require CODEOWNERS approval. On every pull request that touches `LICENSE` or any SPDX
 identifier, CI computes the SHA-256 hash of `LICENSE` and compares it against the known-good
 hash stored in `CODEOWNERS`; the build fails and blocks merge if the hashes differ (PV-2.8).

2. **Compact capability format for the Phase 11 verifier crate** — Working assumption per RD-5:
 COSE_Sign1 over deterministic CBOR, Ed25519 only, fixed-point integers, compact role grants.
 No Datalog, no floats. Final format choice is deferred to `docs/RFC-verifier.md`. Any change to
 this working assumption requires owner approval.

3. **TUF adoption** — The TUF design has been adopted per RD-6 for migration, policy, and
 firmware-manifest distribution. The specific crate choice is deferred to a spike requiring an
 injected `TimeSource` and gossip transport. PV-11.6 is **BLOCKED** pending `docs/RFC-tuf.md`.
 Any change to the TUF adoption decision requires owner approval.

4. **Product naming** — Any change to the product name "TirBase" requires owner approval.

5. **Compliance certification wording** — Compliance documents under `docs/compliance/` are
 evidence aids only. They **SHALL NOT** claim certification with any standard (ISO, IEC, NIS2,
 CRA, etc.) without legal counsel review. Any addition of certification language requires
 documented owner approval (PV-14.6).

6. **Protocol driver selection beyond the three reference drivers** — The three reference drivers
 (Modbus, MQTT bridge, cold-room sim) are approved. Adding a fourth or later protocol driver
 requires owner approval with a documented security review of the driver's trust boundary and
 attack surface.

7. **Break-glass emergency override** — Break-glass is permanently excluded from TirBase per RD-4.
 Any reconsideration of this exclusion requires owner approval with a documented threat model
 update, a revised risk analysis, and a new M-of-N activation design (see Section 6, exclusion 6).

8. **Loosening M floor** — M ≥ 2 is the default floor for policy loosening, LOCKDOWN exits, and
 all M-of-N quorum operations except where explicitly noted (1-of-1 is permitted with a startup
 diagnostic warning per RR-1). Lowering M below 2 for any quorum in any deployment requires
 documented owner approval (RD-9).

9. **Formal verification scope** — The scope of TLA+/Quint model coverage and Kani proof coverage
 (PV-26) requires owner approval to reduce. Expanding coverage does not require approval.

---

## 9. Related Documents

| Document | Status | Notes |
|---|---|---|
| `CLAIMS.md` | Present | Machine-readable claim registry; `CLAIM-3.4` in this document is Planned |
| `docs/RFC-workspace.md` | Present | Workspace crate layout RFC — prerequisite for workspace restructuring |
| `docs/adversary-scenarios.md` | To be created | S1–S35 attack scenarios with attack vector, expected system response, PV reference, and test ID (CLAIM-3.7) |
| `docs/system-invariants.md` | To be created | INV-1..INV-16 invariant catalog with simulation check description, `debug_assert!` location, and test ID (CLAIM-3.8) |
| `docs/security-event-catalog.md` | To be created | Every `SecurityEvent` category and reason code; CI fails if any emitted event is absent from the catalog (CLAIM-3.9) |
| `docs/unit-registry.md` | To be created | Unit ID registry (degC, Pa, rpm, bar, kW, percent, boolean, kPa, m3h, V, A, Hz) (CLAIM-3.10) |
| `docs/EFFECT_SEMANTICS.md` | To be created | At-least-once delivery with idempotent declarative effects; what is and is not guaranteed |
| `SECURITY.md` | To be created | Coordinated disclosure policy; 5-day ack SLA; 90-day disclosure window; RFC 9116 `security.txt` (CLAIM-3.5) |
| `docs/RFC-tuf.md` | To be created — **BLOCKED** | TUF adoption evaluation; PV-11.6 blocked until this RFC is committed (RD-6) |
| `docs/RFC-verifier.md` | To be created | No-`std` verifier crate RFC; Phase 11 capability format finalization (RD-5) |
| `docs/compliance/` | To be created | CRA Annex I and IEC 62443-4-1 evidence (evidence only; no certification claims without legal review) |
| `docs/audits/gate-g1.md` | Present | Phase 0 gate audit with VERIFIED-BY-TRACE rows for CLAIM-G1.1..G1.10 |

---

*Document version: 1.0 — created as part of Phase 0 (Truth, Traceability, and Hygiene).*
*This document must be updated whenever a new actor, asset, trust boundary, failure mode,
out-of-scope exclusion, residual risk, or owner decision is added to the system.*
