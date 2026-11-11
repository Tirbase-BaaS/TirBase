# Authenticated Time — External Source Evaluation (PV-22, CLAIM-53.4)

**Status:** Design note (evaluation). No external time backend is wired in production by this note.  
**Date:** 2026-11-11  
**Scope:** Evaluate NTS, Roughtime, and Galileo OSNMA as external/auxiliary sources for the TirBase authenticated-time model (PV-22, PV-28). The gateway's v1 trust root for command expiry and freshness remains the signed `TimeBeacon` / `TimeRatchet` path (`tirbase-guard::time`, `tirbase-gateway::time_beacon`, `TimeAnchorService`).

## Context and requirements (PV-22, PV-28)

- Command/token expiry uses **authenticated time** (`now_est`), never the unauthenticated wall clock. `now_est = last_beacon_time + (mono_now − mono_at_beacon)` floored at `persisted_floor`; `mono_now` is `CLOCK_BOOTTIME` (suspend-aware, monotonic).
- The ratchet is **monotone**: `persisted_floor` never decreases (except an explicit M-of-N operator time-reset path). A beacon older than the floor is rejected as replay; a forward jump larger than `max_forward_jump_secs` requires an M-of-N `TimeAnchor` quorum.
- After reboot (boot-id change), freshness is `Unverified` and `now_est` is floored at `persisted_floor` until a new authenticated beacon is accepted; critical parameters require a challenge nonce while unverified.
- Beacons are signed (`SignedOperation<TimeBeacon>` / COSE_Sign1 beacon envelope in `TimeAnchorService`) and admitted through `TimeRatchet::advance()`; peer selection uses the most recent valid beacon satisfying the max-forward-jump constraint (PV-28.3).

Any external source must therefore (a) provide **authenticated** time or a verifiable proof, (b) be mapped into ratchet admission with the same monotonicity/quorum/max-jump rules, and (c) fail closed (loss or spoofing of the external source must not move `now_est` backwards or past policy without quorum).

## NTS — Network Time Security (RFC 8915)

**What it is.** NTS adds authentication and key establishment to NTP using TLS (NTS-KE, typically TCP/443) and AEAD-protected NTP extension fields. It protects against on-path packet modification and spoofing of NTP responses when a trusted NTS server/cookie chain is used.

**Strengths**
- Standards-track (RFC 8915), deployable with existing NTP ecosystems (`chrony`, `ntpd-rs`/`nts-pool` participants); uses well-understood TLS + AEAD primitives.
- Good for **wall-clock accuracy** in connected environments; can supply a high-quality candidate UTC sample to a TimeAnchor.
- No special hardware beyond network reachability and TLS trust configuration.

**Limitations / risks for TirBase**
- **Not offline/partition-tolerant:** requires reachability to an NTS-KE/NTP server; partitions (failure mode 5) break updates. Cannot be the sole v1 source for edge gateways that must operate disconnected.
- **Trust anchor is the server/operator PKI**, not a TirBase role credential; mapping NTS time into `TimeRatchet` would require a trusted local NTS client + a gateway-side TimeAnchor component that signs/beacons the vetted sample (preserving domain separation and auditability).
- **Clock-step/attack surface:** NTS authenticates packets but the local clock disciplining stack is complex; must not feed raw unauthenticated `CLOCK_REALTIME` into guard decisions (PV-22.1). Only an accepted signed beacon derived from an attested NTS reading may influence `now_est`.
- Cookie/key rotation and server availability add operational dependencies.

**Fit.** **Recommended as an optional upstream source for a TimeAnchor service** in connected deployments (TimeAnchor verifies via NTS, then emits signed TirBase beacons). **Not suitable as the only time source** for partitioned/off-grid operation.

## Roughtime (IETF draft / ecosystem implementations)

**What it is.** Roughtime is a coarse, authenticated time protocol: clients query multiple servers and receive signed replies (typically with a Merkle-tree/chain structure proving a server endorsed a timestamp within a radius). It is designed for secure coarse time (certificate validity bootstrap) rather than high-precision synchronization.

**Strengths**
- **Multi-server/cross-checking model** aligns with quorum thinking: a client can require agreement across diverse servers to bound lying servers, reducing single-server trust.
- Responses are signed; provides evidence of server attestation at coarse granularity (seconds-scale radius), useful to detect gross skew/poisoning.
- Can work where full NTS/NTP precision is unnecessary but authenticity matters.

**Limitations / risks for TirBase**
- **Coarse accuracy/radius:** not a replacement for monotonic/precision timing; acceptable for ratchet-floor bootstrap/freshness bounds but not for tight expiry semantics without slack accounting.
- **Specification/ecosystem maturity:** historically an Internet-Draft with evolving wire details and a smaller deployment footprint than NTS; library availability and long-term interoperability need vetting before production reliance.
- **Connectivity required** to reach servers; same partition constraint as NTS.
- Trust is in server keys and quorum policy; must be translated into TirBase `TimeAnchor` signatures/quorum before affecting `now_est`.

**Fit.** **Viable as an additional corroborating upstream for TimeAnchor** (coarse authenticated bound / multi-source sanity check). **Not a primary high-precision source** and **not sufficient alone** for offline/partitioned edges. Any adoption should pin a specific draft/profile, audited implementation, and a conservative radius-to-ratchet mapping.

## Galileo OSNMA — Open Service Navigation Message Authentication

**What it is.** Galileo OSNMA authenticates Galileo Open Service navigation messages (TESLA-timed keys/MACs broadcast in-band from satellites). A receiver with GNSS visibility can verify that navigation/timing data originated from the Galileo system (per OSNMA trust/PKI).

**Strengths**
- **Broadcast, infrastructure-light at the edge:** does not require IP connectivity to a time server; useful for remote/off-grid sites with sky view (complements mesh/partitioned operation).
- Provides **cryptographic authentication of GNSS timing signals**, mitigating simple GNSS spoofing that naively trusted receivers would accept.
- Attractive for European critical-infrastructure deployments where Galileo coverage and sovereign signal trust are relevant.

**Limitations / risks for TirBase**
- **Requires GNSS hardware/antenna and sky visibility;** unavailable indoors/underground/jammed environments. Availability is environmental, not guaranteed.
- **Receiver/implementation complexity:** OSNMA verification, TESLA keychain handling, time-to-first-authenticated-fix, and receiver firmware trust are non-trivial; a buggy receiver is a risk surface.
- **Threat model bounds:** OSNMA authenticates Galileo data but does not eliminate all RF attacks (e.g. jamming/denial, some replay/relay scenarios depending on receiver/holding-time policies). Must be treated as one authenticated input, still subject to ratchet monotonicity and max-jump/quorum rules.
- **Latency/warm-up:** authenticated fix and key availability can delay initial beaconing after boot (interacts with `Unverified` freshness).

**Fit.** **Strong candidate as an offline-capable authenticated time hint for TimeAnchor** on GNSS-equipped gateways (TimeAnchor verifies OSNMA, then emits signed TirBase beacons). **Must not bypass ratchet/quorum/max-jump** and should be combined with monotonic persistence and, where possible, peer/secondary corroboration.

## Recommended integration posture

1. **Keep `TimeRatchet` + signed TirBase beacons as the enforcement boundary.** External sources never directly set `now_est`; they feed a TimeAnchor (or equivalent trusted signer path) that produces signed `TimeBeacon`/COSE_Sign1 beacons admitted via `TimeRatchet::advance()`.
2. **Preserve invariants:** monotone `persisted_floor`, reboot → `Unverified`, max-forward-jump with M-of-N for large jumps, per-anchor sequence/validity checks, and domain-separated verification.
3. **Defense in depth:** prefer multi-source corroboration (e.g. OSNMA + local peer beacons, or NTS-backed anchor + peer quorum) for large adjustments; treat single-source jumps conservatively.
4. **Deployment profiles:** NTS for connected/cloud-managed anchors; OSNMA for partition-tolerant/GNSS-equipped edges; Roughtime only as optional coarse corroboration if/when a pinned, audited profile is adopted.
5. **Out of scope for this change:** concrete client implementations, key distribution for external roots, and automatic source failover policy beyond existing ratchet/quorum semantics — these require separate implementation tasks and security review.

## References

- RFC 8915, *Network Time Security for the Network Time Protocol*
- Roughtime protocol drafts/implementations (ecosystem; pin a specific draft before adoption)
- European Union Agency for the Space Programme (EUSPA) / European Commission — *Galileo OSNMA* service and receiver guidelines
- PV-22 (authenticated time/ratchet/freshness), PV-28 (TimeAnchorService), RD-5 (COSE/CBOR beacon signing)
