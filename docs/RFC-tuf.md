# RFC: TUF adoption for migration/firmware/config update distribution (Task 30.7/30.10, PV-8.8, PV-11.6, RD-6)

Status: **ACCEPTED — RD-6 is recorded in `docs/THREAT_MODEL.md`**: adopt TUF metadata semantics over TriBase's existing signed transport; the crate choice stays deferred to the task 30.10 spike. Task 30.9 is implemented against a signed manifest whose role keys come from deployment configuration.

## Summary

This RFC evaluates adopting [The Update Framework (TUF)](https://theupdateframework.io/) for distributing signed migration transforms, gateway firmware manifests, and signed config rollback artifacts over the mesh/gossip transport. TriBase currently relies on CA-signed migration transforms (`MigrationDelta.ca_signature` + SHA-256), manager/M-of-N revocation deltas, and deterministic WASM execution profiles (Tasks 18/29/30). TUF addresses freeze/mix-and-match/rollback/replay attacks and key compromise recovery better than a single-signature manifest model.

## Threat model (PV-8.8)

| Threat | Current mitigation | TUF role |
|---|---|---|
| Malicious/compromised CA signs bad migration | CA verify + shadow/postconditions (30.1/30.2), revocation (18.5–18.7), deterministic profile (29) | Root/targets/snapshot/timestamp roles separate trust; threshold root; key rotation/revocation |
| Replay of old vulnerable migration/firmware | Migration revocation registry, schema version path, monotonic policy | Timestamp/snapshot freshness; explicit expiry; `TimeSource` required |
| Mix-and-match / freeze | Version path + per-device schema state | Consistent snapshot + targets metadata |
| Rollback to last-good vs vulnerable | 30.9 requires signed rollback path (BLOCKED) | Targets metadata versioning + rollback protection; operator-signed rollback remains PolicyAuthority-gated |
| Key compromise | CA key rotation is deployment-specific | TUF root role rotation, delegated targets, threshold signatures |
| Transport adversary (gossip/mesh) | Signatures verified before trust; rate limits/blacklist | Metadata is signed; transport is untrusted (matches gossip) |

Assumptions: devices may be offline/partitioned (RD-1/mesh); monotonic/wall time is policy-constrained (`TimeSource`/`MonotonicCounterTrait`); updates must not execute before signature+profile+shadow+postcondition gates.

## Comparative evaluation

### Custom solution (current direction)

- Pros: already integrated with CA signature model, migration revocation, wasmi deterministic profile, mesh gossip; minimal new deps; can encode TriBase-specific postconditions/fleet preconditions.
- Cons: CA is a high-value single trust anchor unless manually split; no standard metadata freshness/consistency model; rollback/freeze/mix-and-match protections must be re-specified; harder to audit than a standard.

### TUF (`tough` / `rust-tuf`)

- Pros: standard roles (root, targets, snapshot, timestamp), threshold/rotation semantics, rollback/freeze/mix-and-match resistance, ecosystem scrutiny.
- Cons: server/repository model assumptions; timestamp freshness needs trustworthy time (conflicts with adversarial clocks unless `TimeSource`/monotonic policy is injected); metadata distribution over gossip is nonstandard; dependency footprint in constrained gateway/wasm targets.
- **Recommendation (draft, pending RD-6):** adopt TUF metadata *semantics* for firmware/config manifests and optionally for migration catalogs; implement transport adapter over existing signed delta/gossip channels; keep TriBase CA+shadow+postcondition gates as defense-in-depth. Defer full repository service until RD-6 chooses deployment authority.

## Task 30.10 spike findings

- **Crates considered:** `tough` (AWS, async-friendly, pluggable transport/storage traits) and `rust-tuf` (reference implementation; heavier sync/file assumptions historically). Spike target: evaluate `tough` first for trait injection.
- **`TimeSource` injection:** TUF timestamp/snapshot expiry checks require current time. Spike requirement: no direct `std::time::{SystemTime,Instant}` in verification path; time must come from an injected clock compatible with TriBase `TimeSource`/monotonic policy. *Finding:* feasible only if the chosen crate exposes a clock abstraction or verification is wrapped with an application-supplied “trusted now” derived from `TimeSource`/ratchet policy; upstream crate audit required before production. **Action:** record crate API evidence in follow-up PR when RD-6 unblocks; do not add `tough`/`rust-tuf` dependency until that evidence exists.
- **Gossip transport:** repository fetches (root/targets/snapshot/timestamp) are HTTP/file-oriented upstream. Spike requirement: metadata can be obtained from mesh/gossip cache/local store. *Finding:* feasible with a custom repository/transport adapter that serves signed metadata blobs by TUF path/name; consistency must preserve TUF snapshot rules.
- **Compilation constraint:** any adopted crate must compile in CI targets used by gateway/core and must not introduce ambient wall-clock reads in critical verification paths. *Finding (draft):* not yet fully proven in-tree; blocked on RD-6 scope and dependency decision.

## Decision / blockers

- **RD-6 owner decision required:** adopt TUF fully, adopt metadata-only with custom transport, or defer with documented compensating controls.
- **Task 30.9 is implemented.** `/admin/self-update` verifies the UpdateSigner-signed manifest, applies the new config atomically (restoring the previous bytes on a failed write), and accepts rollback only with a PolicyAuthority signature. See `tirbase-gateway/tests/self_update_admin.rs`.
- Next step after RD-6: prototype `tough` repository adapter + injected time source in an isolated spike crate, then wire gateway `self_update` (30.9) to signed firmware manifests and PolicyAuthority-signed config rollback.

