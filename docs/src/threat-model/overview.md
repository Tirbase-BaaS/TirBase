# Threat Model

The authoritative threat model is maintained in
[`docs/THREAT_MODEL.md`](../../THREAT_MODEL.md) (assets, actors, trust
boundaries, five failure modes, non-goals, residual risks, and out-of-scope
exclusions).

## Five failure modes

1. Malicious command through a legitimate channel
2. Bad update or config push
3. Supplier or central-system outage
4. Cascading control failure
5. Comms denial or partition

## Key boundaries

- **Guard boundary:** only guard-admitted commands produce actuation.
- **Role separation:** credentials are role-scoped (CommandIssuer, PolicyAuthority,
 UpdateSigner, RevocationManager, Auditor, TimeAnchor) and cross-role use is rejected.
- **Driver isolation:** drivers are codec/sandbox processes; device I/O is guard-owned.
- **Time/authentication:** expiry and freshness use authenticated-time estimates and
 monotonic ratchets, not trusted wall clock.

See also the adversary catalog in
[`docs/adversary-scenarios.md`](../../adversary-scenarios.md).
