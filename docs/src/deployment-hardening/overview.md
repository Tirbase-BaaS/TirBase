# Deployment Hardening

## Gateway runtime

- Run as a dedicated service account under systemd with hardened unit settings
  (e.g. `NoNewPrivileges`, restricted address families/syscalls, watchdog, memory protections).
- Keep admin access local via Unix socket + peer credentials; enable remote admin only with mTLS
  and scoped credentials when required.
- Do not expose inbound cloud listeners; cloud connectivity is outbound-initiated TLS.

## Policy and trust

- Install and maintain signed `EnvelopeProfile` documents; the guard denies commands until a
  valid profile is installed.
- Protect root/role keys using appropriate `KeyProvider` backends (file for dev, HSM/TPM options
  where available) and follow root ceremony guidance in `docs/root-ceremony.md`.
- Use M-of-N for loosening/critical operations; treat single-signer configurations as reduced-assurance.

## Persistence and integrity

- Primary ledgers use WAL + `synchronous=FULL` and boot integrity checks; corruption/tamper moves
  nodes to restricted/lockdown states as designed.
- Security event logs are hash-chained with signed checkpoints and external anchoring support.
- Apply backup/restore procedures that trigger epoch bump and safety states; never silently rewind
  anti-replay/rollback counters.

## Driver isolation

- Drivers run as sandboxed child processes (socketpair, seccomp-bpf/no-new-privs/landlock where
  supported). Device I/O is owned by the guard; drivers exchange frames only.

## Supply chain and updates

- Verify release artifacts (SBOM/VEX, signatures/provenance, reproducibility evidence).
- Treat self-update/TUF-dependent paths per current RFC/blocker status; apply config rollbacks via
  signed, authorized operations.
