# Licence exceptions

TriBase ships under two licences: the runtime is **AGPL-3.0-only** and the
integration surface (`tirbase-types`, `tirbase-driver-api`, `tirbase-demo`, the
TypeScript SDK and most of `tirbase-sdk`) is **Apache-2.0**. The authoritative
component matrix is [`LICENSING.md`](../LICENSING.md).

Any departure from that policy — a dependency under a licence outside the
allow-list, a generated artefact that cannot carry a header, a reference pack
that must ship a launcher — is an **exception**. Exceptions are not decided in
review threads: they are recorded in the machine-checked register at
[`licence-exceptions.toml`](../licence-exceptions.toml).

## The register

Each `[[exception]]` entry has five required fields:

| Field | Meaning |
|---|---|
| `id` | Stable identifier, unique in the register. |
| `owner` | Accountable person or team (`@team` or an email address). |
| `reason` | Why the exception exists and what would remove the need for it (at least 20 characters). |
| `scope` | Where the exception applies — crate, target, artefact, build stage (at least 10 characters). |
| `expires` | `YYYY-MM-DD`. After this date the entry is dead and CI fails. |
| `crates` | Cargo crate names covered by the entry; must match `deny.toml` one-for-one. |

An exception is valid only while **all** of the following hold:

1. every required field is present and non-empty;
2. `expires` is today or later;
3. every `[[licenses.exceptions]]` crate in `deny.toml` has a register entry;
4. every crate named in the register is actually excepted in `deny.toml`.

Conditions 3 and 4 keep the human-readable register and the enforcement
configuration from drifting apart in either direction.

## Adding an exception

1. Open a pull request that adds the `[[exception]]` entry and, if needed, the
   matching `[[licenses.exceptions]]` block in `deny.toml`.
2. State in the PR why no compliant alternative exists and what the exit plan
   is; put the same reasoning in `reason`.
3. Choose an expiry no more than twelve months out. The owning team is expected
   to renew deliberately or remove the dependency before it lapses.
4. Run `python3 scripts/check-licence-exceptions.py` locally; the blocking
   `licence-exceptions` CI job runs the same command.

## Removing or renewing

Delete the entry when the dependency leaves the graph. To renew, update
`expires` and refresh `reason` with the current justification — an unchanged
reason is a signal that the exception has become permanent, which the policy
does not allow. Expired entries fail CI, so a lapsed exception cannot ship
silently.

## Current exceptions

| ID | Owner | Scope | Expires |
|---|---|---|---|
| `r-efi-lgpl-2.1` | `@tirbase-maintainers` | Transitive UEFI-target dependency of `getrandom`; never distributed | 2027-06-30 |

### `r-efi-lgpl-2.1`

`r-efi` is reached only through `getrandom`'s UEFI target support, via
`libp2p`/`hickory-proto` (`getrandom` 0.3) and `rusqlite` (`getrandom` 0.4). It
is not a direct dependency of any first-party crate and is not linked into the
gateway, SDK, or reference-pack artefacts. The LGPL-2.1-or-later option is
allowed for this crate in `deny.toml`; the exception exists because the policy
otherwise permits only AGPL-3.0-only and Apache-2.0 for first-party code and a
narrow allow-list for third-party code.

## What is *not* an exception

- An AGPL dependency reachable from an Apache-licensed crate. That is a licence
  boundary violation and the `licence-agpl-free` job fails; it cannot be
  waived through this register.
- Executable code inside a reference pack. Packs are data-only by contract; the
  `licence-pack-purity` job fails and the offending file must be removed.
- A missing SPDX header. Headers are generated, not excepted; run the backfill
  described in `LICENSING.md`.
