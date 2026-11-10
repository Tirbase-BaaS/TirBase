# Packaging and fleet inventory (task 37, PV-11.3 / PV-11.4)

This page documents the packaging pipeline for the `tirbase-gateway` binary and
the fleet-inventory CRDT collection. Every item below is enforced by CI; the
job names are the production callers cited by `CLAIMS.md` (CLAIM-37.1 … 37.5).

## 1. Cross-compiled builds (CLAIM-37.1)

`.github/workflows/ci.yml` → `cross-compile` matrix builds the release gateway
for:

| Target | Runner | Verification |
|---|---|---|
| `aarch64-unknown-linux-gnu` | `ubuntu-latest` + cross | ELF machine `AArch64`, executed under qemu via `cross run -- --version` |
| `armv7-unknown-linux-gnueabihf` | `ubuntu-latest` + cross | ELF machine `ARM`, executed under qemu via `cross run -- --version` |

`Cross.toml` installs the target-architecture `libdbus-1-dev` before building:
`tirbase-core`'s `native` feature links the BLE bridge (btleplug → dbus) on
Linux. Each job also runs the binary-size gate (section 4) and uploads the
artifact.

## 2. Debian package (CLAIM-37.2)

`[package.metadata.deb]` in `tirbase-gateway/Cargo.toml` declares the package;
the `package-deb` CI job runs `cargo deb -p tirbase-gateway` **from the
workspace root** (cargo-deb 3.x resolves asset and maintainer-script paths
against the current directory), then installs the resulting `.deb` inside a
`debian:11` container, starts the gateway with
`/etc/tirbase/gateway.toml` and waits for `GET /health`.

Contents:

| Path in package | Source |
|---|---|
| `/usr/bin/tirbase-gateway` | release binary |
| `/lib/systemd/system/tirbase-{gateway,guard,lockdown}.service` | `deploy/systemd/` |
| `/etc/tirbase/gateway.toml` | `deploy/deb/gateway.toml` |
| maintainer scripts | `deploy/deb/{postinst,prerm,postrm}` |

The binary is cross-built for `x86_64-unknown-linux-gnu` (cross's glibc 2.31
image) so it installs on Debian 11, whose glibc is 2.31. The package depends on
`libc6 (>= 2.31), libgcc-s1, libdbus-1-3`.

`postinst` creates the `tirbase` system account and the
`/var/lib/tirbase` + `/run/tirbase` state directories; the gateway generates
`/var/lib/tirbase/device-key.json` on first boot.

Local build:

```bash
cross build --release -p tirbase-gateway --target x86_64-unknown-linux-gnu
cargo install cargo-deb --locked
cargo deb -p tirbase-gateway --target x86_64-unknown-linux-gnu --no-build --output target/debian/
```

## 3. OCI container image (CLAIM-37.3)

`deploy/Dockerfile` builds a `debian:bookworm-slim` image with the
cross-built binary, `deploy/docker/gateway.toml`, a non-root `tirbase` user and
a `HEALTHCHECK` that runs `curl -fsS http://127.0.0.1:8080/health`. The
`package-oci` CI job stages the binary at `dist/tirbase-gateway`, builds the
image (BuildKit produces OCI media types), then starts the container and waits
for Docker's health status to report `healthy`.

`.dockerignore` limits the build context to the staged binary, the Dockerfile
and the container config.

The image ships no signed `EnvelopeProfile`, so command ingress stays in the
deny-all posture (PV-11.5); `/health` and metrics remain available.

## 4. Binary size and RSS budget gates (CLAIM-37.4)

`deploy/budgets.toml` holds the budgets; `scripts/check-size-budget.sh`
enforces them:

```bash
scripts/check-size-budget.sh binary-size <path> <target>
scripts/check-size-budget.sh rss <peak_kib>
scripts/check-size-budget.sh --self-test
```

PV-15.7 defers every numerical budget to the measure-first task (44.2), so all
committed values are `0` — the gate records the measurement and passes. When
44.2 records baselines in `docs/perf-baseline.md`, set each budget at 120% of
the baseline (PV-15.2); exceeding a set budget then fails CI, which is the
regression gate. The `size-budget` job runs the self-test (proving over-budget
size and RSS measurements fail), gates the release binary size, boots the
gateway and gates its peak RSS (`VmHWM`).

## 5. Fleet inventory CRDT (CLAIM-37.5)

`tirbase-core/src/fleet/` implements the fleet inventory as a state-based CRDT
collection keyed by device DID:

* **Provisioning payload cap** — `MAX_PROVISIONING_PAYLOAD_BYTES = 64 KiB`,
  enforced on local provisioning *and* on untrusted inbound updates.
* **Revocation is monotonic** — a revoked entry always dominates a provisioned
  entry, so a stale peer cannot resurrect a revoked device.
* **Convergence** — per-device join is a total order on
  `(lifecycle, version, updated_by)`, so merge is commutative, associative and
  idempotent; `FleetInventory::snapshot_hash()` is byte-stable across replicas
  and is the fleet-precondition hash Contract migrations commit to (task 30.3).
* **Propagation** — `CoreHandle::fleet_provision_device` /
  `fleet_revoke_device` publish a `FleetInventoryDelta` on
  `subscribe_fleet_updates()` and enqueue it on the mesh scheduler at HIGH
  priority as a `GossipMessage::FleetInventoryUpdate` envelope. Inbound deltas
  merge through both `receive_inbound` paths, apply the local revocation side
  effects (the CRDT engine then rejects Deltas authored by the revoked DID),
  and re-broadcast only when the merge changed state. Newly connected peers are
  sent the full inventory on connection, so revocation reaches every connected
  peer within the PV-11.3 60-second budget.

The integration test
`tirbase-core/tests/task37_fleet_inventory.rs::fleet_revocation_propagates_to_connected_peer_within_60_seconds`
drives two real `CoreHandle` instances: the revocation delta must be published,
accepted by the peer and applied to the peer's merge gate inside 60 seconds.
Removing the propagation path makes that wait time out, so it is also the
wiring-mutation check.
