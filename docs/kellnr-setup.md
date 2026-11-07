# Kellnr Private Cargo Registry

TirBase uses [Kellnr](https://kellnr.io) as a private, self-hosted Cargo registry
that acts as a **caching proxy for crates.io**. Every dependency download flows
through the local Kellnr instance, giving the team:

- **Supply-chain control** — a tamper-evident cache; crates are checksum-verified
  before being served.
- **Auditability** — every version that has been pulled is visible in the Kellnr UI.
- **Offline resilience** — once a crate is cached, it is served from Kellnr even if
  crates.io is unreachable.
- **Private crate hosting** — internal crates can be published to Kellnr and used as
  normal `[dependencies]` entries with `registry = "kellnr"`.

---

## Quick Start

Kellnr runs as a Docker container. Docker Desktop must be running.

```bash
# Start Kellnr (detached)
docker compose -f .kellnr/docker-compose.yml up -d

# Check health
curl -s http://localhost:8000/api/v1/health   # → "OK"

# Stop Kellnr
docker compose -f .kellnr/docker-compose.yml down
```

The Web UI is available at **http://localhost:8000** (default: `admin` / `admin`).
**Change the password immediately after first start.**

---

## How It Works

`.cargo/config.toml` contains a source-replacement directive:

```toml
[source.crates-io]
replace-with = "kellnr"

[source.kellnr]
registry = "sparse+http://localhost:8000/api/v1/cratesio/"
```

This tells Cargo to fetch all crates from Kellnr's crates.io proxy endpoint instead
of reaching out to crates.io directly. The crate bytes are identical (Kellnr verifies
checksums); `Cargo.lock` is unaffected.

---

## First-Time Warming (Optional)

On first use Kellnr fetches crates from crates.io on demand and caches them. To
pre-warm the cache for the full workspace:

```bash
cargo fetch   # downloads all locked deps through Kellnr
```

---

## CI Configuration

In CI (GitHub Actions), Kellnr is **not** used — CI fetches directly from crates.io
using the standard sparse index. The `.cargo/config.toml` source replacement is
workspace-local and only applies when Kellnr is running on `localhost:8000`.

If you want CI to also use Kellnr (e.g., a shared team instance), set the
`CARGO_SOURCE_KELLNR_INDEX` environment variable or override `.cargo/config.toml`
in the CI job.

---

## Publishing Internal Crates

```bash
# Login (only needed once per machine)
cargo login --registry kellnr http://localhost:8000

# Publish a workspace crate
cargo publish --registry kellnr -p tirbase-types
```

Internal crates published to Kellnr can be used in `Cargo.toml` as:

```toml
[dependencies]
tirbase-types = { version = "0.1", registry = "kellnr" }
```

---

## Configuration Reference

Key environment variables (see `.kellnr/docker-compose.yml`):

| Variable | Default | Description |
|---|---|---|
| `KELLNR_ORIGIN__HOSTNAME` | `localhost` | Hostname advertised in index config |
| `KELLNR_ORIGIN__PORT` | `8000` | HTTP port |
| `KELLNR_PROXY__ENABLED` | `true` | Enable crates.io proxy |
| `KELLNR_PROXY__NUM_THREADS` | `10` | Concurrent upstream fetch threads |
| `KELLNR_REGISTRY__DATA_DIR` | `/opt/kellnr/data` | Storage path (inside container) |
| `KELLNR_REGISTRY__AUTH_REQUIRED` | `false` | Require login for crate pulls |

Crate data is persisted in a named Docker volume (`kellnr_kellnr-data`).
To reset Kellnr completely: `docker compose -f .kellnr/docker-compose.yml down -v`

---

## Troubleshooting

**`cargo build` fails with "kellnr: no such registry"**  
→ Kellnr is not running. Run `docker compose -f .kellnr/docker-compose.yml up -d`.

**Connection refused on port 8000**  
→ Docker Desktop may not be running, or Kellnr container crashed.  
→ Check: `docker compose -f .kellnr/docker-compose.yml ps`

**Crate not found in Kellnr**  
→ Kellnr fetches from crates.io on demand. The first fetch may take a moment.  
→ If it fails, check internet connectivity from the Docker container.

**`cargo deny check` fails with "unknown registry"**  
→ `deny.toml` already includes Kellnr's URL in `allow-registry`. If you change
   the Kellnr port, update `deny.toml` accordingly.
