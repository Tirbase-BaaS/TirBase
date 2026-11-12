# TirBase gateway OCI image (PV-11.4, CLAIM-37.3).
#
# The binary is built outside this image with the same glibc baseline as the
# Debian 11 package (cross/x86_64-unknown-linux-gnu, glibc 2.31), so the image
# runs on Debian bookworm-slim and any newer Debian release.
#
# Build (from the workspace root, after the CI cross-build step places the
# binary at dist/tirbase-gateway):
#   docker build -f deploy/Dockerfile -t tirbase-gateway:ci .
#
# The image is an OCI image: BuildKit (the default builder) produces OCI media
# types, and the HEALTHCHECK below is what validates the container in CI.

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libdbus-1-3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system tirbase \
    && useradd --system --gid tirbase --home-dir /var/lib/tirbase \
        --no-create-home --shell /usr/sbin/nologin tirbase \
    && mkdir -p /var/lib/tirbase /run/tirbase /etc/tirbase \
    && chown -R tirbase:tirbase /var/lib/tirbase /run/tirbase

COPY dist/tirbase-gateway /usr/local/bin/tirbase-gateway
COPY deploy/docker/gateway.toml /etc/tirbase/gateway.toml

USER tirbase

EXPOSE 8080 9090

# Liveness: GET /health must answer 200 within 500 ms (PV-11.1).
HEALTHCHECK --interval=5s --timeout=3s --start-period=20s --retries=12 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/tirbase-gateway"]
CMD ["/etc/tirbase/gateway.toml"]
