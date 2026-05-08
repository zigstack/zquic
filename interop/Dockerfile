# zquic interop runner image — self-contained local build
#
# Downloads Zig at build time, compiles the binaries, then packages them
# into a slim runtime image. Use this for local docker builds.
#
#   docker build -t zquic-interop -f interop/Dockerfile .
#
# For CI builds where binaries are pre-compiled on the runner, use
# interop/Dockerfile.prebuilt instead.

# ── Stage 1: compile ────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates xz-utils python3 \
    && rm -rf /var/lib/apt/lists/*

# Fetch the 0.16.0 release tarball URL from the official JSON index.  The
# JSON is an object whose top-level keys are version names; we read the
# "0.16.0" entry's "x86_64-linux" tarball.
RUN set -eux; \
    INDEX=$(curl -fsSL https://ziglang.org/download/index.json); \
    ZIG_URL=$(echo "$INDEX" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["0.16.0"]["x86_64-linux"]["tarball"])'); \
    echo "Downloading Zig from: ${ZIG_URL}"; \
    curl -fsSL "${ZIG_URL}" -o /tmp/zig.tar.xz; \
    mkdir -p /usr/local/zig; \
    tar -xf /tmp/zig.tar.xz --strip-components=1 -C /usr/local/zig; \
    rm /tmp/zig.tar.xz

ENV PATH="/usr/local/zig:${PATH}"

WORKDIR /build
COPY . .
RUN zig build -Doptimize=ReleaseFast

# ── Stage 2: minimal runtime ────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        ethtool \
        iproute2 \
        net-tools \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/zig-out/bin/server /usr/local/bin/zquic-server
COPY --from=builder /build/zig-out/bin/client /usr/local/bin/zquic-client
COPY interop/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT ["/run_endpoint.sh"]
