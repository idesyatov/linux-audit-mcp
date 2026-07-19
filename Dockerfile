# Runtime image for `linux-audit-mcp`. Minimal and hardened:
#   - fully static (musl) binary, so no libc/toolchain in the final image;
#   - only an SSH client is added (the tool shells out to system `ssh`);
#   - runs as a non-root user;
#   - NO secrets baked in. Mount the SSH key at run time (see README).
# The dev/CI/cross image is Dockerfile.dev; this one is the shipped artifact.

# ---- build: static musl binary (no C deps in this project) ----
FROM rust:latest AS build
WORKDIR /app
# Pin the toolchain BEFORE adding the target, so musl std lands on the exact
# toolchain rust-toolchain.toml selects (otherwise: "can't find crate for std").
COPY rust-toolchain.toml .
RUN rustup show && rustup target add x86_64-unknown-linux-musl
COPY . .
RUN cargo build --release --locked --target x86_64-unknown-linux-musl \
    && strip target/x86_64-unknown-linux-musl/release/linux-audit-mcp

# ---- runtime: Alpine with only the ssh client, non-root ----
FROM alpine:3.20
RUN apk add --no-cache openssh-client \
    && adduser -D -u 10001 audit \
    # Pre-create the history dir owned by the non-root user, so a mounted volume
    # (named OR bind) inherits writable ownership - no chmod dance needed.
    && mkdir -p /data && chown 10001:10001 /data
COPY --from=build \
    /app/target/x86_64-unknown-linux-musl/release/linux-audit-mcp \
    /usr/local/bin/linux-audit-mcp

# Container conventions, so `docker run` needs no `-e`: mount the config to
# /config/targets.toml and the SSH key to /keys/id_ed25519; to persist health
# history, mount any volume at /data (LINUX_AUDIT_DATA_DIR points there already).
# HOME is a writable tmpdir (for the secured key copy and known_hosts). The
# identity override keeps targets.toml host-portable (its own path is ignored).
ENV HOME=/tmp \
    LINUX_AUDIT_CONFIG=/config/targets.toml \
    LINUX_AUDIT_IDENTITY_FILE=/keys/id_ed25519 \
    LINUX_AUDIT_DATA_DIR=/data

USER 10001
# No subcommand = MCP stdio server; logs go to stderr, protocol to stdout.
ENTRYPOINT ["linux-audit-mcp"]
