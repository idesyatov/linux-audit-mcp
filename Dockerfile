# syntax=docker/dockerfile:1
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
    && adduser -D -u 10001 audit
COPY --from=build \
    /app/target/x86_64-unknown-linux-musl/release/linux-audit-mcp \
    /usr/local/bin/linux-audit-mcp
USER 10001
# No subcommand = MCP stdio server; logs go to stderr, protocol to stdout.
ENTRYPOINT ["linux-audit-mcp"]
