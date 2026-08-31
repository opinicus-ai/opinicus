# Agent Firewall — container image.
#
# A multi-stage build: the first stage compiles the workspace with the
# locked dependencies, the second ships the binary on a slim Debian with a
# shell, so a guarded session can run inside the image:
#
#   docker build -t agent-firewall .
#   docker run --rm agent-firewall --help
#   docker run --rm agent-firewall run -- <command>
#
# The rule pack is compiled into the binary (af-policy `include_str!`),
# so the runtime image carries one file and needs no configuration to
# start protecting. Tracing its own children needs no privilege; run the
# image unprivileged. Not a production security boundary (alpha release).
FROM rust:1-bookworm AS build
WORKDIR /src

# The lockfile and the manifests first, so the dependency layers cache
# independently of the sources.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY policies ./policies

RUN --mount=type=cache,target=/src/target \
    --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release --locked -p af-cli \
    && cp target/release/agent-firewall /usr/local/bin/agent-firewall

FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="Agent Firewall" \
      org.opencontainers.image.description="Deterministic guardrails and evidence-grade audit for cooperative coding agents — alpha release, not a production security boundary" \
      org.opencontainers.image.source="https://github.com/opinicus-ai/opinicus" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="0.1.0"

COPY --from=build /usr/local/bin/agent-firewall /usr/local/bin/agent-firewall

# The wrapper supervises the session it launches; it needs no root for
# that. uid 1000 matches the unprivileged contract of the host binary.
RUN useradd --uid 1000 --create-home --shell /bin/bash firewall
USER firewall
WORKDIR /home/firewall

ENTRYPOINT ["/usr/local/bin/agent-firewall"]
CMD ["--help"]
