# syntax=docker/dockerfile:1
# Multi-stage build: cargo build in a rust image, ship a slim runtime.
#
#   docker build -t redactify:local .
#   docker run --rm -p 8080:8080 redactify:local
#
# The container serves the deterministic REST API (L0 rules + L1 PII +
# policy). The ML layer is NOT shipped: model exports live in ml_models/
# (gitignored, ~2.9GB) and the runtime images stay model-free on purpose.

ARG RUST_IMAGE=rust:1-slim-bookworm

# ---------------------------------------------------------------- build
FROM ${RUST_IMAGE} AS build
ARG FEATURES=api
ENV CARGO_TARGET_DIR=/build/target
WORKDIR /build

# manifest + lock first: dependency layer caches independently of src changes
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# crates/redactify-mcp is a workspace member: its manifest is required
# for workspace resolution even when building only the root binary
COPY crates ./crates
# declared in the manifest ([[bench]], doctest-referenced dirs) - cargo
# resolves these paths even for --release --bin builds
COPY benches ./benches
COPY examples ./examples

# BuildKit cache mounts keep cargo registry + target across rebuilds
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=${CARGO_TARGET_DIR} \
    cargo build --release --locked --features ${FEATURES} --bin redactify \
    && cp ${CARGO_TARGET_DIR}/release/redactify /redactify-bin

# ---------------------------------------------------------------- runtime
FROM debian:bookworm-slim AS runtime
# curl: HEALTHCHECK; ca-certificates: any future TLS fetch; both tiny
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home redactify

COPY --from=build /redactify-bin /usr/local/bin/redactify

# hardening: dedicated non-root user, no shell needed beyond apt-installed
USER redactify
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/redactify"]
# bind 0.0.0.0 inside the container so port mapping reaches the server
CMD ["--serve", "0.0.0.0:8080"]
