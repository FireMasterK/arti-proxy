FROM rust:slim AS build

WORKDIR /app

RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    clang \
    git \
    libsqlite3-dev \
    libssl-dev \
    perl \
    pkg-config \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked && \
    cp target/release/arti-proxy /app/arti-proxy

FROM debian:stable-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    libsqlite3-0 \
    libssl3 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /app/arti-proxy /app/arti-proxy

ENV ARTI_PROXY_LISTEN_ADDR=0.0.0.0:9050

EXPOSE 9050

ENTRYPOINT ["/app/arti-proxy"]
