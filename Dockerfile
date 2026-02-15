# Stage 1: build both binaries from the workspace
FROM rust:latest AS builder

RUN apt-get update && apt-get install -y protobuf-compiler pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY proto/ proto/

# Root [package] in workspace Cargo.toml expects a src/ dir
RUN mkdir src && echo "" > src/lib.rs

RUN cargo build --release -p fastpay-backend -p fastpay-sidecar

# Stage 2: minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/fastpay-backend /usr/local/bin/
COPY --from=builder /build/target/release/fastpay-sidecar /usr/local/bin/
