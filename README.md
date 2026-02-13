# Allegro FastPay (Tempo Hackathon)

Short guide for running the demo flows.

## Prerequisites

- Rust toolchain (repo includes `rust-toolchain`)
- From repo root:

```bash
cargo build --workspace
```

## Quick demo (mock sidecars, easiest)

This runs the Alice → Bob → Carol chained-payment flow entirely in-process.

```bash
cargo run -p demo
```

You should see logs for:
- Alice->Bob submission
- QC1 formed
- Bob->Carol with parent QC
- QC2 formed

## Real gRPC sidecar demo

Start two sidecars in separate terminals.

Terminal 1 (Dave):

```bash
cargo run -p fastpay-sidecar -- \
  --name Dave \
  --listen 127.0.0.1:50051 \
  --seed 4141414141414141414141414141414141414141414141414141414141414141 \
  --validator-id d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1 \
  --chain-id 1337 \
  --epoch 1 \
  --block-height 1 \
  --demo-balances \
  --peers http://127.0.0.1:50052
```

Terminal 2 (Edgar):

```bash
cargo run -p fastpay-sidecar -- \
  --name Edgar \
  --listen 127.0.0.1:50052 \
  --seed 4242424242424242424242424242424242424242424242424242424242424242 \
  --validator-id e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1 \
  --chain-id 1337 \
  --epoch 1 \
  --block-height 1 \
  --demo-balances \
  --peers http://127.0.0.1:50051
```

Then run sidecar integration tests:

```bash
cargo test -p fastpay-sidecar --test grpc_integration
```

## Useful checks

```bash
cargo fmt -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
