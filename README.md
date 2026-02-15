# Allegro

Blockchain finality requires waiting for validators to come to consensus. This latency is unsuitable for retail payments where sub-second confirmation is the expected user experience. Allegro is a decentralized private mempool, run as a Tempo validator sidecar. When a user submits a payment, validators sign certificates attesting to the transaction and send them back as callbacks. Once the user has collected certificates from 2f+1 validators out of 3f+1, they can construct a Quorum Certificate that proves the payment will settle. Recipients can spend funds immediately by presenting the QC as proof of incoming payment, enabling chained payments that complete with cryptographic guarantees before either settles on-chain.

## Demo

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
  --max-total-certs 10000 \
  --max-known-qcs 4096 \
  --max-request-cache 8192 \
  --max-bulletin-board-response 1000 \
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
  --max-total-certs 10000 \
  --max-known-qcs 4096 \
  --max-request-cache 8192 \
  --max-bulletin-board-response 1000 \
  --demo-balances \
  --peers http://127.0.0.1:50051
```

Then run the chained external client flow against those sidecars:

```bash
cargo run -p demo --bin grpc_chained_demo -- \
  --dave-url http://127.0.0.1:50051 \
  --edgar-url http://127.0.0.1:50052 \
  --chain-id 1337 \
  --epoch 1
```

And/or run sidecar integration tests:

```bash
cargo test -p fastpay-sidecar --test grpc_integration
```

## Useful checks

```bash
cargo fmt -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Web UI scaffold (Phase 2/3 bridge)

A minimal Tempo-styled frontend now exists at `apps/web` for:
- submitting payments to the FastPay backend
- reading chain head / tx status from Tempo-backed read APIs

See:
- `apps/web/README.md`
- `docs/web_rest_contract.md`
