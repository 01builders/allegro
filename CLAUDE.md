# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FastPay for Tempo: a preconfirmation payment system for the Tempo blockchain. Users complete chained payments (Alice→Bob→Carol) before block finalization via validator-signed certificates that aggregate into Quorum Certificates (QCs).

**Phases:**
- Phase 1: End-to-end demo with mock sidecars (no node wiring)
- Phase 2: Wire to real Tempo nodes + add third-party FastPay service with UI

## Development Environment

Uses Nix flakes for reproducible development. Enter the environment with:
```bash
direnv allow   # if using direnv
# or
nix develop
```

## Commands

Build and run commands via just:
```bash
just build      # cargo build
just run        # cargo run
just test       # cargo test
just lint       # cargo clippy -- -D warnings
just fmt        # cargo fmt
just ci         # format check + lint + test
```

Single test: `cargo test <test_name>`

WASM compilation check: `cargo check --target wasm32-unknown-unknown`

## Architecture

See `docs/user_client_phase1.md` for the Phase 1 user client implementation plan.

**Planned crate structure:**
- `fastpay-types` — Core traits (`Certificate`, `QuorumCert`, `QuorumAssembler`, `Signer`) and ID types
- `fastpay-crypto` — ed25519 implementations of traits
- `fastpay-proto` — Generated protobuf types from `proto/`
- `fastpay-user-client` — Wallet state, tx builder, cert manager, transport abstraction
- `fastpay-sidecar-mock` — Mock sidecar for testing without real validators

**Proto files** in `proto/`:
- `types.proto` — Shared message types (Address, FastPayTx, ValidatorCertificate, QuorumCertificate, etc.)
- `sidecar.proto` — Validator sidecar gRPC API (SubmitFastPay, GetBulletinBoard, GetValidatorInfo, GetChainHead)
- `aggregator.proto` — Third-party aggregator gRPC API (Phase 2)

## Key Concepts

- **ValidatorCertificate**: Validator signature over `(tx_hash, effects_hash)` attesting to a payment
- **QuorumCertificate (QC)**: Threshold bundle of validator certificates (2/2 for demo)
- **Chained spend**: Bob uses QC(Alice→Bob) as `parent_qc` to spend funds before block settlement
- **Contention key**: `(sender, nonce_key, nonce_seq)` — sidecars sign at most one tx per key
- **Tempo 2D nonces**: `nonce_key` (uint256) + `nonce_seq` (uint64); reuse keys to avoid TIP-1000 state creation costs

## WASM Compatibility

User client code must compile to both native Rust and WASM. Use feature flags:
- `native` — tokio, tonic for gRPC
- `wasm` — wasm-bindgen-futures, grpc-web

Use `#[async_trait(?Send)]` for WASM-compatible async traits.
