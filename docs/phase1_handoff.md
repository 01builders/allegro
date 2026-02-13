# FastPay Phase 1 Handoff Notes

## Public API Summary

Primary user-client API surface (`crates/fastpay-user-client`):

- `FastPayClient<T, C, Q, A>`: high-level facade for payment submit, chained submit, bulletin board polling, and reconciliation.
- `TxBuilder`: canonical `FastPayTx` constructor with payment/nonce/expiry/parent-QC support.
- `CertManager<C, Q, A>`: certificate validation and quorum assembly.
- `WalletState<Q>`: nonce reservation, pending tx/QC/cert caches, pruning, snapshot+journal recovery.
- `SidecarTransport`: trait abstraction for sidecar communication (`MockTransport` in Phase 1).
- `MultiValidatorTransport<T>`: fan-out wrapper for parallel validator requests.

## Trait Interfaces and Upgrade Path

Core protocol traits are defined in `crates/fastpay-types`:

- `Certificate`
- `QuorumCert`
- `QuorumAssembler`
- `Signer`

Upgrade path:

1. Phase 1 currently uses `Ed25519Certificate` + `MultiCertQC` + `SimpleAssembler`.
2. Future threshold schemes can replace these concrete types while preserving client logic through trait bounds.
3. `FastPayClient<T, C, Q, A>` remains generic over transport and certificate/QC representation.

## Mock Sidecar Behavior (Partner Reference)

`MockSidecar` (`crates/fastpay-sidecar-mock/src/mock_sidecar.rs`) implements:

1. Canonical payment decoding from `tempo_tx` bytes.
2. Optional `intent` consistency checks (intent is metadata only).
3. Expiry validation by block height/time.
4. Nonce ordering checks per `(sender, nonce_key)`.
5. Equivocation guard by `(sender, nonce_key, nonce_seq)`.
6. Balance checks over base + overlay + parent QC credits.
7. Certificate signing and signer-deduplicated certificate storage.
8. Bulletin-board queries with optional filters and limit.

Pre-seeded scenario:

- `DemoScenario` includes Alice/Bob/Carol balances and Dave/Edgar sidecars.

## Real Sidecar Integration Guide (Transport Swap)

To migrate from Phase 1 mock transport to real sidecars:

1. Implement `SidecarTransport` with real network I/O (tonic for native, grpc-web for wasm).
2. Keep `RequestMeta` semantics:
   - stable `client_request_id` for idempotency
   - deadline-aware retries
3. Replace `MockTransport` in `MultiValidatorTransport` construction with real transport instances.
4. Preserve `FastPayClient` workflow:
   - `send_payment` / `send_payment_with_parent`
   - cert collection + QC assembly
   - wallet updates and reconciliation loop

No client business-logic rewrites are required if transport implements the same trait contract.

## Phase 2 TODOs

1. Real sidecar gRPC/grpc-web transport implementations.
2. Sidecar-node wiring for real balance/nonce reads and on-chain submission.
3. FastPay aggregator integration path and unified bulletin-board queries.
4. Threshold signature implementation to replace multi-cert QC format.
5. Browser/WASM UX integration (wallet persistence, UI status).
6. Inclusion/finality-aware reconciliation against real chain head.
