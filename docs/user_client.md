# User Client

The `fastpay-user-client` crate provides a Rust library for wallet interactions with FastPay. It handles transaction construction, certificate collection, QC assembly, and wallet state management.

## Overview

The client library coordinates the full payment lifecycle. Users construct transactions with the builder API. The transport layer fans out requests to validators. The certificate manager collects and validates responses. The wallet tracks nonces and pending transactions.

The library compiles to both native Rust and WebAssembly. Native builds use `tokio` and `tonic` for async and gRPC. WASM builds use `wasm-bindgen-futures` for browser compatibility.

## Core Components

### FastPayClient

The `FastPayClient` struct is the main entry point. It coordinates transaction submission, certificate collection, and QC assembly.

```rust
let client = FastPayClient::new(
    transport,
    wallet,
    cert_manager,
    chain_id,
    threshold,
    default_nonce_key,
    cert_parser,
).with_sender_private_key(sender, private_key)?;
```

The constructor accepts pluggable components for transport, wallet, and certificate management. The `with_sender_private_key` method registers signing keys for transaction construction.

### Key Methods

The `send_payment` method performs an atomic payment flow.

```rust
let qc = client.send_payment(
    sender,
    recipient,
    amount,
    asset,
    Expiry::MaxBlockHeight(100),
).await?;
```

This method reserves a nonce, builds the transaction, fans out to validators, collects certificates, and assembles the QC. It returns the complete Quorum Certificate on success.

The `send_payment_with_parent` method enables chained payments. It accepts a parent QC reference that credits the sender with received funds.

```rust
let qc = client.send_payment_with_parent(
    sender,
    recipient,
    amount,
    asset,
    expiry,
    &parent_qc,
).await?;
```

This method attaches the parent QC hash to the transaction. Validators validate the parent and credit the sender accordingly.

## Transaction Builder

The `TxBuilder` constructs `FastPayTx` messages with a fluent API.

```rust
let built = TxBuilder::new(chain_id)
    .with_payment(sender, recipient, amount, asset)
    .with_sender_private_key(private_key)
    .with_nonce(nonce_key)
    .with_expiry(Expiry::MaxBlockHeight(100))
    .build()?;
```

The builder validates inputs and computes hashes. It signs the underlying Tempo transaction using the provided private key. The `build` method returns a `BuiltTx` containing the protobuf message, `tx_hash`, and `effects_hash`.

### Nonce Management

The builder tracks nonce sequences per key. Each call to `with_nonce` with the same key increments the sequence. This prevents nonce reuse within a session.

```rust
let tx1 = builder.clone().with_nonce(key).build()?; // seq = 0
let tx2 = builder.clone().with_nonce(key).build()?; // seq = 1
```

For cross-session persistence, use `WalletState` nonce reservation.

## Certificate Manager

The `CertManager` validates and stores certificates from validators.

```rust
let cert_manager = CertManager::<_, _, SimpleAssembler>::new(verify_ctx, threshold);
cert_manager.collect_certificate(cert)?;
let qc = cert_manager.assemble_qc(tx_hash, effects_hash)?;
```

The manager verifies each certificate against the committee verification context. It rejects certificates from unknown validators or mismatched epochs. Duplicate certificates from the same signer are ignored.

### Verification Context

The verification context binds certificate validation to a specific committee.

```rust
let verify_ctx = VerificationContext {
    chain_id: 1337,
    domain_tag: "tempo.fastpay.cert.v1".to_string(),
    protocol_version: 1,
    epoch: 1,
    committee: validator_pubkeys,
};
```

The committee maps validator IDs to public keys. Certificates from validators not in the committee are rejected.

## Wallet State

The `WalletState` struct manages nonces, balances, and pending transactions.

```rust
let mut wallet = WalletState::<MultiCertQC>::new(address, CacheLimits::default());
let seq = wallet.reserve_next_nonce(nonce_key);
wallet.record_pending_tx(pending);
wallet.record_qc(qc);
```

Nonce reservation prevents double-spending across restarts. The wallet journals state changes for crash recovery.

### Nonce Reservation

The `reserve_next_nonce` method atomically claims the next sequence number. Reserved nonces can be released on failure or committed on success.

```rust
let seq = wallet.reserve_next_nonce(key);
// On success:
wallet.commit_reserved_nonce(key, seq);
// On failure:
wallet.release_reserved_nonce(key, seq);
```

This pattern ensures nonces are not reused even if the process crashes between reservation and submission.

### Cache Management

The wallet enforces memory bounds through cache limits.

```rust
let limits = CacheLimits {
    max_pending_txs: 100,
    max_cached_certs: 1000,
    max_cached_qcs: 100,
};
```

The `prune_caches` method removes settled transactions and old certificates when limits are exceeded.

## Transport Layer

The transport trait abstracts network communication with sidecars.

```rust
#[async_trait(?Send)]
pub trait SidecarTransport {
    async fn submit_fastpay(&self, request: Request, meta: RequestMeta) -> Result<Response>;
    async fn get_bulletin_board(&self, request: Request) -> Result<Response>;
    async fn get_validator_info(&self) -> Result<Response>;
    async fn get_chain_head(&self) -> Result<Response>;
}
```

The `?Send` bound enables WASM compatibility where futures are not `Send`.

### Implementations

Three transport implementations are provided.

The `MockTransport` wraps an in-memory `MockSidecar` for testing. No network calls are made.

The `GrpcTransport` uses `tonic` for native gRPC calls. It supports automatic retry with exponential backoff.

The `MultiValidatorTransport` wraps multiple transports for parallel fan-out.

```rust
let transport = MultiValidatorTransport::new(vec![
    MockTransport::new(sidecar_dave),
    MockTransport::new(sidecar_edgar),
]);
```

Fan-out requests are sent in parallel. All responses are collected before returning.

## Error Handling

The `FastPayClientError` enum covers all error cases.

| Variant | Cause |
|---------|-------|
| `Transport` | Network or sidecar communication failure |
| `Builder` | Invalid transaction parameters |
| `CertManager` | Certificate validation failure |
| `Wallet` | Nonce or state error |
| `Rejected` | Validator rejected the transaction |
| `ThresholdNotMet` | Insufficient certificates for QC |

Errors include context for debugging. Transport errors distinguish between timeouts, unavailable services, and validation failures.

## WASM Compatibility

The library uses feature flags for platform-specific dependencies.

```toml
[features]
default = ["native"]
native = ["tokio", "tonic"]
wasm = ["wasm-bindgen-futures", "getrandom/js"]
```

WASM builds exclude native-only transports. The `MockTransport` works in both environments for testing.

## Related Documentation

See [System Architecture](architecture.md) for the overall system design.

See [Validator Sidecar](sidecar.md) for the gRPC service the client communicates with.

See [Tempo Integration](tempo_integration.md) for transaction format details.
