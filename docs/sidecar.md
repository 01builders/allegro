# Validator Sidecar

The validator sidecar is a gRPC service that manages FastPay certificates for a single validator. It validates incoming transactions, issues signed certificates, and maintains a bulletin board for certificate discovery.

## Purpose

Each validator runs a sidecar alongside their Tempo node. The sidecar receives payment transactions from user clients. It validates each transaction against local state and signs a certificate if valid. Certificates are stored locally and gossiped to peer sidecars.

The sidecar enforces the contention model that prevents double-spending. A validator signs at most one certificate per contention key. The contention key is the tuple `(sender, nonce_key, nonce_seq)`.

## gRPC API

The sidecar implements the `FastPaySidecar` service defined in `proto/sidecar.proto`.

### SubmitFastPay

```protobuf
rpc SubmitFastPay(SubmitFastPayRequest) returns (SubmitFastPayResponse);
```

Validates a `FastPayTx` and returns a `ValidatorCertificate` on success. The request includes the transaction and any parent QCs for chained payments. The response contains either a certificate or a rejection with error code.

### GetBulletinBoard

```protobuf
rpc GetBulletinBoard(GetBulletinBoardRequest) returns (GetBulletinBoardResponse);
```

Returns stored certificates matching the filter criteria. Clients can filter by `tx_hash`, `address`, or `since_unix_millis` for incremental sync. The response includes certificates from this validator and any gossiped certificates from peers.

### GetValidatorInfo

```protobuf
rpc GetValidatorInfo(GetValidatorInfoRequest) returns (GetValidatorInfoResponse);
```

Returns the validator identity including name, public key, and gossip peer list. Clients use this to build the committee verification context.

### GetChainHead

```protobuf
rpc GetChainHead(GetChainHeadRequest) returns (GetChainHeadResponse);
```

Returns the current chain state including block height, block hash, and timestamp. Clients use this to check expiry conditions and reconcile pending transactions.

## State Management

The sidecar maintains several data structures for validation and storage.

### Balances and Overlay

Base balances are seeded from chain state or configuration. The overlay tracks pending debits from in-flight transactions. Available balance is computed as base balance plus overlay adjustments.

```rust
available = base_balance + overlay_delta
```

The overlay becomes negative as the sender submits payments. Parent QC credits are computed by extracting the `EffectsSummary` from the parent certificate.

### Equivocation Guard

The `signed_txs` map prevents signing conflicting transactions. Each entry maps a contention key to the `tx_hash` that was signed. If a new transaction arrives with the same contention key but different hash, validation fails.

### Certificate Store

Certificates are stored by `tx_hash`. Each transaction may have certificates from multiple validators due to gossip. The store deduplicates by signer ID to prevent double-counting.

### Nonce Sequences

The `nonce_sequences` map tracks the next expected nonce for each `(sender, nonce_key)` pair. Transactions must use exactly the next sequence number. Gaps and out-of-order submissions are rejected.

## Validation Flow

Transaction validation proceeds through several checks.

1. Decode the `tempo_tx` bytes and recover the sender from the signature
2. Validate the overlay payment metadata matches the decoded transaction
3. Check expiry against current chain head
4. Check the contention key has not been signed for a different transaction
5. Validate nonce sequence is exactly the expected next value
6. Compute available balance including parent QC credits
7. Verify balance covers the payment amount

If all checks pass, the sidecar signs a certificate. The certificate contains `tx_hash`, `effects_hash`, validator identity, and Ed25519 signature.

## Gossip Protocol

Sidecars synchronize certificates through pull-based gossip. Each sidecar periodically calls `GetBulletinBoard` on its configured peers. The `since_unix_millis` parameter enables incremental sync.

```rust
loop {
    for peer in peers {
        let certs = peer.get_bulletin_board(since_last_sync);
        ingest_peer_certs(certs);
    }
    sleep(gossip_interval);
}
```

Ingested certificates are validated and deduplicated by signer. The gossip interval and peer list are configurable at startup.

## Configuration

The sidecar binary accepts configuration through command-line arguments or environment variables.

| Option | Description |
|--------|-------------|
| `--grpc-addr` | Listen address for gRPC server |
| `--validator-key` | Path to Ed25519 private key |
| `--chain-id` | Tempo chain identifier |
| `--epoch` | Current validator epoch |
| `--peers` | Comma-separated list of peer sidecar endpoints |
| `--gossip-interval` | Interval between gossip pulls |

## Related Documentation

See [System Architecture](architecture.md) for the overall system design.

See [Aggregator Backend](backend.md) for the service that aggregates across sidecars.

See [Tempo Integration](tempo_integration.md) for how sidecars interact with Tempo nodes.
