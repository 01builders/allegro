# Aggregator Backend

The aggregator backend is a third-party service that fans out requests to multiple validator sidecars. It collects certificates, assembles Quorum Certificates, and exposes a REST API for web clients.

## Purpose

The backend simplifies client integration by providing a single endpoint. Clients submit transactions once to the backend. The backend forwards the request to all configured sidecars in parallel. It collects responses and returns the aggregated result.

The backend also maintains a local certificate cache. This reduces load on individual sidecars for bulletin board queries. The cache uses LRU eviction to bound memory usage.

## gRPC API

The backend implements the `FastPayAggregator` service defined in `proto/aggregator.proto`.

### SubmitFastPay

```protobuf
rpc SubmitFastPay(SubmitFastPayRequest) returns (SubmitFastPayResponse);
```

Fans out the request to all sidecar endpoints. Returns all received certificates and any rejections. The client can determine if quorum threshold was reached from the certificate count.

### GetBulletinBoard

```protobuf
rpc GetBulletinBoard(GetBulletinBoardRequest) returns (GetBulletinBoardResponse);
```

Pulls certificates from all sidecars and merges the results. Also serves certificates from the local cache. Deduplicates by `(tx_hash, effects_hash, signer)`.

### GetQuorumCertificate

```protobuf
rpc GetQuorumCertificate(GetQuorumCertificateRequest) returns (GetQuorumCertificateResponse);
```

Refreshes certificates from sidecars for the given `tx_hash`. Groups certificates by `effects_hash` to find the dominant outcome. Assembles the QC from the group with the most validators. Returns the QC with computed `qc_hash`.

### GetTxStatus

```protobuf
rpc GetTxStatus(GetTxStatusRequest) returns (GetTxStatusResponse);
```

Returns all certificates for a transaction. Includes the lifecycle stage based on certificate count. A transaction with threshold certificates is in stage `CERTIFIED`.

### GetChainHead

```protobuf
rpc GetChainHead(GetChainHeadRequest) returns (GetChainHeadResponse);
```

Polls all sidecars and returns the highest observed block height. Uses this to provide consistent expiry checking across validators.

## REST API

The backend exposes HTTP endpoints for web client integration.

### Encoding Conventions

The REST API follows these encoding rules for frontend compatibility.

| Type | Encoding |
|------|----------|
| Bytes | Hex string with `0x` prefix |
| uint64 | Decimal string for precision |
| Stage | One of `ACCEPTED`, `CERTIFIED`, `QUEUED_ONCHAIN`, `INCLUDED`, `FINALIZED` |

The `client_request_id` field enables idempotent request handling. Duplicate requests with the same ID return the cached response.

### Submit Raw Transaction

```
POST /api/v1/submit-raw-tx
Content-Type: application/json

{
  "chain_id": 1337,
  "tempo_tx_hex": "0x...",
  "nonce_key_hex": "0x5b...",
  "nonce_seq": 0,
  "expiry": { "max_block_height": 100 },
  "client_request_id": "req-123"
}
```

Accepts a pre-signed Tempo transaction. Fans out to sidecars and returns the transaction hash with certificate status.

```json
{
  "tx_hash": "0x...",
  "stage": "ACCEPTED",
  "cert_count": 0,
  "qc_formed": false
}
```

Rejected transactions return an error response.

```json
{
  "reject": {
    "code": "INSUFFICIENT_FUNDS",
    "message": "balance check failed"
  }
}
```

### Chain Head

```
GET /api/v1/chain/head
```

Returns the current chain state from the highest responding sidecar.

```json
{
  "block_height": "12345",
  "block_hash": "0x...",
  "unix_millis": "1700000000000"
}
```

This endpoint provides chain state for clients to check expiry conditions. The `block_height` and `unix_millis` fields use decimal strings for uint64 precision.

### Transaction Status

```
GET /api/v1/tx/{tx_hash}/status
```

Returns the certificate count and lifecycle stage for a transaction.

```json
{
  "tx_hash": "0x...",
  "stage": "CERTIFIED",
  "cert_count": 2,
  "qc_formed": true,
  "qc_hash": "0x..."
}
```

The `qc_formed` field indicates whether threshold certificates have been collected. When true, `qc_hash` contains the hash of the assembled Quorum Certificate. Clients poll this endpoint to track payment progress.

## State Management

The backend maintains a certificate cache with bounded memory usage.

### Certificate Ingestion

Certificates arrive through sidecar responses and are stored by `tx_hash`. Each transaction maps to a set of certificates keyed by `effects_hash` and `signer`. This structure supports detecting conflicting validator votes.

### LRU Eviction

The cache tracks certificate timestamps for LRU eviction. When `max_total_certs` is exceeded, the oldest certificates are removed. Per-transaction limits prevent any single transaction from consuming excessive memory.

### Chain Head Tracking

The backend tracks the highest observed block height across all sidecars. This provides consistent chain state for status queries.

## Upstream Fanout

The backend uses parallel requests to minimize latency.

```rust
async fn fanout_submit_fastpay(endpoints: &[String], request: Request) -> Vec<Response> {
    let futures = endpoints.iter().map(|ep| submit_to_endpoint(ep, &request));
    join_all(futures).await
}
```

Each request has a configurable timeout. Timed-out requests return an error code rather than blocking the response. The client receives all successful responses even if some sidecars are slow.

## QC Assembly

Quorum Certificate assembly handles potentially conflicting validator votes.

1. Group certificates by `effects_hash`
2. Count validators in each group
3. Select the group with the most validators
4. Break ties using lexicographic ordering of `effects_hash`
5. Compute `qc_hash` over the selected certificates

The resulting QC contains certificates from validators who agree on the transaction effects.

## Configuration

| Option | Description |
|--------|-------------|
| `--grpc-addr` | Listen address for gRPC server |
| `--rest-addr` | Listen address for REST server |
| `--sidecars` | Comma-separated sidecar endpoints |
| `--threshold` | Certificate threshold for QC |
| `--timeout-ms` | Per-sidecar request timeout |
| `--max-certs` | Maximum cached certificates |

## Related Documentation

See [System Architecture](01-architecture.md) for the overall system design.

See [Validator Sidecar](04-sidecar.md) for the upstream gRPC services.

See [Demo Scenario](06-demo.md) for the end-to-end payment flow.
