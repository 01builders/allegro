# FastPay Web REST Contract (Draft)

This is the frontend/backend handshake for the Phase 2/3 overlap.

## Rules

- JSON `bytes` should be returned as `0x...` hex strings.
- `stage` must map to `TxLifecycleUpdate.Stage` semantics:
  `ACCEPTED | CERTIFIED | QUEUED_ONCHAIN | INCLUDED | FINALIZED`.
- `client_request_id` should be treated idempotently by backend.
- For `uint64` fields (`block_height`, `unix_millis`), prefer decimal strings for long-term safety.
  The current UI accepts number or decimal string.

## Write API (FastPay backend)

### `POST /api/v1/submit-payment`

Request:

```json
{
  "sender": "0x1111111111111111111111111111111111111111",
  "recipient": "0x2222222222222222222222222222222222222222",
  "amount": 1,
  "asset": "0x0000000000000000000000000000000000000000",
  "expiry_unix_millis": 1739200000000,
  "client_request_id": "6f8ce0d2-5602-4fe6-8d26-0c41efe4a9e9"
}
```

Response (minimum):

```json
{
  "tx_hash": "0x...",
  "stage": "ACCEPTED"
}
```

Reject response example:

```json
{
  "reject": {
    "code": "INSUFFICIENT_FUNDS",
    "message": "balance check failed"
  }
}
```

## Read API (Tempo-backed path)

### `GET /api/v1/chain/head`

```json
{
  "block_height": 42,
  "block_hash": "0x...",
  "unix_millis": 1739200000123
}
```

### `GET /api/v1/tx/{tx_hash}/status`

```json
{
  "tx_hash": "0x...",
  "stage": "CERTIFIED",
  "cert_count": 2,
  "qc_formed": true,
  "qc_hash": "0x..."
}
```
