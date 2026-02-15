# Tempo Integration

FastPay integrates with the Tempo blockchain through its sub-block transaction system. This document covers the 2D nonce model, sub-block routing, and how FastPay layers on top of existing Tempo infrastructure.

## 2D Nonce System

Tempo uses a two-dimensional nonce model instead of a single sequential counter. Each account can maintain multiple independent nonce sequences identified by a `nonce_key`.

| nonce_key value | Behavior |
|-----------------|----------|
| `0` | Protocol nonce with standard Ethereum behavior |
| `1` to `2^256-2` | User-defined parallel sequences |
| `U256::MAX` | Expiring nonces |
| `0x5b...` prefix | Reserved for sub-block transactions |

This model allows multiple in-flight transactions without nonce conflicts. FastPay uses dedicated nonce keys to avoid interfering with regular user transactions.

### Nonce Key Economics

Creating a new nonce key incurs state creation costs under TIP-1000. Each new key requires approximately 5,000 gas for the initial storage slot. Clients should reuse a fixed set of FastPay nonce keys rather than generating random keys per transaction.

The recommended pattern is to allocate one or a few nonce keys for FastPay and increment the sequence number within each key. This amortizes the state creation cost across many transactions.

## Sub-block Transactions

Transactions with a `nonce_key` starting with `0x5b` are routed through the sub-block system. These transactions bypass the public mempool and are included through validator sub-blocks.

The `nonce_key` encodes routing information in its bytes.

```
Byte position:  [31]   [30-16]               [15-0]
Content:        0x5b   PartialValidatorKey   Application data
```

Byte 31 contains the sub-block prefix. Bytes 16 through 30 contain the first 15 bytes of the validator's public key. Bytes 0 through 15 are available for application use.

The `PartialValidatorKey` routes the transaction to the correct validator's sub-block queue. The Tempo node matches this prefix against configured validator keys.

## Sub-block Flow

When a transaction arrives at the Tempo node RPC, routing occurs based on the `nonce_key`.

```mermaid
sequenceDiagram
    participant Client
    participant RPC as Tempo RPC
    participant Actor as SubblocksActor
    participant Proposer

    Client->>RPC: eth_sendRawTransaction
    RPC->>RPC: Check nonce_key prefix
    alt 0x5b prefix matches validator
        RPC->>Actor: Route to sub-block channel
        Actor->>Actor: Build SignedSubBlock
        Actor->>Proposer: Broadcast sub-block
        Proposer->>Proposer: Include in block
    else No match
        RPC->>RPC: Reject or use normal mempool
    end
```

This diagram shows the routing decision at the RPC layer. Matching transactions are sent to the `SubblocksActor` for inclusion in the validator's sub-block.

## Gas Allocation

Tempo allocates a portion of block gas to sub-blocks.

| Pool | Allocation | Purpose |
|------|------------|---------|
| Shared pool | 10% of block gas | Divided among all validators |
| Non-shared pool | 90% of block gas | Normal transactions |
| Gas incentive | Unused sub-block gas | Rewards for proposers |

Each validator receives an equal share of the shared pool. The formula is `shared_gas / num_validators`. Unused gas flows to the gas incentive pool.

## FastPay Layer

FastPay adds a preconfirmation layer on top of the sub-block system. Validators issue certificates before submitting transactions to the chain. Users can rely on certificates without waiting for block inclusion.

The integration points are as follows.

1. FastPay sidecars validate transactions and issue certificates
2. Certified transactions are submitted through the sub-block system
3. The `0x5b` prefix routes transactions to validator sub-blocks
4. Block inclusion provides final settlement

This architecture separates preconfirmation from settlement. Certificates provide instant confirmation while the sub-block system handles ordering and inclusion.

## Transaction Format

FastPay transactions wrap Tempo transactions with additional metadata. The `tempo_tx` field contains signed EVM transaction bytes. The `overlay` field provides payment metadata for validation.

```rust
struct FastPayTx {
    chain_id: u64,
    tempo_tx: Vec<u8>,            // Signed EVM transaction
    nonce_key: [u8; 32],          // 2D nonce key
    nonce_seq: u64,               // Sequence within key
    expiry: Expiry,               // Block height or timestamp
    parent_qc_hash: [u8; 32],     // For chained payments
    tempo_tx_format: TempoTxFormat,  // Transaction format discriminator
    overlay: OverlayMetadata,        // Payment metadata for validation
}
```

The `tempo_tx_format` field identifies the encoding format of `tempo_tx`. Currently only `EVM_OPAQUE_BYTES_V1` is supported, representing standard Ethereum transaction encoding.

The `overlay` field contains payment metadata that sidecars validate against the decoded `tempo_tx`. This includes the sender, recipient, amount, and asset. Sidecars independently decode the EVM transaction and verify the overlay matches before signing.

```rust
struct OverlayMetadata {
    payment: PaymentIntent,  // Sender, recipient, amount, asset
}
```

The `tempo_tx` bytes use standard Ethereum encoding. FastPay currently supports ERC-20 transfer calls to TIP-20 payment addresses.

## TIP-20 Payment Format

TIP-20 tokens use an address prefix to indicate payment compatibility. Addresses starting with `0x20c0` are recognized as TIP-20 payment tokens.

```
Token address: 0x20c0...
Call data: transfer(address,uint256) with selector 0xa9059cbb
```

FastPay validates that the transaction target has the TIP-20 prefix. This restricts FastPay to payment transactions and prevents arbitrary contract execution.

## SDK Integration

The `tempo-alloy` Rust crate provides Tempo-specific transaction types. FastPay uses `alloy` for transaction encoding and signature recovery. The user client constructs signed transactions using these libraries.

```rust
let tx = TxLegacy {
    chain_id: Some(chain_id),
    nonce: 0,
    gas_price: 1,
    gas_limit: 80_000,
    to: token_address.into(),
    value: U256::ZERO,
    input: Bytes::from(transfer_calldata),
};
let signed = signer.sign_transaction_sync(&tx)?;
```

This example shows transaction construction with `alloy`. The signed bytes are included in the `FastPayTx` for submission to sidecars.

## Related Documentation

See [System Architecture](01-architecture.md) for the overall FastPay design.

See [Validator Sidecar](04-sidecar.md) for certificate issuance.

See [Demo Scenario](06-demo.md) for the end-to-end demonstration.
