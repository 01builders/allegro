# Demo Scenario

This document describes the Allegro demonstration scenario showing chained payments completing before block finalization.

## Overview

The demo involves five actors completing two chained payments within a single block interval. Alice pays Bob, then Bob immediately spends those funds to pay Carol. Both payments achieve QC-cleared status before the next block height advances.

```mermaid
sequenceDiagram
    participant Alice
    participant Validators
    participant Bob
    participant Carol
    participant Chain

    Note over Alice,Chain: Block N (preconfirmation)
    Alice->>Validators: Pay Bob $10
    Validators-->>Alice: Certificates
    Alice->>Alice: Form QC1
    Bob->>Validators: Pay Carol $10 (parent: QC1)
    Validators-->>Bob: Certificates
    Bob->>Bob: Form QC2
    Carol->>Carol: Verify QC2
    Chain->>Chain: Block N+1 settles
```

Both payments complete with QC confirmation before the block height advances, demonstrating the preconfirmation property.

## Actors

Three user clients participate in the payment flow.

| Actor | Starting Balance | Role |
|-------|------------------|------|
| Alice | $15 | Initiates first payment |
| Bob | $5 | Receives from Alice, pays Carol |
| Carol | $5 | Receives final payment |

Two validators run Allegro sidecars.

| Validator | Role |
|-----------|------|
| Dave | Issues certificates, runs sidecar |
| Edgar | Issues certificates, runs sidecar |

The Allegro service aggregates certificates and provides the web UI.

## Payment Flow

The demo executes two payments in sequence.

1. Alice pays Bob 10 USD
2. Bob pays Carol 10 USD using the QC from payment 1 as parent

After both payments complete, the balances are Alice 5 USD, Bob 5 USD, Carol 15 USD. Bob's balance remains 5 USD because he received 10 USD and immediately spent 10 USD.

## Demo Configuration

The Tempo chain runs with a 5-second block time for visual clarity. This provides enough time to observe QC formation before block inclusion.

```toml
[chain]
block_time_seconds = 5
```

The demo uses a 2-of-2 threshold. Both Dave and Edgar must sign for a QC to form.

## Detailed Information Flow

This diagram shows the complete flow with sidecars wired to Tempo nodes and the Allegro service aggregating certificates.

```mermaid
sequenceDiagram
  autonumber
  participant A as Alice Client
  participant B as Bob Client
  participant C as Carol Client
  participant S as Allegro Service
  participant D as Dave Sidecar
  participant E as Edgar Sidecar
  participant ND as Dave Tempo Node
  participant NE as Edgar Tempo Node

  Note over D: Sidecar wired to node
  Note over E: Sidecar wired to node
  Note over S: Mirrors validator bulletin boards

  S->>D: Subscribe/Poll BulletinBoard
  S->>E: Subscribe/Poll BulletinBoard
  D-->>S: Certificates (CD)
  E-->>S: Certificates (CE)

  A->>D: Submit FastPayTx T1 (A to B $10, nonce_key=FP, seq=a1, expiry)
  A->>E: Submit FastPayTx T1
  D->>ND: Read base state (balances/nonces) and apply overlay checks
  E->>NE: Read base state (balances/nonces) and apply overlay checks
  D-->>A: CD(T1)
  E-->>A: CE(T1)
  D-->>S: CD(T1)
  E-->>S: CE(T1)

  B->>S: Get certificates for T1
  S-->>B: CE(T1)+CD(T1)
  B->>B: Assemble QC1

  B->>D: Submit FastPayTx T2 (B to C $10 + QC1)
  B->>E: Submit FastPayTx T2 (B to C $10 + QC1)

  D->>ND: Enqueue T1/T2 into sub-block tx pipeline
  E->>NE: Enqueue T1/T2 into sub-block tx pipeline

  D-->>S: CD(T2)
  E-->>S: CE(T2)

  S->>S: Poll validators for block height and track QC-clear vs height
  C->>S: Query status / view UI
  S-->>C: QC2 cleared before next block
```

The key observation is that Carol sees the QC-cleared payment before the block height increments. This demonstrates the preconfirmation property.

## Verification Steps

The demo UI displays the following to verify correct operation.

1. Current block height from chain polling
2. List of Allegro transactions with their stage (ACCEPTED, CERTIFIED, INCLUDED)
3. Timestamp showing QC formation occurred before block height change

The successful demo shows both T1 and T2 reach CERTIFIED stage while the block height remains constant.

## Related Documentation

See [System Architecture](01-architecture.md) for the overall system design.

See [Aggregator Backend](03-backend.md) for the Allegro service implementation.

See [Tempo Integration](05-tempo-integration.md) for sub-block transaction routing.
