# Allegro Q&A

## What problem does Allegro solve?

Blockchain finality takes seconds. This latency is acceptable for large-value transfers but unsuitable for retail payments where sub-second confirmation is expected.

Users cannot spend received funds until the sending transaction is finalized. A recipient who wants to immediately forward funds to a third party must wait for the first payment to settle. This creates friction that makes blockchain payments impractical for everyday commerce.

## How does Allegro solve this problem?

Allegro provides cryptographic payment confirmation without waiting for block finality. When a user submits a payment, validators sign certificates attesting to the transaction. Once a threshold of validators have signed, the certificates form a Quorum Certificate that proves the payment will settle.

Recipients can spend funds immediately by presenting the QC as proof of incoming payment. This enables chained payments where Alice pays Bob and Bob pays Carol within a single block interval. Both payments complete with cryptographic guarantees before either settles on-chain.
