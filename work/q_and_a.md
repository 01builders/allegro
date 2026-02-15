# Allegro Q&A

## What problem does Allegro solve?

Blockchain payment systems require consensus to finalize transactions. Consensus protocols establish a total ordering of all transactions through multiple rounds of communication between validators. This process takes seconds even with optimized BFT protocols. The latency is acceptable for large-value transfers but unsuitable for retail payments at physical points of sale.

Users cannot spend received funds until the sending transaction achieves finality. A merchant receiving payment must wait for block confirmation before the customer can leave. A recipient who wants to immediately forward funds to a third party must wait for the first payment to settle. This creates friction that makes blockchain payments impractical for everyday commerce.

## How does Allegro solve this problem?

Allegro provides cryptographic payment confirmation without waiting for consensus. When a user submits a payment, validators sign certificates attesting to the transaction. Once a threshold of validators have signed, the certificates form a Quorum Certificate. The QC proves the payment will settle and cannot be reversed.

Recipients can spend funds immediately by presenting the QC as proof of incoming payment. Validators credit the recipient with the incoming amount before validating their outgoing payment. This enables chained payments where Alice pays Bob and Bob pays Carol within a single block interval. Both payments complete with cryptographic finality before either settles on-chain.
