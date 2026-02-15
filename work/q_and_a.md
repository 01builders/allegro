# Allegro Q&A

## What problem does Allegro solve?

Blockchain finality requires waiting for validators to come to consensus. This latency is acceptable for large-value transfers but unsuitable for retail payments where sub-second confirmation is the expected user experience.

This is also important for commercial applications that process large payment volumes. A payment processor receiving funds cannot forward those funds until finality. Capital sits idle during each confirmation window. Businesses that chain transactions together see latency compound and working capital requirements grow.

## How does Allegro solve this problem?

Allegro is a decentralized private mempool, run as a Tempo validator sidecar. When a user submits a payment, validators sign certificates attesting to the transaction and send them back as callbacks. Once the user has collected certificates from 2f+1 validators out of 3f+1, they can construct a Quorum Certificate that proves the payment will settle.

Recipients can spend funds immediately by presenting the QC as proof of incoming payment. This enables chained payments where Alice pays Bob and Bob pays Carol within a single block interval. Both payments complete with cryptographic guarantees before either settles on-chain.
