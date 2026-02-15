# Background

This document describes the problem FastPay solves, the distributed systems guarantees it provides, and how we adapt the protocol for the Tempo blockchain. The protocol is based on the FastPay paper by Baudet, Danezis, and Sonnino [1].

## The Problem

Blockchain-based settlement systems face a fundamental latency problem. Traditional consensus protocols require multiple rounds of communication to establish a total ordering of transactions. Even optimized BFT protocols achieve finality in seconds. This latency is acceptable for large-value transfers but unsuitable for point-of-sale retail payments.

The core insight of FastPay is that payment transactions have special semantics. Payments are commutative. Crediting an account with $10 then $20 produces the same result as crediting $20 then $10. This property enables a weaker primitive that provides safety without total ordering.

## Byzantine Consistent Broadcast

FastPay builds on Byzantine Consistent Broadcast rather than atomic commit. Consensus establishes a total order across all transactions with multiple communication rounds. Consistent Broadcast provides per-account ordering with a single round-trip. This reduces latency and increases throughput through account parallelism.

Consistent Broadcast guarantees four properties. Validity ensures that if a correct user broadcasts a message, all correct authorities eventually deliver it. No duplication ensures each message is delivered at most once. Integrity ensures delivered messages were actually sent by the claimed sender. Consistency ensures that if two correct authorities deliver messages for the same sequence number, they deliver the same message.

The critical observation is that consistency does not require agreement on a global order. Authorities only need to agree on what happened for each specific account and sequence number pair.

## Security Properties

FastPay provides the following guarantees under Byzantine faults.

Safety ensures no units of value are created or destroyed. The sum of all certified transfers cannot exceed the funds deposited. This holds as long as fewer than f+1 out of 3f+1 total authorities are compromised.

Authenticity ensures only the owner of an account can authorize transfers. Each transfer order requires the account owner's signature. Authorities verify signatures before signing certificates.

Availability ensures correct users can always transfer funds. As long as 2f+1 authorities are honest and reachable, a correct user can obtain a certificate for any valid transfer.

## Threat Model

FastPay operates under the following assumptions. At most f authorities out of 3f+1 total may be Byzantine. The adversary may arbitrarily delay and reorder messages, but messages are eventually delivered. Availability holds only for users who follow the protocol without equivocation.

When up to f authorities are Byzantine, safety and liveness are preserved. Byzantine authorities can refuse to sign or provide incorrect responses. They cannot forge certificates or cause double-spending.

When more than f authorities are Byzantine, safety may be violated. With f+1 or more Byzantine authorities, they can collude to sign conflicting transfers for the same contention key.

## User Equivocation

A user who signs two different transfers with the same sequence number may lock their account. Authorities refuse to sign either transfer once they detect the conflict. The account remains locked until one transfer achieves a certificate, which may never happen if authorities are split.

This failure mode affects only the equivocating user. Other users and their funds are unaffected. The protocol does not require trusted users for safety. It only requires non-equivocating behavior for availability of the user's own account.

## Network Partition

During a network partition, users may experience temporary loss of liveness. Users cannot obtain certificates if they cannot reach 2f+1 authorities. Safety is preserved during the partition. No conflicting certificates can form because no quorum is reachable.

When the partition heals, normal operation resumes. Any partially signed transfers can be completed. No special recovery protocol is required.

## Mempool and Consensus

FastPay operates as a layer above the mempool but below consensus. The mempool propagates raw transactions through the network without ordering guarantees. The FastPay layer issues certificates attesting to specific account, sequence number, and effects tuples. Consensus orders transactions into blocks for final settlement.

The key benefit is that recipients can accept certificates as payment confirmation without waiting for block finality. The certificate is cryptographic proof that settlement will occur. The certified transaction cannot be rejected at the consensus layer.

## Adapting for Tempo

Tempo is an EVM-compatible blockchain built on reth and commonware. We adapt FastPay to leverage Tempo-specific features.

### 2D Nonce Model

Tempo uses two-dimensional nonces instead of a single sequence counter. Each account has a mapping from `nonce_key` to sequence number. The first dimension identifies a nonce sequence. The second dimension is the sequence number within that key.

This maps naturally to FastPay's contention model. The contention key becomes the tuple `(sender, nonce_key, nonce_seq)`. FastPay transactions use dedicated nonce keys prefixed with `0x5b`. This avoids interference with regular user transactions on other nonce keys.

### Sub-block Transactions

Tempo blocks include a sub-block section for validator-specific transactions. Transactions with nonce keys starting with `0x5b` are routed to this section. They bypass the public mempool.

FastPay leverages this for certified transaction settlement. The user obtains a certificate from validator sidecars. The sidecar forwards the certified transaction to the sub-block pipeline. The transaction appears in the next block and settlement completes.

### TIP-20 Payment Restriction

FastPay on Tempo restricts transactions to TIP-20 payment tokens. These are addresses prefixed with `0x20c0`. This restriction ensures FastPay handles only payment semantics. Arbitrary contract execution is not permitted. This preserves the commutative properties that make consistent broadcast sufficient.

## Chained Payments

FastPay supports chained spending where a recipient spends received funds immediately. The recipient includes the parent Quorum Certificate hash in their transaction. Validators credit the recipient with the incoming amount before validating their outgoing payment.

Alice pays Bob $10 and obtains QC1. Bob presents QC1 as `parent_qc_hash` in his payment to Carol. Validators credit Bob with $10 from QC1 before validating his payment. Bob pays Carol $10 and obtains QC2. Both payments complete before either settles on-chain.

## Quorum Certificate Threshold

A Quorum Certificate requires 2f+1 signatures out of 3f+1 total validators. Any two quorums overlap by at least one honest validator. This prevents conflicting certificates from forming. Even with f Byzantine validators refusing to sign, 2f+1 honest validators can form a quorum.

For the demonstration with 2 validators, the threshold is 2-of-2 where f equals 0. Production deployments use larger committees with appropriate thresholds.

## References

[1] Baudet, M., Danezis, G., and Sonnino, A. "FastPay: High-Performance Byzantine Fault Tolerant Settlement." arXiv:2003.11506, 2020. https://arxiv.org/abs/2003.11506

## Related Documentation

See [System Architecture](01-architecture.md) for the component design.

See [Validator Sidecar](04-sidecar.md) for certificate issuance details.

See [Tempo Integration](05-tempo-integration.md) for blockchain-specific details.
