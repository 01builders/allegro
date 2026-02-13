# FastPay User Client — Phase 1 Implementation Work Plan

This file contains the executable task checklist for Phase 1.
Architecture and protocol design are defined in `docs/user_client_phase1.md`.

## Architecture References

- `A1` -> `docs/user_client_phase1.md` / `### Crate Structure`, `**Dependency graph (layered)**`
- `A2` -> `docs/user_client_phase1.md` / `#### 1. Trait Interfaces for Protocol Objects (Upgrade Path)`
- `A3` -> `docs/user_client_phase1.md` / `#### 2. Transport Abstraction (WASM Compatibility)`
- `A4` -> `docs/user_client_phase1.md` / `#### 3. Async Runtime Abstraction`
- `A5` -> `docs/user_client_phase1.md` / `#### 4. Crypto Library Selection`
- `A6` -> `docs/user_client_phase1.md` / `#### 5. Canonical Hashing and Encoding Rules`
- `A7` -> `docs/user_client_phase1.md` / `#### 6. State Management`
- `A8` -> `docs/user_client_phase1.md` / `## Mock Sidecar Design`, `### Mock Sidecar State`, `### Mock Validation Logic`
- `A9` -> `docs/user_client_phase1.md` / `## Demo Scenario Implementation`
- `A10` -> `docs/user_client_phase1.md` / `## Phase 2 Considerations (Not Implemented Yet)`
- `A11` -> `docs/user_client_phase1.md` / `## Design Decisions`

## Implementation Work Plan

### Milestone 1: Project Setup & Workspace

- [x] **1.1** Create workspace structure with crates (fastpay-types, fastpay-crypto, fastpay-proto, fastpay-user-client, fastpay-sidecar-mock). (Ref: `A1`)
- [x] **1.2** Configure root Cargo.toml workspace with shared dependencies. (Ref: `A1`, `A5`)
- [x] **1.3** Configure WASM feature flags across all crates. (Ref: `A4`)
- [x] **1.4** Add wasm32-unknown-unknown to rust-toolchain targets. (Ref: `A4`)
- [x] **1.5** Verify WASM compilation works (`cargo check --target wasm32-unknown-unknown`). (Ref: `A4`, `A5`)

### Milestone 2: Core Traits & IDs (fastpay-types)

- [x] **2.1** Define `Certificate` trait. (Ref: `A2`)
- [x] **2.2** Define `QuorumCert` trait. (Ref: `A2`)
- [x] **2.3** Define `QuorumAssembler` trait. (Ref: `A2`)
- [x] **2.4** Define `Signer` trait with domain-separated signing context. (Ref: `A2`)
- [x] **2.5** Define `VerificationContext` (committee + epoch binding). (Ref: `A2`, `A11`)
- [x] **2.6** Implement `Address` wrapper type (20 bytes, validation, Display). (Ref: `A2`)
- [x] **2.7** Implement `TxHash` wrapper type (32 bytes). (Ref: `A2`)
- [x] **2.8** Implement `EffectsHash` wrapper type (32 bytes). (Ref: `A2`)
- [x] **2.9** Implement `QcHash` wrapper type (32 bytes). (Ref: `A2`)
- [x] **2.10** Implement `NonceKey` wrapper type (32 bytes). (Ref: `A2`)
- [x] **2.11** Define error types (`CryptoError`, `AssemblyError`, `ValidationError`). (Ref: `A2`)

### Milestone 3: Proto Generation (fastpay-proto)

- [x] **3.1** Set up prost-build in build.rs. (Ref: `A1`)
- [x] **3.2** Generate Rust types from proto files. (Ref: `A1`)
- [x] **3.3** Add `convert.rs` with proto <-> domain type conversions (after Milestone 2 domain IDs are stable). (Ref: `A1`, `A2`)
- [x] **3.4** Export generated types in lib.rs. (Ref: `A1`)
- [x] **3.5** Add unit tests for serialization round-trips. (Ref: `A1`)

### Milestone 4: Crypto Implementations (fastpay-crypto)

- [x] **4.1** Implement `Ed25519Certificate` (implements `Certificate` trait). (Ref: `A2`, `A5`)
- [x] **4.2** Implement `Ed25519Signer` (implements `Signer` trait). (Ref: `A2`, `A5`)
- [x] **4.3** Implement `MultiCertQC` (implements `QuorumCert` trait). (Ref: `A2`)
- [x] **4.4** Implement `SimpleAssembler` (implements `QuorumAssembler` trait). (Ref: `A2`)
- [x] **4.5** Implement `compute_tx_hash()` (canonical serialization -> sha256). (Ref: `A6`)
- [x] **4.6** Implement `compute_effects_hash()`. (Ref: `A6`)
- [x] **4.7** Implement domain-separated cert signing preimage (bind chain_id + domain_tag + protocol_version + epoch). (Ref: `A2`, `A6`)
- [x] **4.8** Implement `compute_qc_hash()`. (Ref: `A6`)
- [x] **4.9** Specify canonical byte encoding rules (field order, width, presence tags, sorting). (Ref: `A6`)
- [x] **4.10** Add golden vectors for tx/effects/qc hash and cert preimages (native + WASM). (Ref: `A6`)
- [x] **4.11** Add cross-language vector harness (for example, TypeScript) for hash parity. (Ref: `A6`)
- [x] **4.12** Add unit tests for all crypto operations. (Ref: `A2`, `A6`)
- [x] **4.13** Verify WASM compatibility of crypto crate. (Ref: `A4`, `A5`)
- [x] **4.14** 🔖 **Git commit**: "Implement fastpay-crypto crate with ed25519 certificates and QC assembly"

### Milestone 5: Transport Abstraction (fastpay-user-client)

- [x] **5.1** Define `SidecarTransport` trait (async, ?Send for WASM). (Ref: `A3`, `A4`)
- [x] **5.2** Define `TransportError` type. (Ref: `A3`)
- [x] **5.3** Implement `MockTransport` (wraps MockSidecar). (Ref: `A3`, `A8`)
- [x] **5.4** Add request metadata (idempotency key, timeout budget, retry policy). (Ref: `A3`, `A11`)
- [x] **5.5** Implement retry strategy (exponential backoff + jitter, deadline-aware). (Ref: `A3`, `A11`)
- [x] **5.6** Add transport configuration struct (endpoints, timeouts, retry settings). (Ref: `A3`)
- [x] **5.7** Add multi-validator transport wrapper (submit to N validators). (Ref: `A3`, `A11`)
- [x] **5.8** 🔖 **Git commit**: "Add transport abstraction with mock transport and retry logic"

### Milestone 6: Mock Sidecar (fastpay-sidecar-mock)

- [x] **6.1** Implement `MockSidecar` struct with state. (Ref: `A8`)
- [x] **6.2** Decode and validate payment semantics from canonical `tempo_tx` bytes. (Ref: `A8`, `A6`)
- [x] **6.3** Enforce `intent` consistency check (`intent` is optional metadata only). (Ref: `A8`)
- [x] **6.4** Implement balance checking (base + overlay). (Ref: `A8`)
- [x] **6.5** Implement QC credit extraction (for chained spends). (Ref: `A8`, `A9`)
- [x] **6.6** Implement nonce validation (sequence ordering). (Ref: `A8`, `A11`)
- [x] **6.7** Implement equivocation guard. (Ref: `A8`)
- [x] **6.8** Implement certificate signing using `Ed25519Signer`. (Ref: `A2`, `A8`)
- [x] **6.9** Store multiple certs per tx with dedupe-by-signer logic. (Ref: `A8`)
- [x] **6.10** Implement bulletin board storage and queries. (Ref: `A8`, `A3`)
- [x] **6.11** Add pre-seeded `DemoScenario` (Alice/Bob/Carol with starting balances). (Ref: `A9`)
- [x] **6.12** Add unit tests for validation logic (accept/reject cases). (Ref: `A8`)
- [x] **6.13** 🔖 **Git commit**: "Implement fastpay-sidecar-mock with validation logic and demo scenario"

### Milestone 7: Transaction Builder (fastpay-user-client)

- [x] **7.1** Implement `TxBuilder` struct. (Ref: `A2`, `A7`)
- [x] **7.2** Implement `with_payment()` method (sender, recipient, amount, asset). (Ref: `A6`)
- [x] **7.3** Implement `with_nonce()` method (key selection, auto-increment). (Ref: `A7`, `A11`)
- [x] **7.4** Implement `with_expiry()` method (block height or timestamp). (Ref: `A6`)
- [x] **7.5** Implement `with_parent_qc()` method for chained spends. (Ref: `A2`, `A9`)
- [x] **7.6** Implement `build()` method with local validation. (Ref: `A6`, `A11`)
- [x] **7.7** Add unit tests for tx construction. (Ref: `A6`)

### Milestone 8: Certificate Manager (fastpay-user-client)

- [x] **8.1** Implement `CertManager<C: Certificate, Q: QuorumCert>` (generic over cert types). (Ref: `A2`)
- [x] **8.2** Implement certificate collection and storage. (Ref: `A7`)
- [x] **8.3** Implement signature verification on received certs with committee/epoch context. (Ref: `A2`, `A11`)
- [x] **8.4** Reject certs from unknown validators or wrong epoch. (Ref: `A2`, `A11`)
- [x] **8.5** Implement tx_hash/effects_hash matching validation. (Ref: `A2`, `A6`)
- [x] **8.6** Implement QC assembly using `QuorumAssembler`. (Ref: `A2`)
- [x] **8.7** Add unit tests for assembly edge cases (duplicate certs, mismatched hashes). (Ref: `A2`)
- [x] **8.8** 🔖 **Git commit**: "Add tx builder and certificate manager to fastpay-user-client"

### Milestone 9: Wallet State Management (fastpay-user-client)

- [x] **9.1** Implement `WalletState<Q: QuorumCert>` struct (generic over QC type). (Ref: `A7`)
- [x] **9.2** Implement balance tracking (base + pending adjustments). (Ref: `A7`)
- [x] **9.3** Implement atomic nonce reservation (`reserve_next_nonce`) per key. (Ref: `A7`, `A11`)
- [x] **9.4** Implement reservation release/commit flow for terminal submit outcomes. (Ref: `A7`)
- [x] **9.5** Implement pending tx tracking. (Ref: `A7`)
- [x] **9.6** Implement QC storage for use as parents. (Ref: `A7`, `A9`)
- [x] **9.7** Implement state update on cert/QC receipt. (Ref: `A7`)
- [x] **9.8** Implement bounded cache/pruning policy (pending/certs/QCs). (Ref: `A7`, `A11`)
- [x] **9.9** Add durable snapshot + journal replay for crash recovery. (Ref: `A7`, `A11`)
- [x] **9.10** Add serde serialization support. (Ref: `A7`, `A10`)
- [x] **9.11** 🔖 **Git commit**: "Implement wallet state management with nonce reservation and cache pruning"

### Milestone 10: Client Facade & Demo

- [x] **10.1** Implement `FastPayClient<T, C, Q>` facade (generic over transport, cert, QC). (Ref: `A2`, `A3`, `A7`)
- [x] **10.2** Implement `send_payment()` high-level method. (Ref: `A3`, `A7`)
- [x] **10.3** Implement `send_payment_with_parent()` for chained spends. (Ref: `A9`)
- [x] **10.4** Implement `poll_bulletin_board()` for cert discovery. (Ref: `A3`)
- [x] **10.5** Implement `assemble_qc()` convenience method. (Ref: `A2`)
- [x] **10.6** Implement chain-reconciliation loop (inclusion/finality -> cache cleanup). (Ref: `A7`, `A11`)
- [x] **10.7** Create `demo` binary crate. (Ref: `A1`, `A9`)
- [x] **10.8** Implement Alice->Bob->Carol demo scenario. (Ref: `A9`)
- [x] **10.9** Add tracing/logging for demo visibility. (Ref: `A9`, `A11`)
- [x] **10.10** 🔖 **Git commit**: "Add FastPayClient facade and Alice→Bob→Carol demo binary"

### Milestone 11: Integration Testing

- [x] **11.1** Integration test: single payment (Alice->Bob). (Ref: `A9`)
- [x] **11.2** Integration test: chained payment (Alice->Bob->Carol). (Ref: `A9`)
- [x] **11.3** Integration test: rejection - insufficient funds. (Ref: `A8`)
- [x] **11.4** Integration test: rejection - equivocation attempt. (Ref: `A8`)
- [x] **11.5** Integration test: rejection - expired transaction. (Ref: `A6`, `A8`)
- [x] **11.6** Integration test: rejection - invalid parent QC. (Ref: `A2`, `A8`)
- [x] **11.7** Integration test: rejection - `intent` mismatch vs decoded `tempo_tx`. (Ref: `A8`)
- [x] **11.8** Integration test: cert dedupe by signer for same `tx_hash`. (Ref: `A8`)
- [x] **11.9** Integration test: reject unknown validator signer (not in committee). (Ref: `A2`, `A11`)
- [x] **11.10** Integration test: reject mixed/incorrect epoch certs. (Ref: `A2`, `A11`)
- [x] **11.11** Integration test: conflicting cert sets for same contention domain. (Ref: `A8`)
- [x] **11.12** Integration test: stale chain-head vs expiry boundary race. (Ref: `A3`, `A6`)
- [x] **11.13** Integration test: bulletin-board pagination consistency under partial sync. (Ref: `A3`)
- [x] **11.14** Integration test: crash/restart recovery preserves nonce reservations. (Ref: `A7`, `A11`)
- [x] **11.15** Verify full demo scenario runs end-to-end. (Ref: `A9`)
- [x] **11.16** Test WASM build (`cargo build --target wasm32-unknown-unknown --features wasm`). (Ref: `A4`, `A5`)
- [x] **11.17** 🔖 **Git commit**: "Add integration tests for payment flows and edge cases"

### Milestone 12: Documentation & Handoff

- [x] **12.1** Document public API with rustdoc. (Ref: `A2`, `A3`, `A7`)
- [x] **12.2** Document trait interfaces and upgrade path. (Ref: `A2`)
- [x] **12.3** Document mock sidecar behavior for partner reference. (Ref: `A8`)
- [x] **12.4** Create integration guide for real sidecar (transport swap). (Ref: `A3`, `A10`)
- [x] **12.5** List Phase 2 TODOs (gRPC transport, aggregator, threshold sigs, UI). (Ref: `A10`)
- [x] **12.6** 🔖 **Git commit**: "Add documentation and Phase 2 handoff notes"

### Milestone 13: Phase 1 Remediation (Spec Compliance Gaps)

- [x] **13.1** Implement durable wallet journal events that can replay pending tx and cert/QC state updates from snapshot+delta events. (Ref: `A7`, `A11`)
- [x] **13.2** Add wallet replay tests proving pending tx/cert state is reconstructed from snapshot + journal delta. (Ref: `A7`, `A11`)
- [x] **13.3** Implement reconciliation behavior that marks QC-backed pending txs as settled when chain-head polling succeeds. (Ref: `A7`, `A11`)
- [x] **13.4** Add client reconciliation tests for pending->settled transitions and cache cleanup behavior. (Ref: `A7`, `A11`)
- [x] **13.5** Implement native `GrpcTransport` for `SidecarTransport` using tonic unary RPC calls (submit, bulletin board, validator info, chain head). (Ref: `A3`)
- [x] **13.6** Add `GrpcTransport` tests (endpoint validation/error mapping + request path coverage). (Ref: `A3`)
- [x] **13.7** Add wasm hash-vector test wiring in `fastpay-crypto` so canonical vector assertions compile/run for wasm-targeted tests. (Ref: `A4`, `A6`)
- [x] **13.8** Add test/build commands to verify wasm hash vectors and cross-language vector harness execution as part of remediation validation. (Ref: `A4`, `A6`)
- [x] **13.9** Run comprehensive checks (`cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo test -p fastpay-crypto --target wasm32-unknown-unknown --features wasm --no-run`, `node crates/fastpay-crypto/vectors/hash_vectors.ts`) and confirm clean. (Ref: `A4`, `A6`, `A11`)
- [x] **13.10** 🔖 **Git commit + push**: "Close Phase 1 spec compliance gaps (replay, reconciliation, grpc transport, wasm vector tests)"
