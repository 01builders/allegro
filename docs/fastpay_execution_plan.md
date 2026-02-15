# FastPay Execution Plan

## Context
This document turns the current planning discussion into an execution-ready roadmap.

Current baseline in this repo:
- Standalone sidecars already exist (`crates/fastpay-sidecar/src/main.rs`).
- External submission to sidecars is already validated in gRPC integration tests (`crates/fastpay-sidecar/tests/grpc_integration.rs`).
- Certificates/QC flow and client transport are already in place.

Goal: evolve from protocol demo into production-shaped architecture:
- Sidecars running independently
- Backend gateway/fronting layer
- Frontend app
- Tempo integration with transient tx lifecycle tracking

---

## Architecture Decisions (Lock First)

### Decision A — Aggregator write API
**Decision:** Add submit RPCs to `proto/aggregator.proto` now.

Rationale:
- Frontend should not talk directly to validator sidecars.
- Avoid later breaking redesign of API boundary.
- Centralize idempotency, policy, and future auth/rate limiting in backend.

### Decision B — Frontend protocol
**Decision:** Expose REST from backend now (keep gRPC for internal/Rust clients).

Rationale:
- Faster Bun/React integration.
- Avoid grpc-web/proxy complexity during this phase.
- Keep one shared backend core; REST and gRPC should both be thin transport layers.

---

## Canonical Transaction Lifecycle
Use `TxLifecycleUpdate.Stage` as shared lifecycle contract across sidecar, backend, and frontend:

`ACCEPTED -> CERTIFIED -> QUEUED_ONCHAIN -> INCLUDED -> FINALIZED`

Notes for near-term phases:
- Phases 1–3 should avoid claiming `FINALIZED` unless backed by real chain observation.
- Status semantics must be documented and deterministic.

---

## Phase Plan

## Phase 1 — Independent Sidecars + External Submission

### Scope
- Make standalone sidecar + external submit path first-class and repeatable.
- Keep simulated state/overlay model.

### Target modules
- `crates/fastpay-sidecar/src/main.rs`
- `crates/fastpay-sidecar/src/state.rs`
- `crates/fastpay-sidecar/src/service.rs`
- Optional new client binary crate for external submit smoke flow.

### Key work
- Confirm and document operator runbook (2 sidecars + submitter).
- Ensure idempotency rule is explicit (`client_request_id` as canonical key).
- Expose retention/limit settings operationally.

### Acceptance criteria
- Two sidecars run independently and process external submits.
- Re-submit with same request id returns idempotent behavior.
- Chained payment flow works over gRPC endpoints.

---

## Phase 2 — FastPay Backend (Aggregator)

### Scope
Implement backend service that fronts sidecars and provides client-facing APIs.

### New crate
- `crates/fastpay-aggregator`
  - `src/main.rs`
  - `src/lib.rs`
  - `src/service.rs` (gRPC)
  - `src/http.rs` (REST)
  - `src/state.rs` / `src/core.rs` (shared domain logic)

### Protocol/interface work first
- Extend `proto/aggregator.proto` with submit fanout RPC(s).
- Keep responses explicit about certs and rejects per validator.
- Define deterministic status derivation for `GetTxStatus`.

### Data model
- Bounded tx status store keyed by `tx_hash`.
- Cert dedupe by signer.
- QC assembly path from cached certs.
- TTL + eviction policy required.

### Acceptance criteria
- Backend can:
  - submit to sidecars (fanout)
  - return unified board
  - return tx status
  - assemble/provide QC when threshold met

---

## Phase 3 — Frontend Scaffold (Bun + React)

### Scope
Create minimal frontend in this repo and wire to backend REST.

### Proposed structure
- `apps/web`
  - `src/pages/Submit.tsx`
  - `src/pages/TxStatus.tsx`
  - `src/pages/BulletinBoard.tsx`
  - `src/api/client.ts`

### Key work
- Provide submit form and status views.
- Display cert count, QC formed, chain head, lifecycle stage.
- Use backend API only (no direct sidecar access from browser).

### Acceptance criteria
- UI can submit payment through backend.
- UI shows lifecycle/status updates and QC state.

---

## Phase 4 — Tempo Integration (Do After Stable API/UI)

### Scope
Integrate real chain-aware sidecar behavior:
1. Track transient tx records.
2. Submit opaque tx bytes to Tempo ref instance.
3. Subscribe to blocks/events.
4. Detect inclusion/finality.
5. Cleanup transient state post-finality.
6. Query chain state before accepting/signing.

### Target modules
- `crates/fastpay-sidecar/src/state.rs`
- `crates/fastpay-sidecar/src/main.rs`
- Optional new crate: `crates/fastpay-tempo-client`

### Interface-first requirement
Define `TempoChainClient` trait before implementation (head, balance/nonce checks, submit, receipt/events).

### Critical risk
Current tx encoding path likely does not yet prove compatibility with intended Tempo 2D nonce semantics.

### Required spikes before full implementation
- Spike D: validate tx format compatibility with Tempo ref.
- Spike E: validate submit + inclusion + head/event observation path.
- Spike F: finalize finality policy (`depth N` or explicit finalized event).

### Acceptance criteria
- In tempo mode, sidecar transitions tx lifecycle based on real chain observation.
- Finalized txs are removed from transient storage per policy.
- Pre-accept checks enforce chain-state constraints.

---

## Near-Term 1–2 Week Sequence

### Week 1
1. Lock proto/API decisions and lifecycle semantics in docs.
2. Add aggregator submit RPCs to `aggregator.proto`.
3. Scaffold `fastpay-aggregator` crate with shared core.
4. Implement gRPC + REST thin layers over shared core.
5. Add integration test: 2 sidecars + 1 aggregator.

### Week 2
1. Add Bun/React frontend scaffold under `apps/web`.
2. Implement submit + status pages against REST.
3. Add tempo integration interfaces/flags only (no deep wiring yet).
4. Run tempo spikes to de-risk tx format and event/finality handling.

---

## Validation Strategy
For implementation phases touching code:
- `just fmt-check`
- `just lint`
- `just test-all` (or narrower suites during development + full run before merge)

For this document-only change, no code checks are required.

---

## Rollback/Reversibility
- Keep new behaviors behind explicit flags:
  - Backend submit enable/disable
  - Sidecar `simulated` vs `tempo` mode
  - Tempo submit/watch flags
- Preserve backward compatibility where feasible; version RPCs if semantics change.

---

## Open Questions
1. Should aggregator submit return immediately at threshold or after all responses?
2. Should failure be represented as explicit lifecycle stage extension or reject-only model?
3. Will frontend use demo accounts server-side initially to avoid browser key handling?
4. What exact Tempo finality definition should drive `FINALIZED`?
