# FastPay Web (Phase 3 scaffold)

Tempo-styled frontend for FastPay transaction submission and status tracking.

## Scope

- **Writes** go to FastPay backend (`/api/v1/submit-payment`).
- **Reads** (chain head + tx status) go to Tempo/Reth-backed read API.
- Browser does not call validator sidecars directly.

## Environment

```bash
VITE_READ_BASE_URL=http://127.0.0.1:8080
VITE_WRITE_BASE_URL=http://127.0.0.1:8080
VITE_POLL_MS=1200
```

## Run

```bash
bun install
bun run dev
```

## Build / type-check

```bash
bun run typecheck
bun run build
```

Lockfile policy: commit `apps/web/bun.lock` (text lockfile).

## Assumed REST endpoints

- `POST /api/v1/submit-payment`
- `GET /api/v1/chain/head`
- `GET /api/v1/tx/{tx_hash}/status`

See `docs/web_rest_contract.md` for the contract expected by this UI.
