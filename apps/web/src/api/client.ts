import { z } from "zod";
import { config } from "@/config";
import type {
  ChainHead,
  DemoChainHeadEvent,
  DemoDoneEvent,
  DemoErrorEvent,
  DemoStepEvent,
  TxLifecycleStage,
  TxStatus,
} from "./types";

const stageSchema = z
  .union([z.string(), z.number()])
  .transform<TxLifecycleStage>((stage) => {
    if (typeof stage === "number") {
      switch (stage) {
        case 1:
          return "ACCEPTED";
        case 2:
          return "CERTIFIED";
        case 3:
          return "QUEUED_ONCHAIN";
        case 4:
          return "INCLUDED";
        case 5:
          return "FINALIZED";
        default:
          return "STAGE_UNSPECIFIED";
      }
    }

    const upper = stage.toUpperCase();
    if (
      upper === "ACCEPTED" ||
      upper === "CERTIFIED" ||
      upper === "QUEUED_ONCHAIN" ||
      upper === "INCLUDED" ||
      upper === "FINALIZED"
    ) {
      return upper;
    }
    return "STAGE_UNSPECIFIED";
  });

const chainHeadSchema = z.object({
  block_height: z.union([
    z.number().int().nonnegative(),
    z.string().regex(/^\d+$/),
  ]),
  block_hash: z.string().startsWith("0x"),
  unix_millis: z.union([
    z.number().int().nonnegative(),
    z.string().regex(/^\d+$/),
  ]),
});

const txStatusSchema = z.object({
  tx_hash: z.string().startsWith("0x"),
  stage: stageSchema,
  cert_count: z.number().int().nonnegative().default(0),
  qc_formed: z.boolean().default(false),
  qc_hash: z.string().startsWith("0x").optional(),
});

async function fetchJson(url: string): Promise<unknown> {
  const response = await fetch(url, {
    headers: { Accept: "application/json" },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${JSON.stringify(body)}`);
  }
  return body;
}

export async function getChainHead(): Promise<ChainHead> {
  const raw = await fetchJson(`${config.backendUrl}/api/v1/chain/head`);
  const parsed = chainHeadSchema.parse(raw);
  const blockHeight = Number(parsed.block_height);
  const unixMillis = Number(parsed.unix_millis);
  if (!Number.isSafeInteger(blockHeight) || !Number.isSafeInteger(unixMillis)) {
    throw new Error("Chain head values exceed safe integer range");
  }
  return {
    block_height: blockHeight,
    block_hash: parsed.block_hash,
    unix_millis: unixMillis,
  };
}

export async function getTxStatus(txHash: string): Promise<TxStatus> {
  const raw = await fetchJson(
    `${config.backendUrl}/api/v1/tx/${encodeURIComponent(txHash)}/status`,
  );
  const parsed = txStatusSchema.parse(raw);
  const result: TxStatus = {
    tx_hash: parsed.tx_hash,
    stage: parsed.stage,
    cert_count: parsed.cert_count,
    qc_formed: parsed.qc_formed,
  };
  if (parsed.qc_hash !== undefined) result.qc_hash = parsed.qc_hash;
  return result;
}

// ---------------------------------------------------------------------------
// Chained demo SSE client
// ---------------------------------------------------------------------------

export type DemoCallbacks = {
  onStep: (event: DemoStepEvent) => void;
  onChainHead: (event: DemoChainHeadEvent) => void;
  onDone: (event: DemoDoneEvent) => void;
  onError: (event: DemoErrorEvent) => void;
};

export function startChainedDemo(callbacks: DemoCallbacks): AbortController {
  const controller = new AbortController();

  (async () => {
    try {
      const response = await fetch(
        `${config.backendUrl}/api/v1/demo/chained-flow`,
        {
          method: "POST",
          headers: { Accept: "text/event-stream" },
          signal: controller.signal,
        },
      );

      if (!response.ok) {
        const body = await response.text().catch(() => "");
        callbacks.onError({
          message: `HTTP ${response.status}: ${body}`,
        });
        return;
      }

      const reader = response.body?.getReader();
      if (!reader) {
        callbacks.onError({ message: "no readable stream" });
        return;
      }

      const decoder = new TextDecoder();
      let buffer = "";
      let currentEvent = "";

      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        // Keep the last incomplete line in the buffer
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (line.startsWith("event:")) {
            currentEvent = line.slice(6).trim();
          } else if (line.startsWith("data:")) {
            const data = line.slice(5).trim();
            if (!data || !currentEvent) continue;
            try {
              const parsed = JSON.parse(data);
              switch (currentEvent) {
                case "step":
                  callbacks.onStep(parsed as DemoStepEvent);
                  break;
                case "chain_head":
                  callbacks.onChainHead(parsed as DemoChainHeadEvent);
                  break;
                case "done":
                  callbacks.onDone(parsed as DemoDoneEvent);
                  break;
                case "error":
                  callbacks.onError(parsed as DemoErrorEvent);
                  break;
              }
            } catch {
              // skip malformed JSON
            }
            currentEvent = "";
          } else if (line.trim() === "") {
            currentEvent = "";
          }
        }
      }
    } catch (err) {
      if (!controller.signal.aborted) {
        callbacks.onError({
          message: err instanceof Error ? err.message : String(err),
        });
      }
    }
  })();

  return controller;
}
