import { z } from "zod";
import { config } from "@/config";
import type { ChainHead, TxLifecycleStage, TxStatus } from "./types";

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
