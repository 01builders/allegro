export type Hex = string;

export type TxLifecycleStage =
  | "STAGE_UNSPECIFIED"
  | "ACCEPTED"
  | "CERTIFIED"
  | "QUEUED_ONCHAIN"
  | "INCLUDED"
  | "FINALIZED";

export type ChainHead = {
  block_height: number;
  block_hash: Hex;
  unix_millis: number;
};

export type TxStatus = {
  tx_hash: Hex;
  stage: TxLifecycleStage;
  cert_count: number;
  qc_formed: boolean;
  qc_hash?: Hex | undefined;
};

// ---------------------------------------------------------------------------
// Chained demo SSE types
// ---------------------------------------------------------------------------

export type DemoStepEvent = {
  step: string;
  label: string;
  description: string;
  tx_hash?: Hex;
  qc_hash?: Hex;
  parent_qc_hash?: Hex;
  cert_count?: number;
  timestamp_ms: number;
};

export type DemoChainHeadEvent = {
  block_height: number;
  block_hash: Hex;
  unix_millis: number;
};

export type DemoDoneEvent = {
  success: boolean;
  total_ms: number;
  start_block_height: number;
};

export type DemoErrorEvent = {
  message: string;
};

export type DemoState = {
  status: "idle" | "running" | "done" | "error";
  steps: DemoStepEvent[];
  chainHead: DemoChainHeadEvent | null;
  done: DemoDoneEvent | null;
  error: string | null;
};
