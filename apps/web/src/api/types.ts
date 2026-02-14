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
