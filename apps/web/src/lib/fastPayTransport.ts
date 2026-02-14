import { custom, type Transport } from "viem";

type FastPayTransportOptions = {
  rpcUrl: string;
  backendUrl: string;
};

export function fastPayTransport({
  rpcUrl,
  backendUrl,
}: FastPayTransportOptions): Transport {
  return custom({
    async request({ method, params }) {
      if (method === "eth_sendRawTransaction") {
        const [signedTx] = params as [string];
        const res = await fetch(`${backendUrl}/api/v1/submit-raw-tx`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ signed_tx: signedTx }),
        });
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          throw new Error(
            `FastPay submit failed: ${res.status} ${JSON.stringify(body)}`,
          );
        }
        const data = (await res.json()) as { tx_hash: string };
        return data.tx_hash;
      }

      if (method === "eth_getTransactionReceipt") {
        const [txHash] = params as [string];
        const res = await fetch(
          `${backendUrl}/api/v1/tx/${encodeURIComponent(txHash)}/status`,
        );
        if (!res.ok) return null;
        const data = (await res.json()) as {
          qc_formed: boolean;
          tx_hash: string;
        };
        if (data.qc_formed) {
          return {
            blockHash: data.tx_hash,
            blockNumber: "0x1",
            contractAddress: null,
            cumulativeGasUsed: "0x0",
            effectiveGasPrice: "0x0",
            from: "0x0000000000000000000000000000000000000000",
            gasUsed: "0x0",
            logs: [],
            logsBloom: "0x" + "0".repeat(512),
            status: "0x1",
            to: "0x0000000000000000000000000000000000000000",
            transactionHash: data.tx_hash,
            transactionIndex: "0x0",
            type: "0x0",
          };
        }
        return null;
      }

      // Forward all other calls to real Tempo RPC
      return forwardToRpc(rpcUrl, method, params);
    },
  });
}

async function forwardToRpc(
  rpcUrl: string,
  method: string,
  params: unknown,
): Promise<unknown> {
  const isWs = rpcUrl.startsWith("ws://") || rpcUrl.startsWith("wss://");

  // For WebSocket URLs, use HTTP fallback URL
  const httpUrl = isWs
    ? rpcUrl.replace(/^wss?:\/\//, "https://").replace(/\/ws$/, "")
    : rpcUrl;

  const res = await fetch(httpUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method,
      params,
    }),
  });
  const json = (await res.json()) as {
    result?: unknown;
    error?: { message: string };
  };
  if (json.error) {
    throw new Error(json.error.message);
  }
  return json.result;
}
