const clamp = (value: number, min: number, max: number) =>
  Math.max(min, Math.min(max, value));

export const backendUrl =
  (import.meta.env.VITE_BACKEND_URL as string | undefined) ??
  "http://127.0.0.1:8080";

export const tempoRpcUrl =
  (import.meta.env.VITE_TEMPO_RPC_URL as string | undefined) ??
  "https://rpc.moderato.tempo.xyz";

const pollMsRaw = Number(import.meta.env.VITE_POLL_MS ?? "1200");
const pollMs = Number.isFinite(pollMsRaw)
  ? clamp(pollMsRaw, 250, 10_000)
  : 1200;

export const config = {
  backendUrl,
  tempoRpcUrl,
  pollMs,
};
