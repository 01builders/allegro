import { createConfig, http } from "wagmi";
import { tempoModerato } from "viem/chains";
import { webAuthn, KeyManager } from "wagmi/tempo";
import { fastPayTransport } from "./fastPayTransport";

// TIP-20 token addresses on Tempo Moderato
export const pathUsd =
  "0x20c0000000000000000000000000000000000000" as const;
export const alphaUsd =
  "0x20c0000000000000000000000000000000000001" as const;
export const betaUsd =
  "0x20c0000000000000000000000000000000000002" as const;

export const TOKENS = [
  { address: alphaUsd, label: "AlphaUSD" },
  { address: betaUsd, label: "BetaUSD" },
  { address: pathUsd, label: "PathUSD" },
] as const;

const rpcUrl =
  (import.meta.env.VITE_TEMPO_RPC_URL as string | undefined) ??
  "https://rpc.moderato.tempo.xyz";

const backendUrl =
  (import.meta.env.VITE_BACKEND_URL as string | undefined) ??
  "http://127.0.0.1:8080";

export { backendUrl };

export const config = createConfig({
  connectors: [
    webAuthn({ keyManager: KeyManager.localStorage() }),
  ],
  chains: [tempoModerato],
  multiInjectedProviderDiscovery: false,
  transports: {
    [tempoModerato.id]: fastPayTransport({ rpcUrl, backendUrl }),
  },
});

declare module "wagmi" {
  interface Register {
    config: typeof config;
  }
}
