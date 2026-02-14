import { useAccount, useConnect, useDisconnect } from "wagmi";
import { Button } from "@/components/ui/button";

export function ConnectButton() {
  const { address, isConnected } = useAccount();
  const { connect, connectors, isPending } = useConnect();
  const { disconnect } = useDisconnect();

  if (isConnected && address) {
    const truncated = `${address.slice(0, 6)}...${address.slice(-4)}`;
    return (
      <div className="flex items-center gap-3">
        <span className="font-mono text-sm text-muted-foreground">
          {truncated}
        </span>
        <Button variant="outline" size="sm" onClick={() => disconnect()}>
          Disconnect
        </Button>
      </div>
    );
  }

  const connector = connectors[0];
  if (!connector) return null;

  return (
    <div className="flex items-center gap-2">
      <Button
        size="sm"
        disabled={isPending}
        onClick={() =>
          connect({
            connector,
            capabilities: { type: "sign-up" } as Record<string, unknown>,
          })
        }
      >
        {isPending ? "Connecting..." : "Sign Up"}
      </Button>
      <Button
        variant="outline"
        size="sm"
        disabled={isPending}
        onClick={() => connect({ connector })}
      >
        Sign In
      </Button>
    </div>
  );
}
