import { useChainHead } from "@/hooks/usePolling";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export function NetworkStatus() {
  const { head, error } = useChainHead();

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">Network</CardTitle>
        <Badge variant={head ? "default" : "secondary"}>
          {head ? "Connected" : "..."}
        </Badge>
      </CardHeader>
      <CardContent>
        {error && <p className="text-xs text-destructive">{error}</p>}
        {head ? (
          <div className="space-y-1">
            <p className="text-2xl font-bold">#{head.block_height}</p>
            <p className="truncate font-mono text-xs text-muted-foreground">
              {head.block_hash}
            </p>
            <p className="text-xs text-muted-foreground">
              {new Date(head.unix_millis).toLocaleTimeString()}
            </p>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">Loading head...</p>
        )}
      </CardContent>
    </Card>
  );
}
