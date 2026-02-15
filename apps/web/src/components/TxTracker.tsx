import { useTxStatus } from "@/hooks/usePolling";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const stageVariant = (stage: string) => {
  switch (stage) {
    case "CERTIFIED":
    case "FINALIZED":
      return "default" as const;
    case "ACCEPTED":
    case "QUEUED_ONCHAIN":
    case "INCLUDED":
      return "secondary" as const;
    default:
      return "outline" as const;
  }
};

export function TxTracker({ txHash }: { txHash: string | null }) {
  const { status, error } = useTxStatus(txHash);

  if (!txHash) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">
            Transaction Status
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Submit a payment to track its status.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">
          Transaction Status
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="truncate font-mono text-xs text-muted-foreground">
          {txHash}
        </p>

        {error && <p className="text-xs text-destructive">{error}</p>}

        {status ? (
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Badge variant={stageVariant(status.stage)}>{status.stage}</Badge>
              {status.qc_formed && <Badge variant="default">QC Formed</Badge>}
            </div>

            <p className="text-sm">
              Certificates: {status.cert_count}/2 signed
            </p>

            {status.qc_hash && (
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground">QC Hash:</p>
                <p className="truncate font-mono text-xs">{status.qc_hash}</p>
              </div>
            )}
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">Loading...</p>
        )}
      </CardContent>
    </Card>
  );
}
