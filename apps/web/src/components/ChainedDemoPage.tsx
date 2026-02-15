import { useChainedDemo } from "@/hooks/useChainedDemo";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import type { DemoStepEvent } from "@/api/types";

function truncateHash(hash: string): string {
  if (hash.length <= 14) return hash;
  return `${hash.slice(0, 8)}...${hash.slice(-4)}`;
}

const STEP_META: Record<
  string,
  { participant: string; color: string; initials: string }
> = {
  alice_submit_started: {
    participant: "Alice",
    color: "bg-blue-500",
    initials: "A",
  },
  alice_qc_formed: {
    participant: "Alice",
    color: "bg-blue-500",
    initials: "A",
  },
  bob_import_qc: { participant: "Bob", color: "bg-amber-500", initials: "B" },
  bob_submit_started: {
    participant: "Bob",
    color: "bg-amber-500",
    initials: "B",
  },
  bob_qc_formed: { participant: "Bob", color: "bg-amber-500", initials: "B" },
};

function StepBadge({ step }: { step: string }) {
  const isQcFormed = step.endsWith("_qc_formed");
  const isImport = step === "bob_import_qc";
  if (isQcFormed) return <Badge variant="default">QC FORMED</Badge>;
  if (isImport) return <Badge variant="secondary">IMPORTED</Badge>;
  return <Badge variant="outline">SUBMITTED</Badge>;
}

function StepCard({ event }: { event: DemoStepEvent }) {
  const meta = STEP_META[event.step] ?? {
    participant: "?",
    color: "bg-gray-500",
    initials: "?",
  };

  return (
    <div className="flex gap-3">
      <div className="flex flex-col items-center">
        <div
          className={`${meta.color} flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-xs font-bold text-white`}
        >
          {meta.initials}
        </div>
        <div className="w-px flex-1 bg-border" />
      </div>
      <div className="flex-1 space-y-1 pb-4">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium">{event.label}</span>
          <StepBadge step={event.step} />
          <span className="ml-auto text-xs text-muted-foreground">
            +{event.timestamp_ms}ms
          </span>
        </div>
        <p className="text-xs text-muted-foreground">{event.description}</p>
        {event.tx_hash && (
          <p className="font-mono text-xs text-muted-foreground">
            tx: {truncateHash(event.tx_hash)}
          </p>
        )}
        {event.qc_hash && (
          <p className="font-mono text-xs text-muted-foreground">
            qc: {truncateHash(event.qc_hash)}
          </p>
        )}
        {event.parent_qc_hash && (
          <p className="font-mono text-xs text-muted-foreground">
            parent: {truncateHash(event.parent_qc_hash)}
          </p>
        )}
        {event.cert_count != null && (
          <p className="text-xs text-muted-foreground">
            certs: {event.cert_count}/2
          </p>
        )}
      </div>
    </div>
  );
}

export function ChainedDemoPage() {
  const { state, start, reset } = useChainedDemo();

  return (
    <div className="grid gap-6 md:grid-cols-[1.2fr_0.8fr]">
      <div className="space-y-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Chained Payment Demo
            </CardTitle>
            <div className="flex gap-2">
              <Button
                size="sm"
                onClick={start}
                disabled={state.status === "running"}
              >
                {state.status === "running" ? "Running..." : "Run Demo"}
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={reset}
                disabled={state.status === "idle"}
              >
                Reset
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <p className="mb-4 text-xs text-muted-foreground">
              Alice sends $10 to Bob, then Bob immediately spends those funds to
              Carol -- before the next block is produced. This demonstrates
              chained pre-confirmation payments.
            </p>

            <Separator className="mb-4" />

            {state.status === "idle" && (
              <p className="text-sm text-muted-foreground">
                Click "Run Demo" to start the chained payment flow.
              </p>
            )}

            {state.steps.length > 0 && (
              <div className="space-y-0">
                {state.steps.map((step, i) => (
                  <StepCard key={i} event={step} />
                ))}
              </div>
            )}

            {state.status === "running" && state.steps.length > 0 && (
              <div className="flex items-center gap-2 pl-11">
                <div className="h-2 w-2 animate-pulse rounded-full bg-primary" />
                <span className="text-xs text-muted-foreground">
                  Processing...
                </span>
              </div>
            )}

            {state.error && (
              <p className="mt-2 text-sm text-destructive">{state.error}</p>
            )}

            {state.done?.success && (
              <div className="mt-2 rounded-md border border-primary/20 bg-primary/5 p-3">
                <p className="text-sm font-medium">
                  Both payments settled in {state.done.total_ms}ms
                  {state.chainHead
                    ? `, before block #${state.chainHead.block_height + 1} was produced`
                    : ""}
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <aside className="space-y-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Chain Status</CardTitle>
            <Badge
              variant={state.status === "running" ? "default" : "secondary"}
            >
              {state.status === "running" ? "Live" : "Idle"}
            </Badge>
          </CardHeader>
          <CardContent className="space-y-3">
            {state.done && (
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground">
                  Start block height
                </p>
                <p className="text-2xl font-bold">
                  #{state.done.start_block_height}
                </p>
              </div>
            )}
            {state.chainHead && (
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground">
                  Current block height
                </p>
                <p className="text-2xl font-bold">
                  #{state.chainHead.block_height}
                </p>
                <p className="truncate font-mono text-xs text-muted-foreground">
                  {state.chainHead.block_hash}
                </p>
                <p className="text-xs text-muted-foreground">
                  {new Date(state.chainHead.unix_millis).toLocaleTimeString()}
                </p>
              </div>
            )}
            {!state.done && !state.chainHead && (
              <p className="text-sm text-muted-foreground">
                Chain data will appear once the demo runs.
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">Participants</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {[
              { initials: "A", name: "Alice", role: "Sender", color: "bg-blue-500" },
              { initials: "B", name: "Bob", role: "Relay", color: "bg-amber-500" },
              { initials: "C", name: "Carol", role: "Recipient", color: "bg-green-500" },
            ].map((p) => (
              <div key={p.initials} className="flex items-center gap-2">
                <div
                  className={`${p.color} flex h-6 w-6 items-center justify-center rounded-full text-[10px] font-bold text-white`}
                >
                  {p.initials}
                </div>
                <span className="text-sm font-medium">{p.name}</span>
                <span className="text-xs text-muted-foreground">
                  ({p.role})
                </span>
              </div>
            ))}
          </CardContent>
        </Card>
      </aside>
    </div>
  );
}
