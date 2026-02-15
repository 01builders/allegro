import { useState } from "react";
import { AppShell } from "@/components/layout/AppShell";
import { Header } from "@/components/layout/Header";
import { ConnectButton } from "@/components/ConnectButton";
import { PaymentForm } from "@/components/PaymentForm";
import { NetworkStatus } from "@/components/NetworkStatus";
import { TxTracker } from "@/components/TxTracker";

export default function App() {
  const [activeTxHash, setActiveTxHash] = useState<string | null>(null);

  return (
    <AppShell>
      <Header>
        <ConnectButton />
      </Header>

      <div className="grid gap-6 md:grid-cols-[1.2fr_0.8fr]">
        <div className="space-y-6">
          <PaymentForm onTxHash={setActiveTxHash} />
        </div>

        <aside className="space-y-6">
          <NetworkStatus />
          <TxTracker txHash={activeTxHash} />
        </aside>
      </div>
    </AppShell>
  );
}
