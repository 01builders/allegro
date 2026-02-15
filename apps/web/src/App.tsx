import { useEffect, useState } from "react";
import { AppShell } from "@/components/layout/AppShell";
import { Header } from "@/components/layout/Header";
import { ConnectButton } from "@/components/ConnectButton";
import { PaymentForm } from "@/components/PaymentForm";
import { NetworkStatus } from "@/components/NetworkStatus";
import { TxTracker } from "@/components/TxTracker";
import { ChainedDemoPage } from "@/components/ChainedDemoPage";

type Page = "pay" | "demo";

function pageFromHash(): Page {
  return window.location.hash === "#demo" ? "demo" : "pay";
}

export default function App() {
  const [page, setPage] = useState<Page>(pageFromHash);
  const [activeTxHash, setActiveTxHash] = useState<string | null>(null);

  useEffect(() => {
    const onHashChange = () => setPage(pageFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  return (
    <AppShell>
      <Header page={page}>
        <ConnectButton />
      </Header>

      {page === "demo" ? (
        <ChainedDemoPage />
      ) : (
        <div className="grid gap-6 md:grid-cols-[1.2fr_0.8fr]">
          <div className="space-y-6">
            <PaymentForm onTxHash={setActiveTxHash} />
          </div>

          <aside className="space-y-6">
            <NetworkStatus />
            <TxTracker txHash={activeTxHash} />
          </aside>
        </div>
      )}
    </AppShell>
  );
}
