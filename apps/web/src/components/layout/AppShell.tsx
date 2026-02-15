import type { ReactNode } from "react";

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="dark min-h-screen bg-background text-foreground">
      <div className="mx-auto max-w-5xl px-4 py-6">{children}</div>
    </div>
  );
}
