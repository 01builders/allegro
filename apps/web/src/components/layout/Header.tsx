import type { ReactNode } from "react";
import { Separator } from "@/components/ui/separator";

export function Header({ children }: { children?: ReactNode }) {
  return (
    <>
      <header className="flex items-center justify-between py-4">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Allegro
          </p>
          <h1 className="text-2xl font-bold tracking-tight">FastPay</h1>
        </div>
        {children}
      </header>
      <Separator className="mb-6" />
    </>
  );
}
