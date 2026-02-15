import type { ReactNode } from "react";
import { Separator } from "@/components/ui/separator";

type Page = "pay" | "demo";

export function Header({
  page,
  children,
}: {
  page?: Page;
  children?: ReactNode;
}) {
  return (
    <>
      <header className="flex items-center justify-between py-4">
        <div className="flex items-center gap-6">
          <div>
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Allegro
            </p>
            <h1 className="text-2xl font-bold tracking-tight">FastPay</h1>
          </div>
          {page && (
            <nav className="flex gap-1">
              <a
                href="#pay"
                className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                  page === "pay"
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                Payment
              </a>
              <a
                href="#demo"
                className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                  page === "demo"
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                Chained Demo
              </a>
            </nav>
          )}
        </div>
        {children}
      </header>
      <Separator className="mb-6" />
    </>
  );
}
