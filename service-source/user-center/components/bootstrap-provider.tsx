"use client";

import { createContext, useContext } from "react";
import type { BootstrapData } from "@/lib/api/server";

const BootstrapContext = createContext<BootstrapData | null>(null);

/**
 * Wraps the protected layout tree with the server-fetched bootstrap data
 * so client components can read it without triggering additional fetches.
 */
export function BootstrapProvider({
  data,
  children,
}: {
  data: BootstrapData;
  children: React.ReactNode;
}) {
  return (
    <BootstrapContext.Provider value={data}>
      {children}
    </BootstrapContext.Provider>
  );
}

export function useBootstrap(): BootstrapData {
  const ctx = useContext(BootstrapContext);
  if (!ctx) {
    throw new Error("useBootstrap must be used inside BootstrapProvider");
  }
  return ctx;
}
