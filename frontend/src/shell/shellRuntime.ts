import { createContext, useContext } from "react";

import type { createConsoleClient } from "../lib/apiClient";


export type OperatorShellContext = {
  readonly schema_version: "1";
  readonly environment: "local" | "production" | "unknown";
  readonly safety_profile: "synthetic-local" | "local-conformance" | "production" | "unknown";
  readonly status: "ready" | "unknown" | "unavailable";
};

export type GeneratedConsoleContext = Awaited<
  ReturnType<ReturnType<typeof createConsoleClient>["getContext"]>
>;

export type ConsoleContext = GeneratedConsoleContext & {
  readonly operator_shell?: OperatorShellContext;
};

export type ConsoleClient = ReturnType<typeof createConsoleClient>;

export type ShellRuntime = {
  readonly campaignCreateEnabled: boolean;
  readonly client: ConsoleClient;
  readonly context: ConsoleContext;
  readonly navigate: (path: string) => boolean;
  readonly path: string;
};

export const ShellRuntimeContext = createContext<ShellRuntime | null>(null);

export function useShellRuntime(): ShellRuntime {
  const runtime = useContext(ShellRuntimeContext);
  if (runtime === null) throw new Error("shell_runtime_required");
  return runtime;
}
