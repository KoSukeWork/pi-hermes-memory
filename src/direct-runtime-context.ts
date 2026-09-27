import type { ExtensionContext } from "@earendil-works/pi-coding-agent";

export type DirectRuntimeContext = Pick<ExtensionContext, "model" | "modelRegistry"> & Partial<Pick<ExtensionContext, "sessionManager">>;

let current: DirectRuntimeContext | null = null;

function hasModelRegistry(ctx: object): ctx is DirectRuntimeContext {
  return "modelRegistry" in ctx && (ctx as { modelRegistry?: unknown }).modelRegistry != null;
}

/** Remember the live session model registry for overflow consolidation. */
export function rememberDirectRuntimeContext(ctx: unknown): void {
  if (!ctx || typeof ctx !== "object" || !hasModelRegistry(ctx)) return;
  current = {
    model: (ctx as DirectRuntimeContext).model,
    modelRegistry: (ctx as DirectRuntimeContext).modelRegistry,
  };
  if ("sessionManager" in ctx && (ctx as DirectRuntimeContext).sessionManager) {
    current.sessionManager = (ctx as DirectRuntimeContext).sessionManager;
  }
}

export function getDirectRuntimeContext(): DirectRuntimeContext | null {
  return current;
}

export function clearDirectRuntimeContext(): void {
  current = null;
}
