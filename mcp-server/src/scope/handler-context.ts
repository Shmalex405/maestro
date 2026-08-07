import { AsyncLocalStorage } from "async_hooks";

// Per-call handler context, set by the tool dispatcher AFTER scope validation
// passes and BEFORE the handler runs. Lets a tool handler reach the validated
// in-scope identity_target object (from scope.yml) so it can resolve named
// credential refs (e.g. sa_key_ref) and per-target fields (delegated_subject)
// without the LLM having to pass them as arguments. Mirrors the provenance
// AsyncLocalStorage in logging/tool-provenance.ts.

export interface HandlerContext {
  /** The full matched identity_target object for this tool call, if the call
   *  was scope-validated against the identity dimension. */
  identity_target?: any;
  /** The full matched ai_target object for this tool call, if the call was
   *  scope-validated against the AI dimension. Lets an AI tool reach the
   *  validated target's endpoint / model / declared_tools / credential_ref
   *  without the LLM re-passing them. */
  ai_target?: any;
}

export const handlerContext = new AsyncLocalStorage<HandlerContext>();

export function getHandlerContext(): HandlerContext {
  return handlerContext.getStore() ?? {};
}

export function runWithHandlerContext<T>(ctx: HandlerContext, fn: () => T): T {
  return handlerContext.run(ctx, fn);
}
