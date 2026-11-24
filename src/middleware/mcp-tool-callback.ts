/**
 * Register a middleware-wrapped handler with the MCP SDK's `registerTool`.
 *
 * A {@link KyaOsToolHandler} takes `(args, sessionId?, context?)`; the SDK
 * calls a tool callback with `(args, extra)`, where `extra` is its own request
 * context. Passed straight in, the handler needs a cast, and the SDK's context
 * then arrives as the KYA-OS session id: no session matches it, and the
 * result goes out unproven. The adapter passes the arguments, and the call's
 * `params._meta` as the call context's `requestMeta`, which the SDK hands it
 * as `extra._meta` (SDK 1) or `extra.mcpReq._meta` (SDK 2). The wrappers read
 * from it the KYA-OS data SPEC.md §14 puts there. The session it names is the
 * caller's claim, so it is never threaded as the session id argument: a host
 * threads only a session it has established itself, and only such a session
 * carries a session-bound grant. The SDK's transport session id is a
 * different thing from a KYA-OS session id, so it is not forwarded.
 *
 * Typed structurally, so this package keeps no type dependency on the SDK.
 */

import { requestMetaOf } from "./request-meta.js";
import type { KyaOsToolHandler } from "./with-kya-os.types.js";

/** A tool result in the shape the MCP SDK's `registerTool` callback returns. */
export interface McpToolCallbackResult {
  content: Array<{ type: "text"; text: string; [key: string]: unknown }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
  _meta?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * A callback for a tool registered with an `inputSchema` (an empty one for a
 * tool without arguments): the SDK calls it with the parsed arguments and its
 * request context.
 */
export type McpToolCallback<T extends Record<string, unknown> = Record<string, unknown>> = (
  args: T,
  extra: unknown,
) => Promise<McpToolCallbackResult>;

/**
 * Adapt a handler (one from `wrapWithProof`, `wrapWithDelegation`,
 * `withPolicyGate`, or one returning `proveOutcome`'s result) to the MCP
 * SDK's `registerTool`, with no cast:
 *
 * ```ts
 * server.registerTool('checkout', { inputSchema }, toMcpToolCallback(gated));
 * ```
 *
 * The handler's result is returned as it is; the SDK validates it. Called
 * with one argument, which is how the SDK calls a tool registered without an
 * `inputSchema`, the handler gets empty arguments instead of the SDK's
 * request context.
 */
export function toMcpToolCallback<T extends Record<string, unknown> = Record<string, unknown>>(
  handler: KyaOsToolHandler<T>,
): McpToolCallback<T> {
  return async (...params: [T, unknown?]) => {
    const args = params.length > 1 ? params[0] : ({} as T);
    const extra = params.length > 1 ? params[1] : params[0];
    const requestMeta = requestMetaOf(extra);
    // KyaOsToolHandler types content items' `type` as string; the SDK checks
    // the result it receives, so the narrower declared type is not a claim
    // this adapter has to prove.
    if (requestMeta === undefined) return (await handler(args)) as McpToolCallbackResult;
    return (await handler(args, undefined, { requestMeta })) as McpToolCallbackResult;
  };
}
