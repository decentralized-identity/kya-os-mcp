/**
 * The request a proof's `requestHash` covers (SPEC §7.3), and the shapes of
 * one tool call a verifier accepts it for.
 *
 * SPEC §7.3 covers the JSON-RPC request the client actually sends, so anyone
 * holding the wire message can recompute the hash: the `tools/call` message's
 * `{ method, params }` with the members that cannot be signed taken out.
 * `params._meta` is intermediary-mutable transport metadata, and the
 * `_kyaos`-prefixed control arguments carry the credentials that authorize the
 * call (a delegation, the holder-binding proof, approval grants); two of those
 * are themselves bound to this hash, so covering them would make the hash
 * depend on its own output.
 *
 * Producers in 1.x still hash the legacy shape `{ method: <tool name>, params:
 * <arguments> }`, so verifiers already deployed keep accepting their proofs.
 * Verifiers accept a hash of either shape of the same call (see
 * {@link alternateRequestShapes}); producers switch to the §7.3 shape in 2.0.0.
 */

import type { ToolRequest } from './generator.js';

/** JSON-RPC method of an MCP tool invocation. */
const TOOLS_CALL_METHOD = 'tools/call';

/**
 * The control-arg key prefix. Args beginning with this are protocol envelope
 * (`_kyaos_delegation`, `_kyaos_proof`, `_kyaos_approvals`), not the caller's
 * tool intent.
 */
const KYAOS_CONTROL_PREFIX = '_kyaos';

/**
 * Whether an argument key is reserved KYA-OS protocol envelope (`_kyaos*`:
 * `_kyaos_delegation`, `_kyaos_proof`, `_kyaos_approvals`, …) rather than caller
 * tool intent. The SINGLE predicate behind both the request hash and the
 * middleware's handler-arg stripping, so the set excluded from the bound hash
 * and the set withheld from the handler cannot drift — a proof binds exactly the
 * call the handler runs.
 */
export function isKyaOsControlArg(key: string): boolean {
  return key.startsWith(KYAOS_CONTROL_PREFIX);
}

/** A tool call read from either request shape. */
interface ToolCall {
  name: string;
  /** The call's arguments: `params.arguments`, `{}` when absent. */
  args: Record<string, unknown>;
  /** The `tools/call` params as sent, or as the legacy shape implies them. */
  params: Record<string, unknown>;
}

/**
 * The other shapes of the call `request` describes, whose `requestHash` a
 * verifier accepts as well as the hash of `request` itself. A caller may hold
 * the call in either shape: the legacy shape `{ method: <tool name>, params:
 * <arguments> }` that 1.x producers sign, or the `tools/call` request as sent.
 * From either, this yields the SPEC §7.3 covered request and the legacy shape
 * with the arguments as given and with the control args removed: 1.x
 * producers differ in whether control args stay in the legacy shape (the
 * holder-binding request, the step-up hash and wrapped handlers drop them, a
 * proof added at the transport keeps them).
 *
 * Every shape describes the same tool name and business arguments, so
 * accepting any of them binds the same call. The legacy shape keeps its known
 * ambiguities for the 1.x line: a tool named after a JSON-RPC method hashes
 * like that method's request, and `params` members other than the arguments
 * are not covered.
 */
export function alternateRequestShapes(request: ToolRequest): ToolRequest[] {
  const call = asToolCall(request);
  if (call === undefined) return [];
  const legacy = (args: Record<string, unknown>): ToolRequest => ({
    method: call.name,
    params: args,
  });
  return [
    coveredToolCall(call),
    legacy(call.args),
    legacy(withoutKeys(call.args, isKyaOsControlArg)),
  ];
}

/**
 * Read a tool call's name and arguments from either shape. A `tools/call`
 * whose params carry a string `name` is the wire shape; any other request is
 * read as the legacy shape, its method being the tool name. Arguments that are
 * not an object describe no tool call, so they yield no alternate shapes. An
 * absent `arguments` is read as `{}`: MCP clients may omit it for a call
 * without arguments, and a server cannot tell the two apart.
 */
function asToolCall(request: ToolRequest): ToolCall | undefined {
  const { method, params } = request;
  if (method === TOOLS_CALL_METHOD && isJsonObject(params) && typeof params['name'] === 'string') {
    const args = params['arguments'] ?? {};
    return isJsonObject(args) ? { name: params['name'], args, params } : undefined;
  }
  const args = params ?? {};
  return isJsonObject(args)
    ? { name: method, args, params: { name: method, arguments: args } }
    : undefined;
}

/**
 * The SPEC §7.3 covered request for a tool call: its `tools/call` params
 * without the top-level `_meta` member, and its arguments without the control
 * args. Every other params member stays covered, and nothing nested deeper is
 * touched, so signer and verifier derive the same request.
 */
function coveredToolCall(call: ToolCall): ToolRequest {
  const params = withoutKeys(call.params, (key) => key === '_meta');
  params['arguments'] = withoutKeys(call.args, isKyaOsControlArg);
  return { method: TOOLS_CALL_METHOD, params };
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// Object.fromEntries defines own properties, so a received `__proto__` member
// stays a member instead of becoming the copy's prototype.
function withoutKeys(
  value: Record<string, unknown>,
  drop: (key: string) => boolean,
): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([key]) => !drop(key)));
}
