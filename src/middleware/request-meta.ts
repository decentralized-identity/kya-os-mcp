/**
 * Where a `tools/call` of the session profile carries what KYA-OS reads of it (SPEC.md §14): each
 * datum rides the call's `params._meta` under a key of its own, outside the tool's arguments and
 * outside every request hash (SPEC.md §7.3 rule 1).
 *
 * For the 1.x line a server also reads the `_kyaos_*` arguments 1.x clients send. A call that
 * carries a datum both ways is read from `params._meta`, and its argument is not read.
 */

import { isRecord } from "../utils/guards.js";

/** The session the call belongs to: the `sessionId` its handshake returned. */
export const KYA_OS_SESSION_META_KEY = "org.kya-os/session";

/** The SPEC.md §6.2 delegation credential the call presents, as its issuer signed it: an object, or a VC-JWT. */
export const KYA_OS_DELEGATION_META_KEY = "org.kya-os/delegation-credential";

/** The holder-of-key request proof (SPEC.md §11.8) its delegate signs over the call. */
export const KYA_OS_HOLDER_PROOF_META_KEY = "org.kya-os/holder-proof";

/** The approval grants a call resuming a step-up presents (SPEC.md §9.3). */
export const KYA_OS_APPROVALS_META_KEY = "org.kya-os/approvals";

/** The 1.x argument each datum was carried in before it had a `params._meta` key. */
const LEGACY_ARGUMENTS = {
  [KYA_OS_DELEGATION_META_KEY]: "_kyaos_delegation",
  [KYA_OS_HOLDER_PROOF_META_KEY]: "_kyaos_proof",
  [KYA_OS_APPROVALS_META_KEY]: "_kyaos_approvals",
} as const;

/** A datum a call can carry in its arguments as well as in `params._meta`. */
export type CarriedDatum = keyof typeof LEGACY_ARGUMENTS;

/**
 * The `params._meta` of a call, from the request context the MCP SDK hands a tool callback:
 * `extra._meta` (SDK 1), or `ctx.mcpReq._meta` (SDK 2). `undefined` when it holds none.
 */
export function requestMetaOf(extra: unknown): Readonly<Record<string, unknown>> | undefined {
  if (!isRecord(extra)) return undefined;
  if (isRecord(extra._meta)) return extra._meta;
  return isRecord(extra.mcpReq) && isRecord(extra.mcpReq._meta) ? extra.mcpReq._meta : undefined;
}

/** The session `meta` names, or `undefined` when it names none as a non-empty string. */
export function sessionNamedIn(meta: Readonly<Record<string, unknown>> | undefined): string | undefined {
  const session = meta?.[KYA_OS_SESSION_META_KEY];
  return typeof session === "string" && session.length > 0 ? session : undefined;
}

/** Whether `meta` carries `datum`: it has the member, whatever its value, `null` included. */
export function metaCarries(meta: Readonly<Record<string, unknown>> | undefined, datum: CarriedDatum): boolean {
  return meta !== undefined && Object.hasOwn(meta, datum) && meta[datum] !== undefined;
}

/**
 * What a call carries of `datum`: its `params._meta` member when it has one, `null` included, or
 * else, for the 1.x line, the `_kyaos_*` argument it was carried in. `undefined` when neither holds it.
 */
export function carried(
  datum: CarriedDatum,
  args: Readonly<Record<string, unknown>>,
  meta: Readonly<Record<string, unknown>> | undefined,
): unknown {
  return metaCarries(meta, datum) ? meta![datum] : args[LEGACY_ARGUMENTS[datum]];
}
