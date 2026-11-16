/**
 * KYA-OS Middleware: the DID resolver the delegation gate verifies with. It asks the host's own
 * resolver first, then the resolver `delegation.didResolvers` configures for the DID's method, then
 * the built-in did:key and did:web resolvers, the network ones only while the verifier's deadline
 * holds. For each DID it reports the failure the last resolver it asked reported, so that a
 * refusal of the DID as unresolvable says why.
 */

import { DidResolutionFailures, reportedFailure } from "../delegation/did-resolution-failure.js";
import type { DIDDocument, DIDResolver } from "../delegation/vc-verifier.js";
import { getDidMethod } from "../utils/did-helpers.js";

/** The resolvers the gate's resolver asks, in the order it asks them, and the verifier's deadline. */
export interface GateDidResolvers {
  /** The host's own resolver, `delegation.didResolver`, asked first. */
  readonly custom?: DIDResolver;
  /** The resolvers `delegation.didResolvers` configures, by DID method. */
  readonly configured: Readonly<Record<string, DIDResolver>>;
  /** The built-in did:key resolver. */
  readonly didKey: DIDResolver;
  /** The built-in did:web resolver, when the middleware has a fetch provider to build it on. */
  readonly didWeb?: DIDResolver;
  /** How long the verifier waits on one resolution; no network resolver is asked once it has passed. */
  readonly dependencyTimeoutMs: number;
}

/** The gate's DID resolver over `resolvers`, with `lastFailure` reporting why it last found no document for a DID. */
export function createGateDidResolver(resolvers: GateDidResolvers): DIDResolver {
  const { custom, configured, didKey, didWeb, dependencyTimeoutMs } = resolvers;
  const failures = new DidResolutionFailures();

  /** `document`, after recording for `did` the failure `asked`, the last resolver asked, reports when it is `null`. */
  const answer = (did: string, asked: DIDResolver | undefined, document: DIDDocument | null): DIDDocument | null => {
    const failure = document === null && asked !== undefined ? reportedFailure(asked, did) : undefined;
    if (failure === undefined) failures.clear(did);
    else failures.record(did, failure);
    return document;
  };

  return {
    async resolve(did: string) {
      // The verifier stops waiting at its deadline, so no further resolver is asked once it has passed.
      const deadline = Date.now() + dependencyTimeoutMs;
      let asked: DIDResolver | undefined;
      if (custom) {
        asked = custom;
        const resolved = await custom.resolve(did);
        if (resolved) return answer(did, custom, resolved);
      }

      const method = getDidMethod(did);
      const configuredResolver = method && Date.now() < deadline ? configured[method] : undefined;
      if (configuredResolver) {
        try {
          asked = configuredResolver;
          const resolved = await configuredResolver.resolve(did);
          if (resolved) return answer(did, configuredResolver, resolved);
        } catch {
          return answer(did, undefined, null);
        }
      }

      if (did.startsWith("did:key:")) {
        return answer(did, didKey, await didKey.resolve(did));
      }

      if (didWeb && did.startsWith("did:web:") && Date.now() < deadline) {
        return answer(did, didWeb, (await didWeb.resolve(did)) ?? null);
      }

      return answer(did, asked, null);
    },
    lastFailure: (did: string) => failures.get(did),
  };
}
