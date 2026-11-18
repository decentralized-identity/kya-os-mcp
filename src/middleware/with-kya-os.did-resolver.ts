/**
 * KYA-OS Middleware: the DID resolver the delegation gate verifies with. It asks the host's own
 * resolver first, then the resolver `delegation.didResolvers` configures for the DID's method, then
 * the built-in did:key and did:web resolvers, the network ones only while the verifier's deadline
 * holds, and goes on to the next whenever one finds no document. For each DID it reports the
 * failure of the first resolver it asked that reported one, so a refusal of the DID as unresolvable
 * shows the failure of a resolver the host chose before one of the gate's own, as
 * `DIDResolver.lastFailure` documents. A reported failure is a diagnosis: it never stops the
 * resolvers after it from being asked. A DID of a method none of them serves, with no resolver of
 * the host's to ask, is `invalid_document`: asking again cannot change that.
 */

import { DidResolutionFailures, reportedFailure, unservedMethod } from "../delegation/did-resolution-failure.js";
import type { DIDDocument, DIDResolver, DidResolutionFailure } from "../delegation/vc-verifier.js";
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

  /**
   * The resolver `delegation.didResolvers` configures for `method`, when the registry holds one as
   * its own: a name only an object's prototype holds, such as `constructor`, names none.
   */
  const configuredFor = (method: string | null): DIDResolver | undefined =>
    method !== null && Object.hasOwn(configured, method) ? configured[method] : undefined;

  /** Whether a resolver other than the host's own serves `did`'s method, `method`, deadline or not. */
  const serves = (did: string, method: string | null): boolean =>
    configuredFor(method) !== undefined ||
    did.startsWith("did:key:") ||
    (didWeb !== undefined && did.startsWith("did:web:"));

  return {
    async resolve(did: string) {
      // The verifier stops waiting at its deadline, so no further resolver is asked once it has passed.
      const deadline = Date.now() + dependencyTimeoutMs;
      // The failure of the first resolver asked that reported one, which a later one's never replaces.
      let failure: DidResolutionFailure | undefined;

      /** The document `resolver` finds for `did`, or `null`, noting the failure it reports for none. */
      const ask = async (resolver: DIDResolver): Promise<DIDDocument | null> => {
        const document = await resolver.resolve(did);
        if (document) return document;
        failure ??= reportedFailure(resolver, did);
        return null;
      };

      /** `document`, after recording for `did` the failure noted when it is `null`, or clearing it. */
      const settle = (document: DIDDocument | null): DIDDocument | null => {
        if (document === null && failure !== undefined) failures.record(did, failure);
        else failures.clear(did);
        return document;
      };

      if (custom) {
        const resolved = await ask(custom);
        if (resolved) return settle(resolved);
      }

      const method = getDidMethod(did);
      const configuredResolver = Date.now() < deadline ? configuredFor(method) : undefined;
      if (configuredResolver) {
        try {
          const resolved = await ask(configuredResolver);
          if (resolved) return settle(resolved);
        } catch {
          return settle(null);
        }
      }

      if (did.startsWith("did:key:")) {
        return settle(await ask(didKey));
      }

      if (didWeb && did.startsWith("did:web:") && Date.now() < deadline) {
        return settle(await ask(didWeb));
      }

      if (custom === undefined && !serves(did, method)) {
        failure = unservedMethod("the delegation gate", did);
      }
      return settle(null);
    },
    lastFailure: (did: string) => failures.get(did),
  };
}
