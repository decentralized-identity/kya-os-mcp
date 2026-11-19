/**
 * KYA-OS Middleware - the records of a presented delegation.
 *
 * A call that presents a delegation is recorded in the audit trail's
 * authorization evidence by the reference and the digests of SPEC §7.8,
 * derived here. Authenticating the presentation is
 * `./with-kya-os.delegation-verify.ts`; this module only describes what that
 * found.
 */

import { delegationChainDigest, delegationCredentialDigest, type ReceivedCredential } from "../delegation/chain-digest.js";
import { delegationRefOf } from "../delegation/delegation-ref.js";
import { NoSignedFormError } from "../delegation/signed-form.js";
import type { AuthorizationEvidence, Digest } from "../audit/types.js";
import { logger } from "../logging/index.js";
import type { MiddlewareDeps } from "./with-kya-os.deps.js";

/** The audit event schema admits at most this many `delegationChainDigests`. */
const MAX_AUDITED_CHAIN_DIGESTS = 256;

/**
 * Whether this server records a chain beyond the presented credential's own
 * digest: in the audit trail (each credential's, and a refusal's). Without
 * one, nothing more is digested than a call needed before chains were
 * recorded. What is read, and the verdict on it, are the same either way.
 */
export function recordsChainDigests(deps: Pick<MiddlewareDeps, "audit">): boolean {
  return deps.audit !== undefined;
}

/** How the audit trail refers to the delegation a call presented. */
export interface DelegationRecords {
  /**
   * For the audit trail: the presented credential's reference and its
   * digest, on the gate's events and in the context it hands the handler.
   */
  evidence: Pick<AuthorizationEvidence, "delegationRef" | "delegationCredentialDigest">;
  /**
   * For the audit events that record a verdict on the call: the digest of
   * each credential evaluated, root first. It is recorded there and not
   * carried with the call, since a chain may be long.
   */
  chainEvidence: Pick<AuthorizationEvidence, "delegationChainDigests">;
}

/** What was presented, as authentication found it. */
export interface Presentation {
  /**
   * The credential as presented, read once: an object, or a VC-JWT by its
   * string, the form its signature covers. Absent when it was not read as a
   * credential: of a value that is not plain data nothing is read, and of
   * one that nests too deep, `shown`.
   */
  presented?: unknown;
  /**
   * Of a presented credential object that nests deeper than a credential may
   * (SPEC §7.8), what the walk that refused it read of where it shows its
   * id. It is named by that id, and has no signed form, so no digest.
   */
  shown?: Record<string, unknown>;
  /**
   * The ancestors the chain walk examined before its verdict, root first,
   * each as the walk read it. On a refusal the walk may have stopped short
   * of some; those are not here, and nothing is recorded of them.
   */
  ancestors: readonly unknown[];
  /**
   * Set on a refusal for a value a resolver returned that could not be read:
   * one that is not plain data, or that nests deeper than a credential may
   * (SPEC §7.8). There is then no digest of the chain.
   */
  unreadAncestor?: true;
  /** Whether the chain verified. */
  verified: boolean;
}

export interface DelegationDescriber {
  /**
   * Both records of a presentation.
   *
   * A verified presentation always gets its reference and its own digest.
   * The digests of its ancestors are made when the audit trail carries them.
   * A refused presentation is described where it can be.
   *
   * @throws when `verified` and a record cannot be made (a failing hash
   *   provider): a verified call that cannot be tied to its chain must not
   *   be allowed. It never throws for a refusal.
   */
  describe(presentation: Presentation): Promise<DelegationRecords>;
  /**
   * The digest of the chain a verified presentation was evaluated as (SPEC
   * §7.8): its ancestors, root first, then the presented credential. It is
   * made only when asked, as for a call whose holder proof names a chain, so
   * a server that records no chain digests nothing more for any other call.
   */
  chainDigest(presentation: Pick<Presentation, "presented" | "ancestors">): Promise<Digest>;
}

/** What was digested of a presentation. */
interface Digests {
  /** Of the presented credential. */
  presented: Digest;
  /** Of every credential examined, root first, the presented one last. */
  evaluated?: Digest[];
}

export function createDelegationDescriber(
  deps: Pick<MiddlewareDeps, "cryptoProvider" | "audit">,
): DelegationDescriber {
  const { cryptoProvider } = deps;
  const recordsDigests = recordsChainDigests(deps);
  const hash = (bytes: Uint8Array): Promise<string> => cryptoProvider.hash(bytes);

  const digestOf = (credential: unknown): Promise<Digest> =>
    delegationCredentialDigest(credential as ReceivedCredential, hash);

  /**
   * The digests of a chain's credentials: of each ancestor examined, then the
   * presented credential's, which is given. The presented credential is
   * digested on its own, before this and not here, so its digest does not
   * depend on its ancestors having one.
   */
  async function chainDigestsOf(ancestors: readonly unknown[], presented: Digest): Promise<Digest[]> {
    const credentials: Digest[] = [];
    for (const ancestor of ancestors) credentials.push(await digestOf(ancestor));
    credentials.push(presented);
    return credentials;
  }

  function recordsOf(reference: string | undefined, digests: Digests | undefined): DelegationRecords {
    const named = reference === undefined ? {} : { delegationRef: reference };
    const evaluated = digests?.evaluated;
    return {
      evidence: {
        ...named,
        ...(digests === undefined ? {} : { delegationCredentialDigest: digests.presented }),
      },
      // Past the schema's bound the list is left out, never cut.
      chainEvidence:
        evaluated !== undefined && evaluated.length <= MAX_AUDITED_CHAIN_DIGESTS
          ? { delegationChainDigests: evaluated }
          : {},
    };
  }

  /**
   * A record of a refusal, or nothing where it cannot be made. A value with
   * no signed form was no credential: there is nothing to digest, and
   * nothing went wrong. Anything else that keeps a record unmade did go
   * wrong, and is logged.
   */
  async function attempt<T>(record: () => Promise<T>): Promise<T | undefined> {
    try {
      return await record();
    } catch (error) {
      if (!(error instanceof NoSignedFormError)) {
        logger.error("[kya-os] A refused delegation could not be described in full", {
          error: error instanceof Error ? error.message : String(error),
        });
      }
      return undefined;
    }
  }

  /** A refusal's records: what can be said of what was presented. A fault that keeps some of it unsaid is logged. */
  async function describeRefused(
    presented: unknown,
    ancestors: readonly unknown[],
    unreadAncestor: boolean,
  ): Promise<DelegationRecords> {
    const reference = await attempt(() => delegationRefOf(presented, hash));
    // The presented credential's digest is its own. Where an ancestor the
    // walk examined has no signed form, or a value a resolver returned could
    // not be read and so has none the server can take, there is no digest of
    // the chain (SPEC §7.8). The audit trail still says which credential was
    // presented.
    const own = recordsDigests ? await attempt(() => digestOf(presented)) : undefined;
    const evaluated =
      own === undefined || unreadAncestor ? undefined : await attempt(() => chainDigestsOf(ancestors, own));
    const digests: Digests | undefined =
      own === undefined ? undefined : { presented: own, ...(evaluated === undefined ? {} : { evaluated }) };
    return recordsOf(reference, digests);
  }

  async function describe({ presented, shown, ancestors, unreadAncestor, verified }: Presentation): Promise<DelegationRecords> {
    if (presented === undefined) {
      const reference = shown === undefined ? undefined : await attempt(() => delegationRefOf(shown, hash));
      return recordsOf(reference, undefined);
    }
    if (!verified) return describeRefused(presented, ancestors, unreadAncestor === true);
    const reference = await delegationRefOf(presented, hash);
    const own = await digestOf(presented);
    return recordsOf(reference, {
      presented: own,
      ...(recordsDigests ? { evaluated: await chainDigestsOf(ancestors, own) } : {}),
    });
  }

  async function chainDigest({ presented, ancestors }: Pick<Presentation, "presented" | "ancestors">): Promise<Digest> {
    return delegationChainDigest(await chainDigestsOf(ancestors, await digestOf(presented)), hash);
  }

  return { describe, chainDigest };
}
