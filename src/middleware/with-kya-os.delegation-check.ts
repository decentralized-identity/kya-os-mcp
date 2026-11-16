/**
 * KYA-OS Middleware - the check of a presented delegation.
 *
 * What a caller presents is read here once, and the signature check, the
 * chain walk and the digest all take that one reading, so nothing can verify
 * as one thing and be digested as another (SPEC §7.8). The check is the
 * verdict on what was presented together with the records of it
 * (`./with-kya-os.delegation-records.ts`). Authenticating it is
 * `./with-kya-os.delegation-verify.ts`.
 */

import {
  MAX_CREDENTIAL_NESTING_DEPTH,
  NoSignedFormError,
  canonicalVcJwt,
} from "../delegation/signed-form.js";
import type { DelegationCredentialVerifier } from "../delegation/vc-verifier.js";
import type {
  DelegationVCVerificationResult,
  VerifyDelegationVCOptions,
} from "../delegation/vc-verifier.types.js";
import { DELEGATION_ID_LEVELS } from "../delegation/delegation-id.js";
import type { DelegationCredential } from "../types/protocol.js";
import { copyPlainData } from "../utils/plain-data.js";
import { logger } from "../logging/index.js";
import type { DelegationDescriber, DelegationRecords } from "./with-kya-os.delegation-records.js";

/** A presented delegation as authenticated. */
export type Verdict =
  | { valid: true; vc: DelegationCredential; isJwt: boolean; expiresAt?: number }
  | { valid: false; reason: string; vc?: DelegationCredential };

/** A verdict, with what it was reached on. */
export interface Authenticated {
  verdict: Verdict;
  /** The ancestors the chain walk examined before the verdict, root first, as it read them. */
  ancestors: readonly unknown[];
  /** Set when a value the resolver returned could not be read (see {@link readOnce}). */
  unreadAncestor?: true;
}

/**
 * Outcome of authenticating a presented delegation. On success the caller gets
 * the normalized credential and its wire form; on failure a sanitizable reason
 * plus the best-effort parsed credential, if any. Either way it carries the
 * {@link DelegationRecords} of what was presented: on a refusal they describe
 * a credential that did not verify, or a chain that was refused.
 */
export type DelegationCheck = Verdict & DelegationRecords;

const NOT_PLAIN_DATA = "is not plain data";
const NESTS_TOO_DEEP = `nests more than ${MAX_CREDENTIAL_NESTING_DEPTH} levels deep` as const;

/** A value that was not read as a credential, and why. */
export type NotRead =
  | { unread: typeof NOT_PLAIN_DATA }
  | {
      unread: typeof NESTS_TOO_DEEP;
      /** What the walk that refused it read of where a credential shows its id. */
      shown?: Record<string, unknown>;
    };

/**
 * A value handed over as a credential, as this server reads it: once, as
 * plain data. Everything after this, the signature check and the digest
 * alike, reads the copy.
 *
 * That holds on every server, whatever it records, so the verdict on a value
 * is the same with an audit trail and without one.
 *
 * - A value that is not plain data is not read at all. A copy would make
 *   data of it (the answer a getter gave when it was copied, the members of a
 *   class instance without its class), and a credential would then verify, or
 *   not, on what the copy made of it and not on what it is.
 * - Plain data nested deeper than a credential may be (SPEC §7.8) has no
 *   signed form. It is counted before it is copied, since a copy recurses,
 *   and it is not copied. What the same walk read of where a credential
 *   shows its id is kept, as `shown`, and nothing else of it is read.
 * - A Proxy looks like whatever it answers, so the tests above cannot tell
 *   one. The copy refuses it.
 *
 * One walk settles the first two (`copyPlainData`). Nothing here runs an
 * accessor, and nothing recurses.
 */
export function readOnce(value: unknown): { copy: unknown } | NotRead {
  const read = copyPlainData(value, MAX_CREDENTIAL_NESTING_DEPTH, DELEGATION_ID_LEVELS);
  if ("copy" in read) return read;
  if (read.refused === "not plain data") return { unread: NOT_PLAIN_DATA };
  return { unread: NESTS_TOO_DEEP, ...(read.top === undefined ? {} : { shown: read.top }) };
}

/**
 * A VC-JWT's envelope, verified by `verifier` as `verifyDelegationJwt` does,
 * with the stage a refusal came at.
 *
 * The JWS is handed over with its signature segment written canonically,
 * so the bytes the envelope check reads are the ones the chain digest
 * hashes (SPEC §7.8). A third segment that has no such reading is
 * handed over as it came, for the JWS library to refuse in its own
 * words: the two read a segment alike. Were the library ever to read
 * a signature where this reading has none, nothing it verified could be
 * digested, so that verdict is not taken: it is refused at the signature.
 */
export async function verifyEnvelope(
  verifier: Pick<DelegationCredentialVerifier, "verifyDelegationJwt">,
  jwt: string,
  options: VerifyDelegationVCOptions,
): Promise<Pick<DelegationVCVerificationResult, "valid" | "reason" | "stage">> {
  let envelopeJwt: string | undefined;
  try {
    envelopeJwt = canonicalVcJwt(jwt);
  } catch (error) {
    if (!(error instanceof NoSignedFormError)) throw error;
  }
  const checked = await verifier.verifyDelegationJwt(envelopeJwt ?? jwt, options);
  return checked.valid && envelopeJwt === undefined
    ? { valid: false, reason: "JWT envelope signature is not valid: its signature is not base64url", stage: "signature" }
    : checked;
}

/**
 * The check of a presentation: the verdict `authenticate` reaches on it, and
 * the records `describer` makes of what was presented.
 */
export async function checkPresentation(
  delegationArg: unknown,
  authenticate: (presented: unknown) => Promise<Authenticated>,
  describer: DelegationDescriber,
): Promise<DelegationCheck> {
  // The presentation is read once (see readOnce): a credential object by
  // its copy, and a VC-JWT by its string, which cannot change. What is
  // verified below and what is digested are that one reading.
  let presented: unknown = delegationArg;
  if (typeof delegationArg !== "string") {
    const read = readOnce(delegationArg);
    if ("unread" in read) {
      return {
        valid: false,
        reason: `Malformed delegation credential: it ${read.unread}`,
        // Plain data nested too deep is a presentation with no signed
        // form: it has no digest, and is named by the id the walk that
        // refused it read. Of a value that is not plain data nothing is
        // read, its id included.
        ...(await describer.describe({
          ...("shown" in read && read.shown !== undefined ? { shown: read.shown } : {}),
          ancestors: [],
          verified: false,
        })),
      };
    }
    presented = read.copy;
  }

  // What the records describe: the ancestors the walk examined, then the
  // credential as presented (a VC-JWT by its string, the form its signature
  // covers).
  const { verdict, ancestors, unreadAncestor } = await authenticate(presented);
  const refused = (): Promise<DelegationRecords> =>
    describer.describe({ presented, ancestors, ...(unreadAncestor ? { unreadAncestor } : {}), verified: false });

  if (!verdict.valid) return { ...verdict, ...(await refused()) };
  try {
    return { ...verdict, ...(await describer.describe({ presented, ancestors, verified: true })) };
  } catch (error) {
    // What verified has a signed form, read by the very functions the
    // digest uses, so this is a fault and not the credential's doing: a
    // hash provider that failed, in the main. Whatever it was, the call
    // cannot be tied to its chain, so it is refused, and described as a
    // refusal is: as far as it can be.
    logger.error("[kya-os] A verified delegation could not be described; the call is refused", {
      error: error instanceof Error ? error.message : String(error),
    });
    return {
      valid: false,
      reason: "Delegation credential could not be verified",
      vc: verdict.vc,
      ...(await refused()),
    };
  }
}
