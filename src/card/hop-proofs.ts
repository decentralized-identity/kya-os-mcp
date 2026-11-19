/** Sequential hop-proof verification shared by chain evaluation and request verification. */
import { DeadlineExceededError, type Ask } from '../utils/deadline.js';
import { coded, RefusalError, refusalCodeOf, type Coded } from '../utils/refusal.js';
import { sanitizeForMessage } from '../utils/message-text.js';
import { thrownReason } from '../utils/thrown-words.js';
import { codedVariantOf } from './coded-proof-verifier.js';
import type { DelegationProofVerifier } from './delegation-proof.js';

/** The most UTF-16 code units of a proof refusal kept in a hop's reason. */
const HOP_REFUSAL_LENGTH = 512;

/**
 * Verify the received credentials root to leaf, each asked through `ask`, so under its own
 * deadline and within the time the whole check has, stopping at the first refusal. Its reason names
 * the zero-based hop; `undefined` means every proof verified.
 * The walk is sequential: a later hop must not direct DID resolution before its ancestors verify.
 * That order, and no count of hops, is what keeps a long chain from spending the verifier: each
 * issuer whose DID is resolved is the party a verified hop delegated to, and the first hop that
 * fails ends the walk, so hops that name other parties' hosts get one of them asked.
 * No credential is parsed or projected here, since its signature covers every received member.
 */
export async function firstHopProofRefusal(
  credentials: readonly Record<string, unknown>[],
  verify: DelegationProofVerifier,
  ask: Ask,
): Promise<(Coded & { reason: string }) | undefined> {
  for (const [hop, credential] of credentials.entries()) {
    const refused = await hopProofRefusal(credential, verify, ask);
    if (refused !== undefined) return { ...refused, reason: `hop ${hop}: ${refused.reason}` };
  }
  return undefined;
}

/**
 * Run the hop-proof seam, fail-closed, through `ask`: why the hop is
 * refused, with its code, or `undefined` when its proof verified. A proof that did not verify is
 * `invalid_proof`; a verifier that threw a {@link RefusalError}, as the coded variant of the
 * library's (`./coded-proof-verifier`), which this asks in its place, does when the issuer's DID
 * document cannot be read, is refused with its message and its code, or `invalid_proof` where that
 * code is none of the catalog's; any other throw is
 * `runtime_error`; and a verifier, or its DID resolution, that has not answered by the deadline, or
 * a check whose own time ran out, is `deadline_exceeded`, with a reason that says which.
 */
async function hopProofRefusal(
  credential: Record<string, unknown>,
  verifyHopProof: DelegationProofVerifier,
  ask: Ask,
): Promise<(Coded & { reason: string }) | undefined> {
  try {
    const verify = codedVariantOf(verifyHopProof);
    const verified = await ask('the hop proof verifier', () => verify(credential));
    return verified === true ? undefined : { reason: 'proof did not verify', ...coded('invalid_proof') };
  } catch (error) {
    if (error instanceof DeadlineExceededError) return { reason: error.message, ...coded('deadline_exceeded') };
    if (error instanceof RefusalError) {
      return { reason: sanitizeForMessage(error.message, HOP_REFUSAL_LENGTH), ...coded(refusalCodeOf(error, 'invalid_proof')) };
    }
    return {
      reason: thrownReason(error, { withheld: 'proof did not verify', tag: '[kya-os]' }),
      ...coded(refusalCodeOf(error, 'runtime_error')),
    };
  }
}
