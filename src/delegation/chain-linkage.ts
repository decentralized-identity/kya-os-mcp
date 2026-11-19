/**
 * The structural pass over a delegation chain, root to leaf, run before any DID resolution,
 * signature check or status read: structure, then trust, then proofs, the order
 * `verifyRequestDelegation` (src/card/request-delegation.ts) already follows. It reads what each
 * credential claims and authenticates nothing; verifying each credential afterwards, the presented
 * one first and then its ancestors root first, authenticates the issuer it names. A credential that
 * does not descend from the one before it therefore costs no I/O at all.
 */

import { extractDelegationFromVC, type DelegationCredential, type DelegationRecord } from "../types/protocol.js";
import { describeValue } from "../utils/describe-value.js";
import { webCryptoSha256 } from "../utils/domain-digest.js";
import type { Sha256 } from "./chain-digest.js";
import { credentialIssuerDid } from "./credential-issuer.js";
import { PARENT_CREDENTIAL_DIGEST, commitsTo, parentReferenceOf } from "./parent-commitment.js";

/**
 * A refusal of a chain's links: the `reason` its presenter is told, and, where that withholds what
 * the chain resolver answered, the reason the operator's log is told in `logged`.
 */
export interface LinkageRefusal {
  readonly reason: string;
  readonly logged?: string;
}

/**
 * Why `chain` (root first, the presented credential last) is not one line of descent, or
 * `undefined` when it is: no delegation id repeats, the root names no parent, and every later
 * credential names the one before it as its parent and that parent's subject both as its
 * `issuerDid` and as the issuer of the credential itself ({@link credentialIssuerDid}), so only the
 * parent's delegate can re-delegate. The root names one DID as its `issuerDid` and as the issuer of
 * its credential, so every credential of an accepted chain is issued by the `issuerDid` its
 * delegation names, and the root's, the chain's Responsible Party (SPEC.md §2), is the DID whose key
 * verifies the root.
 *
 * Every credential but the presented one is the chain resolver's answer, which its presenter did not
 * write and has not yet shown it may read. So a refusal tells the presenter only what the presented
 * credential states: how it fails to link to its parent, in its own words, or else that the chain
 * its parent resolves to is broken. What it withholds, an ancestor's id, subject or issuer, is in
 * `logged`.
 */
export function chainLinkageRefusal(chain: readonly DelegationCredential[]): LinkageRefusal | undefined {
  const presented = chain.length - 1;
  const seen = new Set<string>();
  let parent: DelegationRecord | undefined;
  for (const [index, credential] of chain.entries()) {
    const delegation = extractDelegationFromVC(credential);
    const issuer = credentialIssuerDid(credential);
    const refused = seen.has(delegation.id)
      ? { detail: `Delegation chain contains a circular reference at ${delegation.id}` }
      : parent === undefined
        ? rootRefusal(delegation, issuer)
        : childRefusal(delegation, issuer, parent);
    if (refused !== undefined) {
      if (index !== presented) {
        return { reason: brokenAncestry(extractDelegationFromVC(chain[presented]!).id), logged: refused.detail };
      }
      return refused.presented === undefined ? { reason: refused.detail } : { reason: refused.presented, logged: refused.detail };
    }
    seen.add(delegation.id);
    parent = delegation;
  }
  return undefined;
}

/**
 * Why `chain` (root first, the presented credential last) breaks a parent commitment (SPEC.md §6.2),
 * or `undefined` when it breaks none: a re-delegation that states `parentCredentialDigest` states
 * the SPEC §7.8 digest of the credential before it, as the chain holds it, and the root, which has
 * no parent credential, states none. A credential states the member when its delegation holds it,
 * whatever its value. One that states none is accepted, its parent named by its id alone.
 *
 * Run it on a chain {@link chainLinkageRefusal} accepted. It reads the credentials and hashes them;
 * nothing is resolved or fetched. A refusal is told as that one tells its own: the presenter reads
 * only what the presented credential states, and what an ancestor states is in `logged`.
 */
export async function chainCommitmentRefusal(
  chain: readonly DelegationCredential[],
  hash: Sha256 = webCryptoSha256,
): Promise<LinkageRefusal | undefined> {
  const presented = chain.length - 1;
  for (const [index, credential] of chain.entries()) {
    const { commitment } = parentReferenceOf(credential);
    if (commitment === undefined) continue;
    const { id } = extractDelegationFromVC(credential);
    if (index === 0) {
      const states = `has no parent credential, so it states no ${PARENT_CREDENTIAL_DIGEST}`;
      return index === presented
        ? { reason: `Delegation ${describeValue(id)} ${states}` }
        : { reason: brokenAncestry(extractDelegationFromVC(chain[presented]!).id), logged: `Root delegation ${id} ${states}` };
    }
    if (await commitsTo(commitment.stated, chain[index - 1]!, hash)) continue;
    const logged = `Delegation ${id} states a ${PARENT_CREDENTIAL_DIGEST} that is not the digest of its parent ${extractDelegationFromVC(chain[index - 1]!).id} as resolved`;
    return index === presented
      ? { reason: `Delegation ${describeValue(id)} states a ${PARENT_CREDENTIAL_DIGEST} that is not the digest of the parent its chain resolves to`, logged }
      : { reason: brokenAncestry(extractDelegationFromVC(chain[presented]!).id), logged };
  }
  return undefined;
}

/** What the presenter of the delegation `leafId` is told when a link between two of its ancestors is refused. */
function brokenAncestry(leafId: string): string {
  return `Delegation ${describeValue(leafId)} does not descend from a root through the chain its parent resolves to`;
}

/**
 * Why a credential's link is refused: in full, as the operator's log reads it, and, where that names
 * what the chain resolver answered, in the words of the child alone, as its presenter reads it.
 */
interface RefusedLink {
  readonly detail: string;
  readonly presented?: string;
}

/**
 * Why `root`, in a credential naming `issuer`, cannot start a chain. Both DIDs of the second reason
 * are the presenter's until the root is verified, so it quotes them as {@link describeValue} does.
 * A root whose credential names no issuer string is left to the basic stage, which refuses it with
 * its own reason when the root is verified (and to `rootAdmissionRefusal` before that).
 */
function rootRefusal(root: DelegationRecord, issuer: string | undefined): RefusedLink | undefined {
  if (root.parentId) {
    return { detail: `Resolved delegation chain is incomplete: root delegation ${root.id} still references parent ${root.parentId}` };
  }
  if (issuer !== undefined && issuer !== root.issuerDid) {
    return {
      detail: `Root delegation ${root.id} names issuerDid ${describeValue(root.issuerDid)} but its credential names issuer ${describeValue(issuer)}`,
    };
  }
  return undefined;
}

/**
 * Why `child`, in a credential naming `issuer`, is not a re-delegation by the subject of `parent`.
 * The words its presenter reads name only the child's own members, its ids and DIDs quoted as
 * {@link describeValue} quotes them, since nothing has authenticated them yet.
 */
function childRefusal(child: DelegationRecord, issuer: string | undefined, parent: DelegationRecord): RefusedLink | undefined {
  if (child.parentId !== parent.id) {
    return {
      detail: `Delegation ${child.id} references parent ${child.parentId} but expected ${parent.id}`,
      presented: `Delegation ${describeValue(child.id)} references parent ${describeValue(child.parentId)}, which its resolved chain does not end with`,
    };
  }
  if (child.issuerDid !== parent.subjectDid) {
    return {
      detail: `Delegation ${child.id} issued by ${child.issuerDid} but parent subject is ${parent.subjectDid}`,
      presented: `Delegation ${describeValue(child.id)} issued by ${describeValue(child.issuerDid)} is not a re-delegation by the subject of parent ${describeValue(child.parentId)}`,
    };
  }
  if (issuer !== parent.subjectDid) {
    return {
      detail: `Delegation ${child.id} is signed by ${issuer ?? "an unidentified issuer"} but parent subject is ${parent.subjectDid}`,
      presented: `Delegation ${describeValue(child.id)} is signed by ${issuer === undefined ? "an unidentified issuer" : describeValue(issuer)}, not by the subject of parent ${describeValue(child.parentId)}`,
    };
  }
  return undefined;
}
