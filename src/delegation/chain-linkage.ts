/**
 * The structural pass over a delegation chain, root to leaf, run before any DID resolution,
 * signature check or status read: structure, then trust, then proofs, the order
 * `verifyRequestDelegation` (src/card/request-delegation.ts) already follows. It reads what each
 * credential claims and authenticates nothing; verifying each credential afterwards, root first,
 * authenticates the issuer it names. A credential that does not descend from the one before it
 * therefore costs no I/O at all.
 */

import { extractDelegationFromVC, type DelegationCredential, type DelegationRecord } from "../types/protocol.js";
import { credentialIssuerDid } from "./credential-issuer.js";

/**
 * Why `chain` (root first) is not one line of descent, or `undefined` when it is: no delegation id
 * repeats, the root names no parent, and every later credential names the one before it as its
 * parent and that parent's subject both as its `issuerDid` and as the issuer of the credential
 * itself ({@link credentialIssuerDid}), so only the parent's delegate can re-delegate.
 */
export function chainLinkageRefusal(chain: readonly DelegationCredential[]): string | undefined {
  const seen = new Set<string>();
  let parent: DelegationRecord | undefined;
  for (const credential of chain) {
    const delegation = extractDelegationFromVC(credential);
    if (seen.has(delegation.id)) {
      return `Delegation chain contains a circular reference at ${delegation.id}`;
    }
    seen.add(delegation.id);
    const refusal = parent === undefined
      ? rootRefusal(delegation)
      : childRefusal(delegation, credentialIssuerDid(credential), parent);
    if (refusal !== undefined) return refusal;
    parent = delegation;
  }
  return undefined;
}

function rootRefusal(root: DelegationRecord): string | undefined {
  if (!root.parentId) return undefined;
  return `Resolved delegation chain is incomplete: root delegation ${root.id} still references parent ${root.parentId}`;
}

function childRefusal(child: DelegationRecord, issuer: string | undefined, parent: DelegationRecord): string | undefined {
  if (child.parentId !== parent.id) {
    return `Delegation ${child.id} references parent ${child.parentId} but expected ${parent.id}`;
  }
  if (child.issuerDid !== parent.subjectDid) {
    return `Delegation ${child.id} issued by ${child.issuerDid} but parent subject is ${parent.subjectDid}`;
  }
  if (issuer !== parent.subjectDid) {
    return `Delegation ${child.id} is signed by ${issuer ?? "an unidentified issuer"} but parent subject is ${parent.subjectDid}`;
  }
  return undefined;
}
