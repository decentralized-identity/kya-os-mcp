/** Compose native request proof, signed authority, live revocation and resource policy. */
import type { ToolRequest } from '../proof/generator.js';
import {
  DelegationCredentialSchema,
  MAX_DELEGATION_DEPTH,
  evaluateDelegationChain,
  validateDelegationChain,
  type DelegationChain,
  type DelegationCredential,
} from './delegation.js';
import { requireProof, type ProofGateResult, type RequireProofOptions } from './middleware.js';
import type { ProofAssurance, VerifyProofDeps } from './proof/index.js';
import type { BitstringRevocationChecker } from './revocation.js';

export interface VerifiedInvocation {
  /** Root credential issuer, not an asserted human identifier inside the credential. */
  responsibleParty: string;
  /** Verified request signer, equal to the final delegate in the chain. */
  leafInvoker: string;
  resource: string;
  action: string;
  proofLevel: ProofAssurance;
}

export interface DelegatedInvocationDeps {
  proof: VerifyProofDeps;
  /**
   * Verify the credential's Data Integrity signature, including cryptosuite and
   * assertionMethod authorization by its issuer. Structural validation is NOT
   * signature verification. A missing/throwing verifier fails closed.
   */
  verifyCredentialSignature: (credential: DelegationCredential) => Promise<boolean>;
  /** Must authenticate status-list credentials and check their validity window. */
  checkRevocation: BitstringRevocationChecker;
  /**
   * Mandatory resource policy gate after cryptographic checks. Bind the verified
   * chain to the authenticated resource account and evaluate ALL caveats against
   * this operation. Unknown caveats must reject. Never derive account ownership
   * from unverified request fields or treat a userDid string as human consent.
   */
  authorizeInvocation: (
    invocation: Readonly<VerifiedInvocation>,
    request: ToolRequest,
    chain: DelegationChain,
  ) => Promise<boolean>;
}

export interface DelegatedInvocationOptions extends RequireProofOptions {
  /** Trusted route/tool configuration. Never copy these values from the caller. */
  resourceOwner: string;
  resource: string;
  action: string;
}

export type DelegatedInvocationResult =
  | { ok: true; invocation: VerifiedInvocation }
  | Extract<ProofGateResult, { ok: false }>
  | { ok: false; status: 403; error: { code: string; reasons: string[] } };

/**
 * Native Card-profile admission, independent of transport and grant storage.
 * Pass the actual JSON-RPC request and its _meta; provide the original signed
 * chain, including on stored-grant retries. No bearer or cached-allow fallback.
 * All hops require signed credentials and fresh revocation evidence. The
 * existing proof engine enforces request hash, DID key, audience, time and nonce.
 * This helper does not implement legacy VC-JWT conversion or human account policy.
 */
export function requireDelegatedInvocation(
  deps: DelegatedInvocationDeps,
  options: DelegatedInvocationOptions,
): (request: ToolRequest, meta: unknown, chain: unknown) => Promise<DelegatedInvocationResult> {
  if (!options.resourceOwner || !options.resource || !options.action) {
    throw new Error('Delegated invocation requires a configured owner, resource and action');
  }
  // Snapshot policy coordinates so accidental later config mutation cannot
  // change the resource whose authority this guard admits.
  const { resourceOwner, resource, action } = options;
  const proofGuard = requireProof(deps.proof, { minLevel: options.minLevel });
  const reject = (code: string, reasons: string[] = [code]): DelegatedInvocationResult =>
    ({ ok: false, status: 403, error: { code, reasons } });

  return async (request, meta, presentedChain) => {
    try {
      const proof = await proofGuard(request, meta);
      if (!proof.ok) return proof;
      if (!Array.isArray(presentedChain) || presentedChain.length === 0 || presentedChain.length > MAX_DELEGATION_DEPTH) {
        return reject('delegation_chain_invalid');
      }
      const chain: DelegationCredential[] = [];
      for (const presented of presentedChain) {
        const credential: unknown = structuredClone(presented);
        const parsed = DelegationCredentialSchema.safeParse(credential);
        if (!parsed.success || !parsed.data.proof || !parsed.data.credentialStatus ||
            parsed.data.credentialStatus.statusPurpose !== 'revocation') {
          return reject('delegation_credential_invalid');
        }
        // Validate shape without letting schema normalization strip extension
        // fields out of the original document whose signature must verify.
        chain.push(credential as DelegationCredential);
      }
      const context = { resourceOwner, resource, now: deps.proof.now };
      const structural = validateDelegationChain(chain, context);
      if (!structural.ok) return reject('delegation_chain_invalid', structural.reasons);
      if (structural.leafInvoker !== proof.did) return reject('delegation_holder_mismatch');
      if (!structural.allowedAction.includes(action)) return reject('delegation_action_denied');

      // Verify every hop before following its status-list reference. Signature
      // verification may cache crypto, but liveness and policy run each time.
      for (const credential of chain) {
        if (await deps.verifyCredentialSignature(credential) !== true) {
          return reject('delegation_signature_invalid');
        }
      }
      const live = await evaluateDelegationChain(chain, deps.checkRevocation, context);
      if (!live.ok || !live.fresh) return reject('delegation_not_live', live.reasons);

      const invocation: VerifiedInvocation = {
        responsibleParty: resourceOwner,
        leafInvoker: proof.did,
        resource,
        action,
        proofLevel: proof.level,
      };
      if (await deps.authorizeInvocation(invocation, request, chain) !== true) {
        return reject('invocation_policy_denied');
      }
      return { ok: true, invocation };
    } catch {
      return reject('invocation_verification_unavailable');
    }
  };
}
