import type { DIDDocument } from '../../delegation/vc-verifier.js';
import {
  hasAlsoKnownAs,
  isDidDocument,
  normalizeDid,
} from '../../delegation/did-linkage.js';
import type {
  CheqdDidRegistrarClient,
  CheqdRegistrarResult,
  CheqdRegistrarSigner,
} from './registrar.js';

export interface UpdateCheqdAlsoKnownAsOptions {
  didWeb: string;
  didCheqd: string;
  resolver: { resolve(did: string): Promise<DIDDocument | null> };
  registrar: CheqdDidRegistrarClient;
  signer: CheqdRegistrarSigner;
  verificationMethodId?: string;
}

export interface UpdateCheqdAlsoKnownAsResult {
  changed: boolean;
  didDocument?: DIDDocument;
  registrarResult?: CheqdRegistrarResult;
  reason?: string;
}

export async function updateCheqdAlsoKnownAs(
  options: UpdateCheqdAlsoKnownAsOptions,
): Promise<UpdateCheqdAlsoKnownAsResult> {
  const didCheqd = normalizeDid(options.didCheqd);
  const didWeb = normalizeDid(options.didWeb);
  const didDocument = await options.resolver.resolve(didCheqd);

  if (!isDidDocument(didDocument) || normalizeDid(didDocument.id) !== didCheqd) {
    return {
      changed: false,
      reason: `Could not resolve DID Document for ${didCheqd}`,
    };
  }

  if (hasAlsoKnownAs(didDocument, didWeb)) {
    return { changed: false, didDocument };
  }

  const nextDocument: DIDDocument = {
    ...didDocument,
    alsoKnownAs: [...(didDocument.alsoKnownAs ?? []), didWeb],
  };

  const registrarResult = await options.registrar.updateDid({
    did: didCheqd,
    didDocument: nextDocument,
    signer: options.signer,
    verificationMethodId: options.verificationMethodId,
  });

  return {
    changed: registrarResult.success,
    didDocument: nextDocument,
    registrarResult,
    ...(registrarResult.success ? {} : { reason: registrarResult.reason }),
  };
}
