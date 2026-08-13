export {
  DidCheqdResolver,
  cheqdResolver,
  createDidCheqdResolver,
  didCheqdToResolverUrl,
  isDidCheqd,
  parseDidCheqd,
  type DidCheqdNetwork,
  type DidCheqdResolverOptions,
  type ParsedDidCheqd,
} from './resolver.js';

export {
  CheqdDidRegistrarClient,
  createLocalEd25519CheqdRegistrarSigner,
  type CheqdCreateResourceBody,
  type CheqdRegistrarClientOptions,
  type CheqdRegistrarOperation,
  type CheqdRegistrarResult,
  type CheqdRegistrarSigner,
  type CheqdRegistrarSigningRequest,
  type CheqdRegistrarSigningResponse,
  type CreateCheqdDidOptions,
  type CreateCheqdResourceOptions,
  type LocalCheqdRegistrarSignerOptions,
  type UpdateCheqdDidOptions,
} from './registrar.js';

export {
  updateCheqdAlsoKnownAs,
  type UpdateCheqdAlsoKnownAsOptions,
  type UpdateCheqdAlsoKnownAsResult,
} from './linkage.js';

export {
  CHEQD_DLR_ARTIFACT_TYPES,
  buildCheqdDlrReference,
  isSupportedCheqdDlrArtifactType,
  prepareCheqdDlrResource,
  validateCheqdDlrArtifact,
  type CheqdDlrArtifact,
  type CheqdDlrArtifactType,
  type CheqdDlrReference,
  type PreparedCheqdDlrResource,
} from './dlr.js';

export {
  CheqdStatusListResolver,
  createCheqdStatusListResolver,
  type CheqdStatusListResolverOptions,
} from './statuslist-resolver.js';
