import type { CryptoProvider, FetchProvider } from '../providers/base.js';
import type { DIDDocument } from '../delegation/vc-verifier.js';
import { base64ToBytes, base64urlEncodeFromBytes, bytesToBase64 } from '../utils/base64.js';

export type CheqdRegistrarOperation = 'create' | 'update' | 'create-resource';

export interface CheqdRegistrarClientOptions {
  registrarUrl: string;
  fetchProvider: FetchProvider;
  headers?: Record<string, string> | (() => Promise<Record<string, string>>);
}

export interface CheqdRegistrarSigningRequest {
  requestId?: string;
  operation: CheqdRegistrarOperation;
  did?: string;
  verificationMethodId: string;
  serializedPayload: string;
  algorithm: 'Ed25519';
  encoding: 'base64';
  requestBody: unknown;
}

export interface CheqdRegistrarSigningResponse {
  requestId?: string;
  verificationMethodId: string;
  signature: string;
  alg?: string;
  purpose?: string;
}

export type CheqdRegistrarSigner = (
  request: CheqdRegistrarSigningRequest,
) => Promise<CheqdRegistrarSigningResponse | CheqdRegistrarSigningResponse[]>;

export interface CheqdRegistrarResult {
  success: boolean;
  operation: CheqdRegistrarOperation;
  stage: 'request' | 'sign' | 'submit' | 'complete';
  jobId?: string;
  action?: string;
  response?: unknown;
  reason?: string;
}

export interface CreateCheqdDidOptions {
  didDocument: DIDDocument;
  signer: CheqdRegistrarSigner;
  verificationMethodId?: string;
  options?: Record<string, unknown>;
}

export interface UpdateCheqdDidOptions {
  did: string;
  didDocument: DIDDocument;
  signer: CheqdRegistrarSigner;
  verificationMethodId?: string;
  options?: Record<string, unknown>;
}

export interface CheqdCreateResourceBody {
  name: string;
  type: string;
  data: string;
  version?: string;
  mediaType?: string;
  encoding?: string;
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface CreateCheqdResourceOptions {
  did: string;
  resource: CheqdCreateResourceBody;
  signer: CheqdRegistrarSigner;
  verificationMethodId?: string;
  options?: Record<string, unknown>;
}

export interface LocalCheqdRegistrarSignerOptions {
  cryptoProvider: CryptoProvider;
  privateKey: string;
  verificationMethodId: string;
  signatureEncoding?: 'base64' | 'base64url';
}

interface SigningRequestCandidate {
  requestId?: string;
  serializedPayload?: string;
  verificationMethodId?: string;
  kid?: string;
  alg?: string;
  algorithm?: string;
  encoding?: string;
  purpose?: string;
}

export class CheqdDidRegistrarClient {
  private readonly registrarUrl: string;
  private readonly fetchProvider: FetchProvider;
  private readonly headers?: Record<string, string> | (() => Promise<Record<string, string>>);

  constructor(options: CheqdRegistrarClientOptions) {
    this.registrarUrl = options.registrarUrl.replace(/\/+$/, '');
    this.fetchProvider = options.fetchProvider;
    this.headers = options.headers;
  }

  async createDid(options: CreateCheqdDidOptions): Promise<CheqdRegistrarResult> {
    const body = {
      didDocument: options.didDocument,
      ...(options.options ? { options: options.options } : {}),
    };

    return this.runClientManagedSecretFlow({
      operation: 'create',
      did: options.didDocument.id,
      path: '/create',
      body,
      signer: options.signer,
      verificationMethodId: options.verificationMethodId,
    });
  }

  async updateDid(options: UpdateCheqdDidOptions): Promise<CheqdRegistrarResult> {
    const body = {
      did: options.did,
      didDocumentOperation: ['setDidDocument'],
      didDocument: [options.didDocument],
      ...(options.options ? { options: options.options } : {}),
    };

    return this.runClientManagedSecretFlow({
      operation: 'update',
      did: options.did,
      path: '/update',
      body,
      signer: options.signer,
      verificationMethodId: options.verificationMethodId,
    });
  }

  async createResource(options: CreateCheqdResourceOptions): Promise<CheqdRegistrarResult> {
    const body = {
      ...options.resource,
      ...(options.options ? { options: options.options } : {}),
    };

    return this.runClientManagedSecretFlow({
      operation: 'create-resource',
      did: options.did,
      path: `/${options.did}/create-resource`,
      body,
      signer: options.signer,
      verificationMethodId: options.verificationMethodId,
    });
  }

  private async runClientManagedSecretFlow(options: {
    operation: CheqdRegistrarOperation;
    did?: string;
    path: string;
    body: unknown;
    signer: CheqdRegistrarSigner;
    verificationMethodId?: string;
  }): Promise<CheqdRegistrarResult> {
    const requestResponse = await this.post(options.path, options.body);
    if (!requestResponse.ok) {
      return {
        success: false,
        operation: options.operation,
        stage: 'request',
        reason: `Registrar request failed with HTTP ${requestResponse.status}`,
        response: requestResponse.body,
      };
    }

    const jobId = findStringByKey(requestResponse.body, 'jobId');
    const signingRequests = extractSigningRequests(
      requestResponse.body,
      options.operation,
      options.did,
      options.body,
      options.verificationMethodId,
    );
    const action = findStringByKey(requestResponse.body, 'action');

    if (isFinished(requestResponse.body)) {
      return {
        success: true,
        operation: options.operation,
        stage: 'complete',
        ...(jobId ? { jobId } : {}),
        response: requestResponse.body,
      };
    }

    if (!jobId) {
      return {
        success: false,
        operation: options.operation,
        stage: 'request',
        action,
        response: requestResponse.body,
        reason: 'Registrar response did not include a jobId',
      };
    }

    if (signingRequests.length === 0) {
      return {
        success: false,
        operation: options.operation,
        stage: 'request',
        jobId,
        action,
        response: requestResponse.body,
        reason: 'Registrar response did not include a serialized payload to sign',
      };
    }

    let signingResponse: CheqdRegistrarSigningResponse[];
    try {
      signingResponse = (
        await Promise.all(
          signingRequests.map(async (request) =>
            flattenSigningResponses(await options.signer(request)).map((response) => ({
              ...response,
              requestId: response.requestId ?? request.requestId,
            })),
          ),
        )
      ).flat();
    } catch (error) {
      return {
        success: false,
        operation: options.operation,
        stage: 'sign',
        jobId,
        action,
        response: requestResponse.body,
        reason: `Signing failed: ${error instanceof Error ? error.message : String(error)}`,
      };
    }

    const submitBody = {
      jobId,
      secret: {
        signingResponse: formatSigningResponseForRegistrar(signingResponse),
      },
    };

    const submitResponse = await this.post(options.path, submitBody);
    const success = submitResponse.ok && isFinished(submitResponse.body);

    return {
      success,
      operation: options.operation,
      stage: success ? 'complete' : 'submit',
      jobId,
      action,
      response: submitResponse.body,
      ...(success
        ? {}
        : {
            reason: submitResponse.ok
              ? 'Registrar did not finish the operation after signature submission'
              : `Registrar signature submission failed with HTTP ${submitResponse.status}`,
          }),
    };
  }

  private async post(
    path: string,
    body: unknown,
  ): Promise<{ ok: boolean; status: number; body: unknown }> {
    const response = await this.fetchProvider.fetch(`${this.registrarUrl}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(await this.resolveHeaders()),
      },
      body: JSON.stringify(body),
    });

    let responseBody: unknown;
    try {
      responseBody = await response.json();
    } catch {
      responseBody = undefined;
    }

    return {
      ok: response.ok,
      status: response.status,
      body: responseBody,
    };
  }

  private async resolveHeaders(): Promise<Record<string, string>> {
    if (!this.headers) {
      return {};
    }
    return typeof this.headers === 'function' ? this.headers() : this.headers;
  }
}

export function createLocalEd25519CheqdRegistrarSigner(
  options: LocalCheqdRegistrarSignerOptions,
): CheqdRegistrarSigner {
  return async (request) => {
    const payloadBytes = base64ToBytes(request.serializedPayload);
    const signatureBytes = await options.cryptoProvider.sign(payloadBytes, options.privateKey);
    const signature =
      options.signatureEncoding === 'base64url'
        ? base64urlEncodeFromBytes(signatureBytes)
        : bytesToBase64(signatureBytes);

    return {
      verificationMethodId: request.verificationMethodId || options.verificationMethodId,
      signature,
    };
  };
}

function extractSigningRequests(
  response: unknown,
  operation: CheqdRegistrarOperation,
  did: string | undefined,
  requestBody: unknown,
  fallbackVerificationMethodId?: string,
): CheqdRegistrarSigningRequest[] {
  const candidates: SigningRequestCandidate[] = [];
  collectSigningRequestCandidates(response, candidates);

  const completeCandidates = candidates.filter((candidate) => candidate.serializedPayload);
  if (completeCandidates.length === 0) {
    const serializedPayload = findStringByKey(response, 'serializedPayload');
    if (serializedPayload) {
      completeCandidates.push({
        serializedPayload,
        verificationMethodId: fallbackVerificationMethodId,
      });
    }
  }

  return completeCandidates
    .filter((candidate) => candidate.serializedPayload)
    .map((candidate): CheqdRegistrarSigningRequest => ({
      operation,
      did,
      ...(candidate.requestId ? { requestId: candidate.requestId } : {}),
      verificationMethodId:
        candidate.verificationMethodId ??
        candidate.kid ??
        fallbackVerificationMethodId ??
        inferVerificationMethodId(requestBody) ??
        '',
      serializedPayload: candidate.serializedPayload!,
      algorithm: 'Ed25519',
      encoding: 'base64',
      requestBody,
    }))
    .filter((request) => request.verificationMethodId.length > 0);
}

function collectSigningRequestCandidates(
  value: unknown,
  out: SigningRequestCandidate[],
  requestId?: string,
): void {
  if (Array.isArray(value)) {
    for (const entry of value) {
      collectSigningRequestCandidates(entry, out);
    }
    return;
  }

  if (!isRecord(value)) {
    return;
  }

  if (typeof value['serializedPayload'] === 'string') {
    out.push({
      ...(value as SigningRequestCandidate),
      ...(requestId ? { requestId } : {}),
    });
  }

  for (const [key, nested] of Object.entries(value)) {
    const nestedRequestId = isRecord(nested) && typeof nested['serializedPayload'] === 'string'
      ? key
      : undefined;
    collectSigningRequestCandidates(nested, out, nestedRequestId);
  }
}

function flattenSigningResponses(
  response: CheqdRegistrarSigningResponse | CheqdRegistrarSigningResponse[],
): CheqdRegistrarSigningResponse[] {
  return Array.isArray(response) ? response : [response];
}

function formatSigningResponseForRegistrar(
  responses: CheqdRegistrarSigningResponse[],
): unknown {
  const formatted = responses.map(formatSingleSigningResponseForRegistrar);

  if (!responses.some((response) => response.requestId)) {
    return formatted;
  }

  return Object.fromEntries(
    responses.map((response, index) => [
      response.requestId ?? `signingRequest${index}`,
      formatSingleSigningResponseForRegistrar(response),
    ]),
  );
}

function formatSingleSigningResponseForRegistrar(
  response: CheqdRegistrarSigningResponse,
): Record<string, string> {
  return {
    kid: response.verificationMethodId,
    signature: response.signature,
    ...(response.alg ? { alg: response.alg } : {}),
    ...(response.purpose ? { purpose: response.purpose } : {}),
  };
}

function findStringByKey(value: unknown, key: string): string | undefined {
  if (Array.isArray(value)) {
    for (const entry of value) {
      const found = findStringByKey(entry, key);
      if (found) {
        return found;
      }
    }
    return undefined;
  }

  if (!isRecord(value)) {
    return undefined;
  }

  const maybeString = value[key];
  if (typeof maybeString === 'string') {
    return maybeString;
  }

  for (const nested of Object.values(value)) {
    const found = findStringByKey(nested, key);
    if (found) {
      return found;
    }
  }

  return undefined;
}

function inferVerificationMethodId(value: unknown): string | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  const didDocument = value['didDocument'];
  if (isRecord(didDocument)) {
    const verificationMethod = didDocument['verificationMethod'];
    if (Array.isArray(verificationMethod)) {
      const first = verificationMethod[0];
      if (isRecord(first) && typeof first['id'] === 'string') {
        return first['id'];
      }
    }
  }

  return undefined;
}

function isFinished(value: unknown): boolean {
  const state = findStringByKey(value, 'state');
  return state === 'finished';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
