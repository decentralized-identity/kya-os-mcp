import { describe, it, expect, vi } from 'vitest';
import {
  CheqdDidRegistrarClient,
  createLocalEd25519CheqdRegistrarSigner,
  type CheqdRegistrarSigner,
} from '../registrar.js';
import type { FetchProvider } from '../../../providers/base.js';
import type { DIDDocument } from '../../../delegation/vc-verifier.js';

function queuedFetchProvider(responses: Response[]): {
  provider: FetchProvider;
  fetch: ReturnType<typeof vi.fn>;
} {
  const fetch = vi.fn(async () => {
    const next = responses.shift();
    if (!next) {
      throw new Error('No queued response');
    }
    return next;
  });
  return {
    provider: {
      resolveDID: vi.fn(),
      fetchStatusList: vi.fn(),
      fetchDelegationChain: vi.fn(),
      fetch,
    },
    fetch,
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('CheqdDidRegistrarClient', () => {
  const did = 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111';
  const kid = `${did}#key-1`;
  const didDocument: DIDDocument = {
    id: did,
    verificationMethod: [
      {
        id: kid,
        type: 'Ed25519VerificationKey2020',
        controller: did,
      },
    ],
    authentication: [kid],
  };

  it('runs the /create two-step client-managed-secret flow', async () => {
    const { provider, fetch } = queuedFetchProvider([
      jsonResponse({
        jobId: 'job-create',
        didState: {
          state: 'action',
          action: 'signPayload',
          signingRequest: {
            signingRequest0: {
              kid,
              alg: 'EdDSA',
              serializedPayload: 'cGF5bG9hZA==',
            },
          },
        },
      }),
      jsonResponse({ didState: { state: 'finished' } }),
    ]);
    const signer: CheqdRegistrarSigner = vi.fn(async (request) => ({
      verificationMethodId: request.verificationMethodId,
      signature: 'signature-from-test',
    }));
    const client = new CheqdDidRegistrarClient({
      registrarUrl: 'https://registrar.example',
      fetchProvider: provider,
      headers: { Authorization: 'Bearer token' },
    });

    const result = await client.createDid({ didDocument, signer });

    expect(result.success).toBe(true);
    expect(result.jobId).toBe('job-create');
    expect(signer).toHaveBeenCalledWith({
      operation: 'create',
      did,
      requestId: 'signingRequest0',
      verificationMethodId: kid,
      serializedPayload: 'cGF5bG9hZA==',
      algorithm: 'Ed25519',
      encoding: 'base64',
      requestBody: { didDocument },
    });
    expect(fetch).toHaveBeenNthCalledWith(
      1,
      'https://registrar.example/create',
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer token' },
      }),
    );
    expect(JSON.parse(fetch.mock.calls[1]![1].body)).toEqual({
      jobId: 'job-create',
      secret: {
        signingResponse: {
          signingRequest0: { kid, signature: 'signature-from-test' },
        },
      },
    });
  });

  it('runs the /update flow and never sends private key material', async () => {
    const { provider, fetch } = queuedFetchProvider([
      jsonResponse({
        jobId: 'job-update',
        didState: {
          state: 'action',
          signingRequest: [{ verificationMethodId: kid, serializedPayload: 'dXBkYXRl' }],
        },
      }),
      jsonResponse({ didState: { state: 'finished' } }),
    ]);
    const client = new CheqdDidRegistrarClient({
      registrarUrl: 'https://registrar.example/',
      fetchProvider: provider,
    });
    const cryptoProvider = {
      sign: vi.fn(async () => new Uint8Array([9])),
      verify: vi.fn(),
      generateKeyPair: vi.fn(),
      hash: vi.fn(),
      randomBytes: vi.fn(),
    };
    const signer = createLocalEd25519CheqdRegistrarSigner({
      cryptoProvider,
      privateKey: 'secret-private-key',
      verificationMethodId: kid,
    });

    const result = await client.updateDid({
      did,
      didDocument: { ...didDocument, alsoKnownAs: ['did:web:agent.example.com'] },
      verificationMethodId: kid,
      signer,
    });

    expect(result.success).toBe(true);
    expect(fetch.mock.calls[0]![0]).toBe('https://registrar.example/update');
    expect(cryptoProvider.sign).toHaveBeenCalledWith(
      new TextEncoder().encode('update'),
      'secret-private-key',
    );
    const allBodies = fetch.mock.calls.map((call) => JSON.stringify(JSON.parse(call[1].body)));
    expect(allBodies.join('\n')).not.toContain('privateKey');
    expect(allBodies.join('\n')).not.toContain('secret-private-key');
  });

  it('creates a DID-Linked Resource through /{did}/create-resource', async () => {
    const { provider, fetch } = queuedFetchProvider([
      jsonResponse({
        jobId: 'job-resource',
        didState: {
          state: 'action',
          signingRequest: [{ verificationMethodId: kid, serializedPayload: 'cmVzb3VyY2U=' }],
        },
      }),
      jsonResponse({
        didState: { state: 'finished' },
        resourceState: { resourceId: '33333333-3333-4333-8333-333333333333' },
      }),
    ]);
    const client = new CheqdDidRegistrarClient({
      registrarUrl: 'https://registrar.example',
      fetchProvider: provider,
    });

    const result = await client.createResource({
      did,
      resource: {
        name: 'CapabilityManifest',
        type: 'CapabilityManifest',
        data: 'eyJrIjoidiJ9',
      },
      signer: async () => ({ verificationMethodId: kid, signature: 'sig' }),
    });

    expect(result.success).toBe(true);
    expect(fetch.mock.calls[0]![0]).toBe(`${'https://registrar.example'}/${did}/create-resource`);
    expect(JSON.parse(fetch.mock.calls[0]![1].body)).toEqual({
      name: 'CapabilityManifest',
      type: 'CapabilityManifest',
      data: 'eyJrIjoidiJ9',
    });
  });

  it('returns a structured failure when the registrar does not provide a signing job', async () => {
    const { provider } = queuedFetchProvider([
      jsonResponse({ didState: { state: 'failed', reason: 'bad request' } }),
    ]);
    const client = new CheqdDidRegistrarClient({
      registrarUrl: 'https://registrar.example',
      fetchProvider: provider,
    });

    const result = await client.createDid({
      didDocument,
      signer: async () => ({ verificationMethodId: kid, signature: 'sig' }),
    });

    expect(result.success).toBe(false);
    expect(result.stage).toBe('request');
    expect(result.reason).toContain('jobId');
  });

  it('returns a structured failure when signature submission fails', async () => {
    const { provider } = queuedFetchProvider([
      jsonResponse({
        jobId: 'job-update',
        didState: {
          state: 'action',
          signingRequest: {
            signingRequest0: { kid, serializedPayload: 'dXBkYXRl' },
          },
        },
      }),
      jsonResponse({ didState: { state: 'failed', reason: 'bad signature' } }, 400),
    ]);
    const client = new CheqdDidRegistrarClient({
      registrarUrl: 'https://registrar.example',
      fetchProvider: provider,
    });

    const result = await client.updateDid({
      did,
      didDocument,
      signer: async () => ({ verificationMethodId: kid, signature: 'bad-sig' }),
    });

    expect(result.success).toBe(false);
    expect(result.stage).toBe('submit');
    expect(result.reason).toContain('HTTP 400');
    expect(result.response).toEqual({ didState: { state: 'failed', reason: 'bad signature' } });
  });

  it('creates a local Ed25519 signer without exposing private keys to the registrar client', async () => {
    const cryptoProvider = {
      sign: vi.fn(async () => new Uint8Array([1, 2, 3])),
      verify: vi.fn(),
      generateKeyPair: vi.fn(),
      hash: vi.fn(),
      randomBytes: vi.fn(),
    };
    const signer = createLocalEd25519CheqdRegistrarSigner({
      cryptoProvider,
      privateKey: 'secret-private-key',
      verificationMethodId: kid,
    });

    const response = await signer({
      operation: 'update',
      did,
      verificationMethodId: kid,
      serializedPayload: 'cGF5bG9hZA==',
      algorithm: 'Ed25519',
      encoding: 'base64',
      requestBody: {},
    });

    expect(cryptoProvider.sign).toHaveBeenCalledWith(
      new TextEncoder().encode('payload'),
      'secret-private-key',
    );
    expect(response).toEqual({ verificationMethodId: kid, signature: 'AQID' });
  });
});
