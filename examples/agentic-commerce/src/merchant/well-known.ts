/**
 * The merchant's discovery document — what an agent reads BEFORE presenting
 * anything. Shape follows schemas/well-known-mcpi.json (SPEC.md §10) and adds
 * one block this example proposes for the publisher-side agent surface:
 * `acceptedTrustSchemes`, the merchant's declaration of which agent-authority
 * schemes it will verify and under what policy. Everything declared here is
 * what the verifier actually enforces — nothing aspirational.
 */
export interface DiscoveryDocument {
  version: string;
  serverDid: string;
  name: string;
  endpoints: Record<string, string>;
  clockSkewSeconds: number;
  capabilities: Record<string, boolean>;
  supportedDidMethods: string[];
  proofAlgorithms: string[];
  acceptedTrustSchemes: Array<Record<string, unknown>>;
  commerce: Record<string, unknown>;
}

export function buildDiscoveryDocument(options: {
  serverDid: string;
  name: string;
  clockSkewSeconds?: number;
  currency: string;
}): DiscoveryDocument {
  return {
    version: '1.0',
    serverDid: options.serverDid,
    name: options.name,
    endpoints: {
      handshake: '/_kya-os/handshake',
      tools: '/mcp',
      catalog: '/api/catalog',
    },
    clockSkewSeconds: options.clockSkewSeconds ?? 120,
    capabilities: { proofs: true, delegation: true, statusList: true, crisp: true },
    supportedDidMethods: ['did:key', 'did:web'],
    proofAlgorithms: ['EdDSA'],
    acceptedTrustSchemes: [
      {
        id: 'org.kya-os/delegation',
        version: '1',
        spec: 'https://github.com/decentralized-identity/kya-os-mcp/blob/main/SPEC.md',
        credentialFormats: ['vc+ld+json/Ed25519Signature2020', 'vc+jwt/EdDSA'],
        holderBinding: 'required',
        audience: options.serverDid,
        responsibleParty: { didMethods: ['did:web', 'did:key'], trustList: 'any' },
        revocation: { format: 'StatusList2021', checkedAt: 'every-call', onUnresolvable: 'fail-closed' },
        scopes: { resourceScheme: 'gs1:digital-link', matchers: ['exact', 'prefix'] },
        spend: { enforcedBy: 'merchant', from: 'credential.constraints.crisp.scopes[].constraints.maxAmount' },
      },
    ],
    commerce: {
      productIdentifier: 'GS1 Digital Link (https://id.gs1.org/01/{gtin})',
      catalog: '/api/catalog',
      currency: options.currency,
      receipts: 'signed (detached JWS in _meta["org.kya-os/response-proof"])',
    },
  };
}
