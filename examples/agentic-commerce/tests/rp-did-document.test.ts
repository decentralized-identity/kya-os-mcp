import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { canonicalizeJSON, NodeCryptoProvider, type DIDDocument } from '@kya-os/mcp';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { KeyedIdentity } from '../src/lib/wiring.js';

const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'commerce-rp-did-'));
const cryptoProvider = new NodeCryptoProvider();
const did = 'did:web:auth.example';
let rp: typeof import('../src/rp/server.js');
let beforeRotation: KeyedIdentity;
let afterRotation: KeyedIdentity;
beforeAll(async () => {
  vi.stubEnv('DEMO_VAR_DIR', path.join(directory, 'var'));
  vi.stubEnv('DEMO_DATA_DIR', path.join(directory, 'data'));
  vi.stubEnv('DEMO_ENV_FILE', path.join(directory, 'missing.env'));
  vi.stubEnv('GOOGLE_CLIENT_ID', '');
  // Resolve module-owned paths only after isolating all state from the demo.
  rp = await import('../src/rp/server.js');
  const identity = async (): Promise<KeyedIdentity> => {
    const keys = await cryptoProvider.generateKeyPair();
    return { did, kid: `${did}#key-1`, publicKeyBase64: keys.publicKey, privateKeyBase64: keys.privateKey };
  };
  [beforeRotation, afterRotation] = await Promise.all([identity(), identity()]);
});
beforeEach(() => {
  // DID documents include createdAt; keep comparisons independent of clock ticks.
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date('2026-09-09T07:00:00.000Z'));
  fs.rmSync(rp.DID_DOCUMENT_FILE, { force: true });
});
afterEach(() => vi.useRealTimers());
afterAll(() => { vi.unstubAllEnvs(); fs.rmSync(directory, { recursive: true, force: true }); });

function appFor(identity: KeyedIdentity) {
  return rp.createRpApp({ identity, statusListUrl: 'https://auth.example/status-list',
    agentDid: () => 'did:key:test-agent', merchantDid: () => 'did:key:test-merchant', corsOrigins: [],
    keySetup: false, keyWebauthn: false, consentWebauthn: false, bypassWebauthn: false,
    rpID: 'auth.example', origin: 'https://auth.example', googleClientId: '' });
}

describe('RP DID document publication after deployment configuration changes', () => {
  it('serves the new configured key at the same DID and verifies only the new key signature', async () => {
    rp.ensureDidDocument(beforeRotation);
    const app = appFor(afterRotation);
    const response = await app.request('https://auth.example/.well-known/did.json');
    expect(response.status).toBe(200);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    const document = await response.json() as DIDDocument;
    expect(document).toEqual(rp.buildRpDidDocument(afterRotation));
    expect(JSON.parse(fs.readFileSync(rp.DID_DOCUMENT_FILE, 'utf8'))).toEqual(document);
    const key = document.verificationMethod!.find(method => method.id === afterRotation.kid)!;
    const publicKey = Buffer.from(String((key.publicKeyJwk as JsonWebKey).x), 'base64url').toString('base64');
    const message = new TextEncoder().encode('fresh consent result signed by the deployed RP');
    const newSignature = await cryptoProvider.sign(message, afterRotation.privateKeyBase64);
    const oldSignature = await cryptoProvider.sign(message, beforeRotation.privateKeyBase64);
    expect(await cryptoProvider.verify(message, newSignature, publicKey)).toBe(true);
    expect(await cryptoProvider.verify(message, oldSignature, publicKey)).toBe(false);
  });

  it('updates the published verification method and signing relationships when only kid changes', () => {
    rp.ensureDidDocument(beforeRotation);
    const renamed = { ...beforeRotation, kid: `${did}#key-2` };
    const document = rp.ensureDidDocument(renamed);
    expect(document).toEqual(rp.buildRpDidDocument(renamed));
    expect(document.authentication).toEqual([renamed.kid]);
    expect(document.assertionMethod).toEqual([renamed.kid]);
  });

  it('preserves a correct document and its metadata without rewriting the file', () => {
    const expected = { ...rp.ensureDidDocument(beforeRotation), alsoKnownAs: ['https://auth.example/account'] };
    const originalBytes = JSON.stringify(expected, null, '\t') + '\n';
    fs.writeFileSync(rp.DID_DOCUMENT_FILE, originalBytes);
    expect(rp.ensureDidDocument(beforeRotation)).toEqual(expected);
    expect(fs.readFileSync(rp.DID_DOCUMENT_FILE, 'utf8')).toBe(originalBytes);
  });

  it.each(['publicKeyJwk', 'publicKeyMultibase'] as const)('republishes when %s disagrees with the active key', representation => {
    const current = rp.buildRpDidDocument(afterRotation);
    const stale = rp.buildRpDidDocument(beforeRotation);
    const mixed = structuredClone(current);
    Object.assign(mixed.verificationMethod![0]!, { [representation]: stale.verificationMethod![0]![representation] });
    fs.mkdirSync(path.dirname(rp.DID_DOCUMENT_FILE), { recursive: true });
    fs.writeFileSync(rp.DID_DOCUMENT_FILE, JSON.stringify(mixed));
    expect(rp.ensureDidDocument(afterRotation)).toEqual(current);
  });

  it('republishes when the signing key is absent from assertionMethod', () => {
    const current = rp.ensureDidDocument(beforeRotation);
    fs.writeFileSync(rp.DID_DOCUMENT_FILE, JSON.stringify({ ...current, assertionMethod: [] }));
    expect(rp.ensureDidDocument(beforeRotation)).toEqual(current);
  });

  it('re-signs a retained status list for the deployed key without resetting bits or history', async () => {
    const status = await import('../src/rp/statuslist.js');
    const { makeVcSigningFunction } = await import('../src/lib/wiring.js');
    const url = 'https://auth.example/status-list';
    const oldSigner = makeVcSigningFunction(beforeRotation.privateKeyBase64);
    const first = await status.ensureStatusList({ identity: beforeRotation, signingFunction: oldSigner, url });
    const revoked = await status.resignWithBit({ credential: first, identity: beforeRotation, signingFunction: oldSigner, index: 94, revoked: true });
    const retained = await status.resignWithBit({ credential: revoked, identity: beforeRotation, signingFunction: oldSigner, index: 131071, revoked: true });
    status.saveStatusListVersion(retained, { action: 'revoke', index: 131071, at: new Date().toISOString() });
    const version = status.loadStatusListMeta().version;
    const history = fs.readdirSync(status.STATUS_LIST_HISTORY_DIR).map(name => [name, fs.readFileSync(path.join(status.STATUS_LIST_HISTORY_DIR, name), 'utf8')] as const);
    const options = { identity: afterRotation, signingFunction: makeVcSigningFunction(afterRotation.privateKeyBase64), url };
    const response = await appFor(afterRotation).request('https://auth.example/status-list');
    expect(response.status).toBe(200);
    const refreshed = await response.json() as typeof retained;
    expect(refreshed.credentialSubject.encodedList).toBe(retained.credentialSubject.encodedList);
    expect(await status.readBit(refreshed, 94)).toBe(true);
    expect(await status.readBit(refreshed, 131071)).toBe(true);
    expect(await status.readBit(refreshed, 95)).toBe(false);
    const { proof, ...unsigned } = refreshed;
    const signature = Buffer.from(String((proof as Record<string, unknown>)['proofValue']), 'base64url');
    const message = new TextEncoder().encode(canonicalizeJSON(unsigned));
    expect(await cryptoProvider.verify(message, signature, afterRotation.publicKeyBase64)).toBe(true);
    expect(await cryptoProvider.verify(message, signature, beforeRotation.publicKeyBase64)).toBe(false);
    expect(status.loadStatusListMeta().version).toBe(version + 1);
    for (const [name, contents] of history) expect(fs.readFileSync(path.join(status.STATUS_LIST_HISTORY_DIR, name), 'utf8')).toBe(contents);
    expect(await status.ensureStatusList(options)).toEqual(refreshed);
    expect(status.loadStatusListMeta().version).toBe(version + 1);
  });

  it('does not overwrite a revocation published while a rotated-key signature is computing', async () => {
    const status = await import('../src/rp/statuslist.js');
    const { makeVcSigningFunction } = await import('../src/lib/wiring.js');
    const url = 'https://auth.example/status-list';
    const existing = await status.ensureStatusList({ identity: beforeRotation, signingFunction: makeVcSigningFunction(beforeRotation.privateKeyBase64), url });
    const signer = makeVcSigningFunction(afterRotation.privateKeyBase64);
    let signalSigning!: () => void, releaseSigning!: () => void;
    const started = new Promise<void>(resolve => { signalSigning = resolve; });
    const paused = new Promise<void>(resolve => { releaseSigning = resolve; });
    const delayed = vi.fn<typeof signer>().mockImplementationOnce(async (...args) => {
      signalSigning(); await paused; return signer(...args);
    }).mockImplementation((...args) => signer(...args));
    const refreshing = status.ensureStatusList({ identity: afterRotation, signingFunction: delayed, url });
    try {
      await started;
      const revoked = await status.resignWithBit({ credential: existing, index: 99, revoked: true, identity: afterRotation, signingFunction: signer });
      const published = status.saveStatusListVersion(revoked, { action: 'revoke', index: 99, at: new Date().toISOString() });
      releaseSigning();
      const result = await refreshing;
      expect(result).toEqual(revoked);
      expect(await status.readBit(status.loadStatusList()!, 99)).toBe(true);
      expect(status.loadStatusListMeta()).toEqual(published);
    } finally { releaseSigning(); }
  });
});
