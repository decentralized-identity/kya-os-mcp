/**
 * An adopter runs every party on its own machine, each on a `*.localhost` name, and serves the DID
 * documents from memory through its own `FetchProvider`. The private-network rule refuses those
 * names, as it must in production; `development: true` on the did:web resolver lets a developer
 * read them, the refusal says so with the code `host_refused`, and production refuses the switch
 * itself.
 */
import assert from 'node:assert/strict';
import { DelegationCredentialVerifier, createDidWebResolver } from '@kya-os/mcp';
import { runCases } from './shared/cases.js';
import { ed25519SignatureVerifier, issueDelegation } from './shared/credentials.js';
import { didDocumentOf, didKeyParty, didWebParty } from './shared/keys.js';
import { buildInProduction, isProductionChild, reportProductionBuild } from './shared/production.js';
import { MemoryWeb } from './shared/web.js';

/** The issuer as a local demo names it: a `*.localhost` host on a port of its own. */
const ISSUER_DID = 'did:web:issuer.localhost%3A4101';

const issuer = await didWebParty(ISSUER_DID);
const agent = await didKeyParty();
const web = new MemoryWeb();
web.serveDidDocument(didDocumentOf(issuer));
const provider = web.fetchProvider();

if (isProductionChild()) {
  await reportProductionBuild(() => createDidWebResolver(provider, { development: true }));
} else {
  const credential = await issueDelegation(issuer, { id: 'issuer-to-agent', subjectDid: agent.did, scopes: ['notes:read'] });
  const verifierOver = (development: boolean): DelegationCredentialVerifier =>
    new DelegationCredentialVerifier({
      didResolver: development ? createDidWebResolver(provider, { development: true }) : createDidWebResolver(provider),
      signatureVerifier: ed25519SignatureVerifier,
    });

  await runCases('localhost-development', 'a *.localhost did:web is refused with a hint, read with development: true, and the switch throws in production', [
    {
      name: 'control: the same document resolves through a provider with allowPrivateNetworkHosts: true',
      run: async () => {
        const intranetProvider = { allowPrivateNetworkHosts: true, fetch: (url: string, init?: unknown) => provider.fetch(url, init) };
        const document = await createDidWebResolver(intranetProvider).resolve(ISSUER_DID);
        assert.equal(document?.id, ISSUER_DID);
      },
    },
    {
      name: 'without development: true, resolution fails as host_refused and the reason names development: true',
      run: async () => {
        assert.equal(await createDidWebResolver(provider).resolve(ISSUER_DID), null, 'a *.localhost document resolved');
        const result = await verifierOver(false).verifyDelegationCredential(credential);
        assert.equal(result.valid, false, 'the credential verified');
        assert.ok(result.reason?.includes('development: true'), `the reason does not name development: true: ${result.reason}`);
        assert.equal(result.code, 'host_refused', result.reason ?? 'no reason given');
        assert.equal(result.transient, false, 'a refused host was refused as transient');
      },
    },
    {
      name: 'with development: true, the document resolves and the credential verifies',
      run: async () => {
        const document = await createDidWebResolver(provider, { development: true }).resolve(ISSUER_DID);
        assert.equal(document?.id, ISSUER_DID, 'createDidWebResolver returned no document');
        const result = await verifierOver(true).verifyDelegationCredential(credential);
        assert.equal(result.valid, true, result.reason ?? 'no reason given');
      },
    },
    {
      name: 'under NODE_ENV=production, development: true throws when the resolver is built',
      run: () => {
        const build = buildInProduction(import.meta.url);
        assert.equal(build.threw, true, 'createDidWebResolver built a development resolver in production');
        assert.match(build.message, /development/);
      },
    },
  ]);
}
