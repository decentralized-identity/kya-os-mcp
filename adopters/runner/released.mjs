/**
 * What the verifiers of released versions make of the proofs this version signs.
 *
 * A request proof states its delegation in its JWS protected header (SPEC.md §7.8). A verifier that
 * predates the parameter must read past it, so a proof that carries it verifies wherever the same
 * proof without it does, and must still refuse a proof whose header was changed after signing, since
 * the header is part of what is signed. Each function here makes proofs with this version and hands
 * them to one installed version's verifier: one made without the statement, as the control, one as
 * the generator signs it, and that one with its statement swapped and stripped.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const HEADER_PARAMETER = 'org.kya-os/delegation';
const AUDIENCE = 'did:web:server.example.com';
const TOOL = 'records.read';
const OTHER_DIGEST = `sha256:${'cd'.repeat(32)}`;

/** The proofs one verifier is handed, in the order they are printed. */
const COLUMNS = ['no statement', 'as signed', 'statement swapped', 'statement stripped'];

const base64url = (value) => Buffer.from(value).toString('base64url');
const headerOf = (jws) => JSON.parse(Buffer.from(jws.split('.')[0], 'base64url').toString('utf8'));

/** A credential that has a signed form, so a digest. Nothing here verifies its signature. */
const credentialFor = (subjectDid, id) => ({
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  id: `urn:uuid:${id}`,
  type: ['VerifiableCredential', 'DelegationCredential'],
  issuer: 'did:web:user.example.com',
  credentialSubject: { id: subjectDid, delegation: { id, issuerDid: 'did:web:user.example.com', subjectDid, constraints: { scopes: ['records:read'] } } },
  proof: { type: 'Ed25519Signature2020', proofValue: base64url(`signature-of-${id}`.padEnd(64, '.')) },
});

/** `jws` with its protected header rewritten to state `statement`, or nothing for `null`; the signature is left as it was. */
function withStatement(jws, statement) {
  const [, payload, signature] = jws.split('.');
  const own = Object.fromEntries(Object.entries(headerOf(jws)).filter(([name]) => name !== HEADER_PARAMETER));
  return `${base64url(JSON.stringify(statement === null ? own : { ...own, [HEADER_PARAMETER]: statement }))}.${payload}.${signature}`;
}

/** Throw unless `jws` states a credential digest when `stated`, and nothing when not: the proofs are what the columns say. */
function assertStatement(jws, stated) {
  const value = headerOf(jws)[HEADER_PARAMETER];
  if (stated ? !String(value).startsWith('sha256:') : value !== undefined) {
    throw new Error(`a proof made ${stated ? 'by the generator' : 'as the control'} states ${JSON.stringify(value)}`);
  }
}

/** The verdicts of `verdictOf(make, change)` on the four proofs of {@link COLUMNS}. */
async function rowOf(control, stated, verdictOf) {
  return {
    'no statement': await verdictOf(control, (jws) => jws),
    'as signed': await verdictOf(stated, (jws) => jws),
    'statement swapped': await verdictOf(stated, (jws) => withStatement(jws, OTHER_DIGEST)),
    'statement stripped': await verdictOf(stated, (jws) => withStatement(jws, null)),
  };
}

/** The entry points of the package installed in `projectDir`: its main one, and its card one where it has one. */
export async function installedLibrary(projectDir, name) {
  const dist = join(projectDir, 'node_modules', ...name.split('/'), 'dist');
  const card = join(dist, 'card', 'index.js');
  return {
    main: await import(pathToFileURL(join(dist, 'index.js')).href),
    card: existsSync(card) ? await import(pathToFileURL(card).href) : undefined,
  };
}

/** A proof verifier of `library`'s own, with a replay cache of its own and no network. */
function proofVerifierOf(library) {
  const fetchProvider = {
    fetch: async () => {
      throw new Error('no network');
    },
    resolveDID: async () => null,
    fetchStatusList: async () => null,
    fetchDelegationChain: async () => [],
  };
  return new library.ProofVerifier({
    cryptoProvider: new library.NodeCryptoProvider(),
    clockProvider: new library.SystemClockProvider(),
    nonceCacheProvider: new library.MemoryNonceCacheProvider(),
    fetchProvider,
    timestampSkewSeconds: 300,
  });
}

/** What a session request proof's verdict is called when it is accepted, and when its signature fails. */
export const SESSION_VERDICTS = { accepted: 'bound', badSignature: 'unbound (INVALID_JWS_SIGNATURE)' };

/**
 * How `verifier`'s `assertHolderBinding` takes the request proofs `current` makes for a call that
 * presents a delegation.
 */
export async function sessionProofRow(current, verifier) {
  const crypto = new current.NodeCryptoProvider();
  const identity = await new current.MemoryIdentityProvider(crypto).getIdentity();
  const args = { recordId: 'r-1', _kyaos_delegation: credentialFor(identity.did, 'del-compat') };
  const request = current.toHolderBindingRequest(TOOL, args);
  const stated = () => current.generateRequestProof({ identity, crypto, toolName: TOOL, args, audience: AUDIENCE });
  // The same proof as the generator made it before the statement: the proof generator alone, which writes `alg` and `kid`.
  const control = async () => {
    const now = Math.floor(Date.now() / 1000);
    const session = {
      sessionId: `req-${base64url(await crypto.randomBytes(9))}`,
      audience: AUDIENCE,
      nonce: base64url(await crypto.randomBytes(16)),
      timestamp: now,
      createdAt: now,
      lastActivity: now,
      ttlMinutes: 30,
      identityState: 'anonymous',
    };
    return new current.ProofGenerator(identity, crypto).generateProof(request, undefined, session, {});
  };
  return rowOf(control, stated, async (make, change) => {
    const proof = await make();
    assertStatement(proof.jws, make === stated);
    const result = await verifier.assertHolderBinding({
      proof: { ...proof, jws: change(proof.jws) },
      subjectDid: identity.did,
      request: verifier.toHolderBindingRequest(TOOL, args),
      expectedAudience: AUDIENCE,
      proofVerifier: proofVerifierOf(verifier),
    });
    return result.status === 'bound' ? SESSION_VERDICTS.accepted : `${result.status} (${result.cause ?? result.reason})`;
  });
}

/** What a card proof's verdict is called when it is accepted, and when its signature fails. */
export const CARD_VERDICTS = { accepted: 'ok', badSignature: 'refused (invalid_signature)' };

/** A fixed test-only Ed25519 key for the card proofs, as a private JWK. */
const CARD_KEY = { kty: 'OKP', crv: 'Ed25519', x: 'RvWVWwqcVO9f_7aQ8dXf0F16aoQsE4i_Ebjqo8mn_Ts', d: 'Yaa31QgNkAKKHjqn6yEu2vXQTMUEbeBMwIJ4h55Ukh4' };
const CARD_DID = 'did:web:agent.example.com';

/**
 * How `verifierCard`'s `verifyCardProof` takes the card proofs `currentCard` makes for a request
 * that carries a delegation chain.
 */
export async function cardProofRow(currentCard, verifierCard) {
  const request = {
    method: 'tools/call',
    params: { name: TOOL, arguments: { recordId: 'r-1' }, _meta: { 'org.kya-os/delegation-chain': [credentialFor(CARD_DID, 'hop-compat')] } },
  };
  const signer = await currentCard.ed25519SignerFromJwk({ did: CARD_DID, kid: `${CARD_DID}#key-1`, privateJwk: CARD_KEY });
  // A signer that is handed the statement and signs without it, as a signer written before it does.
  const unstating = { ...signer, sign: (payload) => signer.sign(payload) };
  let made = 0;
  const proofBy = (by) => async () => {
    const nonce = `n-compat-${String(++made).padStart(16, '0')}`;
    const [proof] = Object.values(await currentCard.buildCardProof(request, by, { audience: AUDIENCE, nonce }));
    return proof;
  };
  const stated = proofBy(signer);
  return rowOf(proofBy(unstating), stated, async (make, change) => {
    const proof = await make();
    assertStatement(proof.jws, make === stated);
    const seen = new Set();
    const result = await verifierCard.verifyCardProof({ ...proof, jws: change(proof.jws) }, request, {
      resolveKey: async () => ({ kty: 'OKP', crv: 'Ed25519', x: CARD_KEY.x }),
      trustResolveKeyAuthority: true,
      expectedAudience: AUDIENCE,
      consumeNonceIfFresh: async (value) => (seen.has(value) ? false : (seen.add(value), true)),
    });
    return result.ok ? CARD_VERDICTS.accepted : `refused (${result.reasons.join(', ')})`;
  });
}

/**
 * What `row` must hold for the statement to have changed nothing for its verifier: the proof as
 * signed has the verdict of the one without the statement, and where that is accepted, a statement
 * changed after signing fails the signature. A verifier that refuses the control refuses the rest
 * for the same reason.
 */
function expectedOf(row, verdicts) {
  const control = row['no statement'];
  const changed = control === verdicts.accepted ? verdicts.badSignature : control;
  return { 'no statement': control, 'as signed': control, 'statement swapped': changed, 'statement stripped': changed };
}

/**
 * Print `rows`, a map of verifier version to its verdicts or to a line that says why it has none,
 * under `title`. Returns whether every verdict is the expected one.
 */
export function printRows(title, rows, verdicts) {
  const measured = Object.values(rows).filter((row) => typeof row !== 'string');
  const width = Math.max(...measured.flatMap((row) => COLUMNS.map((column) => row[column].length)), ...COLUMNS.map((column) => column.length)) + 2;
  console.log(`\n${title}\n`);
  console.log(`  ${'verifier'.padEnd(10)}${COLUMNS.map((column) => column.padEnd(width)).join('')}`.trimEnd());
  const notes = [];
  for (const [version, row] of Object.entries(rows)) {
    if (typeof row === 'string') {
      console.log(`  ${version.padEnd(10)}${row}`);
      continue;
    }
    const expected = expectedOf(row, verdicts);
    console.log(`  ${version.padEnd(10)}${COLUMNS.map((column) => row[column].padEnd(width)).join('')}`.trimEnd());
    for (const column of COLUMNS) {
      if (row[column] !== expected[column]) notes.push(`${version}, ${column}: got ${row[column]}, expected ${expected[column]}`);
    }
    if (row['no statement'] !== verdicts.accepted) {
      console.log(`  ${''.padEnd(10)}(${version} refuses this version's proof with and without the statement, for the same reason)`);
    }
  }
  for (const note of notes) console.log(`  NOT AS EXPECTED: ${note}`);
  return notes.length === 0;
}
