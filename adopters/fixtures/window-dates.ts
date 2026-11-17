/**
 * An adopter's issuer stamps the window of each status list and delegation hop it signs, and its
 * verifiers read those windows on servers of their own. Two things must not depend on the server
 * that verifies.
 *
 * How a bound is read: a time with no zone names no single instant, so reading it in the server's
 * own zone gives each server its own answer. It is refused, with the same reason in every zone, as
 * is a form `Date.parse` takes that is not an RFC 3339 date-time at all.
 *
 * Whether a list or hop stamped a moment ago is read: a list whose `validFrom` is a few seconds
 * ahead of the verifier's clock, as one issued just now by a server whose clock runs ahead is, is
 * read, as is one a few seconds past its `validUntil`. Both bounds are held with the library's
 * clock tolerance, and a bound beyond it is still refused.
 *
 * Lists are read as an adopter reads them: through `RuntimeFetchProvider` and SafeFetch, by the
 * Card path's `createRevocationChecker` and by `CheqdStatusListResolver`. The zone cases run this
 * file again in child processes whose `TZ` differs, and compare what each read.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  BitstringManager,
  RuntimeFetchProvider,
  base64urlEncodeFromBytes,
  canonicalizeJSON,
  createDidWebResolver,
  statusListGzipCodec,
  type CredentialStatus,
} from '@kya-os/mcp';
import {
  createDelegationProofVerifier,
  createRevocationChecker,
  createSafeFetch,
  createStatusListProofVerifier,
  requireDelegation,
  toDelegationChainMeta,
} from '@kya-os/mcp/card';
import { CheqdStatusListResolver } from '@kya-os/mcp/cheqd';
import { runCases } from './shared/cases.js';
import { revocationEntry, signCardHop } from './shared/credentials.js';
import { crypto, didDocumentOf, didKeyParty, didWebParty, type Party } from './shared/keys.js';
import { LIST_ENTRIES, signedStatusList, type ListWindow } from './shared/lists.js';
import { MemoryWeb } from './shared/web.js';

/** A public unicast address the lookup seam gives for every host. It is never contacted. */
const PUBLIC_ADDRESS = '93.184.215.14';
const RESOURCE = 'did:web:orders.example';
const ACTION = 'orders.place';
const INDEX = 3;
/** The argument that tells this file it runs as a child in another zone, before the bound it reads. */
const ZONE_CHILD = '--read-in-zone';
const REPORT_PREFIX = 'zone-verdicts: ';

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const at = (offsetMs: number): string => new Date(Date.now() + offsetMs).toISOString();

const issuer = await didWebParty('did:web:issuer.example');
const agent = await didKeyParty();
const web = new MemoryWeb();
web.serveDidDocument(didDocumentOf(issuer));
const lookup = async () => [{ address: PUBLIC_ADDRESS, family: 4 as const }];
const provider = new RuntimeFetchProvider({ lookup, transport: web.transport() });
const didResolver = createDidWebResolver(provider);
const cardChecker = createRevocationChecker({
  fetch: createSafeFetch({ lookup, transport: web.transport() }),
  verifyStatusList: createStatusListProofVerifier({ didResolver }),
});
const cheqdResolver = new CheqdStatusListResolver({
  fetchProvider: provider,
  didResolver,
  cryptoProvider: crypto,
  expectedIssuerDid: issuer.did,
  decompressor: statusListGzipCodec,
  cacheTtlMs: 0,
});

let lists = 0;
/** A URL no list was served at before, so no reader answers from what it kept. */
const nextUrl = (): string => `https://issuer.example/lists/${++lists}`;

/** A clear StatusList2021 list at `url`, stating `window` as its VC 1.1 dates, signed as the cheqd resolver checks. */
async function signedStatusList2021(signer: Party, url: string, window: ListWindow): Promise<Record<string, unknown>> {
  const unsigned = {
    '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc/status-list/2021/v1'],
    id: url,
    type: ['VerifiableCredential', 'StatusList2021Credential'],
    issuer: signer.did,
    ...(window.validFrom !== undefined ? { issuanceDate: window.validFrom } : {}),
    ...(window.validUntil !== undefined ? { expirationDate: window.validUntil } : {}),
    credentialSubject: {
      id: `${url}#list`,
      type: 'StatusList2021',
      statusPurpose: 'revocation',
      encodedList: await new BitstringManager(LIST_ENTRIES).encode(),
    },
  };
  const signature = await crypto.sign(new TextEncoder().encode(canonicalizeJSON(unsigned)), signer.privateKey);
  const proof = {
    type: 'Ed25519Signature2020',
    created: at(-MINUTE),
    verificationMethod: signer.kid,
    proofPurpose: 'assertionMethod',
    proofValue: base64urlEncodeFromBytes(signature),
  };
  return { ...unsigned, proof };
}

/** A refusal as a verdict, `refused <code>: <words>`, whichever reader gave it. */
function refused(code: unknown, words: unknown): string {
  return `refused ${String(code)}: ${String(words)}`;
}

/** What the Card path's checker makes of a clear list stating `window`. */
async function cardVerdict(window: ListWindow): Promise<string> {
  const url = nextUrl();
  web.serve(url, await signedStatusList(issuer, url, [], window));
  const answer = await cardChecker(revocationEntry(url, INDEX), { credentialIssuer: issuer.did });
  return answer.revoked ? refused(answer.code, answer.reason) : 'read';
}

/** What `CheqdStatusListResolver` makes of a clear StatusList2021 list stating `window`. */
async function cheqdVerdict(window: ListWindow): Promise<string> {
  const url = nextUrl();
  web.serve(url, await signedStatusList2021(issuer, url, window));
  const entry: CredentialStatus = {
    id: `${url}#${INDEX}`,
    type: 'StatusList2021Entry',
    statusPurpose: 'revocation',
    statusListIndex: String(INDEX),
    statusListCredential: url,
  };
  try {
    return (await cheqdResolver.checkStatus(entry)) ? 'revoked' : 'read';
  } catch (error) {
    const { code, message } = error as { code?: unknown; message?: unknown };
    return refused(code, message);
  }
}

/** What `requireDelegation` makes of a one-hop chain whose hop states `validFrom`, over a clear list. */
async function hopVerdict(validFrom: string): Promise<string> {
  const url = nextUrl();
  web.serve(url, await signedStatusList(issuer, url));
  const hop = await signCardHop(issuer, {
    id: `urn:example:hop-${lists}`,
    invoker: agent.did,
    invocationTarget: RESOURCE,
    parentCapability: RESOURCE,
    allowedAction: [ACTION],
    credentialStatus: revocationEntry(url, INDEX),
    validFrom,
  });
  const guard = requireDelegation({
    resource: RESOURCE,
    trustedRootIssuers: [issuer.did],
    verifyHopProof: createDelegationProofVerifier({ didResolver }),
    checkRevocation: cardChecker,
  });
  const result = await guard({ meta: toDelegationChainMeta([hop]), proofDid: agent.did, action: ACTION });
  return result.ok ? 'read' : refused(result.refusalCode, result.error.reasons.join('; '));
}

/** Each reader's verdict on `window`, the hop's on its `validFrom`, keyed by reader. */
async function verdicts(window: ListWindow & { validFrom: string }): Promise<Record<string, string>> {
  return { card: await cardVerdict(window), cheqd: await cheqdVerdict(window), hop: await hopVerdict(window.validFrom) };
}

/** What a child run with `TZ` set to `zone` reads for a `validFrom` of `stated`. */
function verdictsInZone(zone: string, stated: string): Record<string, string> {
  const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), ZONE_CHILD, stated], {
    env: { ...process.env, TZ: zone },
    encoding: 'utf8',
  });
  const line = child.stdout.split('\n').find((text) => text.startsWith(REPORT_PREFIX));
  assert.ok(line, `the child in ${zone} reported nothing: ${child.stderr.split('\n')[0] ?? ''}`);
  return JSON.parse(line.slice(REPORT_PREFIX.length)) as Record<string, string>;
}

/** Fail unless every verdict is `read`. */
function assertRead(found: Record<string, string>): void {
  for (const [reader, verdict] of Object.entries(found)) assert.equal(verdict, 'read', `${reader}: ${verdict}`);
}

/** Fail unless every reader refused with `code`, saying `words`. */
function assertRefused(found: Record<string, string>, code: string, words: string): void {
  for (const [reader, verdict] of Object.entries(found)) {
    assert.ok(verdict.startsWith(`refused ${code}: `), `${reader}: ${verdict}`);
    assert.ok(verdict.includes(words), `${reader} does not say ${words}: ${verdict}`);
  }
}

const childAt = process.argv.indexOf(ZONE_CHILD);
if (childAt !== -1) {
  const stated = process.argv[childAt + 1] ?? '';
  const found = await verdicts({ validFrom: stated, validUntil: at(30 * MINUTE) });
  await new Promise<void>((done) => process.stdout.write(`${REPORT_PREFIX}${JSON.stringify(found)}\n`, () => done()));
  process.exit(0);
}

/** The verifier's wall clock an hour ago, in UTC, written with no zone, as an issuer that leaves it out writes it. */
const ZONELESS = at(-60 * MINUTE).slice(0, 19);

await runCases('window-dates', 'a status list or hop bound with no zone, or not RFC 3339, is refused alike in every zone, and one a few seconds outside its window is read within the clock tolerance, through RuntimeFetchProvider, createRevocationChecker, CheqdStatusListResolver and requireDelegation', [
  {
    name: 'control: a window stated with zones, open now, is read by every reader',
    run: async () => assertRead(await verdicts({ validFrom: at(-MINUTE), validUntil: at(30 * MINUTE) })),
  },
  {
    name: 'a validFrom with no zone gets the same answer under TZ=UTC and TZ=America/Chicago',
    run: () => {
      const utc = verdictsInZone('UTC', ZONELESS);
      const chicago = verdictsInZone('America/Chicago', ZONELESS);
      assert.deepEqual(chicago, utc, `UTC read ${JSON.stringify(utc)}, America/Chicago read ${JSON.stringify(chicago)}`);
    },
  },
  {
    name: 'a validFrom with no zone is refused, saying the value, in every zone',
    run: () => {
      const { hop, ...lists } = verdictsInZone('America/Chicago', ZONELESS);
      assertRefused(lists, 'status_unavailable', `"${ZONELESS}"`);
      assertRefused({ hop: hop ?? 'no verdict' }, 'delegation_malformed', `"${ZONELESS}"`);
    },
  },
  {
    name: 'a validFrom Date.parse reads but RFC 3339 does not write is refused',
    run: async () => {
      for (const stated of ['2026-01-01', 'Thu, 01 Jan 2026 00:00:00 GMT']) {
        const { hop, ...lists } = await verdicts({ validFrom: stated, validUntil: at(30 * MINUTE) });
        assertRefused(lists, 'status_unavailable', `"${stated}"`);
        assertRefused({ hop: hop ?? 'no verdict' }, 'delegation_malformed', `"${stated}"`);
      }
    },
  },
  {
    name: 'a validFrom 2 seconds ahead of the verifier, as on a list or hop just issued by a server whose clock runs ahead, is read',
    run: async () => assertRead(await verdicts({ validFrom: at(2 * SECOND), validUntil: at(30 * MINUTE) })),
  },
  {
    name: 'a list 2 seconds past its validUntil is read within the clock tolerance',
    run: async () => {
      const window = { validFrom: at(-30 * MINUTE), validUntil: at(-2 * SECOND) };
      assertRead({ card: await cardVerdict(window), cheqd: await cheqdVerdict(window) });
    },
  },
  {
    name: 'control: a validFrom 10 minutes ahead is still refused, saying when it starts',
    run: async () => {
      const validFrom = at(10 * MINUTE);
      const { hop, ...lists } = await verdicts({ validFrom, validUntil: at(30 * MINUTE) });
      assertRefused(lists, 'status_unavailable', `not valid until "${validFrom}"`);
      assertRefused({ hop: hop ?? 'no verdict' }, 'delegation_not_yet_valid', validFrom);
    },
  },
  {
    name: 'control: a list 10 minutes past its validUntil is still refused, saying when it expired',
    run: async () => {
      const window = { validFrom: at(-30 * MINUTE), validUntil: at(-10 * MINUTE) };
      assertRefused({ card: await cardVerdict(window), cheqd: await cheqdVerdict(window) }, 'status_unavailable', `expired at "${window.validUntil}"`);
    },
  },
]);
